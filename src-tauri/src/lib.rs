//! Tauri v2 外壳。核心引擎全部在 `hiveproxy-core` 里，这里只做三件事：
//! 1. 管理服务的启停（GUI 上要有开关）；
//! 2. 把 core 的事件转发成前端事件；
//! 3. 把 core 的 API 暴露成 Tauri 命令（DESIGN.md §6.7 的命令契约）。

use std::path::PathBuf;
use std::sync::Arc;

use hiveproxy_core::config::Config;
use hiveproxy_core::node::HiveNode;
use hiveproxy_core::persist;
use hiveproxy_core::proto::NodeId;
use hiveproxy_core::rules::Rule;
use hiveproxy_core::view::{
    GroupView, NodeStatus, PublishResult, RulePreview, RuleStat, RulesView, SharedRulesStatus,
    StatsSnapshot, StreamProbe, TopologySnapshot, ZoneView2,
};
use serde::Serialize;
use tauri::{Emitter, Manager, State};

/// 前端只订阅一个事件名 `hive`，载荷里带 `event` 字段区分类型。
const EVENT_NAME: &str = "hive";

/// 供事件转发器拿到 AppHandle（在 setup 里写入）。
static APP_HANDLE: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

struct Inner {
    node: Option<Arc<HiveNode>>,
    base_dir: PathBuf,
    /// 上次启动失败的原因，供 UI 显示（而不是静默白屏）。
    last_error: Option<String>,
}

struct AppState {
    inner: parking_lot::Mutex<Inner>,
}

impl AppState {
    fn node(&self) -> Result<Arc<HiveNode>, String> {
        let g = self.inner.lock();
        g.node
            .clone()
            .ok_or_else(|| g.last_error.clone().unwrap_or_else(|| "服务未运行".to_string()))
    }

    fn base_dir(&self) -> PathBuf {
        self.inner.lock().base_dir.clone()
    }
}

/// 服务状态快照。
#[derive(Serialize, Clone)]
struct ServiceState {
    running: bool,
    autostart: bool,
    node_id: String,
    socks5_bind: String,
    admin_endpoint: Option<String>,
    data_dir: String,
    last_error: Option<String>,
}

#[tauri::command]
fn service_state(state: State<'_, AppState>) -> ServiceState {
    let base_dir = state.base_dir();
    let cfg = persist::load_config(&base_dir).unwrap_or_default();
    let g = state.inner.lock();

    let (node_id, socks5) = match &g.node {
        Some(n) => {
            let st = n.status();
            (st.node_id.to_string(), st.socks5_bind)
        }
        None => {
            // 未运行时也要能显示"我是谁、代理挂哪儿"，所以从配置/网卡现算
            let id = cfg
                .node
                .overlay_addr
                .map(|a| a.to_string())
                .or_else(|| hiveproxy_core::net::primary_ip().map(|a| a.to_string()))
                .unwrap_or_else(|| "—".into());
            (id, cfg.proxy.socks5_bind.to_string())
        }
    };

    ServiceState {
        running: g.node.is_some(),
        autostart: cfg.service.autostart,
        node_id,
        socks5_bind: socks5,
        admin_endpoint: g.node.as_ref().and_then(|n| n.admin_endpoint()),
        data_dir: persist::data_dir(&base_dir).to_string_lossy().to_string(),
        last_error: g.last_error.clone(),
    }
}

/// 启动服务。已经在跑时是空操作。
#[tauri::command]
async fn service_start(state: State<'_, AppState>) -> Result<ServiceState, String> {
    let base_dir = state.base_dir();
    if state.inner.lock().node.is_some() {
        return Ok(service_state(state));
    }

    let cfg = persist::load_or_init_config(&base_dir).map_err(|e| e.to_string())?;
    match HiveNode::start(cfg, &base_dir).await {
        Ok(node) => {
            let endpoint = node.admin_endpoint();
            spawn_forwarder(node.clone());
            {
                let mut g = state.inner.lock();
                g.node = Some(node);
                g.last_error = None;
            }
            tracing::info!("服务已启动（管理接口：{endpoint:?}）");
            Ok(service_state(state))
        }
        Err(e) => {
            state.inner.lock().last_error = Some(e.clone());
            tracing::error!("服务启动失败：{e}");
            Err(e)
        }
    }
}

#[tauri::command]
async fn service_stop(state: State<'_, AppState>) -> Result<ServiceState, String> {
    let node = state.inner.lock().node.take();
    if let Some(n) = node {
        n.stop().await;
        tracing::info!("服务已停止");
    }
    Ok(service_state(state))
}

/// 把 core 的事件转发给前端。每次启动服务都挂一个新的。
fn spawn_forwarder(node: Arc<HiveNode>) {
    let Some(app) = APP_HANDLE.get() else { return };
    let handle = app.clone();
    let mut rx = node.subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let _ = handle.emit(EVENT_NAME, &ev);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    let _ = handle.emit(
                        EVENT_NAME,
                        serde_json::json!({
                            "event": "log",
                            "ts_ms": 0,
                            "level": "warn",
                            "module": "ui",
                            "msg": format!("前端事件积压，丢弃了 {n} 条（UI 跟不上引擎速度）"),
                        }),
                    );
                }
                // 服务被停掉后通道关闭 —— 正常退出，不刷错误
                Err(_) => break,
            }
        }
    });
}

/// 前端日志回传：让浏览器侧的报错也进引擎日志（排障时非常有用）。
#[tauri::command]
fn ui_log(state: State<'_, AppState>, level: String, msg: String) {
    let node = state.inner.lock().node.clone();
    match node {
        Some(n) => n.state.log(&level, "ui", msg),
        None => match level.as_str() {
            "error" => tracing::error!(target: "hiveproxy", "ui: {msg}"),
            "warn" => tracing::warn!(target: "hiveproxy", "ui: {msg}"),
            "debug" => tracing::debug!(target: "hiveproxy", "ui: {msg}"),
            _ => tracing::info!(target: "hiveproxy", "ui: {msg}"),
        },
    }
}

// ---------------------------------------------------------------------------
// 引擎 API
// ---------------------------------------------------------------------------

#[tauri::command]
fn status(state: State<'_, AppState>) -> Result<NodeStatus, String> {
    Ok(state.node()?.status())
}

#[tauri::command]
fn topology(state: State<'_, AppState>) -> Result<TopologySnapshot, String> {
    Ok(state.node()?.topology())
}

#[tauri::command]
fn stats(state: State<'_, AppState>) -> Result<StatsSnapshot, String> {
    Ok(state.node()?.stats())
}

/// 服务没跑时也要能编辑配置，所以这一条直接读磁盘。
#[tauri::command]
fn get_config(state: State<'_, AppState>) -> Result<Config, String> {
    persist::load_config(&state.base_dir()).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_config(state: State<'_, AppState>, cfg: Config) -> Result<(), String> {
    match state.inner.lock().node.clone() {
        Some(n) => n.set_config(cfg),
        // 未运行时只落盘，下次启动生效
        None => persist::save_config(&state.base_dir(), &cfg).map_err(|e| e.to_string()),
    }
}

#[tauri::command]
fn get_rules(state: State<'_, AppState>) -> Result<RulesView, String> {
    Ok(state.node()?.rules_view())
}

#[tauri::command]
fn set_rules(state: State<'_, AppState>, rules: Vec<Rule>) -> Result<(), String> {
    state.node()?.set_local_rules(rules)
}

#[tauri::command]
fn preview_rules(state: State<'_, AppState>, rules: Vec<Rule>) -> Result<RulePreview, String> {
    Ok(state.node()?.preview_rules(rules))
}

#[tauri::command]
async fn publish_rules(
    state: State<'_, AppState>,
    rules: Vec<Rule>,
) -> Result<PublishResult, String> {
    state.node()?.publish_rules(rules).await
}

#[tauri::command]
async fn revoke_shared_rules(state: State<'_, AppState>) -> Result<PublishResult, String> {
    state.node()?.revoke_shared_rules().await
}

#[tauri::command]
fn set_rules_enabled(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    state.node()?.set_rules_enabled(enabled)
}

#[tauri::command]
fn sort_rules(state: State<'_, AppState>, rules: Vec<Rule>) -> Result<Vec<Rule>, String> {
    Ok(state.node()?.sort_rules(rules))
}

#[tauri::command]
fn rule_stats(state: State<'_, AppState>) -> Result<Vec<RuleStat>, String> {
    Ok(state.node()?.rule_stats())
}

#[tauri::command]
fn shared_rules_status(state: State<'_, AppState>) -> Result<SharedRulesStatus, String> {
    Ok(state.node()?.shared_rules_status())
}

#[tauri::command]
fn groups(state: State<'_, AppState>) -> Result<Vec<GroupView>, String> {
    Ok(state.node()?.groups())
}

#[tauri::command]
fn zones(state: State<'_, AppState>) -> Result<Vec<ZoneView2>, String> {
    Ok(state.node()?.zones())
}

#[tauri::command]
fn add_seed(state: State<'_, AppState>, addr: String) -> Result<(), String> {
    state.node()?.add_seed(addr)
}

#[tauri::command]
fn remove_seed(state: State<'_, AppState>, addr: String) -> Result<(), String> {
    state.node()?.remove_seed(addr)
}

#[tauri::command]
fn ping_peer(state: State<'_, AppState>, peer: NodeId) -> Result<u32, String> {
    state.node()?.ping_peer(peer)
}

#[derive(Serialize)]
struct StreamRow {
    peer: String,
    stream_id: u64,
    target: String,
}

#[tauri::command]
fn active_streams(state: State<'_, AppState>) -> Result<Vec<StreamRow>, String> {
    Ok(state
        .node()?
        .active_streams()
        .into_iter()
        .map(|(peer, id, target)| StreamRow {
            peer: peer.to_string(),
            stream_id: id,
            target,
        })
        .collect())
}

#[tauri::command]
async fn close_stream(
    state: State<'_, AppState>,
    peer: NodeId,
    stream_id: u64,
) -> Result<(), String> {
    state.node()?.close_stream(peer, stream_id).await
}

#[tauri::command]
async fn probe_target(state: State<'_, AppState>, target: String) -> Result<StreamProbe, String> {
    state.node()?.probe_target(&target).await
}

#[tauri::command]
fn data_dir(state: State<'_, AppState>) -> String {
    persist::data_dir(&state.base_dir()).to_string_lossy().to_string()
}

#[tauri::command]
fn validate_config(_state: State<'_, AppState>, cfg: Config) -> Vec<String> {
    cfg.validate()
}

#[tauri::command]
fn config_to_toml(state: State<'_, AppState>) -> Result<String, String> {
    Ok(persist::load_config(&state.base_dir())
        .map_err(|e| e.to_string())?
        .to_toml())
}

#[tauri::command]
fn config_from_toml(_state: State<'_, AppState>, text: String) -> Result<Config, String> {
    Config::from_toml(&text).map_err(|e| format!("TOML 解析失败：{e}"))
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tauri::Builder::default()
        .setup(|app| {
            let base = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("./data"));
            persist::ensure_dir(&base)?;
            let _ = APP_HANDLE.set(app.handle().clone());

            let cfg = persist::load_or_init_config(&base).unwrap_or_default();
            let autostart = cfg.service.autostart;

            app.manage(AppState {
                inner: parking_lot::Mutex::new(Inner {
                    node: None,
                    base_dir: base.clone(),
                    last_error: None,
                }),
            });

            if autostart {
                let handle = app.handle().clone();
                // 启动引擎涉及 tokio 任务与绑定端口，放到异步里做，别卡住窗口
                tauri::async_runtime::spawn(async move {
                    let st = handle.state::<AppState>();
                    if let Err(e) = service_start(st).await {
                        tracing::error!("自动启动失败：{e}");
                        let _ = handle.emit(
                            EVENT_NAME,
                            serde_json::json!({
                                "event": "log", "ts_ms": 0, "level": "error",
                                "module": "service",
                                "msg": format!("服务自动启动失败：{e}"),
                            }),
                        );
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            service_state,
            service_start,
            service_stop,
            ui_log,
            status,
            topology,
            stats,
            get_config,
            set_config,
            get_rules,
            set_rules,
            preview_rules,
            publish_rules,
            revoke_shared_rules,
            set_rules_enabled,
            sort_rules,
            rule_stats,
            shared_rules_status,
            groups,
            zones,
            add_seed,
            remove_seed,
            ping_peer,
            active_streams,
            close_stream,
            probe_target,
            data_dir,
            validate_config,
            config_to_toml,
            config_from_toml,
        ])
        .run(tauri::generate_context!())
        .expect("启动 Tauri 应用失败");
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    /// ★ 回归守卫：Tauri v2 默认**不允许**前端调用 `event.listen`。
    /// 少了这条权限，前端 `DOMContentLoaded` 里的 `await listen(...)` 会抛错，
    /// 后面整段初始化都不执行 —— 表现就是"界面全空"，而且很难猜。
    /// 这个坑踩过一次，钉在这里。
    #[test]
    fn capabilities_must_allow_event_listen() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("capabilities/default.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读不到 {}：{e}", path.display()));
        let v: serde_json::Value = serde_json::from_str(&text).expect("capabilities 应当是合法 JSON");
        let perms: Vec<String> = v["permissions"]
            .as_array()
            .expect("permissions 应当是数组")
            .iter()
            .filter_map(|p| p.as_str().map(|s| s.to_string()))
            .collect();
        assert!(
            perms.iter().any(|p| p == "core:event:allow-listen" || p == "core:default"),
            "capabilities 必须包含 core:event:allow-listen，否则前端初始化会整段中断：{perms:?}"
        );
        assert!(
            v["windows"].as_array().map(|w| w.iter().any(|x| x == "main")).unwrap_or(false),
            "capabilities 必须作用于 `main` 窗口（tauri.conf.json 里 windows[0].label）"
        );
    }

    /// 窗口 label 与 capability 的 `windows` 列表必须对得上，否则权限形同虚设。
    #[test]
    fn window_label_matches_capability() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let conf: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("tauri.conf.json")).unwrap())
                .expect("tauri.conf.json 应当是合法 JSON");
        let label = conf["app"]["windows"][0]["label"].as_str().unwrap_or("main");
        assert_eq!(label, "main", "capabilities 里写的是 main，窗口 label 必须一致");
    }
}
