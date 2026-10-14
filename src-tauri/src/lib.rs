//! Tauri v2 外壳。核心引擎全部在 `hiveproxy-core` 里，这里只做三件事：
//! 1. 把引擎的生命周期交给 `ServiceHandle`（与 web 界面共用同一份实现）；
//! 2. 把 core 的事件转发成前端事件；
//! 3. 把 core 的 API 暴露成 Tauri 命令（DESIGN.md §6.7 的命令契约）。
//!
//! ★ 从 2026-10-14 起，命令的**函数体全在 `hiveproxy_core::api`**（docs/WEBUI.md §3.1）：
//! 这里每个命令都只剩一行转发。这么做不是为了好看，是因为 web 界面要跑同一套界面 ——
//! 两边各写一份薄包装，迟早会漂移成"桌面上能用、web 上点了没反应"。

use std::sync::Arc;

use hiveproxy_core::api;
use hiveproxy_core::config::Config;
use hiveproxy_core::node::HiveNode;
use hiveproxy_core::proto::NodeId;
use hiveproxy_core::rules::RawRule;
use hiveproxy_core::service::ServiceHandle;
use hiveproxy_core::view::{
    DialResult, ExitCandidate, GroupView, NodeStatus, PublishResult, RuleIssue, RulePreview,
    RuleStat, RulesView, ServiceState, SharedRulesStatus, StatsSnapshot, StreamProbe,
    TopologySnapshot, ZoneView2,
};
use tauri::{Emitter, Manager, State};

/// 前端只订阅一个事件名 `hive`，载荷里带 `event` 字段区分类型。
const EVENT_NAME: &str = "hive";

/// 供事件转发器拿到 AppHandle（在 setup 里写入）。
static APP_HANDLE: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

struct AppState {
    handle: Arc<ServiceHandle>,
}

/// 把 core 的事件转发给前端。**每次引擎启动都会挂一个新的** ——
/// 包括配置改动导致的原地重建（§5.3），所以它走的是 `ServiceHandle::on_start` 钩子，
/// 而不是在 `service_start` 里手工挂一次（那样重建之后界面就再也收不到事件了）。
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
                // 引擎被停掉/重建后通道关闭 —— 正常退出，不刷错误
                Err(_) => break,
            }
        }
    });
}

// ---------------------------------------------------------------------------
// 服务生命周期
// ---------------------------------------------------------------------------

#[tauri::command]
fn service_state(state: State<'_, AppState>) -> ServiceState {
    api::service_state(&state.handle)
}

#[tauri::command]
async fn service_start(state: State<'_, AppState>) -> Result<ServiceState, String> {
    api::service_start(&state.handle).await
}

#[tauri::command]
async fn service_stop(state: State<'_, AppState>) -> Result<ServiceState, String> {
    api::service_stop(&state.handle).await
}

/// 前端日志回传：让浏览器侧的报错也进引擎日志（排障时非常有用）。
#[tauri::command]
fn ui_log(state: State<'_, AppState>, level: String, msg: String) {
    api::ui_log(&state.handle, &level, msg)
}

// ---------------------------------------------------------------------------
// 引擎 API
// ---------------------------------------------------------------------------

#[tauri::command]
fn status(state: State<'_, AppState>) -> Result<NodeStatus, String> {
    api::status(&state.handle)
}

#[tauri::command]
fn topology(state: State<'_, AppState>) -> Result<TopologySnapshot, String> {
    api::topology(&state.handle)
}

#[tauri::command]
fn stats(state: State<'_, AppState>) -> Result<StatsSnapshot, String> {
    api::stats(&state.handle)
}

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> Result<Config, String> {
    api::get_config(&state.handle)
}

#[tauri::command]
async fn set_config(state: State<'_, AppState>, cfg: Config) -> Result<(), String> {
    api::set_config(&state.handle, cfg).await
}

#[tauri::command]
fn get_rules(state: State<'_, AppState>) -> Result<RulesView, String> {
    api::get_rules(&state.handle)
}

#[tauri::command]
fn set_rules(state: State<'_, AppState>, rules: Vec<RawRule>) -> Result<(), String> {
    api::set_rules(&state.handle, rules)
}

#[tauri::command]
fn check_rules(state: State<'_, AppState>, rules: Vec<RawRule>) -> Result<Vec<RuleIssue>, String> {
    api::check_rules(&state.handle, rules)
}

#[tauri::command]
fn preview_rules(state: State<'_, AppState>, rules: Vec<RawRule>) -> Result<RulePreview, String> {
    api::preview_rules(&state.handle, rules)
}

#[tauri::command]
async fn publish_rules(
    state: State<'_, AppState>,
    rules: Vec<RawRule>,
) -> Result<PublishResult, String> {
    api::publish_rules(&state.handle, rules).await
}

#[tauri::command]
async fn revoke_shared_rules(state: State<'_, AppState>) -> Result<PublishResult, String> {
    api::revoke_shared_rules(&state.handle).await
}

#[tauri::command]
fn set_rules_enabled(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    api::set_rules_enabled(&state.handle, enabled)
}

#[tauri::command]
fn sort_rules(state: State<'_, AppState>, rules: Vec<RawRule>) -> Result<Vec<RawRule>, String> {
    api::sort_rules(&state.handle, rules)
}

#[tauri::command]
fn rule_stats(state: State<'_, AppState>) -> Result<Vec<RuleStat>, String> {
    api::rule_stats(&state.handle)
}

#[tauri::command]
fn shared_rules_status(state: State<'_, AppState>) -> Result<SharedRulesStatus, String> {
    api::shared_rules_status(&state.handle)
}

#[tauri::command]
fn groups(state: State<'_, AppState>) -> Result<Vec<GroupView>, String> {
    api::groups(&state.handle)
}

#[tauri::command]
fn zones(state: State<'_, AppState>) -> Result<Vec<ZoneView2>, String> {
    api::zones(&state.handle)
}

#[tauri::command]
fn add_seed(state: State<'_, AppState>, addr: String) -> Result<(), String> {
    api::add_seed(&state.handle, addr)
}

#[tauri::command]
fn remove_seed(state: State<'_, AppState>, addr: String) -> Result<(), String> {
    api::remove_seed(&state.handle, addr)
}

#[tauri::command]
fn ping_peer(state: State<'_, AppState>, peer: NodeId) -> Result<u32, String> {
    api::ping_peer(&state.handle, peer)
}

#[tauri::command]
fn active_streams(state: State<'_, AppState>) -> Result<Vec<api::StreamRow>, String> {
    api::active_streams(&state.handle)
}

#[tauri::command]
async fn close_stream(
    state: State<'_, AppState>,
    peer: NodeId,
    stream_id: u64,
) -> Result<(), String> {
    api::close_stream(&state.handle, peer, stream_id).await
}

#[tauri::command]
async fn probe_target(state: State<'_, AppState>, target: String) -> Result<StreamProbe, String> {
    api::probe_target(&state.handle, target).await
}

#[tauri::command]
fn probe_exits(state: State<'_, AppState>, target: String) -> Result<Vec<ExitCandidate>, String> {
    api::probe_exits(&state.handle, target)
}

#[tauri::command]
async fn probe_dial(
    state: State<'_, AppState>,
    target: String,
    via: NodeId,
) -> Result<DialResult, String> {
    api::probe_dial(&state.handle, target, via).await
}

#[tauri::command]
fn data_dir(state: State<'_, AppState>) -> String {
    api::data_dir(&state.handle)
}

#[tauri::command]
fn validate_config(_state: State<'_, AppState>, cfg: Config) -> Vec<String> {
    api::validate_config(&cfg)
}

#[tauri::command]
fn config_to_toml(state: State<'_, AppState>) -> Result<String, String> {
    api::config_to_toml(&state.handle)
}

#[tauri::command]
fn config_from_toml(_state: State<'_, AppState>, text: String) -> Result<Config, String> {
    api::config_from_toml(&text)
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
            hiveproxy_core::persist::ensure_dir(&base)?;
            let _ = APP_HANDLE.set(app.handle().clone());

            let handle = ServiceHandle::new(base);
            // ★ 事件转发挂在钩子上，不是每次 start 手工挂 —— 引擎原地重建之后
            // 旧通道关闭、旧转发器退出，只有钩子能保证新引擎也有人听（§5.3）
            handle.on_start(spawn_forwarder);

            let autostart = handle.current_config().service.autostart;
            app.manage(AppState { handle: handle.clone() });

            if autostart {
                let handle = handle.clone();
                let app2 = app.handle().clone();
                // 启动引擎涉及 tokio 任务与绑定端口，放到异步里做，别卡住窗口
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = handle.start().await {
                        tracing::error!("自动启动失败：{e}");
                        let _ = app2.emit(
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
            probe_exits,
            probe_dial,
            check_rules,
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
    /// 少了这条权限，前端 `startEventBridge()` 里的 `await listen("hive")` 会抛错，
    /// 事件桥与随后的初始化都建不起来 —— 界面画得出来，但数据永远停在初始状态，
    /// 而且原因不出现在任何日志里（现在会经 `ui_log` 回传，见 lib/report.ts）。
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