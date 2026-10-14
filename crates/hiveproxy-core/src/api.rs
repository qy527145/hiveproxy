//! 前端命令的**唯一实现**（docs/WEBUI.md §3.1）。
//!
//! 桌面端（Tauri IPC）和 web 界面（HTTP）都调这里。两边剩下的只有"转发"：
//! Tauri 那边是 `#[tauri::command] fn x(...) { api::x(...) }`，web 那边是
//! `"x" => api::x(...)`。**两侧都不许再有只服务于自己一侧的分支** ——
//! 一旦有，就是"桌面上能用、web 上点了没反应"这类故障的起点。
//!
//! 命令名、参数形状、返回体三者与 Tauri 的命令契约一一对应（DESIGN.md §6.7）：
//! `api::probe_dial(target, via)` ⇄ `invoke("probe_dial", { target, via })` ⇄ `POST /api/probe_dial`。
//! `web.rs` 里那条路由守卫测试就是为了钉住这件事。

use std::sync::Arc;

use crate::config::{classify_change, Config};
use crate::persist;
use crate::proto::NodeId;
use crate::rules::{RawRule, Rule};
use crate::service::ServiceHandle;
use crate::view::{
    DialResult, ExitCandidate, GroupView, NodeStatus, PublishResult, RuleIssue, RulePreview,
    RuleStat, RulesView, ServiceState, SharedRulesStatus, StatsSnapshot, StreamProbe,
    TopologySnapshot, ZoneView2,
};

// ---------------------------------------------------------------------------
// 服务生命周期
// ---------------------------------------------------------------------------

pub fn service_state(handle: &ServiceHandle) -> ServiceState {
    handle.state()
}

/// 启动服务。已经在跑时是空操作 —— 与桌面端原语义一致。
pub async fn service_start(handle: &Arc<ServiceHandle>) -> Result<ServiceState, String> {
    handle.start().await?;
    Ok(handle.state())
}

/// 停止服务。**web 服务与登录态不受影响**（§5.4）—— 这是"分开控制"的全部意义。
pub async fn service_stop(handle: &Arc<ServiceHandle>) -> Result<ServiceState, String> {
    handle.stop().await;
    Ok(handle.state())
}

/// 前端日志回传：让浏览器侧的报错也进引擎日志（排障时非常有用）。
pub fn ui_log(handle: &ServiceHandle, level: &str, msg: String) {
    match handle.peek() {
        Some(n) => n.state.log(level, "ui", msg),
        None => match level {
            "error" => tracing::error!(target: "hiveproxy", "ui: {msg}"),
            "warn" => tracing::warn!(target: "hiveproxy", "ui: {msg}"),
            "debug" => tracing::debug!(target: "hiveproxy", "ui: {msg}"),
            _ => tracing::info!(target: "hiveproxy", "ui: {msg}"),
        },
    }
}

// ---------------------------------------------------------------------------
// 只读快照
// ---------------------------------------------------------------------------

pub fn status(handle: &ServiceHandle) -> Result<NodeStatus, String> {
    Ok(handle.node()?.status())
}

pub fn topology(handle: &ServiceHandle) -> Result<TopologySnapshot, String> {
    Ok(handle.node()?.topology())
}

pub fn stats(handle: &ServiceHandle) -> Result<StatsSnapshot, String> {
    Ok(handle.node()?.stats())
}

pub fn groups(handle: &ServiceHandle) -> Result<Vec<GroupView>, String> {
    Ok(handle.node()?.groups())
}

pub fn zones(handle: &ServiceHandle) -> Result<Vec<ZoneView2>, String> {
    Ok(handle.node()?.zones())
}

pub fn rule_stats(handle: &ServiceHandle) -> Result<Vec<RuleStat>, String> {
    Ok(handle.node()?.rule_stats())
}

pub fn shared_rules_status(handle: &ServiceHandle) -> Result<SharedRulesStatus, String> {
    Ok(handle.node()?.shared_rules_status())
}

/// 活跃流的一行。字段名与前端 `StreamRow` 一致。
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StreamRow {
    pub peer: String,
    pub stream_id: u64,
    pub target: String,
}

pub fn active_streams(handle: &ServiceHandle) -> Result<Vec<StreamRow>, String> {
    Ok(handle
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

pub async fn close_stream(handle: &ServiceHandle, peer: NodeId, stream_id: u64) -> Result<(), String> {
    handle.node()?.close_stream(peer, stream_id).await
}

pub fn ping_peer(handle: &ServiceHandle, peer: NodeId) -> Result<u32, String> {
    handle.node()?.ping_peer(peer)
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 服务没跑时也要能编辑配置，所以这一条直接读磁盘。
pub fn get_config(handle: &ServiceHandle) -> Result<Config, String> {
    persist::load_config(&handle.base_dir()).map_err(|e| e.to_string())
}

/// 写配置。**按档位分发**（docs/WEBUI.md §5）：
/// 热字段直接生效；端口类原地重绑；身份/网段表这类重建引擎（界面不断线）。
pub async fn set_config(handle: &Arc<ServiceHandle>, cfg: Config) -> Result<(), String> {
    let Some(node) = handle.peek() else {
        // 未运行时只落盘，下次启动生效
        return persist::save_config(&handle.base_dir(), &cfg).map_err(|e| e.to_string());
    };

    if classify_change(&node.config(), &cfg).engine {
        // ③ 档：先把新配置落盘，再停/起。顺序不能反 —— 重建就是"重新读磁盘上那份"。
        persist::save_config(&handle.base_dir(), &cfg).map_err(|e| e.to_string())?;
        node.state.log(
            "info",
            "config",
            "身份或网段表已改动：正在重建引擎（全部链路与在途流会断开）",
        );
        return handle.restart().await.map(|_| ());
    }

    node.apply_config(cfg).await.map(|_| ())
}

pub fn data_dir(handle: &ServiceHandle) -> String {
    persist::data_dir(&handle.base_dir()).to_string_lossy().to_string()
}

pub fn validate_config(cfg: &Config) -> Vec<String> {
    cfg.validate()
}

pub fn config_to_toml(handle: &ServiceHandle) -> Result<String, String> {
    Ok(persist::load_config(&handle.base_dir())
        .map_err(|e| e.to_string())?
        .to_toml())
}

pub fn config_from_toml(text: &str) -> Result<Config, String> {
    Config::from_toml(text).map_err(|e| format!("TOML 解析失败：{e}"))
}

// ---------------------------------------------------------------------------
// 规则
// ---------------------------------------------------------------------------

pub fn get_rules(handle: &ServiceHandle) -> Result<RulesView, String> {
    Ok(handle.node()?.rules_view())
}

/// 原始行（前端草稿的形态）→ 规则表，**逐行报错**。
///
/// 这一层以前收的是 `Vec<Rule>`：任何一行解析失败都是整份反序列化失败，
/// 前端拿到的只有 `invalid args \`rules\` for command \`set_rules\`: …` ——
/// 看不出是哪一行、也看不出该怎么改（§18 第 32 条）。
pub fn parse_rows(rules: Vec<RawRule>) -> Result<Vec<Rule>, String> {
    rules
        .into_iter()
        .enumerate()
        .map(|(i, raw)| Rule::try_from(raw).map_err(|e| format!("第 {} 条：{e}", i + 1)))
        .collect()
}

pub fn set_rules(handle: &ServiceHandle, rules: Vec<RawRule>) -> Result<(), String> {
    handle.node()?.set_local_rules(parse_rows(rules)?)
}

/// 逐行校验（行内红字的来源）。不收 `Vec<Rule>` 是因为那样一失败就整份没了。
pub fn check_rules(handle: &ServiceHandle, rules: Vec<RawRule>) -> Result<Vec<RuleIssue>, String> {
    Ok(handle.node()?.check_rules(rules))
}

pub fn preview_rules(handle: &ServiceHandle, rules: Vec<RawRule>) -> Result<RulePreview, String> {
    Ok(handle.node()?.preview_rules(parse_rows(rules)?))
}

pub async fn publish_rules(
    handle: &ServiceHandle,
    rules: Vec<RawRule>,
) -> Result<PublishResult, String> {
    handle.node()?.publish_rules(parse_rows(rules)?).await
}

pub async fn revoke_shared_rules(handle: &ServiceHandle) -> Result<PublishResult, String> {
    handle.node()?.revoke_shared_rules().await
}

pub fn set_rules_enabled(handle: &ServiceHandle, enabled: bool) -> Result<(), String> {
    handle.node()?.set_rules_enabled(enabled)
}

pub fn sort_rules(handle: &ServiceHandle, rules: Vec<RawRule>) -> Result<Vec<RawRule>, String> {
    let sorted = handle.node()?.sort_rules(parse_rows(rules)?);
    Ok(sorted.into_iter().map(RawRule::from).collect())
}

// ---------------------------------------------------------------------------
// 种子与探测
// ---------------------------------------------------------------------------

pub fn add_seed(handle: &ServiceHandle, addr: String) -> Result<(), String> {
    handle.node()?.add_seed(addr)
}

pub fn remove_seed(handle: &ServiceHandle, addr: String) -> Result<(), String> {
    handle.node()?.remove_seed(addr)
}

pub async fn probe_target(handle: &ServiceHandle, target: String) -> Result<StreamProbe, String> {
    handle.node()?.probe_target(&target).await
}

/// 候选出口清单（§18 第 31 条）：纯路由计算，不建流。
pub fn probe_exits(handle: &ServiceHandle, target: String) -> Result<Vec<ExitCandidate>, String> {
    handle.node()?.probe_exits(&target)
}

/// 实测：让某个出口真的连一次目标再关掉（会产生一次真实连接）。
pub async fn probe_dial(
    handle: &ServiceHandle,
    target: String,
    via: NodeId,
) -> Result<DialResult, String> {
    handle.node()?.probe_dial(&target, via).await
}