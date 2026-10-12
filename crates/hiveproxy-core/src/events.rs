//! 对 UI 暴露的事件（DESIGN.md §6.7）。
//!
//! core 通过 `tokio::sync::broadcast` 发这些事件，Tauri 层转成前端事件。

use serde::Serialize;

use crate::proto::NodeId;
use crate::view::{RulesView, StatsSnapshot, TopologySnapshot};

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HiveEvent {
    /// 拓扑变化时 + 每 5s。
    Topology(Box<TopologySnapshot>),
    /// 规则表变化时。
    Rules(Box<RulesView>),
    /// 每 1s。
    Stats(StatsSnapshot),
    /// 实时日志。
    Log(LogEvent),
    PeerUp {
        peer: NodeId,
        establisher: String,
        carrier: String,
    },
    PeerDown {
        peer: NodeId,
        reason: String,
    },
    StreamOpened {
        peer: NodeId,
        stream_id: u64,
        target: String,
        egress: NodeId,
        direct: bool,
        matched_rule: Option<usize>,
    },
    StreamClosed {
        peer: NodeId,
        stream_id: u64,
        bytes_in: u64,
        bytes_out: u64,
        reason: String,
    },
    /// 共享规则集被拒收（验签失败 / 被关闭采信）。
    SharedRulesRejected {
        source: NodeId,
        reason: String,
    },
    /// 身份冲突：另一台机器声称的身份与本机相同（§6.3）。
    IdentityConflict {
        claimed_edges: usize,
        hint: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct LogEvent {
    pub ts_ms: u64,
    pub level: String,
    pub module: String,
    pub msg: String,
}

impl LogEvent {
    pub fn new(level: &str, module: &str, msg: impl Into<String>) -> Self {
        Self {
            ts_ms: now_ms(),
            level: level.to_string(),
            module: module.to_string(),
            msg: msg.into(),
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn now_unix() -> u64 {
    now_ms() / 1000
}
