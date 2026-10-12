//! 面向前端的视图类型（DESIGN.md §6.7 的事件载荷与 IPC 返回体）。

use serde::{Deserialize, Serialize};

use crate::proto::{Endpoint, NodeId};
use crate::rules::RuleTable;

/// 一个节点在拓扑图上的一行。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeView {
    pub peer: NodeId,
    pub alias: Option<String>,
    pub is_self: bool,
    /// 该节点共享给全网的网段。
    pub subnets: Vec<String>,
    pub listen: Vec<String>,
    pub accepts_egress: bool,
    pub last_seen_ms: u64,
    pub incarnation: u64,
    /// 从本机看是否可达。
    pub reachable: bool,
    pub hops: Option<u8>,
    pub cost: Option<u32>,
    /// 是否有一条直连链路。
    pub direct: bool,
}

/// 一条边。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdgeView {
    pub from: NodeId,
    pub to: NodeId,
    pub cost: u32,
    pub carrier: String,
    pub health: String,
    pub establisher: String,
    pub rtt_ms: u16,
    pub direct: bool,
}

/// 拓扑里的一条**声明边**（任意两个节点之间），用于画 DAG。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub carrier: String,
    pub rtt_ms: u16,
    /// 这条边是否属于本机的直连链路。
    pub local: bool,
}

/// 拓扑快照。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopologySnapshot {
    pub nodes: Vec<NodeView>,
    /// 本机的直连链路（详细：健康、拨号方、成本）。
    pub edges: Vec<EdgeView>,
    /// 全网声明的邻接关系 —— DAG 就是按它画的。
    pub graph: Vec<GraphEdge>,
    pub version: u64,
}

/// 候选集的来源。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupSource {
    Explicit,
    Subnet(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupView {
    pub name: String,
    pub source: GroupSource,
    pub members: Vec<NodeId>,
}

/// 一次 `preview_rules` 的差异条目。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleChange {
    pub target: String,
    pub from: String,
    pub to: String,
}

/// `preview_rules` 的结果（§9.4.3 发布侧要求 3）。
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RulePreview {
    /// 哪些目标会改道。
    pub changes: Vec<RuleChange>,
    /// 永远匹配不到的条目下标（被前面的规则完全遮蔽）。
    pub never_matched: Vec<usize>,
    /// 会把流量变成黑洞的条目下标（`block` 或指向不可达出口）。
    pub blackholes: Vec<usize>,
    /// 非致命告警。
    pub warnings: Vec<String>,
}

/// 每条规则的运行期统计（§9.4.2 的命中统计）。
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RuleStat {
    pub index: usize,
    pub label: Option<String>,
    pub rule: String,
    pub hits: u64,
    pub last_egress: Option<NodeId>,
    pub last_rejected_at: Option<u64>,
}

/// 统计快照（`hive://stats`，每 1s）。
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct StatsSnapshot {
    pub links: usize,
    pub active_streams: usize,
    pub bytes_relayed_in: u64,
    pub bytes_relayed_out: u64,
    pub frames_relayed: u64,
    pub frames_dropped: u64,
    pub streams_dropped: u64,
    pub route_rebuilds: u64,
    pub handshakes_ok: u64,
    pub handshakes_failed: u64,
    pub unreachable_received: u64,
    pub gossip_sent: u64,
    pub gossip_received: u64,
    pub pulls_sent: u64,
    pub dial_attempts: u64,
    pub dial_failures: u64,
}

/// 一个被测目标的探测结果（`open_stream_probe`）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamProbe {
    pub target: Endpoint,
    pub egress: NodeId,
    pub direct: bool,
    pub matched_rule: Option<usize>,
    pub rtt_ms: u32,
}

/// 发布结果。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishResult {
    pub revision: u64,
    pub rules: usize,
    pub published_at: u64,
}

/// 共享规则集的当前状态（§9.4.3 前端必须常驻显示）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedRulesStatus {
    pub source: Option<NodeId>,
    pub source_alias: Option<String>,
    pub revision: u64,
    pub issued_at: u64,
    pub rules: usize,
    pub accepted: bool,
}

/// 分区视图（§9.3）：一个真冲突的网段与它的各个孤岛。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneView2 {
    pub net: String,
    pub islands: Vec<ZoneIslandView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneIslandView {
    pub zone: u16,
    pub label: String,
    /// 建议填写的地址形式，如 `z7+10.1.2.5:3306`。
    pub suggestion: String,
    pub members: Vec<NodeId>,
    /// 孤岛里当前可达的成员数 —— 全不可达说明那片现在够不着。
    pub reachable: usize,
}

/// 本机运行状态。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: NodeId,
    pub alias: Option<String>,
    pub listen: Vec<String>,
    /// 本机**能直达**的网段（我自己的可达范围），与是否对外声明无关。
    pub subnets: Vec<String>,
    /// 是否把上面的网段**广播**给全网（`share.auto_share_subnets`）。
    pub share_subnets: bool,
    pub accepts_egress: bool,
    pub socks5_bind: String,
    pub topology_version: u64,
    pub rule_count: usize,
    pub shared_rule_count: usize,
    pub rules_enabled: bool,
    pub uptime_secs: u64,
    pub version: String,
}

/// 规则表的 IPC 形态：合并表 + 本地/共享分界 + 来源与 revision。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RulesView {
    pub table: RuleTable,
    pub local: Vec<crate::rules::Rule>,
    pub shared: Option<crate::proto::RuleSetAd>,
    pub shared_source_alias: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_are_serializable_to_json() {
        // 这些类型直接作为 Tauri IPC 的返回体，必须能过 JSON。
        let nv = NodeView {
            peer: "10.1.2.5".parse().unwrap(),
            alias: Some("gpu-01".into()),
            is_self: false,
            subnets: vec!["10.1.2.0/24".into()],
            listen: vec!["10.1.2.5:20000".into()],
            accepts_egress: true,
            last_seen_ms: 0,
            incarnation: 1,
            reachable: true,
            hops: Some(2),
            cost: Some(6),
            direct: false,
        };
        let j = serde_json::to_string(&nv).unwrap();
        assert!(j.contains("\"10.1.2.5\""), "NodeId 在人读格式下应当是字符串: {j}");
        let back: NodeView = serde_json::from_str(&j).unwrap();
        assert_eq!(back.peer, nv.peer);
    }
}
