//! 共享类型定义（DESIGN.md §5.7）。避免实现时各自发挥。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::header::NodeId;
use crate::rules::Rule;

// ---------------------------------------------------------------------------
// 基础枚举
// ---------------------------------------------------------------------------

/// 直连分两种：跨网段白名单孔洞（成本高）、同网段（成本低）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize, Hash)]
pub enum Carrier {
    Direct,
    Lan,
}

impl Carrier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Lan => "lan",
        }
    }
}

/// v1 只实现 Tcp。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

/// 目标的"主机"部分：可能是 IP，也可能是域名。
///
/// 域名必须保持原始形式而不是预先解析出的 IP —— 解析发生在**出口节点**，
/// 因为企业内网普遍是 split-horizon DNS（§9.4.2）。
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

impl Host {
    /// 仅用于日志/前端展示，**不要**用它做业务判断。
    pub fn as_display(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Name(n) => n.clone(),
        }
    }
}

/// 流的目标端点。SOCKS5 CONNECT 必然给出具体主机，故 `host` 不可为空。
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: Host,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.host {
            Host::Ip(ip) => write!(f, "{ip}:{}", self.port),
            Host::Name(n) => write!(f, "{n}:{}", self.port),
        }
    }
}

// ---------------------------------------------------------------------------
// 广播内容（§5.3）
// ---------------------------------------------------------------------------

/// 共享的网段。`ports = None` 表示不限端口；`Some` 来自 `share_ports_only`（§9.1）。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SubnetAd {
    pub net: IpNet,
    pub ports: Option<Vec<u16>>,
}

impl SubnetAd {
    pub fn any_port(net: IpNet) -> Self {
        Self { net, ports: None }
    }

    /// 该网段是否覆盖这个端口。
    pub fn covers_port(&self, port: u16) -> bool {
        match &self.ports {
            None => true,
            Some(ps) => ps.contains(&port),
        }
    }
}

/// 本节点入向监听端点的广播（§6.5）。取代原 `dial_hints`，
/// 语义从"请你来拨我（默认关闭）"改为"我在这些地址上监听（默认开启，无来源过滤）"。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ListenAdvert {
    /// `listen.bind × listen.ports` 展开；不含回环。
    pub addrs: Vec<SocketAddr>,
    /// 墙上时钟，仅用于展示与排障。
    pub issued_at: u64,
    /// 过期即不再作为候选（默认 900 秒）。
    pub ttl_secs: u32,
}

impl Default for ListenAdvert {
    fn default() -> Self {
        Self { addrs: Vec::new(), issued_at: 0, ttl_secs: 900 }
    }
}

/// 共享规则集：**整份**作为一个 LWW register 同步（§9.4.3）。
///
/// 不做逐条合并 —— 只有"整份替换"才能用 `(revision, publisher)` 全序裁决，
/// 从而不需要版本向量、不需要中心、任何节点独立计算都得到同一份。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RuleSetAd {
    pub publisher: NodeId,
    pub revision: u64,
    pub issued_at: u64,
    /// 顺序即优先级。
    pub rules: Vec<Rule>,
    /// 可选：`security.rule_token` 的标签；未验签则整份忽略。
    pub hmac: Option<[u8; 16]>,
}

impl RuleSetAd {
    /// LWW 比较键：`(revision, publisher)` 字典序，大者胜（§6.3）。
    pub fn supersedes(&self, other: &RuleSetAd) -> bool {
        (self.revision, self.publisher) > (other.revision, other.publisher)
    }
}

// ---------------------------------------------------------------------------
// 拓扑
// ---------------------------------------------------------------------------

/// owner 声明的直接邻居。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AdjEntry {
    pub peer: NodeId,
    pub cost: u16,
    pub carrier: Carrier,
    pub rtt_ms: u16,
}

/// 一个节点的非拓扑元信息。
#[derive(Clone, Debug)]
pub struct NodeMeta {
    pub alias: Option<String>,
    /// §9.4.4 用它把不愿做出口的节点直接排除出候选。
    pub accepts_egress: bool,
    pub last_seen: Instant,
    pub incarnation: u64,
}

/// 网段 → 能直达它的节点集合（§9.1）。这是本设计里**唯一**的"谁能到哪"索引。
pub type Segments = HashMap<IpNet, Vec<NodeId>>;

// ---------------------------------------------------------------------------
// 流与链路
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Establisher {
    Local,
    Remote,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    Up,
    Degraded,
    Down,
}

#[derive(Clone, Debug)]
pub struct LinkMeta {
    pub establisher: Establisher,
    pub carrier: Carrier,
    pub rtt_ms: u16,
    pub health: Health,
    pub since: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum StreamState {
    Opening = 0,
    Open = 1,
    HalfClosedLocal = 2,
    HalfClosedRemote = 3,
    Closed = 4,
}

/// 本地流键：`(对端节点, 流 id)`。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StreamKey(pub NodeId, pub u64);

/// 不可达原因码，回给源节点供前端展示（§5.7）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum UnreachableReason {
    NoRoute = 0,
    TtlExhausted = 1,
    NextHopWriteFailed = 2,
    Refused = 3,
}

impl UnreachableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoRoute => "无路由",
            Self::TtlExhausted => "跳数耗尽",
            Self::NextHopWriteFailed => "下一跳写入失败",
            Self::Refused => "出口拒绝",
        }
    }
}

// ---------------------------------------------------------------------------
// 前端视图（§6.7）
// ---------------------------------------------------------------------------

/// 前端展示用：一个网段与能直达它的节点集合。
pub struct SegmentView {
    pub net: IpNet,
    pub via: Vec<NodeId>,
    pub is_local: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{EgressTarget, HostMatcher, OnUnreachable, PortMatcher};

    fn rs(rev: u64, pub_key: u8) -> RuleSetAd {
        RuleSetAd {
            publisher: NodeId::from_ip(format!("10.0.0.{pub_key}").parse().unwrap()),
            revision: rev,
            issued_at: 0,
            rules: vec![Rule {
                host: HostMatcher::Any,
                port: PortMatcher::Any,
                egress: EgressTarget::Block,
                on_unreachable: OnUnreachable::default(),
                label: None,
                enabled: true,
            }],
            hmac: None,
        }
    }

    #[test]
    fn lww_ordering_is_total_and_deterministic() {
        // 高 revision 胜；同 revision 按 publisher 字节序稳定裁决（§6.3）。
        assert!(rs(5, 1).supersedes(&rs(3, 9)));
        assert!(!rs(3, 9).supersedes(&rs(5, 1)));
        assert!(rs(5, 9).supersedes(&rs(5, 1)));
        assert!(!rs(5, 1).supersedes(&rs(5, 9)));
        // 相等则互不取代 —— 保留现有的。
        let a = rs(5, 1);
        let b = rs(5, 1);
        assert!(!a.supersedes(&b));
        assert!(!b.supersedes(&a));
    }

    #[test]
    fn subnet_ad_port_scope() {
        let net: IpNet = "10.9.0.0/16".parse().unwrap();
        assert!(SubnetAd::any_port(net).covers_port(3306));
        let scoped = SubnetAd { net, ports: Some(vec![22, 443]) };
        assert!(scoped.covers_port(22));
        assert!(!scoped.covers_port(3306));
    }
}
