//! 协议层：帧头、消息类型、控制消息体、共享类型（DESIGN.md §5）。

pub mod codec;
pub mod header;
pub mod msg_type;
pub mod types;

pub use codec::{read_frame, write_frame, RawFrame};
pub use header::{
    flags, HiveHeader, NodeId, BROADCAST, HEADER_LEN, MAGIC, MAX_FRAME_PAYLOAD, VERSION,
};
pub use msg_type::MsgType;
pub use types::*;

use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::ProtoError;

// ---------------------------------------------------------------------------
// 控制消息体（§5.3）
// ---------------------------------------------------------------------------

/// 拓扑公告（§5.3）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GossipMsg {
    /// 这份公告属于谁。
    pub owner: NodeId,
    /// owner 的世代号，用于失效判定与反驳。
    pub incarnation: u64,
    /// owner 内部单调递增序号。
    pub seq: u64,
    /// owner 的全部直接邻居。
    pub edges: Vec<AdjEntry>,
    /// owner 自动共享的本机网段（§9.1）。
    pub subnets: Vec<SubnetAd>,
    /// owner 的入向监听端点，供全网做拨号候选（§6.5）。
    pub listen: ListenAdvert,
    /// owner 是否愿意做出口；false 的节点不进候选（§9.4.4）。
    pub accepts_egress: bool,
    /// owner 的可读别名。
    pub alias: Option<String>,
    /// owner 发布的共享规则集（LWW register，§9.4.3）。
    pub rule_set: Option<RuleSetAd>,
    /// 反熵摘要：owner 已知的每个节点的最新 seq（§6.3）。
    pub digest: Vec<(NodeId, u64)>,
}

/// 反熵拉取（§6.3）：请对方补发自 `from_seq` 起的 `owner` 公告。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PullMsg {
    pub owner: NodeId,
    pub from_seq: u64,
}

/// 请求在目的节点发起本地 TCP 连接（§5.3）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamOpenMsg {
    pub endpoint: Endpoint,
    pub proto: Proto,
    pub flags: u8,
    /// v2 端到端加密用的发起方临时公钥。
    pub e2e_pk: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamAckMsg {
    pub ok: bool,
    pub code: u16,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnreachableMsg {
    pub reason: UnreachableReason,
    pub last_hop: NodeId,
}

/// 流级信用窗口。信用由**出口侧**生成并回传（§5.5）。
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowUpdateMsg {
    pub stream_id: u64,
    /// 绝对信用值，不是增量 —— 乱序/丢包不会导致信用漂移。
    pub credit: u32,
}

/// 流关闭。
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamCloseMsg {
    pub stream_id: u64,
    pub reason: CloseReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CloseReason {
    Normal = 0,
    Reset = 1,
    Overflow = 2,
    Refused = 3,
    UnknownStream = 4,
}

// ---------------------------------------------------------------------------
// 链路握手（§5.4）—— 仅一跳，不可中继
// ---------------------------------------------------------------------------

/// 链路能力位。目前没有任何位被 v1 使用，全部留给 v2 的加密协商。
pub mod features {
    pub const NONE: u32 = 0;
    /// 声称支持端到端加密（v2）。
    pub const E2E: u32 = 1 << 0;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HelloMsg {
    pub ver_min: u8,
    pub ver_max: u8,
    /// 发送方的身份地址（= 它的 IP），握手即身份交换。
    pub node_addr: NodeId,
    pub nonce: [u8; 16],
    pub features: u32,
    /// `HMAC-SHA256(join_token, nonce_a || nonce_b || addr_a || addr_b)`；token 为空时为 None。
    pub auth: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HelloAckMsg {
    pub node_addr: NodeId,
    pub nonce: [u8; 16],
    pub features: u32,
    pub session_id: u64,
    /// 供拨入方做端口对齐自检（§6.2.3）。
    pub listen_ports: Vec<u16>,
    pub auth: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RejectMsg {
    pub reason: RejectReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    VersionMismatch,
    AuthFailed,
    TooManyLinks,
    IpLimit,
}

// ---------------------------------------------------------------------------
// 编解码辅助
// ---------------------------------------------------------------------------

/// 把控制消息体序列化进载荷。载荷上限在 `RawFrame` 构造时校验。
pub fn encode_payload<T: Serialize>(v: &T) -> Result<Bytes, ProtoError> {
    bincode::serialize(v)
        .map(Bytes::from)
        .map_err(|e| ProtoError::Codec(e.to_string()))
}

pub fn decode_payload<T: DeserializeOwned>(b: &[u8]) -> Result<T, ProtoError> {
    bincode::deserialize(b).map_err(|e| ProtoError::Codec(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gossip_msg_wire_roundtrip() {
        // 控制消息必须同时能过 bincode（wire）与 toml（人读）—— 这里验 wire。
        let msg = GossipMsg {
            owner: NodeId::from_ip("10.1.2.5".parse().unwrap()),
            incarnation: 3,
            seq: 42,
            edges: vec![AdjEntry {
                peer: NodeId::from_ip("10.4.0.9".parse().unwrap()),
                cost: 5,
                carrier: Carrier::Direct,
                rtt_ms: 12,
            }],
            subnets: vec![SubnetAd::any_port("10.1.2.0/24".parse().unwrap())],
            listen: ListenAdvert {
                addrs: vec!["10.1.2.5:20000".parse().unwrap()],
                issued_at: 1_700_000_000,
                ttl_secs: 900,
            },
            accepts_egress: true,
            alias: Some("gpu-01".into()),
            rule_set: None,
            digest: vec![(NodeId::from_ip("10.4.0.9".parse().unwrap()), 7)],
        };
        let bytes = encode_payload(&msg).unwrap();
        let back: GossipMsg = decode_payload(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn rule_set_survives_wire_roundtrip() {
        // Rule 走 RawRule 的字符串形态，必须能在 bincode 下往返（§5.3 + §9.4.3）。
        use crate::rules::{EgressTarget, GroupRef, HostMatcher, OnUnreachable, PortMatcher, Rule};
        let msg = GossipMsg {
            owner: NodeId::from_ip("10.1.2.5".parse().unwrap()),
            incarnation: 1,
            seq: 1,
            edges: vec![],
            subnets: vec![],
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: Some(RuleSetAd {
                publisher: NodeId::from_ip("10.1.2.5".parse().unwrap()),
                revision: 9,
                issued_at: 0,
                rules: vec![
                    Rule {
                        host: HostMatcher::parse("*.internal.example.com").unwrap(),
                        port: PortMatcher::Exact(443),
                        egress: EgressTarget::Group(GroupRef::Subnet("10.9.0.0/16".parse().unwrap())),
                        on_unreachable: OnUnreachable::Fail,
                        label: Some("db".into()),
                        enabled: true,
                    },
                    Rule::new(HostMatcher::Any, PortMatcher::Any, EgressTarget::Auto),
                ],
                hmac: Some([7u8; 16]),
            }),
            digest: vec![],
        };
        let bytes = encode_payload(&msg).unwrap();
        let back: GossipMsg = decode_payload(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn decode_payload_rejects_garbage() {
        assert!(decode_payload::<GossipMsg>(&[0xFF; 8]).is_err());
    }
}
