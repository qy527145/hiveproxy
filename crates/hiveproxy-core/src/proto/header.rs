//! L2 帧层：定长 48 字节帧头与节点地址（DESIGN.md §5.1、§5.8）。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use bytes::{BufMut, BytesMut};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::msg_type::MsgType;
use crate::error::ProtoError;

/// 魔数：字母 'H'（Hive）。
pub const MAGIC: u8 = 0x48;
/// 固定头长度。
pub const HEADER_LEN: usize = 48;
/// 单帧载荷上限 256 KiB（§5.1）。
pub const MAX_FRAME_PAYLOAD: u32 = 256 * 1024;
/// 当前协议版本。
pub const VERSION: u8 = 1;

/// 广播哨兵 = v4-mapped 的 255.255.255.255（`::ffff:255.255.255.255`）。
///
/// 仅用于 Gossip 的多跳扩散，绝不作为业务帧的 dst，也不得替代真实节点地址（§5.7）。
pub const BROADCAST: NodeId = NodeId([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
]);

// ---------------------------------------------------------------------------
// NodeId —— 地址即身份（§5.8）
// ---------------------------------------------------------------------------

/// 节点身份 = 节点网络地址，16 字节定长。
///
/// IPv4 以 v4-mapped IPv6 形式存放（`::ffff:a.b.c.d`），IPv6 原样 16 字节。
/// 实现 `Display` / `FromStr`，使日志与配置里看到的都是 `10.1.2.3` 这样的普通地址。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    /// IPv4 自动转 v4-mapped。
    pub const V4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF];

    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::from_ipv4(v4),
            IpAddr::V6(v6) => Self(v6.octets()),
        }
    }

    pub fn from_ipv4(v4: Ipv4Addr) -> Self {
        let mut b = [0u8; 16];
        b[..12].copy_from_slice(&Self::V4_MAPPED_PREFIX);
        b[12..].copy_from_slice(&v4.octets());
        Self(b)
    }

    /// 非 v4-mapped 则按 IPv6 解析。
    pub fn to_ip(&self) -> Option<IpAddr> {
        if self.is_v4_mapped() {
            let mut o = [0u8; 4];
            o.copy_from_slice(&self.0[12..]);
            Some(IpAddr::V4(Ipv4Addr::from(o)))
        } else {
            Some(IpAddr::V6(Ipv6Addr::from(self.0)))
        }
    }

    pub fn is_v4_mapped(&self) -> bool {
        self.0[..12] == Self::V4_MAPPED_PREFIX
    }

    pub fn is_broadcast(&self) -> bool {
        *self == BROADCAST
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_ip() {
            Some(ip) => write!(f, "{ip}"),
            None => write!(f, "<invalid>"),
        }
    }
}

impl FromStr for NodeId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: IpAddr = s.trim().parse().map_err(|_| format!("无法解析节点地址 `{s}`"))?;
        Ok(Self::from_ip(ip))
    }
}

// 人可读格式走字符串（TOML / 日志），二进制格式走 16 字节定长（bincode 线格式）。
impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            NodeId::from_str(&s).map_err(D::Error::custom)
        } else {
            let v = <Vec<u8>>::deserialize(d)?;
            if v.len() != 16 {
                return Err(D::Error::custom(format!("NodeId 需要 16 字节，得到 {}", v.len())));
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&v);
            Ok(NodeId(b))
        }
    }
}

// ---------------------------------------------------------------------------
// flags（§5.1）
// ---------------------------------------------------------------------------

pub mod flags {
    /// 载荷已端到端加密，中继节点必须透传不可解。
    pub const ENCRYPTED: u8 = 1 << 0;
    /// 控制帧。
    pub const CONTROL: u8 = 1 << 1;
    /// 该流的半关闭信号。
    pub const FIN: u8 = 1 << 2;
    /// 心跳/握手等，走优先车道。
    pub const HIGH_PRIORITY: u8 = 1 << 3;
}

// ---------------------------------------------------------------------------
// HiveHeader（§5.1）
// ---------------------------------------------------------------------------

/// 48 字节定长帧头。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HiveHeader {
    pub version: u8,
    pub msg_type: MsgType,
    pub flags: u8,
    pub ttl: u8,
    pub src: NodeId,
    pub dst: NodeId,
    /// 流作用域消息填流 id；链路与控制消息恒为 0（§5.1）。
    pub stream_id: u64,
    pub payload_len: u32,
}

impl HiveHeader {
    pub fn new(msg_type: MsgType, src: NodeId, dst: NodeId, ttl: u8) -> Self {
        Self { version: VERSION, msg_type, flags: 0, ttl, src, dst, stream_id: 0, payload_len: 0 }
    }

    pub fn with_stream(mut self, stream_id: u64) -> Self {
        self.stream_id = stream_id;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn is_for(&self, me: NodeId) -> bool {
        self.dst == me
    }

    pub fn is_control(&self) -> bool {
        self.flags & flags::CONTROL != 0
    }

    pub fn is_broadcast(&self) -> bool {
        self.dst.is_broadcast()
    }

    /// 写 48 字节。
    pub fn encode_into(&self, buf: &mut BytesMut) {
        buf.put_u8(MAGIC);
        buf.put_u8((self.version << 4) | (self.msg_type as u8 & 0x0F));
        buf.put_u8(self.flags);
        buf.put_u8(self.ttl);
        buf.put_slice(&self.src.0);
        buf.put_slice(&self.dst.0);
        buf.put_u64(self.stream_id);
        buf.put_u32(self.payload_len);
    }

    pub fn encode(&self) -> BytesMut {
        let mut b = BytesMut::with_capacity(HEADER_LEN);
        self.encode_into(&mut b);
        b
    }

    /// 读 48 字节并校验 magic / version / payload_len。
    ///
    /// `magic` 校验是把「拨到非 hiveproxy 服务」变成确定性失败的判据（§6.2.2）。
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < HEADER_LEN {
            return Err(ProtoError::Truncated { need: HEADER_LEN, got: buf.len() });
        }
        if buf[0] != MAGIC {
            return Err(ProtoError::BadMagic(buf[0]));
        }
        let vt = buf[1];
        let version = vt >> 4;
        if version != VERSION {
            return Err(ProtoError::BadVersion(version));
        }
        let msg_type = MsgType::try_from_u8(vt & 0x0F)?;

        let mut src = [0u8; 16];
        src.copy_from_slice(&buf[4..20]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&buf[20..36]);

        let stream_id = u64::from_be_bytes(buf[36..44].try_into().expect("8 字节"));
        let payload_len = u32::from_be_bytes(buf[44..48].try_into().expect("4 字节"));
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(ProtoError::PayloadTooLarge(payload_len));
        }

        Ok(Self {
            version,
            msg_type,
            flags: buf[2],
            ttl: buf[3],
            src: NodeId(src),
            dst: NodeId(dst),
            stream_id,
            payload_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodeid_v4_mapped_layout() {
        // IPv4 → v4-mapped 的字节布局逐字节断言（§16）。
        let n = NodeId::from_ip("10.1.2.3".parse().unwrap());
        assert_eq!(
            n.0,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 1, 2, 3]
        );
        assert!(n.is_v4_mapped());
        assert_eq!(n.to_string(), "10.1.2.3");
        assert_eq!(n.to_ip().unwrap(), "10.1.2.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn nodeid_v6_passthrough() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        let n = NodeId::from_ip(ip);
        assert!(!n.is_v4_mapped());
        assert_eq!(n.to_ip().unwrap(), ip);
        assert_eq!(n.to_string(), "fd00::1");
    }

    #[test]
    fn nodeid_roundtrip_via_str() {
        for s in ["10.1.2.3", "fd00:1::9", "192.168.0.1"] {
            let n: NodeId = s.parse().unwrap();
            assert_eq!(n.to_string(), s.parse::<IpAddr>().unwrap().to_string());
        }
    }

    #[test]
    fn broadcast_does_not_collide_with_real_address() {
        // BROADCAST 不与任何合法 v4 地址冲突，也不是 v4-mapped 的普通地址。
        assert!(BROADCAST.is_broadcast());
        assert_eq!(NodeId::from_ip("255.255.255.255".parse().unwrap()), BROADCAST);
        assert_ne!(NodeId::from_ip("255.255.255.254".parse().unwrap()), BROADCAST);
        assert_ne!(NodeId::from_ip("0.0.0.0".parse().unwrap()), BROADCAST);
    }

    #[test]
    fn header_roundtrip() {
        let h = HiveHeader::new(
            MsgType::Data,
            NodeId::from_ip("10.1.2.3".parse().unwrap()),
            NodeId::from_ip("10.4.0.9".parse().unwrap()),
            8,
        )
        .with_stream(0xDEAD_BEEF)
        .with_flags(flags::CONTROL | flags::ENCRYPTED);
        let buf = h.encode();
        assert_eq!(buf.len(), HEADER_LEN);
        let back = HiveHeader::decode(&buf).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn header_rejects_bad_magic() {
        let mut buf = HiveHeader::new(
            MsgType::Gossip,
            NodeId::from_ip("10.0.0.1".parse().unwrap()),
            BROADCAST,
            4,
        )
        .encode();
        buf[0] = b'G'; // HTTP 响应首字节 'G'
        match HiveHeader::decode(&buf) {
            Err(ProtoError::BadMagic(b)) => assert_eq!(b, b'G'),
            other => panic!("应当报 BadMagic，实际 {other:?}"),
        }
    }

    #[test]
    fn header_rejects_oversize_payload() {
        let mut buf = HiveHeader::new(
            MsgType::Data,
            NodeId::from_ip("10.0.0.1".parse().unwrap()),
            NodeId::from_ip("10.0.0.2".parse().unwrap()),
            8,
        )
        .encode();
        buf[44..48].copy_from_slice(&(MAX_FRAME_PAYLOAD + 1).to_be_bytes());
        assert!(matches!(HiveHeader::decode(&buf), Err(ProtoError::PayloadTooLarge(_))));
    }

    #[test]
    fn header_rejects_bad_version() {
        let mut buf = HiveHeader::new(
            MsgType::Data,
            NodeId::from_ip("10.0.0.1".parse().unwrap()),
            NodeId::from_ip("10.0.0.2".parse().unwrap()),
            8,
        )
        .encode();
        buf[1] = (0x9 << 4) | (MsgType::Data as u8);
        assert!(matches!(HiveHeader::decode(&buf), Err(ProtoError::BadVersion(9))));
    }

    #[test]
    fn header_rejects_truncated() {
        assert!(matches!(
            HiveHeader::decode(&[MAGIC, 0x1A]),
            Err(ProtoError::Truncated { need: HEADER_LEN, got: 2 })
        ));
    }
}
