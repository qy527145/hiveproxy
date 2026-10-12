//! 消息类型表（DESIGN.md §5.2）。低 4 位，与 `version` 共享 1 个字节。

use crate::error::ProtoError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgType {
    Reserved = 0x0,
    Hello = 0x1,
    Ping = 0x2,
    Pong = 0x3,
    Gossip = 0x4,
    StreamOpen = 0x5,
    StreamAck = 0x6,
    StreamClose = 0x7,
    WindowUpdate = 0x8,
    Unreachable = 0x9,
    Data = 0xA,
    /// 反熵拉取：请求补发某 `owner` 自 `from_seq` 起的公告（§6.3）。
    Pull = 0xB,
    /// 握手回执（§5.4）。仅一跳。
    HelloAck = 0xC,
    /// 握手拒绝（§5.4）。仅一跳。
    Reject = 0xD,
}

impl MsgType {
    pub fn try_from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            0x0 => Self::Reserved,
            0x1 => Self::Hello,
            0x2 => Self::Ping,
            0x3 => Self::Pong,
            0x4 => Self::Gossip,
            0x5 => Self::StreamOpen,
            0x6 => Self::StreamAck,
            0x7 => Self::StreamClose,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Unreachable,
            0xA => Self::Data,
            0xB => Self::Pull,
            0xC => Self::HelloAck,
            0xD => Self::Reject,
            other => return Err(ProtoError::UnknownMsgType(other)),
        })
    }

    /// 是否走控制优先车道。
    pub fn is_control(self) -> bool {
        matches!(
            self,
            Self::Hello
                | Self::HelloAck
                | Self::Reject
                | Self::Ping
                | Self::Pong
                | Self::Gossip
                | Self::Pull
                | Self::StreamOpen
                | Self::StreamAck
                | Self::StreamClose
                | Self::WindowUpdate
                | Self::Unreachable
        )
    }

    /// 是否可以被中间节点中继（§5.2 的「是否可中继」列）。
    pub fn is_relayable(self) -> bool {
        !matches!(
            self,
            Self::Reserved | Self::Hello | Self::HelloAck | Self::Reject | Self::Ping | Self::Pong
        )
    }

    /// 是否使用帧头的 `stream_id` 字段（§5.1）。
    pub fn is_stream_scoped(self) -> bool {
        matches!(
            self,
            Self::StreamOpen
                | Self::StreamAck
                | Self::StreamClose
                | Self::WindowUpdate
                | Self::Data
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "Reserved",
            Self::Hello => "Hello",
            Self::Ping => "Ping",
            Self::Pong => "Pong",
            Self::Gossip => "Gossip",
            Self::StreamOpen => "StreamOpen",
            Self::StreamAck => "StreamAck",
            Self::StreamClose => "StreamClose",
            Self::WindowUpdate => "WindowUpdate",
            Self::Unreachable => "Unreachable",
            Self::Data => "Data",
            Self::Pull => "Pull",
            Self::HelloAck => "HelloAck",
            Self::Reject => "Reject",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all() {
        for v in 0u8..=0xD {
            let t = MsgType::try_from_u8(v).unwrap();
            assert_eq!(t as u8, v);
        }
    }

    #[test]
    fn reserved_and_out_of_range() {
        assert_eq!(MsgType::try_from_u8(0x0).unwrap(), MsgType::Reserved);
        assert!(MsgType::try_from_u8(0xE).is_err());
        assert!(MsgType::try_from_u8(0xF).is_err());
    }

    #[test]
    fn stream_scoped_matches_design() {
        // 流作用域消息填 stream_id；链路与控制消息恒为 0（§5.1）。
        assert!(MsgType::Data.is_stream_scoped());
        assert!(MsgType::WindowUpdate.is_stream_scoped());
        assert!(!MsgType::Gossip.is_stream_scoped());
        assert!(!MsgType::Pull.is_stream_scoped());
        assert!(!MsgType::Hello.is_stream_scoped());
    }

    #[test]
    fn hello_is_not_relayable() {
        assert!(!MsgType::Hello.is_relayable());
        assert!(!MsgType::Ping.is_relayable());
        assert!(MsgType::Gossip.is_relayable());
        assert!(MsgType::Data.is_relayable());
    }
}
