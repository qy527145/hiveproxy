//! 控制帧构造辅助。

use bytes::Bytes;

use crate::link::OutboundFrame;
use crate::proto::{flags, HiveHeader, MsgType, NodeId};
use crate::state::HiveState;

/// 构造一个控制帧头。控制帧一律带 `CONTROL` 标志，`stream_id` 由调用方决定。
pub fn control_header(ty: MsgType, src: NodeId, dst: NodeId, ttl: u8) -> HiveHeader {
    let mut h = HiveHeader::new(ty, src, dst, ttl);
    h.flags |= flags::CONTROL;
    h
}

/// 用本节点的默认 TTL 构造一个发往 `dst` 的控制帧。
pub fn control_frame<T: serde::Serialize>(
    state: &HiveState,
    ty: MsgType,
    dst: NodeId,
    msg: &T,
) -> Result<OutboundFrame, crate::error::ProtoError> {
    let ttl = state.cfg().route.ttl_default;
    let header = control_header(ty, state.self_id(), dst, ttl);
    let payload = crate::proto::encode_payload(msg)?;
    Ok(OutboundFrame::new(header, payload))
}

/// 数据帧。
pub fn data_frame(
    state: &HiveState,
    dst: NodeId,
    stream_id: u64,
    ttl: u8,
    payload: Bytes,
) -> OutboundFrame {
    let mut h = HiveHeader::new(MsgType::Data, state.self_id(), dst, ttl);
    h.stream_id = stream_id;
    OutboundFrame::new(h, payload)
}

/// 控制帧（带 stream_id）。
pub fn control_frame_stream<T: serde::Serialize>(
    state: &HiveState,
    ty: MsgType,
    dst: NodeId,
    stream_id: u64,
    msg: &T,
) -> Result<OutboundFrame, crate::error::ProtoError> {
    let ttl = state.cfg().route.ttl_default;
    let header = control_header(ty, state.self_id(), dst, ttl).with_stream(stream_id);
    let payload = crate::proto::encode_payload(msg)?;
    Ok(OutboundFrame::new(header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_header_is_marked() {
        let h = control_header(
            MsgType::Gossip,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            4,
        );
        assert!(h.is_control());
        assert_eq!(h.stream_id, 0, "Gossip 的 stream_id 恒为 0（§5.1）");
    }
}
