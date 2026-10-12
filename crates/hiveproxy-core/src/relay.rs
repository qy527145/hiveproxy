//! 路由分发：`route_packet`（DESIGN.md §8）。
//!
//! 每个链路读任务解析出一帧就调用它，判定"本地消费"还是"内存中继"。
//! **中继全程不解载荷**，唯一改动的字节是 TTL（§5.6）。

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;

use crate::error::ProtoError;
use crate::events::now_unix;
use crate::link::OutboundFrame;
use crate::msg::{control_header, control_frame};
use crate::proto::{
    decode_payload, GossipMsg, MsgType, NodeId, PullMsg, RawFrame, StreamAckMsg, StreamCloseMsg,
    UnreachableMsg, UnreachableReason, WindowUpdateMsg, BROADCAST,
};
use crate::state::{HiveState, SendFail};

/// 去重表上限（§13）。
const GOSSIP_SEEN_CAP: usize = 4096;

/// 入口：处理一帧。
pub async fn route_packet(state: Arc<HiveState>, frame: RawFrame) {
    let header = frame.header;
    let me = state.self_id();

    // ---- 0. 前置校验 ----
    if header.ttl == 0 {
        state.stats.frames_dropped_ttl.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        send_unreachable(&state, header.src, UnreachableReason::TtlExhausted).await;
        return;
    }

    // ---- 1. 控制帧 ----
    if header.msg_type.is_control() {
        match header.msg_type {
            MsgType::Gossip => handle_gossip(&state, &frame, &header).await,
            MsgType::Pull => {
                if header.dst == me {
                    handle_pull(&state, frame.payload(), header.src).await;
                } else {
                    relay(&state, frame).await;
                }
            }
            MsgType::Ping => {
                if header.dst == me {
                    let pong = control_header(MsgType::Pong, me, header.src, state.cfg().route.ttl_default);
                    let _ = state.try_send_control_to(header.src, OutboundFrame::new(pong, Bytes::new()));
                } else {
                    relay(&state, frame).await;
                }
            }
            MsgType::Pong => { /* RTT 由链路层心跳处理 */ }
            MsgType::Hello | MsgType::HelloAck | MsgType::Reject => {
                // 握手类消息不可中继，也不该在此出现。
                state.stats.frames_dropped_queue.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            MsgType::StreamOpen => {
                if header.dst == me {
                    crate::stream::handle_stream_open(state.clone(), frame).await;
                } else {
                    relay(&state, frame).await;
                }
            }
            MsgType::StreamAck => {
                if header.dst == me {
                    if let Ok(msg) = decode_payload::<StreamAckMsg>(frame.payload()) {
                        crate::stream::handle_stream_ack(&state, header.stream_id, msg);
                    }
                } else {
                    relay(&state, frame).await;
                }
            }
            MsgType::StreamClose => {
                if header.dst == me {
                    if let Ok(msg) = decode_payload::<StreamCloseMsg>(frame.payload()) {
                        crate::stream::handle_stream_close(&state, header.src, msg).await;
                    }
                } else {
                    relay(&state, frame).await;
                }
            }
            MsgType::WindowUpdate => {
                if header.dst == me {
                    if let Ok(msg) = decode_payload::<WindowUpdateMsg>(frame.payload()) {
                        crate::stream::handle_window_update(&state, header.src, msg);
                    }
                } else {
                    relay(&state, frame).await;
                }
            }
            MsgType::Unreachable => {
                if header.dst == me {
                    state
                        .stats
                        .unreachable_received
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Ok(msg) = decode_payload::<UnreachableMsg>(frame.payload()) {
                        state.log(
                            "warn",
                            "relay",
                            format!(
                                "目标不可达（{}，最后一跳 {}）",
                                msg.reason.as_str(),
                                msg.last_hop
                            ),
                        );
                        crate::stream::fail_all_streams_via(&state, msg.last_hop, "上游不可达").await;
                    }
                } else {
                    relay(&state, frame).await;
                }
            }
            MsgType::Reserved | MsgType::Data => {
                state.stats.frames_dropped_queue.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        return;
    }

    // ---- 2. 数据帧 ----
    if header.msg_type == MsgType::Data {
        if header.dst == me {
            let payload = frame.into_payload().1;
            crate::stream::deliver_data(&state, header.src, header.stream_id, payload).await;
        } else {
            relay(&state, frame).await;
        }
        return;
    }

    state.stats.frames_dropped_queue.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Gossip（§6.3）
// ---------------------------------------------------------------------------

async fn handle_gossip(state: &Arc<HiveState>, frame: &RawFrame, header: &crate::proto::HiveHeader) {
    state.stats.gossip_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let Ok(msg) = decode_payload::<GossipMsg>(frame.payload()) else { return };

    // ★ 去重键取自载荷 (owner, seq)，不是帧头 src/stream_id（§6.3）
    let key = (msg.owner, msg.seq);
    {
        let mut seen = state.gossip_seen.write();
        if seen.contains_key(&key) {
            return;
        }
        if seen.len() >= GOSSIP_SEEN_CAP {
            // 简单淘汰：清掉最旧的一批
            let mut ages: Vec<((NodeId, u64), Instant)> = seen.iter().map(|(k, v)| (*k, *v)).collect();
            ages.sort_by_key(|(_, t)| *t);
            for (k, _) in ages.into_iter().take(GOSSIP_SEEN_CAP / 4) {
                seen.remove(&k);
            }
        }
        seen.insert(key, Instant::now());
    }

    let now = now_unix();
    let (outcome, snapshot_needed) = {
        let mut topo = state.topology.write();
        topo.expire_listen_adverts(now);
        let outcome = topo.merge_gossip(&msg);
        let changed = outcome.changed;
        (outcome, changed)
    };

    if outcome.self_disputed {
        // §6.3 反驳 + 自身身份冲突自检
        {
            let mut topo = state.topology.write();
            topo.bump_incarnation();
        }
        state.log("warn", "gossip", format!(
            "收到关于本机（{}）的错误描述，已提升世代号并重播",
            state.self_id()
        ));
        if !state.identity_conflict.swap(true, std::sync::atomic::Ordering::Relaxed) {
            state.emit(crate::events::HiveEvent::IdentityConflict {
                claimed_edges: msg.edges.len(),
                hint: format!(
                    "检测到另一节点声称的身份与本机相同（{}）。这通常意味着两台机器配了同一个 node.overlay_addr，请检查配置（§5.8、§6.3）。",
                    state.self_id()
                ),
            });
        }
        crate::gossip::broadcast_now(state, true).await;
    }

    // 反熵：对方有而我缺的，回 Pull
    for (owner, from_seq) in &outcome.need_pull {
        if let Ok(f) = control_frame(state, MsgType::Pull, msg.owner, &PullMsg { owner: *owner, from_seq: *from_seq }) {
            let _ = state.try_send_control_to(header.src, f);
            state.stats.pulls_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    if snapshot_needed {
        state.rebuild_router();
        state.rebuild_rules();
        state.refresh_aliases();
        state.emit_topology();
        if outcome.rules_updated {
            state.emit_rules();
            if let Some(rs) = state.topology.read().shared_rules.clone() {
                let src = state.alias_of(rs.publisher).unwrap_or_else(|| rs.publisher.to_string());
                state.log(
                    "info",
                    "rules",
                    format!("采纳共享规则集：来自 {src}，revision {}，{} 条", rs.revision, rs.rules.len()),
                );
            }
        }
    }

    // 变化驱动的 flood：dst 是 BROADCAST 时继续中继
    if header.dst == BROADCAST {
        let frame = frame.clone();
        relay(state, frame).await;
    }
}

async fn handle_pull(state: &Arc<HiveState>, payload: &[u8], from: NodeId) {
    let Ok(pull) = decode_payload::<PullMsg>(payload) else { return };
    let msg = crate::gossip::build_announcement(state).await;
    // 只补发对方要的那一份
    let reply = if msg.owner == pull.owner {
        Some(msg)
    } else if pull.owner == state.self_id() {
        Some(msg)
    } else {
        None
    };
    if let Some(m) = reply {
        if let Ok(f) = control_frame(state, MsgType::Gossip, from, &m) {
            let _ = state.try_send_control_to(from, f);
        }
    }
}

// ---------------------------------------------------------------------------
// 中继（§5.6、§8）
// ---------------------------------------------------------------------------

/// 中继一帧。唯一改动的字节是 TTL。
pub async fn relay(state: &Arc<HiveState>, mut frame: RawFrame) {
    // ★ 改进：ttl 减到 0 的帧不再白跑一跳（否则回执的 last_hop 会指错节点）
    if frame.header.ttl <= 1 {
        state.stats.frames_dropped_ttl.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        send_unreachable(state, frame.header.src, UnreachableReason::TtlExhausted).await;
        return;
    }

    let new_ttl = frame.decrement_ttl();
    let dst = frame.header.dst;
    let src = frame.header.src;
    let msg_type = frame.header.msg_type;
    let stream_id = frame.header.stream_id;

    let (header, payload) = frame.into_payload();
    let out = OutboundFrame::new(crate::proto::HiveHeader { ttl: new_ttl, ..header }, payload);

    state.stats.frames_relayed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // ★ 广播哨兵不能交给路由器 —— 它不在拓扑图里（§5.7、§6.3）。
    // 多跳扩散的语义就是"发给除来源之外的每一条直连链路"。
    if dst.is_broadcast() {
        let targets: Vec<NodeId> = state
            .links
            .iter()
            .map(|kv| *kv.key())
            .filter(|p| *p != src)
            .collect();
        for t in targets {
            let _ = state.try_send_control_to(t, out.clone());
        }
        return;
    }

    let res = if msg_type == MsgType::Data {
        state.send_to(dst, stream_id, out)
    } else {
        state.send_control_routed(dst, out)
    };

    match res {
        Ok(()) => {
            state
                .stats
                .bytes_relayed_out
                .fetch_add(0, std::sync::atomic::Ordering::Relaxed);
        }
        Err(SendFail::QueueFull) => {
            // 背压信号，不是故障（§5.5）：丢帧并计数。
            state.stats.frames_dropped_queue.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Err(SendFail::SelfLoop) => {}
        Err(SendFail::NoRoute) | Err(SendFail::LinkGone) => {
            state.rebuild_router();
            send_unreachable(state, src, UnreachableReason::NoRoute).await;
        }
    }
}

async fn send_unreachable(state: &Arc<HiveState>, src: NodeId, reason: UnreachableReason) {
    if src == state.self_id() {
        return;
    }
    let msg = UnreachableMsg { reason, last_hop: state.self_id() };
    if let Ok(f) = control_frame(state, MsgType::Unreachable, src, &msg) {
        let _ = state.send_control_routed(src, f);
    }
}

/// 解码一条控制帧载荷，失败时记日志（避免各处重复 unwrap）。
pub fn decode_or_log<T: serde::de::DeserializeOwned>(
    payload: &[u8],
    what: &str,
) -> Option<T> {
    match decode_payload::<T>(payload) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::debug!("{what} 解码失败: {e}");
            None
        }
    }
}

/// 供测试与调试：把一帧直接投给本机的分发逻辑。
pub async fn inject_local(state: Arc<HiveState>, frame: RawFrame) -> Result<(), ProtoError> {
    route_packet(state, frame).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{HiveHeader, ListenAdvert};
    use crate::testutil::nid;

    fn state_with(me: &str, cfg: crate::config::Config) -> Arc<HiveState> {
        let mut cfg = cfg;
        cfg.node.overlay_addr = Some(me.parse().unwrap());
        cfg.listen.bind = me.parse().unwrap();
        let id = Arc::new(crate::identity::NodeIdentity::resolve(&cfg).unwrap());
        HiveState::new(id, cfg)
    }

    #[tokio::test]
    async fn ttl_zero_is_dropped_with_an_unreachable_reply() {
        let st = state_with("10.0.0.1", crate::config::Config::default());
        let mut h = HiveHeader::new(
            MsgType::Data,
            nid("10.0.0.2"),
            nid("10.0.0.3"),
            0, // TTL 已经耗尽
        );
        h.stream_id = 9;
        let frame = RawFrame::build(h, b"x").unwrap();
        route_packet(st.clone(), frame).await;
        assert_eq!(
            st.stats.frames_dropped_ttl.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn ping_is_answered_with_pong() {
        let st = state_with("10.0.0.1", crate::config::Config::default());
        let peer = nid("10.0.0.2");
        let mut obs = crate::testutil::attach_link(&st, peer, crate::proto::Carrier::Direct).await;

        let f = RawFrame::build(HiveHeader::new(MsgType::Ping, peer, nid("10.0.0.1"), 1), b"").unwrap();
        route_packet(st.clone(), f).await;

        let got = crate::testutil::next_frame(&mut obs).await;
        assert_eq!(got.header.msg_type, MsgType::Pong, "Ping 必须被回成 Pong");
    }

    #[tokio::test]
    async fn gossip_merges_and_updates_segments() {
        let st = state_with("10.0.0.1", crate::config::Config::default());
        let peer = nid("10.4.0.9");
        let msg = GossipMsg {
            owner: peer,
            incarnation: 1,
            seq: 1,
            edges: vec![],
            subnets: vec![crate::proto::SubnetAd::any_port("10.4.0.0/24".parse().unwrap())],
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: Some("d-node".into()),
            rule_set: None,
            digest: vec![],
        };
        let payload = crate::proto::encode_payload(&msg).unwrap();
        let mut h = HiveHeader::new(MsgType::Gossip, peer, nid("10.0.0.1"), 4);
        h.flags |= crate::proto::flags::CONTROL;
        let frame = RawFrame::build(h, &payload).unwrap();
        route_packet(st.clone(), frame).await;

        assert_eq!(
            st.topology.read().segments_for_ip("10.4.0.7".parse().unwrap()),
            vec![peer]
        );
        assert_eq!(st.alias_of(peer).as_deref(), Some("d-node"));
    }

    #[tokio::test]
    async fn duplicate_gossip_is_ignored() {
        let st = state_with("10.0.0.1", crate::config::Config::default());
        let peer = nid("10.4.0.9");
        let msg = GossipMsg {
            owner: peer,
            incarnation: 1,
            seq: 7,
            edges: vec![],
            subnets: vec![],
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: None,
            digest: vec![],
        };
        let payload = crate::proto::encode_payload(&msg).unwrap();
        let mk = || {
            let mut h = HiveHeader::new(MsgType::Gossip, peer, nid("10.0.0.1"), 4);
            h.flags |= crate::proto::flags::CONTROL;
            RawFrame::build(h, &payload).unwrap()
        };
        route_packet(st.clone(), mk()).await;
        let before = st.topology.read().version;
        route_packet(st.clone(), mk()).await;
        assert_eq!(st.topology.read().version, before, "同一 (owner, seq) 不得重复合并");
    }

    #[tokio::test]
    async fn data_for_an_unknown_stream_is_dropped_without_panic() {
        let st = state_with("10.0.0.1", crate::config::Config::default());
        let mut h = HiveHeader::new(MsgType::Data, nid("10.0.0.2"), nid("10.0.0.1"), 4);
        h.stream_id = 12345;
        let frame = RawFrame::build(h, b"orphan").unwrap();
        route_packet(st.clone(), frame).await;
        assert!(st.streams.is_empty());
    }

    #[tokio::test]
    async fn relay_decrements_ttl_and_forwards() {
        let st = state_with("10.0.0.1", crate::config::Config::default());
        let next_hop = nid("10.0.0.3");
        let mut obs =
            crate::testutil::attach_link(&st, next_hop, crate::proto::Carrier::Direct).await;
        // 让本机认识"经下一跳去 10.0.0.9"
        {
            let mut topo = st.topology.write();
            let t = crate::testutil::topology(
                "10.0.0.1",
                &[("10.0.0.1", "10.0.0.3"), ("10.0.0.3", "10.0.0.9")],
                &[],
                &[],
            );
            for (k, v) in t.adjacency {
                topo.adjacency.insert(k, v);
            }
            topo.version += 1;
        }
        st.rebuild_router();

        let mut h = HiveHeader::new(MsgType::Data, nid("10.0.0.2"), nid("10.0.0.9"), 5);
        h.stream_id = 42;
        let frame = RawFrame::build(h, b"relay me").unwrap();
        route_packet(st.clone(), frame).await;

        let got = crate::testutil::next_frame(&mut obs).await;
        assert_eq!(got.header.ttl, 4, "中继必须把 TTL 减 1");
        assert_eq!(got.header.dst, nid("10.0.0.9"), "dst 保持最终目标不变");
        assert_eq!(got.header.src, nid("10.0.0.2"), "src 也不得被改写（§5.6）");
        assert_eq!(got.payload(), b"relay me", "载荷必须原样透传");
    }

    #[tokio::test]
    async fn relay_at_ttl_one_replies_unreachable_instead_of_forwarding() {
        let st = state_with("10.0.0.1", crate::config::Config::default());
        let mut obs = crate::testutil::attach_link(
            &st,
            nid("10.0.0.2"),
            crate::proto::Carrier::Direct,
        )
        .await;
        {
            let mut topo = st.topology.write();
            let t = crate::testutil::topology(
                "10.0.0.1",
                &[("10.0.0.1", "10.0.0.2"), ("10.0.0.2", "10.0.0.9")],
                &[],
                &[],
            );
            for (k, v) in t.adjacency {
                topo.adjacency.insert(k, v);
            }
            topo.version += 1;
        }
        st.rebuild_router();

        let mut h = HiveHeader::new(MsgType::Data, nid("10.0.0.2"), nid("10.0.0.9"), 1);
        h.stream_id = 7;
        route_packet(st.clone(), RawFrame::build(h, b"x").unwrap()).await;

        let got = crate::testutil::next_frame(&mut obs).await;
        assert_eq!(
            got.header.msg_type,
            MsgType::Unreachable,
            "TTL 只剩 1 时应当就地回 Unreachable，而不是白跑一跳"
        );
    }
}
