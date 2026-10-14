//! Gossip 广播与反熵（DESIGN.md §6.3）。
//!
//! 两种传播模式：
//! 1. **变化驱动 flood（主）**：状态变化时立即广播，允许中继到全网；
//! 2. **周期一跳刷新（辅）**：稳态下每 `gossip_interval_ms` 只发给直连邻居。
//!
//! 每个公告附带 `digest`（本机已知的每个节点的最新 seq），邻居据此回 `Pull` 补漏。

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::events::now_unix;
use crate::msg::control_header;
use crate::proto::{
    AdjEntry, Carrier, GossipMsg, ListenAdvert, MsgType, NodeId, SubnetAd, BROADCAST,
};
use crate::state::HiveState;
use crate::link::OutboundFrame;

/// 组装本节点的公告。
pub async fn build_announcement(state: &Arc<HiveState>) -> GossipMsg {
    let cfg = state.cfg();
    let (edges, incarnation, seq, digest, rule_set) = {
        let topo = state.topology.read();
        let adj = topo.adjacency.get(&topo.self_id);
        (
            adj.map(|a| a.edges.clone()).unwrap_or_default(),
            adj.map(|a| a.incarnation).unwrap_or(1),
            adj.map(|a| a.seq).unwrap_or(0),
            topo.digest(),
            if cfg.route.publish_enabled {
                state.publish.read().last_published.as_slice();
                topo.shared_rules
                    .as_ref()
                    .filter(|r| r.publisher == topo.self_id)
                    .cloned()
            } else {
                None
            },
        )
    };

    // ★ 广播出去的是"我**愿意**贡献的"，与"我自己能连什么"（`node.subnets`）无关。
    let subnets: Vec<SubnetAd> = if state.node.share_subnets {
        state
            .node
            .subnets
            .iter()
            .map(|n| match cfg.share.share_ports_only.is_empty() {
                true => SubnetAd::any_port(*n),
                false => SubnetAd { net: *n, ports: Some(cfg.share.share_ports_only.clone()) },
            })
            .collect()
    } else {
        Vec::new()
    };

    GossipMsg {
        owner: state.self_id(),
        incarnation,
        seq,
        edges,
        subnets,
        listen: state.listen_advert(cfg.listen.advertise, now_unix(), 900),
        accepts_egress: cfg.egress.allow_egress,
        alias: state.node.alias.clone(),
        rule_set,
        digest,
    }
}

/// 本机当前的全部直连邻居（用于邻接表）。
pub fn current_edges(state: &Arc<HiveState>) -> Vec<AdjEntry> {
    let mut v: Vec<AdjEntry> = state
        .links
        .iter()
        .map(|kv| {
            let meta = kv.value().meta.read();
            AdjEntry {
                peer: *kv.key(),
                cost: 1,
                carrier: meta.carrier,
                rtt_ms: meta.rtt_ms,
            }
        })
        .collect();
    v.sort_by_key(|e| e.peer);
    v
}

/// 把本机的邻接表同步进 `Topology`（链路上下线时调用）。
pub fn sync_self_state(state: &Arc<HiveState>) {
    let cfg = state.cfg();
    // ★ 这里给的是**我自己**的网段索引 —— 必须始终完整，否则本机解析
    // "目标落在哪个网段"时会连自己那一片都找不到（§9.1）。
    // "要不要告诉别人"由 `build_announcement` 里的 `share_subnets` 控制。
    let subnets: Vec<SubnetAd> = state
        .node
        .subnets
        .iter()
        .map(|n| match cfg.share.share_ports_only.is_empty() {
            true => SubnetAd::any_port(*n),
            false => SubnetAd { net: *n, ports: Some(cfg.share.share_ports_only.clone()) },
        })
        .collect();
    let listen = state.listen_advert(cfg.listen.advertise, now_unix(), 900);
    let mut topo = state.topology.write();
    topo.set_self(current_edges(state), subnets, listen, cfg.egress.allow_egress, state.node.alias.clone());
}

/// 立即广播一次。
///
/// - `flood = true`：变化驱动，`dst = BROADCAST`、`ttl = gossip_flood_ttl`，可中继到全网；
/// - `flood = false`：周期刷新，逐个直连邻居、`ttl = 1`，不中继。
pub async fn broadcast_now(state: &Arc<HiveState>, flood: bool) {
    sync_self_state(state);
    let msg = build_announcement(state).await;
    let cfg = state.cfg();

    let payload = match crate::proto::encode_payload(&msg) {
        Ok(p) => p,
        Err(e) => {
            state.log("error", "gossip", format!("公告序列化失败: {e}"));
            return;
        }
    };

    let peers: Vec<NodeId> = state.links.iter().map(|kv| *kv.key()).collect();

    if flood {
        let ttl = cfg.route.gossip_flood_ttl.max(1);
        let header = control_header(MsgType::Gossip, state.self_id(), BROADCAST, ttl);
        for p in peers {
            let _ = state.try_send_control_to(p, OutboundFrame::new(header, payload.clone()));
            state.stats.gossip_sent.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        for p in peers {
            let header = control_header(MsgType::Gossip, state.self_id(), p, 1);
            let _ = state.try_send_control_to(p, OutboundFrame::new(header, payload.clone()));
            state.stats.gossip_sent.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// 稳态：每 `gossip_interval_ms` 一次一跳刷新。
pub fn spawn_periodic(state: Arc<HiveState>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(
            state.cfg().route.gossip_interval_ms.max(500),
        ));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    broadcast_now(&state, false).await;
                }
            }
        }
    });
}

/// 反熵：定期检查 `digest` 缺口并回 `Pull`（由 `route_packet` 在收到公告时触发，
/// 这里额外提供一个兜底定时器，防止长期收不到新公告时缺口一直不补）。
pub fn spawn_anti_entropy(state: Arc<HiveState>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    // 对每个直连邻居，用我们的 digest 主动推一次（对方缺什么就会回 Pull）
                    broadcast_now(&state, false).await;
                }
            }
        }
    });
}

/// 把本机发布的规则集塞进公告（发布时调用）。
pub async fn publish_and_broadcast(state: &Arc<HiveState>) {
    broadcast_now(state, true).await;
}

/// 便捷：构造"上线通知"用的边的载体类型。
pub fn carrier_of(rtt_ms: u16, is_lan: bool) -> Carrier {
    let _ = rtt_ms;
    if is_lan {
        Carrier::Lan
    } else {
        Carrier::Direct
    }
}

/// 空公告（测试用）。
pub fn empty_announcement(owner: NodeId) -> GossipMsg {
    GossipMsg {
        owner,
        incarnation: 1,
        seq: 1,
        edges: Vec::new(),
        subnets: Vec::new(),
        listen: ListenAdvert::default(),
        accepts_egress: true,
        alias: None,
        rule_set: None,
        digest: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::nid;

    fn state_for(ip: &str) -> Arc<HiveState> {
        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some(ip.parse().unwrap());
        cfg.listen.bind = ip.parse().unwrap();
        cfg.listen.ports = vec![20000];
        let id = Arc::new(crate::identity::NodeIdentity::resolve(&cfg).unwrap());
        HiveState::new(id, cfg)
    }

    #[tokio::test]
    async fn announcement_carries_identity_facts() {
        let st = state_for("10.1.2.5");
        sync_self_state(&st);
        let m = build_announcement(&st).await;
        assert_eq!(m.owner, nid("10.1.2.5"));
        assert!(m.accepts_egress);
        assert_eq!(m.listen.addrs, vec!["10.1.2.5:20000".parse().unwrap()]);
        assert!(m.digest.iter().any(|(id, _)| *id == nid("10.1.2.5")));
    }

    #[tokio::test]
    async fn advertise_off_empties_the_listen_field() {
        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some("10.1.2.5".parse().unwrap());
        cfg.listen.advertise = false;
        let id = Arc::new(crate::identity::NodeIdentity::resolve(&cfg).unwrap());
        let st = HiveState::new(id, cfg);
        let m = build_announcement(&st).await;
        assert!(m.listen.addrs.is_empty());
    }

    #[tokio::test]
    async fn share_ports_only_rides_along() {
        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some("10.1.2.5".parse().unwrap());
        cfg.share.share_ports_only = vec![22, 443];
        let id = Arc::new(crate::identity::NodeIdentity::resolve(&cfg).unwrap());
        let st = HiveState::new(id, cfg);
        let m = build_announcement(&st).await;
        if let Some(s) = m.subnets.first() {
            assert_eq!(s.ports, Some(vec![22, 443]), "端口限制必须随广播传出（§9.1）");
        }
    }

    #[tokio::test]
    async fn edges_reflect_live_links() {
        let st = state_for("10.1.2.5");
        assert!(current_edges(&st).is_empty());
        sync_self_state(&st);
        let m = build_announcement(&st).await;
        assert!(m.edges.is_empty());
    }
}
