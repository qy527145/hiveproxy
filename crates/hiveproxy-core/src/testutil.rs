//! 单元测试用的拓扑构造工具。仅 `#[cfg(test)]` 编译。

use crate::proto::{AdjEntry, Carrier, GossipMsg, ListenAdvert, NodeId, SubnetAd};
use crate::router::Router;
use crate::topology::Topology;
use crate::config::CostCfg;

pub fn nid(s: &str) -> NodeId {
    s.parse().expect("测试里的地址应当合法")
}

/// 构造一个拓扑。
///
/// - `edges`：双向可用的直连边（会话复用语义，§3.1）。每条边会同时写进两端的邻接表。
/// - `subnets`：各节点共享的网段。
/// - `deny_egress`：声明 `accepts_egress = false` 的节点（§9.4.4）。
pub fn topology(
    me: &str,
    edges: &[(&str, &str)],
    subnets: &[(&str, &str)],
    deny_egress: &[&str],
) -> Topology {
    let me_id = nid(me);
    let mut t = Topology::new(me_id);

    let mut nodes: Vec<NodeId> = vec![me_id];
    for (a, b) in edges {
        nodes.push(nid(a));
        nodes.push(nid(b));
    }
    for (n, _) in subnets {
        nodes.push(nid(n));
    }
    for n in deny_egress {
        nodes.push(nid(n));
    }
    nodes.sort();
    nodes.dedup();

    for node in nodes {
        let mut adj: Vec<AdjEntry> = Vec::new();
        for (a, b) in edges {
            let (a, b) = (nid(a), nid(b));
            if a == node {
                adj.push(AdjEntry { peer: b, cost: 1, carrier: Carrier::Direct, rtt_ms: 1 });
            } else if b == node {
                adj.push(AdjEntry { peer: a, cost: 1, carrier: Carrier::Direct, rtt_ms: 1 });
            }
        }
        let subs: Vec<SubnetAd> = subnets
            .iter()
            .filter(|(n, _)| nid(n) == node)
            .map(|(_, s)| SubnetAd::any_port(s.parse().expect("测试网段应当合法")))
            .collect();
        let deny = deny_egress.iter().any(|n| nid(n) == node);

        if node == me_id {
            // 自己不能走 merge_gossip —— 那条路径会（正确地）拒绝"别人对我的描述"。
            t.set_self(crate::topology::SelfAnnounce {
                edges: adj,
                subnets_index: subs.clone(),
                subnets_announced: subs,
                listen: ListenAdvert::default(),
                accepts_egress: !deny,
                alias: None,
            });
            continue;
        }

        t.merge_gossip(&GossipMsg {
            owner: node,
            incarnation: 1,
            seq: 1,
            edges: adj,
            subnets: subs,
            listen: ListenAdvert::default(),
            accepts_egress: !deny,
            alias: None,
            rule_set: None,
            digest: Vec::new(),
        });
    }
    t
}

/// 从拓扑构建一个已重建好的 Router。
pub fn router(me: &str, topo: &Topology) -> Router {
    let mut r = Router::new(nid(me));
    r.rebuild(topo, &CostCfg::default());
    r
}

/// 常用拓扑：`me -> 邻居 -> 邻居` 的链式拓扑，用来快速构造可达/不可达场景。
pub fn linked_chain(me: &str, others: &[&str]) -> Topology {
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut prev = me.to_string();
    for o in others {
        edges.push((prev.clone(), o.to_string()));
        prev = o.to_string();
    }
    let refs: Vec<(&str, &str)> = edges.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    topology(me, &refs, &[], &[])
}

// ---------------------------------------------------------------------------
// 运行期测试辅助
// ---------------------------------------------------------------------------

/// 给 `state` 装一条到 `peer` 的链路，返回**观察端**：
/// 链路写出的每一帧都会以线格式出现在这个 duplex 里。
pub async fn attach_link(
    state: &std::sync::Arc<crate::state::HiveState>,
    peer: NodeId,
    carrier: Carrier,
) -> tokio::io::DuplexStream {
    use std::time::Instant;
    let (wire, observe) = tokio::io::duplex(256 * 1024);
    let cancel = tokio_util::sync::CancellationToken::new();
    let (sender, _handle) = crate::link::spawn_link(wire, cancel.clone());

    let link = std::sync::Arc::new(crate::link::LinkHandle {
        peer,
        meta: parking_lot::RwLock::new(crate::proto::LinkMeta {
            establisher: crate::proto::Establisher::Local,
            carrier,
            rtt_ms: 1,
            health: crate::proto::Health::Up,
            since: Instant::now(),
        }),
        cancel,
        sender,
        session_id: 1,
        establisher: crate::proto::Establisher::Local,
        // 纯内存链路没有心跳任务（心跳只在 `register_link` 里起），账本留空即可。
        ping: parking_lot::Mutex::new(crate::link::PingState::default()),
    });
    state.links.insert(peer, link);
    observe
}

/// 从观察端读下一帧。
pub async fn next_frame(r: &mut tokio::io::DuplexStream) -> crate::proto::RawFrame {
    match tokio::time::timeout(std::time::Duration::from_secs(2), crate::proto::read_frame(r)).await {
        Ok(Ok(Some(f))) => f,
        Ok(Ok(None)) => { eprintln!("DBG: link closed early"); panic!("链路提前关闭") }
        Ok(Err(e)) => { eprintln!("DBG: read error {e:?}"); panic!("读帧失败") }
        Err(_) => { eprintln!("DBG: read timed out"); panic!("等帧超时") }
    }
}

/// 断言观察端在一小段时间内收不到任何帧。
pub async fn expect_no_frame(r: &mut tokio::io::DuplexStream) {
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), crate::proto::read_frame(r))
            .await
            .is_err(),
        "不该收到任何帧"
    );
}

/// 构造一个只用于测试的 HiveState。
pub fn state_for(ip: &str, mut cfg: crate::config::Config) -> std::sync::Arc<crate::state::HiveState> {
    cfg.node.overlay_addr = Some(ip.parse().expect("测试地址"));
    if cfg.listen.bind.is_unspecified() {
        cfg.listen.bind = ip.parse().expect("测试地址");
    }
    let id = std::sync::Arc::new(crate::identity::NodeIdentity::resolve(&cfg).expect("身份解析"));
    crate::state::HiveState::new(id, cfg)
}
