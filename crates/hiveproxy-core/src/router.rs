//! L3 路由层：拓扑图 + Dijkstra 选路（DESIGN.md §6.3、§3.4）。
//!
//! 图用 `petgraph::stable_graph::StableDiGraph`；选路用**每节点保留 2 个"不同首跳"标签**
//! 的 Dijkstra —— 最小值标签保证主路径正确，第二个标签提供 `alt`（次优下一跳，写失败时
//! 立即切换，不等下一轮 gossip）。

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;

use crate::config::CostCfg;
use crate::proto::{AdjEntry, Carrier, NodeId};
use crate::topology::Topology;

/// 缓存的选路结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachedRoute {
    pub next_hop: NodeId,
    pub cost: u32,
    pub hops: u8,
    /// 次优下一跳：主路径写失败时立即切换（§3.4）。
    pub alt: Option<NodeId>,
}

/// 每个节点保留的标签数（1 个主 + 1 个 alt）。
const K: usize = 2;

pub struct Router {
    graph: StableDiGraph<NodeId, u32>,
    index: HashMap<NodeId, NodeIndex>,
    cache: HashMap<NodeId, CachedRoute>,
    version: u64,
    self_id: NodeId,
}

impl Router {
    pub fn new(self_id: NodeId) -> Self {
        let mut graph = StableDiGraph::new();
        let mut index = HashMap::new();
        let idx = graph.add_node(self_id);
        index.insert(self_id, idx);
        Self { graph, index, cache: HashMap::new(), version: 0, self_id }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn graph(&self) -> &StableDiGraph<NodeId, u32> {
        &self.graph
    }

    /// 拓扑版本变化时重建图并失效缓存。
    pub fn rebuild(&mut self, topo: &Topology, cost: &CostCfg) {
        self.graph.clear();
        self.index.clear();
        self.cache.clear();
        self.version = topo.version;

        let me = self.graph.add_node(self.self_id);
        self.index.insert(self.self_id, me);

        let ensure = |g: &mut StableDiGraph<NodeId, u32>,
                      idx: &mut HashMap<NodeId, NodeIndex>,
                      id: NodeId| {
            *idx.entry(id).or_insert_with(|| g.add_node(id))
        };

        // 收集全部弧。同一条边会从两端各被声明一次（`owner -> peer`），
        // 且**一次成功的单向拨号得到的会话双向可用**（§3.1），所以两个方向都要加，
        // 权重相同。先去重再建图，避免平行边。
        let mut arcs: HashMap<(NodeId, NodeId), u32> = HashMap::new();
        let mut owners: Vec<NodeId> = topo.adjacency.keys().copied().collect();
        owners.sort();

        for owner in owners {
            let Some(adj) = topo.adjacency.get(&owner) else { continue };
            for e in &adj.edges {
                if e.peer == owner || e.peer == crate::proto::BROADCAST {
                    continue;
                }
                let w = arc_weight(e, cost);
                for (a, b) in [(owner, e.peer), (e.peer, owner)] {
                    let key = (a, b);
                    let slot = arcs.entry(key).or_insert(w);
                    if w < *slot {
                        *slot = w;
                    }
                }
            }
        }

        let mut keys: Vec<(NodeId, NodeId)> = arcs.keys().copied().collect();
        keys.sort();
        for (a, b) in keys {
            let w = arcs[&(a, b)];
            let ia = ensure(&mut self.graph, &mut self.index, a);
            let ib = ensure(&mut self.graph, &mut self.index, b);
            self.graph.add_edge(ia, ib, w);
        }

        self.compute_labels();
    }

    /// 懒加载：只在拓扑版本变化时重算。
    pub fn ensure_fresh(&mut self, topo: &Topology, cost: &CostCfg) {
        if self.version != topo.version {
            self.rebuild(topo, cost);
        }
    }

    /// 到 `dst` 的最低成本。`None` = 不可达。
    pub fn cost_to(&self, dst: NodeId) -> Option<u32> {
        self.cache.get(&dst).map(|r| r.cost)
    }

    pub fn route_to(&self, dst: NodeId) -> Option<&CachedRoute> {
        self.cache.get(&dst)
    }

    /// 下一跳（含 `alt`）。
    pub fn next_hop(&self, dst: NodeId) -> Option<&CachedRoute> {
        self.cache.get(&dst)
    }

    pub fn reachable_count(&self) -> usize {
        self.cache.len()
    }

    fn compute_labels(&mut self) {
        // labels[node] = 最多 K 个 (cost, first_hop, hops)，first_hop 互不相同。
        let mut labels: HashMap<NodeId, Vec<(u32, NodeId, u8)>> = HashMap::new();
        let mut heap: BinaryHeap<Reverse<(u32, u8, NodeId, NodeId)>> = BinaryHeap::new();

        labels.entry(self.self_id).or_default().push((0, self.self_id, 0));
        heap.push(Reverse((0, 0, self.self_id, self.self_id)));

        while let Some(Reverse((cost, hops, node, first))) = heap.pop() {
            // 陈旧的堆项：只有当它仍是我们记录过的标签时才展开
            let fresh = labels
                .get(&node)
                .map(|ls| ls.iter().any(|(c, f, _)| *c == cost && *f == first))
                .unwrap_or(false);
            if !fresh {
                continue;
            }

            let Some(&idx) = self.index.get(&node) else { continue };
            let mut neighbors: Vec<(NodeId, u32)> = self
                .graph
                .neighbors(idx)
                .filter_map(|n| {
                    let w = self.graph.edge_weight(self.graph.find_edge(idx, n)?)?;
                    Some((self.graph[n], *w))
                })
                .collect();
            neighbors.sort();

            for (peer, w) in neighbors {
                let next_first = if node == self.self_id { peer } else { first };
                let nc = cost.saturating_add(w);
                let nh = hops.saturating_add(1);
                if insert_label(labels.entry(peer).or_default(), nc, next_first, nh) {
                    heap.push(Reverse((nc, nh, peer, next_first)));
                }
            }
        }

        self.cache.clear();
        for (node, ls) in labels {
            if node == self.self_id {
                continue;
            }
            let mut sorted = ls;
            sorted.sort_by_key(|(c, f, _)| (*c, *f));
            let Some(&(best_cost, best_first, best_hops)) = sorted.first() else { continue };
            let alt = sorted.iter().skip(1).find(|(_, f, _)| *f != best_first).map(|(_, f, _)| *f);
            self.cache.insert(
                node,
                CachedRoute { next_hop: best_first, cost: best_cost, hops: best_hops, alt },
            );
        }
    }
}

/// 把新标签插进该节点的标签表；返回是否插入了（需要继续展开）。
fn insert_label(ls: &mut Vec<(u32, NodeId, u8)>, cost: u32, first: NodeId, hops: u8) -> bool {
    ls.sort_by_key(|(c, f, _)| (*c, *f));
    if let Some(pos) = ls.iter().position(|(_, f, _)| *f == first) {
        if cost >= ls[pos].0 {
            return false;
        }
        ls[pos] = (cost, first, hops);
        return true;
    }
    if ls.len() < K {
        ls.push((cost, first, hops));
        return true;
    }
    // 已经满了：只有当它比最差的那条更好才顶替
    let worst = ls.iter().enumerate().max_by_key(|(_, (c, f, _))| (*c, *f)).map(|(i, _)| i);
    match worst {
        Some(i) if cost < ls[i].0 => {
            ls[i] = (cost, first, hops);
            true
        }
        _ => false,
    }
}

/// 单条边的权重（§6.3）：`carrier_base + rtt_penalty`。
/// 每跳成本由 Dijkstra 沿路径自然累加。
pub fn arc_weight(e: &AdjEntry, cost: &CostCfg) -> u32 {
    let base = match e.carrier {
        Carrier::Lan => cost.lan,
        Carrier::Direct => cost.wan,
    } as u32;
    let rtt_penalty = (e.rtt_ms as u32) / 10;
    base.saturating_add(rtt_penalty).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ListenAdvert;
    use crate::topology::Topology;

    fn nid(s: &str) -> NodeId {
        s.parse().unwrap()
    }

    fn e(peer: NodeId, carrier: Carrier, rtt: u16) -> AdjEntry {
        AdjEntry { peer, cost: 1, carrier, rtt_ms: rtt }
    }

    /// 构建一条链 A-B-C-D…，每条边双向可达（会话复用语义）。
    fn chain(ids: &[&str], carriers: &[Carrier]) -> Topology {
        let nodes: Vec<NodeId> = ids.iter().map(|s| nid(s)).collect();
        let mut t = Topology::new(nodes[0]);
        for (i, &n) in nodes.iter().enumerate() {
            let mut edges = Vec::new();
            if i > 0 {
                edges.push(e(nodes[i - 1], carriers[i - 1], 1));
            }
            if i + 1 < nodes.len() {
                edges.push(e(nodes[i + 1], carriers[i], 1));
            }
            t.merge_gossip(&crate::proto::GossipMsg {
                owner: n,
                incarnation: 1,
                seq: 1,
                edges,
                subnets: Vec::new(),
                listen: ListenAdvert::default(),
                accepts_egress: true,
                alias: None,
                rule_set: None,
                digest: Vec::new(),
            });
        }
        t
    }

    fn cost() -> CostCfg {
        CostCfg::default()
    }

    #[test]
    fn three_node_chain_routes_through_the_middle() {
        let t = chain(&["10.0.0.1", "10.0.0.2", "10.0.0.3"], &[Carrier::Direct, Carrier::Direct]);
        let mut r = Router::new(nid("10.0.0.1"));
        r.rebuild(&t, &cost());
        let route = r.next_hop(nid("10.0.0.3")).expect("A 应当能到 C");
        assert_eq!(route.next_hop, nid("10.0.0.2"));
        assert_eq!(route.hops, 2);
    }

    #[test]
    fn four_node_chain_is_routable() {
        // 这是本轮修订的核心回归：纯一跳 gossip 只能看到 2 跳邻域，
        // A 根本不认识 D。有了完整拓扑后 A 必须能算出 A→D 的路。
        let t = chain(
            &["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            &[Carrier::Direct, Carrier::Direct, Carrier::Direct],
        );
        let mut r = Router::new(nid("10.0.0.1"));
        r.rebuild(&t, &cost());
        let route = r.next_hop(nid("10.0.0.4")).expect("四节点链上 A 必须能到 D");
        assert_eq!(route.next_hop, nid("10.0.0.2"));
        assert_eq!(route.hops, 3);
        assert_eq!(r.reachable_count(), 3);
    }

    #[test]
    fn eight_hop_chain_still_routes() {
        let ids: Vec<String> = (1..=8).map(|i| format!("10.0.0.{i}")).collect();
        let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        let carriers = vec![Carrier::Direct; 7];
        let t = chain(&refs, &carriers);
        let mut r = Router::new(nid("10.0.0.1"));
        r.rebuild(&t, &cost());
        let route = r.next_hop(nid("10.0.0.8")).expect("Ttl=8 之内的长链必须可路由");
        assert_eq!(route.hops, 7);
    }

    #[test]
    fn lan_is_preferred_over_wan() {
        // A 有两条到 D 的路：直连（wan）与经 B（lan）。
        let a = nid("10.0.0.1");
        let b = nid("10.0.0.2");
        let d = nid("10.0.0.4");
        let mut t = Topology::new(a);
        let mk = |owner: NodeId, edges: Vec<AdjEntry>| crate::proto::GossipMsg {
            owner,
            incarnation: 1,
            seq: 1,
            edges,
            subnets: Vec::new(),
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: None,
            digest: Vec::new(),
        };
        t.merge_gossip(&mk(a, vec![e(d, Carrier::Direct, 1), e(b, Carrier::Lan, 1)]));
        t.merge_gossip(&mk(b, vec![e(a, Carrier::Lan, 1), e(d, Carrier::Lan, 1)]));
        t.merge_gossip(&mk(d, vec![e(a, Carrier::Direct, 1), e(b, Carrier::Lan, 1)]));

        let mut r = Router::new(a);
        r.rebuild(&t, &cost());
        let route = r.next_hop(d).unwrap();
        assert_eq!(route.next_hop, b, "应当选同网段那一跳（§6.3 边权重直觉）");
    }

    #[test]
    fn alt_is_recorded_when_two_disjoint_first_hops_exist() {
        // A 经 B 和经 C 都能到 D —— 两条首跳互不相同。
        let a = nid("10.0.0.1");
        let b = nid("10.0.0.2");
        let c = nid("10.0.0.3");
        let d = nid("10.0.0.4");
        let mut t = Topology::new(a);
        let mk = |owner: NodeId, edges: Vec<AdjEntry>| crate::proto::GossipMsg {
            owner,
            incarnation: 1,
            seq: 1,
            edges,
            subnets: Vec::new(),
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: None,
            digest: Vec::new(),
        };
        t.merge_gossip(&mk(a, vec![e(b, Carrier::Lan, 1), e(c, Carrier::Lan, 1)]));
        t.merge_gossip(&mk(b, vec![e(a, Carrier::Lan, 1), e(d, Carrier::Lan, 1)]));
        t.merge_gossip(&mk(c, vec![e(a, Carrier::Lan, 1), e(d, Carrier::Lan, 1)]));
        t.merge_gossip(&mk(d, vec![e(b, Carrier::Lan, 1), e(c, Carrier::Lan, 1)]));

        let mut r = Router::new(a);
        r.rebuild(&t, &cost());
        let route = r.next_hop(d).unwrap();
        assert_eq!(route.next_hop, b, "成本相同时按首跳字节序稳定裁决");
        assert_eq!(route.alt, Some(c), "必须记下次优下一跳，供写失败时立即切换（§3.4）");
    }

    #[test]
    fn unreachable_peer_has_no_route() {
        let a = nid("10.0.0.1");
        let iso = nid("10.9.9.9");
        let mut t = Topology::new(a);
        let mk = |owner: NodeId, edges: Vec<AdjEntry>| crate::proto::GossipMsg {
            owner,
            incarnation: 1,
            seq: 1,
            edges,
            subnets: Vec::new(),
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: None,
            digest: Vec::new(),
        };
        t.merge_gossip(&mk(a, vec![]));
        t.merge_gossip(&mk(iso, vec![]));
        let mut r = Router::new(a);
        r.rebuild(&t, &cost());
        assert!(r.next_hop(iso).is_none(), "孤岛节点不可达");
        assert!(r.cost_to(iso).is_none());
    }

    #[test]
    fn cache_invalidates_on_topology_change() {
        let t = chain(&["10.0.0.1", "10.0.0.2", "10.0.0.3"], &[Carrier::Direct, Carrier::Direct]);
        let mut r = Router::new(nid("10.0.0.1"));
        r.ensure_fresh(&t, &cost());
        let v1 = r.version();
        assert!(r.next_hop(nid("10.0.0.3")).is_some());

        // 版本没变 → 不重建
        r.ensure_fresh(&t, &cost());
        assert_eq!(r.version(), v1);

        // 版本变了 → 重建
        let mut t2 = t;
        t2.lose_peer(nid("10.0.0.2"));
        r.ensure_fresh(&t2, &cost());
        assert_ne!(r.version(), v1);
        assert!(r.next_hop(nid("10.0.0.3")).is_none(), "中间节点掉线后不可达");
    }

    #[test]
    fn self_loop_and_broadcast_edges_are_ignored() {
        let a = nid("10.0.0.1");
        let mut t = Topology::new(a);
        t.merge_gossip(&crate::proto::GossipMsg {
            owner: a,
            incarnation: 1,
            seq: 1,
            edges: vec![e(a, Carrier::Lan, 1), e(crate::proto::BROADCAST, Carrier::Lan, 1)],
            subnets: Vec::new(),
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: None,
            digest: Vec::new(),
        });
        let mut r = Router::new(a);
        r.rebuild(&t, &cost());
        assert_eq!(r.reachable_count(), 0);
    }
}
