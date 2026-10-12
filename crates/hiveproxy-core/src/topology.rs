//! 拓扑存储与 gossip 合并（DESIGN.md §6.3）。
//!
//! `Topology` 是**唯一权威源**：邻接表、网段索引、监听端点、共享规则集都在这里。
//! `Router` 与 `RuleTable` 都是从它派生出来的缓存（§6.8）。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ipnet::IpNet;

use crate::proto::{
    AdjEntry, GossipMsg, ListenAdvert, NodeId, NodeMeta, RuleSetAd, SubnetAd, BROADCAST,
};

/// owner 声明的直接邻居。
#[derive(Clone, Debug)]
pub struct PeerAdj {
    pub incarnation: u64,
    pub seq: u64,
    pub edges: Vec<AdjEntry>,
    pub updated_at: Instant,
}

/// 一次 gossip 合并的结果。
#[derive(Default, Debug)]
pub struct MergeOutcome {
    /// 本地拓扑是否真的变了（变了就要重建路由与规则表）。
    pub changed: bool,
    /// 有人在描述**我自己**且描述与实际不符 → 需要 `incarnation += 1` 并立即重播（§6.3）。
    pub self_disputed: bool,
    /// 反熵：对方有而我这里缺失/更旧的 `(owner, seq)`，应当回 `Pull`（§6.3）。
    pub need_pull: Vec<(NodeId, u64)>,
    /// 收到了一份更新的共享规则集。
    pub rules_updated: bool,
}

pub struct Topology {
    /// `owner -> 它声明的邻居`（含**自己**）。
    pub adjacency: HashMap<NodeId, PeerAdj>,
    pub peers: HashMap<NodeId, NodeMeta>,
    /// 网段 → 能直达它的节点集合（§9.1）。这是唯一"谁能到哪"索引。
    pub segments: HashMap<IpNet, Vec<NodeId>>,
    /// 各节点广播的入向监听端点（§6.5）。
    pub listen_addrs: HashMap<NodeId, ListenAdvert>,
    /// 当前生效的共享规则集（LWW，§9.4.3）。
    pub shared_rules: Option<RuleSetAd>,

    /// 任一变化即自增，用于路由缓存与规则表失效。
    pub version: u64,
    pub self_id: NodeId,
    /// 本机共享的网段（供 `digest` 与自检使用）。
    pub self_subnets: Vec<IpNet>,
}

impl Topology {
    pub fn new(self_id: NodeId) -> Self {
        Self {
            adjacency: HashMap::new(),
            peers: HashMap::new(),
            segments: HashMap::new(),
            listen_addrs: HashMap::new(),
            shared_rules: None,
            version: 1,
            self_id,
            self_subnets: Vec::new(),
        }
    }

    fn bump(&mut self) -> bool {
        self.version += 1;
        true
    }

    /// 更新**自己**的公告内容。链路上下线、网段变化时调用。
    pub fn set_self(
        &mut self,
        edges: Vec<AdjEntry>,
        subnets: Vec<SubnetAd>,
        listen: ListenAdvert,
        accepts_egress: bool,
        alias: Option<String>,
    ) {
        self.self_subnets = subnets.iter().map(|s| s.net).collect();

        // 自己也进监听端点表 —— 否则本机网段（SELF 成本 0）在候选集里缺少端点信息。
        self.listen_addrs.insert(self.self_id, listen);

        let entry = self.adjacency.entry(self.self_id).or_insert_with(|| PeerAdj {
            incarnation: 1,
            seq: 0,
            edges: Vec::new(),
            updated_at: Instant::now(),
        });
        let edges_changed = !same_edges(&entry.edges, &edges);
        entry.edges = edges;
        entry.updated_at = Instant::now();
        if edges_changed {
            entry.seq += 1;
        }

        self.peers.insert(
            self.self_id,
            NodeMeta {
                alias,
                accepts_egress,
                last_seen: Instant::now(),
                incarnation: entry.incarnation,
            },
        );

        self.rebuild_segments();
        self.bump();
    }

    /// 自己的世代号（反驳时 +1）。
    pub fn incarnation(&self) -> u64 {
        self.adjacency.get(&self.self_id).map(|a| a.incarnation).unwrap_or(1)
    }

    pub fn bump_incarnation(&mut self) {
        let e = self.adjacency.entry(self.self_id).or_insert_with(|| PeerAdj {
            incarnation: 1,
            seq: 0,
            edges: Vec::new(),
            updated_at: Instant::now(),
        });
        e.incarnation += 1;
        e.seq = 0;
        self.bump();
    }

    pub fn self_seq(&self) -> u64 {
        self.adjacency.get(&self.self_id).map(|a| a.seq).unwrap_or(0)
    }

    /// 合并一条 Gossip 公告（§6.3）。
    pub fn merge_gossip(&mut self, msg: &GossipMsg) -> MergeOutcome {
        let mut out = MergeOutcome::default();

        // ---- 1. 反驳检查：有人在描述我，且描述不对 ----
        if msg.owner == self.self_id {
            let mine = self.adjacency.get(&self.self_id);
            let disagree = match mine {
                Some(a) => !same_edges(&a.edges, &msg.edges),
                None => !msg.edges.is_empty(),
            };
            if disagree {
                out.self_disputed = true;
            }
            // 无论如何都不接受别人对我的描述。
            return out;
        }

        if msg.owner == BROADCAST {
            return out; // 哨兵不得作为 owner
        }

        // ---- 2. 反熵摘要比对 ----
        for (owner, seq) in &msg.digest {
            let local = self.adjacency.get(owner).map(|a| a.seq);
            if local.map(|l| *seq > l).unwrap_or(true) {
                out.need_pull.push((*owner, local.unwrap_or(0)));
            }
        }

        // ---- 3. 邻接表：incarnation / seq 的新旧判定 ----
        let accept_edges = match self.adjacency.get(&msg.owner) {
            None => true,
            Some(cur) => {
                msg.incarnation > cur.incarnation
                    || (msg.incarnation == cur.incarnation && msg.seq > cur.seq)
            }
        };

        if accept_edges {
            let changed = self
                .adjacency
                .get(&msg.owner)
                .map(|a| !same_edges(&a.edges, &msg.edges))
                .unwrap_or(true);
            self.adjacency.insert(
                msg.owner,
                PeerAdj {
                    incarnation: msg.incarnation,
                    seq: msg.seq,
                    edges: msg.edges.clone(),
                    updated_at: Instant::now(),
                },
            );
            if changed {
                out.changed = true;
            }
        }

        // ---- 4. 监听端点 ----
        let old_listen = self.listen_addrs.get(&msg.owner).cloned();
        if old_listen.as_ref().map(|l| l.addrs != msg.listen.addrs).unwrap_or(true) {
            self.listen_addrs.insert(msg.owner, msg.listen.clone());
            out.changed = true;
        }

        // ---- 5. 共享规则集：整份 LWW ----
        if let Some(rs) = &msg.rule_set {
            let take = match &self.shared_rules {
                None => true,
                Some(cur) => rs.supersedes(cur),
            };
            if take {
                self.shared_rules = Some(rs.clone());
                out.changed = true;
                out.rules_updated = true;
            }
        }

        // ---- 6. 节点元信息 ----
        let incarnation = self.adjacency.get(&msg.owner).map(|a| a.incarnation).unwrap_or(0);
        self.peers.insert(
            msg.owner,
            NodeMeta {
                alias: msg.alias.clone(),
                accepts_egress: msg.accepts_egress,
                last_seen: Instant::now(),
                incarnation,
            },
        );

        // ---- 7. 网段索引 ----
        if self.apply_subnets(msg.owner, &msg.subnets) {
            out.changed = true;
        }

        if out.changed {
            self.bump();
        }
        out
    }

    /// 把某节点声明的网段并入索引。返回是否发生变化。
    fn apply_subnets(&mut self, owner: NodeId, subnets: &[SubnetAd]) -> bool {
        let mut changed = false;
        let want: Vec<IpNet> = subnets.iter().map(|s| s.net).collect();

        // 先摘掉该 owner 此前声明、现在不再声明的网段
        for (net, owners) in self.segments.iter_mut() {
            if !want.contains(net) {
                let before = owners.len();
                owners.retain(|o| *o != owner);
                if owners.len() != before {
                    changed = true;
                }
            }
        }
        self.segments.retain(|_, owners| !owners.is_empty());

        for net in want {
            let owners = self.segments.entry(net).or_default();
            if !owners.contains(&owner) {
                owners.push(owner);
                owners.sort();
                changed = true;
            }
        }
        changed
    }

    fn rebuild_segments(&mut self) {
        // 重建时不丢弃别人声明的网段，只刷新自己那一份。
        let mine: Vec<IpNet> = self.self_subnets.clone();
        let mut all: Vec<(NodeId, IpNet)> = Vec::new();
        for (net, owners) in &self.segments {
            for o in owners {
                if *o != self.self_id {
                    all.push((*o, *net));
                }
            }
        }
        self.segments.clear();
        for (o, net) in all {
            self.segments.entry(net).or_default().push(o);
        }
        for net in mine {
            let owners = self.segments.entry(net).or_default();
            if !owners.contains(&self.self_id) {
                owners.push(self.self_id);
                owners.sort();
            }
        }
    }

    /// 链路断开：摘掉该 peer 的邻接表、网段与监听端点。
    pub fn lose_peer(&mut self, peer: NodeId) {
        self.adjacency.remove(&peer);
        self.listen_addrs.remove(&peer);
        self.peers.remove(&peer);
        self.segments.retain(|_, owners| {
            owners.retain(|o| *o != peer);
            !owners.is_empty()
        });
        self.bump();
    }

    /// 摘掉某个 owner 的邻居条目（对方声明里不再包含它时）。
    pub fn prune_edge(&mut self, from: NodeId, to: NodeId) {
        if let Some(a) = self.adjacency.get_mut(&from) {
            let before = a.edges.len();
            a.edges.retain(|e| e.peer != to);
            if a.edges.len() != before {
                self.version += 1;
            }
        }
    }

    /// 已知的全部 `(owner, seq)`，用于反熵摘要（§6.3）。
    pub fn digest(&self) -> Vec<(NodeId, u64)> {
        let mut v: Vec<(NodeId, u64)> =
            self.adjacency.iter().map(|(k, a)| (*k, a.seq)).collect();
        v.sort();
        v
    }

    /// 覆盖目标 IP 的网段所对应的候选出口（§9.1、§9.4.4）。
    pub fn segments_for_ip(&self, ip: std::net::IpAddr) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = Vec::new();
        for (net, owners) in &self.segments {
            if net.contains(&ip) {
                for o in owners {
                    if !v.contains(o) {
                        v.push(*o);
                    }
                }
            }
        }
        v.sort();
        v
    }

    /// 网段是否被某节点声明（供 `group:subnet:` 与自检使用）。
    pub fn owners_of_subnet(&self, net: &IpNet) -> Vec<NodeId> {
        let mut v = self.segments.get(net).cloned().unwrap_or_default();
        v.sort();
        v
    }

    /// 清理过期的监听端点（§6.5）。
    pub fn expire_listen_adverts(&mut self, now_unix: u64) -> bool {
        let before = self.listen_addrs.len();
        self.listen_addrs.retain(|_, a| {
            a.ttl_secs == 0 || now_unix.saturating_sub(a.issued_at) <= a.ttl_secs as u64
        });
        if self.listen_addrs.len() != before {
            self.bump();
            true
        } else {
            false
        }
    }

    /// 是否已经很久没有某个 peer 的消息（用于 UI 灰显）。
    pub fn stale_peers(&self, older_than: Duration) -> Vec<NodeId> {
        let now = Instant::now();
        self.peers
            .iter()
            .filter(|(id, m)| **id != self.self_id && now.duration_since(m.last_seen) > older_than)
            .map(|(id, _)| *id)
            .collect()
    }
}

fn same_edges(a: &[AdjEntry], b: &[AdjEntry]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let key = |e: &AdjEntry| (e.peer, e.cost, e.carrier, e.rtt_ms);
    let mut x: Vec<_> = a.iter().map(key).collect();
    let mut y: Vec<_> = b.iter().map(key).collect();
    x.sort();
    y.sort();
    x == y
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Carrier;

    fn nid(s: &str) -> NodeId {
        s.parse().unwrap()
    }

    fn edge(peer: NodeId, carrier: Carrier) -> AdjEntry {
        AdjEntry { peer, cost: 1, carrier, rtt_ms: 1 }
    }

    fn gossip(owner: NodeId, inc: u64, seq: u64, edges: Vec<AdjEntry>, subnets: Vec<IpNet>) -> GossipMsg {
        GossipMsg {
            owner,
            incarnation: inc,
            seq,
            edges,
            subnets: subnets.into_iter().map(SubnetAd::any_port).collect(),
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: None,
            digest: Vec::new(),
        }
    }

    #[test]
    fn newer_incarnation_wins_older_is_dropped() {
        let mut t = Topology::new(nid("10.0.0.1"));
        let b = nid("10.0.0.2");
        let c = nid("10.0.0.3");
        let d = nid("10.0.0.4");

        assert!(t.merge_gossip(&gossip(b, 5, 1, vec![edge(c, Carrier::Direct)], vec![])).changed);
        // 更旧：必须被拒（§16「incarnation 合并规则：旧盖新必须被拒」）
        assert!(!t.merge_gossip(&gossip(b, 3, 9, vec![edge(d, Carrier::Direct)], vec![])).changed);
        assert_eq!(t.adjacency[&b].edges[0].peer, c);

        // 相等的 incarnation 但 seq 更新 → 接受
        assert!(t.merge_gossip(&gossip(b, 5, 2, vec![edge(d, Carrier::Direct)], vec![])).changed);
        assert_eq!(t.adjacency[&b].edges[0].peer, d);
    }

    #[test]
    fn refutation_detected_when_someone_describes_me_wrongly() {
        let me = nid("10.0.0.1");
        let mut t = Topology::new(me);
        t.set_self(vec![edge(nid("10.0.0.2"), Carrier::Lan)], vec![], ListenAdvert::default(), true, None);

        // 有人声称我和一个我没连的节点相连
        let out = t.merge_gossip(&gossip(me, 99, 1, vec![edge(nid("10.9.9.9"), Carrier::Direct)], vec![]));
        assert!(out.self_disputed, "必须检测到关于自己的错误描述并触发反驳（§6.3）");

        // 描述正确时不再反驳
        let good = t.merge_gossip(&gossip(me, 1, 1, vec![edge(nid("10.0.0.2"), Carrier::Lan)], vec![]));
        assert!(!good.self_disputed);
    }

    #[test]
    fn segments_are_built_and_removed() {
        let mut t = Topology::new(nid("10.0.0.1"));
        let a = nid("10.1.2.5");
        let b = nid("10.4.0.9");

        t.merge_gossip(&gossip(a, 1, 1, vec![], vec!["10.1.2.0/24".parse().unwrap()]));
        t.merge_gossip(&gossip(b, 1, 1, vec![], vec!["10.4.0.0/24".parse().unwrap()]));

        assert_eq!(t.segments_for_ip("10.1.2.9".parse().unwrap()), vec![a]);
        assert_eq!(t.segments_for_ip("10.4.0.9".parse().unwrap()), vec![b]);
        assert!(t.segments_for_ip("8.8.8.8".parse().unwrap()).is_empty());

        // 同一网段两节点 → 两个候选出口（§9.3 情形一）
        let a2 = nid("10.1.2.6");
        t.merge_gossip(&gossip(a2, 1, 1, vec![], vec!["10.1.2.0/24".parse().unwrap()]));
        assert_eq!(t.segments_for_ip("10.1.2.9".parse().unwrap()), vec![a, a2]);

        // 对方改口不再声明该网段 → 索引里要摘掉
        t.merge_gossip(&gossip(a, 1, 2, vec![], vec![]));
        assert_eq!(t.segments_for_ip("10.1.2.9".parse().unwrap()), vec![a2]);
    }

    #[test]
    fn shared_rules_are_lww() {
        use crate::rules::{EgressTarget, HostMatcher, PortMatcher, Rule};
        let mut t = Topology::new(nid("10.0.0.1"));
        let p1 = nid("10.0.0.2");
        let p2 = nid("10.0.0.3");

        let mk = |pub_id: NodeId, rev: u64, tag: &str| RuleSetAd {
            publisher: pub_id,
            revision: rev,
            issued_at: 0,
            rules: vec![Rule {
                host: HostMatcher::Exact(tag.into()),
                port: PortMatcher::Any,
                egress: EgressTarget::Auto,
                on_unreachable: Default::default(),
                label: None,
                enabled: true,
            }],
            hmac: None,
        };

        let mut g1 = gossip(p1, 1, 1, vec![], vec![]);
        g1.rule_set = Some(mk(p1, 1, "rev1"));
        assert!(t.merge_gossip(&g1).rules_updated);

        let mut g2 = gossip(p2, 1, 1, vec![], vec![]);
        g2.rule_set = Some(mk(p2, 2, "rev2"));
        assert!(t.merge_gossip(&g2).rules_updated, "更高 revision 整体替换");

        // 旧的被拒
        let mut g3 = gossip(p1, 1, 1, vec![], vec![]);
        g3.rule_set = Some(mk(p1, 1, "rev1"));
        assert!(!t.merge_gossip(&g3).rules_updated, "旧 revision 不得覆盖新的（§9.4.3）");

        assert_eq!(t.shared_rules.as_ref().unwrap().publisher, p2);
    }

    #[test]
    fn digest_reports_what_we_are_missing() {
        let mut t = Topology::new(nid("10.0.0.1"));
        let b = nid("10.0.0.2");
        let c = nid("10.0.0.3");
        t.merge_gossip(&gossip(b, 1, 5, vec![], vec![]));

        let mut g = gossip(c, 1, 1, vec![], vec![]);
        g.digest = vec![(b, 9), (c, 1)]; // 对方掌握的是 b@9，我这边只有 b@5
        let out = t.merge_gossip(&g);
        assert!(out.need_pull.contains(&(b, 5)), "应当回 Pull 请求 b 的 5..9");

        // 我掌握的比对方新时不回拉
        let mut g2 = gossip(c, 1, 2, vec![], vec![]);
        g2.digest = vec![(b, 1)];
        assert!(t.merge_gossip(&g2).need_pull.is_empty());
    }

    #[test]
    fn broadcast_sentinel_is_never_an_owner() {
        let mut t = Topology::new(nid("10.0.0.1"));
        let out = t.merge_gossip(&gossip(BROADCAST, 9, 9, vec![], vec![]));
        assert!(!out.changed);
        assert!(!t.adjacency.contains_key(&BROADCAST));
    }

    #[test]
    fn lose_peer_cleans_everything() {
        let mut t = Topology::new(nid("10.0.0.1"));
        let b = nid("10.1.2.5");
        t.merge_gossip(&gossip(b, 1, 1, vec![], vec!["10.1.2.0/24".parse().unwrap()]));
        assert!(!t.segments.is_empty());
        t.lose_peer(b);
        assert!(t.adjacency.get(&b).is_none());
        assert!(t.peers.get(&b).is_none());
        assert!(t.segments_for_ip("10.1.2.9".parse().unwrap()).is_empty());
    }

    #[test]
    fn listen_adverts_expire() {
        let mut t = Topology::new(nid("10.0.0.1"));
        let b = nid("10.0.0.2");
        let mut g = gossip(b, 1, 1, vec![], vec![]);
        g.listen = ListenAdvert { addrs: vec!["10.0.0.2:20000".parse().unwrap()], issued_at: 1000, ttl_secs: 10 };
        t.merge_gossip(&g);
        assert!(!t.expire_listen_adverts(1005));
        assert!(t.expire_listen_adverts(1011));
        assert!(t.listen_addrs.is_empty());
    }

    #[test]
    fn self_state_feeds_segments_for_group_subnet() {
        let me = nid("10.1.2.5");
        let mut t = Topology::new(me);
        t.set_self(vec![], vec![SubnetAd::any_port("10.1.2.0/24".parse().unwrap())], ListenAdvert::default(), true, None);
        assert_eq!(t.segments_for_ip("10.1.2.9".parse().unwrap()), vec![me]);
        assert_eq!(t.owners_of_subnet(&"10.1.2.0/24".parse().unwrap()), vec![me]);
    }
}
