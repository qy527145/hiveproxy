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
    /// 本机世代号的起点。
    ///
    /// ★ 用**启动时刻**而不是 1：`incarnation` 是"关于同一个 owner 谁更新"的判据，
    /// 而它只活在内存里 —— 进程重启后从 1 重新开始的话，全网手里那份（比如 5）会一直
    /// 把我们后面所有的公告判成旧的，于是**我们的邻接边永远更新不进去**
    /// （别人的拓扑里留着一份我们早就不认的边，路由就会指到不存在的链路上）。
    /// 用启动时刻起步就天然单调：重启一次只会更大。
    self_incarnation0: u64,
    /// 上一次实际广播出去的网段（`share_subnets` 的开关也由它体现）。
    self_announced: Vec<SubnetAd>,
}

/// 一次「本机公告」的内容（`set_self` 的入参）。
///
/// 为什么要显式区分"索引"与"广播出去的那份"：`share_subnets = false` 只影响**广播**
/// （"我不告诉别人我的网段"），而本机自己的网段索引必须始终完整 —— 否则这台机器连
/// 自己所在网段的目标都解析不了（§9.1）。但版本号必须覆盖"实际广播出去的东西"，
/// 不然翻转 `share_subnets` 时 `seq` 不动，对端会把它当重复公告丢掉，改了配置没人知道。
#[derive(Clone, Debug, Default)]
pub struct SelfAnnounce {
    pub edges: Vec<AdjEntry>,
    /// 本机**完整**的网段索引（§9.1）。
    pub subnets_index: Vec<SubnetAd>,
    /// 这次**广播出去**的网段（`share_subnets = false` 时为空）。
    pub subnets_announced: Vec<SubnetAd>,
    pub listen: ListenAdvert,
    pub accepts_egress: bool,
    pub alias: Option<String>,
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
            self_incarnation0: crate::events::now_unix().max(1),
            self_announced: Vec::new(),
        }
    }

    fn bump(&mut self) -> bool {
        self.version += 1;
        true
    }

    /// 更新**自己**的公告内容。链路上下线、网段变化时调用。
    ///
    /// ★ `seq` 覆盖的是**被广播出去的每一样东西**（边、网段、监听端点、别名、
    /// 愿不愿意做出口）：只要其中任何一样变了就 `seq += 1`。早先只在直连边变化时自增，
    /// 于是"改别名 / 改监听端口 / 关掉网段共享"这些变化广播出去时版本号不变，
    /// 对端按 `(owner, incarnation, seq)` 去重后整条丢弃 —— 改了配置，邻居永远看不到。
    ///
    /// **时间戳不算内容变化**：`issued_at` 每次刷新都会变，把它算进去等于每 5 秒
    /// 涨一次版本号 + 一次变化驱动 flood。
    pub fn set_self(&mut self, a: SelfAnnounce) {
        self.self_subnets = a.subnets_index.iter().map(|s| s.net).collect();

        let old_self = self.peers.get(&self.self_id).cloned();
        let old_listen = self.listen_addrs.get(&self.self_id).map(|l| l.addrs.clone());
        // 内容变化判定：**不含 rtt**（见 `edges_shape_same`）。
        let content_changed = !edges_shape_same(
            self.adjacency.get(&self.self_id).map(|e| e.edges.as_slice()).unwrap_or_default(),
            &a.edges,
        ) || !same_subnets(&self.self_announced, &a.subnets_announced)
            || old_listen.as_deref() != Some(a.listen.addrs.as_slice())
            || old_self.as_ref().map(|m| m.accepts_egress) != Some(a.accepts_egress)
            || old_self.as_ref().and_then(|m| m.alias.clone()) != a.alias;

        let incarnation = self.self_incarnation0;
        let entry = self.adjacency.entry(self.self_id).or_insert_with(|| PeerAdj {
            incarnation,
            seq: 0,
            edges: Vec::new(),
            updated_at: Instant::now(),
        });
        entry.edges = a.edges;
        entry.updated_at = Instant::now();
        if content_changed {
            entry.seq += 1;
        }
        let incarnation = entry.incarnation;

        // 自己也进监听端点表 —— 否则本机网段（SELF 成本 0）在候选集里缺少端点信息。
        self.listen_addrs.insert(self.self_id, a.listen);

        self.peers.insert(
            self.self_id,
            NodeMeta {
                alias: a.alias,
                accepts_egress: a.accepts_egress,
                last_seen: Instant::now(),
                incarnation,
            },
        );
        self.self_announced = a.subnets_announced;

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
        //
        // ★ 比较**不含 rtt**（`edges_shape_same`）：这条路径上大概率的来访者是我们
        // 自己那条广播公告的回环副本，而它携带的是**广播那一刻**的 rtt。rtt 是心跳
        // 每秒都在量的观测量，把它算作"描述不符"就会触发 `bump_incarnation` + 重播 ——
        // 一个自我维持的反驳风暴（心跳一上线就会开始）。
        if msg.owner == self.self_id {
            let mine = self.adjacency.get(&self.self_id);
            let disagree = match mine {
                Some(a) => !edges_shape_same(&a.edges, &msg.edges),
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
        //
        // ★ 寿命要跟着对端**重新广播**刷新，而不仅是 `addrs` 变了的时候。
        // 稳定的节点每 5 秒重播一次（内容一样、`issued_at` 是新的），
        // 早先只在 addrs 不同时才写回，于是存下来的 `issued_at` 一直是第一天那个 ——
        // 900 秒的 ttl 一过就被 `expire_listen_adverts` 摘掉，对端在拨号器眼里
        // 变成"不覆盖"的候选，又是一轮重复拨号（每 15 分钟来一次）。
        match self.listen_addrs.get_mut(&msg.owner) {
            Some(cur) => {
                if cur.addrs != msg.listen.addrs {
                    cur.addrs = msg.listen.addrs.clone();
                    out.changed = true;
                }
                // 刷新寿命不算"变化"：它每 5 秒都会发生一次，算进去等于自造 gossip 风暴。
                if msg.listen.issued_at >= cur.issued_at {
                    cur.issued_at = msg.listen.issued_at;
                    cur.ttl_secs = msg.listen.ttl_secs;
                }
            }
            None => {
                self.listen_addrs.insert(msg.owner, msg.listen.clone());
                out.changed = true;
            }
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
        //
        // ★ 别名 / `accepts_egress` 变了也要算 `changed`：调用方据此决定要不要
        // `refresh_aliases()`、重算路由与重画拓扑。不算的话，对端改了别名（或关掉了
        // 出口角色），我们这边的别名表与候选出口会一直停在旧值上 —— 静默失效。
        let incarnation = self.adjacency.get(&msg.owner).map(|a| a.incarnation).unwrap_or(0);
        let old_meta = self.peers.get(&msg.owner);
        if old_meta.map(|m| (m.alias.as_deref(), m.accepts_egress))
            != Some((msg.alias.as_deref(), msg.accepts_egress))
        {
            out.changed = true;
        }
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

/// 结构性地比较两组边：**不含 `rtt_ms`**。
///
/// rtt 是心跳每 3 秒都在量的观测量。凡是"拓扑变没变 / 别人的描述对不对"的判断都必须
/// 用它，否则：① 每次 rtt 跳一格就等于 `seq += 1` + 一次变化驱动 flood；
/// ② 回环回来的"我自己那份公告"会因为 rtt 与当前值不同被判成 `self_disputed`，
/// 触发 `bump_incarnation` + 重播 —— 一个自我维持的反驳风暴。
/// rtt 只影响下一跳的成本（`router::arc_weight`），不影响图的结构。
fn edges_shape_same(a: &[AdjEntry], b: &[AdjEntry]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let key = |e: &AdjEntry| (e.peer, e.cost, e.carrier);
    let mut x: Vec<_> = a.iter().map(key).collect();
    let mut y: Vec<_> = b.iter().map(key).collect();
    x.sort();
    y.sort();
    x == y
}

/// 网段声明是否一模一样（网段 + 端口限制，顺序无关）。
fn same_subnets(a: &[SubnetAd], b: &[SubnetAd]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let key = |s: &SubnetAd| (s.net.to_string(), s.ports.clone());
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
        t.set_self(announce(vec![edge(nid("10.0.0.2"), Carrier::Lan)], vec![]));

        // 有人声称我和一个我没连的节点相连
        let out = t.merge_gossip(&gossip(me, 99, 1, vec![edge(nid("10.9.9.9"), Carrier::Direct)], vec![]));
        assert!(out.self_disputed, "必须检测到关于自己的错误描述并触发反驳（§6.3）");

        // 描述正确时不再反驳
        let good = t.merge_gossip(&gossip(me, 1, 1, vec![edge(nid("10.0.0.2"), Carrier::Lan)], vec![]));
        assert!(!good.self_disputed);
    }

    /// `set_self` 的测试入参：网段同时作为"索引"与"广播出去的那份"。
    fn announce(edges: Vec<AdjEntry>, subnets: Vec<IpNet>) -> SelfAnnounce {
        let subs: Vec<SubnetAd> = subnets.into_iter().map(SubnetAd::any_port).collect();
        SelfAnnounce {
            edges,
            subnets_index: subs.clone(),
            subnets_announced: subs,
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
        }
    }

    /// ★ 公告内容变了就必须 `seq += 1`，否则对端按 `(owner, incarnation, seq)` 去重后
    /// 会把这条更新整条丢掉 —— 改了别名/端口/网段共享，邻居永远看不到。
    #[test]
    fn any_announced_content_change_bumps_seq() {
        let me = nid("10.0.0.1");
        let mut t = Topology::new(me);
        t.set_self(announce(vec![], vec![]));
        let s0 = t.self_seq();

        // 只改监听端点（边没变）
        let mut a = announce(vec![], vec![]);
        a.listen = ListenAdvert {
            addrs: vec!["10.0.0.1:20000".parse().unwrap()],
            issued_at: 0,
            ttl_secs: 900,
        };
        t.set_self(a);
        let s1 = t.self_seq();
        assert!(s1 > s0, "监听端点变了必须升版本号");

        // 同样的内容再同步一次（周期刷新）—— 不能又涨
        let mut a = announce(vec![], vec![]);
        a.listen = ListenAdvert {
            addrs: vec!["10.0.0.1:20000".parse().unwrap()],
            issued_at: 9_999, // 只有时间戳不同
            ttl_secs: 900,
        };
        t.set_self(a);
        assert_eq!(t.self_seq(), s1, "纯时间戳刷新不得涨版本号（否则每 5 秒一次 flood）");

        // 只改别名
        let mut a = announce(vec![], vec![]);
        a.listen = ListenAdvert {
            addrs: vec!["10.0.0.1:20000".parse().unwrap()],
            issued_at: 0,
            ttl_secs: 900,
        };
        a.alias = Some("gpu-01".into());
        t.set_self(a);
        assert!(t.self_seq() > s1, "别名变了必须升版本号");

        // 只翻转"要不要告诉别人我的网段"（索引不变，广播出去的那份变了）
        let s2 = t.self_seq();
        let mut a = announce(vec![], vec!["10.1.2.0/24".parse().unwrap()]);
        a.alias = Some("gpu-01".into());
        a.subnets_announced = Vec::new(); // share_subnets = false
        t.set_self(a);
        assert!(t.self_seq() > s2, "share_subnets 翻转必须升版本号");
        assert_eq!(
            t.segments_for_ip("10.1.2.9".parse().unwrap()),
            vec![me],
            "但本机自己的网段索引必须始终完整（§9.1）"
        );
    }

    /// rtt 是心跳每几秒就在变的观测量：它不该让"边变了"成立，
    /// 更不该让"回环回来的我自己那份公告"被判成描述不符（那会变成反驳风暴）。
    #[test]
    fn rtt_changes_are_not_topology_changes() {
        let me = nid("10.0.0.1");
        let peer = nid("10.0.0.2");
        let mut t = Topology::new(me);
        let with = |rtt: u16| {
            let mut e = edge(peer, Carrier::Direct);
            e.rtt_ms = rtt;
            announce(vec![e], vec![])
        };
        t.set_self(with(0));
        let s = t.self_seq();
        t.set_self(with(70));
        assert_eq!(t.self_seq(), s, "rtt 变化不得升版本号");

        // 回环回来的自己那份公告（rtt 是广播那一刻的值）不能触发反驳
        let echo = gossip(me, t.incarnation(), t.self_seq(), vec![{
            let mut e = edge(peer, Carrier::Direct);
            e.rtt_ms = 1;
            e
        }], vec![]);
        let out = t.merge_gossip(&echo);
        assert!(!out.self_disputed, "rtt 不同不代表有人错误地描述了我");
    }

    /// 稳定对端每 5 秒重播一次（内容一样、`issued_at` 是新的）：寿命必须跟着刷新，
    /// 否则 900 秒的 ttl 一过它就被摘掉，拨号器立刻开始重复拨号。
    #[test]
    fn repeated_adverts_refresh_their_ttl() {
        let mut t = Topology::new(nid("10.0.0.1"));
        let b = nid("10.0.0.2");
        let advert = |issued_at: u64| ListenAdvert {
            addrs: vec!["10.0.0.2:20000".parse().unwrap()],
            issued_at,
            ttl_secs: 900,
        };

        let mut g = gossip(b, 1, 1, vec![], vec![]);
        g.listen = advert(1_000);
        t.merge_gossip(&g);

        // 对端重播：内容一样，只是时间戳新了
        let mut g2 = gossip(b, 1, 2, vec![], vec![]);
        g2.listen = advert(1_800);
        t.merge_gossip(&g2);

        assert!(
            !t.expire_listen_adverts(1_890),
            "重播过的公告不该在 900 秒后被摘掉（寿命要跟着重播刷新）：{:?}",
            t.listen_addrs
        );
    }

    /// 对端改了别名 / 关掉出口角色时必须算 `changed`，否则调用方不会刷新别名表与路由。
    #[test]
    fn alias_and_egress_flag_changes_count_as_changes() {
        let mut t = Topology::new(nid("10.0.0.1"));
        let b = nid("10.0.0.2");
        let mut g = gossip(b, 1, 1, vec![], vec![]);
        t.merge_gossip(&g);

        g.seq = 2;
        g.alias = Some("gpu-01".into());
        assert!(t.merge_gossip(&g).changed, "别名变了必须算变化");

        g.seq = 3;
        g.accepts_egress = false;
        assert!(t.merge_gossip(&g).changed, "accepts_egress 变了必须算变化");

        g.seq = 4;
        assert!(!t.merge_gossip(&g).changed, "同样的内容再来一遍不算变化");
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
        t.set_self(announce(vec![], vec!["10.1.2.0/24".parse().unwrap()]));
        assert_eq!(t.segments_for_ip("10.1.2.9".parse().unwrap()), vec![me]);
        assert_eq!(t.owners_of_subnet(&"10.1.2.0/24".parse().unwrap()), vec![me]);
    }
}
