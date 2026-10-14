//! 全局状态（DESIGN.md §6.8）。
//!
//! **权威源只有 `topology` 与 `publish` 两处**；`router` 与 `rules` 是派生缓存，
//! 由 `topology.version` / 配置版本触发重建。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::events::{HiveEvent, LogEvent};
use crate::identity::NodeIdentity;
use crate::link::{LinkHandle, OutboundFrame, StreamSender};
use crate::proto::{Endpoint, NodeId, StreamKey};
use crate::router::Router;
use crate::rules::{Rule, RuleTable};
use crate::session::StreamCtx;
use crate::stats::{RuleHits, Stats};
use crate::topology::Topology;
use crate::view::{
    EdgeView, GroupSource, GroupView, NodeView, RulesView, TopologySnapshot,
};

/// 发布侧状态。**必须持久化**（`data/publish_state.json`），
/// 否则重启后 `own_revision` 归零，新发布的规则集会因 `(0, me) < (旧 revision, me)`
/// 而被全网判为旧消息**永久忽略**（§9.4.3）。
#[derive(Clone, Debug, Default)]
pub struct PublishState {
    pub own_revision: u64,
    pub last_published: Vec<Rule>,
}

/// 某个拨号目标的退避状态。
#[derive(Clone, Debug)]
pub struct DialState {
    pub failures: u32,
    pub next_attempt: Instant,
    /// 该地址已被确认「不是 hiveproxy 节点」（§6.2.2），不再反复重试。
    pub not_a_node: bool,
}

impl DialState {
    pub fn new() -> Self {
        Self { failures: 0, next_attempt: Instant::now(), not_a_node: false }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendFail {
    /// 无路由到该目标。
    NoRoute,
    /// 下一跳链路已不存在。
    LinkGone,
    /// 队列满（背压信号，不是故障，§5.5）。
    QueueFull,
    /// 目的是自己 —— 调用方应当短路成本地 connect。
    SelfLoop,
}

pub struct HiveState {
    pub node: Arc<NodeIdentity>,
    pub config: Arc<ArcSwap<Config>>,

    // ── 权威源 ──────────────────────────────
    pub topology: RwLock<Topology>,
    pub publish: RwLock<PublishState>,

    // ── 派生缓存 ────────────────────────────
    pub router: RwLock<Router>,
    pub rules: RwLock<RuleTable>,

    // ── 运行期 ──────────────────────────────
    pub links: DashMap<NodeId, Arc<LinkHandle>>,
    /// `(下一跳, 流 id) -> 该链路上该流的数据队列`。
    pub stream_queues: DashMap<(NodeId, u64), StreamSender>,
    pub streams: DashMap<StreamKey, Arc<StreamCtx>>,
    /// 等待 `StreamAck` 的待开启流。
    pub pending_opens: DashMap<u64, oneshot::Sender<crate::proto::StreamAckMsg>>,
    pub aliases: RwLock<HashMap<String, NodeId>>,
    pub dial_state: DashMap<std::net::SocketAddr, DialState>,
    /// LAN 自动发现到的候选地址（§6.5 第 2 条）。
    pub lan_candidates: RwLock<std::collections::HashSet<std::net::SocketAddr>>,
    /// Gossip 去重表：`(owner, seq) -> 首次见到的时间`（§6.3、§13）。
    pub gossip_seen: RwLock<HashMap<(NodeId, u64), Instant>>,
    pub next_stream_id: AtomicU64,

    pub stats: Arc<Stats>,
    pub rule_hits: RuleHits,
    pub events: broadcast::Sender<HiveEvent>,
    pub shutdown: CancellationToken,
    pub started_at: Instant,
    /// 分区视图缓存（§9.3），随 `topology.version` 失效。
    pub zones: RwLock<crate::zone::ZoneTable>,
    /// SOCKS5 实际绑定的地址（配 `:0` 时由系统分配，UI 与测试需要知道真实端口）。
    pub proxy_bound: RwLock<Option<std::net::SocketAddr>>,
    /// 入向端口**实际**绑上的地址，由 `listener` 在 bind 成功后写入。
    ///
    /// 为什么不能直接读 `node.listen`：那是 `NodeIdentity` 里的启动快照，而身份是 `Arc`、
    /// 全引擎按不可变在用。配置改端口后引擎会**原地重绑**（不重建），只更新身份是做不到的 ——
    /// 没有这一份的话，`status().listen` 会一直显示老端口，属于"静默失效"那一类。
    pub listen_bound: RwLock<Vec<std::net::SocketAddr>>,
    /// 是否探测到身份冲突（§6.3）。
    pub identity_conflict: AtomicBool,
    /// 规则表版本，用于 `hive://rules` 去抖。
    pub rules_version: AtomicU64,
}

impl HiveState {
    pub fn new(node: Arc<NodeIdentity>, config: Config) -> Arc<Self> {
        let topology = Topology::new(node.node_id);
        let router = Router::new(node.node_id);
        let rules = RuleTable::build(&config.route.rules, None, config.route.rules_enabled);
        let (events, _) = broadcast::channel(1024);

        let state = Arc::new(Self {
            node,
            config: Arc::new(ArcSwap::from_pointee(config)),
            topology: RwLock::new(topology),
            publish: RwLock::new(PublishState::default()),
            router: RwLock::new(router),
            rules: RwLock::new(rules),
            links: DashMap::new(),
            stream_queues: DashMap::new(),
            streams: DashMap::new(),
            pending_opens: DashMap::new(),
            aliases: RwLock::new(HashMap::new()),
            dial_state: DashMap::new(),
            lan_candidates: RwLock::new(std::collections::HashSet::new()),
            gossip_seen: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU64::new(1),
            stats: Arc::new(Stats::default()),
            rule_hits: RuleHits::default(),
            events,
            shutdown: CancellationToken::new(),
            started_at: Instant::now(),
            zones: RwLock::new(crate::zone::ZoneTable::default()),
            proxy_bound: RwLock::new(None),
            listen_bound: RwLock::new(Vec::new()),
            identity_conflict: AtomicBool::new(false),
            rules_version: AtomicU64::new(1),
        });
        state.rule_hits.resize(state.rules.read().merged.len());
        state
    }

    pub fn cfg(&self) -> Arc<Config> {
        self.config.load_full()
    }

    pub fn self_id(&self) -> NodeId {
        self.node.node_id
    }

    /// 当前**实际**在听的地址。
    ///
    /// 优先用 `listener` 绑出来的那份；还没绑上（启动瞬间、或全部端口都绑失败）时退回身份里
    /// 的初始猜测。所有"对外说我在哪儿"的地方都必须走这里，不能直接读 `node.listen`。
    pub fn listen_addrs(&self) -> Vec<std::net::SocketAddr> {
        let bound = self.listen_bound.read().clone();
        if bound.is_empty() {
            self.node.listen.clone()
        } else {
            bound
        }
    }

    /// 当前实际监听的端口（`HelloAck.listen_ports` 的对齐自检、mDNS 广播都用它）。
    pub fn listen_ports_live(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.listen_addrs().iter().map(|a| a.port()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// 生成本节点的 `ListenAdvert`（§6.5）。
    ///
    /// 与 `NodeIdentity::listen_advert` 的唯一区别：用**实际绑上的**地址。
    /// 端口改过之后，广播给别人的必须是真的在听的那个，否则对端会一直往一个已经关掉的孔洞拨。
    pub fn listen_advert(
        &self,
        advertise: bool,
        now_unix: u64,
        ttl_secs: u32,
    ) -> crate::proto::ListenAdvert {
        crate::proto::ListenAdvert {
            addrs: if advertise { self.listen_addrs() } else { Vec::new() },
            issued_at: now_unix,
            ttl_secs,
        }
    }

    pub fn alloc_stream_id(&self) -> u64 {
        self.next_stream_id.fetch_add(1, Ordering::Relaxed)
    }

    // ------------------------------------------------------------------
    // 派生缓存重建
    // ------------------------------------------------------------------

    /// 拓扑变化后重建路由缓存与分区视图（§9.3）。
    pub fn rebuild_router(&self) {
        let topo = self.topology.read();
        let cfg = self.cfg();
        {
            let mut router = self.router.write();
            if router.version() != topo.version {
                router.rebuild(&topo, &cfg.route.cost);
                self.stats.route_rebuilds.fetch_add(1, Ordering::Relaxed);
            }
        }
        if self.zones.read().version != topo.version {
            let zt = crate::zone::ZoneTable::build(&topo);
            *self.zones.write() = zt;
        }
    }

    /// 覆盖 `ip` 所在孤岛的成员集合；`None` 表示不需要限定。
    pub fn island_filter(&self, zone: crate::zone::ZoneId) -> Option<std::collections::HashSet<NodeId>> {
        self.zones
            .read()
            .island_members(zone)
            .map(|v| v.iter().copied().collect())
    }

    /// 本机所在的孤岛（用于"目标 IP 属于多片时优先选自己那片"）。
    pub fn self_zone(&self) -> Option<crate::zone::ZoneId> {
        self.zones.read().zone_of(self.self_id())
    }

    /// 重新合并规则表（本地 + 共享）。
    pub fn rebuild_rules(&self) {
        let cfg = self.cfg();
        let topo = self.topology.read();
        let shared = if cfg.route.accept_shared_rules {
            topo.shared_rules.clone()
        } else {
            None
        };
        drop(topo);

        let table = RuleTable::build(&cfg.route.rules, shared.as_ref(), cfg.route.rules_enabled);
        self.rule_hits.resize(table.merged.len());
        let mut cur = self.rules.write();
        if *cur != table {
            *cur = table;
            self.rules_version.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ------------------------------------------------------------------
    // 发送
    // ------------------------------------------------------------------

    /// 取（或创建）某条链路上某条流的数据队列。
    pub fn stream_queue(
        &self,
        hop: NodeId,
        stream_id: u64,
    ) -> Option<StreamSender> {
        if let Some(q) = self.stream_queues.get(&(hop, stream_id)) {
            return Some(q.clone());
        }
        let link = self.links.get(&hop)?;
        let q = link.sender.register_stream(stream_id);
        self.stream_queues.insert((hop, stream_id), q.clone());
        Some(q)
    }

    pub fn drop_stream_queue(&self, hop: NodeId, stream_id: u64) {
        if let Some((_, q)) = self.stream_queues.remove(&(hop, stream_id)) {
            // 队列的 Receiver 由链路写出任务持有；这里只需让它自然断开。
            drop(q);
        }
        if let Some(link) = self.links.get(&hop) {
            link.sender.unregister_stream(stream_id);
        }
    }

    /// 把一帧交给通往 `dst` 的下一跳。
    pub fn send_to(
        &self,
        dst: NodeId,
        stream_id: u64,
        frame: OutboundFrame,
    ) -> Result<(), SendFail> {
        if dst == self.self_id() {
            return Err(SendFail::SelfLoop);
        }

        // 快路径：目的就是直连邻居
        let hop = if self.links.contains_key(&dst) {
            dst
        } else {
            let router = self.router.read();
            match router.next_hop(dst) {
                Some(r) => r.next_hop,
                None => return Err(SendFail::NoRoute),
            }
        };

        if !self.links.contains_key(&hop) {
            return Err(SendFail::LinkGone);
        }

        let q = self.stream_queue(hop, stream_id).ok_or(SendFail::LinkGone)?;
        q.try_send(frame).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => SendFail::QueueFull,
            mpsc::error::TrySendError::Closed(_) => SendFail::LinkGone,
        })
    }

    /// 向直连邻居发一个控制帧（`await`，控制车道）。
    pub async fn send_control_to(&self, peer: NodeId, frame: OutboundFrame) -> Result<(), ()> {
        // 注意 clone 的是 Arc，而不是 DashMap 的 Ref —— 后者会把读锁带过 await 点。
        let link = self.links.get(&peer).map(|r| r.value().clone()).ok_or(())?;
        link.sender.send_control(frame).await
    }

    /// 尽力而为地发一个控制帧（不阻塞）。
    pub fn try_send_control_to(&self, peer: NodeId, frame: OutboundFrame) -> Result<(), ()> {
        let link = self.links.get(&peer).map(|r| r.value().clone()).ok_or(())?;
        link.sender.try_send_control(frame)
    }

    /// 沿路由发送一个控制帧（可能多跳）。
    pub fn send_control_routed(&self, dst: NodeId, frame: OutboundFrame) -> Result<(), SendFail> {
        if dst == self.self_id() {
            return Err(SendFail::SelfLoop);
        }
        let hop = if self.links.contains_key(&dst) {
            dst
        } else {
            let router = self.router.read();
            router.next_hop(dst).map(|r| r.next_hop).ok_or(SendFail::NoRoute)?
        };
        let link = self.links.get(&hop).map(|r| r.value().clone()).ok_or(SendFail::LinkGone)?;
        link.sender.try_send_control(frame).map_err(|_| SendFail::QueueFull)
    }

    // ------------------------------------------------------------------
    // 事件与日志
    // ------------------------------------------------------------------

    pub fn emit(&self, ev: HiveEvent) {
        let _ = self.events.send(ev);
    }

    pub fn log(&self, level: &str, module: &str, msg: impl Into<String>) {
        let msg = msg.into();
        match level {
            "error" => tracing::error!(target: "hiveproxy", "{module}: {msg}"),
            "warn" => tracing::warn!(target: "hiveproxy", "{module}: {msg}"),
            "debug" => tracing::debug!(target: "hiveproxy", "{module}: {msg}"),
            _ => tracing::info!(target: "hiveproxy", "{module}: {msg}"),
        }
        self.emit(HiveEvent::Log(LogEvent::new(level, module, msg)));
    }

    pub fn emit_topology(&self) {
        let snap = self.snapshot_topology();
        self.emit(HiveEvent::Topology(Box::new(snap)));
    }

    pub fn emit_rules(&self) {
        self.emit(HiveEvent::Rules(Box::new(self.rules_view())));
    }

    pub fn emit_stats(&self) {
        self.emit(HiveEvent::Stats(self.stats.snapshot()));
    }

    // ------------------------------------------------------------------
    // 快照
    // ------------------------------------------------------------------

    pub fn snapshot_topology(&self) -> TopologySnapshot {
        let topo = self.topology.read();
        let router = self.router.read();

        let mut nodes: Vec<NodeView> = Vec::new();
        let mut ids: Vec<NodeId> = topo.peers.keys().copied().collect();
        if !ids.contains(&self.self_id()) {
            ids.push(self.self_id());
        }
        ids.sort();
        ids.dedup();

        let now = Instant::now();
        for id in ids {
            let meta = topo.peers.get(&id);
            let subnets = topo
                .segments
                .iter()
                .filter(|(_, owners)| owners.contains(&id))
                .map(|(net, _)| net.to_string())
                .collect();
            let listen = topo
                .listen_addrs
                .get(&id)
                .map(|a| a.addrs.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default();
            let route = router.route_to(id);
            let is_self = id == self.self_id();
            // 自己不该显示成"经中继 / 跳数 —"：它就是原点。
            let (hops, cost) = if is_self {
                (Some(0), Some(0))
            } else {
                (route.map(|r| r.hops), route.map(|r| r.cost))
            };
            nodes.push(NodeView {
                peer: id,
                alias: meta.and_then(|m| m.alias.clone()),
                is_self,
                subnets,
                listen,
                accepts_egress: meta.map(|m| m.accepts_egress).unwrap_or(true),
                last_seen_ms: meta
                    .map(|m| now.duration_since(m.last_seen).as_millis() as u64)
                    .unwrap_or(0),
                incarnation: meta.map(|m| m.incarnation).unwrap_or(0),
                reachable: is_self || route.is_some(),
                hops,
                cost,
                direct: self.links.contains_key(&id),
            });
        }

        let mut edges: Vec<EdgeView> = self
            .links
            .iter()
            .map(|kv| {
                let peer = *kv.key();
                let l = kv.value();
                let meta = l.meta.read();
                EdgeView {
                    from: self.self_id(),
                    to: peer,
                    cost: crate::router::arc_weight(
                        &crate::proto::AdjEntry {
                            peer,
                            cost: 1,
                            carrier: meta.carrier,
                            rtt_ms: meta.rtt_ms,
                        },
                        &self.cfg().route.cost,
                    ),
                    carrier: meta.carrier.as_str().to_string(),
                    health: format!("{:?}", meta.health).to_lowercase(),
                    establisher: format!("{:?}", meta.establisher).to_lowercase(),
                    rtt_ms: meta.rtt_ms,
                    direct: true,
                }
            })
            .collect();
        edges.sort_by_key(|e| e.to.to_string());

        // 全量邻接：DAG 渲染需要看到"谁和谁直连"，不只是本机的边
        let mut graph: Vec<crate::view::GraphEdge> = Vec::new();
        let mut owners: Vec<NodeId> = topo.adjacency.keys().copied().collect();
        owners.sort();
        for owner in owners {
            let Some(adj) = topo.adjacency.get(&owner) else { continue };
            for e in &adj.edges {
                if e.peer == owner || e.peer.is_broadcast() {
                    continue;
                }
                graph.push(crate::view::GraphEdge {
                    from: owner,
                    to: e.peer,
                    carrier: e.carrier.as_str().to_string(),
                    rtt_ms: e.rtt_ms,
                    local: owner == self.self_id() && self.links.contains_key(&e.peer),
                });
            }
        }
        // 去重：同一条边会被两端各声明一次
        graph.sort_by_key(|g| (g.from, g.to));
        graph.dedup_by_key(|g| (g.from, g.to));

        TopologySnapshot { nodes, edges, graph, version: topo.version }
    }

    pub fn rules_view(&self) -> RulesView {
        let cfg = self.cfg();
        let topo = self.topology.read();
        let shared = topo.shared_rules.clone();
        let alias = shared
            .as_ref()
            .and_then(|s| topo.peers.get(&s.publisher).and_then(|p| p.alias.clone()));
        RulesView {
            table: self.rules.read().clone(),
            local: cfg.route.rules.clone(),
            shared,
            shared_source_alias: alias,
        }
    }

    pub fn groups_view(&self) -> Vec<GroupView> {
        let cfg = self.cfg();
        let topo = self.topology.read();
        let mut out: Vec<GroupView> = cfg
            .route
            .groups
            .iter()
            .map(|g| GroupView {
                name: g.name.clone(),
                source: GroupSource::Explicit,
                members: g
                    .members
                    .iter()
                    .filter_map(|m| crate::config::parse_peer_address(m).ok())
                    .map(|(ip, _)| NodeId::from_ip(ip))
                    .collect(),
            })
            .collect();

        // 派生组：每个已知网段天然对应一个组（§9.4.2）
        let mut nets: Vec<_> = topo.segments.keys().copied().collect();
        nets.sort_by_key(|n| n.to_string());
        for net in nets {
            out.push(GroupView {
                name: format!("subnet:{net}"),
                source: GroupSource::Subnet(net.to_string()),
                members: topo.owners_of_subnet(&net),
            });
        }
        out
    }

    /// 别名表：本地 `peers.entry` 优先，其次是 gossip 广播的 alias。
    pub fn refresh_aliases(&self) {
        let cfg = self.cfg();
        let topo = self.topology.read();
        let mut map: HashMap<String, NodeId> = HashMap::new();
        for (id, meta) in topo.peers.iter() {
            if let Some(a) = &meta.alias {
                map.insert(a.clone(), *id);
            }
        }
        for e in &cfg.peers.entry {
            if let Ok((ip, _)) = crate::config::parse_peer_address(&e.address) {
                map.insert(e.alias.clone(), NodeId::from_ip(ip));
            }
        }
        *self.aliases.write() = map;
    }

    pub fn alias_of(&self, id: NodeId) -> Option<String> {
        self.topology.read().peers.get(&id).and_then(|m| m.alias.clone())
    }

    pub fn active_streams(&self) -> usize {
        self.streams.len()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// 目标是本机吗（应当短路成本地 connect）。
    pub fn is_self(&self, id: NodeId) -> bool {
        id == self.self_id()
    }

    pub fn endpoint_target_of(&self, key: &StreamKey) -> Option<Endpoint> {
        self.streams.get(key).map(|s| s.target.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    fn state_for(ip: &str) -> Arc<HiveState> {
        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some(ip.parse().unwrap());
        cfg.listen.bind = ip.parse().unwrap();
        let id = Arc::new(NodeIdentity::resolve(&cfg).unwrap());
        HiveState::new(id, cfg)
    }

    #[test]
    fn rules_rebuild_reflects_config() {
        let st = state_for("10.0.0.1");
        assert!(st.rules.read().is_empty());

        let mut cfg = st.cfg().as_ref().clone();
        cfg.route.rules = vec![Rule::new(
            crate::rules::HostMatcher::Any,
            crate::rules::PortMatcher::Any,
            crate::rules::EgressTarget::Block,
        )];
        st.config.store(Arc::new(cfg));
        st.rebuild_rules();
        assert_eq!(st.rules.read().merged.len(), 1);
    }

    #[test]
    fn bypass_switch_empties_the_table() {
        let st = state_for("10.0.0.1");
        let mut cfg = st.cfg().as_ref().clone();
        cfg.route.rules = vec![Rule::new(
            crate::rules::HostMatcher::Any,
            crate::rules::PortMatcher::Any,
            crate::rules::EgressTarget::Block,
        )];
        st.config.store(Arc::new(cfg));
        st.rebuild_rules();
        assert_eq!(st.rules.read().merged.len(), 1);

        let mut cfg = st.cfg().as_ref().clone();
        cfg.route.rules_enabled = false;
        st.config.store(Arc::new(cfg));
        st.rebuild_rules();
        assert!(st.rules.read().is_empty(), "全局旁路必须清空整张表（§9.4.4）");
    }

    #[test]
    fn shared_rules_are_ignored_when_disabled() {
        let st = state_for("10.0.0.1");
        {
            let mut topo = st.topology.write();
            topo.shared_rules = Some(crate::proto::RuleSetAd {
                publisher: "10.0.0.9".parse().unwrap(),
                revision: 3,
                issued_at: 0,
                rules: vec![Rule::new(
                    crate::rules::HostMatcher::Any,
                    crate::rules::PortMatcher::Any,
                    crate::rules::EgressTarget::Block,
                )],
                hmac: None,
            });
        }
        st.rebuild_rules();
        assert_eq!(st.rules.read().shared_revision, 3);

        let mut cfg = st.cfg().as_ref().clone();
        cfg.route.accept_shared_rules = false;
        st.config.store(Arc::new(cfg));
        st.rebuild_rules();
        assert_eq!(st.rules.read().shared_revision, 0, "拒收开关必须生效（§9.4.3）");
    }

    #[test]
    fn send_to_self_is_a_self_loop() {
        let st = state_for("10.0.0.1");
        let me = st.self_id();
        let frame = OutboundFrame::new(
            crate::proto::HiveHeader::new(crate::proto::MsgType::Data, me, me, 8),
            bytes::Bytes::new(),
        );
        assert_eq!(st.send_to(me, 1, frame), Err(SendFail::SelfLoop));
    }

    #[test]
    fn send_to_unknown_destination_reports_no_route() {
        let st = state_for("10.0.0.1");
        let frame = OutboundFrame::new(
            crate::proto::HiveHeader::new(
                crate::proto::MsgType::Data,
                st.self_id(),
                "10.9.9.9".parse().unwrap(),
                8,
            ),
            bytes::Bytes::new(),
        );
        assert_eq!(st.send_to("10.9.9.9".parse().unwrap(), 1, frame), Err(SendFail::NoRoute));
    }

    #[test]
    fn topology_snapshot_always_contains_self() {
        let st = state_for("10.0.0.1");
        let snap = st.snapshot_topology();
        assert!(snap.nodes.iter().any(|n| n.is_self));
    }
}
