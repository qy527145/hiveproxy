//! 编排器：把各子系统拼成一个可运行的节点，并对外提供稳定的 API
//! （Tauri 命令层唯一需要依赖的就是这里）。
//!
//! DESIGN.md §6.8 的结构在这里落地：`topology` 与 `publish` 是权威源，
//! `router` / `rules` 是派生缓存。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::discovery;
use crate::error::ConfigError;
use crate::events::now_unix;
use crate::identity::NodeIdentity;
use crate::msg::control_header;
use crate::persist;
use crate::proto::{Endpoint, Host, MsgType, NodeId, RuleSetAd};
use crate::resolver::{self, Egress, ResolveCtx};
use crate::rules::{EgressTarget, Rule};
use crate::state::HiveState;
use crate::stats::RuleHits;
use crate::view::{
    GroupView, NodeStatus, PublishResult, RulePreview, RuleStat, RulesView, StatsSnapshot,
    StreamProbe, TopologySnapshot,
};

pub struct HiveNode {
    pub state: Arc<HiveState>,
    pub base_dir: PathBuf,
    cancel: CancellationToken,
    tasks: parking_lot::Mutex<Vec<JoinHandle<()>>>,
    /// 管理接口实际监听的位置（`None` = 未启用）。CLI 用它来告诉用户往哪儿连。
    admin_endpoint: parking_lot::Mutex<Option<String>>,
}

impl HiveNode {
    /// 启动一个节点。
    pub async fn start(cfg: Config, base_dir: impl Into<PathBuf>) -> Result<Arc<Self>, String> {
        let base_dir = base_dir.into();
        persist::ensure_dir(&base_dir).map_err(|e| format!("无法创建数据目录：{e}"))?;

        // 配置自检只告警，不阻断启动（使用者已经知道自己要什么）
        for w in cfg.validate() {
            tracing::warn!(target: "hiveproxy", "配置告警：{w}");
        }

        let identity = Arc::new(NodeIdentity::resolve(&cfg).map_err(|e| e.to_string())?);
        let state = HiveState::new(identity, cfg);

        // 载入持久化状态：**这两份缺一都会造成"静默失效"**（§9.4.3）
        {
            let ps = persist::load_publish_state(&base_dir);
            *state.publish.write() = ps;
            if let Some(rs) = persist::load_shared_rules(&base_dir) {
                state.topology.write().shared_rules = Some(rs);
            }
        }

        crate::gossip::sync_self_state(&state);
        state.rebuild_router();
        state.rebuild_rules();
        state.refresh_aliases();

        let cancel = CancellationToken::new();
        let mut tasks = Vec::new();

        // ---- 子系统 ----
        crate::listener::spawn_listeners(state.clone(), cancel.clone());
        crate::dialer::spawn_dialer(state.clone(), cancel.clone());
        crate::gossip::spawn_periodic(state.clone(), cancel.clone());
        crate::gossip::spawn_anti_entropy(state.clone(), cancel.clone());
        discovery::spawn_discovery(state.clone(), cancel.clone());
        crate::socks5::spawn_socks5(state.clone(), cancel.clone());

        // ---- 事件泵 ----
        tasks.push(tokio::spawn(stats_pump(state.clone(), cancel.clone())));
        tasks.push(tokio::spawn(topology_pump(state.clone(), cancel.clone())));

        // 开机就广播一次，让邻居尽快认识我们
        crate::gossip::broadcast_now(&state, true).await;

        let node = Arc::new(Self {
            state: state.clone(),
            base_dir,
            cancel,
            tasks: parking_lot::Mutex::new(tasks),
            admin_endpoint: parking_lot::Mutex::new(None),
        });

        // 本地管理接口（§20）：无界面服务器靠它查询与下发规则。
        // 必须在 `Arc<Self>` 构造出来之后才能启动。
        let ep = crate::admin::spawn_admin(node.clone(), node.cancel.clone());
        *node.admin_endpoint.lock() = ep;

        node.state.emit_topology();
        node.state.emit_rules();
        Ok(node)
    }

    pub async fn stop(&self) {
        self.cancel.cancel();
        self.state.shutdown.cancel();
        let tasks: Vec<JoinHandle<()>> = std::mem::take(&mut *self.tasks.lock());
        for t in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<crate::events::HiveEvent> {
        self.state.events.subscribe()
    }

    // ------------------------------------------------------------------
    // 只读快照
    // ------------------------------------------------------------------

    pub fn status(&self) -> NodeStatus {
        let cfg = self.state.cfg();
        let rules = self.state.rules.read();
        NodeStatus {
            node_id: self.state.self_id(),
            alias: self.state.node.alias.clone(),
            listen: self.state.node.listen.iter().map(|a| a.to_string()).collect(),
            subnets: self.state.node.subnets.iter().map(|n| n.to_string()).collect(),
            share_subnets: self.state.node.share_subnets,
            accepts_egress: cfg.egress.allow_egress,
            socks5_bind: cfg.proxy.socks5_bind.to_string(),
            topology_version: self.state.topology.read().version,
            rule_count: rules.local_count,
            shared_rule_count: rules.merged.len().saturating_sub(rules.local_count),
            rules_enabled: rules.rules_enabled,
            uptime_secs: self.state.uptime_secs(),
            version: crate::VERSION.to_string(),
        }
    }

    pub fn topology(&self) -> TopologySnapshot {
        self.state.snapshot_topology()
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.state.stats.snapshot()
    }

    pub fn rules_view(&self) -> RulesView {
        self.state.rules_view()
    }

    pub fn rule_stats(&self) -> Vec<RuleStat> {
        let rules = self.state.rules.read().merged.clone();
        self.state.rule_hits.snapshot(&rules)
    }

    pub fn groups(&self) -> Vec<GroupView> {
        self.state.groups_view()
    }

    /// 分区视图（§9.3）：有哪些网段真冲突、每个 zone 建议怎么填地址。
    pub fn zones(&self) -> Vec<crate::view::ZoneView2> {
        let topo = self.state.topology.read();
        crate::zone::zone_views(&topo)
            .into_iter()
            .map(|v| crate::view::ZoneView2 {
                net: v.net.to_string(),
                islands: v
                    .islands
                    .into_iter()
                    .map(|(z, suggestion, members)| {
                        let reachable = {
                            let router = self.state.router.read();
                            members.iter().filter(|m| router.cost_to(**m).is_some()).count()
                        };
                        crate::view::ZoneIslandView {
                            zone: z.0,
                            label: z.label(),
                            suggestion,
                            members,
                            reachable,
                        }
                    })
                    .collect(),
            })
            .collect()
    }

    pub fn config(&self) -> Config {
        self.state.cfg().as_ref().clone()
    }

    pub fn shared_rules_status(&self) -> crate::view::SharedRulesStatus {
        let topo = self.state.topology.read();
        let cfg = self.state.cfg();
        match &topo.shared_rules {
            None => crate::view::SharedRulesStatus {
                source: None,
                source_alias: None,
                revision: 0,
                issued_at: 0,
                rules: 0,
                accepted: cfg.route.accept_shared_rules,
            },
            Some(rs) => crate::view::SharedRulesStatus {
                source: Some(rs.publisher),
                source_alias: topo.peers.get(&rs.publisher).and_then(|p| p.alias.clone()),
                revision: rs.revision,
                issued_at: rs.issued_at,
                rules: rs.rules.len(),
                accepted: cfg.route.accept_shared_rules,
            },
        }
    }

    // ------------------------------------------------------------------
    // 配置与规则
    // ------------------------------------------------------------------

    /// 热更新配置。
    pub fn set_config(&self, cfg: Config) -> Result<(), String> {
        let warns = cfg.validate();
        let old = self.state.cfg();
        let listen_changed = old.listen.ports != cfg.listen.ports
            || old.listen.bind != cfg.listen.bind
            || old.listen.max_links != cfg.listen.max_links;
        let proxy_changed = old.proxy != cfg.proxy;
        let discovery_changed = old.discovery != cfg.discovery;
        let peers_changed = old.peers != cfg.peers;

        persist::save_config(&self.base_dir, &cfg).map_err(|e| e.to_string())?;
        self.state.config.store(Arc::new(cfg.clone()));

        self.state.rebuild_rules();
        self.state.emit_rules();
        self.state.emit_topology();
        for w in warns {
            self.state.log("warn", "config", w);
        }
        if listen_changed {
            self.state.log(
                "warn",
                "config",
                "listen 已改动：端口/绑定地址的变化需要重启进程才会真正生效",
            );
        }
        if proxy_changed {
            self.state.log("warn", "config", "proxy 已改动：SOCKS5 绑定地址变化需要重启进程");
        }
        if discovery_changed || peers_changed {
            self.state.log("info", "config", "发现/种子配置已更新，拨号器会在下一轮巡检采用");
        }
        Ok(())
    }

    pub fn set_local_rules(&self, rules: Vec<Rule>) -> Result<(), String> {
        let mut cfg = self.state.cfg().as_ref().clone();
        cfg.route.rules = rules;
        persist::save_config(&self.base_dir, &cfg).map_err(|e| e.to_string())?;
        self.state.config.store(Arc::new(cfg));
        self.state.rebuild_rules();
        self.state.emit_rules();
        Ok(())
    }

    pub fn set_rules_enabled(&self, on: bool) -> Result<(), String> {
        let mut cfg = self.state.cfg().as_ref().clone();
        cfg.route.rules_enabled = on;
        persist::save_config(&self.base_dir, &cfg).map_err(|e| e.to_string())?;
        self.state.config.store(Arc::new(cfg));
        self.state.rebuild_rules();
        self.state.emit_rules();
        self.state
            .log("warn", "rules", if on { "路由规则已启用" } else { "★ 全局旁路已开启：所有规则被忽略，只跑网段自动匹配" });
        Ok(())
    }

    /// 按具体度重排（§9.4.2 的"一键重排"）。
    pub fn sort_rules(&self, rules: Vec<Rule>) -> Vec<Rule> {
        crate::rules::RuleTable::sorted_by_specificity(&rules)
    }

    /// 发布前 dry-run（§9.4.3 发布侧要求 3）。
    pub fn preview_rules(&self, proposed: Vec<Rule>) -> RulePreview {
        let mut p = RulePreview::default();

        let cfg = self.state.cfg();
        if let Err(bad) = cfg.resolve_aliases(&mut proposed.clone()) {
            for i in bad {
                p.warnings.push(format!("第 {} 条的别名在本机别名表里找不到，发布会被拒绝", i + 1));
            }
        }

        // 「永不命中」：被前面的规则完全覆盖
        for (i, r) in proposed.iter().enumerate() {
            if !r.enabled {
                continue;
            }
            if proposed[..i].iter().any(|prev| prev.enabled && prev.covers(r) && !prev.is_catch_all()) {
                p.never_matched.push(i);
            }
        }

        // 「黑洞」：block，或指向当前不可达的节点
        for (i, r) in proposed.iter().enumerate() {
            match &r.egress {
                EgressTarget::Block => p.blackholes.push(i),
                EgressTarget::Node(n) if self.state.router.read().cost_to(*n).is_none() => {
                    p.blackholes.push(i);
                    p.warnings
                        .push(format!("第 {} 条指向的出口 {n} 当前不可达（发布后仍会按 on_unreachable 处理）", i + 1));
                }
                _ => {}
            }
        }

        // 「影响面」：对已知网段里的代表地址，比较新旧出口
        let new_table = crate::rules::RuleTable::build(
            &proposed,
            self.state.topology.read().shared_rules.as_ref(),
            cfg.route.rules_enabled,
        );
        let old_table = self.state.rules.read().clone();

        let mut ports: Vec<u16> = vec![22, 80, 443, 3389, 3306, 8080];
        for r in proposed.iter().chain(old_table.merged.iter()) {
            match r.port {
                crate::rules::PortMatcher::Exact(p) => ports.push(p),
                crate::rules::PortMatcher::Range(lo, _) => ports.push(lo),
                crate::rules::PortMatcher::Any => {}
            }
        }
        ports.sort_unstable();
        ports.dedup();

        let samples = self.sample_targets(&ports);
        for t in samples {
            let old = self.resolve_with(&old_table, &t);
            let new = self.resolve_with(&new_table, &t);
            if old != new {
                p.changes.push(crate::view::RuleChange {
                    target: t.to_string(),
                    from: describe(&old),
                    to: describe(&new),
                });
                if p.changes.len() >= 200 {
                    p.warnings.push("影响面条目过多，已截断到 200 条".into());
                    break;
                }
            }
        }

        for (i, r) in proposed.iter().enumerate() {
            if r.is_catch_all() {
                p.warnings.push(format!(
                    "第 {} 条是 `*:*` 无边界规则：会兜住所有未被前面规则命中的流量（§17 风险 10）",
                    i + 1
                ));
            }
        }
        p
    }

    fn sample_targets(&self, ports: &[u16]) -> Vec<Endpoint> {
        let mut out = Vec::new();
        let topo = self.state.topology.read();
        let mut nets: Vec<_> = topo.segments.keys().copied().collect();
        nets.sort_by_key(|n| n.to_string());
        for net in nets {
            // 取网段的第 9 个地址作为代表（避开网络号与网关习惯位置）
            let ip = match net {
                ipnet::IpNet::V4(n) => {
                    let o = n.network().octets();
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        o[0],
                        o[1],
                        o[2],
                        o[3].saturating_add(9),
                    ))
                }
                ipnet::IpNet::V6(n) => std::net::IpAddr::V6(n.network()),
            };
            for p in ports.iter().take(24) {
                out.push(Endpoint::new(Host::Ip(ip), *p));
            }
        }
        out.truncate(4000);
        out
    }

    fn resolve_with(
        &self,
        table: &crate::rules::RuleTable,
        t: &Endpoint,
    ) -> Option<Egress> {
        let cfg = self.state.cfg();
        let topo = self.state.topology.read();
        let router = self.state.router.read();
        let aliases = self.state.aliases.read();
        let ctx = ResolveCtx {
            rules: table,
            topo: &topo,
            router: &router,
            self_id: self.state.self_id(),
            alias_table: &aliases,
            groups: &cfg.route.groups,
            island_filter: None,
        };
        resolver::resolve(&ctx, t).ok().map(|r| r.egress)
    }

    /// 一键发布：`revision += 1` → 落盘 → 广播（§9.4.3）。
    pub async fn publish_rules(&self, mut rules: Vec<Rule>) -> Result<PublishResult, String> {
        let cfg = self.state.cfg();
        if !cfg.route.publish_enabled {
            return Err("本节点的 route.publish_enabled = false，已禁止对外发布".into());
        }

        // 发布侧要求 2：别名必须在这里解析成 NodeId，解析不到就整次拒绝
        if let Err(bad) = cfg.resolve_aliases(&mut rules) {
            let list: Vec<String> = bad.iter().map(|i| format!("第 {} 条", i + 1)).collect();
            return Err(format!(
                "以下规则用了别名但本机别名表（peers.entry）里找不到：{}。\
                 共享规则必须是自足的，不能依赖接收方的本地别名表。",
                list.join("、")
            ));
        }

        let revision = {
            let mut ps = self.state.publish.write();
            ps.own_revision += 1;
            ps.last_published = rules.clone();
            let snapshot = ps.clone();
            // ★ 先落盘再广播：否则重启后 revision 归零，发布会被全网判为旧消息而永久忽略
            persist::save_publish_state(&self.base_dir, &snapshot)
                .map_err(|e| format!("发布状态落盘失败：{e}"))?;
            ps.own_revision
        };

        let ad = RuleSetAd {
            publisher: self.state.self_id(),
            revision,
            issued_at: now_unix(),
            rules: rules.clone(),
            hmac: self.rule_hmac(&rules),
        };
        self.state.topology.write().shared_rules = Some(ad.clone());
        self.state.rebuild_rules();
        self.state.emit_rules();
        crate::gossip::broadcast_now(&self.state, true).await;
        self.state
            .log("info", "rules", format!("已发布规则集 revision {revision}（{} 条）", rules.len()));

        Ok(PublishResult { revision, rules: rules.len(), published_at: ad.issued_at })
    }

    /// 撤回：发布一份**空规则集**（LWW register 只有"写"没有"删"）。
    pub async fn revoke_shared_rules(&self) -> Result<PublishResult, String> {
        let r = self.publish_rules(Vec::new()).await?;
        self.state.log("warn", "rules", "共享规则集已撤回（发布了一份空的）");
        Ok(r)
    }

    fn rule_hmac(&self, rules: &[Rule]) -> Option<[u8; 16]> {
        let token = &self.state.cfg().security.rule_token;
        if token.is_empty() {
            return None;
        }
        use hmac::Mac;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(token.as_bytes()).ok()?;
        for r in rules {
            mac.update(r.host.to_config_string().as_bytes());
            mac.update(r.port.to_config_string().as_bytes());
            mac.update(r.egress.to_config_string().as_bytes());
        }
        let out = mac.finalize().into_bytes();
        let mut a = [0u8; 16];
        a.copy_from_slice(&out[..16]);
        Some(a)
    }

    pub fn add_seed(&self, addr: String) -> Result<(), String> {
        crate::config::expand_seed(&addr, &self.state.cfg().peers.probe_ports)?;
        let mut cfg = self.state.cfg().as_ref().clone();
        if cfg.peers.seeds.contains(&addr) {
            return Ok(());
        }
        cfg.peers.seeds.push(addr);
        self.set_config(cfg)
    }

    pub fn remove_seed(&self, addr: String) -> Result<(), String> {
        let mut cfg = self.state.cfg().as_ref().clone();
        cfg.peers.seeds.retain(|s| s != &addr);
        self.set_config(cfg)
    }

    /// 探测一个目标会走哪个出口（不真正建流）。
    pub async fn probe_target(&self, target: &str) -> Result<StreamProbe, String> {
        let (mut zone, t) = parse_target_zoned(target)?;
        let started = std::time::Instant::now();

        // 区域分流与 SOCKS5 侧保持一致（§9.3）
        if zone.is_none() {
            if let Host::Ip(ip) = &t.host {
                let self_zone = self.state.self_zone();
                let resolution = self.state.zones.read().resolve_ip(*ip, self_zone);
                match resolution {
                    crate::zone::ZoneResolution::Ambiguous(zs) => {
                        let labels: Vec<String> = zs.iter().map(|z| z.label()).collect();
                        return Err(format!(
                            "该地址在多个孤岛里都存在（{}）—— 请用 z<zone>+{}:{} 指定",
                            labels.join(", "), ip, t.port
                        ));
                    }
                    crate::zone::ZoneResolution::PreferLocal(z) => zone = Some(z),
                    _ => {}
                }
            }
        }
        let island = zone.and_then(|z| self.state.island_filter(z));

        let cfg = self.state.cfg();
        let topo = self.state.topology.read();
        let router = self.state.router.read();
        let rules = self.state.rules.read();
        let aliases = self.state.aliases.read();
        let ctx = ResolveCtx {
            rules: &rules,
            topo: &topo,
            router: &router,
            self_id: self.state.self_id(),
            alias_table: &aliases,
            groups: &cfg.route.groups,
            island_filter: island.as_ref(),
        };
        let r = resolver::resolve(&ctx, &t).map_err(|e| format!("{e:?}"))?;
        Ok(StreamProbe {
            target: t,
            egress: r.dst_node(self.state.self_id()),
            direct: matches!(r.egress, Egress::Direct),
            matched_rule: r.matched_rule,
            rtt_ms: started.elapsed().as_millis() as u32,
        })
    }

    /// 给某个 peer 发一个 Ping 并等 Pong（简化为：报告当前链路的 RTT 观测）。
    pub fn ping_peer(&self, peer: NodeId) -> Result<u32, String> {
        let link = self
            .state
            .links
            .get(&peer)
            .map(|r| r.value().clone())
            .ok_or_else(|| format!("{peer} 不是直连邻居"))?;
        let header = control_header(MsgType::Ping, self.state.self_id(), peer, 1);
        link.sender
            .try_send_control(crate::link::OutboundFrame::new(header, bytes::Bytes::new()))
            .map_err(|_| "发送失败：控制车道已满".to_string())?;
        Ok(link.rtt_ms() as u32)
    }

    /// 给某条流发一个 StreamClose（前端"断开这条流"用）。
    pub async fn close_stream(&self, peer: NodeId, stream_id: u64) -> Result<(), String> {
        crate::stream::close_stream(
            &self.state,
            crate::proto::StreamKey(peer, stream_id),
            crate::proto::CloseReason::Normal,
        )
        .await;
        Ok(())
    }

    pub fn active_streams(&self) -> Vec<(NodeId, u64, String)> {
        self.state
            .streams
            .iter()
            .map(|kv| (kv.key().0, kv.key().1, kv.value().target.to_string()))
            .collect()
    }

    /// 把当前监听端口广播出去（`listen.advertise` 打开时才有内容）。
    pub fn listen_advert(&self) -> Vec<SocketAddr> {
        self.state
            .node
            .listen_advert(
                self.state.cfg().listen.advertise,
                now_unix(),
                900,
            )
            .addrs
    }

    /// 规则命中统计的引用（供 UI）。
    pub fn rule_hits(&self) -> &RuleHits {
        &self.state.rule_hits
    }

    pub fn data_dir(&self) -> PathBuf {
        persist::data_dir(&self.base_dir)
    }

    /// 管理接口的位置描述。
    pub fn admin_endpoint(&self) -> Option<String> {
        self.admin_endpoint.lock().clone()
    }

    /// 按配置推导管理接口位置（CLI 用它来知道该连哪儿，不需要先起节点）。
    pub fn resolve_admin_endpoint(base_dir: &Path, cfg: &Config) -> Option<String> {
        if !cfg.admin.enabled {
            return None;
        }
        if let Some(a) = cfg.admin.tcp {
            return Some(format!("tcp {a}"));
        }
        #[cfg(unix)]
        {
            let path = if cfg.admin.socket.is_empty() {
                persist::data_dir(base_dir).join("hiveproxy.sock")
            } else {
                PathBuf::from(&cfg.admin.socket)
            };
            Some(format!("unix {}", path.display()))
        }
        #[cfg(not(unix))]
        {
            let _ = base_dir;
            None
        }
    }

    /// 读一份配置模板（首次启动时写的）。
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

fn describe(e: &Option<Egress>) -> String {
    match e {
        None => "无路由".into(),
        Some(Egress::Direct) => "本机直连".into(),
        Some(Egress::Node(n)) => format!("出口 {n}"),
    }
}

/// 解析 `"ip:port"` / `"domain:port"` / `"z7+10.1.2.5:3306"` / `"[fd00:7::10.1.2.5]:3306"`。
///
/// 返回 `(zone 限定, 端点)`；zone 是 §9.3 情形二的区域限定。
pub fn parse_target_zoned(s: &str) -> Result<(Option<crate::zone::ZoneId>, Endpoint), String> {
    let p = crate::zone::parse_zoned_target(s)?;
    Ok((p.zone, Endpoint::new(p.host, p.port)))
}

/// 只要端点（丢掉 zone 限定）。
pub fn parse_target(s: &str) -> Result<Endpoint, String> {
    parse_target_zoned(s).map(|(_, e)| e)
}

/// 统计与拓扑的周期事件泵。
async fn stats_pump(state: Arc<HiveState>, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = state.shutdown.cancelled() => break,
            _ = ticker.tick() => {
                state.stats.links.store(state.links.len(), Ordering::Relaxed);
                state.emit_stats();
            }
        }
    }
}

async fn topology_pump(state: Arc<HiveState>, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = state.shutdown.cancelled() => break,
            _ = ticker.tick() => {
                let now = now_unix();
                if state.topology.write().expire_listen_adverts(now) {
                    state.rebuild_router();
                }
                state.emit_topology();
            }
        }
    }
}

/// 便捷：用默认路径（当前目录）初始化配置。
pub fn init_config(base_dir: impl AsRef<Path>) -> Result<Config, ConfigError> {
    persist::load_or_init_config(base_dir.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{HostMatcher, PortMatcher};

    #[test]
    fn parse_target_forms() {
        assert_eq!(
            parse_target("10.1.2.5:3389").unwrap(),
            Endpoint::new(Host::Ip("10.1.2.5".parse().unwrap()), 3389)
        );
        assert_eq!(
            parse_target("api.corp.example.com:443").unwrap(),
            Endpoint::new(Host::Name("api.corp.example.com".into()), 443)
        );
        // zone 限定前缀被剥掉
        assert_eq!(
            parse_target("z7+10.1.2.5:3306").unwrap(),
            Endpoint::new(Host::Ip("10.1.2.5".parse().unwrap()), 3306)
        );
        assert!(parse_target("10.1.2.5").is_err());
        assert!(parse_target("10.1.2.5:notaport").is_err());
    }

    #[tokio::test]
    async fn node_starts_and_reports_status() {
        let dir = std::env::temp_dir().join(format!("hiveproxy-node-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg.listen.bind = "127.0.0.1".parse().unwrap();
        cfg.listen.ports = vec![0]; // 由系统分配，避免与真实服务冲突
        cfg.proxy.socks5_bind = "127.0.0.1:0".parse().unwrap();
        cfg.discovery.lan_udp = false;
        cfg.node.alias = Some("test-node".into());

        let node = HiveNode::start(cfg, &dir).await.expect("节点应当能启动");
        let st = node.status();
        assert_eq!(st.node_id, "127.0.0.1".parse().unwrap());
        assert_eq!(st.alias.as_deref(), Some("test-node"));
        assert!(st.rules_enabled);
        assert_eq!(st.shared_rule_count, 0);
        node.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn publish_resolves_aliases_and_bumps_revision() {
        let dir = std::env::temp_dir().join(format!("hiveproxy-pub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg.listen.bind = "127.0.0.1".parse().unwrap();
        cfg.listen.ports = vec![0];
        cfg.proxy.socks5_bind = "127.0.0.1:0".parse().unwrap();
        cfg.discovery.lan_udp = false;
        cfg.peers.entry = vec![crate::config::PeerEntry {
            address: "10.4.0.9:20000".into(),
            alias: "gpu-01".into(),
        }];

        let node = HiveNode::start(cfg, &dir).await.unwrap();

        // 别名会被解析成 node:
        let r = node
            .publish_rules(vec![Rule::new(
                HostMatcher::parse("*.corp.example.com").unwrap(),
                PortMatcher::Exact(443),
                EgressTarget::Alias("gpu-01".into()),
            )])
            .await
            .expect("别名可解析，应当发布成功");
        assert_eq!(r.revision, 1);
        let published = &node.state.topology.read().shared_rules.clone().unwrap();
        assert_eq!(
            published.rules[0].egress,
            EgressTarget::Node("10.4.0.9".parse().unwrap()),
            "共享规则里绝不能留别名"
        );

        // revision 递增
        let r2 = node.publish_rules(vec![]).await.unwrap();
        assert_eq!(r2.revision, 2);

        // 解析不到的别名 → 整次拒绝
        let e = node
            .publish_rules(vec![Rule::new(
                HostMatcher::Any,
                PortMatcher::Any,
                EgressTarget::Alias("nope".into()),
            )])
            .await
            .unwrap_err();
        assert!(e.contains("别名"), "{e}");

        node.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn revision_survives_restart() {
        let dir = std::env::temp_dir().join(format!("hiveproxy-restart-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mk = || {
            let mut cfg = Config::default();
            cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
            cfg.listen.bind = "127.0.0.1".parse().unwrap();
            cfg.listen.ports = vec![0];
            cfg.proxy.socks5_bind = "127.0.0.1:0".parse().unwrap();
            cfg.discovery.lan_udp = false;
            cfg
        };

        let node = HiveNode::start(mk(), &dir).await.unwrap();
        node.publish_rules(vec![]).await.unwrap();
        node.publish_rules(vec![]).await.unwrap();
        assert_eq!(node.state.publish.read().own_revision, 2);
        node.stop().await;

        // 重启后 revision 必须继续递增（否则发布会被全网永久忽略）
        let node2 = HiveNode::start(mk(), &dir).await.unwrap();
        assert_eq!(node2.state.publish.read().own_revision, 2, "revision 必须跨重启保持");
        let r = node2.publish_rules(vec![]).await.unwrap();
        assert_eq!(r.revision, 3);
        node2.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn self_is_still_an_egress_when_it_refuses_to_serve_others() {
        // ★ 回归：`allow_egress = false`（不当网关）+ `auto_share_subnets = false`（不贡献网段）
        // 这两件事都**不该**影响"本机自己访问自己所在网段"。
        // 早期实现把两者绑在一起，敏感机器一这么配就连自己局域网都连不上了。
        let dir = std::env::temp_dir().join(format!("hiveproxy-selfeg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut cfg = Config::default();
        cfg.listen.ports = vec![0];
        cfg.proxy.socks5_bind = "127.0.0.1:0".parse().unwrap();
        cfg.discovery.lan_udp = false;
        cfg.admin.enabled = false;
        cfg.egress.allow_egress = false;      // 我不替别人转发
        cfg.share.auto_share_subnets = false; // 我不把我的网段告诉别人
        // overlay_addr 留空 = 取真实主网卡地址，这样它的子网一定在 subnets 里
        let node = HiveNode::start(cfg, &dir).await.unwrap();

        let me = node.status().node_id.to_string();
        let r = node
            .probe_target(&format!("{me}:80"))
            .await
            .expect("自己所在网段里的目标必须仍然可达");
        assert_eq!(r.egress.to_string(), me, "出口必须是自己");
        assert!(r.direct, "应当是本机直连，不进 overlay");

        // 同时确认：它确实没有对外声明网段（关闭共享仍然生效）
        let t = node.topology();
        let self_node = t.nodes.iter().find(|n| n.is_self).unwrap();
        assert!(!self_node.subnets.is_empty(), "本机自己的网段索引必须完整");

        node.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn preview_detects_shadowed_and_blackhole_rules() {
        let dir = std::env::temp_dir().join(format!("hiveproxy-prev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg.listen.bind = "127.0.0.1".parse().unwrap();
        cfg.listen.ports = vec![0];
        cfg.proxy.socks5_bind = "127.0.0.1:0".parse().unwrap();
        cfg.discovery.lan_udp = false;

        let node = HiveNode::start(cfg, &dir).await.unwrap();

        let rules = vec![
            // 完全覆盖后面那条 → 后者永不命中
            Rule::new(HostMatcher::parse("10.9.0.0/16").unwrap(), PortMatcher::Any, EgressTarget::Block),
            Rule::new(
                HostMatcher::parse("10.9.1.0/24").unwrap(),
                PortMatcher::Exact(443),
                EgressTarget::Auto,
            ),
        ];
        let p = node.preview_rules(rules);
        assert!(p.never_matched.contains(&1), "被完全覆盖的规则必须被标出来: {p:?}");
        assert!(p.blackholes.contains(&0), "block 规则是黑洞: {p:?}");

        node.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }
}
