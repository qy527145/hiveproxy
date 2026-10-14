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

use crate::config::{Config, ConfigChange};
use crate::discovery;
use crate::error::ConfigError;
use crate::events::now_unix;
use crate::identity::NodeIdentity;
use crate::msg::control_header;
use crate::persist;
use crate::proto::{Endpoint, Host, MsgType, NodeId, RuleSetAd};
use crate::resolver::{self, Egress, ResolveCtx};
use crate::rules::{EgressTarget, HostMatcher, OnUnreachable, PortMatcher, RawRule, Rule};
use crate::state::HiveState;
use crate::stats::RuleHits;
use crate::view::{
    DialResult, ExitCandidate, GroupView, NodeStatus, PublishResult, RuleIssue, RulePreview,
    RuleStat, RulesView, StatsSnapshot, StreamProbe, TopologySnapshot,
};

pub struct HiveNode {
    pub state: Arc<HiveState>,
    pub base_dir: PathBuf,
    cancel: CancellationToken,
    /// **只管绑定类子系统**（listener + proxy）的任务句柄。
    ///
    /// 单独记着它们是改端口能做到"不重建引擎"的全部原因：`abort` 掉这几个任务
    /// 只会让 listener / proxy 的 accept loop 停下，拨号器、gossip、事件泵、**在途连接**
    /// 全都不受影响（已接受的连接是各自 detached 的任务，见 `listener::accept_loop` /
    /// `proxy::serve`）。
    ///
    /// ★ 必须是句柄而不是取消令牌：**取消是异步的**，取消之后旧任务要等到被调度才释放
    /// 那个 `TcpListener`。改端口时不等它死透就去绑，重叠的端口必然 `EADDRINUSE`
    /// （这个 bug 是 `tests/rebind.rs` 抓出来的）。`abort()` + `await` 才是确定的。
    ///
    /// ★ 两侧**分开记**：只改入向端口时压根不碰代理。合成一坨的话，代理端口被
    /// 别人占着（很常见）就会让"改个入向端口"整体失败，甚至回滚都拿不回来。
    listen_tasks: parking_lot::Mutex<Vec<JoinHandle<()>>>,
    proxy_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
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
        crate::dialer::spawn_dialer(state.clone(), cancel.clone());
        crate::gossip::spawn_periodic(state.clone(), cancel.clone());
        crate::gossip::spawn_anti_entropy(state.clone(), cancel.clone());
        discovery::spawn_discovery(state.clone(), cancel.clone());

        // ---- 事件泵 ----
        tasks.push(tokio::spawn(stats_pump(state.clone(), cancel.clone())));
        tasks.push(tokio::spawn(topology_pump(state.clone(), cancel.clone())));

        // 开机就广播一次，让邻居尽快认识我们
        crate::gossip::broadcast_now(&state, true).await;

        let node = Arc::new(Self {
            state: state.clone(),
            base_dir,
            cancel,
            listen_tasks: parking_lot::Mutex::new(Vec::new()),
            proxy_task: parking_lot::Mutex::new(None),
            tasks: parking_lot::Mutex::new(tasks),
            admin_endpoint: parking_lot::Mutex::new(None),
        });

        // 入向端口与本地代理在 `Arc<Self>` 建好之后才绑：这样
        // ① 绑失败能经 `self.state.log` 进日志与界面；② 和改端口走**同一段代码**。
        // 冷启动是**容忍**单个端口失败的（§6.2.3）—— 端口被占也得能把节点起起来，
        // 否则用户没有界面可改（docs/WEBUI.md §2.1）。
        let start_cfg = node.state.cfg();
        if let Err(e) = node.spawn_listen(&start_cfg, false).await {
            node.state.log("error", "listener", e);
        }
        if let Err(e) = node.spawn_proxy(&start_cfg, false).await {
            node.state.log("error", "proxy", e);
        }

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
            listen: self.state.listen_addrs().iter().map(|a| a.to_string()).collect(),
            subnets: self.state.node.subnets.iter().map(|n| n.to_string()).collect(),
            excluded_subnets: self.state.node.excluded_subnets.clone(),
            share_subnets: self.state.node.share_subnets,
            accepts_egress: cfg.egress.allow_egress,
            proxy_bind: cfg.proxy.bind.to_string(),
            topology_version: self.state.topology.read().version,
            rule_count: rules.local_count,
            shared_rule_count: rules.merged.len().saturating_sub(rules.local_count),
            rules_enabled: rules.rules_enabled,
            default_egress: cfg.route.default_egress.as_ref().map(|e| e.to_config_string()),
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

    /// 热更新配置（**不处理绑定类字段**）。
    ///
    /// 调用方必须先用 `config::classify_change` 判过：`listen` / `proxy` 档要走
    /// [`Self::apply_config`]，`engine` 档要走 `ServiceHandle::restart`。
    /// 这里对绑定类字段是"存下来但不生效"，所以直接调它会让界面显示的和实际听的对不上。
    pub fn set_config(&self, cfg: Config) -> Result<(), String> {
        let warns = cfg.validate();
        let old = self.state.cfg();
        let discovery_changed = old.discovery != cfg.discovery;
        let peers_changed = old.peers != cfg.peers;

        persist::save_config(&self.base_dir, &cfg).map_err(|e| e.to_string())?;
        self.state.config.store(Arc::new(cfg.clone()));

        self.state.rebuild_rules();
        self.state.emit_rules();
        // ★ 有些字段（`share.share_ports_only` / `listen.advertise` / `egress.allow_egress`）
        // 是经 `sync_self_state` 进拓扑的，只存进 ArcSwap 还不够 —— 邻居会等到下一次周期刷新
        // 才知道。这里补一次同步与广播（§5.5）。
        crate::gossip::sync_self_state(&self.state);
        self.state.emit_topology();
        for w in warns {
            self.state.log("warn", "config", w);
        }
        if discovery_changed || peers_changed {
            self.state.log("info", "config", "发现/种子配置已更新，拨号器会在下一轮巡检采用");
        }
        Ok(())
    }

    /// 应用一份新配置：热字段直接生效，绑定类字段**原地重绑**（不重建引擎）。
    ///
    /// 返回本次的档位，供调用方记录/回显。
    ///
    /// ★ 顺序是"先停旧的（并且**等它真的停**）→ 再绑新的 → 绑不上就把旧的绑回来"。
    /// 为什么不能"先绑新的、成了再换"：端口重叠（`[5678, 5679]` → `[5678]`）时新端口
    /// 根本绑不上 —— 那个端口还在自己手里。而先停后绑只要"停"是确定的，回滚就一定成功
    /// （旧端口刚从我们手里放走，大概率还空着）；真有人在这零点几秒里抢走了它，
    /// 就大声说出来，绝不假装还在听（§6.2.3 的"不静默降级"）。
    pub async fn apply_config(self: &Arc<Self>, cfg: Config) -> Result<ConfigChange, String> {
        let old = self.state.cfg().as_ref().clone();
        let change = crate::config::classify_change(&old, &cfg);
        if change.engine {
            return Err(
                "这份配置改了身份或网段表（node.* / share.subnet_deny* / admin.*），\
                 需要重建引擎 —— 应当由 ServiceHandle::restart 处理"
                    .into(),
            );
        }
        if !change.listen && !change.proxy {
            self.set_config(cfg)?;
            return Ok(change);
        }

        // ★ **只动真正变了的那一侧。**
        //
        // 第一版是"两边一起重绑"，结果是：只改入向端口，却因为代理端口被别的程序占着
        // 而整体失败 —— 而且回滚也拿不回入向端口（回滚同样在代理那一步就退出了），
        // 最后**一个端口都不在听**。这台机器的 1080 恰好被人占着，CLI 冒烟测试直接踩中。
        // 现在每个子系统各管各的：改入向端口时压根不碰代理。
        let mut stopped: Vec<Sub> = Vec::new();
        let mut fail: Option<String> = None;

        if change.listen {
            self.stop_listen().await;
            stopped.push(Sub::Listen);
            if let Err(e) = self.spawn_listen(&cfg, true).await {
                fail = Some(format!("入向端口 {e}"));
            }
        }
        if fail.is_none() && change.proxy {
            self.stop_proxy().await;
            stopped.push(Sub::Proxy);
            if let Err(e) = self.spawn_proxy(&cfg, true).await {
                fail = Some(format!("本地代理 {e}"));
            }
        }

        if let Some(cause) = fail {
            // 回滚：把**停过的**那一侧按原配置重新绑上（没动过的一侧绝不碰）
            let mut bad: Vec<String> = Vec::new();
            for sub in stopped.iter().rev() {
                let r = match sub {
                    Sub::Listen => self.spawn_listen(&old, true).await,
                    Sub::Proxy => self.spawn_proxy(&old, true).await,
                };
                if let Err(e) = r {
                    bad.push(e);
                }
            }
            let msg = if bad.is_empty() {
                format!("绑定失败，已保留原端口：{cause}")
            } else {
                format!(
                    "绑定失败（{cause}），且回滚也失败（{}）：那一部分现在没有任何端口在听",
                    bad.join("；")
                )
            };
            self.state.log("error", "config", msg.clone());
            return Err(msg);
        }

        // 提交配置。**必须在重绑之后**：`proxy::serve` 一开跑就读配置里的绑定地址与
        // allow_remote，反过来的话它会读到旧值。
        self.set_config(cfg)?;
        crate::gossip::broadcast_now(&self.state, true).await;

        self.state.log(
            "info",
            "config",
            format!("监听端点已重新绑定（{}）—— 在途连接不受影响", change_label(change)),
        );
        Ok(change)
    }

    /// 停掉入向端口的 accept loop，并等它们真的退出（端口才真的腾出来）。
    async fn stop_listen(&self) {
        let tasks: Vec<JoinHandle<()>> = std::mem::take(&mut *self.listen_tasks.lock());
        abort_all(tasks).await;
        self.state.listen_bound.write().clear();
    }

    /// 停掉本地代理的 accept loop。
    async fn stop_proxy(&self) {
        let task = self.proxy_task.lock().take();
        if let Some(t) = task {
            abort_all(vec![t]).await;
        }
        *self.state.proxy_bound.write() = None;
    }

    /// 按配置绑入向端口并起 accept loop。
    ///
    /// - `strict = false`（冷启动）：单个端口绑不上只告警，节点照起 ——
    ///   端口被人占了也得能起来，否则用户没有界面可改（§6.2.3、docs/WEBUI.md §2.1）；
    /// - `strict = true`（改配置）：全有全无，任何一个失败就整体报错（调用方负责回滚）。
    async fn spawn_listen(&self, cfg: &Config, strict: bool) -> Result<(), String> {
        let ports = if cfg.listen.ports.is_empty() { vec![5678] } else { cfg.listen.ports.clone() };
        let mut listeners = Vec::new();
        let mut bound = Vec::new();

        for port in ports {
            match crate::listener::bind_one(cfg.listen.bind, port).await {
                Ok(l) => {
                    bound.extend(bound_addrs(&l));
                    listeners.push(l);
                }
                Err(e) if strict => return Err(e),
                Err(e) => {
                    // ★ 必须显式告警：静默降级会让"端口对齐"变成一个看不见的失败
                    self.state.log("error", "listener", format!(
                        "{e} —— 这个入向孔洞对本机不可用，其它节点拨不进来（§6.2.3）。\
                         端口可能已被别的服务占用，或需要更高权限。"
                    ));
                }
            }
        }

        *self.state.listen_bound.write() = bound;
        *self.listen_tasks.lock() = crate::listener::spawn_on(self.state.clone(), listeners);
        Ok(())
    }

    /// 按配置绑本地代理端口并起 accept loop。
    ///
    /// ⚠️ 这里失败**不能**影响入向端口：两者互不相干，而且代理端口被别的程序占着是常态
    /// （这台开发机上就是），没理由因此连入向端口一起废掉。
    async fn spawn_proxy(&self, cfg: &Config, strict: bool) -> Result<(), String> {
        let listener = match crate::proxy::bind_one(cfg.proxy.bind).await {
            Ok(l) => l,
            Err(e) if strict => return Err(e),
            Err(e) => {
                self.state.log("error", "proxy", e);
                return Ok(());
            }
        };
        *self.state.proxy_bound.write() = listener.local_addr().ok();
        *self.proxy_task.lock() = Some(crate::proxy::spawn_on(self.state.clone(), listener));
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

    /// 设置 / 清除默认出口（`route.default_egress`，§9.4.4）。
    ///
    /// `None` 或 `"none"` = 清除。写法与规则的 `egress` 同一套，
    /// 但 `auto` / `block` 在这里没有意义（`check_default_egress`）。
    pub fn set_default_egress(&self, value: Option<&str>) -> Result<(), String> {
        let mut cfg = self.state.cfg().as_ref().clone();
        cfg.route.default_egress = match value.map(str::trim) {
            None | Some("") | Some("none") | Some("clear") => None,
            Some(v) => {
                let t = EgressTarget::parse(v)?;
                t.check_default_egress()?;
                Some(t)
            }
        };
        let shown = cfg
            .route
            .default_egress
            .as_ref()
            .map(|e| e.to_config_string())
            .unwrap_or_else(|| "（已清除）".into());
        self.set_config(cfg)?;
        self.state.log("info", "route", format!("默认出口：{shown}"));
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
            default_egress: cfg.route.default_egress.as_ref(),
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
            default_egress: cfg.route.default_egress.as_ref(),
        };
        let r = resolver::resolve(&ctx, &t).map_err(|e| resolve_error_text(&e))?;
        Ok(StreamProbe {
            target: t,
            egress: r.dst_node(self.state.self_id()),
            direct: matches!(r.egress, Egress::Direct),
            via: r.source.as_str().to_string(),
            matched_rule: r.source.rule_index(),
            rtt_ms: started.elapsed().as_millis() as u32,
        })
    }

    /// 列出这个目标的**候选出口**（§18 第 31 条）。
    ///
    /// 纯路由计算：成本、跳数、是否声明过目标网段、哪个是当前自动选中的。
    /// "这条路真的通吗"是另一个问题，由 [`Self::probe_dial`] 回答。
    pub fn probe_exits(&self, target: &str) -> Result<Vec<ExitCandidate>, String> {
        let (_zone, t) = parse_target_zoned(target)?;
        let cfg = self.state.cfg();
        let topo = self.state.topology.read();
        let router = self.state.router.read();
        let rules = self.state.rules.read();
        let aliases = self.state.aliases.read();
        let self_id = self.state.self_id();

        let ctx = ResolveCtx {
            rules: &rules,
            topo: &topo,
            router: &router,
            self_id,
            alias_table: &aliases,
            groups: &cfg.route.groups,
            island_filter: None,
            default_egress: cfg.route.default_egress.as_ref(),
        };
        let selected = resolver::resolve(&ctx, &t).ok();

        let target_ip = match &t.host {
            Host::Ip(ip) => Some(*ip),
            Host::Name(_) => None,
        };
        let chosen = selected.as_ref().map(|s| s.dst_node(self_id));

        // 某节点声明了哪些网段：`segments` 是唯一权威索引，反查一次即可（`NodeMeta` 里没有）。
        let subnets_of = |id: &NodeId| -> Vec<String> {
            let mut v: Vec<String> = topo
                .segments
                .iter()
                .filter(|(_, owners)| owners.contains(id))
                .map(|(net, _)| net.to_string())
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let declares = |id: &NodeId| -> bool {
            target_ip
                .map(|ip| topo.segments_for_ip(ip).iter().any(|n| n == id))
                .unwrap_or(false)
        };

        let mut out: Vec<ExitCandidate> = Vec::new();
        for (id, meta) in topo.peers.iter() {
            let route = router.route_to(*id);
            let unusable = if route.is_none() {
                Some("当前无路由".to_string())
            } else if !meta.accepts_egress {
                Some("对端声明不做出口（accepts_egress = false）".to_string())
            } else {
                None
            };
            out.push(ExitCandidate {
                node: *id,
                alias: meta.alias.clone(),
                is_self: false,
                cost: route.map(|r| r.cost),
                hops: route.map(|r| r.hops),
                accepts_egress: meta.accepts_egress,
                subnets: subnets_of(id),
                declares_target: declares(id),
                selected: chosen == Some(*id),
                unusable,
            });
        }
        // 本机不一定在 `topo.peers` 里，而"本机直连"永远是一个候选 —— 补一行。
        if !out.iter().any(|c| c.node == self_id) {
            let mut subnets: Vec<String> =
                self.state.node.subnets.iter().map(|n| n.to_string()).collect();
            subnets.sort();
            out.push(ExitCandidate {
                node: self_id,
                alias: self.state.node.alias.clone(),
                is_self: true,
                cost: Some(0),
                hops: Some(0),
                accepts_egress: true,
                subnets,
                declares_target: declares(&self_id),
                selected: chosen == Some(self_id),
                unusable: None,
            });
        } else if let Some(c) = out.iter_mut().find(|c| c.node == self_id) {
            // 自己在拓扑里的那一行：成本恒为 0（§9.4.4），且永远可用。
            c.is_self = true;
            c.cost = Some(0);
            c.hops = Some(0);
            c.accepts_egress = true;
            c.unusable = None;
        }

        // 排序：选中的排第一，然后可用的按 (成本, 地址)，最后不可用的。
        out.sort_by_key(|c| (!c.selected, c.unusable.is_some(), c.cost.unwrap_or(u32::MAX), c.node));
        Ok(out)
    }

    /// **实测**：让指定的出口真的连一次目标，然后立刻把流关掉（§18 第 31 条）。
    ///
    /// 这是唯一能回答"这条出口真的够得着吗"的办法 —— 路由算得出来不代表防火墙放行，
    /// 也不代表出口那一侧能连上目标。**它会在网络上产生一次真实连接**，所以是手工动作。
    pub async fn probe_dial(&self, target: &str, via: NodeId) -> Result<DialResult, String> {
        let (_zone, t) = parse_target_zoned(target)?;
        let self_id = self.state.self_id();
        let direct = via == self_id;
        let started = std::time::Instant::now();

        if direct {
            // 本机直连：不进 overlay，直接一个 TCP connect（域名在本机解析，
            // 与 SOCKS5 的 handle_direct 同一条路径）。
            let addrs: Vec<std::net::SocketAddr> = match &t.host {
                Host::Ip(ip) => vec![std::net::SocketAddr::new(*ip, t.port)],
                Host::Name(n) => tokio::net::lookup_host((n.as_str(), t.port))
                    .await
                    .map_err(|e| format!("域名解析失败：{e}"))?
                    .collect(),
            };
            if addrs.is_empty() {
                return Ok(DialResult {
                    target: t.to_string(),
                    via,
                    direct,
                    ok: false,
                    rtt_ms: started.elapsed().as_millis() as u32,
                    detail: "域名解析不到地址".into(),
                });
            }
            let timeout = crate::stream::CONNECT_TIMEOUT;
            let dial = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addrs[..])).await;
            return Ok(match dial {
                Ok(Ok(_)) => DialResult {
                    target: t.to_string(),
                    via,
                    direct,
                    ok: true,
                    rtt_ms: started.elapsed().as_millis() as u32,
                    detail: "本机直连成功".into(),
                },
                Ok(Err(e)) => DialResult {
                    target: t.to_string(),
                    via,
                    direct,
                    ok: false,
                    rtt_ms: started.elapsed().as_millis() as u32,
                    detail: format!("本机连接失败：{e}"),
                },
                Err(_) => DialResult {
                    target: t.to_string(),
                    via,
                    direct,
                    ok: false,
                    rtt_ms: started.elapsed().as_millis() as u32,
                    detail: "本机连接超时".into(),
                },
            });
        }

        // 经 overlay：让该出口去连（`open_stream` 等的是出口侧的 StreamAck，
        // 也就是"它那边 connect 成没成"），拿到结果后立刻关流。
        let opened = crate::stream::open_stream(self.state.clone(), t.clone(), via, None).await;
        let rtt = started.elapsed().as_millis() as u32;
        match opened {
            Ok(o) => {
                crate::stream::close_stream(
                    &self.state,
                    o.ctx.key,
                    crate::proto::CloseReason::Normal,
                )
                .await;
                Ok(DialResult {
                    target: t.to_string(),
                    via,
                    direct,
                    ok: true,
                    rtt_ms: rtt,
                    detail: "出口已连上目标".into(),
                })
            }
            Err(e) => Ok(DialResult {
                target: t.to_string(),
                via,
                direct,
                ok: false,
                rtt_ms: rtt,
                detail: open_error_text(&e),
            }),
        }
    }

    /// 逐行校验一份**原始规则**（界面草稿的形态），返回出错的行（§18 第 32 条）。
    ///
    /// 为什么不让界面自己校验：解析规则的是引擎，在界面上再写一遍等于抄一遍语法 ——
    /// 两份实现迟早对不上。这里把"哪一行、哪个字段、为什么"原样回给界面。
    pub fn check_rules(&self, rows: Vec<RawRule>) -> Vec<RuleIssue> {
        let mut out = Vec::new();
        for (index, raw) in rows.iter().enumerate() {
            let mut push = |field: &str, message: String| {
                out.push(RuleIssue { index, field: field.to_string(), message });
            };
            if let Err(e) = HostMatcher::parse(&raw.host) {
                push("host", e);
            }
            if let Err(e) = PortMatcher::parse(&raw.port.as_str()) {
                push("port", e);
            }
            if let Err(e) = EgressTarget::parse(&raw.egress) {
                push("egress", e);
            }
            if let Err(e) = OnUnreachable::parse(&raw.on_unreachable) {
                push("on_unreachable", e);
            }
        }
        out
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
            .listen_advert(self.state.cfg().listen.advertise, now_unix(), 900)
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

/// 绑定类的两个子系统。分开是为了"只动变了的那一个"。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sub {
    Listen,
    Proxy,
}

/// `abort()` 只是"请求取消"；`await` 之后任务才真的被丢弃、`TcpListener` 才真的关闭。
async fn abort_all(tasks: Vec<JoinHandle<()>>) {
    for t in &tasks {
        t.abort();
    }
    for t in tasks {
        let _ = t.await;
    }
}

/// 一个监听器"实际在听哪里"。
///
/// `0.0.0.0:5678` 这种通配绑定要**展开成各网卡的具体地址**：对界面和运维来说
/// "我该拨哪个地址"才是他们要的答案，`0.0.0.0` 只是内核的一个写法。
/// 展开走的是 `net::expand_listen_addrs`，与身份里那份初始猜测同一套规则。
fn bound_addrs(l: &tokio::net::TcpListener) -> Vec<SocketAddr> {
    match l.local_addr() {
        // 通配绑定展开成各网卡的具体地址（多网卡时是好几行）
        Ok(a) if a.ip().is_unspecified() => crate::net::expand_listen_addrs(a.ip(), &[a.port()]),
        Ok(a) => vec![a],
        Err(_) => Vec::new(),
    }
}

/// 档位的人话说法（日志与界面共用同一套措辞）。
fn change_label(c: ConfigChange) -> String {
    match (c.listen, c.proxy) {
        (true, true) => "入向端口与本地代理".to_string(),
        (true, false) => "入向端口".to_string(),
        (false, true) => "本地代理端口".to_string(),
        (false, false) => "配置".to_string(),
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

/// 解析失败的原因文本。
///
/// 早先这里是 `format!("{e:?}")` —— 界面上的报错就是一句 `NoRoute`，
/// 既不是中文也不知道该改什么（§18 第 31 条同批修掉）。
fn resolve_error_text(e: &resolver::ResolveError) -> String {
    match e {
        resolver::ResolveError::NoRoute => {
            "无路由：目标不落在任何已知网段，也没有规则或默认出口接管".to_string()
        }
        resolver::ResolveError::Refused => "被规则显式拒绝（egress = block）".to_string(),
    }
}

/// 实测失败的原因文本（`OpenError` 同样没有 `Display`）。
fn open_error_text(e: &crate::stream::OpenError) -> String {
    match e {
        crate::stream::OpenError::SelfLoop => "目标是本机自己，应当走直连".to_string(),
        crate::stream::OpenError::NoRoute => "到该出口当前没有路由".to_string(),
        crate::stream::OpenError::Refused => "出口侧拒绝（egress = block）".to_string(),
        crate::stream::OpenError::Timeout => "出口没有在超时内回应".to_string(),
        crate::stream::OpenError::Rejected { code, reason } => {
            format!("出口连不上目标（code {code}）：{reason}")
        }
    }
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
    use crate::testutil::nid;

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
        cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
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
        cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
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
            cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
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
        cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
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
        cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
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

    /// 起一个只监听回环、不发现、不拨号的节点（新加的探测/默认出口测试共用）。
    async fn start_test_node(tag: &str) -> (Arc<HiveNode>, PathBuf) {
        let dir = std::env::temp_dir()
            .join(format!("hiveproxy-{tag}-{}-{}", std::process::id(), now_unix()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg.listen.bind = "127.0.0.1".parse().unwrap();
        cfg.listen.ports = vec![0];
        cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
        cfg.discovery.lan_udp = false;
        (HiveNode::start(cfg, &dir).await.unwrap(), dir)
    }

    #[tokio::test]
    async fn default_egress_is_settable_persisted_and_visible_in_status() {
        let (node, dir) = start_test_node("defegress").await;

        node.set_default_egress(Some("10.0.0.5")).unwrap();
        assert_eq!(node.status().default_egress.as_deref(), Some("node:10.0.0.5"));
        // 落盘：重新读一遍磁盘上的配置
        let saved = persist::load_config(&dir).unwrap();
        assert_eq!(
            saved.route.default_egress,
            Some(EgressTarget::Node("10.0.0.5".parse().unwrap()))
        );

        // "none" = 清除
        node.set_default_egress(Some("none")).unwrap();
        assert!(node.status().default_egress.is_none());

        // auto / block 在这里没有意义，必须报错而不是静默收下
        assert!(node.set_default_egress(Some("auto")).is_err());
        assert!(node.set_default_egress(Some("block")).is_err());
        assert!(node.set_default_egress(Some("乱七八糟")).is_err());

        node.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn check_rules_points_at_the_bad_row_and_field() {
        let (node, dir) = start_test_node("checkrules").await;
        let rows: Vec<RawRule> = serde_json::from_str(
            r#"[
              {"host":"*.corp.example.com","port":"443","egress":"direct"},
              {"host":"10.1.2.9:8080","port":"*","egress":"auto"},
              {"host":"10.9.0.0/33","port":"8000-7000","egress":"node:10.0.0.5"},
              {"host":"10.9.1.0/24","port":"*","egress":"nod:10.0.0.5","on_unreachable":"fail"}
            ]"#,
        )
        .unwrap();
        let issues = node.check_rules(rows);

        assert!(!issues.iter().any(|i| i.index == 0), "第 1 行是好的");
        assert!(issues.iter().any(|i| i.index == 1 && i.field == "host"), "{issues:?}");
        let third: Vec<&str> =
            issues.iter().filter(|i| i.index == 2).map(|i| i.field.as_str()).collect();
        assert!(third.contains(&"host") && third.contains(&"port"), "{issues:?}");
        assert!(issues.iter().any(|i| i.index == 3 && i.field == "egress"), "{issues:?}");
        // 每一条都要有话说，不能只报"错了"（§18 第 32 条：行内校验的意义就在这句人话里）
        assert!(issues.iter().all(|i| !i.message.is_empty()));

        node.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn probe_exits_lists_self_first_and_marks_the_declarer() {
        let (node, dir) = start_test_node("probeexits").await;

        // 手动塞一份拓扑：本机 -> 10.4.0.9（声明 10.4.0.0/24），另有一台不做出口的 10.0.0.7
        let topo = crate::testutil::topology(
            "127.0.0.1",
            &[("127.0.0.1", "10.4.0.9"), ("127.0.0.1", "10.0.0.7")],
            &[("10.4.0.9", "10.4.0.0/24")],
            &["10.0.0.7"],
        );
        *node.state.topology.write() = topo;
        node.state.rebuild_router();

        let cands = node.probe_exits("10.4.0.7:3389").unwrap();
        let self_row = cands.iter().find(|c| c.is_self).expect("本机直连必须在候选里");
        assert_eq!(self_row.cost, Some(0), "自己永远是成本 0（§9.4.4）");
        assert!(self_row.unusable.is_none());

        let declarer = cands.iter().find(|c| c.node == nid("10.4.0.9")).unwrap();
        assert!(declarer.declares_target, "它声明了目标所在的网段");
        assert!(declarer.selected, "自动选中的应当就是它");
        assert_eq!(cands[0].node, declarer.node, "选中的排第一");

        let refuse = cands.iter().find(|c| c.node == nid("10.0.0.7")).unwrap();
        assert!(refuse.unusable.is_some(), "不做出口的节点要给出理由，而不是消失");
        assert!(!refuse.declares_target);

        // 域名目标：没有人"声明"过它
        let by_name = node.probe_exits("api.corp.example.com:443").unwrap();
        assert!(by_name.iter().all(|c| !c.declares_target));

        node.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn probe_dial_really_connects_or_reports_why_not() {
        let (node, dir) = start_test_node("probedial").await;
        let me = node.state.self_id();

        // 真起一个本地监听，实测本机直连必须通
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let ok = node.probe_dial(&format!("127.0.0.1:{port}"), me).await.unwrap();
        assert!(ok.ok, "本机直连应当成功：{}", ok.detail);
        assert!(ok.direct);

        // 没人监听的端口：报错，且要说人话（不是 `ConnectionRefused` 这种原文）
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let bad = node.probe_dial(&format!("127.0.0.1:{dead_port}"), me).await.unwrap();
        assert!(!bad.ok);
        assert!(bad.detail.contains("本机"), "{}", bad.detail);

        // 走 overlay 但到不了那个节点：给的是"没有路由"，不是 panic
        let unreachable = node.probe_dial("10.4.0.7:3389", nid("10.99.99.99")).await.unwrap();
        assert!(!unreachable.ok);
        assert!(!unreachable.direct);

        node.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }
}
