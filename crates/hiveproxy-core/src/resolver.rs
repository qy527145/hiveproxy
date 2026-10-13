//! 出口选择：`resolve()`（DESIGN.md §9.4.4）。
//!
//! 这是 SOCKS5 入口唯一要问的问题：**"谁去连这个目标"**。
//! 规则是**有序列表、先匹配者胜**；表尾的内置网段匹配等价于一条只读的兜底规则。

use std::collections::{HashMap, HashSet};

use crate::config::GroupCfg;
use crate::proto::{Endpoint, Host, NodeId};
use crate::router::Router;
use crate::rules::{EgressTarget, GroupRef, OnUnreachable, RuleTable};
use crate::topology::Topology;

/// 选出的出口。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Egress {
    /// 由该节点发起 connect。
    Node(NodeId),
    /// 本机直接 connect，不进 overlay（§9.4.4 的 `SelfDirect`）。
    Direct,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// 无路由 / 目标不落在任何已知网段。
    NoRoute,
    /// 被规则显式拒绝（§5.7 的 `UnreachableReason::Refused`）。
    Refused,
}

impl ResolveError {
    pub fn reason(&self) -> crate::proto::UnreachableReason {
        match self {
            Self::NoRoute => crate::proto::UnreachableReason::NoRoute,
            Self::Refused => crate::proto::UnreachableReason::Refused,
        }
    }
}

/// 这个出口是怎么定下来的（§9.4.4）。
///
/// 界面上必须能区分三者：探测结果说"内置网段兜底行"而实际走的是默认出口，
/// 是最容易让人对着界面怀疑人生的那种错。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchSource {
    /// 命中了合并表里的第 `idx` 条规则（本地在前、共享在后）。
    Rule(usize),
    /// 内置的网段兜底行（"目标落在已知网段 → 选最近的声明者"）。
    Subnet,
    /// `route.default_egress`（最后一顺位，§18 第 29 条）。
    Default,
}

impl MatchSource {
    /// 命中的规则下标；非规则命中时为 `None`。
    pub fn rule_index(self) -> Option<usize> {
        match self {
            Self::Rule(i) => Some(i),
            _ => None,
        }
    }

    /// 给界面用的短标识（`StreamProbe.via`）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule(_) => "rule",
            Self::Subnet => "subnet",
            Self::Default => "default",
        }
    }
}

/// 解析结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub egress: Egress,
    pub source: MatchSource,
}

impl Resolved {
    /// 解析出的目的节点（`Direct` 时就是自己）。
    pub fn dst_node(&self, self_id: NodeId) -> NodeId {
        match self.egress {
            Egress::Node(n) => n,
            Egress::Direct => self_id,
        }
    }
}

/// 解析所需的全部上下文。
pub struct ResolveCtx<'a> {
    pub rules: &'a RuleTable,
    pub topo: &'a Topology,
    pub router: &'a Router,
    pub self_id: NodeId,
    /// 别名 → 节点（本地 `peers.entry` 优先，其次是 gossip 里广播的 alias）。
    pub alias_table: &'a HashMap<String, NodeId>,
    pub groups: &'a [GroupCfg],
    /// zone 限定：非空时只在该孤岛的节点里选出口（§9.3 情形二）。
    pub island_filter: Option<&'a HashSet<NodeId>>,
    /// 最后一顺位出口（`route.default_egress`）。
    ///
    /// **注意它不在 `RuleTable` 里**：放进规则表就必然排在只读的网段兜底行**之前**
    /// —— 等于"没命中规则就一律走它"，会把内网目标的自动就近整个吃掉
    /// （§18 第 29 条明确否掉了那个方案）。
    pub default_egress: Option<&'a EgressTarget>,
}

/// 出口可用性判定（§9.4.4）：有路由，且对端没有声明 `accepts_egress = false`。
///
/// ⚠️ **自己永远算可用** —— `egress.allow_egress` 管的是"别人能不能把流量交给**我**"，
/// 与"我自己能不能连自己够得着的地方"是两件事。早先把它也套在自己身上，
/// 结果是敏感机器一关出口，连自己局域网都访问不了。
fn can_egress(ctx: &ResolveCtx<'_>, n: NodeId) -> bool {
    if n == ctx.self_id {
        return true;
    }
    if ctx.router.cost_to(n).is_none() {
        return false;
    }
    match ctx.topo.peers.get(&n) {
        Some(m) => m.accepts_egress,
        // 拓扑里还没有它的元信息时保守放行（能用 IP 路由到就说明链路是活的）
        None => true,
    }
}

fn in_island(ctx: &ResolveCtx<'_>, n: NodeId) -> bool {
    match ctx.island_filter {
        None => true,
        Some(set) => set.contains(&n),
    }
}

/// 在候选集中选成本最低者；成本相同按 `NodeId` 字节序稳定裁决（§9.3 情形一）。
fn min_by_cost<'a, I>(ctx: &ResolveCtx<'_>, cands: I) -> Option<NodeId>
where
    I: IntoIterator<Item = &'a NodeId>,
{
    let mut best: Option<(u32, NodeId)> = None;
    for &n in cands {
        if !in_island(ctx, n) {
            continue;
        }
        let cost = if n == ctx.self_id { 0 } else { ctx.router.cost_to(n).unwrap_or(u32::MAX) };
        if cost == u32::MAX {
            continue;
        }
        let key = (cost, n);
        if best.map(|b| key < b).unwrap_or(true) {
            best = Some(key);
        }
    }
    best.map(|(_, n)| n)
}

/// 网段匹配 —— 表尾那条只读兜底行的实现，也是 §9.2 的第 2 步。
pub fn subnet_match(ctx: &ResolveCtx<'_>, target: &Endpoint) -> Result<NodeId, ResolveError> {
    let ip = match &target.host {
        Host::Ip(ip) => *ip,
        // 域名没有 IP，永远不参与网段匹配（§9.4.2 推论）。
        Host::Name(_) => return Err(ResolveError::NoRoute),
    };
    let owners = ctx.topo.segments_for_ip(ip);
    let viable: Vec<NodeId> =
        owners.into_iter().filter(|n| can_egress(ctx, *n)).collect();
    min_by_cost(ctx, &viable).ok_or(ResolveError::NoRoute)
}

/// 候选集（`group:`）的成员解析。
fn group_members(ctx: &ResolveCtx<'_>, g: &GroupRef) -> Vec<NodeId> {
    match g {
        GroupRef::Subnet(net) => {
            let mut v = ctx.topo.owners_of_subnet(net);
            v.sort();
            v.dedup();
            v
        }
        GroupRef::Named(name) => {
            let Some(cfg) = ctx.groups.iter().find(|c| &c.name == name) else {
                return Vec::new();
            };
            let mut v = Vec::new();
            for m in &cfg.members {
                match crate::config::parse_peer_address(m) {
                    Ok((ip, _)) => v.push(NodeId::from_ip(ip)),
                    Err(_) => {
                        if let Some(id) = ctx.alias_table.get(m) {
                            v.push(*id);
                        }
                    }
                }
            }
            v.sort();
            v.dedup();
            v
        }
    }
}

/// 解析一个出口目标 → 具体出口（§9.4.4）。
///
/// 返回 `Ok(None)` ＝ "这次没定下来"（候选都不可用 / `auto` 没找到网段），由**调用方**
/// 决定是顺延下一顺位还是就此收尾 —— 规则那侧还要看 `on_unreachable`，
/// 默认出口那侧没有下一顺位可退。
fn resolve_egress_target(
    ctx: &ResolveCtx<'_>,
    target: &Endpoint,
    egress: &EgressTarget,
) -> Result<Option<Egress>, ResolveError> {
    match egress {
        EgressTarget::Block => Err(ResolveError::Refused),

        // "本机直接 connect" 与"愿不愿意为别人做出口"无关，永远生效。
        EgressTarget::SelfDirect => Ok(Some(Egress::Direct)),

        EgressTarget::Node(n) => {
            Ok((can_egress(ctx, *n) && in_island(ctx, *n)).then(|| egress_of(ctx, *n)))
        }

        EgressTarget::Alias(a) => Ok(ctx
            .alias_table
            .get(a)
            .filter(|n| can_egress(ctx, **n) && in_island(ctx, **n))
            .map(|n| egress_of(ctx, *n))),

        EgressTarget::Group(g) => {
            let members = group_members(ctx, g);
            let viable: Vec<NodeId> = members
                .iter()
                .copied()
                .filter(|n| can_egress(ctx, *n) && in_island(ctx, *n))
                .collect();
            Ok(min_by_cost(ctx, &viable).map(|n| egress_of(ctx, n)))
        }

        // 显式交给网段规则；**失败也要能继续往后找**，不能直接判死。
        EgressTarget::Auto => Ok(subnet_match(ctx, target).ok().map(|n| egress_of(ctx, n))),
    }
}

/// 解析目标 → 出口（§9.4.4）。顺序：**规则表 → 内置网段匹配 → 默认出口**。
pub fn resolve(ctx: &ResolveCtx<'_>, target: &Endpoint) -> Result<Resolved, ResolveError> {
    // 全局旁路：整表退化为只有网段兜底行。**默认出口仍然生效** —— 它是配置而不是规则，
    // 而旁路这个紧急开关要解决的是"某条规则写错了"，不是"我想要的默认出口也要停"。
    if ctx.rules.rules_enabled {
        for (idx, rule) in ctx.rules.merged.iter().enumerate() {
            if !rule.enabled || !rule.matches(target) {
                continue;
            }
            match resolve_egress_target(ctx, target, &rule.egress)? {
                Some(egress) => return Ok(Resolved { egress, source: MatchSource::Rule(idx) }),
                None => {
                    // ★ `auto` 没找到网段时**一律顺延**，不看 on_unreachable：
                    // 它表达的是"这类目标我不管，谁近谁去"，没找到就是没找到（§9.4.4）。
                    if matches!(rule.egress, EgressTarget::Auto) {
                        continue;
                    }
                    match rule.on_unreachable {
                        OnUnreachable::Fail => return Err(ResolveError::NoRoute),
                        OnUnreachable::Fallback => continue,
                    }
                }
            }
        }
    }

    // 内置网段兜底行（只读）。
    if let Ok(n) = subnet_match(ctx, target) {
        return Ok(Resolved { egress: egress_of(ctx, n), source: MatchSource::Subnet });
    }

    // 最后一顺位：默认出口。**不可达时不再改道** —— 它后面没有下一顺位了，
    // 静默改道只会让"为什么走了别处"变成没人答得上来的问题（§18 第 29 条）。
    if let Some(d) = ctx.default_egress {
        // `auto` / `block` 在配置反序列化时就被拒了；这里再兜一层，防止程序化构造绕过。
        if d.check_default_egress().is_err() {
            return Err(ResolveError::NoRoute);
        }
        if let Some(egress) = resolve_egress_target(ctx, target, d)? {
            return Ok(Resolved { egress, source: MatchSource::Default });
        }
    }

    Err(ResolveError::NoRoute)
}

fn egress_of(ctx: &ResolveCtx<'_>, n: NodeId) -> Egress {
    if n == ctx.self_id {
        Egress::Direct
    } else {
        Egress::Node(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{EgressTarget, GroupRef, HostMatcher, PortMatcher, Rule, RuleTable};
    use crate::testutil::{linked_chain, nid, router, topology};

    fn ep(s: &str) -> Endpoint {
        let (h, p) = s.rsplit_once(':').unwrap();
        let port: u16 = p.parse().unwrap();
        let host = match h.parse() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Name(h.to_string()),
        };
        Endpoint::new(host, port)
    }

    struct Fixture {
        topo: Topology,
        router: Router,
        groups: Vec<GroupCfg>,
        aliases: HashMap<String, NodeId>,
        default_egress: Option<EgressTarget>,
    }

    impl Fixture {
        fn ctx<'a>(&'a self, rules: &'a RuleTable, self_id: &str) -> ResolveCtx<'a> {
            ResolveCtx {
                rules,
                topo: &self.topo,
                router: &self.router,
                self_id: nid(self_id),
                alias_table: &self.aliases,
                groups: &self.groups,
                island_filter: None,
                default_egress: self.default_egress.as_ref(),
            }
        }
    }

    fn fx(me: &str, edges: &[(&str, &str)], subnets: &[(&str, &str)], deny: &[&str]) -> Fixture {
        let topo = topology(me, edges, subnets, deny);
        let router = router(me, &topo);
        Fixture {
            topo,
            router,
            groups: Vec::new(),
            aliases: HashMap::new(),
            default_egress: None,
        }
    }

    /// 带一个默认出口的 fixture（§9.4.4 的最后一顺位）。
    fn fx_default(
        me: &str,
        edges: &[(&str, &str)],
        subnets: &[(&str, &str)],
        default_egress: EgressTarget,
    ) -> Fixture {
        let topo = topology(me, edges, subnets, &[]);
        let router = router(me, &topo);
        Fixture {
            topo,
            router,
            groups: Vec::new(),
            aliases: HashMap::new(),
            default_egress: Some(default_egress),
        }
    }

    #[test]
    fn default_egress_takes_domains_nobody_can_route() {
        // 域名不参与网段匹配（§9.4.2），没有默认出口时只能 NoRoute —— 这正是
        // "浏览器流量为什么全废"的根因，也是默认出口存在的理由（§18 第 29 条）。
        let f = fx_default(
            "10.0.0.1",
            &[("10.0.0.1", "10.0.0.5")],
            &[("10.0.0.5", "10.9.0.0/16")],
            EgressTarget::Node(nid("10.0.0.5")),
        );
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("api.corp.example.com:443")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.0.0.5")));
        assert_eq!(r.source, MatchSource::Default, "来源必须是默认出口，不能算成网段兜底");
    }

    #[test]
    fn default_egress_never_beats_subnet_matching() {
        // ★ 这条是整个设计的关键：默认出口排在**网段匹配之后**。
        // 目标在已知网段里，就必须走声明了该网段的节点，而不是默认出口 ——
        // 否则零配置合岛（§18 第 14 条）被一条配置项悄悄吃掉。
        let f = fx_default(
            "10.0.0.1",
            &[("10.0.0.1", "10.0.0.5"), ("10.0.0.1", "10.4.0.9")],
            &[("10.4.0.9", "10.4.0.0/24"), ("10.0.0.5", "10.9.0.0/16")],
            EgressTarget::Node(nid("10.0.0.5")),
        );
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.4.0.7:3389")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.4.0.9")));
        assert_eq!(r.source, MatchSource::Subnet);
        // 网段里没人能去（换一个谁都没声明的 IP）时才轮到默认出口。
        let r = resolve(&ctx, &ep("172.16.0.9:3389")).unwrap();
        assert_eq!(r.source, MatchSource::Default);
    }

    #[test]
    fn default_egress_survives_the_bypass_switch() {
        // 全局旁路是"规则都别生效"，而默认出口是配置不是规则 —— 旁路时它照常生效，
        // 否则排障期间连域名都解析不动，人会怀疑是网络坏了。
        let f = fx_default(
            "10.0.0.1",
            &[("10.0.0.1", "10.0.0.5")],
            &[("10.0.0.5", "10.9.0.0/16")],
            EgressTarget::Node(nid("10.0.0.5")),
        );
        let t = RuleTable::build(
            &[Rule::new(HostMatcher::Any, PortMatcher::Any, EgressTarget::Block)],
            None,
            false,
        );
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("api.corp.example.com:443")).unwrap();
        assert_eq!(r.source, MatchSource::Default);
    }

    #[test]
    fn unreachable_default_egress_is_no_route_not_a_silent_detour() {
        // 默认出口后面没有下一顺位了：不可达就报错，不偷偷改成别的出口。
        let f = fx_default(
            "10.0.0.1",
            &[("10.0.0.1", "10.0.0.5")],
            &[("10.0.0.5", "10.9.0.0/16")],
            EgressTarget::Node(nid("10.99.99.99")),
        );
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        assert_eq!(
            resolve(&ctx, &ep("api.corp.example.com:443")),
            Err(ResolveError::NoRoute)
        );
    }

    #[test]
    fn default_egress_direct_never_consults_the_overlay() {
        // `default_egress = "direct"`：目标在本机够得着的地方时，这是最省事的兜底。
        let f = fx_default(
            "10.0.0.1",
            &[("10.0.0.1", "10.0.0.5")],
            &[("10.0.0.5", "10.9.0.0/16")],
            EgressTarget::SelfDirect,
        );
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("api.corp.example.com:443")).unwrap();
        assert_eq!(r.egress, Egress::Direct);
        assert_eq!(r.source, MatchSource::Default);
    }

    #[test]
    fn default_behaviour_needs_no_rules() {
        // §18 第 14 条：一条规则都不写也能访问所有节点网段内的任意 IP。
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[("10.4.0.9", "10.4.0.0/24")], &[]);
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.4.0.7:3389")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.4.0.9")));
        assert_eq!(r.source, MatchSource::Subnet, "由内置网段兜底行命中");
    }

    #[test]
    fn self_wins_on_its_own_subnet_by_zero_cost() {
        let f = fx("10.1.2.5", &[("10.1.2.5", "10.0.0.1")], &[("10.1.2.5", "10.1.2.0/24")], &[]);
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.1.2.5");
        let r = resolve(&ctx, &ep("10.1.2.9:22")).unwrap();
        assert_eq!(r.egress, Egress::Direct, "本机网段内的目标自然走直连，无需特殊分支");
    }

    #[test]
    fn domain_never_matches_subnet() {
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[("10.4.0.9", "10.4.0.0/24")], &[]);
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        assert_eq!(resolve(&ctx, &ep("api.corp.example.com:443")), Err(ResolveError::NoRoute));
    }

    #[test]
    fn block_returns_refused_not_denied() {
        // UnreachableReason 里没有 Denied 变体（§5.7）。
        let f = fx("10.0.0.1", &[], &[], &[]);
        let rules = vec![Rule::new(HostMatcher::Any, PortMatcher::Any, EgressTarget::Block)];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        let err = resolve(&ctx, &ep("10.9.9.9:22")).unwrap_err();
        assert_eq!(err, ResolveError::Refused);
        assert_eq!(err.reason(), crate::proto::UnreachableReason::Refused);
    }

    #[test]
    fn auto_falls_through_to_the_next_rule() {
        // ★ 本轮修掉的 bug：`Auto` 命中但网段匹配失败时，必须继续匹配后面的规则，
        // 而不是直接返回错误把后面的规则全屏蔽掉。
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[("10.4.0.9", "10.4.0.0/24")], &[]);
        let rules = vec![
            // 命中域名，但域名永远不参与网段匹配 → 必须顺延
            Rule::new(
                HostMatcher::parse("*.example.com").unwrap(),
                PortMatcher::Any,
                EgressTarget::Auto,
            ),
            Rule::new(
                HostMatcher::parse("*.example.com").unwrap(),
                PortMatcher::Any,
                EgressTarget::Node(nid("10.4.0.9")),
            ),
        ];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("api.example.com:443")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.4.0.9")));
        assert_eq!(r.source, MatchSource::Rule(1), "应当命中第二条规则");
    }

    #[test]
    fn fail_stops_instead_of_falling_through() {
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[("10.4.0.9", "10.4.0.0/24")], &[]);
        let mut r1 = Rule::new(
            HostMatcher::Any,
            PortMatcher::Any,
            EgressTarget::Node(nid("10.99.99.99")), // 不可达
        );
        r1.on_unreachable = OnUnreachable::Fail;
        let rules = vec![r1];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        assert_eq!(resolve(&ctx, &ep("10.4.0.7:22")), Err(ResolveError::NoRoute));
    }

    #[test]
    fn fallback_reaches_the_builtin_subnet_rule() {
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[("10.4.0.9", "10.4.0.0/24")], &[]);
        let rules = vec![Rule::new(
            HostMatcher::Any,
            PortMatcher::Any,
            EgressTarget::Node(nid("10.99.99.99")), // 不可达，默认 fallback
        )];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.4.0.7:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.4.0.9")), "顺延最终落到内置网段规则");
        assert_eq!(r.source, MatchSource::Subnet);
    }

    #[test]
    fn group_subnet_derives_membership_from_topology() {
        let f = fx(
            "10.0.0.1",
            &[("10.0.0.1", "10.1.2.5"), ("10.0.0.1", "10.1.2.6")],
            &[("10.1.2.5", "10.9.0.0/16"), ("10.1.2.6", "10.9.0.0/16")],
            &[],
        );
        let rules = vec![Rule::new(
            HostMatcher::parse("*.db.corp.com").unwrap(),
            PortMatcher::Any,
            EgressTarget::Group(GroupRef::Subnet("10.9.0.0/16".parse().unwrap())),
        )];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("shard1.db.corp.com:5432")).unwrap();
        // 成本相同 → 按 NodeId 字节序稳定裁决
        assert_eq!(r.egress, Egress::Node(nid("10.1.2.5")));
    }

    #[test]
    fn group_subnet_members_shrink_when_a_node_goes_away() {
        let f = fx(
            "10.0.0.1",
            &[("10.0.0.1", "10.1.2.5"), ("10.0.0.1", "10.1.2.6")],
            &[("10.1.2.5", "10.9.0.0/16"), ("10.1.2.6", "10.9.0.0/16")],
            &[],
        );
        let rules = vec![Rule::new(
            HostMatcher::Any,
            PortMatcher::Any,
            EgressTarget::Group(GroupRef::Subnet("10.9.0.0/16".parse().unwrap())),
        )];
        let t = RuleTable::build(&rules, None, true);
        let mut f = f;
        f.topo.lose_peer(nid("10.1.2.5"));
        f.router = router("10.0.0.1", &f.topo);
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.9.1.1:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.1.2.6")), "成员自动跟随拓扑变化");
    }

    #[test]
    fn named_group_uses_explicit_members() {
        let mut f = fx("10.0.0.1", &[("10.0.0.1", "10.1.2.5"), ("10.0.0.1", "10.1.2.6")], &[], &[]);
        f.groups = vec![GroupCfg {
            name: "db".into(),
            members: vec!["10.1.2.6".into()],
        }];
        let rules = vec![Rule::new(
            HostMatcher::Any,
            PortMatcher::Any,
            EgressTarget::Group(GroupRef::Named("db".into())),
        )];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.9.1.1:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.1.2.6")));
    }

    #[test]
    fn alias_resolves_through_the_table() {
        let mut f = fx("10.0.0.1", &[("10.0.0.1", "10.1.2.5")], &[], &[]);
        f.aliases.insert("gpu-01".into(), nid("10.1.2.5"));
        let rules = vec![Rule::new(
            HostMatcher::Any,
            PortMatcher::Any,
            EgressTarget::Alias("gpu-01".into()),
        )];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.9.1.1:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.1.2.5")));
    }

    #[test]
    fn unreachable_alias_falls_through() {
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[("10.4.0.9", "10.4.0.0/24")], &[]);
        let rules = vec![Rule::new(
            HostMatcher::Any,
            PortMatcher::Any,
            EgressTarget::Alias("nope".into()),
        )];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.4.0.7:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.4.0.9")));
    }

    #[test]
    fn node_that_refuses_egress_is_never_chosen() {
        // §9.4.4：accepts_egress = false 的节点直接不进候选。
        let f = fx(
            "10.0.0.1",
            &[("10.0.0.1", "10.1.2.5"), ("10.0.0.1", "10.1.2.6")],
            &[("10.1.2.5", "10.9.0.0/16"), ("10.1.2.6", "10.9.0.0/16")],
            &["10.1.2.5"],
        );
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.9.1.1:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.1.2.6")), "拒绝做出口的节点必须被跳过");
    }

    #[test]
    fn all_candidates_refusing_yields_no_route_not_silent_direct() {
        let f = fx(
            "10.0.0.1",
            &[("10.0.0.1", "10.1.2.5")],
            &[("10.1.2.5", "10.9.0.0/16")],
            &["10.1.2.5"],
        );
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        assert_eq!(
            resolve(&ctx, &ep("10.9.1.1:22")),
            Err(ResolveError::NoRoute),
            "候选全部不可达时必须回错误码，而不是静默退化成不可预期的本地连接"
        );
    }

    #[test]
    fn bypass_ignores_every_rule() {
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[("10.4.0.9", "10.4.0.0/24")], &[]);
        let rules = vec![Rule::new(HostMatcher::Any, PortMatcher::Any, EgressTarget::Block)];
        let t = RuleTable::build(&rules, None, false); // rules_enabled = false
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.4.0.7:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.4.0.9")));
    }

    #[test]
    fn first_match_wins_ordered_rules() {
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.1.2.5"), ("10.0.0.1", "10.1.2.6")], &[], &[]);
        let rules = vec![
            Rule::new(HostMatcher::parse("10.9.0.0/16").unwrap(), PortMatcher::Any, EgressTarget::Node(nid("10.1.2.6"))),
            Rule::new(HostMatcher::parse("10.9.0.0/16").unwrap(), PortMatcher::Any, EgressTarget::Node(nid("10.1.2.5"))),
        ];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.9.1.1:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.1.2.6")), "先匹配者胜");
        assert_eq!(r.source, MatchSource::Rule(0));
    }

    #[test]
    fn island_filter_restricts_candidates() {
        // zone 限定：只在该孤岛的节点里选（§9.3 情形二）。
        let f = fx(
            "10.0.0.1",
            &[("10.0.0.1", "10.1.2.5"), ("10.0.0.1", "10.1.2.6")],
            &[("10.1.2.5", "10.9.0.0/16"), ("10.1.2.6", "10.9.0.0/16")],
            &[],
        );
        let t = RuleTable::default();
        let island: HashSet<NodeId> = [nid("10.1.2.6")].into_iter().collect();
        let ctx = ResolveCtx {
            rules: &t,
            topo: &f.topo,
            router: &f.router,
            self_id: nid("10.0.0.1"),
            alias_table: &f.aliases,
            groups: &[],
            island_filter: Some(&island),
            default_egress: None,
        };
        let r = resolve(&ctx, &ep("10.9.1.1:22")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.1.2.6")));
        let _ = &f;
    }

    #[test]
    fn self_is_always_an_egress_for_its_own_traffic() {
        // 不变式：**自己永远是自己的出口候选项**。
        // `egress.allow_egress` 管的是"别人能不能把流量交给我"，与"我自己能连什么"无关；
        // 早期版本把两者混在一起，导致 `allow_egress = false` 的机器连自己的局域网都访问不了。
        // 现在 ResolveCtx 里根本不带这个字段，也就是说这个 bug 在类型层面就写不出来了。
        let f = fx("10.1.2.5", &[("10.1.2.5", "10.0.0.1")], &[("10.1.2.5", "10.1.2.0/24")], &[]);
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.1.2.5");
        let r = resolve(&ctx, &ep("10.1.2.9:22")).expect("本机网段内的目标必须可达");
        assert_eq!(r.egress, Egress::Direct);
    }

    #[test]
    fn self_direct_rule_always_applies() {
        // `egress = "direct"` 的语义就是"本机直接连"，不该有任何前置条件。
        let f = fx("10.1.2.5", &[("10.1.2.5", "10.0.0.1")], &[], &[]);
        let rules = vec![Rule::new(
            HostMatcher::parse("192.168.1.0/24").unwrap(),
            PortMatcher::Any,
            EgressTarget::SelfDirect,
        )];
        let t = RuleTable::build(&rules, None, true);
        let ctx = f.ctx(&t, "10.1.2.5");
        let r = resolve(&ctx, &ep("192.168.1.9:80")).expect("direct 规则必须生效");
        assert_eq!(r.egress, Egress::Direct);
    }

    #[test]
    fn long_chain_still_reachable_through_relays() {
        let topo = linked_chain("10.0.0.1", &["10.0.0.2", "10.0.0.3", "10.0.0.4"]);
        let mut topo = topo;
        topo.merge_gossip(&crate::proto::GossipMsg {
            owner: nid("10.0.0.4"),
            incarnation: 1,
            seq: 2,
            edges: vec![crate::proto::AdjEntry {
                peer: nid("10.0.0.3"),
                cost: 1,
                carrier: crate::proto::Carrier::Direct,
                rtt_ms: 1,
            }],
            subnets: vec![crate::proto::SubnetAd::any_port("10.8.0.0/24".parse().unwrap())],
            listen: crate::proto::ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: None,
            digest: Vec::new(),
        });
        let r = router("10.0.0.1", &topo);
        let f = Fixture {
            topo,
            router: r,
            groups: vec![],
            aliases: HashMap::new(),
            default_egress: None,
        };
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        let res = resolve(&ctx, &ep("10.8.0.5:80")).unwrap();
        assert_eq!(res.egress, Egress::Node(nid("10.0.0.4")), "三跳之外仍然可达");
    }
}
