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

/// 解析结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub egress: Egress,
    /// 命中的规则在合并表里的下标；`None` 表示由内置网段兜底行命中。
    pub matched_rule: Option<usize>,
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

/// 解析目标 → 出口（§9.4.4）。
pub fn resolve(ctx: &ResolveCtx<'_>, target: &Endpoint) -> Result<Resolved, ResolveError> {
    if !ctx.rules.rules_enabled {
        // 全局旁路：整表退化为只有网段兜底行。
        return subnet_match(ctx, target)
            .map(|n| Resolved { egress: egress_of(ctx, n), matched_rule: None });
    }

    for (idx, rule) in ctx.rules.merged.iter().enumerate() {
        if !rule.enabled || !rule.matches(target) {
            continue;
        }

        // 命中但出口不可用时统一处理（§9.4.4 的 fallthrough）。
        let fallthrough = |rule: &crate::rules::Rule| -> Option<Result<Resolved, ResolveError>> {
            match rule.on_unreachable {
                OnUnreachable::Fail => Some(Err(ResolveError::NoRoute)),
                OnUnreachable::Fallback => None, // 顺延下一顺位
            }
        };

        match &rule.egress {
            EgressTarget::Block => return Err(ResolveError::Refused),

            // "本机直接 connect" 与"愿不愿意为别人做出口"无关，永远生效。
            EgressTarget::SelfDirect => {
                return Ok(Resolved { egress: Egress::Direct, matched_rule: Some(idx) })
            }

            EgressTarget::Node(n) => {
                if can_egress(ctx, *n) && in_island(ctx, *n) {
                    return Ok(Resolved { egress: egress_of(ctx, *n), matched_rule: Some(idx) });
                }
                if let Some(e) = fallthrough(rule) {
                    return e;
                }
                continue;
            }

            EgressTarget::Alias(a) => {
                match ctx.alias_table.get(a) {
                    Some(n) if can_egress(ctx, *n) && in_island(ctx, *n) => {
                        return Ok(Resolved { egress: egress_of(ctx, *n), matched_rule: Some(idx) })
                    }
                    _ => {
                        if let Some(e) = fallthrough(rule) {
                            return e;
                        }
                        continue;
                    }
                }
            }

            EgressTarget::Group(g) => {
                let members = group_members(ctx, g);
                let viable: Vec<NodeId> = members
                    .iter()
                    .copied()
                    .filter(|n| can_egress(ctx, *n) && in_island(ctx, *n))
                    .collect();
                match min_by_cost(ctx, &viable) {
                    Some(n) => {
                        return Ok(Resolved { egress: egress_of(ctx, n), matched_rule: Some(idx) })
                    }
                    None => {
                        if let Some(e) = fallthrough(rule) {
                            return e;
                        }
                        continue;
                    }
                }
            }

            // ★ 显式交给网段规则；**失败也要继续往后找**，不能直接 return。
            EgressTarget::Auto => match subnet_match(ctx, target) {
                Ok(n) => {
                    return Ok(Resolved { egress: egress_of(ctx, n), matched_rule: Some(idx) })
                }
                Err(_) => continue,
            },
        }
    }

    subnet_match(ctx, target).map(|n| Resolved { egress: egress_of(ctx, n), matched_rule: None })
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
            }
        }
    }

    fn fx(me: &str, edges: &[(&str, &str)], subnets: &[(&str, &str)], deny: &[&str]) -> Fixture {
        let topo = topology(me, edges, subnets, deny);
        let router = router(me, &topo);
        Fixture { topo, router, groups: Vec::new(), aliases: HashMap::new() }
    }

    #[test]
    fn default_behaviour_needs_no_rules() {
        // §18 第 14 条：一条规则都不写也能访问所有节点网段内的任意 IP。
        let f = fx("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[("10.4.0.9", "10.4.0.0/24")], &[]);
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        let r = resolve(&ctx, &ep("10.4.0.7:3389")).unwrap();
        assert_eq!(r.egress, Egress::Node(nid("10.4.0.9")));
        assert_eq!(r.matched_rule, None, "由内置网段兜底行命中");
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
        assert_eq!(r.matched_rule, Some(1), "应当命中第二条规则");
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
        assert_eq!(r.matched_rule, None);
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
        assert_eq!(r.matched_rule, Some(0));
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
        let f = Fixture { topo, router: r, groups: vec![], aliases: HashMap::new() };
        let t = RuleTable::default();
        let ctx = f.ctx(&t, "10.0.0.1");
        let res = resolve(&ctx, &ep("10.8.0.5:80")).unwrap();
        assert_eq!(res.egress, Egress::Node(nid("10.0.0.4")), "三跳之外仍然可达");
    }
}
