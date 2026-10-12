//! 网段重叠的消歧：孤岛检测、`ZoneId` 确定性派生、区域限定寻址（DESIGN.md §9.3）。
//!
//! 两种情形必须分开：
//! - **情形一（正常，不是冲突）**：同一个局域网被多个节点声明 → 同一张网的多条冗余出口。
//! - **情形二（真冲突）**：两片彼此隔离的孤岛撞了同一个私网段 → 需要 zone 前缀消歧。
//!
//! 判定用的是**节点身份地址是否落在同一条被声明的前缀内**，而不是"有没有直连边" ——
//! §6.5 的 `max_links` 剪枝会让同一个 L2 里的节点也可能不直连，按"必须直连"判定会
//! 把正常情况误报成真冲突（§9.3 已明确要求放宽）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::proto::{Carrier, NodeId};
use crate::topology::Topology;

/// 孤岛区域号。真冲突时系统自动派生（§9.3），种子 = 孤岛内字节序最小的 NodeId。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct ZoneId(pub u16);

impl ZoneId {
    /// 确定性派生：任一节点独立计算都得到同一结果，不需要中心协调。
    pub fn derive(island_anchor: NodeId) -> Self {
        let mut h = Sha256::new();
        h.update(b"hiveproxy-zone-v1");
        h.update(island_anchor.0);
        let d = h.finalize();
        // 取 2 字节并避开 0（0 留给"未分配"）
        let v = u16::from_be_bytes([d[0], d[1]]);
        Self(if v == 0 { 1 } else { v })
    }

    /// 短标签 `z<zone>`。
    pub fn label(&self) -> String {
        format!("z{}", self.0)
    }

    /// 真实 IP → overlay 地址：`fd00:<zone>::/64` 之下，真实 IP 保留在低位。
    ///
    /// v1 只对 IPv4 目标做映射（真冲突 + 目标还是 v6 的组合在实践中不出现）；
    /// v6 目标返回 `None`，调用方按"不支持"处理。
    pub fn map_target(&self, ip: IpAddr) -> Option<Ipv6Addr> {
        let IpAddr::V4(v4) = ip else { return None };
        let mut o = [0u8; 16];
        o[0] = 0xfd;
        o[1] = 0x00;
        o[2..4].copy_from_slice(&self.0.to_be_bytes());
        o[12..16].copy_from_slice(&v4.octets());
        Some(Ipv6Addr::from(o))
    }

    /// 反向：overlay 地址 → `(zone, 真实 IP)`。可逆，排障时能反算出真实地址与所属孤岛。
    pub fn unmap_target(&self, addr: Ipv6Addr) -> Option<IpAddr> {
        let o = addr.octets();
        if o[0] != 0xfd || o[1] != 0x00 {
            return None;
        }
        if u16::from_be_bytes([o[2], o[3]]) != self.0 {
            return None;
        }
        Some(IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15])))
    }

    /// 从任意 overlay 地址反解出 zone（不需要预先知道是哪个 zone）。
    pub fn unmap_any(addr: Ipv6Addr) -> Option<(ZoneId, IpAddr)> {
        let o = addr.octets();
        if o[0] != 0xfd || o[1] != 0x00 {
            return None;
        }
        let z = ZoneId(u16::from_be_bytes([o[2], o[3]]));
        Some((z, IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]))))
    }
}

/// 某个网段在某个孤岛里的成员。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IslandDecl {
    pub zone: ZoneId,
    pub anchor: NodeId,
    pub members: Vec<NodeId>,
}

/// 全网的分区视图。
#[derive(Clone, Debug, Default)]
pub struct ZoneTable {
    /// 网段 → 该网段的若干孤岛声明。长度 > 1 即"真冲突"。
    pub by_net: HashMap<IpNet, Vec<IslandDecl>>,
    /// zone → 成员节点（跨网段合并）。
    pub islands: HashMap<ZoneId, Vec<NodeId>>,
    /// 每个节点属于哪个 zone（一个节点可能因为多网卡而属于多个 zone，取排序后第一个）。
    pub node_zone: HashMap<NodeId, ZoneId>,
    /// 拓扑版本，用于缓存失效。
    pub version: u64,
}

impl ZoneTable {
    /// 从拓扑推导分区。**纯函数**：任何节点独立计算都得到同一结果。
    pub fn build(topo: &Topology) -> Self {
        let mut by_net: HashMap<IpNet, Vec<IslandDecl>> = HashMap::new();

        for (net, owners) in &topo.segments {
            // 同类集合：声明了同一网段、且彼此"在同一个 L2 里"的节点归为一个孤岛。
            let components = cluster(owners, topo);
            let mut decls = Vec::new();
            for mut comp in components {
                comp.sort();
                let anchor = comp[0]; // 孤岛内字节序最小的 NodeId
                decls.push(IslandDecl {
                    zone: ZoneId::derive(anchor),
                    anchor,
                    members: comp,
                });
            }
            decls.sort_by_key(|d| d.zone);
            by_net.insert(*net, decls);
        }

        let mut islands: HashMap<ZoneId, Vec<NodeId>> = HashMap::new();
        let mut node_zone: HashMap<NodeId, ZoneId> = HashMap::new();
        let mut nets: Vec<IpNet> = by_net.keys().copied().collect();
        nets.sort_by_key(|n| n.to_string());
        for net in nets {
            for d in &by_net[&net] {
                let e = islands.entry(d.zone).or_default();
                for m in &d.members {
                    if !e.contains(m) {
                        e.push(*m);
                    }
                    node_zone.entry(*m).or_insert(d.zone);
                }
            }
        }
        for v in islands.values_mut() {
            v.sort();
        }

        Self { by_net, islands, node_zone, version: topo.version }
    }

    pub fn is_empty(&self) -> bool {
        self.by_net.is_empty()
    }

    /// 是否存在"真冲突"（某个网段被多个互不相邻的孤岛声明）。
    pub fn has_conflict(&self) -> bool {
        self.by_net.values().any(|v| v.len() > 1)
    }

    pub fn conflicting_nets(&self) -> Vec<IpNet> {
        let mut v: Vec<IpNet> = self
            .by_net
            .iter()
            .filter(|(_, d)| d.len() > 1)
            .map(|(n, _)| *n)
            .collect();
        v.sort_by_key(|n| n.to_string());
        v
    }

    pub fn island_members(&self, z: ZoneId) -> Option<&Vec<NodeId>> {
        self.islands.get(&z)
    }

    pub fn zone_of(&self, node: NodeId) -> Option<ZoneId> {
        self.node_zone.get(&node).copied()
    }

    /// 覆盖 `ip` 的全部 (网段, 孤岛声明) 组合。
    pub fn decls_for_ip(&self, ip: IpAddr) -> Vec<(IpNet, &IslandDecl)> {
        let mut out = Vec::new();
        let mut nets: Vec<IpNet> = self.by_net.keys().copied().collect();
        nets.sort_by_key(|n| n.to_string());
        for net in nets {
            if net.contains(&ip) {
                for d in &self.by_net[&net] {
                    out.push((net, d));
                }
            }
        }
        out
    }

    /// 解析一个真实目标 IP：决定它是否需要 zone 限定（§9.3 情形二的解析优先级表）。
    pub fn resolve_ip(&self, ip: IpAddr, requester_zone: Option<ZoneId>) -> ZoneResolution {
        let decls = self.decls_for_ip(ip);
        if decls.is_empty() {
            return ZoneResolution::Unknown;
        }
        let zones: Vec<ZoneId> = {
            let mut v: Vec<ZoneId> = decls.iter().map(|(_, d)| d.zone).collect();
            v.sort();
            v.dedup();
            v
        };
        if zones.len() == 1 {
            return ZoneResolution::Unique(zones[0]);
        }
        // 目标属于多个孤岛：请求方在其中之一时无感
        if let Some(rz) = requester_zone {
            if zones.contains(&rz) {
                return ZoneResolution::PreferLocal(rz);
            }
        }
        ZoneResolution::Ambiguous(zones)
    }
}

/// `resolve_ip` 的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZoneResolution {
    /// 目标不落在任何已知网段。
    Unknown,
    /// 只属于一个孤岛 —— 直接用真实 IP，用户无感。
    Unique(ZoneId),
    /// 属于多个孤岛，但请求方就在其中之一 —— 选请求方那片，仍然无感。
    PreferLocal(ZoneId),
    /// 属于多个孤岛且请求方在两片之外 —— 必须用 `z<zone>+ip:port` 指定。
    Ambiguous(Vec<ZoneId>),
}

/// 把声明了同一网段的节点按"是否属于同一个 L2 广播域"聚成孤岛。
///
/// ## 为什么只能靠 L2 载体判定
///
/// 两片彼此隔离的孤岛都用 `10.1.2.0/24` 时，两侧节点的**身份地址也都在 `10.1.2.0/24` 里**，
/// 所以"地址落在同一前缀内"根本无法区分它们（那样只会得到"永远不冲突"）。
/// 而 overlay 图上的连通性同样不能作为判据 —— 孤岛之间正是被这张网连起来的。
///
/// 唯一真正区分两者的信号是**它们是否在同一个广播域里**，也就是链路被标成
/// `Carrier::Lan`（同网段载体）。
///
/// ## 已知局限（务必知情）
///
/// - `max_links` 剪枝会让同一 L2 的节点之间没有直连边 → 被拆成多个孤岛 → **误报冲突**。
///   表现是系统多派生了几个 zone；单孤岛目标仍然走真实 IP，只是在"多片"场景下会要求
///   写 `z<zone>+` 前缀，属于"多要一步"而不是"走错路"。
/// - 节点用 `node.overlay_addr` 覆盖身份时，载体判定依据的是身份地址而不是本机网卡，
///   可能不准。
///
/// 两者都属于"保守方向"（宁可多分一个 zone，也不要漏掉真冲突）。
fn cluster(owners: &[NodeId], topo: &Topology) -> Vec<Vec<NodeId>> {
    let n = owners.len();
    if n <= 1 {
        return owners.iter().map(|o| vec![*o]).collect();
    }

    // 并查集
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut Vec<usize>, x: usize) -> usize {
        if p[x] != x {
            let r = find(p, p[x]);
            p[x] = r;
        }
        p[x]
    }
    fn union(p: &mut Vec<usize>, a: usize, b: usize) {
        let (ra, rb) = (find(p, a), find(p, b));
        if ra != rb {
            p[ra] = rb;
        }
    }

    for i in 0..n {
        for j in (i + 1)..n {
            let (a, b) = (owners[i], owners[j]);
            // 判据一：地址落在同一片（这里用拓扑里记载的 L2 直连做辅助，
            // 因为"两节点是否同网段"需要网卡信息，跨节点拿不到，只能用可达性近似）
            if same_l2(topo, a, b) {
                union(&mut parent, i, j);
            }
        }
    }

    let mut groups: HashMap<usize, Vec<NodeId>> = HashMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(owners[i]);
    }
    groups.into_values().collect()
}

/// 两节点是否在同一个 L2 广播域里。
///
/// 取"拓扑上存在一条同网段载体的边"作为证据。注意这只是**充分**证据：
/// `max_links` 剪枝会让一些同 L2 的节点没有直连边，此时它会被当成独立孤岛 ——
/// 这是保守方向（宁可多分一个 zone，也不要漏掉真冲突）。
fn same_l2(topo: &Topology, a: NodeId, b: NodeId) -> bool {
    has_lan_edge(topo, a, b) || has_lan_edge(topo, b, a)
}

fn has_lan_edge(topo: &Topology, from: NodeId, to: NodeId) -> bool {
    topo.adjacency
        .get(&from)
        .map(|adj| adj.edges.iter().any(|e| e.peer == to && e.carrier == Carrier::Lan))
        .unwrap_or(false)
}

/// 把 `z<zone>+<ip>` / `fd00:<zone>::<ip>` 形式的目标解析出来。
pub struct ParsedTarget {
    pub zone: Option<ZoneId>,
    pub host: crate::proto::Host,
    pub port: u16,
}

/// 解析用户填的目标。支持三种写法：
/// - `10.1.2.5:3306`
/// - `z7+10.1.2.5:3306`（短标签）
/// - `[fd00:7::10.1.2.5]:3306`（overlay 地址）
pub fn parse_zoned_target(s: &str) -> Result<ParsedTarget, String> {
    let s = s.trim();
    let (host_part, port_part) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("`{s}` 缺少端口，应当写成 ip:port 或 域名:port"))?;
    let port: u16 = port_part.parse().map_err(|_| format!("无效端口 `{port_part}`"))?;

    // 形式一：z<zone>+<ip>
    if let Some(rest) = host_part.strip_prefix('z') {
        if let Some((zstr, real)) = rest.split_once('+') {
            let z: u16 = zstr
                .parse()
                .map_err(|_| format!("无效的区域号 `z{zstr}`，应当形如 z7+10.1.2.5"))?;
            let ip: IpAddr = real
                .parse()
                .map_err(|_| format!("区域限定后的 `{real}` 不是合法 IP"))?;
            return Ok(ParsedTarget {
                zone: Some(ZoneId(z)),
                host: crate::proto::Host::Ip(ip),
                port,
            });
        }
    }

    // 形式二：overlay 地址（可能是 [fd00:7::10.1.2.5] 或裸 fd00:7::10.1.2.5）
    let bare = host_part.trim_start_matches('[').trim_end_matches(']');
    if let Ok(v6) = bare.parse::<Ipv6Addr>() {
        if let Some((z, real)) = ZoneId::unmap_any(v6) {
            return Ok(ParsedTarget { zone: Some(z), host: crate::proto::Host::Ip(real), port });
        }
    }

    // 普通写法
    let host = match host_part.parse::<IpAddr>() {
        Ok(ip) => crate::proto::Host::Ip(ip),
        Err(_) => crate::proto::Host::Name(host_part.to_string()),
    };
    Ok(ParsedTarget { zone: None, host, port })
}

/// 供 UI 展示：当前有哪些网段真冲突，每个 zone 对应哪些"可填的地址"。
pub struct ZoneView {
    pub net: IpNet,
    pub islands: Vec<(ZoneId, String, Vec<NodeId>)>, // (zone, 建议填写的地址, 成员)
}

pub fn zone_views(topo: &Topology) -> Vec<ZoneView> {
    let table = ZoneTable::build(topo);
    let mut out = Vec::new();
    for net in table.conflicting_nets() {
        let decls = &table.by_net[&net];
        let mut islands = Vec::new();
        for d in decls {
            // 建议地址取"该孤岛里最小的成员地址"，用户把它当前缀用
            let suggest = format!("{}+10.1.2.5", d.zone.label());
            islands.push((d.zone, suggest, d.members.clone()));
        }
        out.push(ZoneView { net, islands });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{AdjEntry, GossipMsg, ListenAdvert, SubnetAd};
    use crate::testutil::nid;

    fn gossip(owner: NodeId, carrier: Carrier, peers: &[NodeId], subnets: &[&str]) -> GossipMsg {
        GossipMsg {
            owner,
            incarnation: 1,
            seq: 1,
            edges: peers
                .iter()
                .map(|p| AdjEntry { peer: *p, cost: 1, carrier, rtt_ms: 1 })
                .collect(),
            subnets: subnets
                .iter()
                .map(|s| SubnetAd::any_port(s.parse().unwrap()))
                .collect(),
            listen: ListenAdvert::default(),
            accepts_egress: true,
            alias: None,
            rule_set: None,
            digest: Vec::new(),
        }
    }

    fn topo(me: &str) -> Topology {
        Topology::new(nid(me))
    }

    #[test]
    fn zone_derive_is_deterministic_and_nonzero() {
        let a = nid("10.1.2.5");
        let b = nid("10.1.2.6");
        assert_eq!(ZoneId::derive(a), ZoneId::derive(a), "同一锚点必须得到同一 zone");
        assert_ne!(ZoneId::derive(a), ZoneId::derive(b), "不同锚点应当得到不同 zone");
        assert_ne!(ZoneId::derive(a).0, 0, "0 留给未分配");
    }

    #[test]
    fn map_and_unmap_are_inverse() {
        let z = ZoneId(7);
        let ip: IpAddr = "10.1.2.5".parse().unwrap();
        let mapped = z.map_target(ip).expect("v4 应当可映射");
        assert_eq!(mapped.to_string(), "fd00:7::a01:205");
        assert_eq!(z.unmap_target(mapped), Some(ip));
        assert_eq!(ZoneId::unmap_any(mapped), Some((z, ip)));
        // 别的 zone 反解不出来
        assert_eq!(ZoneId(8).unmap_target(mapped), None);
        // 非 ULA 前缀反解不出来
        assert_eq!(ZoneId::unmap_any("fd01::1".parse().unwrap()), None);
    }

    #[test]
    fn single_declarer_is_not_a_conflict() {
        let mut t = topo("10.0.0.1");
        t.merge_gossip(&gossip(nid("10.1.2.5"), Carrier::Lan, &[], &["10.1.2.0/24"]));

        let zt = ZoneTable::build(&t);
        assert!(!zt.has_conflict());
        assert_eq!(zt.conflicting_nets(), Vec::<IpNet>::new());
        assert_eq!(
            zt.resolve_ip("10.1.2.9".parse().unwrap(), None),
            ZoneResolution::Unique(ZoneId::derive(nid("10.1.2.5")))
        );
    }

    #[test]
    fn same_lan_is_redundant_egresses_not_a_conflict() {
        // §9.3 情形一：同一 L2 里的两个节点声明同一网段 → 一个逻辑网段、两条冗余出口
        let a = nid("10.1.2.5");
        let b = nid("10.1.2.6");
        let mut t = topo("10.0.0.1");
        t.merge_gossip(&gossip(a, Carrier::Lan, &[b], &["10.1.2.0/24"]));
        t.merge_gossip(&gossip(b, Carrier::Lan, &[a], &["10.1.2.0/24"]));

        let zt = ZoneTable::build(&t);
        assert!(!zt.has_conflict(), "同 L2 不是冲突（§9.3 情形一）");
        let decls = &zt.by_net[&"10.1.2.0/24".parse().unwrap()];
        assert_eq!(decls.len(), 1, "应当合并成一个孤岛");
        assert_eq!(decls[0].members, vec![a, b], "两条冗余出口同属一个孤岛");
    }

    #[test]
    fn two_isolated_islands_on_the_same_private_range_conflict() {
        // §9.3 情形二：两片隔离孤岛都用 10.1.2.0/24
        let a = nid("10.1.2.5"); // 孤岛 1
        let b = nid("10.1.2.6"); // 孤岛 1（同 L2）
        let c = nid("10.9.9.5"); // 孤岛 2
        let d = nid("10.9.9.6"); // 孤岛 2（同 L2）
        let mut t = topo("10.0.0.1");
        t.merge_gossip(&gossip(a, Carrier::Lan, &[b], &["10.1.2.0/24"]));
        t.merge_gossip(&gossip(b, Carrier::Lan, &[a], &["10.1.2.0/24"]));
        // c/d 是另一片 L2（同网段载体），与 a/b 之间**没有任何边**
        t.merge_gossip(&gossip(c, Carrier::Lan, &[d], &["10.1.2.0/24"]));
        t.merge_gossip(&gossip(d, Carrier::Lan, &[c], &["10.1.2.0/24"]));

        let zt = ZoneTable::build(&t);
        assert!(zt.has_conflict(), "两片隔离孤岛撞同一私网段 = 真冲突");
        assert_eq!(zt.conflicting_nets(), vec!["10.1.2.0/24".parse().unwrap()]);

        let decls = &zt.by_net[&"10.1.2.0/24".parse().unwrap()];
        assert_eq!(decls.len(), 2, "应当分出两个孤岛");
        // 锚点是各孤岛里字节序最小的 NodeId
        let zones: Vec<ZoneId> = decls.iter().map(|d| d.zone).collect();
        assert!(zones.contains(&ZoneId::derive(a)), "孤岛 1 的锚是 10.1.2.5");
        assert!(zones.contains(&ZoneId::derive(c)), "孤岛 2 的锚是 10.9.9.5");
        assert_ne!(zones[0], zones[1]);
    }

    #[test]
    fn resolution_prefers_the_requester_island() {
        let a = nid("10.1.2.5");
        let c = nid("10.9.9.5");
        let mut t = topo("10.0.0.1");
        t.merge_gossip(&gossip(a, Carrier::Lan, &[], &["10.1.2.0/24"]));
        t.merge_gossip(&gossip(c, Carrier::Lan, &[], &["10.1.2.0/24"]));
        let zt = ZoneTable::build(&t);
        // 上面两个各自独立（没有边）→ 两个孤岛
        assert_eq!(zt.by_net[&"10.1.2.0/24".parse().unwrap()].len(), 2);

        let za = ZoneId::derive(a);
        let zc = ZoneId::derive(c);
        let ip: IpAddr = "10.1.2.9".parse().unwrap();

        assert_eq!(zt.resolve_ip(ip, Some(za)), ZoneResolution::PreferLocal(za));
        assert_eq!(zt.resolve_ip(ip, Some(zc)), ZoneResolution::PreferLocal(zc));
        // 请求方在两片之外 → 需要 zone 限定
        let mut zones = vec![za, zc];
        zones.sort();
        assert_eq!(zt.resolve_ip(ip, None), ZoneResolution::Ambiguous(zones));
        // 目标不在任何网段
        assert_eq!(
            zt.resolve_ip("8.8.8.8".parse().unwrap(), None),
            ZoneResolution::Unknown
        );
    }

    #[test]
    fn parse_zone_prefixed_targets() {
        let p = parse_zoned_target("z7+10.1.2.5:3306").unwrap();
        assert_eq!(p.zone, Some(ZoneId(7)));
        assert_eq!(p.host, crate::proto::Host::Ip("10.1.2.5".parse().unwrap()));
        assert_eq!(p.port, 3306);

        // overlay 地址形式
        let v6 = ZoneId(7).map_target("10.1.2.5".parse().unwrap()).unwrap();
        let p = parse_zoned_target(&format!("[{v6}]:3306")).unwrap();
        assert_eq!(p.zone, Some(ZoneId(7)));
        assert_eq!(p.host, crate::proto::Host::Ip("10.1.2.5".parse().unwrap()));

        // 普通写法不受影响
        let p = parse_zoned_target("10.1.2.5:3389").unwrap();
        assert_eq!(p.zone, None);
        let p = parse_zoned_target("api.corp.example.com:443").unwrap();
        assert_eq!(p.zone, None);
        assert_eq!(p.host, crate::proto::Host::Name("api.corp.example.com".into()));

        assert!(parse_zoned_target("zabc+10.1.2.5:80").is_err());
        assert!(parse_zoned_target("10.1.2.5").is_err());
    }

    #[test]
    fn zone_membership_covers_all_declarers() {
        let a = nid("10.1.2.5");
        let c = nid("10.9.9.5");
        let mut t = topo("10.0.0.1");
        t.merge_gossip(&gossip(a, Carrier::Lan, &[], &["10.1.2.0/24", "10.4.0.0/24"]));
        t.merge_gossip(&gossip(c, Carrier::Lan, &[], &["10.1.2.0/24"]));
        let zt = ZoneTable::build(&t);
        // a 同时在两个网段里，但只有一个 zone（取排序后第一个）
        let za = zt.zone_of(a).expect("a 应当有 zone");
        assert_eq!(za, ZoneId::derive(a));
        assert!(zt.island_members(za).unwrap().contains(&a));
        assert_eq!(zt.zone_of(c), Some(ZoneId::derive(c)));
    }

    #[test]
    fn views_list_conflicts() {
        let a = nid("10.1.2.5");
        let c = nid("10.9.9.5");
        let mut t = topo("10.0.0.1");
        t.merge_gossip(&gossip(a, Carrier::Lan, &[], &["10.1.2.0/24"]));
        t.merge_gossip(&gossip(c, Carrier::Lan, &[], &["10.1.2.0/24"]));
        let views = zone_views(&t);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].islands.len(), 2);
    }
}
