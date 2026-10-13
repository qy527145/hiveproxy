//! 网卡枚举与网段推导（DESIGN.md §9.1、§6.5）。
//!
//! `socket2` **不提供**接口地址列举，所以这里用 `if-addrs`（跨平台 `getifaddrs`）。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipnet::IpNet;

/// 一块网卡。
#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub ip: IpAddr,
    /// 该地址所在的网段（由掩码推导）。
    pub net: Option<IpNet>,
    pub is_loopback: bool,
}

/// 列出本机所有地址。失败时返回空（调用方降级为"无网段"）。
pub fn list_interfaces() -> Vec<Iface> {
    let Ok(addrs) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    addrs
        .into_iter()
        .map(|i| {
            let ip = i.ip();
            let is_loopback = ip.is_loopback();
            let net = match &i.addr {
                if_addrs::IfAddr::V4(v4) => IpNet::new(IpAddr::V4(v4.ip), v4.prefixlen).ok(),
                if_addrs::IfAddr::V6(v6) => IpNet::new(IpAddr::V6(v6.ip), v6.prefixlen).ok(),
            };
            Iface { name: i.name, ip, net, is_loopback }
        })
        .collect()
}

/// 该地址是否适合作为"共享给全网的网段"。
///
/// 排除：回环、链路本地（169.254/16、fe80::/10）、组播、未指定、以及 /31 与 /32 这类
/// 没有实际网段意义的掩码。
pub fn is_shareable(ip: IpAddr, net: &Option<IpNet>) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                return false;
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unicast_link_local() {
                return false;
            }
        }
    }
    match net {
        Some(n) => n.prefix_len() <= 30,
        None => false,
    }
}

/// 默认**不**当成"本机网段"的地址范围。
///
/// `198.18.0.0/15` 是 RFC 2544 的基准测试段 —— Clash / Clash Verge / sing-box 这类工具的
/// **TUN 假地址池默认就落在这里**（常见 `198.18.0.1/30`）。它不是真实网络：把它当成本机网段
/// 广播出去，等于让全网把"某台机器上代理工具编出来的假 IP"当成一个可路由的网段。
///
/// 2026-10-13 由用户实测撞到：`本机可直达网段 10.10.12.66/22, 198.18.0.1/30`，
/// 后者的网卡是 tun。取值可在 `share.subnet_deny` 里改。
pub const DEFAULT_SUBNET_DENY: &[&str] = &["198.18.0.0/15"];

/// 默认**不**当成"本机网段"的网卡名模式（结尾 `*` = 前缀匹配，否则精确匹配）。
///
/// 这些名字基本只出现在虚拟网卡上（TUN/TAP、容器桥、虚拟机网卡、零信任客户端）。
/// **取舍写在明处**：如果你的真实内网访问本来就依赖某条隧道 —— macOS 上 WireGuard 也叫
/// `utunN` —— 就把对应的模式从 `share.subnet_deny_ifaces` 里删掉。
/// 这里排除的是**网段声明**（"这块地方我替大家去"），不是"我能不能连"。
pub const DEFAULT_IFACE_DENY: &[&str] = &[
    "tun*",
    "tap*",
    "utun*",
    "wg*",
    "wintun*",
    "docker*",
    "veth*",
    "br-*",
    "bridge*",
    "vmnet*",
    "vboxnet*",
    "zt*",
    "tailscale*",
    "ipsec*",
];

/// 默认排除表的解析结果（每次调用现解析；表只有两三条，不值得加缓存）。
pub fn default_subnet_deny() -> Vec<IpNet> {
    DEFAULT_SUBNET_DENY.iter().filter_map(|s| s.parse().ok()).collect()
}

/// 默认网卡名排除表。
pub fn default_iface_deny() -> Vec<String> {
    DEFAULT_IFACE_DENY.iter().map(|s| s.to_string()).collect()
}

/// 网卡名是否命中模式表。唯一支持的元字符是**结尾的** `*`（前缀匹配）。
pub fn iface_denied(name: &str, patterns: &[String]) -> bool {
    let name = name.to_ascii_lowercase();
    patterns.iter().any(|p| {
        let p = p.trim().to_ascii_lowercase();
        if p.is_empty() {
            return false;
        }
        match p.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => name == p,
        }
    })
}

/// 一次网卡扫描的结果。
///
/// `excluded` 是给界面看的：用户会问"我明明在 10.x 网段里，为什么界面说我没有网段"，
/// 这条链路必须能自己回答，而不是让人去读源码（2026-10-13 的 TUN 事件就是这么发现的）。
#[derive(Clone, Debug, Default)]
pub struct SubnetScan {
    /// 适合当"本机网段"的。
    pub subnets: Vec<IpNet>,
    /// 被排除的，每行一句人话。
    pub excluded: Vec<String>,
}

/// 扫描网卡，推导"本机所在、且适合共享"的网段。
pub fn scan_subnets(ifaces: &[Iface], deny_cidrs: &[IpNet], deny_ifaces: &[String]) -> SubnetScan {
    let mut out = SubnetScan::default();
    for i in ifaces {
        let Some(net) = i.net else {
            continue;
        };
        if !is_shareable(i.ip, &i.net) {
            continue;
        }
        if iface_denied(&i.name, deny_ifaces) {
            out.excluded.push(format!("{net}（{}：虚拟网卡，见 share.subnet_deny_ifaces）", i.name));
            continue;
        }
        if deny_cidrs.iter().any(|d| d.contains(&i.ip)) {
            out.excluded.push(format!("{net}（{}：落在 share.subnet_deny 里）", i.name));
            continue;
        }
        out.subnets.push(net);
    }
    out.subnets.sort_by_key(|n| n.to_string());
    out.subnets.dedup();
    out.excluded.sort();
    out.excluded.dedup();
    out
}

/// 按默认规则扫描本机（`share.subnet_deny` / `share.subnet_deny_ifaces` 的默认值）。
pub fn scan_local_subnets(deny_cidrs: &[IpNet], deny_ifaces: &[String]) -> SubnetScan {
    scan_subnets(&list_interfaces(), deny_cidrs, deny_ifaces)
}

/// 本机所在、且**适合共享**的全部网段。这是 §9.1「自动共享本机所在子网」的数据源。
///
/// 用默认排除规则；带配置的版本见 [`scan_local_subnets`]。
pub fn local_subnets() -> Vec<IpNet> {
    scan_local_subnets(&default_subnet_deny(), &default_iface_deny()).subnets
}

/// 本机主地址的近似判定。
///
/// `std` 拿不到路由表，所以这里用启发式：优先非回环的私有 IPv4，
/// 其次任意非回环 IPv4，最后任意非回环地址。**不保证**与真实的 default route 一致。
/// 地址不固定或被判定错误的环境请显式配置 `node.overlay_addr`（§5.8）。
pub fn primary_ip() -> Option<IpAddr> {
    primary_ip_with(&list_interfaces(), &default_subnet_deny(), &default_iface_deny())
}

/// 同 [`primary_ip`]，但排除虚拟网卡与排除段 —— **身份不该落在 TUN 上**。
///
/// 全被排除时退回未过滤的那份：宁可挑一个可疑的地址，也不能让节点起不来。
pub fn primary_ip_with(
    ifaces: &[Iface],
    deny_cidrs: &[IpNet],
    deny_ifaces: &[String],
) -> Option<IpAddr> {
    let clean = ifaces
        .iter()
        .filter(|i| !iface_denied(&i.name, deny_ifaces))
        .filter(|i| !deny_cidrs.iter().any(|d| d.contains(&i.ip)))
        .cloned()
        .collect::<Vec<Iface>>();
    let pool: &[Iface] = if clean.is_empty() { ifaces } else { &clean };
    let ifaces: Vec<Iface> = pool.iter().filter(|i| !i.is_loopback).cloned().collect();

    let v4s: Vec<Ipv4Addr> = ifaces
        .iter()
        .filter_map(|i| match i.ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();

    // 1) 私有 IPv4（最像内网主地址）
    if let Some(v4) = v4s.iter().find(|v| v.is_private()) {
        return Some(IpAddr::V4(*v4));
    }
    // 2) 任意非链路本地 IPv4
    if let Some(v4) = v4s.iter().find(|v| !v.is_link_local()) {
        return Some(IpAddr::V4(*v4));
    }
    // 3) 任意 IPv4
    if let Some(v4) = v4s.first() {
        return Some(IpAddr::V4(*v4));
    }
    // 4) IPv6（排除链路本地）
    ifaces
        .iter()
        .map(|i| i.ip)
        .find(|ip| match ip {
            IpAddr::V6(v6) => !v6.is_unicast_link_local(),
            _ => false,
        })
}

/// 判断某个地址是否与本机属于同一网段（用于把链路标成 `Carrier::Lan`，§3.3）。
pub fn is_same_subnet(a: IpAddr, b: IpAddr) -> bool {
    local_subnets().iter().any(|n| n.contains(&a) && n.contains(&b))
}

/// 把 `listen.bind × listen.ports` 展开成实际的监听地址（§5.7 的 `ListenAdvert.addrs`）。
///
/// - `bind` 是具体地址 → 直接展开；
/// - `bind` 是 `0.0.0.0` / `::` → 用本机所有非回环地址展开（否则广播出去的地址没有意义）。
///
/// 不含回环地址。
pub fn expand_listen_addrs(bind: IpAddr, ports: &[u16]) -> Vec<SocketAddr> {
    let ips: Vec<IpAddr> = if bind.is_unspecified() {
        let mut v: Vec<IpAddr> = list_interfaces()
            .into_iter()
            .filter(|i| !i.is_loopback)
            .map(|i| i.ip)
            .collect();
        v.sort_by_key(|ip| ip.to_string());
        v.dedup();
        v
    } else {
        vec![bind]
    };

    let mut out = Vec::new();
    for ip in ips {
        for &p in ports {
            out.push(SocketAddr::new(ip, p));
        }
    }
    out
}

/// 各网卡的定向广播地址（§6.5 第 2 条的 LAN 发现用）。
pub fn directed_broadcasts() -> Vec<Ipv4Addr> {
    list_interfaces()
        .into_iter()
        .filter(|i| !i.is_loopback)
        .filter_map(|i| match (i.ip, i.net) {
            (IpAddr::V4(_), Some(IpNet::V4(net))) => Some(net.broadcast()),
            _ => None,
        })
        .collect()
}

/// 该地址是否属于本机（用于排除"自己广播给自己的候选"）。
pub fn is_local_ip(ip: IpAddr) -> bool {
    list_interfaces().iter().any(|i| i.ip == ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shareable_rejects_loopback_and_link_local() {
        assert!(!is_shareable("127.0.0.1".parse().unwrap(), &Some("127.0.0.0/8".parse().unwrap())));
        assert!(!is_shareable(
            "169.254.1.1".parse().unwrap(),
            &Some("169.254.0.0/16".parse().unwrap())
        ));
        assert!(!is_shareable(
            "fe80::1".parse().unwrap(),
            &Some("fe80::/64".parse().unwrap())
        ));
        assert!(is_shareable("10.1.2.9".parse().unwrap(), &Some("10.1.2.0/24".parse().unwrap())));
    }

    #[test]
    fn shareable_rejects_slash31_and_slash32() {
        // /31 与 /32 没有"网段"的意义，共享出去只会误导出口选择。
        assert!(!is_shareable("10.1.2.9".parse().unwrap(), &Some("10.1.2.9/32".parse().unwrap())));
        assert!(!is_shareable("10.1.2.8".parse().unwrap(), &Some("10.1.2.8/31".parse().unwrap())));
        assert!(is_shareable("10.1.2.9".parse().unwrap(), &Some("10.1.2.0/30".parse().unwrap())));
    }

    #[test]
    fn shareable_requires_known_net() {
        assert!(!is_shareable("10.1.2.9".parse().unwrap(), &None));
    }

    #[test]
    fn expand_bind_specific_address_expands_only_ports() {
        let addrs = expand_listen_addrs("10.1.2.9".parse().unwrap(), &[20000, 20001]);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&"10.1.2.9:20000".parse().unwrap()));
        assert!(addrs.contains(&"10.1.2.9:20001".parse().unwrap()));
    }

    #[test]
    fn expand_wildcard_bind_excludes_loopback() {
        let addrs = expand_listen_addrs("0.0.0.0".parse().unwrap(), &[20000]);
        assert!(addrs.iter().all(|a| !a.ip().is_loopback()), "广播出去的地址不该包含回环");
    }

    #[test]
    fn enumerate_does_not_panic_on_this_host() {
        // 不同机器网卡各异，这里只断言不 panic 且结果自洽。
        let subs = local_subnets();
        for n in &subs {
            assert!(n.prefix_len() <= 30);
        }
        let _ = primary_ip();
        let _ = directed_broadcasts();
    }

    fn iface(name: &str, addr: &str) -> Iface {
        let net: IpNet = addr.parse().unwrap();
        Iface { name: name.to_string(), ip: net.addr(), net: Some(net), is_loopback: net.addr().is_loopback() }
    }

    #[test]
    fn tun_interface_is_not_a_local_subnet() {
        // 2026-10-13 用户实测：`本机可直达网段 10.10.12.66/22, 198.18.0.1/30` ——
        // 后者的网卡是 tun（代理工具的假地址池），不是真实网络。
        let ifaces = vec![
            iface("en0", "10.10.12.66/22"),
            iface("utun4", "198.18.0.1/30"),
            iface("lo0", "127.0.0.1/8"),
        ];
        let scan = scan_subnets(&ifaces, &default_subnet_deny(), &default_iface_deny());
        assert_eq!(scan.subnets, vec!["10.10.12.66/22".parse::<IpNet>().unwrap()]);
        assert_eq!(scan.excluded.len(), 1, "{:?}", scan.excluded);
        assert!(scan.excluded[0].contains("utun4"), "{:?}", scan.excluded);

        // 只关掉网卡名规则，光靠地址范围也必须能排掉它（两条防线各自独立）
        let scan2 = scan_subnets(&ifaces, &default_subnet_deny(), &[]);
        assert_eq!(scan2.subnets, vec!["10.10.12.66/22".parse::<IpNet>().unwrap()]);
        assert!(scan2.excluded[0].contains("subnet_deny"), "{:?}", scan2.excluded);
    }

    #[test]
    fn iface_patterns_prefix_match_only_with_star() {
        let p = |s: &str| vec![s.to_string()];
        assert!(iface_denied("utun4", &p("utun*")));
        assert!(iface_denied("Wintun", &p("wintun*")), "名字匹配大小写不敏感");
        assert!(!iface_denied("en0", &p("utun*")));
        assert!(iface_denied("en0", &p("en0")));
        assert!(!iface_denied("en01", &p("en0")), "不带 * 就是精确匹配");
        assert!(!iface_denied("en0", &vec!["".to_string()]), "空模式不匹配任何东西");
    }

    #[test]
    fn primary_ip_skips_virtual_adapters() {
        // 身份落在 TUN 上是灾难：全网的节点地址会变成一台代理工具的假地址。
        let ifaces = vec![iface("utun4", "198.18.0.1/30"), iface("en0", "10.10.12.66/22")];
        assert_eq!(
            primary_ip_with(&ifaces, &default_subnet_deny(), &default_iface_deny()),
            Some("10.10.12.66".parse().unwrap())
        );
        // 全被排除时退回未过滤的那份：宁可挑一个可疑地址，也不能让节点起不来
        let only_tun = vec![iface("utun4", "198.18.0.1/30")];
        assert_eq!(
            primary_ip_with(&only_tun, &default_subnet_deny(), &default_iface_deny()),
            Some("198.18.0.1".parse().unwrap())
        );
    }
}
