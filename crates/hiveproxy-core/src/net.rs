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

/// 本机所在、且**适合共享**的全部网段。这是 §9.1「自动共享本机所在子网」的数据源。
pub fn local_subnets() -> Vec<IpNet> {
    let mut v: Vec<IpNet> = list_interfaces()
        .into_iter()
        .filter(|i| is_shareable(i.ip, &i.net))
        .filter_map(|i| i.net)
        .collect();
    v.sort_by_key(|n| n.to_string());
    v.dedup();
    v
}

/// 本机主地址的近似判定。
///
/// `std` 拿不到路由表，所以这里用启发式：优先非回环的私有 IPv4，
/// 其次任意非回环 IPv4，最后任意非回环地址。**不保证**与真实的 default route 一致。
/// 地址不固定或被判定错误的环境请显式配置 `node.overlay_addr`（§5.8）。
pub fn primary_ip() -> Option<IpAddr> {
    let ifaces: Vec<Iface> = list_interfaces().into_iter().filter(|i| !i.is_loopback).collect();

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
}
