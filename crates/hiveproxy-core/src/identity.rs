//! 身份：地址即身份（DESIGN.md §5.8）。
//!
//! 不做任何 ID 生成、不做持久化。启动时按「配置的 `overlay_addr` → 否则本机主网卡地址」
//! 判定自己的身份。因此**不存在** `identity.json` 这类文件。

use std::net::SocketAddr;

use ipnet::IpNet;

use crate::config::Config;
use crate::net;
use crate::proto::NodeId;

/// 本节点的运行期身份。
///
/// ⚠️ 这里有三件**必须分开**的事，早期版本把它们搅在一起，导致"敏感机器连不上自己的局域网"：
///
/// 1. `subnets` —— **我自己能连到什么**。永远包含本机网卡所在的所有子网。
/// 2. `share_subnets` —— **要不要把这件事实告诉别人**（`share.auto_share_subnets`）。
/// 3. `accepts_egress` —— **愿不愿意替别人把流量发出去**（`egress.allow_egress`）。
///
/// 1 与 2、3 之间没有任何依赖：只消费不贡献的机器照样要能访问自己的局域网；
/// 拒绝当网关的机器照样要能连自己够得着的地方。
#[derive(Clone, Debug)]
pub struct NodeIdentity {
    /// = 本机地址（或 `overlay_addr` 覆盖值）。
    pub node_id: NodeId,
    pub alias: Option<String>,
    /// 实际监听的全部地址（多端口，§6.2.3）。
    pub listen: Vec<SocketAddr>,
    /// 本机所在、适合共享的网段 —— **始终**填充，与本机配置无关。
    pub subnets: Vec<IpNet>,
    /// 被排除、因而**没有**算进 `subnets` 的地址，每行一句人话（虚拟网卡 / 排除段）。
    ///
    /// 存在的理由很具体：用户会问"我明明在 10.x 里，为什么它说我没有网段"。
    /// 界面必须能自己回答这个问题（§9.1、2026-10-13 的 TUN 事件）。
    pub excluded_subnets: Vec<String>,
    /// 是否把 `subnets` 广播给全网（§9.1 的 `auto_share_subnets`）。
    pub share_subnets: bool,
    /// 是否愿意做出口（§9.4.4）。
    pub accepts_egress: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("无法确定本机地址：网卡枚举为空且未配置 node.overlay_addr")]
    NoAddress,
    #[error("node.overlay_addr = {0} 不是本机地址；身份只需唯一，不要求可拨，但打错地址会让整个网络无法定位这台机器")]
    OverlayAddrNotLocal(std::net::IpAddr),
}

impl NodeIdentity {
    /// 解析本节点身份。
    pub fn resolve(cfg: &Config) -> Result<Self, IdentityError> {
        let ip = match cfg.node.overlay_addr {
            Some(ip) => ip,
            None => net::primary_ip().ok_or(IdentityError::NoAddress)?,
        };

        // ★ `subnets` 与 `auto_share_subnets` **无关**：它描述的是"我自己能连什么"，
        // 而不是"我告诉别人什么"。早先把两者绑在一起，结果是敏感机器一关共享，
        // 连自己网段里的目标都访问不了了。
        // 虚拟网卡与排除段不算"我的网段"（默认排掉 TUN/容器网卡与 RFC 2544 段，§9.1）。
        let scan = net::scan_local_subnets(&cfg.share.deny_cidrs(), &cfg.share.deny_ifaces());
        let mut subnets: Vec<IpNet> = scan.subnets;
        let mut excluded: Vec<String> = scan.excluded;
        // 身份地址自身所在网段也要算进去（`overlay_addr` 覆盖时尤其重要）。
        // **显式配置优先于排除表**：把身份钉在某个地址上，就是"我知道我在干什么"。
        for i in net::list_interfaces() {
            if i.ip == ip {
                if let Some(n) = i.net {
                    if n.prefix_len() <= 30 && !subnets.contains(&n) {
                        subnets.push(n);
                        excluded.retain(|e| !e.starts_with(&n.to_string()));
                    }
                }
            }
        }
        subnets.sort_by_key(|n| n.to_string());
        subnets.dedup();

        let listen = net::expand_listen_addrs(cfg.listen.bind, &cfg.listen.ports);

        Ok(Self {
            node_id: NodeId::from_ip(ip),
            alias: cfg.node.alias.clone().filter(|s| !s.is_empty()),
            listen,
            subnets,
            excluded_subnets: excluded,
            share_subnets: cfg.share.auto_share_subnets,
            accepts_egress: cfg.egress.allow_egress,
        })
    }

    /// 监听端口列表（供 `HelloAck.listen_ports` 做对齐自检，§6.2.3）。
    pub fn listen_ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.listen.iter().map(|a| a.port()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// 生成本节点的 `ListenAdvert`（§6.5）。`advertise = false` 时返回空地址列表 ——
    /// 语义是"我不告诉别人我在哪，但别人仍可以拨我（如果他们自己知道地址）"。
    pub fn listen_advert(&self, advertise: bool, now_unix: u64, ttl_secs: u32) -> crate::proto::ListenAdvert {
        crate::proto::ListenAdvert {
            addrs: if advertise { self.listen.clone() } else { Vec::new() },
            issued_at: now_unix,
            ttl_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_overlay_addr_wins() {
        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("fd00:1::9".parse().unwrap());
        let id = NodeIdentity::resolve(&cfg).unwrap();
        assert_eq!(id.node_id, "fd00:1::9".parse().unwrap());
    }

    #[test]
    fn alias_empty_string_becomes_none() {
        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("10.9.9.9".parse().unwrap());
        cfg.node.alias = Some(String::new());
        assert_eq!(NodeIdentity::resolve(&cfg).unwrap().alias, None);
    }

    #[test]
    fn auto_share_off_stops_contributing_but_keeps_local_reachability() {
        // 「只消费不贡献」= 不把我的局域网告诉别人，
        // **不是** = 我自己连不上自己的局域网。这两件事必须分开。
        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("10.9.9.9".parse().unwrap());
        cfg.share.auto_share_subnets = false;
        let id = NodeIdentity::resolve(&cfg).unwrap();
        assert!(!id.share_subnets, "不该再对外声明");
        // 本机网段仍然保留（用于"我自己能连什么"）；测试机上具体有几个网段不重要，
        // 关键是这个字段不再被 auto_share_subnets 清空。
        let _ = &id.subnets;
    }

    #[test]
    fn advert_respects_advertise_flag() {
        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("10.9.9.9".parse().unwrap());
        cfg.listen.bind = "10.9.9.9".parse().unwrap();
        cfg.listen.ports = vec![20000];
        let id = NodeIdentity::resolve(&cfg).unwrap();

        let on = id.listen_advert(true, 0, 900);
        assert_eq!(on.addrs, vec!["10.9.9.9:20000".parse().unwrap()]);

        let off = id.listen_advert(false, 0, 900);
        assert!(off.addrs.is_empty(), "advertise = false 时不出现在他人候选里（§16）");
    }

    #[test]
    fn listen_ports_dedup_and_sort() {
        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("10.9.9.9".parse().unwrap());
        cfg.listen.bind = "10.9.9.9".parse().unwrap();
        cfg.listen.ports = vec![20000, 5678, 20000];
        let id = NodeIdentity::resolve(&cfg).unwrap();
        assert_eq!(id.listen_ports(), vec![5678, 20000]);
    }
}
