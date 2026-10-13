//! 配置模型（DESIGN.md §10 / §10.1）。

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// 顶层配置。以 `Arc<ArcSwap<Config>>` 承载以实现热更新（§6.8）。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub node: NodeCfg,
    pub listen: ListenCfg,
    pub peers: PeersCfg,
    pub discovery: DiscoveryCfg,
    pub share: ShareCfg,
    pub egress: EgressCfg,
    pub route: RouteCfg,
    pub proxy: ProxyCfg,
    pub security: SecurityCfg,
    pub service: ServiceCfg,
    pub admin: AdminCfg,
    pub log: LogCfg,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NodeCfg {
    /// 留空 = 自动取 default route 网卡地址（§5.8）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_addr: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// 可选：手动冻结自动派生的区域号；None = 自动（§9.3）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ListenCfg {
    pub bind: IpAddr,
    pub ports: Vec<u16>,
    pub max_links: usize,
    /// 是否把监听端点广播给全网（§6.5 第 3 条）。
    pub advertise: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PeersCfg {
    /// 引导种子，三种写法："ip:port" | "ip" | "ip:lo-hi"（§6.2.2）。
    pub seeds: Vec<String>,
    pub probe_ports: Vec<u16>,
    /// 采信 gossip 广播的监听端点（§6.5）。2026-10-12 起不再做地址过滤。
    pub accept_listen_adverts: bool,
    /// 别名表，供规则里的 `alias:` 出口解析（§9.4.2）。
    pub entry: Vec<PeerEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    pub address: String,
    pub alias: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryCfg {
    pub lan_udp: bool,
    pub udp_port: u16,
    pub mdns: bool,
    pub dial_interval_ms: u64,
    pub backoff_max_ms: u64,
    pub max_dial_candidates: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ShareCfg {
    pub auto_share_subnets: bool,
    pub share_ports_only: Vec<u16>,
    /// 不当成"本机网段"的地址范围（CIDR 列表）。
    ///
    /// 默认排除 `198.18.0.0/15`（RFC 2544 基准段）：Clash / Clash Verge / sing-box 这类
    /// 代理工具的 **TUN 假地址池默认就落在这里**，它不是真实网络（§9.1）。
    pub subnet_deny: Vec<String>,
    /// 不当成"本机网段"的网卡名模式（结尾 `*` = 前缀匹配）。
    ///
    /// 默认排除 tun / utun / wg / docker 之类虚拟网卡。**取舍**：真实内网若走某条隧道
    /// （macOS 上 WireGuard 也叫 `utunN`），把对应模式删掉即可 —— 这里排除的是
    /// "网段声明"，不是"我能不能连"。
    pub subnet_deny_ifaces: Vec<String>,
}

impl ShareCfg {
    /// 解析后的排除段。非法项由 `validate()` 告警，这里直接跳过。
    pub fn deny_cidrs(&self) -> Vec<ipnet::IpNet> {
        self.subnet_deny.iter().filter_map(|s| s.trim().parse().ok()).collect()
    }

    pub fn deny_ifaces(&self) -> Vec<String> {
        self.subnet_deny_ifaces.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EgressCfg {
    pub allow_egress: bool,
    pub egress_ack_timeout_ms: u64,
    pub egress_cache_ttl_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RouteCfg {
    pub ttl_default: u8,
    pub gossip_interval_ms: u64,
    pub gossip_flood_ttl: u8,
    pub route_switch_timeout_ms: u64,
    pub cost: CostCfg,
    pub rules_enabled: bool,
    pub rules: Vec<crate::rules::Rule>,
    pub groups: Vec<GroupCfg>,
    pub accept_shared_rules: bool,
    pub publish_enabled: bool,
    /// 规则与网段匹配都没命中时的**最后一顺位**出口（§9.4.4、§18 第 29 条）。
    /// 写法与规则的 `egress` 同一套，但不接受 `auto` / `block`（见 `check_default_egress`）。
    #[serde(default, deserialize_with = "de_default_egress", skip_serializing_if = "Option::is_none")]
    pub default_egress: Option<crate::rules::EgressTarget>,
}

/// `default_egress` 的字段级校验：能解析还不够，还得是个合法的"默认位"取值。
///
/// 放在反序列化这一层（而不是 `validate()` 的告警表里）是刻意的：
/// 写错一个默认出口会让整台机器的流量改道，属于"宁可报错也不静默"的那一类。
fn de_default_egress<'de, D>(d: D) -> Result<Option<crate::rules::EgressTarget>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<crate::rules::EgressTarget>::deserialize(d)?;
    if let Some(e) = &v {
        e.check_default_egress().map_err(serde::de::Error::custom)?;
    }
    Ok(v)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CostCfg {
    pub lan: u16,
    pub wan: u16,
    pub per_hop: u16,
}

/// 显式候选集，供 `egress = "group:<name>"` 使用（§9.4.2）。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupCfg {
    pub name: String,
    pub members: Vec<String>,
}

/// 本地代理端口（**一个端口同时讲 SOCKS5 与 HTTP 代理**，§6.4）。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyCfg {
    /// 本机应用要连的本地代理地址。
    ///
    /// `alias` 认旧名 `socks5_bind`：端口上只有 SOCKS5 时的老配置必须继续能解析 ——
    /// `deny_unknown_fields` 会把不认识的键直接当错误，改名不能是破坏性的。
    #[serde(alias = "socks5_bind")]
    pub bind: SocketAddr,
    /// 是否允许非回环地址使用本地代理。旧名 `allow_remote_socks`（同上，走 alias）。
    #[serde(alias = "allow_remote_socks")]
    pub allow_remote: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityCfg {
    pub join_token: String,
    pub rule_token: String,
    pub e2e: E2eMode,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum E2eMode {
    #[default]
    Off,
    Required,
}

/// 服务本身的行为（§20）。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceCfg {
    /// GUI 启动时是否自动开始组网。`hiveproxy-cli run` 忽略此项（它总是启动）。
    pub autostart: bool,
}

impl Default for ServiceCfg {
    fn default() -> Self {
        Self { autostart: true }
    }
}

/// 本地管理接口（§20）。给无界面的服务器用；GUI 不需要走它。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminCfg {
    pub enabled: bool,
    /// Unix socket 路径。留空 = `<data_dir>/hiveproxy.sock`。仅 Unix 有效。
    pub socket: String,
    /// 或者监听回环 TCP（Windows 上没有 Unix socket，用这个）。
    /// 一律只绑 `127.0.0.1` / `::1`，**不要**绑到 0.0.0.0。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<SocketAddr>,
}

impl Default for AdminCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            socket: String::new(),
            // Unix 上走 Unix socket；其它平台没有它，给一个回环 TCP 默认值，
            // 这样 `hiveproxy-cli` 在任何平台上都能跟运行中的节点说话。
            tcp: if cfg!(unix) { None } else { Some("127.0.0.1:10800".parse().expect("字面量")) },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LogCfg {
    pub level: String,
}

// ---------------------------------------------------------------------------
// 默认值（DESIGN.md §10 的配置示例即权威来源）
// ---------------------------------------------------------------------------

impl Default for Config {
    fn default() -> Self {
        Self {
            node: NodeCfg::default(),
            listen: ListenCfg::default(),
            peers: PeersCfg::default(),
            discovery: DiscoveryCfg::default(),
            share: ShareCfg::default(),
            egress: EgressCfg::default(),
            route: RouteCfg::default(),
            proxy: ProxyCfg::default(),
            security: SecurityCfg::default(),
            service: ServiceCfg::default(),
            admin: AdminCfg::default(),
            log: LogCfg::default(),
        }
    }
}

impl Default for NodeCfg {
    fn default() -> Self {
        Self { overlay_addr: None, alias: None, zone: None }
    }
}

impl Default for ListenCfg {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".parse().expect("valid literal"),
            // 未配置时兜底 5678 —— 那只是"尚未对齐"的默认值，不是固定的 overlay 端口（§6.2.3）。
            ports: vec![5678],
            max_links: 16,
            advertise: true,
        }
    }
}

impl Default for PeersCfg {
    fn default() -> Self {
        Self {
            seeds: Vec::new(),
            probe_ports: vec![5678, 5679, 8000, 8080],
            accept_listen_adverts: true,
            entry: Vec::new(),
        }
    }
}

impl Default for DiscoveryCfg {
    fn default() -> Self {
        Self {
            lan_udp: true,
            udp_port: 5679,
            mdns: false,
            dial_interval_ms: 5000,
            backoff_max_ms: 60_000,
            max_dial_candidates: 64,
        }
    }
}

impl Default for ShareCfg {
    fn default() -> Self {
        Self {
            auto_share_subnets: true,
            share_ports_only: Vec::new(),
            subnet_deny: crate::net::DEFAULT_SUBNET_DENY.iter().map(|s| s.to_string()).collect(),
            subnet_deny_ifaces: crate::net::DEFAULT_IFACE_DENY.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Default for EgressCfg {
    fn default() -> Self {
        Self { allow_egress: true, egress_ack_timeout_ms: 3000, egress_cache_ttl_ms: 30_000 }
    }
}

impl Default for RouteCfg {
    fn default() -> Self {
        Self {
            ttl_default: 8,
            gossip_interval_ms: 5000,
            gossip_flood_ttl: 4,
            route_switch_timeout_ms: 30_000,
            cost: CostCfg::default(),
            rules_enabled: true,
            rules: Vec::new(),
            groups: Vec::new(),
            accept_shared_rules: true,
            publish_enabled: true,
            default_egress: None,
        }
    }
}

impl Default for CostCfg {
    fn default() -> Self {
        Self { lan: 1, wan: 5, per_hop: 3 }
    }
}

impl Default for ProxyCfg {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:1080".parse().expect("valid literal"),
            allow_remote: false,
        }
    }
}

impl Default for SecurityCfg {
    fn default() -> Self {
        Self { join_token: String::new(), rule_token: String::new(), e2e: E2eMode::Off }
    }
}

impl Default for LogCfg {
    fn default() -> Self {
        Self { level: "info".into() }
    }
}

impl Config {
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// 提交前的健全性检查。返回所有**非致命**的告警（致命错误由调用方另行处理）。
    pub fn validate(&self) -> Vec<String> {
        let mut warns = Vec::new();

        if self.listen.ports.is_empty() {
            warns.push("listen.ports 为空，将回退到默认端口 5678".to_string());
        }
        if self.listen.ports.len() > 8 {
            warns.push(format!(
                "listen.ports 有 {} 个端口，既是把自己变成扫描目标也白耗 fd（§6.2.3）",
                self.listen.ports.len()
            ));
        }
        if self.listen.ports.contains(&0) {
            warns.push("listen.ports 含 0，非法端口".to_string());
        }
        if self.discovery.max_dial_candidates == 0 {
            warns.push("discovery.max_dial_candidates = 0 会让 dialer 没有候选可拨".to_string());
        }
        if self.proxy.allow_remote && !self.proxy.bind.ip().is_loopback() {
            warns.push(format!(
                "本地代理监听在非回环地址 {} 且 allow_remote = true —— 同网段任何人都能用你的网络位置（§11）。\
                 端口上同时讲 SOCKS5 与 HTTP 代理，**HTTP 正向代理比 SOCKS5 更容易被滥用**（任何 GUI 应用、\
                 甚至一段脚本都能拿它出去），非必要不要开",
                self.proxy.bind
            ));
        }
        if let Some(a) = self.admin.tcp {
            if !a.ip().is_loopback() {
                warns.push(format!(
                    "admin.tcp = {a} 不是回环地址 —— 管理接口没有任何认证，绑到外部等于把控制权交出去"
                ));
            }
        }
        if self.route.gossip_flood_ttl == 0 {
            warns.push(
                "gossip_flood_ttl = 0 会让拓扑只传播 1 跳，四节点链以上无法路由（§6.3）".to_string(),
            );
        }
        for (i, r) in self.route.rules.iter().enumerate() {
            if r.is_catch_all() {
                warns.push(format!(
                    "规则 #{} `*:*` 无边界规则：会兜住所有未被前面规则命中的流量（§17 风险 10）",
                    i + 1
                ));
            }
        }
        for g in &self.route.groups {
            if g.name.is_empty() {
                warns.push("存在未命名的 route.groups 条目".to_string());
            }
        }
        for s in &self.share.subnet_deny {
            // 解析不了的排除项等于没排除 —— 必须说出来，否则用户以为配上了
            if s.trim().parse::<ipnet::IpNet>().is_err() {
                warns.push(format!("share.subnet_deny 里的 `{s}` 不是合法 CIDR，已忽略"));
            }
        }
        if self.share.subnet_deny_ifaces.iter().all(|p| p.trim().is_empty()) {
            warns.push(
                "share.subnet_deny_ifaces 为空：虚拟网卡（tun/utun 等）的地址也会被当成真实网段（§9.1）"
                    .to_string(),
            );
        }
        warns
    }

    /// 递归解析别名：把 `alias:` 出口换成 `node:`（§9.4.3 发布侧要求 2）。
    pub fn resolve_aliases(&self, rules: &mut [crate::rules::Rule]) -> Result<(), Vec<usize>> {
        let mut bad = Vec::new();
        for (i, r) in rules.iter_mut().enumerate() {
            if let crate::rules::EgressTarget::Alias(name) = &r.egress {
                match self.alias_to_node(name) {
                    Some(node) => r.egress = crate::rules::EgressTarget::Node(node),
                    None => bad.push(i),
                }
            }
        }
        if bad.is_empty() {
            Ok(())
        } else {
            Err(bad)
        }
    }

    /// `peers.entry` → NodeId（§9.4.2）。
    pub fn alias_to_node(&self, alias: &str) -> Option<crate::proto::NodeId> {
        self.peers
            .entry
            .iter()
            .find(|e| e.alias == alias)
            .and_then(|e| parse_peer_address(&e.address).ok())
            .map(|(ip, _)| crate::proto::NodeId::from_ip(ip))
    }

    /// 别名 → 监听地址（用于拨号候选）。
    pub fn alias_to_socket(&self, alias: &str) -> Option<SocketAddr> {
        self.peers
            .entry
            .iter()
            .find(|e| e.alias == alias)
            .and_then(|e| parse_peer_address(&e.address).ok())
            .and_then(|(ip, port)| port.map(|p| SocketAddr::new(ip, p)))
    }
}

/// 解析种子的三种写法（§6.2.2）：返回 `(ip, Option<port>)`。
pub fn parse_peer_address(s: &str) -> Result<(IpAddr, Option<u16>), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("空地址".into());
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, None));
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok((sa.ip(), Some(sa.port())));
    }
    // "ip:lo-hi"
    if let Some((host, range)) = s.rsplit_once(':') {
        if let Some((lo, hi)) = range.split_once('-') {
            let ip: IpAddr = host.parse().map_err(|_| format!("无法解析地址 `{s}`"))?;
            let lo: u16 = lo.trim().parse().map_err(|_| format!("无效端口 `{lo}`"))?;
            // 端口范围取起点作为起始候选（完整范围由 expand_seed 展开）。
            let _hi: u16 = hi.trim().parse().map_err(|_| format!("无效端口 `{hi}`"))?;
            return Ok((ip, Some(lo)));
        }
    }
    Err(format!("无法解析地址 `{s}`，支持 ip | ip:port | ip:lo-hi"))
}

/// 把一个种子展开成候选端口序列（§6.2.2）。
pub fn expand_seed(s: &str, probe_ports: &[u16]) -> Result<(IpAddr, Vec<u16>), String> {
    let s = s.trim();
    // 端口范围
    if let Some((host, range)) = s.rsplit_once(':') {
        if let Some((lo, hi)) = range.split_once('-') {
            let ip: IpAddr = host.parse().map_err(|_| format!("无法解析地址 `{s}`"))?;
            let lo: u16 = lo.trim().parse().map_err(|_| format!("无效端口 `{lo}`"))?;
            let hi: u16 = hi.trim().parse().map_err(|_| format!("无效端口 `{hi}`"))?;
            if lo > hi {
                return Err(format!("端口范围倒置 `{s}`"));
            }
            return Ok((ip, (lo..=hi).collect()));
        }
    }
    let (ip, port) = parse_peer_address(s)?;
    Ok(match port {
        Some(p) => (ip, vec![p]),
        None => (ip, probe_ports.to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{EgressTarget, HostMatcher, PortMatcher, Rule};

    #[test]
    fn defaults_match_design_doc() {
        let c = Config::default();
        assert_eq!(c.listen.ports, vec![5678], "未配置时兜底 5678（§6.2.3）");
        assert!(c.listen.advertise, "监听端点默认广播（§18 第 19 条）");
        assert!(c.share.auto_share_subnets, "默认即合岛（§18 第 14 条）");
        assert!(c.peers.accept_listen_adverts);
        assert_eq!(c.route.gossip_flood_ttl, 4, "变化驱动 flood 的默认半径（§18 第 20 条）");
        assert!(c.route.rules_enabled);
        assert!(c.route.accept_shared_rules);
        assert!(c.route.publish_enabled, "发布不限制（§18 第 22 条）");
        assert!(c.egress.allow_egress);
        assert_eq!(c.proxy.bind.to_string(), "127.0.0.1:1080");
        assert!(!c.proxy.allow_remote);
        assert_eq!(c.discovery.max_dial_candidates, 64);
        // 虚拟网卡与代理工具的假地址池默认排除（§9.1、2026-10-13）
        assert_eq!(c.share.subnet_deny, vec!["198.18.0.0/15"]);
        assert!(c.share.subnet_deny_ifaces.iter().any(|p| p == "utun*"));
        assert!(!c.share.deny_cidrs().is_empty(), "默认排除段应当能解析出来");
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields：拼错的键必须报错，而不是静默忽略（§10.1）。
        let err = Config::from_toml("[listen]\nprot = [5678]\n");
        assert!(err.is_err(), "拼错的键 `prot` 应当报错");
    }

    #[test]
    fn proxy_accepts_the_old_field_names() {
        // ★ 端口上只有 SOCKS5 时落盘的配置（`socks5_bind` / `allow_remote_socks`）必须继续能读 ——
        // 已经有机器在跑老配置，改名不能变成"启动即解析失败"（§6.4、2026-10-13）。
        let old = Config::from_toml(
            "[proxy]\nsocks5_bind = \"127.0.0.1:18080\"\nallow_remote_socks = true\n",
        )
        .expect("旧字段名必须继续可解析");
        assert_eq!(old.proxy.bind.to_string(), "127.0.0.1:18080");
        assert!(old.proxy.allow_remote);

        // 新名字与旧名字等价，且写回去用的是新名字
        let new = Config::from_toml("[proxy]\nbind = \"127.0.0.1:18080\"\nallow_remote = true\n").unwrap();
        assert_eq!(new.proxy, old.proxy);
        let toml = new.to_toml();
        assert!(toml.contains("bind = "), "序列化必须用新名字：\n{toml}");
        assert!(!toml.contains("socks5_bind"), "不该再写出旧名字：\n{toml}");
    }

    #[test]
    fn minimal_config_parses() {
        // 只写 listen.ports 就应当能跑（必填项从 3 项降到 2 项，§18 第 28 条）。
        let c = Config::from_toml("[listen]\nports = [20000]\n").unwrap();
        assert_eq!(c.listen.ports, vec![20000]);
        assert!(c.peers.seeds.is_empty(), "seeds 可以为空");
        assert!(c.route.rules.is_empty(), "规则可以一条都不写");
    }

    #[test]
    fn seed_forms() {
        let probe = vec![5678, 5679];
        assert_eq!(expand_seed("10.1.2.3:20000", &probe).unwrap().1, vec![20000]);
        assert_eq!(expand_seed("10.1.2.3", &probe).unwrap().1, vec![5678, 5679]);
        assert_eq!(expand_seed("10.1.2.3:5678-5680", &probe).unwrap().1, vec![5678, 5679, 5680]);
        assert!(expand_seed("10.1.2.3:5680-5678", &probe).is_err());
        assert!(expand_seed("not-an-ip", &probe).is_err());
    }

    #[test]
    fn default_egress_round_trips_as_a_string() {
        // 默认出口的人读形态就是它自己的字符串语法（§9.4.4、§10）。
        let c = Config::from_toml("[route]\ndefault_egress = \"node:10.0.0.1\"\n").unwrap();
        assert_eq!(
            c.route.default_egress,
            Some(EgressTarget::Node("10.0.0.1".parse().unwrap()))
        );
        let toml = c.to_toml();
        assert!(toml.contains("default_egress = \"node:10.0.0.1\""), "{toml}");
        let back = Config::from_toml(&toml).unwrap();
        assert_eq!(back.route.default_egress, c.route.default_egress);

        // 不写 = None，且序列化时不落一个空行（skip_serializing_if）
        let c2 = Config::default();
        assert!(c2.route.default_egress.is_none());
        assert!(!c2.to_toml().contains("default_egress"));
    }

    #[test]
    fn default_egress_rejects_auto_and_block_at_parse_time() {
        // 这两个值不是"写错了"，而是"在这里没有意义"：auto 就是网段匹配本身，
        // block 等于一键拒绝全部流量。宁可 TOML 解析阶段报错，也不静默忽略（§18 第 29 条）。
        for bad in ["auto", "block"] {
            let src = format!("[route]\ndefault_egress = \"{bad}\"\n");
            let err = Config::from_toml(&src).expect_err("应当报错");
            assert!(err.to_string().contains("默认出口"), "{err}");
        }
        // 拼错的写法同样报错（走的是 EgressTarget::parse）
        assert!(Config::from_toml("[route]\ndefault_egress = \"nod:1.2.3.4\"\n").is_err());
    }

    #[test]
    fn validate_flags_flood_zero() {
        let c = Config::from_toml("[route]\ngossip_flood_ttl = 0\n").unwrap();
        assert!(c.validate().iter().any(|w| w.contains("1 跳")));
    }

    #[test]
    fn validate_flags_wildcard_rule() {
        let c = Config::from_toml("").unwrap();
        let r = Rule {
            host: HostMatcher::Any,
            port: PortMatcher::Any,
            egress: EgressTarget::Block,
            on_unreachable: Default::default(),
            label: None,
            enabled: true,
        };
        let mut c2 = c;
        c2.route.rules.push(r);
        assert!(c2.validate().iter().any(|w| w.contains("无边界")));
    }
}
