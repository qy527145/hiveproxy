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
    pub web: WebCfg,
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

/// Web 界面（docs/WEBUI.md）。
///
/// ★ **只有 `hiveproxy-cli` 会读这一节并启动它**；桌面端（Tauri）从不启动 web 服务。
/// 这是一条硬边界，不是约定 —— "只做 CLI 侧"就落在这里。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WebCfg {
    /// 关掉它就等于回到"只有管理 socket"的老样子（剪贴板里那些 `nc -U` 用法照旧）。
    pub enabled: bool,
    /// 默认监听局域网。改 `127.0.0.1:10801` = 只允许本机 / SSH 隧道。
    ///
    /// ★ 端口选 10801 而不是 10800：`admin.tcp` 在非 Unix 平台的默认值就是 10800，
    /// 两个都是 TCP，Windows 上会撞。
    pub bind: SocketAddr,
    /// `Host` 头校验的额外白名单 —— 反代用了域名时填这里。
    ///
    /// 这条校验挡的是 **DNS rebinding**：攻击页面必然带着一个域名来，
    /// 而正常的访问者带的是本机地址或 `localhost`（见 `web.rs`）。
    pub allowed_hosts: Vec<String>,
}

impl Default for WebCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "0.0.0.0:10801".parse().expect("字面量"),
            allowed_hosts: Vec::new(),
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
            web: WebCfg::default(),
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
        // web 界面默认监听局域网，这是本项目里唯一一处主动扩大攻击面的默认值 ——
        // 它靠令牌 + Origin/Host 校验兜住，但**令牌在网段里是明文**，配置改不掉。必须说出来。
        if self.web.enabled && !self.web.bind.ip().is_loopback() {
            warns.push(format!(
                "web.bind = {} 监听在非回环地址：界面靠令牌认证，但令牌与全部数据在网段里是**明文 HTTP**。\
                 想更安全就把 enabled 关掉或 bind 改回环，用 `ssh -L {}:127.0.0.1:{}` 访问（docs/WEBUI.md §6）",
                self.web.bind,
                self.web.bind.port(),
                self.web.bind.port()
            ));
        }
        if self.web.enabled && self.web.bind.ip().is_unspecified() && self.web.allowed_hosts.is_empty() {
            // 不是错误，只是提醒：反代用了域名就必须填白名单，否则 Host 校验会把它挡在门外
            warns.push(
                "web.bind 是通配地址且 web.allowed_hosts 为空：直接用 IP 访问没问题，\
                 但前面挂反代（带域名）时要往 allowed_hosts 里加域名"
                    .to_string(),
            );
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

/// 一份配置改动的**生效档位**（docs/WEBUI.md §5）。
///
/// 分散在各处的 `if old.x != new.x` 迟早会漏掉一个字段，而漏掉的症状是
/// "改完看着保存成功了、其实没生效" —— 所以集中在这里，并且**由测试钉住**。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigChange {
    /// 要重新绑定入向端口（`listen.bind` / `listen.ports`）。
    pub listen: bool,
    /// 要重新绑定本地代理端口（`proxy.bind`）。
    pub proxy: bool,
    /// 要重建整个引擎 —— 身份变了，或者网段表变了（`NodeIdentity` 是 `Arc`，改不了它的内容）。
    pub engine: bool,
}

impl ConfigChange {
    /// 热生效：不用重绑、更不用重建。
    pub fn is_hot(self) -> bool {
        !self.listen && !self.proxy && !self.engine
    }
}

/// 比较两份配置，给出各档位是否要动作。
///
/// ★ `listen.max_links` **不算** `listen` 档：它每个 accept 都现读配置，
/// 把它算进来的话，改一次上限就会去重绑同一个端口 —— 那是必然的 `EADDRINUSE`。
pub fn classify_change(old: &Config, new: &Config) -> ConfigChange {
    ConfigChange {
        listen: old.listen.bind != new.listen.bind || old.listen.ports != new.listen.ports,
        proxy: old.proxy.bind != new.proxy.bind,
        engine: old.node != new.node
            || old.share.auto_share_subnets != new.share.auto_share_subnets
            || old.share.subnet_deny != new.share.subnet_deny
            || old.share.subnet_deny_ifaces != new.share.subnet_deny_ifaces
            || old.admin != new.admin,
    }
}

/// 把某个字段动一下（测试用）。
///
/// 每个改动都保证**真的改了值** —— 否则 `classify_change` 看到的是同一份配置，
/// 测试会假绿。Rust 没有反射，路径 → 字段这张表只能在测试里手写一遍；
/// 写错了这条测试会直接报"某档位不对"，不会静默放过。
#[cfg(test)]
fn poke(cfg: &mut Config, path: &str) {
    match path {
        "listen.bind" => cfg.listen.bind = "127.0.0.2".parse().unwrap(),
        "listen.ports" => cfg.listen.ports = vec![5699],
        "listen.max_links" => cfg.listen.max_links += 1,
        "listen.advertise" => cfg.listen.advertise = !cfg.listen.advertise,
        "proxy.bind" => cfg.proxy.bind = "127.0.0.1:1099".parse().unwrap(),
        "proxy.allow_remote" => cfg.proxy.allow_remote = !cfg.proxy.allow_remote,
        "node.overlay_addr" => cfg.node.overlay_addr = Some("10.9.9.9".parse().unwrap()),
        "node.alias" => cfg.node.alias = Some("poke".into()),
        "node.zone" => cfg.node.zone = Some(7),
        "share.auto_share_subnets" => cfg.share.auto_share_subnets = !cfg.share.auto_share_subnets,
        "share.share_ports_only" => cfg.share.share_ports_only = vec![5678],
        "share.subnet_deny" => cfg.share.subnet_deny.push("10.99.0.0/16".into()),
        "share.subnet_deny_ifaces" => cfg.share.subnet_deny_ifaces.push("poke*".into()),
        "admin.enabled" => cfg.admin.enabled = !cfg.admin.enabled,
        "admin.socket" => cfg.admin.socket = "/tmp/poke.sock".into(),
        "admin.tcp" => cfg.admin.tcp = Some("127.0.0.1:10999".parse().unwrap()),
        "route.rules" => {
            cfg.route.rules.push(crate::rules::Rule::new(
                crate::rules::HostMatcher::parse("poke.example.com").unwrap(),
                crate::rules::PortMatcher::Any,
                crate::rules::EgressTarget::Auto,
            ))
        }
        "peers.seeds" => cfg.peers.seeds.push("10.1.2.3:5678".into()),
        other => panic!("poke 里没有 `{other}` —— 加了字段就把它补上"),
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

    /// 生效档位的**唯一权威表**（docs/WEBUI.md §5.1）。
    ///
    /// 这份表要同时管住三件事，所以它只有一处：
    /// ① 引擎的 `classify_change` 真按它分档；② web 界面的提示文案（`configSpec.ts`）；
    /// ③ 上面那条 `poke` 认得这些路径。
    const TIER_TABLE: &[(&str, &str)] = &[
        // ② 引擎内重绑 —— 只有"要换监听 socket"的这三个
        ("listen.bind", "rebind"),
        ("listen.ports", "rebind"),
        ("proxy.bind", "rebind"),
        // 下面两个**特意钉成热生效**：它们是每个连接现读配置的。
        // 把 `max_links` 算进重绑档的话，改一次上限就会去绑同一个端口 —— 必然 EADDRINUSE。
        ("listen.max_links", "hot"),
        ("proxy.allow_remote", "hot"),
        // ③ 重建引擎（身份 / 网段表 / 管理接口端点）
        ("node.overlay_addr", "rebuild"),
        ("node.alias", "rebuild"),
        ("node.zone", "rebuild"),
        ("share.auto_share_subnets", "rebuild"),
        ("share.subnet_deny", "rebuild"),
        ("share.subnet_deny_ifaces", "rebuild"),
        ("admin.enabled", "rebuild"),
        ("admin.socket", "rebuild"),
        ("admin.tcp", "rebuild"),
        // ① 热生效的抽样（不是全集，只需要有代表性）
        ("route.rules", "hot"),
        ("peers.seeds", "hot"),
        ("share.share_ports_only", "hot"),
        ("listen.advertise", "hot"),
    ];

    #[test]
    fn classify_change_puts_each_field_in_the_right_tier() {
        let base = Config::default();
        for (path, want) in TIER_TABLE {
            let mut c = base.clone();
            poke(&mut c, path);
            let ch = classify_change(&base, &c);
            let got = if ch.engine {
                "rebuild"
            } else if ch.listen || ch.proxy {
                "rebind"
            } else {
                "hot"
            };
            assert_eq!(got, *want, "`{path}` 的档位不对（want {want}）——{ch:?}");
        }
    }

    /// ★ 守卫：前端的档位表必须和 `TIER_TABLE` 一致。
    ///
    /// 这两张表漂了不会报错，只会让界面**说错话**："改了会重绑"实际热生效（或反过来，
    /// 用户以为不用管，结果断了所有连接）。第一次接前端时就漂过一次
    /// （`listen.max_links` / `proxy.allow_remote` 被标成了重绑档），所以钉住。
    #[test]
    fn frontend_tier_table_matches_the_backend() {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src/lib/configSpec.ts");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读不到 {}：{e}", path.display()));

        // FIELD_EFFECT 段里那些 `"路径": "档位",` 的行
        let start = text.find("FIELD_EFFECT").expect("configSpec.ts 里应当有 FIELD_EFFECT");
        let end = text[start..].find("};").expect("FIELD_EFFECT 应当以 }; 收尾") + start;
        let mut ts: Vec<(String, String)> = Vec::new();
        for line in text[start..end].lines() {
            let line = line.trim();
            if !line.starts_with('"') {
                continue;
            }
            let Some((k, v)) = line.split_once("\":") else { continue };
            let k = k.trim().trim_start_matches('"').trim();
            let v = v.trim().trim_end_matches(',').trim().trim_matches('"');
            if matches!(v, "hot" | "rebind" | "rebuild") {
                ts.push((k.to_string(), v.to_string()));
            }
        }
        assert!(!ts.is_empty(), "没能从 configSpec.ts 里解析出任何档位条目");

        let mut want: Vec<(String, String)> = TIER_TABLE
            .iter()
            .filter(|(_, t)| *t != "hot") // 前端只列非热生效的，热生效是默认档
            .map(|(p, t)| (p.to_string(), t.to_string()))
            .collect();
        ts.sort();
        want.sort();

        assert_eq!(
            ts, want,
            "前端 configSpec.ts 的 FIELD_EFFECT 与后端的 TIER_TABLE 不一致 —— \
             界面上的提示会说错话（两边都不报错，只是说法不对）"
        );
    }
}
