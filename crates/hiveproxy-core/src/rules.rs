//! 路由规则与出口选择（DESIGN.md §9.4）。
//!
//! 规则是**有序列表、先匹配者胜** —— 顺序即优先级，由使用者显式表达，
//! 因此不需要"具体度"枚举来隐式排序（§9.4.2）。

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::proto::header::NodeId;
use crate::proto::types::{Endpoint, Host, RuleSetAd};

// ---------------------------------------------------------------------------
// 匹配条件
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HostMatcher {
    /// `*`
    Any,
    /// `10.1.2.9` 或 `api.corp.example.com`（不做 DNS 解析，纯字面比对）
    Exact(String),
    /// `*.internal.example.com`（存 `internal.example.com`）
    Suffix(String),
    /// `10.9.0.0/16`
    Cidr(IpNet),
}

impl HostMatcher {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("host 不能为空".into());
        }
        if s == "*" {
            return Ok(Self::Any);
        }
        if let Some(rest) = s.strip_prefix("*.") {
            if rest.is_empty() {
                return Err("`*.` 后必须有域名后缀".into());
            }
            return Ok(Self::Suffix(rest.to_ascii_lowercase()));
        }
        if s.contains('/') {
            let net: IpNet = s.parse().map_err(|_| format!("无效 CIDR `{s}`"))?;
            return Ok(Self::Cidr(net));
        }
        // 规范化 IP 写法（10.1.2.3 / ::ffff:10.1.2.3 → 统一形式）
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Exact(ip.to_string()));
        }
        // 防呆：`host` 只写主机部分，端口另有一栏。写成 "127.0.0.1:8080" 会得到一个
        // 永远匹配不到的模式（IPv6 地址本身含 ':'，所以只有在解析不成 IP 时才判错）。
        if s.contains(':') {
            return Err(format!(
                "host 只写主机部分（`{s}` 看起来带了端口）。端口请写在 port 字段里：host = \"{}\", port = ...",
                s.rsplit_once(':').map(|(h, _)| h).unwrap_or(s)
            ));
        }
        Ok(Self::Exact(s.to_ascii_lowercase()))
    }

    pub fn to_config_string(&self) -> String {
        match self {
            Self::Any => "*".into(),
            Self::Exact(s) => s.clone(),
            Self::Suffix(s) => format!("*.{s}"),
            Self::Cidr(n) => n.to_string(),
        }
    }

    /// 字面对比，不做 DNS 解析（§9.4.2）。
    pub fn matches(&self, host: &Host) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(want) => match host {
                Host::Ip(ip) => want == &ip.to_string(),
                Host::Name(n) => want == &n.to_ascii_lowercase(),
            },
            Self::Suffix(suf) => match host {
                // 域名后缀匹配，要求标签边界：`a.internal.example.com` 命中 `internal.example.com`，
                // 而 `notinternal.example.com` 不命中。
                Host::Name(n) => {
                    let n = n.to_ascii_lowercase();
                    n.len() > suf.len() + 1
                        && n.ends_with(suf)
                        && n.as_bytes()[n.len() - suf.len() - 1] == b'.'
                }
                Host::Ip(_) => false,
            },
            // 域名没有 IP，永不参与网段匹配（§9.4.2 推论）。
            Self::Cidr(net) => match host {
                Host::Ip(ip) => net.contains(ip),
                Host::Name(_) => false,
            },
        }
    }

    /// `self` 是否覆盖 `other` —— 即 `other` 命中的集合是 `self` 的子集。
    /// 用于 `preview_rules` 判断"被前面的规则完全遮蔽"（§9.4.3 发布侧要求 3）。
    pub fn covers(&self, other: &HostMatcher) -> bool {
        match (self, other) {
            (Self::Any, _) => true,
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Suffix(s), Self::Exact(b)) => {
                b.len() > s.len() + 1 && b.ends_with(s) && b.as_bytes()[b.len() - s.len() - 1] == b'.'
            }
            (Self::Suffix(s), Self::Suffix(t)) => {
                t == s || (t.len() > s.len() && t.ends_with(s) && t.as_bytes()[t.len() - s.len() - 1] == b'.')
            }
            (Self::Cidr(n), Self::Cidr(m)) => {
                m.prefix_len() >= n.prefix_len() && n.contains(&m.network())
            }
            (Self::Cidr(n), Self::Exact(ip)) => ip
                .parse::<IpAddr>()
                .map(|a| n.contains(&a))
                .unwrap_or(false),
            _ => false,
        }
    }

    /// 用于"按具体度重排"（§9.4.2）。数字越小越具体。
    pub fn specificity(&self) -> u8 {
        match self {
            Self::Exact(_) => 0,
            Self::Suffix(_) => 1,
            Self::Cidr(_) => 2,
            Self::Any => 3,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PortMatcher {
    Any,
    Exact(u16),
    Range(u16, u16),
}

impl PortMatcher {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s == "*" || s.is_empty() {
            return Ok(Self::Any);
        }
        if let Some((lo, hi)) = s.split_once('-') {
            let lo: u16 = lo.trim().parse().map_err(|_| format!("无效端口 `{lo}`"))?;
            let hi: u16 = hi.trim().parse().map_err(|_| format!("无效端口 `{hi}`"))?;
            if lo > hi {
                return Err(format!("端口范围倒置 `{s}`"));
            }
            return Ok(Self::Range(lo, hi));
        }
        let p: u16 = s.parse().map_err(|_| format!("无效端口 `{s}`"))?;
        Ok(Self::Exact(p))
    }

    pub fn to_config_string(&self) -> String {
        match self {
            Self::Any => "*".into(),
            Self::Exact(p) => p.to_string(),
            Self::Range(lo, hi) => format!("{lo}-{hi}"),
        }
    }

    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(p) => *p == port,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
        }
    }

    pub fn specificity(&self) -> u8 {
        match self {
            Self::Exact(_) => 0,
            Self::Range(..) => 1,
            Self::Any => 2,
        }
    }

    /// `self` 是否覆盖 `other`（端口集合的包含关系）。
    pub fn covers(&self, other: &PortMatcher) -> bool {
        match (self, other) {
            (Self::Any, _) => true,
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Range(lo, hi), Self::Exact(p)) => p >= lo && p <= hi,
            (Self::Range(lo, hi), Self::Range(lo2, hi2)) => lo <= lo2 && hi2 <= hi,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// 出口
// ---------------------------------------------------------------------------

/// 候选集，两种写法（§9.4.2、§18 第 24 条）。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum GroupRef {
    /// `group:db` —— 查 `route.groups`
    Named(String),
    /// `group:subnet:10.9.0.0/16` —— 成员 = 声明了该网段的节点，随拓扑自动增减
    Subnet(IpNet),
}

/// 命中后往哪走。这是规则的全部动作面。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EgressTarget {
    /// 交给内置网段规则：命中网段的声明者中选路由成本最低者。
    Auto,
    /// 本机直接 connect，不进 overlay。
    SelfDirect,
    /// 钉死一个出口节点。
    Node(NodeId),
    /// 钉死一个别名。**仅本地规则可用** —— 发布前会被解析成 `Node`（§9.4.3）。
    Alias(String),
    /// 候选集。
    Group(GroupRef),
    /// 拒绝（回 SOCKS5 `0x02`）。
    Block,
}

impl EgressTarget {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        match s {
            "auto" => return Ok(Self::Auto),
            "direct" | "self" => return Ok(Self::SelfDirect),
            "block" | "reject" => return Ok(Self::Block),
            _ => {}
        }
        if let Some(rest) = s.strip_prefix("group:") {
            if let Some(cidr) = rest.strip_prefix("subnet:") {
                let net: IpNet = cidr.parse().map_err(|_| format!("无效 CIDR `{cidr}`"))?;
                return Ok(Self::Group(GroupRef::Subnet(net)));
            }
            if rest.is_empty() {
                return Err("`group:` 后必须有组名".into());
            }
            return Ok(Self::Group(GroupRef::Named(rest.to_string())));
        }
        if let Some(rest) = s.strip_prefix("alias:") {
            if rest.is_empty() {
                return Err("`alias:` 后必须有别名".into());
            }
            return Ok(Self::Alias(rest.to_string()));
        }
        // 裸 IP 等价于 node:<ip>（§9.4.2 取值表）
        let bare = s.strip_prefix("node:").unwrap_or(s);
        if let Ok(id) = bare.parse::<NodeId>() {
            return Ok(Self::Node(id));
        }
        Err(format!(
            "无法解析出口 `{s}`，支持 auto | direct | block | <ip> | node:<ip> | alias:<名> | group:<名> | group:subnet:<cidr>"
        ))
    }

    pub fn to_config_string(&self) -> String {
        match self {
            Self::Auto => "auto".into(),
            Self::SelfDirect => "direct".into(),
            Self::Node(n) => format!("node:{n}"),
            Self::Alias(a) => format!("alias:{a}"),
            Self::Group(GroupRef::Named(g)) => format!("group:{g}"),
            Self::Group(GroupRef::Subnet(n)) => format!("group:subnet:{n}"),
            Self::Block => "block".into(),
        }
    }
}

/// 指定出口不可达时怎么办。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum OnUnreachable {
    /// 顺延到下一顺位匹配（最终落到内置网段规则）；仍无则报错。**默认。**
    #[default]
    Fallback,
    /// 直接回 SOCKS5 错误，不静默改变路径。
    Fail,
}

impl OnUnreachable {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "fallback" | "auto" => Ok(Self::Fallback),
            "fail" => Ok(Self::Fail),
            other => Err(format!("无效 on_unreachable `{other}`，支持 fallback | fail")),
        }
    }

    pub fn to_config_string(self) -> String {
        match self {
            Self::Fallback => "fallback".into(),
            Self::Fail => "fail".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rule（含 TOML 字符串字面量的编解码）
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "RawRule", into = "RawRule")]
pub struct Rule {
    pub host: HostMatcher,
    pub port: PortMatcher,
    pub egress: EgressTarget,
    pub on_unreachable: OnUnreachable,
    /// 前端可读备注，不参与匹配。
    pub label: Option<String>,
    /// `false` = 仅留档不参与匹配。
    pub enabled: bool,
}

impl Rule {
    pub fn new(host: HostMatcher, port: PortMatcher, egress: EgressTarget) -> Self {
        Self {
            host,
            port,
            egress,
            on_unreachable: OnUnreachable::Fallback,
            label: None,
            enabled: true,
        }
    }

    pub fn matches(&self, target: &Endpoint) -> bool {
        self.host.matches(&target.host) && self.port.matches(target.port)
    }

    /// 规则 `self` 是否在匹配范围上完全覆盖 `other`。
    pub fn covers(&self, other: &Rule) -> bool {
        self.host.covers(&other.host) && self.port.covers(&other.port)
    }

    /// 用于"按具体度重排"。自左向右比较，越小越靠前（§9.4.2）。
    pub fn specificity_key(&self) -> (u8, u8) {
        (self.host.specificity(), self.port.specificity())
    }

    /// 是否是 `*:*` 这类无边界兜底规则（§17 风险 10，前端须给出显式告警）。
    pub fn is_catch_all(&self) -> bool {
        matches!(self.host, HostMatcher::Any) && matches!(self.port, PortMatcher::Any)
    }
}

/// 配置里的字符串写法（§9.4.2 的 TOML 形态）。`port` 同时接受整数与字符串。
///
/// 注意：**不能**在这里用 `skip_serializing_if`。`Rule` 会随 `RuleSetAd` 走 bincode
/// wire 格式（§5.3），而 bincode 不是自描述格式 —— 少写一个字段就会导致
/// "反序列化到一半 EOF"。所有字段必须无条件序列化。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    /// 空串 = 无备注。
    #[serde(default)]
    pub label: String,
    pub host: String,
    #[serde(default = "default_port_str")]
    pub port: PortSpec,
    pub egress: String,
    #[serde(default = "default_on_unreachable")]
    pub on_unreachable: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_port_str() -> PortSpec {
    PortSpec::Str("*".into())
}
fn default_on_unreachable() -> String {
    "fallback".into()
}
fn default_true() -> bool {
    true
}

/// `port = 443` 与 `port = "*"` 两种写法都要接受（§9.4.2 配置示例）。
///
/// 手写 `Serialize`/`Deserialize` 而不是 `#[serde(untagged)]`：后者在 bincode 下不可用，
/// 而 `Rule` 会随 `RuleSetAd` 走 wire 格式（§5.3），必须两种格式都能往返。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortSpec {
    Str(String),
    Int(u16),
}

impl PortSpec {
    fn as_str(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Int(p) => p.to_string(),
        }
    }
}

impl Serialize for PortSpec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // 始终按字符串输出：TOML 与 bincode 都能往返，且 `port = "443"` 读回来仍是 Exact(443)。
        s.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct PortVisitor;

        impl<'de> serde::de::Visitor<'de> for PortVisitor {
            type Value = PortSpec;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("端口号整数，或 \"*\" / \"443\" / \"8000-9000\" 形式的字符串")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(PortSpec::Str(v.to_string()))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                if v > u16::MAX as u64 {
                    return Err(E::custom(format!("端口 {v} 超出 u16 范围")));
                }
                Ok(PortSpec::Int(v as u16))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if !(0..=u16::MAX as i64).contains(&v) {
                    return Err(E::custom(format!("端口 {v} 超出 u16 范围")));
                }
                Ok(PortSpec::Int(v as u16))
            }
        }

        if d.is_human_readable() {
            d.deserialize_any(PortVisitor)
        } else {
            d.deserialize_str(PortVisitor)
        }
    }
}

impl TryFrom<RawRule> for Rule {
    type Error = String;

    fn try_from(raw: RawRule) -> Result<Self, Self::Error> {
        Ok(Rule {
            host: HostMatcher::parse(&raw.host)?,
            port: PortMatcher::parse(&raw.port.as_str())?,
            egress: EgressTarget::parse(&raw.egress)?,
            on_unreachable: OnUnreachable::parse(&raw.on_unreachable)?,
            label: if raw.label.is_empty() { None } else { Some(raw.label) },
            enabled: raw.enabled,
        })
    }
}

impl From<Rule> for RawRule {
    fn from(r: Rule) -> Self {
        RawRule {
            label: r.label.unwrap_or_default(),
            host: r.host.to_config_string(),
            port: PortSpec::Str(r.port.to_config_string()),
            egress: r.egress.to_config_string(),
            on_unreachable: r.on_unreachable.to_config_string(),
            enabled: r.enabled,
        }
    }
}

// ---------------------------------------------------------------------------
// RuleTable —— SOCKS5 入口消费的扁平视图（§5.7、§9.4.3）
// ---------------------------------------------------------------------------

/// 合并后的规则表：**本地规则在前，共享规则在后**（外加末尾物化的网段兜底行）。
///
/// 入口只按序匹配，不关心某条来自哪里；`shared_source` / `shared_revision`
/// 供前端展示"当前策略是谁下发的"。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RuleTable {
    pub merged: Vec<Rule>,
    /// `merged[..local_count]` 是本地规则。
    pub local_count: usize,
    pub shared_source: Option<NodeId>,
    pub shared_revision: u64,
    /// 全局旁路：`false` 时忽略全部规则，只跑内置网段匹配（§9.4.4）。
    pub rules_enabled: bool,
}

impl Default for RuleTable {
    fn default() -> Self {
        Self {
            merged: Vec::new(),
            local_count: 0,
            shared_source: None,
            shared_revision: 0,
            rules_enabled: true,
        }
    }
}

impl RuleTable {
    /// 按 §9.4.3 的合并顺序构建。
    pub fn build(local: &[Rule], shared: Option<&RuleSetAd>, rules_enabled: bool) -> Self {
        let mut merged: Vec<Rule> = Vec::new();
        if rules_enabled {
            merged.extend_from_slice(local);
        }
        let local_count = merged.len();
        if rules_enabled {
            if let Some(rs) = shared {
                // 共享规则里的别名不应当存在（发布时会解析掉）；防御性地跳过。
                merged.extend(rs.rules.iter().filter(|r| !matches!(r.egress, EgressTarget::Alias(_))).cloned());
            }
        }
        Self {
            merged,
            local_count,
            shared_source: shared.map(|s| s.publisher),
            shared_revision: shared.map(|s| s.revision).unwrap_or(0),
            rules_enabled,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.merged.is_empty()
    }

    /// 按具体度重排**本地段**（共享段顺序由发布者决定，不重排）。
    pub fn sorted_by_specificity(local: &[Rule]) -> Vec<Rule> {
        let mut v = local.to_vec();
        v.sort_by_key(|r| r.specificity_key());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> Endpoint {
        // 测试辅助：只处理 ip:port / domain:port
        let (h, p) = s.rsplit_once(':').unwrap();
        let port: u16 = p.parse().unwrap();
        let host = match h.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Name(h.to_string()),
        };
        Endpoint::new(host, port)
    }

    #[test]
    fn host_matcher_parse_forms() {
        assert_eq!(HostMatcher::parse("*").unwrap(), HostMatcher::Any);
        assert_eq!(
            HostMatcher::parse("*.internal.example.com").unwrap(),
            HostMatcher::Suffix("internal.example.com".into())
        );
        assert_eq!(
            HostMatcher::parse("10.9.0.0/16").unwrap(),
            HostMatcher::Cidr("10.9.0.0/16".parse().unwrap())
        );
        assert_eq!(HostMatcher::parse("10.1.2.9").unwrap(), HostMatcher::Exact("10.1.2.9".into()));
        assert_eq!(
            HostMatcher::parse("API.Corp.Example.com").unwrap(),
            HostMatcher::Exact("api.corp.example.com".into())
        );
        assert!(HostMatcher::parse("").is_err());
        assert!(HostMatcher::parse("*.").is_err());
        assert!(HostMatcher::parse("10.9.0.0/99").is_err());
        // 把端口写进 host 是个常见错误，必须明确报错而不是产出一个永不命中的模式
        let e = HostMatcher::parse("127.0.0.1:8080").unwrap_err();
        assert!(e.contains("port"), "{e}");
        // IPv6 地址本身含 ':'，不能被误伤
        assert_eq!(
            HostMatcher::parse("fd00::1").unwrap(),
            HostMatcher::Exact("fd00::1".into())
        );
    }

    #[test]
    fn suffix_requires_label_boundary() {
        let m = HostMatcher::parse("*.internal.example.com").unwrap();
        assert!(m.matches(&Host::Name("a.internal.example.com".into())));
        assert!(m.matches(&Host::Name("deep.a.internal.example.com".into())));
        assert!(!m.matches(&Host::Name("notinternal.example.com".into())));
        assert!(!m.matches(&Host::Name("evil-internal.example.com".into())));
        // 域名后缀永不匹配 IP
        assert!(!m.matches(&Host::Ip("10.1.2.3".parse().unwrap())));
    }

    #[test]
    fn cidr_never_matches_domain() {
        // §9.4.2 推论：域名目标永远不可能命中"网段匹配"。
        let m = HostMatcher::parse("10.9.0.0/16").unwrap();
        assert!(m.matches(&Host::Ip("10.9.1.2".parse().unwrap())));
        assert!(!m.matches(&Host::Ip("10.10.1.2".parse().unwrap())));
        assert!(!m.matches(&Host::Name("10.9.1.2".into())));
    }

    #[test]
    fn port_matcher_forms() {
        assert_eq!(PortMatcher::parse("*").unwrap(), PortMatcher::Any);
        assert_eq!(PortMatcher::parse("443").unwrap(), PortMatcher::Exact(443));
        assert_eq!(PortMatcher::parse("8000-9000").unwrap(), PortMatcher::Range(8000, 9000));
        assert!(PortMatcher::parse("9000-8000").is_err());
        assert!(PortMatcher::parse("99999").is_err());
        assert!(PortMatcher::Range(8000, 9000).matches(8080));
        assert!(!PortMatcher::Range(8000, 9000).matches(9001));
    }

    #[test]
    fn egress_target_forms() {
        assert_eq!(EgressTarget::parse("auto").unwrap(), EgressTarget::Auto);
        assert_eq!(EgressTarget::parse("direct").unwrap(), EgressTarget::SelfDirect);
        assert_eq!(EgressTarget::parse("block").unwrap(), EgressTarget::Block);
        assert_eq!(
            EgressTarget::parse("alias:gpu-01").unwrap(),
            EgressTarget::Alias("gpu-01".into())
        );
        assert_eq!(
            EgressTarget::parse("group:db").unwrap(),
            EgressTarget::Group(GroupRef::Named("db".into()))
        );
        assert_eq!(
            EgressTarget::parse("group:subnet:10.9.0.0/16").unwrap(),
            EgressTarget::Group(GroupRef::Subnet("10.9.0.0/16".parse().unwrap()))
        );
        // 裸 IP 与 node: 前缀等价
        let want = EgressTarget::Node("10.1.2.3".parse().unwrap());
        assert_eq!(EgressTarget::parse("10.1.2.3").unwrap(), want);
        assert_eq!(EgressTarget::parse("node:10.1.2.3").unwrap(), want);
        assert!(EgressTarget::parse("bogus:x").is_err());
    }

    #[test]
    fn rule_toml_roundtrip_and_heterogeneous_port() {
        let toml_src = r#"
label  = "内网 API"
host   = "api.corp.example.com"
port   = 443
egress = "alias:gpu-01"
on_unreachable = "fallback"
enabled = true
"#;
        let r: Rule = toml::from_str(toml_src).unwrap();
        assert_eq!(r.port, PortMatcher::Exact(443));
        assert_eq!(r.egress, EgressTarget::Alias("gpu-01".into()));

        // port 也可以写成字符串 "*"（同节示例里两种写法并存）
        let r2: Rule = toml::from_str("host = \"*\"\nport = \"*\"\negress = \"block\"\n").unwrap();
        assert_eq!(r2.port, PortMatcher::Any);
        assert!(r2.is_catch_all());

        // round-trip 回字符串形态
        let raw = RawRule::from(r.clone());
        let back: Rule = raw.try_into().unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn rule_rejects_unknown_key() {
        let bad = "host = \"*\"\nport = \"*\"\negress = \"block\"\nfrobnicate = 1\n";
        assert!(toml::from_str::<Rule>(bad).is_err());
    }

    #[test]
    fn matching_is_host_and_port_conjunction() {
        let r = Rule::new(
            HostMatcher::parse("*.internal.example.com").unwrap(),
            PortMatcher::parse("443").unwrap(),
            EgressTarget::Auto,
        );
        assert!(r.matches(&ep("a.internal.example.com:443")));
        assert!(!r.matches(&ep("a.internal.example.com:80")));
        assert!(!r.matches(&ep("a.public.example.com:443")));
    }

    #[test]
    fn merge_order_local_before_shared() {
        // §9.4.3：本地整体排在共享之前，因此一条本地 block 能压住共享的 node:X。
        let local = vec![Rule::new(
            HostMatcher::parse("10.1.2.9").unwrap(),
            PortMatcher::Any,
            EgressTarget::Block,
        )];
        let shared = RuleSetAd {
            publisher: "10.0.0.9".parse().unwrap(),
            revision: 7,
            issued_at: 0,
            rules: vec![Rule::new(
                HostMatcher::parse("*").unwrap(),
                PortMatcher::Any,
                EgressTarget::Node("10.0.0.1".parse().unwrap()),
            )],
            hmac: None,
        };
        let t = RuleTable::build(&local, Some(&shared), true);
        assert_eq!(t.local_count, 1);
        assert_eq!(t.merged.len(), 2);
        assert_eq!(t.merged[0].egress, EgressTarget::Block);
        assert_eq!(t.shared_source, Some("10.0.0.9".parse().unwrap()));
        assert_eq!(t.shared_revision, 7);
        // 目标 10.1.2.9 命中的是本地那条（先匹配者胜）
        let e = ep("10.1.2.9:22");
        assert_eq!(t.merged.iter().find(|r| r.matches(&e)).unwrap().egress, EgressTarget::Block);
    }

    #[test]
    fn bypass_drops_all_rules() {
        let local = vec![Rule::new(HostMatcher::Any, PortMatcher::Any, EgressTarget::Block)];
        let t = RuleTable::build(&local, None, false);
        assert!(t.is_empty(), "rules_enabled = false 时整表退化为只剩网段兜底行");
        assert_eq!(t.local_count, 0);
    }

    #[test]
    fn covers_implements_subset_semantics() {
        use host_covers_case as hc;
        assert!(hc("*", "10.1.2.9"));
        assert!(hc("*.internal.example.com", "a.internal.example.com"));
        assert!(!hc("*.internal.example.com", "a.public.example.com"));
        assert!(hc("10.9.0.0/16", "10.9.1.2"));
        assert!(!hc("10.9.0.0/16", "10.10.1.2"));
        assert!(hc("10.9.0.0/16", "10.9.1.0/24"));
        assert!(!hc("10.9.1.0/24", "10.9.0.0/16"), "更窄的网段不能覆盖更宽的");
    }

    fn host_covers_case(a: &str, b: &str) -> bool {
        HostMatcher::parse(a).unwrap().covers(&HostMatcher::parse(b).unwrap())
    }

    #[test]
    fn port_covers_semantics() {
        assert!(PortMatcher::Any.covers(&PortMatcher::Exact(80)));
        assert!(PortMatcher::Range(8000, 9000).covers(&PortMatcher::Exact(8080)));
        assert!(!PortMatcher::Range(8000, 9000).covers(&PortMatcher::Exact(9001)));
        assert!(PortMatcher::Range(8000, 9000).covers(&PortMatcher::Range(8100, 8200)));
        assert!(!PortMatcher::Range(8000, 9000).covers(&PortMatcher::Range(7999, 8200)));
    }

    #[test]
    fn specificity_sort_puts_exact_first() {
        let rules = vec![
            Rule::new(HostMatcher::Any, PortMatcher::Exact(8080), EgressTarget::Block),
            Rule::new(HostMatcher::parse("10.9.0.0/16").unwrap(), PortMatcher::Any, EgressTarget::Block),
            Rule::new(
                HostMatcher::parse("10.1.2.9").unwrap(),
                PortMatcher::Exact(443),
                EgressTarget::Block,
            ),
            Rule::new(HostMatcher::parse("*.internal.example.com").unwrap(), PortMatcher::Any, EgressTarget::Block),
        ];
        let sorted = RuleTable::sorted_by_specificity(&rules);
        let keys: Vec<(u8, u8)> = sorted.iter().map(|r| r.specificity_key()).collect();
        assert_eq!(keys, vec![(0, 0), (1, 2), (2, 2), (3, 0)]);
    }
}
