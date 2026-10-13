// Rust 侧的类型契约 —— 与 DESIGN.md §6.7 的「IPC 返回体 / 事件载荷」一一对应。
//
// 权威定义在 crates/hiveproxy-core/src/view.rs、events.rs、rules.rs、config.rs。
// 改了那边就要改这里：这份文件是**手写的镜像**，不是自动生成的。
//
// 两个容易记错的点：
// 1) `Rule` 走 IPC 时是它的字符串形态（Rust 侧的 `RawRule`）：host/port/egress
//    都是字符串（`"10.9.0.0/16"` / `"8000-9000"` / `"alias:gpu-01"`），
//    不是结构体 —— 所以编辑表格可以直接绑字符串，不需要在前端做解析。
// 2) Rust 的 `Option<T>` 序列化成 `T | null`（没有 skip_serializing_if 的字段一定出现），
//    唯独 `NodeCfg.zone` / `overlay_addr` / `alias` / `AdminCfg.tcp` 是
//    `skip_serializing_if = "Option::is_none"`，缺字段与 null 等价。

/* ────────────────────────────── 基础 ────────────────────────────── */

/** 节点身份 = 本机地址，JSON 里永远是字符串（§5.8）。 */
export type NodeId = string;

/* ────────────────────────────── 拓扑 ────────────────────────────── */

/** 拓扑图上的一行。 */
export interface NodeView {
  peer: NodeId;
  alias: string | null;
  is_self: boolean;
  subnets: string[];
  listen: string[];
  accepts_egress: boolean;
  last_seen_ms: number;
  incarnation: number;
  reachable: boolean;
  hops: number | null;
  cost: number | null;
  direct: boolean;
}

/** 本机的直连链路。 */
export interface EdgeView {
  from: NodeId;
  to: NodeId;
  cost: number;
  /** `lan` = 同网段，其余为跨网段。 */
  carrier: string;
  /** `up` / 其它。 */
  health: string;
  /** `local` = 本机拨出。 */
  establisher: string;
  rtt_ms: number;
  direct: boolean;
}

/** 全网声明的邻接关系，DAG 按它画。 */
export interface GraphEdge {
  from: NodeId;
  to: NodeId;
  carrier: string;
  rtt_ms: number;
  local: boolean;
}

export interface TopologySnapshot {
  nodes: NodeView[];
  edges: EdgeView[];
  graph: GraphEdge[];
  version: number;
}

/** 候选集来源：`"explicit"` 或 `{ subnet: "10.9.0.0/16" }`。 */
export type GroupSource = "explicit" | { subnet: string };

export interface GroupView {
  name: string;
  source: GroupSource;
  members: NodeId[];
}

/* ────────────────────────────── 规则 ────────────────────────────── */

/** 规则走 IPC 时的字符串形态（Rust 的 `RawRule`）。 */
export interface Rule {
  /** 空串 = 无备注（Rust 侧 `Option<String>` 的字符串形态）。 */
  label: string;
  /** `*` | `10.1.2.9` | `*.internal.example.com` | `10.9.0.0/16` */
  host: string;
  /** `*` | `443` | `8000-9000` */
  port: string;
  /** `auto` | `direct` | `node:<ip>` | `<ip>` | `alias:<名>` | `group:<名>` | `group:subnet:<cidr>` | `block` */
  egress: string;
  /** `fallback` | `fail` */
  on_unreachable: string;
  enabled: boolean;
}

/**
 * 一条新增规则的默认值。
 *
 * `host = "*."` 是**故意的**：它解释成"域名后缀、但还没填后缀"，因此引擎会回一句
 * "`*.` 后必须有域名后缀" —— 于是新行一出现就是"待填"，而**不会**被自动保存成一条
 * 兜住所有目标的 `*:*` 规则（规则页是边改边存的，见 UI.md §3.5）。
 * 想改成"任意"随时可以在条件类型里选，但那时是你显式选的。
 */
export const NEW_RULE: Rule = {
  label: "",
  host: "*.",
  port: "*",
  egress: "auto",
  on_unreachable: "fallback",
  enabled: true,
};

export interface RuleSetAd {
  publisher: NodeId;
  revision: number;
  issued_at: number;
  rules: Rule[];
  /** `security.rule_token` 的标签（16 字节），未验签时整份被忽略。 */
  hmac: number[] | null;
}

/** 合并后的规则表：本地在前，共享在后（§9.4.3）。 */
export interface RuleTable {
  merged: Rule[];
  /** `merged[..local_count]` 是本地规则。 */
  local_count: number;
  shared_source: NodeId | null;
  shared_revision: number;
  rules_enabled: boolean;
}

export interface RulesView {
  table: RuleTable;
  local: Rule[];
  shared: RuleSetAd | null;
  shared_source_alias: string | null;
}

export interface RuleChange {
  target: string;
  from: string;
  to: string;
}

export interface RulePreview {
  changes: RuleChange[];
  /** 永远匹配不到的条目下标（被前面的规则完全遮蔽）。 */
  never_matched: number[];
  /** 会把流量变成黑洞的条目下标（`block` 或指向不可达出口）。 */
  blackholes: number[];
  warnings: string[];
}

export interface RuleStat {
  index: number;
  label: string | null;
  rule: string;
  hits: number;
  last_egress: NodeId | null;
  last_rejected_at: number | null;
}

export interface PublishResult {
  revision: number;
  rules: number;
  published_at: number;
}

export interface SharedRulesStatus {
  source: NodeId | null;
  source_alias: string | null;
  revision: number;
  issued_at: number;
  rules: number;
  accepted: boolean;
}

/* ────────────────────────────── 统计 / 状态 ────────────────────────────── */

export interface StatsSnapshot {
  links: number;
  active_streams: number;
  bytes_relayed_in: number;
  bytes_relayed_out: number;
  frames_relayed: number;
  frames_dropped: number;
  streams_dropped: number;
  route_rebuilds: number;
  handshakes_ok: number;
  handshakes_failed: number;
  unreachable_received: number;
  gossip_sent: number;
  gossip_received: number;
  pulls_sent: number;
  dial_attempts: number;
  dial_failures: number;
}

/** 目标主机：IP 或域名。域名必须保持原样 —— 解析发生在**出口节点**（§9.4.2）。 */
export type Host = { Ip: string } | { Name: string };

export interface Endpoint {
  host: Host;
  port: number;
}

/** 出口是怎么定下来的（Rust 侧 `MatchSource`，§9.4.4）。 */
export type ProbeVia = "rule" | "subnet" | "default";

export interface StreamProbe {
  target: Endpoint;
  egress: NodeId;
  direct: boolean;
  via: ProbeVia;
  /** `via === "rule"` 时才有意义（0 基）。 */
  matched_rule: number | null;
  rtt_ms: number;
}

/** 一个候选出口（`probe_exits`）。纯路由计算，不含"真的通不通"。 */
export interface ExitCandidate {
  node: NodeId;
  alias: string | null;
  /** 本机（选中它 = 直接 connect，不进 overlay）。 */
  is_self: boolean;
  cost: number | null;
  hops: number | null;
  accepts_egress: boolean;
  subnets: string[];
  /** 目标 IP 是否落在它声明的网段里（域名目标恒为 false）。 */
  declares_target: boolean;
  selected: boolean;
  /** 不能选它的原因；`null` = 可用。 */
  unusable: string | null;
}

/** 一次实测（`probe_dial`）的结果：真的建了一次流，然后立刻关掉。 */
export interface DialResult {
  target: string;
  via: NodeId;
  direct: boolean;
  ok: boolean;
  rtt_ms: number;
  detail: string;
}

/** 一条规则的逐行校验结果（`check_rules`）。 */
export interface RuleIssue {
  index: number;
  field: "host" | "port" | "egress" | "on_unreachable" | string;
  message: string;
}

export interface NodeStatus {
  node_id: NodeId;
  alias: string | null;
  listen: string[];
  /** 本机**能直达**的网段，与是否对外声明无关。 */
  subnets: string[];
  /** 被排除、因而不在 `subnets` 里的地址（虚拟网卡 / `share.subnet_deny`），界面要能解释。 */
  excluded_subnets: string[];
  /** 是否把上面的网段**广播**给全网（`share.auto_share_subnets`）。 */
  share_subnets: boolean;
  accepts_egress: boolean;
  proxy_bind: string;
  topology_version: number;
  rule_count: number;
  shared_rule_count: number;
  rules_enabled: boolean;
  /** 最后一顺位出口；`null` = 没设（§9.4.4）。 */
  default_egress: string | null;
  uptime_secs: number;
  version: string;
}

/* ────────────────────────────── 分区（§9.3 情形二）────────────────────────────── */

export interface ZoneIslandView {
  zone: number;
  label: string;
  /** 建议填写的地址形式，如 `z7+10.1.2.5:3306`。 */
  suggestion: string;
  members: NodeId[];
  reachable: number;
}

export interface ZoneView2 {
  net: string;
  islands: ZoneIslandView[];
}

/* ────────────────────────────── 服务（Tauri 壳自己定义）────────────────────────────── */

export interface ServiceState {
  running: boolean;
  autostart: boolean;
  node_id: string;
  proxy_bind: string;
  /** 管理接口端点（Unix socket 或回环 TCP），供 `hiveproxy-cli` 用（§20）。 */
  admin_endpoint: string | null;
  data_dir: string;
  /** 上次启动失败的原因 —— 有它就别让用户面对一个空界面。 */
  last_error: string | null;
}

export interface StreamRow {
  peer: NodeId;
  stream_id: number;
  target: string;
}

/* ────────────────────────────── 配置（§10）────────────────────────────── */

export interface PeerEntry {
  address: string;
  alias: string;
}

export interface GroupCfg {
  name: string;
  members: string[];
}

export interface CostCfg {
  lan: number;
  wan: number;
  per_hop: number;
}

export interface NodeCfg {
  /** 留空 = 自动取主网卡地址。 */
  overlay_addr?: string | null;
  alias?: string | null;
  /** 手动冻结区域号，不写 = 自动派生（§9.3）。 */
  zone?: number | null;
}

export interface ListenCfg {
  bind: string;
  ports: number[];
  max_links: number;
  advertise: boolean;
}

export interface PeersCfg {
  seeds: string[];
  probe_ports: number[];
  accept_listen_adverts: boolean;
  /** 别名表，供 `egress = "alias:<名>"` 解析。 */
  entry: PeerEntry[];
}

export interface DiscoveryCfg {
  lan_udp: boolean;
  udp_port: number;
  mdns: boolean;
  dial_interval_ms: number;
  backoff_max_ms: number;
  max_dial_candidates: number;
}

export interface ShareCfg {
  auto_share_subnets: boolean;
  share_ports_only: number[];
  /** 不当成"本机网段"的地址范围（默认含 `198.18.0.0/15`：代理工具 TUN 的假地址池）。 */
  subnet_deny: string[];
  /** 不当成"本机网段"的网卡名模式（结尾 `*` = 前缀匹配）。 */
  subnet_deny_ifaces: string[];
}

export interface EgressCfg {
  allow_egress: boolean;
  egress_ack_timeout_ms: number;
  egress_cache_ttl_ms: number;
}

export interface RouteCfg {
  ttl_default: number;
  gossip_interval_ms: number;
  gossip_flood_ttl: number;
  route_switch_timeout_ms: number;
  cost: CostCfg;
  rules_enabled: boolean;
  rules: Rule[];
  groups: GroupCfg[];
  accept_shared_rules: boolean;
  publish_enabled: boolean;
  /** 规则与网段都没命中时的**最后一顺位**出口（§9.4.4）；缺字段与 `null` 等价。 */
  default_egress?: string | null;
}

export interface ProxyCfg {
  bind: string;
  allow_remote: boolean;
}

export type E2eMode = "off" | "required";

export interface SecurityCfg {
  join_token: string;
  rule_token: string;
  e2e: E2eMode;
}

export interface ServiceCfg {
  autostart: boolean;
}

export interface AdminCfg {
  enabled: boolean;
  /** Unix socket 路径；留空 = `<数据目录>/hiveproxy.sock`。 */
  socket: string;
  /** 回环 TCP（Windows 用），如 `127.0.0.1:10800`。 */
  tcp?: string | null;
}

export interface LogCfg {
  level: string;
}

export interface Config {
  node: NodeCfg;
  listen: ListenCfg;
  peers: PeersCfg;
  discovery: DiscoveryCfg;
  share: ShareCfg;
  egress: EgressCfg;
  route: RouteCfg;
  proxy: ProxyCfg;
  security: SecurityCfg;
  service: ServiceCfg;
  admin: AdminCfg;
  log: LogCfg;
}

/* ────────────────────────────── 事件（DESIGN.md §6.7）────────────────────────────── */

export interface LogEvent {
  ts_ms: number;
  level: string;
  module: string;
  msg: string;
}

export type HiveEvent =
  | ({ event: "topology" } & TopologySnapshot)
  | ({ event: "rules" } & RulesView)
  | ({ event: "stats" } & StatsSnapshot)
  | ({ event: "log" } & LogEvent)
  | { event: "peer_up"; peer: NodeId; establisher: string; carrier: string }
  | { event: "peer_down"; peer: NodeId; reason: string }
  | {
      event: "stream_opened";
      peer: NodeId;
      stream_id: number;
      target: string;
      egress: NodeId;
      direct: boolean;
      matched_rule: number | null;
    }
  | {
      event: "stream_closed";
      peer: NodeId;
      stream_id: number;
      bytes_in: number;
      bytes_out: number;
      reason: string;
    }
  | { event: "shared_rules_rejected"; source: NodeId; reason: string }
  | { event: "identity_conflict"; claimed_edges: number; hint: string };

/** Tauri 侧统一用一个事件名 `hive`，载荷里用 `event` 字段区分（src-tauri/src/lib.rs）。 */
export const HIVE_EVENT = "hive";
