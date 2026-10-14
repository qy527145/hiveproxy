// 配置表单的字段表（DESIGN.md §10 的 TOML 逐项对应）。
//
// 为什么用"表"而不是手写一堆 JSX：配置项有 40 多个，散在 JSX 里会变成
// 复制粘贴的海洋，而且加一项就得改三处。这里一项一行，渲染与读取各走一遍表。
//
// `nullable` 的项（overlay_addr / alias / zone / admin.tcp）留空时要写成 `null`
// 而不是空串 —— Rust 侧是 `Option<T>`，空串会解析失败（`deny_unknown_fields`
// 的取向是"宁可报错也不静默"）。

export type FieldType = "text" | "bool" | "number" | "select" | "numlist" | "strlist";

export interface ConfigField {
  /** 配置里的路径，如 `route.cost.lan`。 */
  path: string;
  label: string;
  type: FieldType;
  /** `select` 的选项。 */
  options?: string[];
  hint?: string;
  /** 留空 → `null`（对应 Rust 的 `Option<T>`）。 */
  nullable?: boolean;
  /** 输入框的占位提示。 */
  placeholder?: string;
}

export interface ConfigSection {
  title: string;
  fields: ConfigField[];
}

/* ────────────────────────────── 生效档位（DESIGN.md §21 / WEBUI.md §5）────────────────────────────── */

/**
 * 配置改完**怎么才算生效**。三档（外加一个"改不了、得重启进程"的部署档，那种字段根本不进界面）：
 *
 * - `hot`     热生效：点保存就落定，界面不抖、连接不断。**默认档**，所以不列在表里。
 * - `rebind`  引擎内重绑：取消子令牌 → 重新 bind → 重起 accept loop。在途连接不受影响。
 * - `rebuild` 重建引擎：停引擎 → 原地重建。会断开全部链路与在途流，约 1 秒。
 *
 * ★ 这张表是"标 ★ 的改动需要重启吗 / 具体哪一档"的**唯一来源**：文案与 ★ 都由它推出来，
 * 不再散在字段的 hint 和字段名里各写一遍（那才会漂移）。
 */
export type EffectTier = "hot" | "rebind" | "rebuild";

/** 非热生效档位的提示语。`hot` 空串 = 不提示。 */
export const EFFECT_HINTS: Record<EffectTier, string> = {
  hot: "",
  rebind: "端口将重新绑定，在途连接不受影响",
  rebuild: "将重建引擎，断开现有连接",
};

/** 档位轻重：hot < rebind < rebuild。取一段里"最重"的那档给标题用。 */
const TIER_RANK: Record<EffectTier, number> = { hot: 0, rebind: 1, rebuild: 2 };

/**
 * 字段路径 → 生效档位。**只列非热生效的**（没列到的一律热生效）。
 * 与 DESIGN.md §21 / WEBUI.md §5.1 的三档表逐项对应；改那边就要改这里。
 */
export const FIELD_EFFECT: Record<string, EffectTier> = {
  // ② 引擎内重绑。**只有"要换监听 socket"的那两个** ——
  // `listen.max_links` 与 `proxy.allow_remote` 不在此列：它们是每个连接现读配置的，
  // 改完即生效，重绑一次纯属白断连接（引擎侧同一份判断在 config::classify_change）。
  "listen.bind": "rebind",
  "listen.ports": "rebind",
  "proxy.bind": "rebind",
  // ③ 重建引擎（改地址 / zone 等于换一台机器，语义上就不该热更）
  "node.overlay_addr": "rebuild",
  "node.alias": "rebuild",
  "node.zone": "rebuild",
  "share.auto_share_subnets": "rebuild",
  "share.subnet_deny": "rebuild",
  "share.subnet_deny_ifaces": "rebuild",
  "admin.enabled": "rebuild",
  "admin.socket": "rebuild",
  "admin.tcp": "rebuild",
};

/** 某个字段的生效档位；没列的按热生效。 */
export function effectTier(path: string): EffectTier {
  return FIELD_EFFECT[path] ?? "hot";
}

/** 一段配置里"最重"的生效档位 —— 用于给 section 标题配一句说明。 */
export function sectionEffect(fields: ConfigField[]): EffectTier {
  let worst: EffectTier = "hot";
  for (const f of fields) {
    const t = effectTier(f.path);
    if (TIER_RANK[t] > TIER_RANK[worst]) worst = t;
  }
  return worst;
}

export const CONFIG_SECTIONS: ConfigSection[] = [
  {
    title: "身份",
    fields: [
      {
        path: "node.overlay_addr",
        label: "overlay_addr",
        type: "text",
        nullable: true,
        hint: "留空 = 自动取主网卡地址。只有在两片网段地址重叠时才需要钉一个全网唯一地址（通常 fd00::/8）",
      },
      {
        path: "node.alias",
        label: "alias",
        type: "text",
        nullable: true,
        hint: "可选可读名，用于规则里的 alias: 出口与拓扑显示",
      },
      {
        path: "node.zone",
        label: "zone",
        type: "number",
        nullable: true,
        hint: "留空 = 自动派生区域号。手动冻结只在网段真冲突（§9.3 情形二）时才需要",
      },
    ],
  },
  {
    title: "监听",
    fields: [
      {
        path: "listen.ports",
        label: "ports",
        type: "numlist",
        placeholder: "用逗号分隔，如 5678, 5679",
        hint: "★ 监听端口 = IT 授权给这台机器的入向端口。别人就是拨这个端口找到你；它必须与对端 seeds 里写的端口一致",
      },
      {
        path: "listen.bind",
        label: "bind",
        type: "text",
        hint: "监听的网卡地址（不含端口）",
      },
      { path: "listen.max_links", label: "max_links", type: "number", hint: "同时维持的最大直连链路数" },
      {
        path: "listen.advertise",
        label: "advertise",
        type: "bool",
        hint: "把自己的监听端点广播给全网，供他人自动纳入拨号候选",
      },
    ],
  },
  {
    title: "种子与发现",
    fields: [
      {
        path: "peers.seeds",
        label: "seeds",
        type: "strlist",
        placeholder: "用逗号分隔，如 10.1.2.3:20000",
        hint: "跨网段的第一条链路只能靠它点火：写「你能拨通的一台机器」。接通后监听端点广播会把其余候选自动补齐，所以每台 0~1 条即可",
      },
      {
        path: "peers.probe_ports",
        label: "probe_ports",
        type: "numlist",
        hint: "仅当种子没写端口时按序试探的候选端口",
      },
      {
        path: "peers.accept_listen_adverts",
        label: "accept_listen_adverts",
        type: "bool",
        hint: "采信别人广播的监听端点作为拨号候选",
      },
      { path: "discovery.lan_udp", label: "lan_udp", type: "bool", hint: "同网段 UDP 广播自动发现" },
      { path: "discovery.udp_port", label: "udp_port", type: "number" },
      { path: "discovery.mdns", label: "mdns", type: "bool", hint: "mDNS 发现（当前版本未启用）" },
      { path: "discovery.dial_interval_ms", label: "dial_interval_ms", type: "number" },
      { path: "discovery.backoff_max_ms", label: "backoff_max_ms", type: "number" },
      { path: "discovery.max_dial_candidates", label: "max_dial_candidates", type: "number" },
    ],
  },
  {
    title: "共享与出口",
    fields: [
      {
        path: "share.auto_share_subnets",
        label: "auto_share_subnets",
        type: "bool",
        hint: "默认把自己的整个子网贡献给全网（零配置合岛）。敏感机器置 false：只消费不贡献",
      },
      {
        path: "share.share_ports_only",
        label: "share_ports_only",
        type: "numlist",
        hint: "非空时只共享这些端口；留空 = 不限端口",
      },
      {
        path: "share.subnet_deny",
        label: "subnet_deny",
        type: "strlist",
        placeholder: "用逗号分隔，默认 198.18.0.0/15",
        hint: "不当成「本机网段」的地址范围。默认排除 198.18.0.0/15（RFC 2544 基准段）—— Clash / sing-box 这类代理工具的 TUN 假地址池就落在那儿，它不是真实网络",
      },
      {
        path: "share.subnet_deny_ifaces",
        label: "subnet_deny_ifaces",
        type: "strlist",
        placeholder: "用逗号分隔，如 tun*,utun*,wg*",
        hint: "不当成「本机网段」的网卡名（结尾 * = 前缀匹配）。如果你的真实内网访问本来就依赖某条隧道（macOS 上 WireGuard 也叫 utun），把对应模式删掉即可 —— 这里排除的是「我替大家去」，不是「我能不能连」",
      },
      {
        path: "egress.allow_egress",
        label: "allow_egress",
        type: "bool",
        hint: "false = 不做出口：别人的流量不会被引到这台机器上",
      },
      { path: "egress.egress_ack_timeout_ms", label: "egress_ack_timeout_ms", type: "number" },
      { path: "egress.egress_cache_ttl_ms", label: "egress_cache_ttl_ms", type: "number" },
    ],
  },
  {
    title: "路由",
    fields: [
      {
        path: "route.rules_enabled",
        label: "rules_enabled",
        type: "bool",
        hint: "false = 全局旁路：忽略全部规则，只跑网段自动匹配（排障用）。规则页左上角有同样的一键开关",
      },
      {
        path: "route.accept_shared_rules",
        label: "accept_shared_rules",
        type: "bool",
        hint: "是否采信全网发布的共享规则集",
      },
      {
        path: "route.publish_enabled",
        label: "publish_enabled",
        type: "bool",
        hint: "是否允许本节点对外发布规则集",
      },
      { path: "route.ttl_default", label: "ttl_default", type: "number", hint: "帧头 TTL，成环时的唯一兜底" },
      { path: "route.gossip_interval_ms", label: "gossip_interval_ms", type: "number" },
      {
        path: "route.gossip_flood_ttl",
        label: "gossip_flood_ttl",
        type: "number",
        hint: "变化驱动 flood 的扩散半径。设为 0 会让拓扑只传播 1 跳，四节点链以上无法路由",
      },
      {
        path: "route.route_switch_timeout_ms",
        label: "route_switch_timeout_ms",
        type: "number",
        hint: "路径切换的等待上限（§5.5）",
      },
      { path: "route.cost.lan", label: "cost.lan", type: "number" },
      { path: "route.cost.wan", label: "cost.wan", type: "number" },
      { path: "route.cost.per_hop", label: "cost.per_hop", type: "number" },
    ],
  },
  {
    title: "本地代理",
    fields: [
      {
        path: "proxy.bind",
        label: "bind",
        type: "text",
        hint: "本机应用要连的本地代理地址。同一个端口同时支持 SOCKS5 与 HTTP 代理，默认 127.0.0.1:1080（首页有快捷入口）",
      },
      {
        path: "proxy.allow_remote",
        label: "allow_remote",
        type: "bool",
        hint: "是否允许非回环地址使用本地代理（SOCKS5 与 HTTP 会一起暴露给同网段）",
      },
    ],
  },
  {
    title: "安全",
    fields: [
      {
        path: "security.join_token",
        label: "join_token",
        type: "text",
        hint: "空 = 不鉴权。填入即启用握手 HMAC 校验：两侧必须一致，否则握不上手",
      },
      {
        path: "security.rule_token",
        label: "rule_token",
        type: "text",
        hint: "空 = 不校验共享规则集签名",
      },
      {
        path: "security.e2e",
        label: "e2e",
        type: "select",
        options: ["off", "required"],
        hint: "v2 端到端加密（当前版本未实现，填 required 不生效）",
      },
    ],
  },
  {
    title: "服务与命令行",
    fields: [
      {
        path: "service.autostart",
        label: "autostart",
        type: "bool",
        hint: "GUI 启动时是否自动开始组网。命令行版忽略此项（它总是启动）",
      },
      {
        path: "admin.enabled",
        label: "enabled",
        type: "bool",
        hint: "本地管理接口。GUI 不需要它；无界面服务器靠它执行 hiveproxy-cli",
      },
      {
        path: "admin.socket",
        label: "socket",
        type: "text",
        hint: "Unix socket 路径；留空 = <数据目录>/hiveproxy.sock",
      },
      {
        path: "admin.tcp",
        label: "tcp",
        type: "text",
        nullable: true,
        hint: "或者监听回环 TCP（Windows 用），如 127.0.0.1:10800",
      },
    ],
  },
  {
    title: "日志",
    fields: [
      { path: "log.level", label: "level", type: "select", options: ["trace", "debug", "info", "warn", "error"] },
    ],
  },
];

/** 按 `a.b.c` 路径取嵌套值。 */
export function getPath(obj: unknown, path: string): unknown {
  return path
    .split(".")
    .reduce<unknown>(
      (acc, key) => (acc == null ? undefined : (acc as Record<string, unknown>)[key]),
      obj,
    );
}

/** 按 `a.b.c` 路径写嵌套值（中间层缺失就补空对象）。**原地**修改。 */
export function setPath(obj: unknown, path: string, value: unknown): void {
  const keys = path.split(".");
  const last = keys.pop();
  if (last === undefined) return;
  let cur = obj as Record<string, unknown>;
  for (const key of keys) {
    const next = cur[key];
    if (next == null || typeof next !== "object") cur[key] = {};
    cur = cur[key] as Record<string, unknown>;
  }
  cur[last] = value;
}
