// 引擎状态在前端这一侧的**唯一**落点：所有 store、所有动作、事件桥、轮询。
//
// 结构上刻意分成"别人拉不动的小块"：服务状态、拓扑、统计、规则、日志……
// 各自一个 store。引擎的事件是每秒 / 每 5 秒一条的实时流，如果塞进一个
// Context，每次 stats 心跳都会把整棵树重渲染一遍。
//
// 两条从老前端继承下来的硬约束（DESIGN.md §6.7、§17 风险 11）：
// 1) **任何一条命令失败都不能白屏** —— 所有拉取走 `call()` 逐项容错，
//    服务没启动时配置页照样可用；
// 2) **前端报错进引擎日志** —— 见 lib/report.ts。

import { call, errText, onHiveEvent, type CallResult } from "../lib/ipc";
import { onlyLocal, report } from "../lib/report";
import { NEW_RULE } from "../lib/types";
import type {
  Config,
  DialResult,
  ExitCandidate,
  GroupView,
  NodeStatus,
  Rule,
  RuleIssue,
  RulePreview,
  RuleStat,
  RulesView,
  ServiceState,
  SharedRulesStatus,
  StatsSnapshot,
  StreamProbe,
  StreamRow,
  TopologySnapshot,
  ZoneView2,
} from "../lib/types";
import { createStore, shallowEqual } from "./store";

/* ────────────────────────────── 初值 ────────────────────────────── */

export const EMPTY_TOPOLOGY: TopologySnapshot = { nodes: [], edges: [], graph: [], version: 0 };

const EMPTY_RULES_VIEW: RulesView = {
  table: { merged: [], local_count: 0, shared_source: null, shared_revision: 0, rules_enabled: true },
  local: [],
  shared: null,
  shared_source_alias: null,
};

const SERVICE_UNKNOWN: ServiceState = {
  running: false,
  autostart: true,
  node_id: "—",
  proxy_bind: "—",
  admin_endpoint: null,
  data_dir: "",
  last_error: null,
};

/**
 * 这些载荷都是"纯数据小对象"（几十到几千字节），直接按 JSON 比内容：
 * 轮询每 2 秒回来一份**新对象**，浅比较一定会认为"变了"，于是每秒都白渲染一轮。
 */
function jsonEqual<T>(a: T, b: T): boolean {
  if (a === b) return true;
  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
  }
}

/* ────────────────────────────── store ────────────────────────────── */

export const serviceStore = createStore<ServiceState>(SERVICE_UNKNOWN, jsonEqual);
export const statusStore = createStore<NodeStatus | null>(null, jsonEqual);
export const statsStore = createStore<StatsSnapshot | null>(null, jsonEqual);
export const topologyStore = createStore<TopologySnapshot>(EMPTY_TOPOLOGY, jsonEqual);
export const streamsStore = createStore<StreamRow[]>([], jsonEqual);
export const zonesStore = createStore<ZoneView2[]>([], jsonEqual);
export const groupsStore = createStore<GroupView[]>([], jsonEqual);
export const rulesViewStore = createStore<RulesView>(EMPTY_RULES_VIEW, jsonEqual);
export const ruleStatsStore = createStore<RuleStat[]>([], jsonEqual);
export const sharedStore = createStore<SharedRulesStatus | null>(null, jsonEqual);
export const configStore = createStore<Config | null>(null, jsonEqual);

/** 规则草稿：编排中（可能还没保存）的本地规则表。 */
export interface RuleDraft {
  rules: Rule[];
  dirty: boolean;
}

export const ruleDraftStore = createStore<RuleDraft>(
  { rules: [], dirty: false },
  (a, b) => a.dirty === b.dirty && a.rules === b.rules,
);

/* ────────────────────────────── 日志 ────────────────────────────── */

export interface LogLine {
  level: string;
  module: string;
  msg: string;
  t: Date;
}

const LOG_CAP = 2000;

export const logStore = createStore<LogLine[]>([], (a, b) => a === b);

export function pushLog(level: string, module: string, msg: string): void {
  logStore.patch((lines) => {
    const next = lines.length >= LOG_CAP ? lines.slice(lines.length - LOG_CAP + 1) : lines.slice();
    next.push({ level, module, msg, t: new Date() });
    return next;
  });
}

export function clearLogs(): void {
  logStore.set([]);
}

/* ────────────────────────────── toast ────────────────────────────── */

export type ToastKind = "info" | "warn" | "err" | "ok";

export interface Toast {
  id: number;
  msg: string;
  kind: ToastKind;
}

export const toastStore = createStore<Toast[]>([], (a, b) => a === b);

let toastSeq = 0;

export function toast(msg: string, kind: ToastKind = "info", ms = 4200): void {
  const id = ++toastSeq;
  toastStore.patch((list) => [...list, { id, msg, kind }]);
  window.setTimeout(() => dismissToast(id), ms);
}

export function dismissToast(id: number): void {
  toastStore.patch((list) => list.filter((t) => t.id !== id));
}

/* ────────────────────────────── 拉取 ────────────────────────────── */

export async function refreshService(): Promise<void> {
  const r = await call<ServiceState>("service_state");
  if (r.ok) serviceStore.set(r.v);
}

/** 完整刷新：服务状态 + 配置 + （在跑的话）全部运行期视图。 */
export async function refreshAll(): Promise<void> {
  await refreshService();
  await loadConfig();

  if (!serviceStore.get().running) {
    // 服务没跑：运行期视图清空，但配置页与规则表仍可用（规则退回到磁盘上的那份）
    statusStore.set(null);
    statsStore.set(null);
    topologyStore.set(EMPTY_TOPOLOGY);
    streamsStore.set([]);
    zonesStore.set([]);
    groupsStore.set([]);
    ruleStatsStore.set([]);
    rulesViewStore.set(EMPTY_RULES_VIEW);
    sharedStore.set(null);
    syncDraftFrom(configStore.get()?.route.rules ?? []);
    return;
  }

  const [status, topology, stats, rulesView, ruleStats, shared, streams, zones, groups] =
    await Promise.all([
      call<NodeStatus>("status"),
      call<TopologySnapshot>("topology"),
      call<StatsSnapshot>("stats"),
      call<RulesView>("get_rules"),
      call<RuleStat[]>("rule_stats"),
      call<SharedRulesStatus>("shared_rules_status"),
      call<StreamRow[]>("active_streams"),
      call<ZoneView2[]>("zones"),
      call<GroupView[]>("groups"),
    ]);

  const failed: string[] = [];
  if (status.ok) statusStore.set(status.v);
  else failed.push(`status: ${status.e}`);
  if (topology.ok) topologyStore.set(topology.v);
  else failed.push(`topology: ${topology.e}`);
  if (stats.ok) statsStore.set(stats.v);
  else failed.push(`stats: ${stats.e}`);
  if (rulesView.ok) {
    rulesViewStore.set(rulesView.v);
    syncDraftFrom(rulesView.v.local ?? []);
  } else failed.push(`rules: ${rulesView.e}`);
  if (ruleStats.ok) ruleStatsStore.set(ruleStats.v);
  if (shared.ok) sharedStore.set(shared.v);
  if (streams.ok) streamsStore.set(streams.v);
  if (zones.ok) zonesStore.set(zones.v);
  if (groups.ok) groupsStore.set(groups.v);

  if (failed.length) onlyLocal("warn", "ui", `部分数据拉取失败：${failed.join("；")}`);
}

/** 轻量刷新：只更新会跳动的运行期数据（2 秒一次）。 */
export async function refreshLight(): Promise<void> {
  if (!serviceStore.get().running) return;
  const [status, topology, stats, ruleStats, streams] = await Promise.all([
    call<NodeStatus>("status"),
    call<TopologySnapshot>("topology"),
    call<StatsSnapshot>("stats"),
    call<RuleStat[]>("rule_stats"),
    call<StreamRow[]>("active_streams"),
  ]);
  if (status.ok) statusStore.set(status.v);
  if (topology.ok) topologyStore.set(topology.v);
  if (stats.ok) statsStore.set(stats.v);
  if (ruleStats.ok) ruleStatsStore.set(ruleStats.v);
  if (streams.ok) streamsStore.set(streams.v);
}

/* ────────────────────────────── 服务开关 ────────────────────────────── */

export async function togglePower(): Promise<void> {
  const running = serviceStore.get().running;
  const r = running
    ? await call<ServiceState>("service_stop")
    : await call<ServiceState>("service_start");
  if (!r.ok) toast(`操作失败：${r.e}`, "err", 9000);
  else toast(running ? "服务已停止" : "服务已启动", "ok");
  await refreshService();
  await refreshAll();
}

/* ────────────────────────────── 种子 ────────────────────────────── */

export async function addSeed(addr: string): Promise<boolean> {
  const r = await call<void>("add_seed", { addr });
  if (!r.ok) {
    toast(`添加失败：${r.e}`, "err", 8000);
    return false;
  }
  toast("已添加种子", "ok");
  await refreshAll();
  return true;
}

export async function removeSeed(addr: string): Promise<void> {
  const r = await call<void>("remove_seed", { addr });
  if (r.ok) await refreshAll();
  else toast(r.e, "err");
}

/* ────────────────────────────── 流 / 探测 ────────────────────────────── */

export function probeTarget(target: string): Promise<CallResult<StreamProbe>> {
  return call<StreamProbe>("probe_target", { target });
}

/** 候选出口清单（§18 第 31 条）：纯路由计算，不建流。 */
export function probeExits(target: string): Promise<CallResult<ExitCandidate[]>> {
  return call<ExitCandidate[]>("probe_exits", { target });
}

/** 实测：让某个出口真的连一次目标再关掉。**会产生一次真实连接**。 */
export function probeDial(target: string, via: string): Promise<CallResult<DialResult>> {
  return call<DialResult>("probe_dial", { target, via });
}

/** 逐行校验规则草稿 —— 行内红字的来源（引擎解析，前端不重复实现一遍语法）。 */
export function checkRules(rules: Rule[]): Promise<CallResult<RuleIssue[]>> {
  return call<RuleIssue[]>("check_rules", { rules });
}

export function closeStream(peer: string, streamId: number): Promise<CallResult<void>> {
  return call<void>("close_stream", { peer, streamId });
}

export function pingPeer(peer: string): Promise<CallResult<number>> {
  return call<number>("ping_peer", { peer });
}

/* ────────────────────────────── 规则草稿 ────────────────────────────── */

function ruleEquals(a: Rule, b: Rule): boolean {
  return (
    a.host === b.host &&
    a.port === b.port &&
    a.egress === b.egress &&
    a.on_unreachable === b.on_unreachable &&
    a.label === b.label &&
    a.enabled === b.enabled
  );
}

function rulesEqual(a: Rule[], b: Rule[]): boolean {
  return a.length === b.length && a.every((r, i) => ruleEquals(r, b[i]));
}

function setDraft(rules: Rule[], dirty: boolean): void {
  ruleDraftStore.set({ rules, dirty });
}

/** 从权威数据同步草稿 —— 用户正在编辑（dirty）时绝不动它。 */
export function syncDraftFrom(local: Rule[]): void {
  const cur = ruleDraftStore.get();
  if (cur.dirty) return;
  if (rulesEqual(cur.rules, local)) return;
  setDraft(local.map((r) => ({ ...r })), false);
}

export function draftRules(): Rule[] {
  return ruleDraftStore.get().rules;
}

export function addRule(): void {
  setDraft([...draftRules(), { ...NEW_RULE }], true);
}

/** 追加一条**填好条件与出口**的草稿（首页"生成规则"用，UI.md §2.3）。 */
export function addRuleWith(rule: Rule): void {
  setDraft([...draftRules(), { ...rule }], true);
}

export function updateRuleField(index: number, field: keyof Rule, value: string | boolean): void {
  setDraft(
    draftRules().map((r, i) => (i === index ? ({ ...r, [field]: value } as Rule) : r)),
    true,
  );
}

export function moveRule(index: number, dir: -1 | 1): void {
  const rules = draftRules().slice();
  const j = index + dir;
  if (j < 0 || j >= rules.length) return;
  const tmp = rules[index];
  rules[index] = rules[j];
  rules[j] = tmp;
  setDraft(rules, true);
}

export function deleteRule(index: number): void {
  const rules = draftRules().slice();
  rules.splice(index, 1);
  setDraft(rules, true);
}

/**
 * 保存本地规则。
 *
 * `silent` = **自动保存**路径（规则页边改边存，SwitchyOmega 那种）：
 * 不弹 toast、也不拉一整轮数据 —— 引擎本来就会把规则变化推事件回来。
 */
export async function saveRules(opts: { silent?: boolean } = {}): Promise<boolean> {
  const rules = draftRules();
  const r = await call<void>("set_rules", { rules });
  if (!r.ok) {
    if (!opts.silent) toast(`保存失败：${r.e}`, "err", 9000);
    return false;
  }
  // 请求飞在半空中时用户可能又改了：那就**别清 dirty**，否则刚敲的字会被当成"已保存"。
  if (rulesEqual(draftRules(), rules)) setDraft(rules, false);
  if (opts.silent) return true;
  toast("本地规则已保存（尚未发布到全网）", "ok");
  await refreshAll();
  return true;
}

export async function sortRules(): Promise<void> {
  const r = await call<Rule[]>("sort_rules", { rules: draftRules() });
  if (r.ok) {
    setDraft(r.v, true);
    toast("已按具体度重排（记得保存）", "info");
  } else {
    toast(r.e, "err");
  }
}

export async function previewRules(): Promise<RulePreview | null> {
  const r = await call<RulePreview>("preview_rules", { rules: draftRules() });
  if (!r.ok) {
    toast(`预览失败：${r.e}`, "err", 9000);
    return null;
  }
  return r.v;
}

export async function publishRules(): Promise<void> {
  const r = await call<{ revision: number; rules: number }>("publish_rules", {
    rules: draftRules(),
  });
  if (r.ok) {
    toast(`已发布 revision ${r.v.revision}（${r.v.rules} 条）`, "ok");
    await refreshAll();
  } else {
    toast(`发布失败：${r.e}`, "err", 9000);
  }
}

export async function revokeSharedRules(): Promise<void> {
  const r = await call<{ revision: number }>("revoke_shared_rules");
  if (r.ok) {
    toast(`已撤回（revision ${r.v.revision}）`, "warn");
    await refreshAll();
  } else {
    toast(`撤回失败：${r.e}`, "err");
  }
}

/** 全局旁路：`false` = 忽略全部规则，只跑网段自动匹配（§9.4.4）。 */
export async function setRulesEnabled(enabled: boolean): Promise<void> {
  const r = await call<void>("set_rules_enabled", { enabled });
  if (!r.ok) {
    toast(`切换失败：${r.e}`, "err", 9000);
    return;
  }
  toast(enabled ? "路由规则已启用" : "已开启全局旁路：所有规则被忽略", enabled ? "ok" : "warn", 8000);
  await refreshAll();
}

/* ────────────────────────────── 配置 ────────────────────────────── */

export async function loadConfig(): Promise<Config | null> {
  const r = await call<Config>("get_config");
  if (r.ok) {
    configStore.set(r.v);
    return r.v;
  }
  toast(`读取配置失败：${r.e}`, "err", 9000);
  return null;
}

export async function saveConfig(cfg: Config): Promise<boolean> {
  const r = await call<void>("set_config", { cfg });
  if (!r.ok) {
    toast(`保存失败：${r.e}`, "err", 9000);
    return false;
  }
  toast("配置已保存并应用", "ok");
  await refreshService();
  await refreshAll();
  return true;
}

/**
 * 只改**一个**字段的配置写入（首页那几张快捷卡用）。
 *
 * 关键在"先 `loadConfig()` 再改"：拿一份**最新**的配置去改，而不是拿界面上那份可能
 * 已经过期的副本整份覆盖 —— 后者会把别人（或另一个页面）刚改的东西抹掉。
 * 服务没跑时 `set_config` 只落盘，正好也是快捷卡要的行为。
 */
export async function patchConfig(mutate: (cfg: Config) => void): Promise<boolean> {
  const fresh = await loadConfig();
  if (!fresh) return false;
  const next = JSON.parse(JSON.stringify(fresh)) as Config;
  mutate(next);
  return saveConfig(next);
}

/** ① 入向端口（IT 授权给本机的那个）—— ★ 需重启才真正生效。 */
export function setListenPorts(ports: number[]): Promise<boolean> {
  return patchConfig((c) => {
    c.listen.ports = ports;
  });
}

/** ④ 本机 SOCKS5 端口。 */
export function setSocks5Bind(addr: string): Promise<boolean> {
  return patchConfig((c) => {
    c.proxy.bind = addr;
  });
}

/** 默认出口（规则与网段都没命中时的最后一顺位，§9.4.4）。传 `null` = 清除。 */
export function setDefaultEgress(egress: string | null): Promise<boolean> {
  return patchConfig((c) => {
    c.route.default_egress = egress;
  });
}

export async function configToToml(): Promise<string | null> {
  const r = await call<string>("config_to_toml");
  if (!r.ok) {
    toast(r.e, "err");
    return null;
  }
  return r.v;
}

export function configFromToml(text: string): Promise<CallResult<Config>> {
  return call<Config>("config_from_toml", { text });
}

export function validateConfig(cfg: Config): Promise<CallResult<string[]>> {
  return call<string[]>("validate_config", { cfg });
}

/* ────────────────────────────── 事件桥 ────────────────────────────── */

/** 订阅引擎事件。返回 unlisten。 */
export async function startEventBridge(): Promise<() => void> {
  return onHiveEvent((p) => {
    switch (p.event) {
      case "topology":
        topologyStore.set(p);
        break;

      case "rules":
        rulesViewStore.set(p);
        syncDraftFrom(p.local ?? []);
        break;

      case "stats":
        statsStore.set(p);
        break;

      case "log":
        // 引擎自己已经记过这条日志了，只需要进界面
        onlyLocal(p.level, p.module, p.msg);
        break;

      case "peer_up":
        onlyLocal("info", "link", `节点上线：${p.peer}（${p.carrier}）`);
        break;

      case "peer_down":
        onlyLocal("warn", "link", `节点下线：${p.peer}（${p.reason}）`);
        break;

      case "stream_opened":
        onlyLocal(
          "info",
          "stream",
          `流 #${p.stream_id} ${p.target} → ${p.egress}${p.direct ? "（本机直连）" : ""}`,
        );
        break;

      case "stream_closed":
        onlyLocal(
          "debug",
          "stream",
          `流 #${p.stream_id} 关闭（${p.reason}）：入 ${p.bytes_in} / 出 ${p.bytes_out} 字节`,
        );
        break;

      case "shared_rules_rejected":
        onlyLocal("warn", "rules", `拒收来自 ${p.source} 的共享规则集：${p.reason}`);
        break;

      case "identity_conflict":
        onlyLocal("error", "identity", p.hint);
        toast(p.hint, "err", 15000);
        break;
    }
  });
}

/* ────────────────────────────── 轮询 ────────────────────────────── */

/**
 * 事件已经覆盖了大部分变化，轮询只是兜底（事件积压、或某个变化没发事件）。
 * 窗口不可见时跳过轻量轮询 —— 别在后台白白唤醒引擎。
 */
export function startPolling(): () => void {
  const light = window.setInterval(() => {
    if (!document.hidden) void refreshLight();
  }, 2000);
  const svc = window.setInterval(() => void refreshService(), 5000);
  return () => {
    window.clearInterval(light);
    window.clearInterval(svc);
  };
}

/** 界面启动：接事件 → 拉一次全量 → 起轮询。返回清理函数（React 严格模式下会调两次）。 */
/**
 * 挂载时启动一次，**全程不往外抛异常** —— 这是"任何一条命令失败都不能白屏"的最后一环。
 *
 * 事件订阅失败（典型场景：capabilities 少了 `core:event:allow-listen`，见 lib.rs 的回归守卫）
 * 之前会把启动卡在第一个 `await` 上：轮询没起来、配置页停在初始值、引擎日志里也什么都没有。
 * 界面看着画出来了，其实半瘫 —— 正是 DESIGN.md §17 风险 11 描述的那种。
 * 现在退化成纯轮询：实时性下降，功能仍然可用，且失败原因会经 `report` 进引擎日志。
 */
export async function boot(): Promise<() => void> {
  let unlisten: () => void = () => {};
  try {
    unlisten = await startEventBridge();
  } catch (e) {
    report("error", "ui", `事件订阅失败，退化为纯轮询（实时性下降，功能可用）：${errText(e)}`);
  }

  try {
    await refreshAll();
  } catch (e) {
    // refreshAll 内部走 call() 逐项容错，正常不会抛；兜住是为了不让 tick 变成未处理拒绝。
    report("error", "ui", `首次数据拉取异常：${errText(e)}`);
  }

  const stopPolling = startPolling();
  return () => {
    unlisten();
    stopPolling();
  };
}

/** 供组件做"这个值是不是我刚编辑过的"这类浅比较（避免重复导出 store.ts）。 */
export { shallowEqual };
