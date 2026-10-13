// 出口（egress）的取值语法在**前端这一侧**的唯一落点。
//
// 引擎里 `egress` 是一个字符串前缀语法（§9.4.2）：
//   auto | direct | block | node:<ip> | <ip> | alias:<名> | group:<名> | group:subnet:<cidr>
// 规则页以前把这一栏做成裸输入框，于是"写什么都报错"（用户原话：行内要填的信息很抽象）。
// 这里把它拆成「下拉里能选到的都是引擎认得的写法」+「其它…」手填兜底 —— 与 SwitchyOmega
// 的"条件 → 情景模式"是同一个思路（UI.md §3.3）。

import type { GroupView, NodeView } from "./types";

export type EgressKind = "auto" | "direct" | "block" | "node" | "alias" | "group" | "raw";

export interface ParsedEgress {
  kind: EgressKind;
  /** 剥掉前缀后的部分（`node:` / `group:` / `alias:` 的值）。 */
  value: string;
}

/** 把引擎语法拆成"类型 + 值"，认不出来的一律算 `raw`（原样保留，不做有损改写）。 */
export function parseEgress(s: string): ParsedEgress {
  const t = s.trim();
  switch (t) {
    case "":
    case "auto":
      return { kind: "auto", value: "" };
    case "direct":
    case "self":
      return { kind: "direct", value: "" };
    case "block":
    case "reject":
      return { kind: "block", value: "" };
  }
  const rest = t.startsWith("node:") ? t.slice(5) : t;
  // 裸 IP 等价于 node:<ip>（§9.4.2 取值表），但界面上统一按 node 处理，写回时补上前缀
  const looksIp =
    /^\d{1,3}(\.\d{1,3}){3}$/.test(rest) ||
    (rest.includes(":") && /^[0-9a-fA-F:]+$/.test(rest));
  if (looksIp) {
    return { kind: "node", value: rest };
  }
  if (t.startsWith("alias:")) return { kind: "alias", value: t.slice(6) };
  if (t.startsWith("group:subnet:")) return { kind: "group", value: t.slice(6) };
  if (t.startsWith("group:")) return { kind: "group", value: t.slice(6) };
  return { kind: "raw", value: t };
}

/** 把"类型 + 值"写回引擎语法。 */
export function formatEgress(kind: EgressKind, value: string): string {
  const v = value.trim();
  switch (kind) {
    case "auto":
      return "auto";
    case "direct":
      return "direct";
    case "block":
      return "block";
    case "node":
      return v.startsWith("node:") || v === "" ? v || "auto" : `node:${v}`;
    case "alias":
      return v === "" ? "auto" : `alias:${v}`;
    case "group":
      return v === "" ? "auto" : `group:${v}`;
    case "raw":
      return v === "" ? "auto" : v;
  }
}

export interface EgressOption {
  value: string;
  label: string;
  /** 下拉里的分组标题；`""` = 不分组。 */
  group: string;
}

/**
 * 现场生成出口下拉的选项 —— 这就是"从拓扑里选节点"。
 *
 * 每一项都带上"为什么选它"的现场信息（别名、直连还是多跳、成本），
 * 因为让用户自己照着拓扑表手打 IP，正是旧版最别扭的地方。
 */
export function egressOptions(
  nodes: NodeView[],
  groups: GroupView[],
  aliases: { address: string; alias: string }[],
): EgressOption[] {
  const out: EgressOption[] = [
    { value: "auto", label: "自动（按网段就近，谁能到谁上）", group: "" },
    { value: "direct", label: "本机直连（不进 overlay）", group: "" },
    { value: "block", label: "拒绝连接", group: "" },
  ];

  for (const n of nodes) {
    if (n.is_self) continue;
    const bits = [
      n.alias ? `${n.alias} · ` : "",
      !n.reachable ? "不可达" : n.direct ? "直连" : `${n.hops ?? "?"} 跳`,
      n.cost != null ? `成本 ${n.cost}` : "",
      n.accepts_egress ? "" : "不做出口",
    ].filter(Boolean);
    out.push({
      value: `node:${n.peer}`,
      label: `${n.peer}（${bits.join(" · ")}）`,
      group: "节点",
    });
  }

  for (const g of groups) {
    const derived = typeof g.source === "object";
    out.push({
      value: `group:${g.name}`,
      label: derived
        ? `${g.name}（自动派生 · ${g.members.length} 个声明者）`
        : `${g.name}（显式定义 · ${g.members.length} 个成员）`,
      group: "候选集",
    });
  }

  for (const a of aliases) {
    // 别名**只在本地规则里可用**（发布时会被解析成 node:，§9.4.3）
    out.push({ value: `alias:${a.alias}`, label: `${a.alias}（别名 → ${a.address}）`, group: "别名（仅本地规则）" });
  }

  return out;
}

/** 给只读位置（表尾、状态带）用的人话标签。 */
export function egressLabel(s: string | null | undefined, nodes: NodeView[] = []): string {
  if (!s) return "（没设）";
  const p = parseEgress(s);
  const node = p.kind === "node" ? nodes.find((n) => n.peer === p.value) : undefined;
  switch (p.kind) {
    case "auto":
      return "自动（按网段就近）";
    case "direct":
      return "本机直连";
    case "block":
      return "拒绝连接";
    case "node":
      return node
        ? `${p.value}（${node.alias ? `${node.alias} · ` : ""}${node.reachable ? "可达" : "不可达"}）`
        : p.value;
    case "alias":
      return `别名 ${p.value}`;
    case "group":
      return `候选集 ${p.value}`;
    default:
      return p.value;
  }
}