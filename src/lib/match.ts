// 规则匹配条件的「类型 + 值」写法（UI.md §3.2）。
//
// 形状照 SwitchyOmega 的「切换规则」：**条件类型是一个下拉，条件设置是一个输入框**。
// 这里只做两件事：
//   1. 把那个输入框的内容（`host[:port]`）翻译成引擎的两个字段；
//   2. 在切换类型时把内容转换成仍然属于该类型的写法。
//
// 类型与引擎的枚举**一一对应，不多不少**（下拉里出现不了引擎不认识的写法）：
//   host: 任意 / 域名后缀 / 精确主机 / 网段   ↔ HostMatcher::{Any,Suffix,Exact,Cidr}
//
// 草稿里存的**始终是引擎的字符串形态**（`*.corp.example.com` / `3389`），
// UI 这两个函数只是来回翻译，中间不额外存一份状态 —— 两处状态一定会分叉，
// 分叉了就不知道该信谁。

export type HostKind = "any" | "suffix" | "exact" | "cidr";

export interface Cond {
  kind: HostKind;
  value: string;
}

export const HOST_KINDS: { kind: HostKind; label: string }[] = [
  { kind: "any", label: "任意" },
  { kind: "suffix", label: "域名后缀" },
  { kind: "exact", label: "精确主机" },
  { kind: "cidr", label: "网段" },
];

/** `*.corp.example.com` → `{kind:"suffix", value:"corp.example.com"}`。 */
export function parseHost(s: string): Cond {
  const t = s.trim();
  if (t === "" || t === "*") return { kind: "any", value: "" };
  if (t.startsWith("*.")) return { kind: "suffix", value: t.slice(2) };
  if (t.includes("/")) return { kind: "cidr", value: t };
  return { kind: "exact", value: t };
}

/**
 * 条件的**单行写法**：`host[:port]`（不加端口 = 任意端口）。
 *
 *   `*.corp.example.com`  `10.9.0.0/16`  `10.4.0.9:3389`  `10.9.0.0/16:8000-9000`  `*:443`
 *
 * IPv6 要带端口时写成 `[fd00::1]:443` —— 不加方括号时，地址里的 `:` 与端口分不开。
 */
export function splitCondition(text: string): { host: string; port: string } {
  const t = text.trim();
  if (t === "") return { host: "*", port: "*" };
  const v6 = t.match(/^\[(.+)\]:(\*|\d+(?:-\d+)?)$/);
  if (v6) return { host: v6[1], port: v6[2] };
  const i = t.lastIndexOf(":");
  if (i > 0) {
    const maybeHost = t.slice(0, i);
    const maybePort = t.slice(i + 1);
    // 只有当"地址部分"自己不含 `:` 时，最后一段才是端口 —— 否则它是 IPv6 地址的一部分
    if (/^(\*|\d+(?:-\d+)?)$/.test(maybePort) && maybeHost !== "" && !maybeHost.includes(":")) {
      return { host: maybeHost, port: maybePort };
    }
  }
  return { host: t, port: "*" };
}

/**
 * 反向：把引擎的 host / port 拼回那一个输入框。
 *
 * **空就是空**：不再把空 host 写成 `*` —— 否则"还没填"与"匹配所有目标"在框里长得一样，
 * 而它们是两件完全不同的事（前者不该被保存，后者是你显式选的）。
 */
export function formatCondition(host: string, port: string): string {
  const h = host.trim();
  if (h === "") return "";
  const hh = h.includes(":") && !h.startsWith("[") ? `[${h}]` : h;
  return !port || port === "*" ? hh : `${hh}:${port}`;
}

/**
 * 切换条件类型时，把已经填的内容尽量带过去。
 *
 * 为什么需要它：切换只改了"解释方式"，值还在框里。能带过去就带过去
 * （`10.1.2.9` → 切到网段 → `10.1.2.9/`，引擎随后告诉你缺前缀长度）；
 * 带不过去就留一个**仍然属于该类型**的残值（空 → `*.`），由引擎在行内说"该怎么填"。
 * 唯一的例外是值真的为空（`""`），这时下拉框靠调用方的"类型覆盖"钉住，
 * 引擎会明确报"不能为空" —— **绝不替用户写成 `*`**，那会静默变成一条兜住全网的 `*:*`。
 */
export function convertHost(to: HostKind, cur: Cond): string {
  const v = cur.value;
  switch (to) {
    case "any":
      return "*";
    case "suffix":
      return v === "" ? "*." : `*.${v.replace(/^\*\./, "")}`;
    case "cidr":
      return v === "" ? "" : v.includes("/") ? v : `${v}/`;
    case "exact":
      return v;
  }
}

/** 切换类型时连端口一起转换那一个框。 */
export function convertCondition(to: HostKind, cur: Cond, port: string): string {
  return formatCondition(convertHost(to, cur), port);
}