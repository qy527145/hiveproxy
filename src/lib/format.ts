// 展示层的格式化。纯函数，无副作用。

import type { Endpoint, Host } from "./types";

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  return `${(n / 1024 ** 3).toFixed(2)} GiB`;
}

export function fmtUptime(s: number): string {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${s % 60}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d${Math.floor((s % 86400) / 3600)}h`;
}

/** Unix 秒 → 本地时间字符串。0 / undefined / null 都显示 `—`。 */
export function fmtUnix(secs: number | null | undefined, withDate = false): string {
  if (!secs) return "—";
  const d = new Date(secs * 1000);
  return withDate ? d.toLocaleString() : d.toLocaleTimeString();
}

export function fmtClock(t: Date): string {
  return t.toLocaleTimeString();
}

/**
 * `Endpoint` 在 JSON 里是 `{host:{Ip:"10.1.2.9"},port:3389}` —— 直接塞进
 * JSX 会渲染成 `[object Object]`（老前端就是这么错的）。这里统一转成 `ip:port`。
 */
export function hostToString(h: Host | null | undefined): string {
  if (!h) return "?";
  if (typeof h === "object" && "Ip" in h) return h.Ip;
  if (typeof h === "object" && "Name" in h) return h.Name;
  return String(h);
}

export function endpointToString(ep: Endpoint | null | undefined): string {
  if (!ep) return "?";
  return `${hostToString(ep.host)}:${ep.port}`;
}

/** `RuleSetAd.hmac` 之类的字节串，只用于展示。 */
export function fmtBytesArray(v: number[] | null | undefined): string {
  if (!v || v.length === 0) return "—";
  return v.map((b) => b.toString(16).padStart(2, "0")).join("");
}
