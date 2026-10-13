// Tauri IPC 的薄封装。只有两条规矩，但都被踩过，所以写死在这里：
//
// 1) **任何一条命令失败都不能让整个界面白屏** —— 所以这里统一返回
//    `CallResult`，而不是让异常往外抛。界面按项容错：服务没启动时，
//    配置页照样能编辑、能落盘。
// 2) **前端报错要能进引擎日志** —— `uiLog` 用它自己的失败兜住自己的异常，
//    绝不能在"报错"这条路径上再抛错（那才是真的白屏）。

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import { HIVE_EVENT, type HiveEvent } from "./types";

export type CallResult<T> = { ok: true; v: T } | { ok: false; e: string };

/** 逐项容错的 invoke。用法：`const r = await call<NodeStatus>("status");` */
export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<CallResult<T>> {
  try {
    return { ok: true, v: await invoke<T>(cmd, args) };
  } catch (e) {
    return { ok: false, e: errText(e) };
  }
}

/** Rust 侧的错误统一是 `String`，但保险起见把非字符串也捋顺。 */
export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

/** 把浏览器侧的日志回传到引擎（`ui_log`），进 tracing 日志。失败就算了。 */
export function uiLog(level: "debug" | "info" | "warn" | "error", msg: string): void {
  try {
    void invoke("ui_log", { level, msg }).catch(() => {});
  } catch {
    /* 忽略：报错路径上不能再抛错 */
  }
}

/** 订阅引擎事件。返回 unlisten —— 组件卸载时务必调用。 */
export async function onHiveEvent(cb: (e: HiveEvent) => void): Promise<UnlistenFn> {
  return listen<HiveEvent>(HIVE_EVENT, (e) => cb(e.payload));
}
