// IPC 的薄封装 —— **一层运行时传输适配**，两条规矩，但都被踩过，所以写死在这里：
//
// 1) **任何一条命令失败都不能让整个界面白屏** —— 所以这里统一返回
//    `CallResult`，而不是让异常往外抛。界面按项容错：服务没启动时，
//    配置页照样能编辑、能落盘。
// 2) **前端报错要能进引擎日志** —— `uiLog` 用它自己的失败兜住自己的异常，
//    绝不能在"报错"这条路径上再抛错（那才是真的白屏）。
//
// 传输在**运行时**二选一：Tauri 里走 `invoke` / `listen`，纯浏览器里走 HTTP+SSE
// （契约见 docs/WEBUI.md §3.2）。同一份 bundle 两边都要吃，所以判定只能放在运行时，
// 不能做成构建期常量。三个导出（`call` / `onHiveEvent` / `uiLog`）的签名刻意一个
// 字都不动 —— 换了传输就不动界面，靠的就是这条线。`@tauri-apps/api` 保持静态 import：
// 只要浏览器分支里不执行到它，它就不会被用到。

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import { HIVE_EVENT, type HiveEvent } from "./types";

/**
 * Tauri 是否在场。`__TAURI_INTERNALS__` 是它注入到 window 上的内部约定 ——
 * 用它而不是"有没有某个 API"，是因为判定必须在**任何 import 之前**就能成立，
 * 否则模块加载顺序一变就翻车。模块加载时算一次即可（窗口的宿主一进程内不会变）。
 */
export const IS_TAURI = "__TAURI_INTERNALS__" in window;

export type CallResult<T> = { ok: true; v: T } | { ok: false; e: string };

/**
 * web 分支收到 401 时的接收端（由 state/auth.ts 注册）。
 *
 * 为什么不直接 import auth：ipc 是传输层，auth 反过来要用 ipc 的 `call`，
 * 直接依赖会成环。这里只留一个回调孔，谁关心登录态谁自己插进来。
 */
let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(fn: (() => void) | null): void {
  unauthorizedHandler = fn;
}

/** 逐项容错的 invoke。用法：`const r = await call<NodeStatus>("status");` */
export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<CallResult<T>> {
  if (!IS_TAURI) return httpCall<T>(cmd, args);
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
  // 两条传输的背后都是同一条 `ui_log` 命令（web 的端点名 = 命令名）。
  if (!IS_TAURI) {
    void httpPost("ui_log", { level, msg }).catch(() => {});
    return;
  }
  try {
    void invoke("ui_log", { level, msg }).catch(() => {});
  } catch {
    /* 忽略：报错路径上不能再抛错 */
  }
}

/** 订阅引擎事件。返回 unlisten —— 组件卸载时务必调用。 */
export async function onHiveEvent(cb: (e: HiveEvent) => void): Promise<UnlistenFn> {
  if (!IS_TAURI) return sseOnHiveEvent(cb);
  return listen<HiveEvent>(HIVE_EVENT, (e) => cb(e.payload));
}

/* ────────────────────────────── HTTP / SSE 传输 ────────────────────────────── */

/**
 * `invoke` 的 HTTP 对偶：POST /api/<命令名>，body 就是 args。
 * 成功体即返回值（void 命令是 `null`），失败体是 `{"error":"…"}`。
 */
async function httpCall<T>(cmd: string, args?: Record<string, unknown>): Promise<CallResult<T>> {
  let res: Response;
  try {
    res = await httpPost(cmd, args ?? {});
  } catch (e) {
    // 网络本身断了（服务没起、被反代掐掉）：也走逐项容错，不要往外抛。
    return { ok: false, e: errText(e) };
  }

  if (res.status === 401) {
    // 会话没了：让 auth 层弹登录页。具体错误仍从响应体取（例如改令牌的"旧令牌不对"）。
    unauthorizedHandler?.();
    return { ok: false, e: await readError(res, "未登录") };
  }
  if (!res.ok) return { ok: false, e: await readError(res, `HTTP ${res.status}`) };
  try {
    return { ok: true, v: (await res.json()) as T };
  } catch (e) {
    // 200 但体不是 JSON（服务端异常）：当失败处理，仍不抛。
    return { ok: false, e: errText(e) };
  }
}

function httpPost(cmd: string, body: unknown): Promise<Response> {
  return fetch(`/api/${cmd}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function readError(res: Response, fallback: string): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string };
    if (body?.error) return body.error;
  } catch {
    /* 体不是 JSON：用调用方给的兜底文案 */
  }
  return fallback;
}

/**
 * SSE：EventSource 不能设自定义头，认证只能靠会话 cookie（同源请求默认带 cookie）。
 *
 * 单条事件解析失败**不能**把整条流带走 —— 吞掉它、记一行日志，其余事件照常。
 * 连接断了 EventSource 自己会重连；真重连不上也无妨：`startEventBridge` 早就把
 * "订阅失败 → 退化成纯轮询"这条退路铺好了（state/hive.ts）。
 */
function sseOnHiveEvent(cb: (e: HiveEvent) => void): UnlistenFn {
  const es = new EventSource("/api/events");
  es.onmessage = (ev) => {
    try {
      cb(JSON.parse(ev.data as string) as HiveEvent);
    } catch (e) {
      uiLog("warn", `事件解析失败：${errText(e)}`);
    }
  };
  return () => es.close();
}