// 浏览器侧的报错兜底：window.onerror / 未处理的 Promise 拒绝 / React 渲染崩溃，
// 全部回传到引擎日志（`ui_log`），同时进界面自己的日志面板。
//
// 为什么值得单独一个文件：DESIGN.md §17 的风险 11 记的就是"前端静默白屏"——
// Tauri 的权限没配好时初始化会整段中断，界面上什么都不显示、日志里也什么都没有。
// 把这条链路打通之后，`RUST_LOG=info hiveproxy` 的终端输出里就能看到浏览器侧的问题。

import { uiLog } from "./ipc";

/** 日志落点：界面自己的日志面板。由 main.tsx 注入，避免 lib → state 的反向依赖。 */
export type LogSink = (level: string, module: string, msg: string) => void;

let sink: LogSink | null = null;

/** 同时进界面日志 + 回传引擎。 */
export function report(level: "debug" | "info" | "warn" | "error", module: string, msg: string): void {
  sink?.(level, module, msg);
  uiLog(level, msg);
}

/** 只进界面日志（引擎已经在自己的日志里记过的事件走这条）。 */
export function onlyLocal(level: string, module: string, msg: string): void {
  sink?.(level, module, msg);
}

export function installGlobalErrorReporting(logSink: LogSink): void {
  sink = logSink;

  window.addEventListener("error", (e) => {
    report("error", "ui", `${e.message} @ ${e.filename}:${e.lineno}:${e.colno}`);
  });

  window.addEventListener("unhandledrejection", (e) => {
    const r: unknown = e.reason;
    const msg = r instanceof Error ? r.message : String(r);
    report("error", "ui", `未处理的 Promise 拒绝：${msg}`);
  });
}
