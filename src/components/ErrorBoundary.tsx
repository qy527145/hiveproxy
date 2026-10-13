// React 渲染崩溃的兜底。
//
// 老前端最怕的是"白屏"（DESIGN.md §17 风险 11：一次权限配错就让整个界面
// 什么都不显示，而且日志里也什么都没有）。React 里渲染期抛错默认会卸载整棵树 ——
// 那就是白屏。这个边界把错误显示出来，同时回传引擎日志，让"白屏"变成"一条可读的报错"。

import { Component, type ErrorInfo, type ReactNode } from "react";

import { report } from "../lib/report";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    const where = info.componentStack ? `\n组件栈：${info.componentStack}` : "";
    report("error", "ui", `界面渲染崩溃：${error.message}${where}`);
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="crash">
        <h2>界面渲染出错</h2>
        <p>
          报错已回传到引擎日志（<code>ui_log</code>）。看终端里 <code>RUST_LOG=info hiveproxy</code>{" "}
          的输出，或点下面的「重试渲染」。
        </p>
        <pre>{String(error.stack ?? error.message)}</pre>
        <button onClick={() => this.setState({ error: null })}>重试渲染</button>
      </div>
    );
  }
}
