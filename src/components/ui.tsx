// 排版元件：面板、行、标签、横幅、卡片、空态。
//
// 都是纯展示、无状态，凑在一起放一个文件 —— 分散成十几个文件只会让
// import 变长，读起来并不更清楚。

import type { PropsWithChildren, ReactNode } from "react";

export function Panel({
  title,
  hint,
  actions,
  children,
  className = "",
}: PropsWithChildren<{
  title?: ReactNode;
  hint?: ReactNode;
  actions?: ReactNode;
  /** 额外的类名（首页的快捷卡用它做跨列）。 */
  className?: string;
}>) {
  return (
    <section className={`panel ${className}`.trim()}>
      {(title || actions) && (
        <div className="row between">
          <div>
            {title && <h2>{title}</h2>}
            {hint && <p className="hint">{hint}</p>}
          </div>
          {actions && <div className="row nowrap">{actions}</div>}
        </div>
      )}
      {!title && hint && <p className="hint">{hint}</p>}
      {children}
    </section>
  );
}

export function Hint({ children }: PropsWithChildren) {
  return <p className="hint">{children}</p>;
}

export function Row({
  children,
  between = false,
  nowrap = false,
}: PropsWithChildren<{ between?: boolean; nowrap?: boolean }>) {
  const cls = ["row", between ? "between" : "", nowrap ? "nowrap" : ""].filter(Boolean).join(" ");
  return <div className={cls}>{children}</div>;
}

export type PillTone = "" | "ok" | "no" | "cy";

export function Pill({ tone = "", children }: PropsWithChildren<{ tone?: PillTone }>) {
  return <span className={`pill ${tone}`}>{children}</span>;
}

export function Empty({ children }: PropsWithChildren) {
  return <div className="empty">{children}</div>;
}

export function TableWrap({ children, className = "" }: PropsWithChildren<{ className?: string }>) {
  return <div className={`tablewrap ${className}`.trim()}>{children}</div>;
}

/** 卡片：概览页那一排指标。`tone` 决定数值颜色。 */
export function Card({
  label,
  value,
  tone = "",
  wide = false,
}: {
  label: string;
  value: ReactNode;
  tone?: "" | "good" | "bad";
  wide?: boolean;
}) {
  return (
    <div className={`card ${tone} ${wide ? "wide" : ""}`.trim()}>
      <div className="k">{label}</div>
      <div className="v">{value}</div>
    </div>
  );
}

export type BannerTone = "" | "soft" | "warn" | "err";

export function Banner({ tone = "", children }: PropsWithChildren<{ tone?: BannerTone }>) {
  if (children == null || children === false) return null;
  return <div className={`banner ${tone}`.trim()}>{children}</div>;
}

/** 键值行：侧栏与详情里用。 */
export function KV({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className="v mono">{v}</span>
    </div>
  );
}
