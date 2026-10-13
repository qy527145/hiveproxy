// 导航定义。侧栏、标题栏、App 的路由都用这一份，避免"加了页面忘了改标题"。

export const VIEWS = [
  { id: "overview", label: "首页", icon: "◫" },
  { id: "topology", label: "拓扑", icon: "⬡" },
  { id: "rules", label: "路由规则", icon: "⇄" },
  { id: "config", label: "配置", icon: "⚙" },
  { id: "logs", label: "日志", icon: "▤" },
] as const;

export type ViewId = (typeof VIEWS)[number]["id"];

export function viewTitle(id: ViewId): string {
  return VIEWS.find((v) => v.id === id)?.label ?? id;
}
