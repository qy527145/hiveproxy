import { refreshAll } from "../state/hive";
import { useService } from "../state/useHive";
import { viewTitle, type ViewId } from "./nav";
import { Banner } from "./ui";

/** 标题栏 + 全局横幅。服务没跑 / 启动失败时，把原因摆在最显眼的地方。 */
export function TopBar({ view }: { view: ViewId }) {
  const svc = useService();
  const canRefresh = view === "overview" || view === "topology";

  return (
    <header className="topbar">
      <h1>{viewTitle(view)}</h1>
      {svc.last_error ? (
        <Banner tone="err">服务启动失败：{svc.last_error}</Banner>
      ) : !svc.running ? (
        <Banner tone="warn">
          服务未运行 —— 点左下角「启动」开始组网。「配置」页现在也可以编辑并保存。
        </Banner>
      ) : null}
      <div className="actions">
        {canRefresh && (
          <button className="ghost" onClick={() => void refreshAll()}>
            刷新
          </button>
        )}
      </div>
    </header>
  );
}
