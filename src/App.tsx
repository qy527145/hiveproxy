import { useEffect, useRef, useState } from "react";

import { ErrorBoundary } from "./components/ErrorBoundary";
import { Sidebar } from "./components/Sidebar";
import { Toasts } from "./components/Toasts";
import { TopBar } from "./components/TopBar";
import { VIEWS, type ViewId } from "./components/nav";
import { report } from "./lib/report";
import { boot, ruleDraftStore, serviceStore, topologyStore } from "./state/hive";
import { ConfigView } from "./views/ConfigView";
import { LogsView } from "./views/LogsView";
import { OverviewView } from "./views/OverviewView";
import { RulesView } from "./views/RulesView";
import { TopologyView } from "./views/TopologyView";

function View({ view }: { view: ViewId }) {
  switch (view) {
    case "overview":
      return <OverviewView />;
    case "topology":
      return <TopologyView />;
    case "rules":
      return <RulesView />;
    case "config":
      return <ConfigView />;
    case "logs":
      return <LogsView />;
  }
}

/** 从 URL hash 取初始视图（`#rules`）。认不出来就回概览。 */
function viewFromHash(): ViewId {
  const wanted = window.location.hash.replace(/^#\/?/, "");
  return VIEWS.some((v) => v.id === wanted) ? (wanted as ViewId) : "overview";
}

export function App() {
  const [view, setView] = useState<ViewId>(viewFromHash);
  const started = useRef(false);

  // 视图与 hash 同步。看着像给桌面应用加了个没用的 URL，其实解决的是一个真问题：
  // dev 下改一行前端就整页刷新（没有 Fast Refresh），没有它每次都被打回概览页，
  // 想改「规则」页就得重新点一次。
  useEffect(() => {
    const onHashChange = () => setView(viewFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const selectView = (next: ViewId) => {
    setView(next);
    window.location.hash = next;
  };

  useEffect(() => {
    // 挂载时只启动一次：事件桥与轮询都是"全局单例"，跑两遍会重复订阅。
    if (started.current) return;
    started.current = true;

    let stop: (() => void) | null = null;
    let cancelled = false;

    void boot().then((cleanup) => {
      if (cancelled) {
        cleanup();
        return;
      }
      stop = cleanup;

      // 回执 + 渲染自检：排障时从引擎日志就能确认"界面到底画出来没有"。
      // 引擎的 `RUST_LOG=info` 输出里能看到这一行，README 的排障一节写的就是它。
      const svc = serviceStore.get();
      const topo = topologyStore.get();
      const draft = ruleDraftStore.get();
      // 用 report() 而不是 pushLog()：这条回执必须**同时**落到引擎日志里。
      // 只在界面日志里说"我画出来了"，终端里就看不到 —— 而那正是排障时唯一看得见的地方。
      report(
        "info",
        "ui",
        `界面渲染完成：服务 ${svc.running ? "运行中" : "未启动"}，节点 ${topo.nodes.length}，本地规则 ${draft.rules.length}`,
      );
    }).catch((e) => {
      // boot() 现在自己不抛了（见 state/hive.ts），这条纯属防线：
      // 将来谁在启动路径上写了会抛的代码，也应该变成日志里的一行，
      // 而不是一条"未处理的 Promise 拒绝"。
      report("error", "ui", `启动流程异常：${String(e)}`);
    });

    report("info", "ui", "界面已就绪。左下角是服务开关；「配置」页可以改监听端口等全部参数。");

    return () => {
      cancelled = true;
      stop?.();
    };
  }, []);

  return (
    <>
      <Sidebar view={view} onSelect={selectView} />
      <main>
        <TopBar view={view} />
        {/*
          每个视图一个边界：某个视图渲染炸了，不会连侧栏和导航一起带走，
          切到别的页面照样能用。老前端最怕的"白屏"在这里变成一条可读的报错。
        */}
        <div className="view">
          <ErrorBoundary key={view}>
            <View view={view} />
          </ErrorBoundary>
        </div>
      </main>
      <Toasts />
    </>
  );
}
