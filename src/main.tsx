import { createRoot } from "react-dom/client";

import { App } from "./App";
import { installGlobalErrorReporting } from "./lib/report";
import { pushLog } from "./state/hive";

import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/views.css";

// 先把浏览器侧的报错通道接上，再挂载界面 —— 这样连"挂载本身失败"都能进引擎日志。
installGlobalErrorReporting(pushLog);

const container = document.getElementById("root");
if (!container) {
  throw new Error("找不到 #root：index.html 与 main.tsx 对不上，界面无法挂载");
}

// 刻意不套 <StrictMode>：它会在开发模式下把每个 effect 跑两遍，
// 而事件订阅与轮询是全局单例，双跑只会重复订阅引擎事件。
createRoot(container).render(<App />);
