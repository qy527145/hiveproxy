import { useState } from "react";

import { fmtUptime } from "../lib/format";
import { togglePower } from "../state/hive";
import { useService, useStatus } from "../state/useHive";
import { VIEWS, type ViewId } from "./nav";
import { KV } from "./ui";

/**
 * 侧栏：导航 + 左下角的服务开关。
 *
 * 这里也承担"现在处于什么状态"的第一眼信息：服务在跑没有、代理挂在哪儿、
 * 以及几条**必须显眼**的开关状态（全局旁路、不共享网段、不做出口）。
 */
export function Sidebar({ view, onSelect }: { view: ViewId; onSelect: (id: ViewId) => void }) {
  const svc = useService();
  const status = useStatus();
  const [busy, setBusy] = useState(false);

  async function onPower() {
    setBusy(true);
    try {
      await togglePower();
    } finally {
      setBusy(false);
    }
  }

  const dot = svc.running ? "on" : svc.last_error ? "err" : "off";
  const state = svc.running ? "运行中" : svc.last_error ? "启动失败" : "未启动";

  const warnings: string[] = [];
  if (status) {
    if (!status.rules_enabled) warnings.push("★ 全局旁路已开启");
    if (!status.share_subnets) warnings.push("不对外共享网段（仍可访问自己的网段）");
    if (!status.accepts_egress) warnings.push("不替他人转发（自己仍然出得去）");
    if (status.listen.length > 0) warnings.push(`监听 ${status.listen.length} 个地址`);
  }

  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="logo">⬡</span>
        <div>
          <div className="bname">hiveproxy</div>
          <div className="bver">
            {status
              ? `v${status.version} · 运行 ${fmtUptime(status.uptime_secs)}`
              : svc.autostart
                ? "未运行"
                : "未运行（已关自动启动）"}
          </div>
        </div>
      </div>

      <nav id="nav">
        {VIEWS.map((v) => (
          <button
            key={v.id}
            className={v.id === view ? "active" : ""}
            onClick={() => onSelect(v.id)}
          >
            <i>{v.icon}</i>
            {v.label}
          </button>
        ))}
      </nav>

      <div className="servicebox">
        <div className="svcrow">
          <span className={`dot ${dot}`} />
          <span className="svctext">{state}</span>
          <button
            className={`power ${svc.running ? "stop" : ""}`}
            disabled={busy}
            onClick={() => void onPower()}
          >
            {busy ? (svc.running ? "停止中…" : "启动中…") : svc.running ? "停止" : "启动"}
          </button>
        </div>
        <KV k="本机" v={svc.node_id} />
        <KV k="代理" v={svc.proxy_bind} />
        <KV k="默认出口" v={status?.default_egress ?? "（没设）"} />
        <div className="foot">
          {warnings.map((w) => (
            <div className="warn" key={w}>
              {w}
            </div>
          ))}
          {svc.admin_endpoint && <div>管理接口 {svc.admin_endpoint}</div>}
        </div>
      </div>
    </aside>
  );
}
