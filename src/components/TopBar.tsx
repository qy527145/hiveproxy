import { useState, type CSSProperties } from "react";

import { IS_TAURI } from "../lib/ipc";
import { changeToken, logout } from "../state/auth";
import { refreshAll } from "../state/hive";
import { useService } from "../state/useHive";
import { viewTitle, type ViewId } from "./nav";
import { Banner } from "./ui";

const backdropStyle: CSSProperties = { position: "fixed", inset: 0, zIndex: 39 };
const popStyle: CSSProperties = {
  position: "absolute",
  right: 0,
  top: "calc(100% + 8px)",
  zIndex: 40,
  width: 320,
};

/** 标题栏 + 全局横幅。服务没跑 / 启动失败时，把原因摆在最显眼的地方。 */
export function TopBar({ view }: { view: ViewId }) {
  const svc = useService();
  const canRefresh = view === "overview" || view === "topology";
  const [menu, setMenu] = useState(false);
  // 桌面端没有会话这回事，也就没有这个按钮 —— 它整块只属于 web 模式。
  const web = !IS_TAURI;

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
      <div className="actions" style={{ position: "relative" }}>
        {canRefresh && (
          <button className="ghost" onClick={() => void refreshAll()}>
            刷新
          </button>
        )}
        {web && (
          <button className="ghost" onClick={() => setMenu((v) => !v)}>
            访问令牌
          </button>
        )}
        {web && menu && (
          <>
            {/* 点面板外面收起 —— 用一层透明遮罩，免得加一个全局 mousedown 监听 */}
            <div style={backdropStyle} onClick={() => setMenu(false)} />
            <div className="panel" style={popStyle}>
              <TokenMenu />
            </div>
          </>
        )}
      </div>
    </header>
  );
}

/** 「访问令牌」下拉里的内容：改令牌 + 退出登录。 */
function TokenMenu() {
  const [oldTok, setOldTok] = useState("");
  const [nw, setNw] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function submit() {
    setBusy(true);
    setMsg(null);
    const r = await changeToken(oldTok.trim(), nw);
    setBusy(false);
    if (r.ok) {
      setMsg({ kind: "ok", text: "令牌已更新" });
      setOldTok("");
      setNw("");
    } else {
      setMsg({ kind: "err", text: r.e });
    }
  }

  return (
    <>
      <div className="sub">改令牌</div>
      <div className="field" style={{ gridTemplateColumns: "76px minmax(0, 1fr)", marginTop: 8 }}>
        <label htmlFor="tk_old">当前令牌</label>
        <div>
          <input
            id="tk_old"
            type="password"
            value={oldTok}
            disabled={busy}
            onChange={(e) => setOldTok(e.target.value)}
          />
        </div>
        <label htmlFor="tk_new">新令牌</label>
        <div>
          <input
            id="tk_new"
            type="password"
            value={nw}
            disabled={busy}
            onChange={(e) => setNw(e.target.value)}
          />
        </div>
      </div>
      {msg ? <div className={msg.kind === "ok" ? "dialok" : "cellerr"}>{msg.text}</div> : null}
      <div className="row" style={{ marginTop: 8 }}>
        <button
          className="primary"
          disabled={busy || !oldTok.trim() || nw.length < 8}
          onClick={() => void submit()}
        >
          {busy ? "提交中…" : "更新令牌"}
        </button>
        <span className="spacer" />
        <button className="danger" onClick={() => void logout()}>
          退出登录
        </button>
      </div>
    </>
  );
}
