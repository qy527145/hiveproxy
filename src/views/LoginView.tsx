// 登录页 —— "界面完全一致"唯一的例外，无法避免：界面本身要有门。
//
// 只在 web 模式、且未登录（或首次登录还没改令牌）时出现；桌面端永远不会渲染到它
// （桌面端的会话 status 初值就是 authed，见 state/auth.ts）。
//
// 样式只复用 tokens.css / base.css / views.css 里已有的零件（panel / field / row /
// cellerr / button），定位这种一次性布局用行内 style —— 不为它新造一套设计语言。

import { useState, type CSSProperties } from "react";

import { Panel } from "../components/ui";
import { changeToken, login, logout, useSession } from "../state/auth";

const wrapStyle: CSSProperties = {
  flex: "1 1 auto",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: 24,
  overflow: "auto",
};
const cardStyle: CSSProperties = { width: 400, maxWidth: "100%" };
// 登录卡窄，`.field` 默认那 200px 的标签列在这里太浪费，压窄一点。
const fieldStyle: CSSProperties = { gridTemplateColumns: "96px minmax(0, 1fr)" };

export function LoginView() {
  const session = useSession();
  // 登录时输入的那串令牌同时就是"改令牌"要用的旧令牌。
  // 为空说明是从"必须先改令牌"的状态刷新进来的（手里没有旧令牌）—— 那就先回登录框。
  const [token, setToken] = useState("");

  return (
    <div style={wrapStyle}>
      <div style={cardStyle}>
        {session.mustChange && token ? (
          <ChangeTokenPanel oldToken={token} />
        ) : (
          <LoginPanel token={token} setToken={setToken} />
        )}
      </div>
    </div>
  );
}

function LoginPanel({ token, setToken }: { token: string; setToken: (v: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!token.trim()) {
      setErr("请填写访问令牌");
      return;
    }
    setBusy(true);
    setErr(null);
    const r = await login(token.trim());
    setBusy(false);
    if (!r.ok) setErr(r.e);
  }

  return (
    <Panel
      title="hiveproxy web 界面"
      hint="输入启动日志里打印的一次性令牌。首次登录后会立刻要求你把它改成只有你知道的令牌。"
    >
      <div className="field" style={fieldStyle}>
        <label htmlFor="auth_token">访问令牌</label>
        <div>
          <input
            id="auth_token"
            autoFocus
            value={token}
            placeholder="XXXX-XXXX-XXXX-XXXX"
            disabled={busy}
            onChange={(e) => setToken(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void submit();
            }}
          />
        </div>
      </div>
      {err ? <div className="cellerr">{err}</div> : null}
      <div className="row" style={{ marginTop: 10 }}>
        <button className="primary" disabled={busy} onClick={() => void submit()}>
          {busy ? "登录中…" : "登录"}
        </button>
      </div>
    </Panel>
  );
}

/**
 * 首次登录的强制改令牌：启动日志里那串是一次性的，必须换掉才能进界面。
 * 这里**没有跳过**这个选项 —— 不想继续只能退出登录。
 */
function ChangeTokenPanel({ oldToken }: { oldToken: string }) {
  const [nw, setNw] = useState("");
  const [nw2, setNw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const tooShort = nw.length > 0 && nw.length < 8;
  const mismatch = nw2.length > 0 && nw !== nw2;
  const canSubmit = nw.length >= 8 && nw === nw2 && !busy;

  async function submit() {
    setBusy(true);
    setErr(null);
    const r = await changeToken(oldToken, nw);
    setBusy(false);
    if (!r.ok) setErr(r.e);
  }

  return (
    <Panel
      title="首次登录：设置你自己的访问令牌"
      hint="启动日志里打印的令牌是一次性的。为了安全，必须先把它改成只有你知道的令牌才能进入界面（这一步不可跳过）。"
    >
      <div className="field" style={fieldStyle}>
        <label htmlFor="new_token">新令牌</label>
        <div>
          <input
            id="new_token"
            autoFocus
            type="password"
            value={nw}
            disabled={busy}
            onChange={(e) => setNw(e.target.value)}
          />
        </div>
        <label htmlFor="new_token2">确认新令牌</label>
        <div>
          <input
            id="new_token2"
            type="password"
            value={nw2}
            disabled={busy}
            onChange={(e) => setNw2(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && canSubmit) void submit();
            }}
          />
        </div>
      </div>
      {tooShort ? <div className="cellerr">新令牌太短（至少 8 位）</div> : null}
      {mismatch ? <div className="cellerr">两次输入不一致</div> : null}
      {err ? <div className="cellerr">{err}</div> : null}
      <div className="row" style={{ marginTop: 10 }}>
        <button className="primary" disabled={!canSubmit} onClick={() => void submit()}>
          {busy ? "提交中…" : "设为新令牌"}
        </button>
        <button className="ghost" disabled={busy} onClick={() => void logout()}>
          退出登录
        </button>
      </div>
    </Panel>
  );
}