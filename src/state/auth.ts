// web 模式的会话状态：登录 / 登出 / 改令牌，以及"被 401 拒绝就退回登录页"的那条线。
//
// 桌面端没有会话这回事，所以 status 初值直接是 `authed` —— App 用同一段分支就能两边
// 通吃（见 lib/types.ts 的 SessionState）。
//
// 刻意的例外：登录与改令牌这两条**不走 ipc 的 `call`**，而是自己 fetch。原因是它们的
// 401 是**表单错误**（令牌不对），不是"会话没了"；若经 `call`，那条全局的 401 拦截会把
// 用户从登录/改令牌流程里直接踢出去，反而说不清是哪一步错的。

import { errText, IS_TAURI, setUnauthorizedHandler } from "../lib/ipc";
import type { SessionState } from "../lib/types";
import { createStore, shallowEqual, useStore } from "./store";

export const sessionStore = createStore<SessionState>(
  IS_TAURI
    ? { status: "authed", mustChange: false } // 桌面端：根本没有登录这道门
    : { status: "unknown", mustChange: false }, // web：先问一次服务端
  shallowEqual,
);

export const useSession = () => useStore(sessionStore);

/**
 * 普通命令被 401 拒 = 会话没了，退回登录页。注册给 ipc 的传输层，由它在任何
 * `call()` 收到 401 时触发。
 *
 * 只在"确实已登录（且不在强制改令牌流程里）"时才作废会话：登录 / 改令牌自己的 401
 * 已经绕开了这条线（见文件头），而加载态下的 401 也不该改变什么。
 */
setUnauthorizedHandler(() => {
  const s = sessionStore.get();
  if (s.status === "authed" && !s.mustChange) {
    sessionStore.set({ status: "anon", mustChange: false });
  }
});

type AuthResult<T = null> = { ok: true; v: T } | { ok: false; e: string };

async function postJson<T>(path: string, body: unknown): Promise<AuthResult<T>> {
  try {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) return { ok: false, e: await readError(res) };
    // 这些端点的成功体可能带 must_change，也可能就是 null；缺字段一律当 false。
    return { ok: true, v: (await res.json().catch(() => null)) as T };
  } catch (e) {
    return { ok: false, e: errText(e) };
  }
}

async function readError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string };
    if (body?.error) return body.error;
  } catch {
    /* 体不是 JSON：用状态码兜底 */
  }
  return `HTTP ${res.status}`;
}

/** 用一次性令牌登录。成功后由响应里的 `must_change` 决定要不要弹强制改令牌。 */
export async function login(token: string): Promise<AuthResult> {
  const r = await postJson<{ must_change?: boolean } | null>("/api/login", { token });
  if (!r.ok) return r;
  sessionStore.set({ status: "authed", mustChange: Boolean(r.v?.must_change) });
  return { ok: true, v: null };
}

/** 改令牌。首次登录后这一步不可跳过；400 = 新令牌太弱，401 = 旧令牌不对。 */
export async function changeToken(oldToken: string, newToken: string): Promise<AuthResult> {
  const r = await postJson<null>("/api/token", { old: oldToken, new: newToken });
  if (!r.ok) return r;
  sessionStore.set({ status: "authed", mustChange: false });
  return { ok: true, v: null };
}

export async function logout(): Promise<void> {
  await postJson<null>("/api/logout", {});
  sessionStore.set({ status: "anon", mustChange: false });
}

/**
 * 问一次服务端"我登录了没"（GET /api/session）。App 挂载时调一次。
 *
 * 网络不通也当成未登录 —— 登录页至少能显示、能重试，而不是把界面卡在加载态。
 */
export async function checkSession(): Promise<void> {
  let next: SessionState;
  try {
    const res = await fetch("/api/session");
    if (res.ok) {
      const body = (await res.json().catch(() => null)) as { must_change?: boolean } | null;
      next = { status: "authed", mustChange: Boolean(body?.must_change) };
    } else {
      next = { status: "anon", mustChange: false };
    }
  } catch {
    next = { status: "anon", mustChange: false };
  }
  sessionStore.set(next);
}