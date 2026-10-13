import { useState } from "react";

import { fmtUnix } from "../lib/format";
import type { Rule, RulePreview } from "../lib/types";
import {
  addRule,
  deleteRule,
  moveRule,
  previewRules,
  publishRules,
  revokeSharedRules,
  saveRules,
  setRulesEnabled,
  sortRules,
  updateRuleField,
} from "../state/hive";
import {
  useGroups,
  useRuleDraft,
  useRuleStats,
  useRulesView,
  useService,
  useShared,
  useStatus,
} from "../state/useHive";
import { Empty, Panel, Pill, Row, TableWrap } from "../components/ui";

/** 出口写法的取值表 —— 规则页最容易写错的就是这一栏，所以常驻在表下面。 */
const EGRESS_HELP = (
  <>
    egress 写法：<code>auto</code> · <code>direct</code> · <code>node:10.1.2.3</code>（裸 IP 等价）·{" "}
    <code>alias:gpu-01</code>（仅本地规则可用）· <code>group:db</code> ·{" "}
    <code>group:subnet:10.9.0.0/16</code> · <code>block</code>
  </>
);

export function RulesView() {
  const svc = useService();
  const status = useStatus();
  const rulesView = useRulesView();
  const shared = useShared();
  const stats = useRuleStats();
  const groups = useGroups();
  const { rules, dirty } = useRuleDraft();
  const [preview, setPreview] = useState<RulePreview | null>(null);

  const statsByIndex = new Map(stats.map((s) => [s.index, s]));
  // 共享段 = 合并表里本地段之后的部分。用服务端的 local_count 而不是草稿长度：
  // 草稿被改过时长度会变，共享段的位置不该跟着变。
  const sharedRules = rulesView.table.merged.slice(rulesView.table.local_count);
  const rulesEnabled = status?.rules_enabled ?? rulesView.table.rules_enabled;

  async function onToggleBypass() {
    if (rulesEnabled) {
      const ok = window.confirm(
        "开启全局旁路：所有路由规则（含共享规则集）立即被忽略，只跑内置的网段自动匹配。\n\n" +
          "这是排障用的紧急开关，设置会落盘。确定？",
      );
      if (!ok) return;
    }
    await setRulesEnabled(!rulesEnabled);
  }

  async function onSave() {
    await saveRules();
  }

  async function onPreview() {
    const p = await previewRules();
    if (p) setPreview(p);
  }

  async function onPublish() {
    const ok = window.confirm(
      `把 ${rules.length} 条规则**整份发布**给全网？\n\n` +
        "· 各机器的本地规则仍然优先于它\n" +
        "· 后发布者会整体覆盖先发布者\n" +
        "· 带别名的条目会在发布前解析成 IP，解析不到的会整次拒绝",
    );
    if (!ok) return;
    await publishRules();
  }

  async function onRevoke() {
    const ok = window.confirm(
      "撤回共享规则集：会发布一份**空的**规则集，全网立即回到「只跑本地规则」。确定？",
    );
    if (!ok) return;
    await revokeSharedRules();
  }

  return (
    <>
      <Panel
        actions={
          <>
            <button className={rulesEnabled ? "ghost" : "danger"} onClick={() => void onToggleBypass()}>
              {rulesEnabled ? "全局旁路：关" : "★ 全局旁路已开启"}
            </button>
            <button className="primary" onClick={() => addRule()}>
              + 新增规则
            </button>
          </>
        }
        title="本地规则"
        hint={
          <>
            顺序即优先级，<b>先匹配者胜</b>。本地规则整体排在共享规则之前，所以本地永远能覆盖共享。
            不写任何规则也完全正常 —— 内置的网段自动匹配会兜住绝大多数目标。
          </>
        }
      >
        <div className={`banner soft ${rulesEnabled ? "" : "err"}`}>
          {rulesEnabled
            ? sharedBanner(svc.running, shared)
            : "★ 全局旁路已开启：当前**所有**规则都被忽略，只跑网段自动匹配。"}
        </div>

        <Row>
          <button onClick={() => void sortRules()}>按具体度重排</button>
          <button onClick={() => void onPreview()}>发布前预览</button>
          <button className="primary" onClick={() => void onSave()} disabled={!dirty}>
            {dirty ? "保存本地规则 *" : "保存本地规则"}
          </button>
          <span className="spacer" />
          <button className="ok" onClick={() => void onPublish()}>
            一键发布到全网
          </button>
          <button className="danger" onClick={() => void onRevoke()}>
            撤回共享
          </button>
        </Row>

        <TableWrap>
          <table className="editable">
            <thead>
              <tr>
                <th style={{ width: 34 }}>#</th>
                <th style={{ width: 52 }}>启用</th>
                <th>host</th>
                <th style={{ width: 110 }}>port</th>
                <th style={{ width: 210 }}>egress</th>
                <th style={{ width: 110 }}>不可达</th>
                <th style={{ width: 170 }}>备注</th>
                <th style={{ width: 70 }}>命中</th>
                <th style={{ width: 140 }}>最近出口</th>
                <th style={{ width: 110 }} />
              </tr>
            </thead>
            <tbody>
              {rules.map((r, i) => (
                <RuleRow
                  key={i}
                  index={i}
                  rule={r}
                  hits={statsByIndex.get(i)?.hits ?? 0}
                  lastEgress={statsByIndex.get(i)?.last_egress ?? null}
                />
              ))}

              <tr>
                <td className="lv-debug">⤷</td>
                <td colSpan={8} className="hint" style={{ margin: 0 }}>
                  目标落在已知网段 → 选最近的声明者 <Pill>内置兜底行（只读）</Pill>
                </td>
                <td />
              </tr>

              {sharedRules.map((r, j) => {
                const i = rulesView.table.local_count + j;
                const st = statsByIndex.get(i);
                return (
                  <tr key={`shared-${i}`} className="dim">
                    <td className="lv-debug">{i + 1}</td>
                    <td>
                      <Pill>共享</Pill>
                    </td>
                    <td className="mono">{r.host}</td>
                    <td className="mono">{r.port}</td>
                    <td className="mono">{r.egress}</td>
                    <td>{r.on_unreachable}</td>
                    <td>{r.label}</td>
                    <td>{st?.hits ?? "—"}</td>
                    <td className="mono lv-debug">{st?.last_egress ?? "—"}</td>
                    <td />
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>

        <p className="hint" style={{ marginTop: 10 }}>
          {EGRESS_HELP}
        </p>
      </Panel>

      {preview && (
        <Panel title="发布前预览">
          <pre className="out">{formatPreview(preview)}</pre>
        </Panel>
      )}

      <Panel
        title="候选集（group:）"
        hint="egress = group:<名> 与 group:subnet:<cidr> 的成员来源。网段派生的组随拓扑自动增减。"
      >
        {groups.length === 0 ? (
          <Empty>{svc.running ? "还没有候选集。" : "服务未运行。"}</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 200 }}>名称</th>
                  <th style={{ width: 120 }}>来源</th>
                  <th>成员</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <tr key={g.name}>
                    <td className="mono">{g.name}</td>
                    <td>
                      {g.source === "explicit" ? <Pill>显式</Pill> : <Pill tone="cy">网段派生</Pill>}
                    </td>
                    <td className="mono">{g.members.join(", ") || "（无成员）"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Panel>

      <Panel
        title="规则命中统计"
        hint="「从来没命中」的规则往往意味着写错了，或者被前面的规则完全遮蔽了。"
      >
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th style={{ width: 40 }}>#</th>
                <th>规则</th>
                <th style={{ width: 80 }}>命中</th>
                <th style={{ width: 150 }}>最近出口</th>
                <th style={{ width: 150 }}>最近被拒</th>
              </tr>
            </thead>
            <tbody>
              {stats.length === 0 ? (
                <tr>
                  <td colSpan={5}>
                    <Empty>还没有规则。</Empty>
                  </td>
                </tr>
              ) : (
                stats.map((s) => (
                  <tr key={s.index}>
                    <td className="lv-debug">{s.index + 1}</td>
                    <td className="mono">
                      {s.rule}
                      {s.label ? <span className="lv-debug">（{s.label}）</span> : null}
                    </td>
                    <td>{s.hits === 0 ? <Pill tone="no">0</Pill> : s.hits}</td>
                    <td className="mono lv-debug">{s.last_egress ?? "—"}</td>
                    <td className="lv-debug">{fmtUnix(s.last_rejected_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </TableWrap>
      </Panel>
    </>
  );
}

function RuleRow({
  index,
  rule,
  hits,
  lastEgress,
}: {
  index: number;
  rule: Rule;
  hits: number;
  lastEgress: string | null;
}) {
  const set = (field: keyof Rule, value: string | boolean) => updateRuleField(index, field, value);
  return (
    <tr>
      <td className="lv-debug">{index + 1}</td>
      <td>
        <input
          type="checkbox"
          checked={rule.enabled}
          onChange={(e) => set("enabled", e.target.checked)}
        />
      </td>
      <td>
        <input value={rule.host} onChange={(e) => set("host", e.target.value)} />
      </td>
      <td>
        <input value={rule.port} onChange={(e) => set("port", e.target.value)} />
      </td>
      <td>
        <input value={rule.egress} onChange={(e) => set("egress", e.target.value)} />
      </td>
      <td>
        <select
          value={rule.on_unreachable}
          onChange={(e) => set("on_unreachable", e.target.value)}
        >
          <option value="fallback">fallback</option>
          <option value="fail">fail</option>
        </select>
      </td>
      <td>
        <input value={rule.label} onChange={(e) => set("label", e.target.value)} />
      </td>
      <td>{hits}</td>
      <td className="mono lv-debug">{lastEgress ?? "—"}</td>
      <td>
        <button className="mini ghost" title="上移" onClick={() => moveRule(index, -1)}>
          ↑
        </button>
        <button className="mini ghost" title="下移" onClick={() => moveRule(index, 1)}>
          ↓
        </button>
        <button className="mini danger" title="删除" onClick={() => deleteRule(index)}>
          ✕
        </button>
      </td>
    </tr>
  );
}

function sharedBanner(
  running: boolean,
  shared: ReturnType<typeof useShared>,
): string {
  if (!shared || !shared.source) {
    return running
      ? "共享规则集：无（当前只跑本地规则 + 内置网段匹配）"
      : "服务未运行 —— 规则表暂不可用，但下面的本地规则仍可编辑与保存。";
  }
  const when = shared.issued_at ? new Date(shared.issued_at * 1000).toLocaleString() : "—";
  const who = shared.source_alias ? `${shared.source}（${shared.source_alias}）` : shared.source;
  return (
    `当前共享策略来自 ${who}，revision ${shared.revision}，${shared.rules} 条，发布于 ${when}` +
    (shared.accepted ? "" : "　已拒收")
  );
}

function formatPreview(p: RulePreview): string {
  let out = "";
  if (p.warnings.length > 0) out += `${p.warnings.map((w) => `⚠ ${w}`).join("\n")}\n\n`;
  out += "影响面（相对当前生效的规则表）：\n";
  out += p.changes.length
    ? p.changes.map((c) => `  ${c.target}：${c.from} → ${c.to}`).join("\n")
    : "  （没有变化）";
  out += `\n\n永不命中的条目：${
    p.never_matched.length > 0 ? p.never_matched.map((i) => `#${i + 1}`).join(", ") : "无"
  }`;
  out += `\n黑洞条目：${
    p.blackholes.length > 0 ? p.blackholes.map((i) => `#${i + 1}`).join(", ") : "无"
  }`;
  return out;
}
