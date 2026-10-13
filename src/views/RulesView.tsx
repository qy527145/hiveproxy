// 路由规则页 ——**按 SwitchyOmega 的「切换规则」那一页来做**（UI.md §3）。
//
// 它那页长这样，一行一条，没有别的：
//
//   排序 │ 条件类型 │ 条件设置 │ 情景模式 │ 操作
//
// 这个形状是**有意**的：条件类型是下拉、条件设置是**一个**输入框、出口是下拉，
// 剩下的一律收进"操作"或收进引擎。上一版把它做成了 12 列的控件墙（启用 / host /
// 端口 / 出口 / 不可达 / 备注 / 命中 / 最近出口…），用户的原话是"不知所谓" ——
// 控件越多，越看不出"这个目标从哪儿出去"这一件事。
//
// 因此这一版的几条规矩：
// 1. **一行只有三样要填的**：条件类型、条件设置（`host[:port]` 一个框）、出口；
// 2. 端口折进条件设置里（`10.4.0.9:3389`），不给单独一列；
// 3. 改完**自动保存**（SwitchyOmega 也没有保存按钮）—— 下面是引擎的 `set_rules`，
//    落盘 + 热生效；保存前的行内校验用 `check_rules` 兜住"一整份失败"的老毛病；
// 4. 启用/不可达/备注是**次要**的：收进每行的「⋯」，点开才出现；
// 5. 命中统计不进表格，留在下面那张表里（那里才是看统计的地方）。

import { useEffect, useRef, useState } from "react";

import { fmtUnix } from "../lib/format";
import { egressOptions, formatEgress, parseEgress, type EgressKind } from "../lib/egress";
import {
  HOST_KINDS,
  type HostKind,
  convertCondition,
  formatCondition,
  parseHost,
  splitCondition,
} from "../lib/match";
import type { Rule, RuleIssue, RulePreview } from "../lib/types";
import {
  addRule,
  checkRules,
  deleteRule,
  moveRule,
  previewRules,
  publishRules,
  revokeSharedRules,
  saveRules,
  setDefaultEgress,
  setRulesEnabled,
  sortRules,
  toast,
  updateRuleField,
} from "../state/hive";
import {
  useConfig,
  useGroups,
  useRuleDraft,
  useRuleStats,
  useRulesView,
  useService,
  useShared,
  useStatus,
  useTopology,
} from "../state/useHive";
import { Empty, Panel, Pill, Row, TableWrap } from "../components/ui";

const AUTOSAVE_MS = 600;

export function RulesView() {
  const svc = useService();
  const status = useStatus();
  const rulesView = useRulesView();
  const shared = useShared();
  const stats = useRuleStats();
  const groups = useGroups();
  const topo = useTopology();
  const config = useConfig();
  const { rules, dirty } = useRuleDraft();

  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [issues, setIssues] = useState<RuleIssue[]>([]);
  const [showHelp, setShowHelp] = useState(false);
  const [open, setOpen] = useState<Record<number, boolean>>({}); // 每行的「⋯」展开
  const [kinds, setKinds] = useState<Record<string, HostKind>>({}); // 条件类型的覆盖（见 lib/match.ts）
  const [saveState, setSaveState] = useState<
    "idle" | "saving" | "saved" | "blocked" | "failed" | "offline"
  >("idle");

  const saving = useRef(false);
  const again = useRef(false);

  const statsByIndex = new Map(stats.map((s) => [s.index, s]));
  const sharedRules = rulesView.table.merged.slice(rulesView.table.local_count);
  const rulesEnabled = status?.rules_enabled ?? rulesView.table.rules_enabled;
  const defaultEgress = config?.route.default_egress ?? status?.default_egress ?? null;

  const options = egressOptions(topo.nodes, groups, config?.peers.entry ?? []);

  const issuesByIndex = new Map<number, RuleIssue[]>();
  for (const i of issues) {
    const list = issuesByIndex.get(i.index);
    if (list) list.push(i);
    else issuesByIndex.set(i.index, [i]);
  }
  const blocked = issues.length > 0;

  // ---- 行内校验：草稿一变就（防抖地）问一次引擎 ----
  // 前端不自己解析语法：解析规则的是引擎，在界面上再抄一遍，两份实现迟早对不上。
  useEffect(() => {
    if (rules.length === 0) {
      setIssues([]);
      return;
    }
    let alive = true;
    const t = window.setTimeout(() => {
      void checkRules(rules).then((r) => {
        if (!alive) return;
        setIssues(r.ok ? r.v : []);
      });
    }, 200);
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [rules]);

  // ---- 自动保存：校验没问题才存；一次只飞一个请求，飞完再补下一次 ----
  //
  // 服务没跑时**不存**：`set_rules` 走的是引擎 API，节点不在就够不着；这时绝不能
  // 退化成"直接写配置文件" —— 那样没经过引擎校验的规则会落进 TOML，下次启动直接解析失败。
  // 改动留在本地，服务一起来（svc.running 进依赖）就自动补存。
  useEffect(() => {
    if (!dirty) return;
    if (!svc.running) {
      setSaveState("offline");
      return;
    }
    if (blocked) {
      setSaveState("blocked");
      return;
    }
    const t = window.setTimeout(() => void flush(), AUTOSAVE_MS);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rules, dirty, blocked, svc.running]);

  async function flush() {
    if (saving.current) {
      again.current = true;
      return;
    }
    saving.current = true;
    setSaveState("saving");
    const ok = await saveRules({ silent: true });
    saving.current = false;
    setSaveState(ok ? "saved" : "failed");
    if (again.current) {
      again.current = false;
      await flush();
    }
  }

  // ---- 增删/上下移会打乱行号，条件类型的覆盖表跟着作废（之后从字符串重新推导）----
  function onAdd() {
    setKinds({});
    addRule();
  }
  function onMove(index: number, dir: -1 | 1) {
    setKinds({});
    moveRule(index, dir);
  }
  function onDelete(index: number) {
    setKinds({});
    setOpen({});
    deleteRule(index);
  }

  async function onToggleBypass() {
    if (rulesEnabled) {
      const ok = window.confirm(
        "开启全局旁路：所有路由规则（含共享规则集）立即被忽略，只跑内置的网段自动匹配。\n\n" +
          "默认出口不在此列 —— 它是配置而不是规则，仍然生效。\n" +
          "这是排障用的紧急开关，设置会落盘。确定？",
      );
      if (!ok) return;
    }
    await setRulesEnabled(!rulesEnabled);
  }

  async function onPreview() {
    const p = await previewRules();
    if (p) setPreview(p);
  }

  async function onPublish() {
    if (blocked) {
      toast("有行还没填对，先把红字那几行改好", "warn");
      return;
    }
    const ok = window.confirm(
      `把 ${rules.length} 条规则整份发布给全网？\n\n` +
        "· 各机器的本地规则仍然优先于它\n" +
        "· 后发布者会整体覆盖先发布者\n" +
        "· 带别名的条目会在发布前解析成 IP，解析不到的会整次拒绝",
    );
    if (!ok) return;
    await publishRules();
  }

  async function onRevoke() {
    const ok = window.confirm(
      "撤回共享规则集：会发布一份空的规则集，全网立即回到「只跑本地规则」。确定？",
    );
    if (!ok) return;
    await revokeSharedRules();
  }

  async function onDefaultEgress(value: string) {
    if (await setDefaultEgress(value === "" ? null : value)) {
      toast(value === "" ? "已清除默认出口" : `默认出口：${value}`, "ok");
    }
  }

  return (
    <>
      <Panel
        title="默认出口"
        hint={
          <>
            规则与网段匹配都没命中时，从这儿出去 —— 相当于 SwitchyOmega 的「默认情景模式」。
            域名与没被任何节点声明过的公网 IP 全落在这一格；内网目标仍然自动就近，不受它影响。
          </>
        }
        actions={
          <button
            className={rulesEnabled ? "ghost" : "danger"}
            onClick={() => void onToggleBypass()}
            title="全局旁路：忽略全部规则，只跑网段自动匹配（排障用）"
          >
            {rulesEnabled ? "全局旁路：关" : "★ 全局旁路已开启"}
          </button>
        }
      >
        <Row>
          <select
            className="grow"
            value={defaultEgress ?? ""}
            onChange={(e) => void onDefaultEgress(e.target.value)}
          >
            <option value="">不设 —— 这类目标直接报「不可达」</option>
            {/* `auto` 就是网段匹配本身；`block` 等于一键拒绝全部流量。引擎也会拒绝这两个，
                所以干脆不列出来（省掉一次"选完才被告知不行"）。 */}
            {options
              .filter((o) => o.value !== "auto" && o.value !== "block")
              .map((o) => (
                <option key={o.value} value={o.value}>
                  {o.group ? `${o.group} · ${o.label}` : o.label}
                </option>
              ))}
          </select>
        </Row>
      </Panel>

      <Panel
        title="规则列表"
        hint="自上而下先匹配者胜，改完自动保存。"
        actions={
          <>
            <span className={`savestate ${saveState}`}>{saveLabel(saveState, dirty)}</span>
            <button className="ghost" onClick={() => setShowHelp((v) => !v)} title="这页是怎么回事">
              {showHelp ? "收起说明" : "说明"}
            </button>
            <button className="primary" onClick={onAdd}>
              + 新增规则
            </button>
          </>
        }
      >
        {showHelp && (
          <div className="banner soft">
            本地规则整体排在共享规则之前，所以本地永远能覆盖共享。一条都不写也完全正常 ——
            内置的网段自动匹配会兜住绝大多数目标，剩下的交给上面的「默认出口」。
            <br />
            条件设置那一个框写的是<b>目标</b>：<code>*.corp.example.com</code> ·{" "}
            <code>10.9.0.0/16</code> · <code>10.4.0.9:3389</code> ·{" "}
            <code>10.9.0.0/16:8000-9000</code>（不写端口 = 任意端口；IPv6 带端口写{" "}
            <code>[fd00::1]:443</code>）。
          </div>
        )}

        <div className={`banner soft ${rulesEnabled ? "" : "err"}`}>
          {rulesEnabled
            ? sharedBanner(svc.running, shared)
            : "★ 全局旁路已开启：当前所有规则都被忽略，只跑网段自动匹配。"}
        </div>

        <TableWrap>
          <table className="rules">
            <thead>
              <tr>
                <th style={{ width: 72 }}>排序</th>
                <th style={{ width: 130 }}>条件类型</th>
                <th>条件设置</th>
                <th style={{ width: 300 }}>出口</th>
                <th style={{ width: 96 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {rules.length === 0 && (
                <tr>
                  <td colSpan={5}>
                    <Empty>
                      还没有规则 —— 这很正常。点「+ 新增规则」，或到首页用「出口探测」挑一个出口生成。
                    </Empty>
                  </td>
                </tr>
              )}

              {rules.map((r, i) => (
                <RuleRow
                  key={i}
                  index={i}
                  rule={r}
                  issues={issuesByIndex.get(i) ?? []}
                  options={options}
                  expanded={!!open[i]}
                  onExpand={() => setOpen((o) => ({ ...o, [i]: !o[i] }))}
                  kindHost={kinds[`${i}:host`]}
                  onKind={(k) => setKinds((m) => ({ ...m, [`${i}:host`]: k }))}
                  onMove={(dir) => onMove(i, dir)}
                  onDelete={() => onDelete(i)}
                />
              ))}

              <tr className="readonly">
                <td colSpan={4} className="hint" style={{ margin: 0 }}>
                  ⤷ 目标落在已知网段 → 选最近的声明者
                </td>
                <td>
                  <Pill>内置兜底</Pill>
                </td>
              </tr>
              <tr className="readonly">
                <td colSpan={4} className="hint" style={{ margin: 0 }}>
                  ⤷ 上面都没命中 → 默认出口：
                  <b className="mono"> {defaultEgress ?? "（没设）"}</b>
                  <span className="lv-debug">　（在最上面那张卡里改）</span>
                </td>
                <td />
              </tr>

              {sharedRules.map((r, j) => {
                const i = rulesView.table.local_count + j;
                const st = statsByIndex.get(i);
                return (
                  <tr key={`shared-${i}`} className="readonly dim">
                    <td />
                    <td>
                      <Pill>共享</Pill>
                    </td>
                    <td className="mono">
                      {formatCondition(r.host, r.port)}
                      {r.label ? <span className="lv-debug">　{r.label}</span> : null}
                    </td>
                    <td className="mono">{r.egress}</td>
                    <td className="lv-debug">{st?.hits ?? "—"} 次</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>

        <Row>
          <button className="ghost" onClick={() => void sortRules()} title="把范围更具体的排到前面">
            按具体度重排
          </button>
          <button className="ghost" onClick={() => void onPreview()}>
            发布前预览
          </button>
          <span className="spacer" />
          <button className="ok" onClick={() => void onPublish()}>
            一键发布到全网
          </button>
          <button className="danger" onClick={() => void onRevoke()}>
            撤回共享
          </button>
        </Row>

        {blocked && (
          <p className="hint err" style={{ marginTop: 8 }}>
            有 {issues.length} 处还没填对（见行内红字）：改好之前，这一份不会保存 ——
            引擎里仍然是上一次有效的那份。
          </p>
        )}
      </Panel>

      {preview && (
        <Panel title="发布前预览" actions={<button className="ghost" onClick={() => setPreview(null)}>关闭</button>}>
          <pre className="out">{formatPreview(preview)}</pre>
        </Panel>
      )}

      <Panel
        title="规则命中统计"
        hint="「从来没命中」的规则往往意味着写错了，或者被前面的规则完全遮蔽了。"
      >
        <TableWrap className="tight">
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

      <Panel
        title="候选集（group:）"
        hint="出口下拉里「候选集」那些选项的成员来源。网段派生的组随拓扑自动增减。"
      >
        {groups.length === 0 ? (
          <Empty>{svc.running ? "还没有候选集。" : "服务未运行。"}</Empty>
        ) : (
          <TableWrap className="tight">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 220 }}>名称</th>
                  <th style={{ width: 110 }}>来源</th>
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
    </>
  );
}

/**
 * 一行规则：`排序 │ 条件类型 │ 条件设置 │ 出口 │ 操作`。
 *
 * 展开「⋯」才出现的三样是**次要**的：启用、不可达时怎么办、备注。它们都要有，
 * 但不该在一眼看上去的时候跟"这个目标从哪儿出去"抢位置。
 */
function RuleRow({
  index,
  rule,
  issues,
  options,
  expanded,
  onExpand,
  kindHost,
  onKind,
  onMove,
  onDelete,
}: {
  index: number;
  rule: Rule;
  issues: RuleIssue[];
  options: ReturnType<typeof egressOptions>;
  expanded: boolean;
  onExpand: () => void;
  kindHost?: HostKind;
  onKind: (k: HostKind) => void;
  onMove: (dir: -1 | 1) => void;
  onDelete: () => void;
}) {
  const set = (field: keyof Rule, value: string | boolean) => updateRuleField(index, field, value);
  const errOf = (field: string) => issues.find((i) => i.field === field)?.message ?? null;

  const parsed = parseHost(rule.host);
  const kind = kindHost ?? parsed.kind;
  const port = rule.port === "" ? "*" : rule.port;
  const egress = parseEgress(rule.egress);
  const egressValue = options.some((o) => o.value === rule.egress) ? rule.egress : "__other__";

  /** 条件设置那一个框的内容（`host[:port]`）。 */
  const fieldText = formatCondition(rule.host, port);

  return (
    <>
      <tr className={[issues.length > 0 ? "bad" : "", rule.enabled ? "" : "dim"].join(" ")}>
        <td className="ordcell">
          <div>
            <span className="ord">{index + 1}</span>
            <span className="mvpair">
              <button className="mini ghost" title="上移" onClick={() => onMove(-1)}>
                ↑
              </button>
              <button className="mini ghost" title="下移" onClick={() => onMove(1)}>
                ↓
              </button>
            </span>
            {!rule.enabled && <Pill tone="no">已停用</Pill>}
          </div>
        </td>

        <td>
          <select
            className="full"
            value={kind}
            onChange={(e) => {
              const k = e.target.value as HostKind;
              onKind(k);
              if (k === "any") {
                set("host", "*"); // 显式选"任意"才是 `*`
                return;
              }
              if (fieldText.trim() === "") return; // 还没填：只换类型，别替它写东西
              const sp = splitCondition(convertCondition(k, parsed, port));
              set("host", sp.host);
              set("port", sp.port);
            }}
          >
            {HOST_KINDS.map((k) => (
              <option key={k.kind} value={k.kind}>
                {k.label}
              </option>
            ))}
          </select>
        </td>

        <td>
          {/*
            ★ 这个框**永远可编辑**。早先"任意"时把它 disable 掉，于是把内容删到只剩 `*`
            （解析回"任意"）的那一瞬间它就变成只读 —— 看上去就是"`*` 删不掉、也改不了"。
            现在的规矩：
            · 框里显示的就是引擎里那个字符串（"任意"显示为 `*`）；想写条件直接打字，
              类型**跟着内容走**（打了 `1` 就是精确主机，打了 `*.x` 就是域名后缀）；
            · 删空 = "还没填"（引擎会回 `host 不能为空`，红字在行内，不会静默变成 `*:*`）；
            · 真要"匹配所有目标"，把类型显式选成「任意」——那时才是 `*`。
          */}
          <input
            className="mono full"
            value={fieldText}
            placeholder="10.4.0.9:3389 / *.corp.example.com / 10.9.0.0/16"
            onChange={(e) => {
              const text = e.target.value;
              if (text.trim() === "") {
                set("host", "");
                set("port", "*");
                return;
              }
              const sp = splitCondition(text);
              const next = parseHost(sp.host).kind;
              if (next !== kind) onKind(next);
              set("host", sp.host);
              set("port", sp.port);
            }}
          />
          {errOf("host") && <div className="cellerr">{errOf("host")}</div>}
          {errOf("port") && <div className="cellerr">{errOf("port")}</div>}
          {!errOf("host") && !errOf("port") && (
            <div className="rowhint">{describe(kind, rule.host, port)}</div>
          )}
          {/* `*:*` 是允许的（§18 第 8 条），但它会兜住所有没被前面规则命中的流量 ——
              引擎在配置告警里也会说这件事，这里让它在**写下这一行的当下**就看得见。
              只认 `host === "*"`：删空的格子（待填）不该同时背上这条警告。 */}
          {rule.host === "*" && (port === "*" || port === "") && (
            <div className="rowhint warn">⚠ 会兜住所有未被前面规则命中的目标</div>
          )}
        </td>

        <td>
          <select
            className="full"
            value={egressValue}
            onChange={(e) => {
              if (e.target.value === "__other__") return;
              set("egress", e.target.value);
            }}
          >
            {options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.group ? `${o.group} · ${o.label}` : o.label}
              </option>
            ))}
            <option value="__other__">其它（手填）</option>
          </select>
          {egressValue === "__other__" && (
            <div className="row nowrap" style={{ marginTop: 4 }}>
              <select
                value={egress.kind}
                onChange={(e) => set("egress", formatEgress(e.target.value as EgressKind, egress.value))}
              >
                {(["node", "alias", "group", "auto", "direct", "block", "raw"] as EgressKind[]).map(
                  (k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ),
                )}
              </select>
              <input
                className="grow mono"
                value={egress.value}
                placeholder="10.1.2.3 / db / gpu-01"
                onChange={(e) => set("egress", formatEgress(egress.kind, e.target.value))}
              />
            </div>
          )}
          {errOf("egress") && <div className="cellerr">{errOf("egress")}</div>}
        </td>

        <td className="opcell">
          <div>
            <button
              className={`mini ghost ${expanded ? "on" : ""}`}
              title="更多设置（启用 / 不可达时 / 备注）"
              onClick={onExpand}
            >
              ⋯
            </button>
            <button className="mini danger" title="删除这条" onClick={() => onDelete()}>
              ✕
            </button>
          </div>
        </td>
      </tr>

      {expanded && (
        <tr className="subrow">
          <td />
          <td colSpan={4}>
            <Row>
              <label className="chk">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={(e) => set("enabled", e.target.checked)}
                />
                启用
              </label>
              <span className="hint" style={{ margin: 0 }}>
                出口不可用时：
              </span>
              <select
                value={rule.on_unreachable}
                onChange={(e) => set("on_unreachable", e.target.value)}
              >
                <option value="fallback">顺延下一条</option>
                <option value="fail">直接失败</option>
              </select>
              <input
                className="grow"
                value={rule.label}
                placeholder="备注（只给你自己看，不参与匹配）"
                onChange={(e) => set("label", e.target.value)}
              />
            </Row>
            <div className="rowhint">
              引擎里的写法：host = <code>{rule.host}</code> · port = <code>{rule.port}</code> ·
              egress = <code>{rule.egress}</code>
            </div>
          </td>
        </tr>
      )}

      {/* 报错**只显示一次**，就在出错的那一格下面（见上面的 errOf）。
          原先这里还有一整行重复的红字，同一句话出现两遍比不显示还糟。 */}
    </>
  );
}

/** 把这一行翻译成人话，压在输入框下面 —— 单框写法最需要的就是这个。 */
function describe(kind: HostKind, host: string, port: string): string {
  const h = parseHost(host);
  const head =
    kind === "suffix"
      ? `域名后缀 ${h.value || "（还没填）"} 及其子域`
      : kind === "exact"
        ? `只匹配 ${h.value || "（还没填）"} 这一个地址`
        : kind === "cidr"
          ? `匹配 ${h.value || "（还没填）"} 里所有地址`
          : "所有目标";
  const tail = port === "*" || port === "" ? "任意端口" : `端口 ${port}`;
  return `${head} · ${tail}`;
}

type SaveState = "idle" | "saving" | "saved" | "blocked" | "failed" | "offline";

function saveLabel(state: SaveState, dirty: boolean): string {
  switch (state) {
    case "saving":
      return "保存中…";
    case "saved":
      return dirty ? "有改动…" : "已保存";
    case "blocked":
      return "有行没填对";
    case "failed":
      return "保存失败";
    case "offline":
      return "服务未运行 · 改动待保存";
    default:
      return dirty ? "有改动…" : "";
  }
}

function sharedBanner(running: boolean, shared: ReturnType<typeof useShared>): string {
  if (!shared || !shared.source) {
    return running
      ? "共享规则集：无（当前只跑本地规则 + 内置网段匹配 + 默认出口）"
      : "服务未运行 —— 规则可以编辑，但存不进引擎（edit 本身不落盘）；点左下角「启动」，改动会自动补存。";
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