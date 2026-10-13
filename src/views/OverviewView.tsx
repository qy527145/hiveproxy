// 首页 = 四张快捷配置卡 + 底部的运行指标（UI.md §2）。
//
// 为什么把指标挪到后面：指标是"看"的，配置是"做"的。装完一台机器第一件要做的事，
// 是把四个必填项填对；在那之前，12 张指标卡全是 `—`，占着首屏却没有任何信息量。
//
// 四张卡：① 白名单端口（入向）② 引导种子 ③ 出口探测 → 一键生成规则 ④ 代理端口。
// ①②④都是"改一个字段"，走的是 `patchConfig`（先取最新配置再改，服务没跑也能落盘）。

import { useState } from "react";

import { egressLabel } from "../lib/egress";
import { fmtBytes } from "../lib/format";
import type { DialResult, ExitCandidate, StreamProbe } from "../lib/types";
import {
  addRuleWith,
  addSeed,
  closeStream,
  probeDial,
  probeExits,
  probeTarget,
  removeSeed,
  setDefaultEgress,
  setListenPorts,
  setSocks5Bind,
  toast,
} from "../state/hive";
import {
  useConfig,
  useService,
  useStats,
  useStatus,
  useStreams,
  useTopology,
} from "../state/useHive";
import { Card, Empty, Panel, Pill, Row } from "../components/ui";

// 卡片顺序 = 阅读顺序：先"我让别人怎么连上我"，再"我要连谁"，然后"谁来替我出去"，最后"我怎么用"。
const CARD_LABELS = [
  "直连链路",
  "活跃流",
  "中继帧",
  "入向字节",
  "出向字节",
  "丢帧",
  "流被重置",
  "握手 成功/失败",
  "拨号 尝试/失败",
  "gossip 收/发",
  "路由重建",
  "本机可直达网段",
] as const;

/** `10.4.0.9:3389` / `[fd00::1]:80` / `z7+10.1.2.5:3306` → host + port。 */
function splitTarget(s: string): { host: string; port: string } | null {
  const t = s.trim();
  const v6 = t.match(/^(?:z\d+\+)?\[(.+)\]:(\d+)$/);
  if (v6) return { host: v6[1], port: v6[2] };
  const i = t.lastIndexOf(":");
  if (i <= 0) return null;
  const host = t.slice(0, i).replace(/^z\d+\+/, "");
  const port = t.slice(i + 1);
  if (host === "" || !/^\d+$/.test(port)) return null;
  return { host, port };
}

function isDomain(host: string): boolean {
  return !/^\d+\.\d+\.\d+\.\d+$/.test(host) && !host.includes(":");
}

export function OverviewView() {
  const svc = useService();
  const status = useStatus();
  const stats = useStats();
  const streams = useStreams();
  const config = useConfig();
  const topo = useTopology();

  const [probeInput, setProbeInput] = useState("");
  const [probeErr, setProbeErr] = useState<string | null>(null);
  const [auto, setAuto] = useState<StreamProbe | null>(null);
  const [cands, setCands] = useState<ExitCandidate[] | null>(null);
  const [pick, setPick] = useState<string | null>(null);
  const [dials, setDials] = useState<Record<string, DialResult | "…">>({});
  const [seedInput, setSeedInput] = useState("");

  const [portsInput, setPortsInput] = useState<string | null>(null);
  const [socksInput, setSocksInput] = useState<string | null>(null);

  const seeds = config?.peers.seeds ?? [];
  const listenPorts = portsInput ?? (config?.listen.ports ?? []).join(", ");
  const socksBind = socksInput ?? config?.proxy.bind ?? "";
  const defaultEgress = config?.route.default_egress ?? status?.default_egress ?? null;
  const ready = status !== null && stats !== null;

  async function onProbe() {
    const target = probeInput.trim();
    if (!target) return;
    setProbeErr(null);
    setCands(null);
    setDials({});
    const [exits, picked] = await Promise.all([probeExits(target), probeTarget(target)]);
    if (!exits.ok) {
      setProbeErr(exits.e);
      setAuto(null);
      return;
    }
    setCands(exits.v);
    setAuto(picked.ok ? picked.v : null);
    const first = exits.v.find((c) => c.selected) ?? exits.v[0];
    setPick(first ? first.node : null);
  }

  async function onDial(c: ExitCandidate) {
    const target = probeInput.trim();
    setDials((d) => ({ ...d, [c.node]: "…" }));
    const r = await probeDial(target, c.node);
    setDials((d) => ({ ...d, [c.node]: r.ok ? r.v : { target, via: c.node, direct: c.is_self, ok: false, rtt_ms: 0, detail: r.e } }));
  }

  /** 把探测的目标 + 挑中的出口变成一条规则草稿，然后跳到规则页去改备注、保存。 */
  function onMakeRule() {
    const target = splitTarget(probeInput);
    if (!target || !pick) return;
    const isSelf = cands?.find((c) => c.node === pick)?.is_self ?? false;
    addRuleWith({
      label: "",
      host: target.host,
      port: target.port,
      egress: isSelf ? "direct" : `node:${pick}`,
      on_unreachable: "fallback",
      enabled: true,
    });
    toast("已加到规则列表（那边会自动保存）", "ok");
    window.location.hash = "rules";
  }

  async function onSetDefault() {
    if (!pick) return;
    const isSelf = cands?.find((c) => c.node === pick)?.is_self ?? false;
    const value = isSelf ? "direct" : `node:${pick}`;
    if (await setDefaultEgress(value)) toast(`默认出口已设为 ${value}`, "ok");
  }

  async function onAddSeed() {
    const addr = seedInput.trim();
    if (!addr) return;
    if (await addSeed(addr)) setSeedInput("");
  }

  async function onSavePorts() {
    const list = listenPorts
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map(Number);
    if (list.length === 0 || list.some((p) => !Number.isInteger(p) || p <= 0 || p > 65535)) {
      toast("端口要写 1~65535 的整数，多个用逗号分隔", "err");
      return;
    }
    if (await setListenPorts(list)) {
      setPortsInput(null);
      toast("入向端口已保存 —— 需要重启服务才真正生效", "warn", 9000);
    }
  }

  async function onSaveSocks() {
    // 只填端口也认（`1080` → `127.0.0.1:1080`）：默认就是回环，没必要让人每次都打一遍
    const raw = socksBind.trim();
    const v = /^\d+$/.test(raw) ? `127.0.0.1:${raw}` : raw;
    if (!/^(\d{1,3}\.){3}\d{1,3}:\d+$/.test(v) && !/^\[.+]:\d+$/.test(v)) {
      toast("写成 ip:端口，例如 127.0.0.1:1080", "err");
      return;
    }
    if (await setSocks5Bind(v)) {
      setSocksInput(null);
      toast("代理地址已保存 —— 需要重启服务才真正生效", "warn", 9000);
    }
  }

  async function onCloseStream(peer: string, streamId: number) {
    const r = await closeStream(peer, streamId);
    if (!r.ok) toast(r.e, "err");
  }

  const target = splitTarget(probeInput);
  const domainWarning = target && isDomain(target.host);

  return (
    <>
      <div className="statusbar">
        <span className={`dot ${svc.running ? "on" : svc.last_error ? "err" : "off"}`} />
        <span>{svc.running ? "运行中" : svc.last_error ? "启动失败" : "未启动"}</span>
        <span className="sep">·</span>
        <span className="mono">{status?.node_id ?? svc.node_id}</span>
        <span className="sep">·</span>
        <span className="mono">代理 {svc.proxy_bind}</span>
        <span className="sep">·</span>
        <span>{topo.nodes.length} 个节点</span>
        <span className="sep">·</span>
        <button className="linklike" onClick={() => (window.location.hash = "rules")}>
          默认出口：{egressLabel(defaultEgress, topo.nodes)}
        </button>
      </div>

      {status && status.excluded_subnets.length > 0 && (
        <div className="banner soft">
          已从「本机可直达网段」里排除：{status.excluded_subnets.join("；")}
          <span className="lv-debug">
            　（虚拟网卡与假地址池不算真实网络；要改去「配置」页的 share.subnet_deny / subnet_deny_ifaces）
          </span>
        </div>
      )}

      <div className="quickgrid">
        <Panel
          title="① 白名单端口"
          hint={
            <>
              IT 授权给这台机器的<b>入向端口</b> —— 别人就是拨这个端口找到你。
              必须与对端 <code>seeds</code> 里写的端口一致。
            </>
          }
          actions={<Pill>★ 改完需重启</Pill>}
        >
          <Row>
            <input
              className="grow mono"
              value={listenPorts}
              placeholder="5678"
              onChange={(e) => setPortsInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void onSavePorts();
              }}
            />
            <button className="primary" onClick={() => void onSavePorts()}>
              保存
            </button>
          </Row>
          <p className="hint" style={{ marginTop: 8 }}>
            一个就够。多个候选端口用逗号分隔（比如 IT 给了两个还没定用哪个）。
          </p>
        </Panel>

        <Panel
          title="② 引导种子"
          hint="跨网段的第一条链路只能靠它点火；接通之后监听端点广播会把其余候选自动补齐。每台写 0~1 条即可。"
        >
          <Row>
            <input
              className="grow mono"
              placeholder="10.1.2.3:20000"
              value={seedInput}
              onChange={(e) => setSeedInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void onAddSeed();
              }}
            />
            <button onClick={() => void onAddSeed()}>添加</button>
          </Row>
          {seeds.length === 0 ? (
            <Empty>没有种子。同网段可以靠 UDP 自动发现；跨网段必须至少有一条。</Empty>
          ) : (
            <ul className="list">
              {seeds.map((s) => (
                <li key={s}>
                  <span className="mono grow">{s}</span>
                  <button className="mini ghost" onClick={() => void removeSeed(s)}>
                    移除
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          className="span2"
          title="③ 出口探测 → 一键加规则"
          hint={
            <>
              填一个目标，看<b>能</b>从哪儿出去。默认出口与探测都不建流；只有点「实测」才会真的连一次。
            </>
          }
        >
          <Row>
            <input
              className="grow mono"
              placeholder="10.4.0.9:3389（也可以填域名）"
              value={probeInput}
              onChange={(e) => setProbeInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void onProbe();
              }}
            />
            <button className="primary" onClick={() => void onProbe()}>
              探测
            </button>
          </Row>

          {domainWarning && (
            <p className="hint">
              这是<b>域名</b>目标：按域名写的规则，只有在客户端把域名交给代理解析时才命中。
              浏览器多数会自己解析后把 IP 交给代理 —— 那种情况下用 <code>socks5h</code>
              （或曲奇代理的「代理侧解析」）才会走域名匹配。
            </p>
          )}

          {probeErr && <div className="banner err">✗ {probeErr}</div>}

          {auto && (
            <p className="hint">
              当前会自动选中 <b className="mono">{auto.egress}</b>
              {auto.direct ? "（本机直连）" : ""}，来源：
              {auto.via === "rule"
                ? `规则 #${(auto.matched_rule ?? 0) + 1}`
                : auto.via === "default"
                  ? "默认出口"
                  : "内置网段兜底行"}
              　·　{auto.rtt_ms} ms
            </p>
          )}

          {cands && (
            <>
              <div className="tablewrap">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 40 }} />
                      <th>候选出口</th>
                      <th style={{ width: 120 }}>路径</th>
                      <th style={{ width: 200 }}>凭什么</th>
                      <th style={{ width: 90 }}>实测</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cands.map((c) => {
                      const d = dials[c.node];
                      return (
                        <tr
                          key={c.node}
                          className={[pick === c.node ? "sel" : "", c.unusable ? "dim" : ""]
                            .filter(Boolean)
                            .join(" ")}
                          onClick={() => !c.unusable && setPick(c.node)}
                        >
                          <td>
                            <input
                              type="radio"
                              checked={pick === c.node}
                              disabled={!!c.unusable}
                              onChange={() => setPick(c.node)}
                            />
                          </td>
                          <td className="mono">
                            {c.node}
                            {c.alias ? <span className="lv-debug">（{c.alias}）</span> : null}
                            {c.selected ? <Pill tone="cy">自动选中</Pill> : null}
                            {c.is_self ? <Pill>本机</Pill> : null}
                          </td>
                          <td>
                            {c.unusable ? (
                              <Pill tone="no">不可用</Pill>
                            ) : c.is_self ? (
                              "直连"
                            ) : (
                              `${c.hops ?? "?"} 跳 · 成本 ${c.cost ?? "?"}`
                            )}
                          </td>
                          <td className="lv-debug">
                            {c.unusable
                              ? c.unusable
                              : c.declares_target
                                ? "它声明了目标所在的网段"
                                : c.is_self
                                  ? "不进 overlay"
                                  : "没有它声明该网段的证据"}
                          </td>
                          <td>
                            <button
                              className="mini ghost"
                              disabled={!!c.unusable || d === "…"}
                              title="真的建一次连接再立刻关掉"
                              onClick={(e) => {
                                e.stopPropagation();
                                void onDial(c);
                              }}
                            >
                              {d === "…" ? "测试中…" : "实测"}
                            </button>
                            {d && d !== "…" && (
                              <div className={d.ok ? "dialok" : "dialbad"} title={d.detail}>
                                {d.ok ? `✓ ${d.rtt_ms}ms` : "✗"}
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <Row>
                <button className="primary" disabled={!pick || !target} onClick={() => onMakeRule()}>
                  生成规则
                </button>
                <button disabled={!pick} onClick={() => void onSetDefault()}>
                  设为默认出口
                </button>
                <span className="hint" style={{ margin: 0 }}>
                  生成规则会跳到规则页并自动保存 —— 到那儿确认一眼就行。
                </span>
              </Row>
            </>
          )}

          {Object.keys(dials).length > 0 && (
            <p className="hint">
              实测会真的建一次连接（可能短暂出现在「活跃流」里）。它同时验证了
              overlay 这条路<b>和</b>出口那一侧能不能连上目标 —— 路由算得出来不代表连得上。
            </p>
          )}
        </Panel>

        <Panel
          title="④ 代理端口"
          hint={
            <>
              本机应用连这个地址，<b>同一个端口既讲 SOCKS5 也讲 HTTP 代理</b>：
              <code>curl -x</code> / 浏览器的「HTTP 代理」和 <code>curl --socks5-hostname</code> 都能用。默认 1080。
            </>
          }
          actions={<Pill>★ 改完需重启</Pill>}
        >
          <Row>
            <input
              className="grow mono"
              value={socksBind}
              placeholder="127.0.0.1:1080"
              onChange={(e) => setSocksInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void onSaveSocks();
              }}
            />
            <button className="primary" onClick={() => void onSaveSocks()}>
              保存
            </button>
            {socksBind !== "127.0.0.1:1080" && (
              <button
                className="ghost"
                title="恢复成默认的 127.0.0.1:1080"
                onClick={() => setSocksInput("127.0.0.1:1080")}
              >
                恢复 1080
              </button>
            )}
          </Row>
          <p className="hint" style={{ marginTop: 8 }}>
            只填端口也可以（`1080` 会补成 `127.0.0.1:1080`）。
          </p>
        </Panel>
      </div>

      <Panel
        title="运行指标"
        hint="指标口径见 DESIGN.md §6.7。要看细节就切到「日志」页。"
        className="span2"
      >
        <div className="cards">
          {ready ? (
            <>
              <Card label={CARD_LABELS[0]} value={stats.links} />
              <Card
                label={CARD_LABELS[1]}
                value={stats.active_streams}
                tone={stats.active_streams > 0 ? "good" : ""}
              />
              <Card label={CARD_LABELS[2]} value={stats.frames_relayed} />
              <Card label={CARD_LABELS[3]} value={fmtBytes(stats.bytes_relayed_in)} />
              <Card label={CARD_LABELS[4]} value={fmtBytes(stats.bytes_relayed_out)} />
              <Card
                label={CARD_LABELS[5]}
                value={stats.frames_dropped}
                tone={stats.frames_dropped > 0 ? "bad" : ""}
              />
              <Card
                label={CARD_LABELS[6]}
                value={stats.streams_dropped}
                tone={stats.streams_dropped > 0 ? "bad" : ""}
              />
              <Card
                label={CARD_LABELS[7]}
                value={`${stats.handshakes_ok} / ${stats.handshakes_failed}`}
                tone={stats.handshakes_failed > 0 ? "bad" : ""}
              />
              <Card label={CARD_LABELS[8]} value={`${stats.dial_attempts} / ${stats.dial_failures}`} />
              <Card label={CARD_LABELS[9]} value={`${stats.gossip_received} / ${stats.gossip_sent}`} />
              <Card label={CARD_LABELS[10]} value={stats.route_rebuilds} />
              <Card label={CARD_LABELS[11]} value={status.subnets.join(", ") || "（无）"} wide />
            </>
          ) : (
            CARD_LABELS.map((label, i) => (
              <Card key={label} label={label} value="—" wide={i === CARD_LABELS.length - 1} />
            ))
          )}
        </div>

        <Row>
          <span className="sub">活跃流</span>
          <span className="spacer" />
        </Row>
        {streams.length === 0 ? (
          <Empty>{svc.running ? "没有活跃流" : "服务未运行"}</Empty>
        ) : (
          <ul className="list scroll">
            {streams.map((s) => (
              <li key={`${s.peer}#${s.stream_id}`}>
                <span className="mono grow">
                  {s.peer} #{s.stream_id} → {s.target}
                </span>
                <button className="mini ghost" onClick={() => void onCloseStream(s.peer, s.stream_id)}>
                  断开
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}