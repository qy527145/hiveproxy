import { useState } from "react";

import { endpointToString, fmtBytes } from "../lib/format";
import {
  addSeed,
  closeStream,
  probeTarget,
  removeSeed,
  toast,
} from "../state/hive";
import { useConfig, useService, useStats, useStatus, useStreams } from "../state/useHive";
import { Card, Empty, Panel, Row } from "../components/ui";

// 卡片顺序 = 阅读顺序：先"我连了几条"，再"流量与错误"，最后"我的可达范围"。
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

export function OverviewView() {
  const svc = useService();
  const status = useStatus();
  const stats = useStats();
  const streams = useStreams();
  const config = useConfig();

  const [probeInput, setProbeInput] = useState("");
  const [probeOut, setProbeOut] = useState("—");
  const [seedInput, setSeedInput] = useState("");

  async function onProbe() {
    const target = probeInput.trim();
    if (!target) return;
    const r = await probeTarget(target);
    if (r.ok) {
      const p = r.v;
      setProbeOut(
        `目标      ${endpointToString(p.target)}\n` +
          `出口      ${p.egress}${p.direct ? "（本机直连）" : ""}\n` +
          `命中规则  ${p.matched_rule === null ? "内置网段兜底行" : `#${p.matched_rule + 1}`}\n` +
          `耗时      ${p.rtt_ms} ms`,
      );
    } else {
      setProbeOut(
        `✗ ${r.e}\n\n` +
          "目标不落在任何已知网段、且没有规则命中时就会这样。\n" +
          "看看「拓扑」里有哪些网段，或到「路由规则」写一条指定出口。",
      );
    }
  }

  async function onAddSeed() {
    const addr = seedInput.trim();
    if (!addr) return;
    if (await addSeed(addr)) setSeedInput("");
  }

  async function onCloseStream(peer: string, streamId: number) {
    const r = await closeStream(peer, streamId);
    if (!r.ok) toast(r.e, "err");
  }

  const seeds = config?.peers.seeds ?? [];
  const ready = status !== null && stats !== null;

  return (
    <>
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
            <Card
              label={CARD_LABELS[11]}
              value={status.subnets.join(", ") || "（无）"}
              wide
            />
          </>
        ) : (
          CARD_LABELS.map((label, i) => (
            <Card key={label} label={label} value="—" wide={i === CARD_LABELS.length - 1} />
          ))
        )}
      </div>

      <div className="grid2">
        <Panel title="活跃流" hint="本机 SOCKS5 正在承载的连接。">
          {streams.length === 0 ? (
            <Empty>{svc.running ? "没有活跃流" : "服务未运行"}</Empty>
          ) : (
            <ul className="list scroll">
              {streams.map((s) => (
                <li key={`${s.peer}#${s.stream_id}`}>
                  <span className="mono grow">
                    {s.peer} #{s.stream_id} → {s.target}
                  </span>
                  <button
                    className="mini ghost"
                    onClick={() => void onCloseStream(s.peer, s.stream_id)}
                  >
                    断开
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="出口探测" hint="填一个目标，看它会走哪个出口（不真正建流）。">
          <Row>
            <input
              className="grow"
              placeholder="10.4.0.9:3389"
              value={probeInput}
              onChange={(e) => setProbeInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void onProbe();
              }}
            />
            <button onClick={() => void onProbe()}>探测</button>
          </Row>
          <pre className="out">{probeOut}</pre>
        </Panel>
      </div>

      <Panel
        title="引导种子"
        hint={
          <>
            跨网段的<b>第一条</b>链路只能靠它点火；接通之后，监听端点广播会把其余候选自动补齐。
            每台写 0~1 条即可。
          </>
        }
      >
        <Row>
          <input
            className="grow"
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
    </>
  );
}
