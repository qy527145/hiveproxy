import { useEffect, useRef, useState } from "react";

import { pingPeer, toast } from "../state/hive";
import { useService, useStatus, useTopology, useZones } from "../state/useHive";
import { Empty, Panel, Pill, TableWrap } from "../components/ui";
import { Dag } from "./Dag";

/** 树边的方向由 BFS 给出；这张表是 DAG 的文字版，两边的排序刻意一致。 */
function sortNodes<T extends { hops: number | null; peer: string }>(nodes: T[]): T[] {
  return nodes
    .slice()
    .sort((a, b) => (a.hops ?? 99) - (b.hops ?? 99) || a.peer.localeCompare(b.peer));
}

export function TopologyView() {
  const svc = useService();
  const status = useStatus();
  const topo = useTopology();
  const zones = useZones();

  const [showLabels, setShowLabels] = useState(true);
  const [showRelay, setShowRelay] = useState(true);
  const [highlight, setHighlight] = useState<string | null>(null);

  // 点 DAG 上的节点 → 把下面表格里对应那行滚到眼前并描一下边。
  // 用 ref 表而不是 querySelector：行的存在与否归 React 管，DOM 查询会打架。
  const rowRefs = useRef(new Map<string, HTMLTableRowElement>());

  useEffect(() => {
    if (highlight === null) return;
    rowRefs.current.get(highlight)?.scrollIntoView({ block: "center", behavior: "smooth" });
    const timer = window.setTimeout(() => setHighlight(null), 1800);
    return () => window.clearTimeout(timer);
  }, [highlight]);

  const selfId = status?.node_id ?? svc.node_id;
  const nodes = sortNodes(topo.nodes);

  return (
    <>
      <Panel
        title="网络拓扑（DAG）"
        hint="以本机为根按跳数分层。亮线＝BFS 主路径，淡线＝其余声明边。点节点可定位到下面的表格。"
        actions={
          <>
            <label className="chk">
              <input
                type="checkbox"
                checked={showLabels}
                onChange={(e) => setShowLabels(e.target.checked)}
              />
              显示地址
            </label>
            <label className="chk">
              <input
                type="checkbox"
                checked={showRelay}
                onChange={(e) => setShowRelay(e.target.checked)}
              />
              显示其余边
            </label>
          </>
        }
      >
        <div className="dagwrap">
          <Dag
            nodes={topo.nodes}
            graph={topo.graph}
            selfId={selfId}
            showLabels={showLabels}
            showRelay={showRelay}
            running={svc.running}
            onSelectNode={setHighlight}
          />
        </div>
        <div className="legend">
          <span>
            <i className="sw self" />
            本机
          </span>
          <span>
            <i className="sw direct" />
            直连
          </span>
          <span>
            <i className="sw relay" />
            经中继
          </span>
          <span>
            <i className="sw nogress" />
            不做出口
          </span>
          <span>
            <i className="sw down" />
            不可达
          </span>
        </div>
      </Panel>

      {zones.length > 0 && (
        <Panel
          title="网段真冲突（§9.3 情形二）"
          hint="同一个私网段被两片互不相邻的孤岛分别声明。片内目标照常填真实 IP；要到片外才需要带区域号。"
        >
          {zones.map((z) => (
            <div key={z.net} style={{ marginBottom: 12 }}>
              <div className="mono" style={{ marginBottom: 4 }}>
                <b>{z.net}</b>
              </div>
              <TableWrap>
                <table>
                  <thead>
                    <tr>
                      <th>区域号</th>
                      <th>成员</th>
                      <th>可达</th>
                      <th>从片外请这样填</th>
                    </tr>
                  </thead>
                  <tbody>
                    {z.islands.map((i) => (
                      <tr key={i.label}>
                        <td className="mono" style={{ color: "var(--cyan)" }}>
                          {i.label}
                        </td>
                        <td className="mono">{i.members.join(", ")}</td>
                        <td>
                          {i.reachable} / {i.members.length}
                        </td>
                        <td className="mono">{i.suggestion}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </div>
          ))}
        </Panel>
      )}

      <Panel title="节点">
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th>节点</th>
                <th>别名</th>
                <th>共享网段</th>
                <th>监听</th>
                <th>跳数</th>
                <th>成本</th>
                <th>路径</th>
                <th>出口</th>
                <th>心跳</th>
              </tr>
            </thead>
            <tbody>
              {nodes.length === 0 ? (
                <tr>
                  <td colSpan={9}>
                    <Empty>
                      {svc.running
                        ? "还没有任何节点。配一条 seeds，或等同网段的 UDP 发现。"
                        : "服务未运行。"}
                    </Empty>
                  </td>
                </tr>
              ) : (
                nodes.map((n) => (
                  <tr
                    key={n.peer}
                    ref={(el) => {
                      if (el) rowRefs.current.set(n.peer, el);
                      else rowRefs.current.delete(n.peer);
                    }}
                    className={[
                      n.is_self ? "self" : n.reachable ? "" : "dim",
                      highlight === n.peer ? "flash" : "",
                    ]
                      .filter(Boolean)
                      .join(" ")}
                  >
                    <td className="mono">
                      {n.peer}
                      {n.is_self ? " ← 本机" : ""}
                    </td>
                    <td>{n.alias ?? ""}</td>
                    <td className="mono">
                      {n.subnets.join(", ") || <span className="lv-debug">—</span>}
                    </td>
                    <td className="mono">
                      {n.listen.join(", ") || <span className="lv-debug">—</span>}
                    </td>
                    <td>{n.hops ?? "—"}</td>
                    <td>{n.cost ?? "—"}</td>
                    <td>
                      {n.is_self ? (
                        <Pill tone="cy">本机</Pill>
                      ) : n.direct ? (
                        <Pill tone="cy">直连</Pill>
                      ) : n.reachable ? (
                        <Pill>经中继</Pill>
                      ) : (
                        <Pill tone="no">不可达</Pill>
                      )}
                    </td>
                    <td>{n.accepts_egress ? "是" : <Pill tone="no">否</Pill>}</td>
                    <td className="lv-debug">{n.last_seen_ms} ms</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </TableWrap>
      </Panel>

      <Panel title="直连链路">
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th>对端</th>
                <th>载体</th>
                <th>健康</th>
                <th>拨号方</th>
                <th>RTT</th>
                <th>成本</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {topo.edges.length === 0 ? (
                <tr>
                  <td colSpan={7}>
                    <Empty>没有直连链路。</Empty>
                  </td>
                </tr>
              ) : (
                topo.edges.map((e) => (
                  <tr key={e.to}>
                    <td className="mono">{e.to}</td>
                    <td>{e.carrier === "lan" ? <Pill tone="cy">同网段</Pill> : "跨网段"}</td>
                    <td>
                      {e.health === "up" ? (
                        <Pill tone="ok">up</Pill>
                      ) : (
                        <Pill tone="no">{e.health}</Pill>
                      )}
                    </td>
                    <td>{e.establisher === "local" ? "本机拨出" : "对方拨入"}</td>
                    <td>{e.rtt_ms} ms</td>
                    <td>{e.cost}</td>
                    <td>
                      <button
                        className="mini ghost"
                        onClick={async () => {
                          const r = await pingPeer(e.to);
                          if (r.ok) toast(`${e.to} RTT ≈ ${r.v} ms`, "ok");
                          else toast(r.e, "err");
                        }}
                      >
                        ping
                      </button>
                    </td>
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
