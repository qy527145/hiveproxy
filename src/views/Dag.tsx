// 拓扑 DAG：以本机为根、按 BFS 跳数分层的声明图。
//
// 为什么手写 SVG 而不引图库：这张图的性质很具体 —— 有根、分层、边数少
// （一台机器几十条边），布局算法总共三十行。引一个通用图库反而要跟它的
// 力导向/交互模型较劲，还多一份依赖要联网装。
//
// 亮线 = BFS 主路径（树边），淡线 = 其余声明边。位置只由跳数决定，
// 所以拓扑没变时画面是稳定的，不会每次刷新都"跳一下"。

import { useMemo } from "react";

import type { GraphEdge, NodeId, NodeView } from "../lib/types";

const NODE_W = 134;
const NODE_H = 46;
const GAP_Y = 22;
const GAP_X = 116;
const PAD = 28;

interface Layout {
  pos: Map<NodeId, { x: number; y: number }>;
  parents: Map<NodeId, NodeId>;
  width: number;
  height: number;
  empty: boolean;
}

/** 从本机出发在声明图里做 BFS：得到跳数与父节点（DAG 的树边）。 */
function layout(nodes: NodeView[], graph: GraphEdge[], selfId: string): Layout {
  const adj = new Map<NodeId, NodeId[]>();
  const link = (a: NodeId, b: NodeId) => {
    const list = adj.get(a);
    if (list) list.push(b);
    else adj.set(a, [b]);
  };
  for (const e of graph) {
    link(e.from, e.to);
    link(e.to, e.from); // 会话双向可用（§3.1）
  }

  const depth = new Map<NodeId, number>([[selfId, 0]]);
  const parents = new Map<NodeId, NodeId>();
  const queue: NodeId[] = [selfId];
  for (let i = 0; i < queue.length; i++) {
    const cur = queue[i];
    const d = depth.get(cur) ?? 0;
    for (const next of adj.get(cur) ?? []) {
      if (depth.has(next)) continue;
      depth.set(next, d + 1);
      parents.set(next, cur);
      queue.push(next);
    }
  }

  const layers = new Map<number, NodeView[]>();
  const orphans: NodeView[] = [];
  for (const n of nodes) {
    const d = depth.get(n.peer);
    if (d === undefined) {
      orphans.push(n);
      continue;
    }
    const layer = layers.get(d);
    if (layer) layer.push(n);
    else layers.set(d, [n]);
  }
  // 直连的排前面：同层里"离我最近的那几个"看起来应当在最上面
  for (const arr of layers.values()) {
    arr.sort((a, b) => Number(b.direct) - Number(a.direct) || a.peer.localeCompare(b.peer));
  }
  orphans.sort((a, b) => a.peer.localeCompare(b.peer));

  const colX = (d: number) => PAD + d * (NODE_W + GAP_X);
  const colH = (arr: unknown[]) => arr.length * (NODE_H + GAP_Y) - GAP_Y;
  const heights = [...layers.values()].map(colH);
  if (orphans.length > 0) heights.push(colH(orphans));
  const maxCol = Math.max(1, ...heights);

  const pos = new Map<NodeId, { x: number; y: number }>();
  let maxDepth = 0;
  for (const [d, arr] of layers) {
    maxDepth = Math.max(maxDepth, d);
    const top = PAD + Math.max(0, (maxCol - colH(arr)) / 2);
    arr.forEach((n, i) => pos.set(n.peer, { x: colX(d), y: top + i * (NODE_H + GAP_Y) }));
  }
  // 够不着的节点单独摆一列：不参与分层，但也别让它们从图上消失
  const orphanX = colX(maxDepth + 1);
  orphans.forEach((n, i) => pos.set(n.peer, { x: orphanX, y: PAD + i * (NODE_H + GAP_Y) }));

  const width = colX(maxDepth + (orphans.length > 0 ? 2 : 0)) + NODE_W + PAD;
  const height = Math.max(260, maxCol + PAD * 2);

  return { pos, parents, width: Math.max(width, 400), height: Math.max(height, 240), empty: nodes.length === 0 };
}

export function Dag({
  nodes,
  graph,
  selfId,
  showLabels,
  showRelay,
  running,
  onSelectNode,
  defaultEgressNode,
}: {
  nodes: NodeView[];
  graph: GraphEdge[];
  selfId: string;
  showLabels: boolean;
  showRelay: boolean;
  running: boolean;
  onSelectNode?: (peer: NodeId) => void;
  /** 当前默认出口所在的节点 —— 图上要能一眼认出来（UI.md §4.3）。 */
  defaultEgressNode?: string | null;
}) {
  const { pos, parents, width, height, empty } = useMemo(
    () => layout(nodes, graph, selfId),
    [nodes, graph, selfId],
  );

  const edges: React.ReactElement[] = [];
  const drawn = new Set<string>();
  const addEdge = (a: NodeId, b: NodeId, tree: boolean) => {
    const key = [a, b].sort().join("|");
    if (drawn.has(key)) return;
    drawn.add(key);
    const pa = pos.get(a);
    const pb = pos.get(b);
    if (!pa || !pb) return;
    const forward = pa.x < pb.x;
    const x1 = forward ? pa.x + NODE_W : pa.x;
    const x2 = forward ? pb.x : pb.x + NODE_W;
    const y1 = pa.y + NODE_H / 2;
    const y2 = pb.y + NODE_H / 2;
    const mx = (x1 + x2) / 2;
    edges.push(
      <path
        key={`${key}:${tree ? "t" : "o"}`}
        d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
        stroke={tree ? "#4fd1c5" : "#333c4e"}
        strokeWidth={tree ? 1.6 : 1}
        fill="none"
        opacity={tree ? 0.7 : 0.45}
        markerEnd={tree ? "url(#dag-arrow)" : undefined}
      />,
    );
  };

  for (const [child, parent] of parents) addEdge(parent, child, true);
  if (showRelay) for (const e of graph) addEdge(e.from, e.to, false);

  return (
    <svg id="dag" width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      <defs>
        <marker id="dag-arrow" markerWidth="9" markerHeight="7" refX="8.5" refY="3.5" orient="auto">
          <path d="M0,0 L9,3.5 L0,7 z" fill="#4fd1c5" />
        </marker>
      </defs>

      {edges}

      {nodes.map((n) => {
        const p = pos.get(n.peer);
        if (!p) return null;
        const isSelf = n.peer === selfId;
        let stroke = "#5b6b8f";
        let fill = "#1b2333";
        let text = "#e8ebf2";
        if (isSelf) {
          stroke = "#ffc857";
          fill = "#3a2f13";
          text = "#ffc857";
        } else if (!n.reachable) {
          stroke = "#39404f";
          fill = "#14161c";
          text = "#5d6577";
        } else if (n.direct) {
          stroke = "#4fd1c5";
          fill = "#16302c";
        } else if (!n.accepts_egress) {
          stroke = "#e5657a";
          fill = "#332027";
        }
        const isDefault = defaultEgressNode === n.peer;
        const name = n.alias || n.peer;
        const relay = n.hops ? `${n.hops} 跳` : "直连";
        const badge = isSelf
          ? "本机"
          : !n.reachable
            ? "不可达"
            : `${relay}${n.accepts_egress ? "" : " · 不做出口"}`;
        return (
          <g
            key={n.peer}
            className="dag-node"
            onClick={() => onSelectNode?.(n.peer)}
            style={{ cursor: onSelectNode ? "pointer" : "default" }}
          >
            <title>
              {[
                n.alias ? `${n.alias}（${n.peer}）` : n.peer,
                isSelf ? "本机" : n.direct ? "直连" : n.reachable ? `经中继 · ${n.hops} 跳` : "不可达",
                n.subnets.length > 0 ? `网段 ${n.subnets.join(" ")}` : "",
                n.accepts_egress ? "" : "不做出口",
                isDefault ? "★ 默认出口：不命中规则与网段时从这里出去" : "",
              ]
                .filter(Boolean)
                .join("\n")}
            </title>
            <rect
              x={p.x}
              y={p.y}
              width={NODE_W}
              height={NODE_H}
              rx={9}
              fill={fill}
              stroke={isDefault ? "#8be9a8" : stroke}
              strokeWidth={isSelf ? 2 : isDefault ? 2 : 1.3}
              strokeDasharray={isDefault ? "5 3" : undefined}
            />
            <text x={p.x + 11} y={p.y + 19} fill={text} fontSize={12.5} fontWeight={600}>
              {name.length > 16 ? `${name.slice(0, 15)}…` : name}
            </text>
            <text x={p.x + 11} y={p.y + 34} fill="#8b93a7" fontSize={10.5} fontFamily="monospace">
              {showLabels ? n.peer : ""}
            </text>
            <text x={p.x + NODE_W - 9} y={p.y + 34} textAnchor="end" fill="#5d6577" fontSize={10}>
              {badge}
            </text>
            {isDefault && (
              <text x={p.x + NODE_W - 9} y={p.y + 13} textAnchor="end" fill="#8be9a8" fontSize={10}>
                ★ 默认出口
              </text>
            )}
          </g>
        );
      })}

      {empty && (
        <text x={PAD + 10} y={70} fill="#5d6577" fontSize={13}>
          {running ? "还没有任何节点 —— 配一条 seeds，或等同网段的 UDP 发现" : "服务未运行"}
        </text>
      )}
    </svg>
  );
}
