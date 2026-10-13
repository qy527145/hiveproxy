import { useEffect, useRef, useState } from "react";

import { clearLogs } from "../state/hive";
import { useLogs } from "../state/useHive";
import { Panel, Row } from "../components/ui";

/**
 * 一次最多画多少行。日志本身留 2000 行（state/hive.ts 的 LOG_CAP），但**渲染**要
 * 有上限：每来一行新日志都重画几千个 DOM 节点，界面会先于引擎卡住。
 * 看历史请用关键字过滤 —— 真要看全部，引擎的 tracing 日志才是完整的。
 */
const RENDER_CAP = 500;

const RANK: Record<string, number> = { debug: 0, info: 1, warn: 2, error: 3 };

export function LogsView() {
  const logs = useLogs();
  const [follow, setFollow] = useState(true);
  const [level, setLevel] = useState("info");
  const [filter, setFilter] = useState("");
  const paneRef = useRef<HTMLPreElement>(null);

  const want = RANK[level] ?? 1;
  const keyword = filter.trim().toLowerCase();
  const matched = logs.filter(
    (l) =>
      (RANK[l.level] ?? 1) >= want &&
      (keyword === "" || `${l.module} ${l.msg}`.toLowerCase().includes(keyword)),
  );
  const shown = matched.length > RENDER_CAP ? matched.slice(matched.length - RENDER_CAP) : matched;

  useEffect(() => {
    if (!follow) return;
    const pane = paneRef.current;
    if (pane) pane.scrollTop = pane.scrollHeight;
  }, [shown, follow]);

  return (
    <Panel
      title="日志"
      hint="引擎日志的实时镜像。浏览器侧的报错也会回传到引擎（ui_log），所以这里和终端看到的是同一份。"
    >
      <Row>
        <label className="chk">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
          自动滚动
        </label>
        <select value={level} onChange={(e) => setLevel(e.target.value)}>
          <option value="debug">debug 及以上</option>
          <option value="info">info 及以上</option>
          <option value="warn">warn 及以上</option>
          <option value="error">仅 error</option>
        </select>
        <input
          className="grow"
          placeholder="关键字过滤…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <button className="ghost" onClick={() => clearLogs()}>
          清空
        </button>
      </Row>

      {matched.length > shown.length && (
        <p className="hint" style={{ margin: "0 0 8px" }}>
          匹配 {matched.length} 行，只画最后 {shown.length} 行 —— 收窄关键字或调高等级看得更清。
        </p>
      )}

      <pre className="log" ref={paneRef}>
        {shown.map((l, i) => (
          <div key={`${i}-${l.t.getTime()}-${l.module}`} className={`lv-${l.level}`}>
            {l.t.toLocaleTimeString()} [{l.module}] {l.msg}
          </div>
        ))}
      </pre>
    </Panel>
  );
}
