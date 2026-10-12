// hiveproxy 前端。无构建步骤 —— Tauri 直接加载这个目录。
//
// 两条设计约束：
// 1) **任何一条命令失败都不能让整个界面白屏** —— 所有拉取都走 tryInvoke，
//    逐项容错；服务没启动时界面照样可用（配置页能编辑并落盘）。
// 2) **前端报错要能进引擎日志** —— window.onerror / unhandledrejection 统一回传
//    `ui_log`，这样排障时在终端 / journalctl 里就能看到浏览器侧的问题。

const { invoke: rawInvoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmtBytes = (n) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  return `${(n / 1024 ** 3).toFixed(2)} GiB`;
};
const fmtUptime = (s) => {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${s % 60}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d${Math.floor((s % 86400) / 3600)}h`;
};
const getPath = (o, p) => p.split('.').reduce((a, k) => (a == null ? undefined : a[k]), o);
const setPath = (o, p, v) => {
  const ks = p.split('.'); const last = ks.pop();
  let cur = o;
  for (const k of ks) { if (cur[k] == null) cur[k] = {}; cur = cur[k]; }
  cur[last] = v;
};

/** 把前端日志回传到引擎（失败就算了，绝不能因此再抛错）。 */
function toBackend(level, msg) {
  try { rawInvoke('ui_log', { level, msg }).catch(() => {}); } catch { /* 忽略 */ }
}

window.addEventListener('error', (e) => {
  const m = `${e.message} @ ${e.filename}:${e.lineno}:${e.colno}`;
  pushLog('error', 'ui', m);
  toBackend('error', m);
});
window.addEventListener('unhandledrejection', (e) => {
  const m = `未处理的 Promise 拒绝：${e.reason && e.reason.message ? e.reason.message : e.reason}`;
  pushLog('error', 'ui', m);
  toBackend('error', m);
});

/** 逐项容错的 invoke。 */
async function call(cmd, args) {
  try {
    return { ok: true, v: await rawInvoke(cmd, args) };
  } catch (e) {
    return { ok: false, e: String(e) };
  }
}

function toast(msg, kind = 'info', ms = 4200) {
  const d = document.createElement('div');
  d.className = kind; d.textContent = msg;
  $('toast').appendChild(d);
  setTimeout(() => d.remove(), ms);
}

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------
const S = {
  view: 'overview',
  svc: { running: false, autostart: true, node_id: '—', socks5_bind: '—', admin_endpoint: null, data_dir: '', last_error: null },
  status: null, stats: null,
  topology: { nodes: [], edges: [], graph: [], version: 0 },
  rulesView: { table: { merged: [], local_count: 0, rules_enabled: true }, local: [], shared: null },
  draft: [], ruleStats: [], shared: null, streams: [], zones: [], config: null,
  dirtyRules: false,
};

// ---------------------------------------------------------------------------
// 路由
// ---------------------------------------------------------------------------
const TITLES = { overview: '概览', topology: '拓扑', rules: '路由规则', config: '配置', logs: '日志' };

function showView(v) {
  S.view = v;
  for (const b of $('nav').querySelectorAll('button')) b.classList.toggle('active', b.dataset.view === v);
  for (const sec of document.querySelectorAll('.view')) sec.classList.toggle('hidden', sec.id !== `view-${v}`);
  $('view-title').textContent = TITLES[v] || v;
  $('topactions').innerHTML = ['overview', 'topology'].includes(v)
    ? `<button class="ghost" data-act="refresh">刷新</button>` : '';
  if (v === 'topology') renderDag();
  if (v === 'config') { fillConfigForm(); $('data-dir').textContent = S.svc.data_dir || ''; }
  if (v === 'logs') renderLogs();
}

// ---------------------------------------------------------------------------
// 侧栏 / 服务开关
// ---------------------------------------------------------------------------
function renderService() {
  const s = S.svc;
  const dot = $('svc-dot'), txt = $('svc-text'), btn = $('btn-power');
  dot.className = 'dot ' + (s.running ? 'on' : (s.last_error ? 'err' : 'off'));
  txt.textContent = s.running ? '运行中' : (s.last_error ? '启动失败' : '未启动');
  btn.textContent = s.running ? '停止' : '启动';
  btn.classList.toggle('stop', s.running);
  btn.disabled = false;

  $('side-node').textContent = s.node_id;
  $('side-socks').textContent = s.socks5_bind;

  const foot = [];
  if (S.status) {
    $('ver').textContent = `v${S.status.version} · 运行 ${fmtUptime(S.status.uptime_secs)}`;
    if (!S.status.rules_enabled) foot.push('★ 全局旁路已开启');
    if (!S.status.share_subnets) foot.push('不对外共享网段（仍可访问自己的网段）');
    if (!S.status.accepts_egress) foot.push('不替他人转发（自己仍然出得去）');
    if (S.status.listen.length) foot.push(`监听 ${S.status.listen.length} 个地址`);
  } else {
    $('ver').textContent = s.autostart ? '未运行' : '未运行（已关自动启动）';
  }
  $('sidefoot').innerHTML = foot.map(w => `<div class="warn">${esc(w)}</div>`).join('');

  // 顶部横幅：启动失败时把原因摆出来，而不是让用户面对一个空界面
  const b = $('banner');
  if (s.last_error) {
    b.className = 'banner err';
    b.textContent = `服务启动失败：${s.last_error}`;
  } else if (!s.running) {
    b.className = 'banner warn';
    b.textContent = '服务未运行 —— 点左下角「启动」开始组网。「配置」页现在也可以编辑并保存。';
  } else {
    b.className = 'banner';
    b.textContent = '';
  }
}

async function togglePower() {
  const btn = $('btn-power');
  btn.disabled = true;
  btn.textContent = S.svc.running ? '停止中…' : '启动中…';
  const r = S.svc.running ? await call('service_stop') : await call('service_start');
  btn.disabled = false;
  if (!r.ok) { toast(`操作失败：${r.e}`, 'err', 9000); }
  else { toast(S.svc.running ? '服务已停止' : '服务已启动', 'ok'); }
  await refreshService();
  await refreshAll();
}

async function refreshService() {
  const r = await call('service_state');
  if (r.ok) S.svc = r.v;
  renderService();
}

// ---------------------------------------------------------------------------
// 概览
// ---------------------------------------------------------------------------
function renderCards() {
  const st = S.status, k = S.stats;
  if (!st || !k) {
    const labels = ['直连链路', '活跃流', '中继帧', '入向字节', '出向字节', '丢帧', '流被重置', '握手 成功/失败', '拨号 尝试/失败', 'gossip 收/发', '路由重建', '共享网段'];
    $('cards').innerHTML = labels.map((l, i) =>
      `<div class="card ${i === labels.length - 1 ? 'wide' : ''}"><div class="k">${esc(l)}</div><div class="v">—</div></div>`).join('');
    return;
  }
  const cards = [
    ['直连链路', k.links, ''],
    ['活跃流', k.active_streams, k.active_streams > 0 ? 'good' : ''],
    ['中继帧', k.frames_relayed, ''],
    ['入向字节', fmtBytes(k.bytes_relayed_in), ''],
    ['出向字节', fmtBytes(k.bytes_relayed_out), ''],
    ['丢帧', k.frames_dropped, k.frames_dropped > 0 ? 'bad' : ''],
    ['流被重置', k.streams_dropped, k.streams_dropped > 0 ? 'bad' : ''],
    ['握手 成功/失败', `${k.handshakes_ok} / ${k.handshakes_failed}`, k.handshakes_failed > 0 ? 'bad' : ''],
    ['拨号 尝试/失败', `${k.dial_attempts} / ${k.dial_failures}`, ''],
    ['gossip 收/发', `${k.gossip_received} / ${k.gossip_sent}`, ''],
    ['路由重建', k.route_rebuilds, ''],
    ['本机可直达网段', st.subnets.join(', ') || '（无）', 'wide'],
  ];
  $('cards').innerHTML = cards.map(([label, v, cls]) =>
    `<div class="card ${cls}"><div class="k">${esc(label)}</div><div class="v">${esc(v)}</div></div>`).join('');
}

function renderStreams() {
  $('streams').innerHTML = S.streams.length
    ? S.streams.map(s =>
        `<li><span class="mono grow">${esc(s.peer)} #${s.stream_id} → ${esc(s.target)}</span>
         <button class="mini ghost" data-close-peer="${esc(s.peer)}" data-close-id="${s.stream_id}">断开</button></li>`).join('')
    : `<li class="empty">${S.svc.running ? '没有活跃流' : '服务未运行'}</li>`;
}

function renderSeeds() {
  const seeds = S.config?.peers?.seeds || [];
  $('seed-list').innerHTML = seeds.length
    ? seeds.map(s => `<li><span class="mono grow">${esc(s)}</span>
        <button class="mini ghost" data-del="${esc(s)}">移除</button></li>`).join('')
    : '<li class="empty">没有种子。同网段可以靠 UDP 自动发现；跨网段必须至少有一条。</li>';
}

// ---------------------------------------------------------------------------
// 拓扑
// ---------------------------------------------------------------------------
function renderTopologyTables() {
  const t = S.topology;
  const nb = $('nodes').querySelector('tbody');
  nb.innerHTML = t.nodes.length ? t.nodes
    .slice().sort((a, b) => (a.hops ?? 99) - (b.hops ?? 99) || String(a.peer).localeCompare(String(b.peer)))
    .map(n => `<tr class="${n.is_self ? 'self' : (n.reachable ? '' : 'dim')}" data-peer="${esc(n.peer)}">
      <td class="mono">${esc(n.peer)}${n.is_self ? ' ← 本机' : ''}</td>
      <td>${esc(n.alias ?? '')}</td>
      <td class="mono">${esc(n.subnets.join(', ')) || '<span class="lv-debug">—</span>'}</td>
      <td class="mono">${esc(n.listen.join(', ')) || '<span class="lv-debug">—</span>'}</td>
      <td>${n.hops ?? '—'}</td><td>${n.cost ?? '—'}</td>
      <td>${n.is_self ? '<span class="pill cy">本机</span>'
            : n.direct ? '<span class="pill cy">直连</span>'
            : n.reachable ? '<span class="pill">经中继</span>'
            : '<span class="pill no">不可达</span>'}</td>
      <td>${n.accepts_egress ? '是' : '<span class="pill no">否</span>'}</td>
      <td class="lv-debug">${n.last_seen_ms} ms</td></tr>`).join('')
    : `<tr><td colspan="9" class="empty">${S.svc.running ? '还没有任何节点。配一条 seeds，或等同网段的 UDP 发现。' : '服务未运行。'}</td></tr>`;

  const eb = $('edges').querySelector('tbody');
  eb.innerHTML = t.edges.length ? t.edges.map(e => `<tr>
      <td class="mono">${esc(e.to)}</td>
      <td>${e.carrier === 'lan' ? '<span class="pill cy">同网段</span>' : '跨网段'}</td>
      <td>${e.health === 'up' ? '<span class="pill ok">up</span>' : `<span class="pill no">${esc(e.health)}</span>`}</td>
      <td>${e.establisher === 'local' ? '本机拨出' : '对方拨入'}</td>
      <td>${e.rtt_ms} ms</td><td>${e.cost}</td>
      <td><button class="mini ghost" data-ping="${esc(e.to)}">ping</button></td></tr>`).join('')
    : '<tr><td colspan="7" class="empty">没有直连链路。</td></tr>';
}

function renderZones() {
  const zs = S.zones || [];
  const wrap = $('zones-wrap');
  if (!zs.length) { wrap.classList.add('hidden'); return; }
  wrap.classList.remove('hidden');
  $('zones').innerHTML = zs.map(z => `
    <div style="margin-bottom:12px">
      <div class="mono" style="margin-bottom:4px"><b>${esc(z.net)}</b></div>
      <div class="tablewrap"><table><thead><tr><th>区域号</th><th>成员</th><th>可达</th><th>从片外请这样填</th></tr></thead>
      <tbody>${z.islands.map(i => `<tr>
        <td class="mono" style="color:var(--cyan)">${esc(i.label)}</td>
        <td class="mono">${esc(i.members.join(', '))}</td>
        <td>${i.reachable} / ${i.members.length}</td>
        <td class="mono">${esc(i.suggestion)}</td>
      </tr>`).join('')}</tbody></table></div>
    </div>`).join('');
}

/** 从本机出发在声明图里做 BFS，得到跳数与父节点（DAG 的树边）。 */
function bfsTree() {
  const adj = new Map();
  for (const e of (S.topology.graph || [])) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    if (!adj.has(e.to)) adj.set(e.to, []);
    adj.get(e.from).push(e.to);
    adj.get(e.to).push(e.from); // 会话双向可用
  }
  const selfId = S.status?.node_id ?? S.svc.node_id;
  const depth = new Map([[selfId, 0]]);
  const parent = new Map();
  const order = [selfId];
  for (let i = 0; i < order.length; i++) {
    for (const nx of (adj.get(order[i]) || [])) {
      if (!depth.has(nx)) { depth.set(nx, depth.get(order[i]) + 1); parent.set(nx, order[i]); order.push(nx); }
    }
  }
  return { depth, parent };
}

function renderDag() {
  const svg = $('dag');
  if (!svg) return;
  const nodes = S.topology.nodes || [];
  const showLabels = $('dag-labels').checked;
  const showRelay = $('dag-relay').checked;
  const selfId = S.status?.node_id ?? S.svc.node_id;
  const { depth, parent } = bfsTree();

  const layers = new Map();
  const unreachable = [];
  for (const n of nodes) {
    const d = depth.get(n.peer);
    if (d == null) { unreachable.push(n); continue; }
    if (!layers.has(d)) layers.set(d, []);
    layers.get(d).push(n);
  }
  for (const arr of layers.values()) {
    arr.sort((a, b) => (b.direct - a.direct) || String(a.peer).localeCompare(String(b.peer)));
  }
  unreachable.sort((a, b) => String(a.peer).localeCompare(String(b.peer)));
  const maxDepth = layers.size ? Math.max(...layers.keys()) : 0;

  const NW = 134, NH = 46, GAPY = 22, GAPX = 116, PAD = 28;
  const pos = new Map();
  const colX = (d) => PAD + d * (NW + GAPX);
  const colH = (arr) => arr.length * (NH + GAPY) - GAPY;
  const maxCol = Math.max(1, ...[...layers.values()].map(colH), unreachable.length ? colH(unreachable) : 1);
  for (const [d, arr] of layers) {
    const top = PAD + Math.max(0, (maxCol - colH(arr)) / 2);
    arr.forEach((n, i) => pos.set(n.peer, { x: colX(d), y: top + i * (NH + GAPY) }));
  }
  const isoX = colX(maxDepth + 1);
  unreachable.forEach((n, i) => pos.set(n.peer, { x: isoX, y: PAD + i * (NH + GAPY) }));

  const width = colX(maxDepth + (unreachable.length ? 2 : 0)) + NW + PAD;
  const height = Math.max(260, maxCol + PAD * 2);

  const parts = [`<defs>
    <marker id="ah" markerWidth="9" markerHeight="7" refX="8.5" refY="3.5" orient="auto">
      <path d="M0,0 L9,3.5 L0,7 z" fill="#4fd1c5"/></marker></defs>`];

  const drawn = new Set();
  const edge = (a, b, cls) => {
    const key = [a, b].sort().join('|');
    if (drawn.has(key)) return;
    drawn.add(key);
    const pa = pos.get(a), pb = pos.get(b);
    if (!pa || !pb) return;
    const forward = pa.x < pb.x;
    const x1 = forward ? pa.x + NW : pa.x;
    const x2 = forward ? pb.x : pb.x + NW;
    const y1 = pa.y + NH / 2, y2 = pb.y + NH / 2;
    const mx = (x1 + x2) / 2;
    const col = cls === 'tree' ? '#4fd1c5' : '#333c4e';
    parts.push(`<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" stroke="${col}"
      stroke-width="${cls === 'tree' ? 1.6 : 1}" fill="none" opacity="${cls === 'tree' ? .7 : .45}"
      ${cls === 'tree' ? 'marker-end="url(#ah)"' : ''}/>`);
  };

  for (const [child, par] of parent) edge(par, child, 'tree');
  if (showRelay) for (const e of (S.topology.graph || [])) edge(e.from, e.to, 'other');

  for (const n of nodes) {
    const p = pos.get(n.peer); if (!p) continue;
    const isSelf = n.peer === selfId;
    let stroke = '#5b6b8f', fill = '#1b2333', tc = '#e8ebf2';
    if (isSelf) { stroke = '#ffc857'; fill = '#3a2f13'; tc = '#ffc857'; }
    else if (!n.reachable) { stroke = '#39404f'; fill = '#14161c'; tc = '#5d6577'; }
    else if (n.direct) { stroke = '#4fd1c5'; fill = '#16302c'; }
    else if (!n.accepts_egress) { stroke = '#e5657a'; fill = '#332027'; }

    const name = n.alias || String(n.peer);
    const badge = isSelf ? '本机'
      : !n.reachable ? '不可达'
      : (n.hops ? `${n.hops} 跳` : '直连') + (n.accepts_egress ? '' : ' · 不做出口');

    parts.push(`<g class="dag-node" data-peer="${esc(n.peer)}" style="cursor:pointer">
      <rect x="${p.x}" y="${p.y}" width="${NW}" height="${NH}" rx="9" fill="${fill}"
        stroke="${stroke}" stroke-width="${isSelf ? 2 : 1.3}"/>
      <text x="${p.x + 11}" y="${p.y + 19}" fill="${tc}" font-size="12.5" font-weight="600"
        font-family="Segoe UI, PingFang SC, sans-serif">${esc(name.length > 16 ? name.slice(0, 15) + '…' : name)}</text>
      <text x="${p.x + 11}" y="${p.y + 34}" fill="#8b93a7" font-size="10.5"
        font-family="Cascadia Mono, Consolas, monospace">${esc(showLabels ? String(n.peer) : '')}</text>
      <text x="${p.x + NW - 9}" y="${p.y + 34}" text-anchor="end" fill="#5d6577" font-size="10">${esc(badge)}</text>
    </g>`);
  }

  if (!nodes.length) {
    parts.push(`<text x="${PAD + 10}" y="70" fill="#5d6577" font-size="13">
      ${S.svc.running ? '还没有任何节点 —— 配一条 seeds，或等同网段的 UDP 发现' : '服务未运行'}</text>`);
  }

  svg.setAttribute('width', Math.max(width, 400));
  svg.setAttribute('height', Math.max(height, 240));
  svg.setAttribute('viewBox', `0 0 ${Math.max(width, 400)} ${Math.max(height, 240)}`);
  svg.innerHTML = parts.join('');

  svg.querySelectorAll('.dag-node').forEach(g => {
    g.addEventListener('click', () => {
      const row = $('nodes').querySelector(`tr[data-peer="${CSS.escape(g.dataset.peer)}"]`);
      if (row) {
        row.scrollIntoView({ block: 'center', behavior: 'smooth' });
        row.style.outline = '1px solid var(--accent)';
        setTimeout(() => { row.style.outline = ''; }, 1600);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// 规则
// ---------------------------------------------------------------------------
function renderRules() {
  const stats = new Map((S.ruleStats || []).map(s => [s.index, s]));
  const local = S.draft;
  const shared = (S.rulesView.table.merged || []).slice(local.length);

  const rowLocal = (r, i) => {
    const st = stats.get(i);
    return `<tr data-i="${i}" data-local="true">
      <td class="lv-debug">${i + 1}</td>
      <td><input type="checkbox" data-f="enabled" ${r.enabled ? 'checked' : ''} /></td>
      <td><input data-f="host" value="${esc(r.host)}" /></td>
      <td><input data-f="port" value="${esc(r.port)}" /></td>
      <td><input data-f="egress" value="${esc(r.egress)}" /></td>
      <td><select data-f="on_unreachable">
        <option value="fallback"${r.on_unreachable === 'fallback' ? ' selected' : ''}>fallback</option>
        <option value="fail"${r.on_unreachable === 'fail' ? ' selected' : ''}>fail</option></select></td>
      <td><input data-f="label" value="${esc(r.label ?? '')}" /></td>
      <td>${st ? st.hits : 0}</td>
      <td class="mono lv-debug">${st?.last_egress ?? '—'}</td>
      <td><button class="mini ghost" data-act="up">↑</button>
          <button class="mini ghost" data-act="down">↓</button>
          <button class="mini danger" data-act="del">✕</button></td></tr>`;
  };

  const rowShared = (r, i) => `<tr data-i="${i}" data-local="false" class="dim">
      <td class="lv-debug">${i + 1}</td><td><span class="pill">共享</span></td>
      <td class="mono">${esc(r.host)}</td><td class="mono">${esc(r.port)}</td>
      <td class="mono">${esc(r.egress)}</td><td>${esc(r.on_unreachable)}</td>
      <td>${esc(r.label ?? '')}</td><td>${stats.get(i)?.hits ?? '—'}</td>
      <td class="mono lv-debug">${stats.get(i)?.last_egress ?? '—'}</td><td></td></tr>`;

  $('rules').querySelector('tbody').innerHTML =
    local.map(rowLocal).join('') +
    `<tr><td class="lv-debug">⤷</td><td colspan="8" class="hint" style="margin:0">
      目标落在已知网段 → 选最近的声明者　<span class="pill">内置兜底行（只读）</span></td><td></td></tr>` +
    shared.map((r, j) => rowShared(r, local.length + j)).join('');

  const sr = S.shared, b = $('shared-banner');
  if (!sr || !sr.source) {
    b.textContent = S.svc.running
      ? '共享规则集：无（当前只跑本地规则 + 内置网段匹配）'
      : '服务未运行 —— 规则表暂不可用，但下面的本地规则仍可编辑与保存。';
  } else {
    const when = sr.issued_at ? new Date(sr.issued_at * 1000).toLocaleString() : '—';
    b.innerHTML = `当前共享策略来自 <b class="mono">${esc(sr.source)}</b>${sr.source_alias ? `（${esc(sr.source_alias)}）` : ''}` +
      `，revision <b>${sr.revision}</b>，${sr.rules} 条，发布于 ${esc(when)}` +
      (sr.accepted ? '' : '　<span class="pill no">已拒收</span>');
  }

  $('rule-stats').querySelector('tbody').innerHTML = S.ruleStats.length
    ? S.ruleStats.map(s => `<tr>
        <td class="lv-debug">${s.index + 1}</td>
        <td class="mono">${esc(s.rule)}${s.label ? ` <span class="lv-debug">（${esc(s.label)}）</span>` : ''}</td>
        <td>${s.hits === 0 ? '<span class="pill no">0</span>' : s.hits}</td>
        <td class="mono lv-debug">${s.last_egress ?? '—'}</td>
        <td class="lv-debug">${s.last_rejected_at ? new Date(s.last_rejected_at * 1000).toLocaleTimeString() : '—'}</td>
      </tr>`).join('')
    : '<tr><td colspan="5" class="empty">还没有规则。</td></tr>';
}

function collectDraft() {
  const out = [];
  $('rules').querySelectorAll('tbody tr[data-local="true"]').forEach(tr => {
    const f = (n) => tr.querySelector(`[data-f="${n}"]`);
    out.push({
      host: f('host').value.trim(),
      port: f('port').value.trim() || '*',
      egress: f('egress').value.trim(),
      on_unreachable: f('on_unreachable').value,
      label: f('label').value.trim() || null,
      enabled: f('enabled').checked,
    });
  });
  return out;
}

// ---------------------------------------------------------------------------
// 配置表单
// ---------------------------------------------------------------------------
const CFG_SPEC = [
  { title: '身份', fields: [
    { p: 'node.overlay_addr', l: 'overlay_addr', t: 'text', h: '留空 = 自动取主网卡地址。只有在两片网段地址重叠时才需要钉一个全网唯一地址（通常 fd00::/8）' },
    { p: 'node.alias', l: 'alias', t: 'text', h: '可选可读名，用于规则里的 alias: 出口与拓扑显示' },
  ]},
  { title: '监听（★ 改动需重启服务）', fields: [
    { p: 'listen.ports', l: 'ports', t: 'numlist', star: true, h: '★ 监听端口 = IT 授权给这台机器的入向端口。别人就是拨这个端口找到你；它必须与对端 seeds 里写的端口一致' },
    { p: 'listen.bind', l: 'bind', t: 'text', star: true, h: '监听的网卡地址（不含端口）' },
    { p: 'listen.max_links', l: 'max_links', t: 'number', h: '同时维持的最大直连链路数' },
    { p: 'listen.advertise', l: 'advertise', t: 'bool', h: '把自己的监听端点广播给全网，供他人自动纳入拨号候选' },
  ]},
  { title: '种子与发现', fields: [
    { p: 'peers.seeds', l: 'seeds', t: 'strlist', h: '跨网段的第一条链路只能靠它点火：写「你能拨通的一台机器」。接通后监听端点广播会把其余候选自动补齐，所以每台 0~1 条即可' },
    { p: 'peers.probe_ports', l: 'probe_ports', t: 'numlist', h: '仅当种子没写端口时按序试探的候选端口' },
    { p: 'peers.accept_listen_adverts', l: 'accept_listen_adverts', t: 'bool', h: '采信别人广播的监听端点作为拨号候选' },
    { p: 'discovery.lan_udp', l: 'lan_udp', t: 'bool', h: '同网段 UDP 广播自动发现' },
    { p: 'discovery.udp_port', l: 'udp_port', t: 'number' },
    { p: 'discovery.dial_interval_ms', l: 'dial_interval_ms', t: 'number' },
    { p: 'discovery.backoff_max_ms', l: 'backoff_max_ms', t: 'number' },
    { p: 'discovery.max_dial_candidates', l: 'max_dial_candidates', t: 'number' },
  ]},
  { title: '共享与出口', fields: [
    { p: 'share.auto_share_subnets', l: 'auto_share_subnets', t: 'bool', h: '默认把自己的整个子网贡献给全网（零配置合岛）。敏感机器置 false：只消费不贡献' },
    { p: 'share.share_ports_only', l: 'share_ports_only', t: 'numlist', h: '非空时只共享这些端口；留空 = 不限端口' },
    { p: 'egress.allow_egress', l: 'allow_egress', t: 'bool', h: 'false = 不做出口：别人的流量不会被引到这台机器上' },
    { p: 'egress.egress_ack_timeout_ms', l: 'egress_ack_timeout_ms', t: 'number' },
    { p: 'egress.egress_cache_ttl_ms', l: 'egress_cache_ttl_ms', t: 'number' },
  ]},
  { title: '路由', fields: [
    { p: 'route.rules_enabled', l: 'rules_enabled', t: 'bool', h: 'false = 全局旁路：忽略全部规则，只跑网段自动匹配（排障用）' },
    { p: 'route.accept_shared_rules', l: 'accept_shared_rules', t: 'bool', h: '是否采信全网发布的共享规则集' },
    { p: 'route.publish_enabled', l: 'publish_enabled', t: 'bool', h: '是否允许本节点对外发布规则集' },
    { p: 'route.ttl_default', l: 'ttl_default', t: 'number', h: '帧头 TTL，成环时的唯一兜底' },
    { p: 'route.gossip_interval_ms', l: 'gossip_interval_ms', t: 'number' },
    { p: 'route.gossip_flood_ttl', l: 'gossip_flood_ttl', t: 'number', h: '变化驱动 flood 的扩散半径。设为 0 会让拓扑只传播 1 跳，四节点链以上无法路由' },
    { p: 'route.cost.lan', l: 'cost.lan', t: 'number' },
    { p: 'route.cost.wan', l: 'cost.wan', t: 'number' },
    { p: 'route.cost.per_hop', l: 'cost.per_hop', t: 'number' },
  ]},
  { title: '本地代理（★ 改动需重启服务）', fields: [
    { p: 'proxy.socks5_bind', l: 'socks5_bind', t: 'text', star: true, h: '本机应用要连的 SOCKS5 地址' },
    { p: 'proxy.allow_remote_socks', l: 'allow_remote_socks', t: 'bool', h: '是否允许非回环地址使用本地 SOCKS5' },
  ]},
  { title: '安全', fields: [
    { p: 'security.join_token', l: 'join_token', t: 'text', h: '空 = 不鉴权。填入即启用握手 HMAC 校验：两侧必须一致，否则握不上手' },
    { p: 'security.rule_token', l: 'rule_token', t: 'text', h: '空 = 不校验共享规则集签名' },
    { p: 'security.e2e', l: 'e2e', t: 'select', opts: ['off', 'required'], h: 'v2 端到端加密（当前版本未实现，填 required 不生效）' },
  ]},
  { title: '服务与命令行', fields: [
    { p: 'service.autostart', l: 'autostart', t: 'bool', h: 'GUI 启动时是否自动开始组网。命令行版忽略此项（它总是启动）' },
    { p: 'admin.enabled', l: 'enabled', t: 'bool', h: '本地管理接口。GUI 不需要它；无界面服务器靠它执行 hiveproxy-cli' },
    { p: 'admin.socket', l: 'socket', t: 'text', h: 'Unix socket 路径；留空 = <数据目录>/hiveproxy.sock' },
    { p: 'admin.tcp', l: 'tcp', t: 'text', h: '或者监听回环 TCP（Windows 用），如 127.0.0.1:10800' },
  ]},
  { title: '日志', fields: [
    { p: 'log.level', l: 'level', t: 'select', opts: ['trace', 'debug', 'info', 'warn', 'error'] },
  ]},
];

function fillConfigForm() {
  const cfg = S.config;
  if (!cfg) { $('cfg-form').innerHTML = '<div class="empty">配置还没读出来。</div>'; return; }
  $('cfg-form').innerHTML = CFG_SPEC.map(sec => `<fieldset><legend>${esc(sec.title)}</legend>` +
    sec.fields.map(f => {
      const v = getPath(cfg, f.p);
      const id = `cf_${f.p.replace(/\./g, '_')}`;
      let input;
      if (f.t === 'bool') input = `<input type="checkbox" id="${id}" ${v ? 'checked' : ''} />`;
      else if (f.t === 'select') input = `<select id="${id}">${f.opts.map(o => `<option value="${esc(o)}"${v === o ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
      else if (f.t === 'numlist') input = `<input id="${id}" value="${esc((v || []).join(', '))}" placeholder="用逗号分隔，如 5678, 5679" />`;
      else if (f.t === 'strlist') input = `<input id="${id}" value="${esc((v || []).join(', '))}" placeholder="用逗号分隔，如 10.1.2.3:20000" />`;
      else if (f.t === 'number') input = `<input type="number" id="${id}" value="${v ?? ''}" />`;
      else input = `<input id="${id}" value="${esc(v ?? '')}" />`;
      return `<div class="field">
        <label for="${id}">${f.star ? '<span class="star">★</span> ' : ''}${esc(f.l)}</label>
        <div>${input}</div>
        ${f.h ? `<div class="hint">${esc(f.h)}</div>` : ''}</div>`;
    }).join('') + '</fieldset>').join('');
  $('cfg-form').dataset.touched = '';
}

function readConfigForm() {
  const cfg = JSON.parse(JSON.stringify(S.config));
  for (const sec of CFG_SPEC) {
    for (const f of sec.fields) {
      const el = $(`cf_${f.p.replace(/\./g, '_')}`);
      if (!el) continue;
      let v;
      if (f.t === 'bool') v = el.checked;
      else if (f.t === 'number') v = el.value === '' ? 0 : Number(el.value);
      else if (f.t === 'numlist') v = el.value.split(',').map(s => s.trim()).filter(Boolean).map(Number);
      else if (f.t === 'strlist') v = el.value.split(',').map(s => s.trim()).filter(Boolean);
      else if (f.t === 'select') v = el.value;
      else {
        v = el.value.trim();
        if (['node.overlay_addr', 'node.alias', 'admin.tcp'].includes(f.p)) v = v === '' ? null : v;
      }
      setPath(cfg, f.p, v);
    }
  }
  return cfg;
}

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------
const LOGS = [];
function pushLog(level, module, msg) {
  LOGS.push({ level, module, msg, t: new Date() });
  if (LOGS.length > 2000) LOGS.splice(0, LOGS.length - 2000);
  if (S.view === 'logs') renderLogs();
}
function renderLogs() {
  const want = $('log-level')?.value || 'info';
  const rank = { debug: 0, info: 1, warn: 2, error: 3 };
  const kw = ($('log-filter')?.value || '').trim().toLowerCase();
  const el = $('log');
  if (!el) return;
  el.innerHTML = LOGS
    .filter(l => rank[l.level] >= rank[want] && (!kw || `${l.module} ${l.msg}`.toLowerCase().includes(kw)))
    .map(l => `<div class="lv-${l.level}">${l.t.toLocaleTimeString()} [${esc(l.module)}] ${esc(l.msg)}</div>`).join('');
  if ($('log-follow')?.checked) el.scrollTop = el.scrollHeight;
}

// ---------------------------------------------------------------------------
// 数据拉取（逐项容错）
// ---------------------------------------------------------------------------
async function refreshAll() {
  await refreshService();

  const [cfgR] = await Promise.all([call('get_config')]);
  if (cfgR.ok) { S.config = cfgR.v; renderSeeds(); }

  if (!S.svc.running) {
    S.status = null; S.stats = null;
    S.topology = { nodes: [], edges: [], graph: [], version: 0 };
    S.streams = []; S.zones = []; S.ruleStats = [];
    S.rulesView = { table: { merged: [], local_count: 0, rules_enabled: true }, local: [], shared: null };
    if (!S.dirtyRules) S.draft = (S.config?.route?.rules || []).map(r => ({ ...r }));
    S.shared = { source: null, source_alias: null, revision: 0, issued_at: 0, rules: 0, accepted: true };
    renderCards(); renderStreams(); renderTopologyTables(); renderRules(); renderZones();
    if (S.view === 'topology') renderDag();
    return;
  }

  const [status, topology, stats, rulesView, ruleStats, shared, streams, zones] = await Promise.all([
    call('status'), call('topology'), call('stats'), call('get_rules'),
    call('rule_stats'), call('shared_rules_status'), call('active_streams'), call('zones'),
  ]);

  const failed = [];
  if (status.ok) S.status = status.v; else failed.push(`status: ${status.e}`);
  if (topology.ok) S.topology = topology.v; else failed.push(`topology: ${topology.e}`);
  if (stats.ok) S.stats = stats.v; else failed.push(`stats: ${stats.e}`);
  if (rulesView.ok) {
    S.rulesView = rulesView.v;
    if (!S.dirtyRules) S.draft = (rulesView.v.local || []).map(r => ({ ...r }));
  } else failed.push(`rules: ${rulesView.e}`);
  if (ruleStats.ok) S.ruleStats = ruleStats.v;
  if (shared.ok) S.shared = shared.v;
  if (streams.ok) S.streams = streams.v;
  if (zones.ok) S.zones = zones.v;

  if (failed.length) {
    pushLog('warn', 'ui', `部分数据拉取失败：${failed.join('；')}`);
  }

  renderService(); renderCards(); renderStreams();
  renderTopologyTables(); renderRules(); renderZones();
  if (S.view === 'topology') renderDag();
  if (S.view === 'config' && !$('cfg-form').dataset.touched) fillConfigForm();
}

async function refreshLight() {
  if (!S.svc.running) return;
  const [status, topology, stats, ruleStats, streams] = await Promise.all([
    call('status'), call('topology'), call('stats'), call('rule_stats'), call('active_streams'),
  ]);
  if (status.ok) S.status = status.v;
  if (topology.ok) S.topology = topology.v;
  if (stats.ok) S.stats = stats.v;
  if (ruleStats.ok) S.ruleStats = ruleStats.v;
  if (streams.ok) S.streams = streams.v;
  renderService(); renderCards(); renderStreams(); renderTopologyTables();
  if (S.view === 'rules') renderRules();
  if (S.view === 'topology') renderDag();
}

// ---------------------------------------------------------------------------
// 事件
// ---------------------------------------------------------------------------
async function wireEvents() {
  await listen('hive', (e) => {
    const p = e.payload;
    switch (p.event) {
      case 'topology': S.topology = p; renderTopologyTables(); if (S.view === 'topology') renderDag(); break;
      case 'stats': S.stats = p; renderCards(); break;
      case 'log': pushLog(p.level, p.module, p.msg); break;
      case 'rules':
        S.rulesView = p;
        if (!S.dirtyRules) S.draft = (p.local || []).map(r => ({ ...r }));
        renderRules(); break;
      case 'peer_up': pushLog('info', 'link', `节点上线：${p.peer}（${p.carrier}）`); break;
      case 'peer_down': pushLog('warn', 'link', `节点下线：${p.peer}（${p.reason}）`); break;
      case 'stream_opened':
        pushLog('info', 'stream', `流 #${p.stream_id} ${p.target} → ${p.egress}${p.direct ? '（本机直连）' : ''}`); break;
      case 'stream_closed':
        pushLog('debug', 'stream', `流 #${p.stream_id} 关闭（${p.reason}）：入 ${p.bytes_in} / 出 ${p.bytes_out} 字节`); break;
      case 'identity_conflict': pushLog('error', 'identity', p.hint); toast(p.hint, 'err', 15000); break;
      case 'shared_rules_rejected': pushLog('warn', 'rules', `拒收来自 ${p.source} 的共享规则集：${p.reason}`); break;
    }
  });
}

// ---------------------------------------------------------------------------
// 启动与绑定
// ---------------------------------------------------------------------------
window.addEventListener('DOMContentLoaded', async () => {
  $('nav').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-view]');
    if (b) showView(b.dataset.view);
  });
  $('btn-power').onclick = togglePower;
  $('topactions').addEventListener('click', async (e) => {
    if (e.target.closest('button[data-act="refresh"]')) await refreshAll();
  });

  $('btn-seed-add').onclick = async () => {
    const v = $('seed-input').value.trim(); if (!v) return;
    const r = await call('add_seed', { addr: v });
    if (r.ok) { $('seed-input').value = ''; toast('已添加种子', 'ok'); await refreshAll(); }
    else toast(`添加失败：${r.e}`, 'err', 8000);
  };
  $('seed-list').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-del]'); if (!b) return;
    const r = await call('remove_seed', { addr: b.dataset.del });
    if (r.ok) await refreshAll(); else toast(`${r.e}`, 'err');
  });
  $('btn-probe').onclick = async () => {
    const t = $('probe-input').value.trim(); if (!t) return;
    const r = await call('probe_target', { target: t });
    if (r.ok) {
      $('probe-out').textContent =
        `目标      ${r.v.target}\n出口      ${r.v.egress}${r.v.direct ? '（本机直连）' : ''}\n` +
        `命中规则  ${r.v.matched_rule === null ? '内置网段兜底行' : '#' + (r.v.matched_rule + 1)}\n耗时      ${r.v.rtt_ms} ms`;
    } else {
      $('probe-out').textContent = `✗ ${r.e}\n\n目标不落在任何已知网段、且没有规则命中时就会这样。\n看看「拓扑」里有哪些网段，或到「路由规则」写一条指定出口。`;
    }
  };
  $('streams').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-close-peer]'); if (!b) return;
    const r = await call('close_stream', { peer: b.dataset.closePeer, streamId: Number(b.dataset.closeId) });
    if (!r.ok) toast(`${r.e}`, 'err');
  });

  $('dag-labels').onchange = renderDag;
  $('dag-relay').onchange = renderDag;
  $('edges').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-ping]'); if (!b) return;
    const r = await call('ping_peer', { peer: b.dataset.ping });
    if (r.ok) toast(`${b.dataset.ping} RTT ≈ ${r.v} ms`, 'ok'); else toast(`${r.e}`, 'err');
  });

  $('btn-rule-add').onclick = () => {
    S.draft = collectDraft();
    S.draft.push({ host: '*', port: '*', egress: 'auto', on_unreachable: 'fallback', label: null, enabled: true });
    S.dirtyRules = true; renderRules();
  };
  $('rules').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-act]'); if (!b) return;
    const i = Number(b.closest('tr').dataset.i);
    S.draft = collectDraft();
    if (b.dataset.act === 'del') S.draft.splice(i, 1);
    if (b.dataset.act === 'up' && i > 0) [S.draft[i - 1], S.draft[i]] = [S.draft[i], S.draft[i - 1]];
    if (b.dataset.act === 'down' && i < S.draft.length - 1) [S.draft[i + 1], S.draft[i]] = [S.draft[i], S.draft[i + 1]];
    S.dirtyRules = true; renderRules();
  });
  $('rules').addEventListener('input', () => { S.dirtyRules = true; });

  $('btn-rule-sort').onclick = async () => {
    const r = await call('sort_rules', { rules: collectDraft() });
    if (r.ok) { S.draft = r.v; S.dirtyRules = true; renderRules(); toast('已按具体度重排（记得保存）', 'info'); }
    else toast(`${r.e}`, 'err');
  };
  $('btn-rule-save').onclick = async () => {
    S.draft = collectDraft();
    const r = await call('set_rules', { rules: S.draft });
    if (r.ok) { S.dirtyRules = false; toast('本地规则已保存（尚未发布到全网）', 'ok'); await refreshAll(); }
    else toast(`保存失败：${r.e}`, 'err', 9000);
  };
  $('btn-rule-preview').onclick = async () => {
    S.draft = collectDraft();
    const r = await call('preview_rules', { rules: S.draft });
    if (!r.ok) { toast(`预览失败：${r.e}`, 'err', 9000); return; }
    const p = r.v;
    $('preview-panel').style.display = '';
    let s = '';
    if (p.warnings.length) s += p.warnings.map(w => `⚠ ${w}`).join('\n') + '\n\n';
    s += '影响面（相对当前生效的规则表）：\n';
    s += p.changes.length ? p.changes.map(c => `  ${c.target}：${c.from} → ${c.to}`).join('\n') : '  （没有变化）';
    s += `\n\n永不命中的条目：${p.never_matched.length ? p.never_matched.map(i => '#' + (i + 1)).join(', ') : '无'}`;
    s += `\n黑洞条目：${p.blackholes.length ? p.blackholes.map(i => '#' + (i + 1)).join(', ') : '无'}`;
    $('preview-out').textContent = s;
    $('preview-panel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };
  $('btn-rule-publish').onclick = async () => {
    S.draft = collectDraft();
    if (!confirm(`把 ${S.draft.length} 条规则**整份发布**给全网？\n\n· 各机器的本地规则仍然优先于它\n· 后发布者会整体覆盖先发布者\n· 带别名的条目会在发布前解析成 IP，解析不到的会整次拒绝`)) return;
    const r = await call('publish_rules', { rules: S.draft });
    if (r.ok) { toast(`已发布 revision ${r.v.revision}（${r.v.rules} 条）`, 'ok'); await refreshAll(); }
    else toast(`发布失败：${r.e}`, 'err', 9000);
  };
  $('btn-rule-revoke').onclick = async () => {
    if (!confirm('撤回共享规则集：会发布一份**空的**规则集，全网立即回到「只跑本地规则」。确定？')) return;
    const r = await call('revoke_shared_rules');
    if (r.ok) { toast(`已撤回（revision ${r.v.revision}）`, 'warn'); await refreshAll(); }
    else toast(`撤回失败：${r.e}`, 'err');
  };

  $('btn-cfg-save').onclick = async () => {
    const cfg = readConfigForm();
    const r = await call('set_config', { cfg });
    if (r.ok) {
      toast('配置已保存并应用', 'ok');
      await refreshService(); await refreshAll();
      if (S.config) fillConfigForm();
    } else toast(`保存失败：${r.e}`, 'err', 9000);
  };
  $('btn-cfg-reload').onclick = async () => {
    const r = await call('get_config');
    if (r.ok) { S.config = r.v; fillConfigForm(); renderSeeds(); toast('已从磁盘重新读取配置', 'ok'); }
    else toast(`${r.e}`, 'err');
  };
  $('cfg-form').addEventListener('input', () => { $('cfg-form').dataset.touched = '1'; });

  $('btn-toml-load').onclick = async () => {
    const r = await call('config_to_toml');
    if (r.ok) { $('toml').value = r.v; $('toml-out').textContent = '（已从磁盘配置刷新）'; }
    else toast(`${r.e}`, 'err');
  };
  $('btn-toml-check').onclick = async () => {
    const p = await call('config_from_toml', { text: $('toml').value });
    if (!p.ok) { $('toml-out').textContent = `✗ ${p.e}`; return; }
    const w = await call('validate_config', { cfg: p.v });
    const warns = w.ok ? w.v : [];
    $('toml-out').textContent = warns.length
      ? `✓ 语法正确，但有 ${warns.length} 条告警：\n` + warns.map(x => `  ⚠ ${x}`).join('\n')
      : '✓ 语法正确，没有告警。';
  };
  $('btn-toml-apply').onclick = async () => {
    const p = await call('config_from_toml', { text: $('toml').value });
    if (!p.ok) { toast(`应用失败：${p.e}`, 'err', 9000); return; }
    const r = await call('set_config', { cfg: p.v });
    if (r.ok) { toast('TOML 已应用', 'ok'); await refreshService(); await refreshAll(); fillConfigForm(); }
    else toast(`应用失败：${r.e}`, 'err', 9000);
  };

  $('btn-log-clear').onclick = () => { LOGS.length = 0; renderLogs(); };
  $('log-level').onchange = renderLogs;
  $('log-filter').oninput = renderLogs;

  await wireEvents();
  await refreshAll();
  showView('overview');
  pushLog('info', 'ui', '界面已就绪。左下角是服务开关；「配置」页可以改监听端口等全部参数。');
  // 回执 + 渲染自检：排障时从引擎日志就能确认"界面到底画出来没有、切页会不会炸"。
  // 每个视图的渲染函数都先跑一遍（不切页，所以没有视觉闪烁）—— 有问题第一时间暴露在日志里。
  const checks = [];
  try { renderDag(); checks.push('拓扑'); } catch (e) { toBackend('error', `拓扑视图渲染失败：${e}`); }
  try { renderRules(); checks.push('规则'); } catch (e) { toBackend('error', `规则视图渲染失败：${e}`); }
  try { renderZones(); checks.push('分区'); } catch (e) { toBackend('error', `分区视图渲染失败：${e}`); }
  try { fillConfigForm(); checks.push('配置'); } catch (e) { toBackend('error', `配置表单渲染失败：${e}`); }
  try { renderLogs(); checks.push('日志'); } catch (e) { toBackend('error', `日志视图渲染失败：${e}`); }
  toBackend('info', `界面渲染完成：服务 ${S.svc.running ? '运行中' : '未启动'}，`
    + `卡片 ${$('cards').childElementCount}，节点 ${S.topology.nodes.length}，`
    + `规则 ${S.draft.length}（本地），自检通过视图 [${checks.join(' ')}]`);
  setInterval(refreshLight, 2000);
  setInterval(refreshService, 5000);
});
