# hiveproxy Web 界面：无界面机器上的同一套界面（2026-10-14）

## 0. 结论

给 `hiveproxy-cli` 加一个 **web 界面**，渲染的就是桌面端那一份前端（`src/`，5.5k 行原样复用），
不是"另做一个精简网页版"。三条依据：

1. 全工程**只有 `src/lib/ipc.ts` 一个文件**碰 `@tauri-apps`，入口只有 `invoke` 和 `listen`。
   换成"运行时判定 + HTTP/SSE"，`call` / `onHiveEvent` / `uiLog` 三个签名一个字都不用改，
   于是所有 store、所有 view、所有组件零改动。
2. 引擎里已经有 `HiveNode` 的完整 API，桌面端 `src-tauri/src/lib.rs` 里那 33 个命令**全是薄包装**。
   把它们下沉到 `hiveproxy-core`，让 Tauri 与 web 两条传输共用同一份实现 —— 一致性就不再靠"人记得同步两边"。
3. 现有管理接口（§20）是给 `nc` 和脚本用的行协议，不是给浏览器用的。它继续留着自己的位置。

四个已定的取舍（本次确认）：

| 问题 | 决定 |
| :--- | :--- |
| 谁能访问 | **默认监听局域网**（`0.0.0.0:10801`）；首次启动生成随机令牌，**打印在启动日志里**；首次登录后强制改令牌 |
| 配置文件 | **自动写 `hiveproxy.toml`，用户全程不碰文件**。文件仍是唯一真源，`reload` / 手工编辑 / 子命令照旧 |
| 电源开关 | **保留，且与桌面端语义完全一致**；同时把"配置生效"做到三层（热生效 / 引擎内重绑 / 重建引擎），日常根本用不到它 |
| 范围 | **只做 CLI 侧**；桌面端行为不变（见 §10 第 2 步，`lib.rs` 会变薄，但那是纯机械改动） |

---

## 1. 现状

- **CLI 现在必须要配置文件。** `cmd_run` / `cmd_check` / `cmd_query` 都走 `load_config`，
  文件不存在直接报错（`crates/hiveproxy-cli/src/main.rs:121`）。而桌面端走的是
  `persist::load_or_init_config`（`crates/hiveproxy-core/src/persist.rs:37`）—— 没有就写一份默认的。
  也就是说"零配置文件"这件事桌面端早就做到了，CLI 只是没接上。**这一条是一行的事。**
- **没有 web 界面。** 无界面那条路走 `crates/hiveproxy-core/src/admin.rs`：Unix socket / 回环 TCP，
  一行请求一段响应，纯文本或一行 JSON。它**只能被本机进程触达**，因此没有认证、也明确拒绝绑非回环地址。
- **管理接口缺命令。** 它没有 `sort_rules` / `preview_rules` / `ping_peer` / `close_stream` /
  `config_to_toml` / `validate_config` / 服务开关。界面要的功能比它多，所以**不能**直接把
  admin 行协议当 HTTP API 用。

---

## 2. 架构：进程内的三个角色

```
hiveproxy-cli run
 ├─ ServiceHandle ── 持有 Option<Arc<HiveNode>>，可 start / stop / restart
 │     └─ HiveNode ── 引擎（listen、dialer、gossip、proxy、admin socket…）
 └─ WebService ───── HTTP + SSE，持 ServiceHandle，**生命周期与引擎无关**
```

### 2.1 `ServiceHandle`：把引擎的生命周期从进程里拆出来

新增 `crates/hiveproxy-core/src/service.rs`：

```rust
pub struct ServiceHandle {
    base_dir: PathBuf,
    inner: parking_lot::Mutex<Inner>,   // { node: Option<Arc<HiveNode>>, last_error: Option<String> }
}
impl ServiceHandle {
    pub fn node(&self) -> Result<Arc<HiveNode>, String>;   // 未运行时返回 last_error 或"服务未运行"
    pub fn peek(&self) -> Option<Arc<HiveNode>>;           // 判活，不报错
    pub async fn start(&self) -> Result<(), String>;       // 读/建配置 → HiveNode::start
    pub async fn stop(&self) -> ();
    pub async fn restart(&self) -> Result<(), String>;
}
```

**这个形状不是新发明的** —— `src-tauri/src/lib.rs` 里的 `AppState` / `Inner` 已经是它，
连 `last_error` 的用途（"上次启动失败的原因，供 UI 显示，而不是静默白屏"）都一模一样。
这次只是把它收进 core，让 web 层能用。桌面端暂时继续用自己的那份（本轮不动），
将来可以整体换成 `ServiceHandle`，那是纯减法。

★ **为什么必须拆**：无界面机器上最容易卡死的场景是"配置改坏了、引擎起不来"——
如果 web 服务跟着引擎一起生灭，这时候浏览器也打不开，用户只能回到终端。
拆开之后：**引擎起不来，web 界面照常打开**，页面上显示 `last_error` 原文，直接改配置、点重启。

### 2.2 `WebService`：放在 core，但只由 CLI 启动

新增 `crates/hiveproxy-core/src/web.rs`，手写 HTTP/1.1（复用已有的 `httparse`），
**不引入任何新依赖**（这一点很重要：本机 crates.io 出口不稳，且 core 一直刻意保持依赖精简）。

```rust
pub fn spawn(handle: Arc<ServiceHandle>, cfg: &Config) -> Result<WebHandle, String>;
```

`WebHandle` 含实际绑定地址与一次性令牌，供 CLI 打印。

★ 它放在 core、但**只有 `hiveproxy-cli run` 会调用它**。`[web] enabled` 这个开关由 CLI 独占解释；
桌面端（Tauri）本轮不启动 web 服务，也不去读这一节。这样"只做 CLI 侧"在代码上是一条硬边界，
而不是一句约定。

---

## 3. 命令契约：一份实现，两条传输

### 3.1 下沉到 `core::api`

新增 `crates/hiveproxy-core/src/api.rs`，把 `lib.rs` 里 33 个命令的函数体原样搬过去：

```rust
pub fn set_rules(node: &Arc<HiveNode>, rules: Vec<RawRule>) -> Result<(), String>;
pub async fn publish_rules(node: &Arc<HiveNode>, rules: Vec<RawRule>) -> Result<PublishResult, String>;
pub fn service_state(handle: &ServiceHandle) -> ServiceState;
// ……
```

两侧都变成薄壳：

```rust
// src-tauri/src/lib.rs（改动是机械的，行为不变）
#[tauri::command]
fn set_rules(state: State<'_, AppState>, rules: Vec<RawRule>) -> Result<(), String> {
    api::set_rules(&state.node()?, rules)
}
```

```rust
// core/src/web.rs
match cmd {
    "set_rules" => { let args: SetRulesArgs = parse(body)?; api::set_rules(&node, args.rules) }
    // ……
}
```

★ **HTTP 端点的名字 = Tauri 命令的名字 = `api` 函数的名字**，参数形状也一致（就是 `invoke` 的 `args`）。
不做任何改名映射：一旦做映射，两边就会各说各话，而"保持一致"正是这次唯一的目标。
顺带的好处：`parse_rows` 那套**逐行报错**（§18 第 32 条）现在只有一份，web 上第几行错也是同一句话。

### 3.2 HTTP 协议

```
POST /api/<命令名>        body: JSON（与 invoke 的 args 逐字一致）
  成功 → 200 + <返回值>            （`()` 就是 `null`）
  失败 → 4xx/5xx + {"error":"…"}   （就是 Rust 侧那个 String）

GET  /api/events          SSE，载荷与 Tauri 的 `hive` 事件逐字一致
POST /api/login           {"token":"…"} → 设会话 cookie
POST /api/logout
POST /api/token           {"old":"…","new":"…"}
GET  /api/session         200 / 401
```

前端适配层因此只有一种分支：

```ts
const res = await fetch(`/api/${cmd}`, { method: "POST", headers: {...}, body: JSON.stringify(args ?? {}) });
if (res.status === 401) { onUnauthorized(); return { ok: false, e: "未登录" }; }
return res.ok ? { ok: true, v: await res.json() } : { ok: false, e: (await res.json()).error };
```

★ **`shutdown` 不暴露给 web。** 桌面端就没有它（只有 `service_stop`），web 也不该有：
进程退出只走 Ctrl-C / `systemctl stop`，与 systemd 的心智模型对齐。管理行协议里那条 `shutdown`
保持现状（它只在本机 socket 上）。

### 3.3 事件流

SSE 一个连接一条，`payload` 就是 `HiveEvent` 的 JSON（与 Tauri `emit("hive", ev)` 同一个对象）。

★ 关键在于**引擎重建时要能续上**：SSE 处理器不持有一条固定的 `broadcast::Receiver`，而是循环：

```
loop {
    match handle.peek() {
        None            → 发一条 {"event":"log",…"引擎未运行"}，睡 1s 再看
        Some(node)      → node.subscribe() 流式转发；通道关闭（引擎被停/重建）就回到循环顶
    }
}
```

这样"内核重启不影响 web"在事件这条线上是真的成立：浏览器只看到一小段静默，不需要重连页面。

前端侧 `startEventBridge()` 已经把**订阅失败**降级成纯轮询（`src/state/hive.ts:583`），
所以即使 SSE 被中间的反代掐掉，界面仍然可用 —— 这条现成的退路正好覆盖它。

---

## 4. 前端改造

一共 4 个文件改动 + 2 个新文件：

| 文件 | 改动 |
| :--- | :--- |
| `src/lib/ipc.ts` | 运行时判定（`"__TAURI_INTERNALS__" in window`）+ 浏览器走 HTTP/SSE。**三个导出函数的签名不变** —— 这是"界面零改动"的那条线 |
| `src/state/auth.ts` | **新**：会话状态、登录、改令牌、401 拦截回调 |
| `src/views/LoginView.tsx` | **新**：登录 / 首次强制改令牌（复用 `styles/tokens.css`） |
| `src/App.tsx` | web 模式且未登录 → 渲染 `LoginView`；其余分支原样 |
| `src/components/TopBar.tsx` | web 模式下多一个「访问令牌」按钮（改令牌 / 退出登录） |
| `src/lib/configSpec.ts` | 加 字段 → 生效档位 的映射表（§5 那段提示文案的唯一来源） |
| `src/views/ConfigView.tsx` | `listen` / `proxy` 的「★ 需重启才真正生效」改成三档文案（见 §5.4） |

登录页是**「和客户端界面完全一致」唯一的例外**，无法避免 —— 界面本身要有门。
它只在 web 模式且未登录时出现，桌面端永远不会渲染到它。

---

## 5. 配置：三层生效档位（这也是"电源开关"的答案）

### 5.1 三档

| 档位 | 字段 | 行为 |
| :--- | :--- | :--- |
| **① 热生效** | `route.*`（规则 / `rules_enabled` / `default_egress` / `groups` / `cost` / `ttl_*` / `gossip_*` / `accept_shared_rules` / `publish_enabled`）、`egress.*`、`security.*`、`peers.seeds` / `probe_ports` / `entry` / `accept_listen_adverts`、`discovery.*`、`share.share_ports_only`、`listen.advertise`、`service.autostart`、`log.level` | 点保存即生效，界面不抖、连接不断 |
| **② 引擎内重绑** | `listen.bind` / `ports` / `max_links`、`proxy.bind` / `allow_remote` | 引擎内取消子令牌 → 重新 bind → 重新起 accept loop。**在途连接不受影响** |
| **③ 重建引擎** | `node.overlay_addr` / `alias` / `zone`、`share.auto_share_subnets` / `subnet_deny` / `subnet_deny_ifaces`、`admin.*` | 停引擎 → 原地重建 → web 不断线，页面显示"引擎重启中"约 1 秒 |
| **④ 重启进程** | `web.*` | 唯一需要重启**进程**的一类，由 CLI 层处理 |

### 5.2 档位②为什么能做到（不需要重启进程）

`listener` 与 `proxy` 都只是"bind → accept loop"的自包含任务，而**已接受的连接是 detached 的**
（`tokio::spawn(handle_conn(...))`），所以停掉 accept loop 只换掉监听 socket 的位置，
**手里的入向链路和本机代理连接一个都不断**。

落地时踩到两个坑，都写在这里免得下次再踩：

1. **取消令牌是异步的，不能用来"腾端口"。** 第一版是 cancel → 立刻 bind 新端口，结果
   `EADDRINUSE`（旧 `TcpListener` 还在旧任务手里，要等它被调度才释放）。改成
   **`abort()` + `await` 任务句柄**才是确定的（`node.rs::stop_bound`）——
   所以 `HiveNode` 记的是 `Vec<JoinHandle<()>>`，不是取消令牌。
   顺带：冷启动与重绑现在走**同一段** `spawn_bound`，只有"单个端口绑失败是否致命"不同
   （冷启动容忍：端口被占也得能起来让用户改配置；重绑是全有全无）。
2. `status().listen` 必须读**实际绑上的**（`state.listen_bound`），不能读身份里那份启动快照。
   第一版 `spawn_bound` 在代理端口绑失败时提前 `return`，`listen_bound` 于是没被写，
   `status` 退回配置里的**猜测值** —— 看上去在听、其实一个端口都没绑。
   这次是被 CLI 的冒烟测试抓到的（这台机器的 1080 被别人占着）。
   通配绑定（`0.0.0.0`）要展开成各网卡的具体地址再报出去。

★ **顺序是"先停旧的（并等它真的停）→ 再绑新的 → 绑不上就把旧的绑回来"**，
不是教科书的"先绑后换"：端口重叠（`[5678, 5679]` → `[5678]`）时新端口根本绑不上，
那个端口还在自己手里。而先停后绑只要"停"是确定的，回滚就一定成功；
真有人在这零点几秒里抢走了旧端口，就把"回滚也失败、现在没有任何端口在听"写进日志
（§6.2.3 的"不静默降级"），绝不假装还在听。

⚠️ **"在途连接不受影响"的边界**：已经 accept、正在被服务的连接不受影响；
刚刚三次握手完、**还躺在 backlog 里没被 accept** 的那种会被 RST —— 监听 socket 一关，
内核就重置未 accept 的连接。这是内核行为，躲不掉，也没有实际影响（客户端立刻重连，
连到的是新端口）。`tests/rebind.rs` 里那条测试为此必须先完成一次 SOCKS5 往返，
否则测的是 backlog 这个边界而不是"在途"。

### 5.3 档位③为什么不做成热更新

`state.node` 是 `Arc<NodeIdentity>`，全引擎按不可变在用（寻址热路径上就是 `state.node.subnets`）。
改成 `ArcSwap` 是机械可行的，但**改身份地址在语义上就是换了一台机器**：
`node_id` 变了、拓扑里的"我自己"变了、zone 号变了、既有链路要全部拆、规则里 `node:` 出口可能全失效。
把 `ArcSwap` 套上去只是把"重建引擎"这件事藏起来，代价是让"我是谁"这个最该稳定的东西变成可变的。

所以 ③ 保留，而且是**正确**的语义，不是妥协。

### 5.4 于是电源开关

- 日常 99% 的配置改动落在 ① 和 ②：**点保存就完事，不存在"关一下再开"**。
- 落在 ③ 时，界面弹一次确认："这会重建引擎（断开全部链路与在途流，约 1 秒）"，确认后原地重建，
  **web 界面不断线**。
- **电源开关保留**，语义与桌面端逐字一致：停止 = 停引擎，web 仍在，可以再启。
  它从"日常操作"降级成"排障按钮" —— 正常配置路径根本碰不到它。

ConfigView 里那两处 `★ 需重启才真正生效` 的文案按档位改成三档（①无提示 / ②"端口将重新绑定，
在途连接不受影响" / ③"将重建引擎，断开现有连接"）。这是共享文件的文案改动，
桌面端**行为不变**，只是同一件事在两处说得更准（桌面端的"重启服务"本来就是进程内重建）。

★ `[web]` 段**不进界面**：它属于部署参数（和 systemd 的 `ExecStart` 同层），不是运行期配置。
放进界面等于诱导用户点一个"保存后什么都不会发生、必须重启进程"的开关。
配置页只显示一行只读信息：web 界面地址、怎么改（`--web-bind` 或直接编辑 TOML）。

### 5.5 顺手修掉的一个现有小缺口

`set_config` 目前只做 `rebuild_rules` + emit，没有 `sync_self_state` + 广播。
于是 `share.share_ports_only` / `listen.advertise` / `egress.allow_egress` 这几项改了之后，
`ArcSwap` 里是新值，但**邻居要等下一次周期刷新才知道**。这次在 `set_config` 末尾补一次
`sync_self_state` + `broadcast_now(flood = true)`。

---

## 6. 认证与安全

默认监听局域网之后，这是本次**唯一一处真正扩大攻击面**的决定，必须写清楚对策。

### 6.1 令牌

- 首次启动：`rand` 生成 128 bit，按 `XXXX-XXXX-XXXX-XXXX` 分组打印在启动日志里。
- 落盘只存 `sha256(salt || token)` 与 `salt`，存 `data/web_auth.json`（权限 0600），**从不存明文**。
- 首次登录后 `must_change = true`，界面弹**不可跳过**的改令牌对话框。
- 忘掉令牌的出路：`hiveproxy-cli web-token --reset`（生成新的、并再次打印一次）。
- 改过之后，后续启动**不再打印令牌**，只打印地址。

### 6.2 启动日志

```
┌─ hiveproxy web 界面 ───────────────────────────────────────
│  地址   http://10.4.0.12:10801/
│  令牌   HK7Q-2M4X-9WVT-3BPD     ← 首次登录用，进去后请改掉
│  ⚠ 明文 HTTP：令牌与全部数据在网段里是明文。
│    更安全的两种用法：
│      · SSH 隧道：ssh -L 10801:127.0.0.1:10801 用户@这台机器（并把 web.bind 改为回环）
│      · 前面放一个带 TLS 的反向代理
└────────────────────────────────────────────────────────────
```

### 6.3 浏览器特有的两类攻击

管理 socket 浏览器碰不到，HTTP 端点则不然，必须挡：

- **CSRF**：任何网页都能向 `127.0.0.1:10801` 或局域网地址发跨站请求。三重防护：
  ① 会话 cookie 用 `HttpOnly; SameSite=Strict`；
  ② `/api/*` 一律校验 `Origin`（缺失或同源才放行）；
  ③ 只接受 `Content-Type: application/json`（非简单请求，会触发预检）。**不接受**表单编码、
  `text/plain`，也不接受任何 GET 写操作。
- **DNS rebinding**：校验 `Host` 头 —— 必须是本机地址之一、`localhost`、或配置在
  `web.allowed_hosts` 里的名字。攻击页面必然带着一个域名来，这一条就把它挡在门外。

### 6.4 其余

- **登录限速**：同一来源连续失败按 1s / 2s / 4s … 退避，上限 30s；失败进日志（谁在撞、撞了几次）。
- **会话**：`expiry || HMAC-SHA256(secret, expiry)` 的 cookie，`secret` 存 `web_auth.json`。
  **与引擎生命周期无关** —— 所以引擎重建、web 重绑都不影响登录态。默认 12 小时，滑动续期。
- **不做内置 TLS**：要引入 `rustls` + `rcgen` 两个新依赖，且自签证书在浏览器里的劝退体验比 SSH 隧道差。
  文档里给的是隧道和反代两条路。
- **管理行协议不动**：Unix socket / 回环 TCP，无认证。它不被浏览器触达，风险面没变；
  加认证会打断已有脚本。web 与它各管一段，互不替代。

---

## 7. 静态资源

新增 `crates/hiveproxy-core/build.rs`：扫 `dist/`，生成 `OUT_DIR/assets.rs`：

```rust
pub static ASSETS: &[(&str, &[u8], &str)] = &[
    ("/index.html", include_bytes!("…/dist/index.html"), "text/html; charset=utf-8"),
    ("/assets/index-XXXX.js", include_bytes!("…"), "text/javascript; charset=utf-8"),
];
```

- 零新依赖（`std::fs` 递归 + 一张扩展名 → MIME 小表，几十行）。
- `dist/` 不存在时生成空表 + `cargo:warning=web 界面未内嵌（先 bun run build）`；
  服务端遇到空表就返回一页"此构建未内嵌界面"的说明，不是 404 白屏。
- **内嵌 vs 磁盘**：默认内嵌，为了"scp 一个二进制到服务器上就能用"。
  开发时用 `--web-assets <dir>` 从磁盘读 —— 改完 `bun run build` 刷新浏览器即可，
  不必重编 Rust（这一条对迭代速度影响很大）。
- 响应头：`/assets/*` 长缓存（文件名带 hash），`index.html` 不缓存，
  `X-Content-Type-Options: nosniff`，`Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'`
  （`style-src` 需要 `unsafe-inline`，因为组件里有 `style={{…}}` 属性）。
- 没命中 `/api/*` 的路径：命中资源就发，否则发 `index.html`（`App.tsx` 用 hash 路由，其实用不到，留着无害）。

---

## 8. 命令行与部署

```
hiveproxy-cli run                      引擎 + web 界面（都不需要预先准备配置文件）
hiveproxy-cli run --no-web             只跑引擎（等价于今天的行为）
hiveproxy-cli run --web-bind <addr>    覆盖 [web] bind（一次性，不写回配置）
hiveproxy-cli run --web-assets <dir>   开发：界面从磁盘读
hiveproxy-cli web-token                看令牌状态（是否已改过、何时改的）
hiveproxy-cli web-token --reset        生成新的一次性令牌并打印
```

`run` 的启动顺序：

1. `persist::load_or_init_config(base)` —— **没有配置文件就写一份默认的**。
   这就是"启动不需要准备配置文件"的落地（桌面端早就是这个行为）。
2. `ServiceHandle::start()` —— 引擎。**失败不中断**：记 `last_error`，继续下一步。
3. `web::spawn(handle, cfg)` —— web 服务。
4. 打印地址与令牌（§6.2）。
5. 等信号 → 先停 web，再停引擎。

`[web]` 新增配置节：

```toml
[web]
enabled = true                 # 只有 hiveproxy-cli 会读它；桌面端从不启动 web 服务
bind = "0.0.0.0:10801"         # 默认监听局域网。改 "127.0.0.1:10801" = 只允许本机 / SSH 隧道
allowed_hosts = []             # Host 校验的额外白名单（反代用了域名时填这里）
```

★ 端口选 10801 而不是 10800：10800 已经是 `admin.tcp` 在非 Unix 平台的默认值，
Windows 上两个都是 TCP，会撞。

systemd 可以简化了（`--config` 不再必需）：

```ini
[Service]
Type=simple
ExecStart=/usr/local/bin/hiveproxy-cli run --data-dir /var/lib/hiveproxy
Restart=always
Environment=RUST_LOG=info
```

---

## 9. 测试

- **一致性守卫（最重要的一条）**：`web::tests::routes_match_the_tauri_commands` 遍历 web 路由表与
  Tauri 的命令表，断言两个键集合**完全相同**。防的是将来加了一个 Tauri 命令忘了加 web 路由 ——
  症状是"桌面能用、web 上点了没反应"，而且两边都不报错。
- **档位表守卫**：`config::tests::frontend_tier_table_matches_the_backend` 把前端的
  `configSpec.ts` 与后端的 `classify_change` 焊在一起。**这条不是预防性的**：第一版接前端时
  就漂过一次（`listen.max_links` / `proxy.allow_remote` 被标成了重绑档，实际是热生效）。
- `web.rs` 单测：令牌归一化与分组、令牌不明文落盘、会话签名/过期、登录限速、
  `Host` 校验（含 rebinding 的域名）、**重复的 `Host` 头必须整条拒绝**、磁盘资源的路径穿越。
- `tests/web_e2e.rs`：真节点 + 真 HTTP。登录 → 401 的各种姿势 → 命令 → 静态 → SSE，
  外加**引擎停掉之后 web 还活着**（"分开控制"的存在理由）、令牌跨重启存活与重置。
- `tests/rebind.rs`：档位②。**不测"函数返回了 Ok"，而是真的去连那个端口** ——
  连得上才算在听。含回滚、在途连接存活、代理绑失败不掩盖入向端口、通配绑定要展开成具体地址。
- 前端：`bun run typecheck` + `bun run build`；再用无头 Chrome 走一遍登录 → 五个页面。
- 桌面端不能坏：`cargo test --workspace` + `bun run build` 都要过。

### 9.1 实现时抓到的真问题（留个记录）

这几条都不是"顺手改改"，是测试/冒烟真的报了红：

1. **取消令牌不能用来腾端口**（见 §5.2 第 1 条）—— 换端口时 `EADDRINUSE`。
2. **代理绑失败会掩盖入向端口**（见 §5.2 第 2 条）—— `status` 报的是猜测值。
3. **重复的 `Host` 头能绕过 rebinding 校验**：第一版"后来者覆盖"，于是攻击者送两个 `Host`
   （反代按第一个转发、我们按第二个校验）就能绕过。现在这几个头（`Host` / `Cookie` /
   `Origin` / `Content-Length` / `Content-Type`）重复出现一律整条拒绝。
4. **登录限速对人不友好**：第一版"第一次输错就锁 2 秒"，于是用户输错一次、改对了，
   看到的却是"尝试过于频繁" —— 会以为界面坏了。现在前两次失败不锁，第三次起退避。
5. **打印出来的地址里混进了 TUN 假地址**（`198.18.0.1`）：它正是本项目明确排除的
   RFC 2544 段，指路到一个谁都够不着的地方。
6. **重绑把两个子系统捆在一起，代理端口被占就会连入向端口一起废掉**：
   改入向端口时把代理也重绑了一遍 —— 代理端口被别人占着（这台开发机上就是）→ 整体失败；
   更糟的是回滚同样在代理那一步就退出，**最后两个端口一个都没在听**。
   现在每个子系统各管各的：改入向端口压根不碰代理（`tests/rebind.rs` 守着）。
7. 测试自身的两处坑（不是产品问题，但会让人误判成产品问题）：并行测试里
   "pid + 纳秒"命名的临时目录会撞车；`#[tokio::test]` 默认单线程，配阻塞 socket 会死锁。
8. 上面第 1、2、6 条都是**只有真的去连那个端口**才会暴露的 —— 单看 `apply_config`
   返回 `Ok` 一切正常。所以 `tests/rebind.rs` 的断言一律是"连得上/连不上"，
   不是"函数没报错"。

---

## 10. 落地顺序

1. **core**：`service.rs`（`ServiceHandle`）、`api.rs`（33 个命令下沉）、`config.rs`（`WebCfg`）、
   `state.rs`（`listen_bound` + 子取消令牌）、`node.rs`（档位②重绑、档位①补 `sync_self_state`）。
   先做完这一层，`cargo test -p hiveproxy-core` 全绿。
2. **src-tauri/lib.rs**：命令体改成调 `core::api`。**纯机械改动，行为不变**，
   那道 capabilities 守卫原样保留。跑一遍桌面端确认没坏。
3. **core/web.rs** + `build.rs`：HTTP + SSE + 静态 + 认证。
4. **hiveproxy-cli**：`run` 的编排（含 `load_or_init_config`）、`web-token`、
   `--web-bind` / `--web-assets` / `--no-web`。
5. **前端**：`ipc.ts` 传输层 → `auth.ts` + `LoginView` → `App.tsx`/`TopBar` → `configSpec` 三档文案。
6. **文档**：DESIGN.md 加 §21、USAGE.md 加 web 段、README、这份文档转正。

---

## 11. 风险与自我质疑

- ★ **最大风险是两套传输的漂移**：桌面上有、web 上没有的命令，症状是"按钮点了没反应且不报错"。
  §9 那条守卫测试是防线，但它只保证**命令集合**一致，不保证**参数形状**一致 ——
  后者只能靠"两侧都薄到只剩一行转发"来保证，所以 `api.rs` 里不要有任何一处只服务于其中一侧的分支。
- **默认监听局域网 + 明文 HTTP** 是这次唯一扩大攻击面的一步。令牌 + Origin/Host 校验 + 限速
  把"未授权访问"挡掉了，但**令牌在网段里是明文**这一点靠配置改不了。
  如果你更看重这一点，把默认 `bind` 改成 `127.0.0.1:10801` 只差一行 —— 它写在配置里，随时可翻。
- **档位②的"绑定失败要回滚"是这次最容易写出 bug 的地方**：改完配置、界面显示成功、实际没在听。
  §9 专门为它留了一条单测。
- **引擎重建那 1 秒里界面是半瘫的**（命令会失败）。复用现有的逐项容错 + toast 就够，
  不额外做"维护态"界面 —— 那会为了 1 秒的窗口加一整个状态机。
- **二进制变大**：内嵌 `dist/` 会让 `hiveproxy-cli` 大几百 KB。可接受（换来的是单文件部署）。
- **登录页是"界面完全一致"唯一的例外**，无法避免。
- **`lib.rs` 要动**，尽管范围是"桌面端不动"。那是为了让两条传输共用一份实现而必须付的机械代价；
  如果不做，`api.rs` 就得把 33 个薄包装抄两遍 —— 那正是漂移的来源。

---

## 12. 落地记录（2026-10-14）

### 12.1 新增 / 改动的文件

| 文件 | 是什么 |
| :--- | :--- |
| `crates/hiveproxy-core/src/service.rs` | **新**：`ServiceHandle`，引擎的生命周期从进程里拆出来 |
| `crates/hiveproxy-core/src/api.rs` | **新**：33 个命令的唯一实现（从 `src-tauri/src/lib.rs` 搬过来的） |
| `crates/hiveproxy-core/src/web.rs` | **新**：HTTP + SSE + 认证 + 静态资源（手写 HTTP/1.1，零新依赖） |
| `crates/hiveproxy-core/build.rs` | **新**：把 `dist/` 内嵌成一张 `include_bytes!` 表 |
| `crates/hiveproxy-core/src/{config,state,node,listener,proxy,admin,gossip,dialer,handshake,discovery,view}.rs` | 档位分类、`listen_bound`、重绑、读取实际监听地址 |
| `src-tauri/src/lib.rs` | 变薄：每个命令只剩一行转发到 `core::api`（行为不变） |
| `crates/hiveproxy-cli/src/main.rs` | `run` 编排、`web-token`、`--web-bind` / `--web-assets` / `--no-web`、不再要求先 `init` |
| `src/lib/ipc.ts` | 运行时传输适配（三个导出签名不变） |
| `src/state/auth.ts`、`src/views/LoginView.tsx` | **新**：会话与登录页 |
| `src/{App.tsx,components/TopBar.tsx,lib/configSpec.ts,lib/types.ts,views/ConfigView.tsx,views/OverviewView.tsx,state/hive.ts}` | 登录分支、访问令牌按钮、三档提示文案 |
| `crates/hiveproxy-core/tests/{web_e2e,rebind}.rs` | **新**：端到端与档位②的回归 |

### 12.2 与原设计的偏差（都已落到代码与本文档里）

1. **`listen.max_links` / `proxy.allow_remote` 从"重绑档"降成"热生效档"**。
   它们是每个连接现读配置的，重绑一次纯属白断连接；更要紧的是 `max_links` 走重绑会去绑
   **同一个端口** —— 必然 `EADDRINUSE`。`proxy.allow_remote` 因此改成在 accept 里现读
   （原来是启动时快照，改了不生效 —— 那才是真 bug）。
2. **重绑的顺序反了过来**（先停后绑 + 回滚，而不是先绑后换），理由见 §5.2。
3. **`admin.rs` 的 `reload` 改走 `apply_config`**：手工把端口改在 TOML 里再 `reload`，
   过去是"存下来但不生效"（只留一行 warn）。身份/网段表那一档在这条路上处理不了，
   如实拒绝（而不是收下一个不会生效的配置）。
4. **`--web-bind` / `--no-web` 参与配置自检**：它们只作用于本次运行，不参与校验的话
   会出现"我明明指了回环，它还在警告监听局域网"这种自相矛盾的日志。
5. **`set_config` 末尾补了一次 `sync_self_state` + 广播**（§5.5 那个既有小缺口）。

### 12.3 浏览器里验过什么

无头 Chrome 走了一遍：登录页 → 登录成功 → 强制改令牌 → 主界面。
主界面那一轮发出 14 个 `/api/*` 请求**全部 200**（含 SSE），首页 / 拓扑 / 路由规则 /
配置 / 日志五个页面都画得出来，数据与引擎一致（节点地址、代理端口、被排除的 TUN 网段）。
桌面端的 Tauri 分支未受影响：`ipc.ts` 在 Tauri 里仍然走 `invoke` / `listen`。

## 13. 本轮不做

- 内置 TLS（要新依赖）、自签证书生成。
- 桌面端内嵌 web 服务 / 桌面端连远端节点（范围选了只做 CLI 侧；架构上留了路：前端传输层
  只差一个"任意 base URL"）。
- 多用户、权限分级、审计日志。
- WebSocket（SSE 单向够用：事件只有服务端 → 浏览器这一个方向）。
- 给管理行协议加认证。
- 把 `AppState` 换成 `ServiceHandle`（纯减法，等 web 这层跑顺了再顺手做）。