# hiveproxy 系统设计文档

> 版本：v1 设计草案（2026-10-12）
> 输入：`IDEA.md`（初步想法）+ 双方问答纪要
> 说明：IDEA.md 中的二进制报文格式与部分组件描述仅作示意。本设计在其思想与目标不变的前提下重新定义细节。

---

## 1. 文档目标与范围

本文档定义 hiveproxy 的完整技术设计，覆盖：

- 传输层覆盖网络（overlay）的网络模型与协议
- Rust 后端核心引擎的组件划分、数据结构与接口
- 本地 SOCKS5 出口的寻址模型
- 配置模型、安全演进路径、可观测性与 Tauri 集成
- 里程碑、验收标准、测试策略、已知风险

不在本文档范围：Tauri 前端具体页面实现细节（仅约定事件与命令契约）、CI/打包发布流程。

---

## 2. 需求澄清结论

### 2.1 来自 IDEA.md 的硬性约束（不可违背）

| 编号 | 约束 | 说明 |
| :--- | :--- | :--- |
| C1 | 用户态 TCP，不用 TUN/TAP | 规避 Root/Administrator 权限，不做 L3 虚拟网卡 |
| C2 | 全网运行同一程序 | 无中心服务端，无每台机器不同的角色配置 |
| C3 | 每台机器有全局唯一身份，重启后不变 | IDEA 原始想法是「启动生成 UUID 并持久化」。本设计改为**节点地址即身份**（§5.8）：全网寻址、单向规则、种子配置用的都是现有网络地址，额外生成 UUID 后没有任何地方能对上（§14 差异表） |
| C4 | 利用 IT 留下的单向白名单孔洞建立长连接 | A 可连 B:5678，B 不能连 A |
| C5 | 去中心化 Gossip 交换拓扑，Dijkstra 算最短路 | 无中心协调者 |
| C6 | 传输层内存中多跳中继，中间节点不解业务包体 | 中继只解析协议头 |
| C7 | 本地释放统一 SOCKS5 出口 `127.0.0.1:1080` | 实现全网双向无感访问 |
| C8 | Rust + tokio + serde + petgraph，UI 用 Tauri v2 | 技术栈固定 |

### 2.2 问答确认的关键决策

| 议题 | 你的回答 | 本设计的落地方式 |
| :--- | :--- | :--- |
| 目标寻址 | 「如果 A 能访问 B 的某个端口，直接在 A 的可访问对端中定义 `b_ip:b_port` 能访问，然后 A、B 通过 hiveproxy 协议建立稳定连接」 | 配置里声明**我可拨号的对端**（`ip:port`，现在只作**引导**，§6.5）。SOCKS5 客户端仍填 `目标ip:port`；本地用**全网汇聚的网段索引 + 本地路由规则**把它解析成出口节点（见 §9） |
| 组网发现 | 「只需部分客户端配置可访问对端信息，再结合局域网自动发现策略」 | **混合发现**：跨网段靠**引导种子**（0~1 条）+ 监听端点广播自动汇聚候选，同网段靠 UDP 广播自动发现，两者结果统一进拓扑（见 §6.5） |
| 报文格式 | 「IDEA 只是初步想法，细节你重新设计」 | 重定义为 **48 字节定长帧头**，含 version / flags / TTL，解决成环与协议演进问题（见 §5） |
| 安全 | 「做端到端加密，但传输层要解耦合，协议部分可随时替换；先具备传输任意数据的能力，再实现端到端加密」 | 严格分层。v1 纯明文可跑通，加密以 `CryptoProvider` trait + 帧头 flags 位接入，**不改动帧头布局与中继逻辑**（见 §11） |
| **出口选择**（2026-10-12 修订，取代原「能力声明」） | 「客户端不需要声明能连接的外部服务。我作为其中一个节点客户端 A，使用 hiveproxy 提供的代理访问某个网络时，只需要收集所有节点的子网段，默认使用和访问目标同一子网的节点作为出口节点即可；如果目标地址和现有网络中的子网均不匹配，则通过路由规则来指定出口节点（即将网络中的每个节点都当成备选出口，由路由规则决定从哪个出口走）」 | **简化为两级**：**网段自动匹配**（零配置，§9.1）+ **路由规则**（有序列表，先匹配者胜，§9.4）。原 `Serve`/`Reach` **能力（Capability）模型整体删除** —— 它要求每个消费者都知道"谁能到哪"，而网段是自动汇聚的，不需要任何声明 |
| **路由规则的归属**（2026-10-12） | 「可以使用本地管理，但是可以一键发布到整个网络，因为我是所有机器的管理者，我不想多个地方配很多遍」 | **本地管理 + 整份发布**：规则默认只写在本地配置；`publish` 命令把**整份规则集**作为一个 LWW register 推给全网（§9.4.3）。合并时**本地规则整体排在共享规则之前**，所以本地永远能覆盖共享；接收方仍须本地校验可达性 |
| **默认可达性（细化）** | 「即使不声明默认也能访问同网段下的其它 ip 地址及其所有端口」+「代理端口连接到所有客户端节点能连接的服务的并集」 | 每个节点自动把自己**所在的整个子网**（全部 IP、全部端口）广播给全网，并集 = 所有节点网段之和，零配置完成孤岛合并（§9.1、§18 第 14 条）。这是本设计里**唯一**的"我能到哪"声明，且不需要人手写 |
| **监听端点广播**（2026-10-12） | 「要保留客户端声明监听地址（IT 开了白名单的端口），方便其它节点建立连接做网络聚合用」 | `listen.ports`（§6.2.3 的 overlay 入向端口）保留，并**从握手自检项升级为默认全网广播字段**（`GossipMsg.listen`）。邻居帮你把这个事实扩散出去，使跨网段的候选拨号目标自动汇聚，减少手工 `seeds`（§6.5 第 3 条）。注意这**不是**业务端点声明 —— 业务流量一律走本地 SOCKS5 口（§18 第 15 条） |
| **节点身份** | 「感觉生成 id 也没有意义，没有地方能用上，定义单向访问规则也是用的现有网络的 ip」 | 采纳。**取消 UUID 生成**，`NodeId` 直接就是节点自己的网络地址（IPv4 用 v4-mapped IPv6 的 16 字节表示）。帧头字段宽度不变，配置词汇与寻址词汇统一（§5.8） |
| **无端口规则** | 「在设置可单向访问规则时，也不一定要设置端口，因为有时候并没有限制端口」 | 种子支持不写端口（`"10.1.2.3"`）或写端口范围，dialer 按 `probe_ports` 候选列表试探；用 `magic` 校验把「拨到非 hiveproxy 服务」变成确定性失败。**这是备用路径**：当前环境授权端口已知（§18 第 11、12 条），正常情况直接写端口即可（§6.2.2） |
| **冷启动握手** | 「即使 A 知道 A 能访问 B 的 5678，但 B 一开始并不知道 A 的存在，B 的 5678 也没有一个 TCP 占用，A 如何与 B 建立连接？」 | 前提修正：该端口由 **B 自己的 hiveproxy** 占用并处于 `LISTEN`，白名单放行的正是 A 的 SYN 到达这个 socket。B 在 accept 后的 `Hello` 里才认识 A，**不需要预先知道 A**；唯一真实风险是 B 的程序未启动，由常驻重连 + 退避兜住（§6.2.1） |
| **端口对齐（死锁正解）** | 「A 能访问 B 的 20000，但 B 并没有监听 20000，这是由 IT 防火墙决定的，如何破局？难道只能穷举端口识别协议？」 | 防火墙放行的是 `(源, 目的, 端口)` **许可**，不是服务；路的尽头必须有监听套接字。正解是**让 B 监听授权端口**：A 侧 `seeds` 写端口、B 侧 `listen.ports` 写同一条事实，一次对齐。穷举端口既不必要（授权端口是已知事实）又有害（未授权端口不可达、全扫描触发 IDS）。仅当授权不限端口时才用有界试探（§6.2.3、§6.2.2） |

上表记录的是**自由问答**里确认的决策。另有 16 项通过多选确认，2026-10-12 修订再追加 3 项，同日评审后又追加 8 项，收尾再追加 1 项，**共 28 项**（默认端口、服务暴露粒度、是否设 `allow_relay`、跳数上限、平台、`petgraph`、出口选择模型的传播范围、`*:*` 模式、`Serve` 优先级、身份方案、IT 规则形态、授权端口可知性、B 出向权限、默认可达性、接管监听含义、网段重叠、出口选择模型、规则归属、监听端点广播、gossip 传播模型、背压与流隔离、发布信任、分片与路径切换、Group 定义、别名发布、revision 持久化、v1 优化项、`allowed_cidrs` 去留），结论统一记录在 **§18**。

---

## 3. 网络模型与关键洞察

### 3.1 核心洞察：反向可达性来自会话复用，不是反向建连

IDEA.md 描述「A 能连 B:5678，B 连不回 A」，并期望最终「双向无感访问」。二者只有一种成立方式：

**TCP 连接是全双工的。B 收到 A 拨进来的连接后，可以在这条已建立的连接上把数据写回 A。B 不需要反向建连，它复用的就是 A 建的那条会话。**

这条洞察决定了几条设计铁律：

1. **叠层图的边在「建立方向」上是有向的，在「可用方向」上是双向的。**
   A 拨向 B 得到的 socket，既可以承载 A→B 帧，也可以承载 B→A 帧。所以一次成功的单向拨号，得到一条双向可用的叠层边。
2. **Dialer 必须常驻重连，不能按需拨号。**
   B 能不能访问 A，取决于 A 那个方向有没有活着的会话。只要 A 的 dialer 一直挂着到 B 的连接，B→A 就始终通。所以拨号器对已知目标是"持久保活 + 断开立即重试（指数退避）"，而不是"有流量才连"。
3. **A 的配置决定 B 的生死。**
   如果 A 没人要求它拨 B（也没有任何种子指向 A），B 就永远够不到 A。为此提供补充机制：节点在 gossip 里广播自己**入向监听端点**（`GossipMsg.listen`，默认开启），其它节点听到后会把它纳入拨号候选并尝试连接（§6.5 第 3 条）。

### 3.2 拓扑示例

```
      企业防火墙（只放行 A:any -> B:5678）          企业防火墙（只放行 C:any -> D:5678）

   [A] ──拨号──────────────────────────► [B]
    │  ◄─────────────复用同一条 TCP 回传数据──────┘
    │
    │ 同网段 UDP 广播自动发现（A 与 C 同网段）
    ▼
   [C] ──拨号──────────────────────────► [D]

   A 想访问 10.4.0.9:3389（该地址在 D 所在网段内，D 默认自动共享了整个子网）：
   A -> C（同网段直连）-> D（C 拨号建立的那条会话）-> D 本地 connect -> 10.4.0.9:3389
   中间节点 C 只改 TTL，不看业务明文。
   —— 全程无需任何人声明"我能到哪"：D 的本地网段默认就对全网可见（§9.1）。
```

### 3.3 边的三个属性

| 属性 | 取值 | 用途 |
| :--- | :--- | :--- |
| `establisher` | `Local` / `Remote` | 谁是拨号方。决定谁负责重连保活；用于判断可达性的可靠性 |
| `carrier` | `Direct` / `Lan` | 直连分两种：跨网段白名单孔洞（成本高）、同网段（成本低） |
| `health` | `Up` / `Degraded` / `Down` | 由心跳与写失败驱动 |

这三者共同决定边的成本与切换时机（§6.3、§3.4）。

### 3.4 对等与多路径（两条基础性质）

**全网对等，无中心。** 每个节点运行同一程序、承担同一套角色：既是端点也是中继，既主动拨号也被动接受。没有任何节点是其他节点的必要前置 —— 不存在注册中心、调度服务器或会合点。拓扑完全靠 gossip 自发收敛（§6.3）。这对应 IDEA 的 C2 与 C5。

**多路径：选最近，其余备选。** 两节点之间往往不止一条路径（直连、经同网段邻居、跨网段多跳）。设计不追求同时复用所有路径，而是：

- 用 Dijkstra 选出**当下成本最低**的一条作为主路径（边权重见 §6.3）；
- 其余路径不主动使用，但**记在路由缓存里**（`CachedRoute.alt`），主路径写失败时立即切换，不等下一轮 gossip；
- 因此**单个节点掉线不等于网络断裂**：只要还存在一条替代路径，受影响流量在秒级内自动绕行。只有当某个目标变成所有路径的共同瓶颈时，它才真正不可达。

这是「某些客户端掉线后也不一定会对其它节点网络整体性有影响」的实现基础：**整体性不依赖任何单点存活，只依赖是否存在替代路径**。收敛时限见 §12；唯一的例外见 §17 风险 1 —— 若某个方向只有唯一拨号者，该方向会随它一起失效。

---

## 4. 总体架构分层（协议可替换性的实现方式）

你要求"传输层解耦合、协议可随时替换"。设计成五层，层间只通过 trait 与数据帧交互，任一层可整体换掉：

```
┌──────────────────────────────────────────────────────────────┐
│ L5 应用/出口层   SOCKS5 服务端、目录/网段索引、本地 TCP 泵     │  可替换：换 HTTP CONNECT / TUN(未来)
├──────────────────────────────────────────────────────────────┤
│ L4 会话层        Stream 生命周期、流控、半关闭、多路复用        │  稳定，改动少
├──────────────────────────────────────────────────────────────┤
│ L3 路由层        Topology(邻接表) + petgraph + Dijkstra 选路   │  稳定
├──────────────────────────────────────────────────────────────┤
│ L2 帧层          HiveHeader 编解码、定长头 + 载荷边界          │  版本号内演进
├──────────────────────────────────────────────────────────────┤
│ L1 链路层        TCP 连接、握手、心跳、读写任务、公平调度器     │  可替换：换 QUIC / WebSocket / UnixSocket
└──────────────────────────────────────────────────────────────┘
        ▲ 正交插入：CryptoProvider（v1 空实现，v2 端到端加密）
```

关键解耦点（对应你的要求）：

- **L1 与 L2 之间的边界是一个 `AsyncRead + AsyncWrite` 对象**。换成 TLS 流、QUIC 流、WebSocket，L2 以上零改动。
- **L2 与 L3/L4 之间是一对 `(HiveHeader, Bytes)`**。载荷是字节，协议之内是什么由 `msg_type` 决定；换序列化格式（bincode → protobuf/flatbuffers）只改 L4 编解码。
- **加密封装在 `CryptoProvider` trait 后**，用帧头 `flags` 位标记，中继节点读到标记后原样透传，不解析不解密。所以"先能传任意数据、后加端到端加密"是零架构改动的叠加。

---

## 5. 二进制协议设计 v1

### 5.1 帧头（定长 48 字节）

| 偏移 | 字段 | 类型 | 说明 |
| :--- | :--- | :--- | :--- |
| `0..1` | `magic` | `u8` | 固定 `0x48`（'H'） |
| `1..2` | `ver_type` | `u8` | 高 4 位 `version`（v1 = `0x1`），低 4 位 `msg_type`。IDEA 只用 1 字节 msg_type，这里拆开以便协议演进 |
| `2..3` | `flags` | `u8` | 位标记，见下表 |
| `3..4` | `ttl` | `u8` | 剩余跳数。每经过一个中继节点减 1，为 0 丢弃并回 `Unreachable`。**IDEA 缺此字段，是成环时唯一兜底** |
| `4..20` | `src_node` | `[u8;16]` | 源节点地址（编码见 §5.8） |
| `20..36` | `dst_node` | `[u8;16]` | 目的节点地址（编码见 §5.8） |
| `36..44` | `stream_id` | `u64` | 大端。流标识，同一节点并发 SOCKS5 连接靠它区分 |
| `44..48` | `payload_len` | `u32` | 大端。后续载荷字节数，上限 `MAX_FRAME_PAYLOAD = 256 KiB` |
| `48..` | `payload` | `[u8]` | 裸字节 |

固定头 48 字节。相比 IDEA 的 46 字节，多出的 2 字节换来 TTL 与 flags，所有原有字段偏移后移但语义不变。`src_node`/`dst_node` 的**宽度不变**，语义从「随机 ID」改为「节点地址」（§5.8）。

`stream_id` 的取值：**流作用域的消息**（`StreamOpen`/`StreamAck`/`StreamClose`/`WindowUpdate`/`Data`）填该流的 id；**链路与控制消息**（`Hello`/`Ping`/`Pong`/`Gossip`/`Pull`）恒为 `0`。因此 `Gossip` 的去重**不能**用帧头，只能用载荷里的 `(owner, seq)`（§6.3）。

`flags` 位定义：

| 位 | 名称 | 含义 |
| :--- | :--- | :--- |
| 0 | `ENCRYPTED` | 载荷已端到端加密，中继节点必须透传不可解 |
| 1 | `CONTROL` | 该帧为控制帧，中继路径上需按控制语义处理（如 gossip 需要去重） |
| 2 | `FIN` | 该流的半关闭信号 |
| 3 | `HIGH_PRIORITY` | 心跳/握手等，走优先车道 |
| 4..8 | 保留 | 未来分片、压缩、链路层加密标记 |

### 5.2 消息类型表（低 4 位）

| 值 | 名称 | 是否可中继 | 用途 |
| :--- | :--- | :--- | :--- |
| `0x0` | `Reserved` | — | 非法，丢弃并记统计 |
| `0x1` | `Hello` | 否 | 链路握手（仅一跳，ttl 不参与中继） |
| `0x2` | `Ping` / `0x3 Pong` | 否（仅一跳） | 链路心跳与 RTT 测量 |
| `0x4` | `Gossip` | 是（**变化时 flood** + 周期一跳） | 邻接表/网段/监听端点/规则集广播，附带反熵摘要（§6.3） |
| `0x5` | `StreamOpen` | 是 | 请求在目的节点发起本地 TCP 连接 |
| `0x6` | `StreamAck` | 是 | 接受/拒绝 + 拒绝原因码 |
| `0x7` | `StreamClose` | 是 | 流关闭（双向各发一次即全关） |
| `0x8` | `WindowUpdate` | 是 | 流级信用窗口（**v1 必做**，见 §5.5） |
| `0x9` | `Unreachable` | 是 | 无路由 / TTL 耗尽 / 出口拒绝，回给 src |
| `0xA` | `Data` | 是（**载荷不透传解析**） | 业务字节流 |
| `0xB` | `Pull` | 是 | 反熵拉取：请求补发某 `owner` 自 `from_seq` 起的公告（§6.3） |
| `0xC` | `HelloAck` | **否**（仅一跳） | 握手回执（§5.4） |
| `0xD` | `Reject` | **否**（仅一跳） | 握手拒绝 + 原因码（§5.4） |
| `0xE`–`0xF` | 保留 | — | 未来：路由探测、链路层加密协商、指标采集 |

### 5.3 控制消息体（`payload` 内容，serde/bincode）

```rust
#[derive(Serialize, Deserialize)]
pub struct GossipMsg {
    pub owner: NodeId,               // 这份公告属于谁
    pub incarnation: u64,            // owner 的世代号，用于失效判定与反驳
    pub seq: u64,                    // owner 内部单调递增序号
    pub edges: Vec<AdjEntry>,        // owner 的全部直接邻居
    pub subnets: Vec<SubnetAd>,      // owner 自动共享的本机网段（§9.1）
    pub listen: ListenAdvert,        // owner 的入向监听端点，供全网做拨号候选（§6.5）
    pub accepts_egress: bool,        // owner 是否愿意做出口；false 的节点不进候选（§9.4.4）
    pub alias: Option<String>,       // owner 的可读别名
    pub rule_set: Option<RuleSetAd>, // owner 发布的共享规则集（LWW register，§9.4.3）
    pub digest: Vec<(NodeId, u64)>,  // 反熵摘要：owner 已知的每个节点的最新 seq（§6.3）
}

/// 共享的网段。`ports = None` 表示不限端口；`Some` 来自 `share_ports_only`（§9.1）。
pub struct SubnetAd { pub net: IpNet, pub ports: Option<Vec<u16>> }

/// 反熵拉取（§6.3）：请对方补发自 `from_seq` 起的 `owner` 公告。
pub struct PullMsg { pub owner: NodeId, pub from_seq: u64 }

pub struct AdjEntry { pub peer: NodeId, pub cost: u16, pub carrier: Carrier, pub rtt_ms: u16 }

pub struct StreamOpenMsg { pub endpoint: Endpoint, pub proto: Proto, pub flags: u8, pub e2e_pk: Option<[u8;32]> }
pub struct StreamAckMsg   { pub ok: bool, pub code: u16, pub reason: String }
pub struct UnreachableMsg { pub reason: UnreachableReason, pub last_hop: NodeId }
pub struct WindowUpdateMsg { pub stream_id: u64, pub credit: u32 }   // 绝对信用值（§5.5）

// ---- 链路握手（§5.4）—— 仅一跳，不可中继 ----
pub struct HelloMsg {
    pub ver_min: u8, pub ver_max: u8,
    pub node_addr: NodeId,        // 发送方的身份地址（= 它的 IP），握手即身份交换
    pub nonce: [u8; 16],
    pub features: u32,            // 位标记：端到端加密能力等
    pub auth: Option<[u8; 32]>,   // HMAC-SHA256(join_token, ..)；join_token 为空时为 None
}
pub struct HelloAckMsg {
    pub node_addr: NodeId, pub nonce: [u8; 16], pub features: u32,
    pub session_id: u64,
    pub listen_ports: Vec<u16>,   // 供拨入方做端口对齐自检（§6.2.3）
    pub auth: Option<[u8; 32]>,
}
pub struct RejectMsg { pub reason: RejectReason }
pub enum RejectReason { VersionMismatch, AuthFailed, TooManyLinks, IpLimit }
```

### 5.4 握手（链接建立，仅一跳）

**握手同时承担「端口探测」职责**：当种子未指定端口（§6.2.2）时，A 拨通后必须立刻判断对面是不是 hiveproxy 节点。判据就是首字节 `magic = 0x48` 加后续字段合法性 —— 非本协议的响应会在校验阶段被拒，A 关闭连接并把该端口标记为「非节点」，从而让「无端口规则」下的探测既确定性又廉价。

1. Dialer 连上后立即发 `Hello { magic, ver_min, ver_max, node_addr, nonce_a, features }`，其中 `node_addr` 就是它自己的身份地址（§5.8）。这一步**本身就是身份交换**，不需要额外的 ID 协商 —— 因为身份就是地址。
2. Listener 回 `HelloAck { node_addr, nonce_b, features, session_id, listen_ports }`，或 `Reject { reason }`（版本不兼容、认证失败、超出 `max_links`）。回包里带上自己的地址，使**拨入方也能知道被拨方的名字** —— 这是 B→A 方向复用会话时填写 `dst_node` 的依据。`listen_ports` 则让 A 能做端口对齐自检（§6.2.3）：若 A 配置的 seed 端口不在 B 的监听列表里，立刻告警。
3. 认证槽位（**实现时修正**）：原式 `HMAC(join_token, nonce_a ‖ nonce_b ‖ addr_a ‖ addr_b)` 发起方**算不出来** —— 它发出 `Hello` 时还不知道 `nonce_b`。改成**双向各证一次**：

   | 字段 | 计算式 | 证明了什么 |
   | :--- | :--- | :--- |
   | `Hello.auth` | `HMAC(token, "hello" ‖ nonce_a ‖ addr_a)` | **拨入方**持令牌 |
   | `HelloAck.auth` | `HMAC(token, "ack" ‖ nonce_a ‖ nonce_b ‖ addr_a ‖ addr_b)` | **被拨方**持令牌 |

   两侧各验一次：任何一侧没有令牌都握不上手（拨入方无令牌 → 被拨方回 `Reject{AuthFailed}`；被拨方无令牌 → 拨入方验不过 `HelloAck.auth`）。比较用**常量时间**，避免时序侧信道。v1 默认 `join_token` 为空即跳过（见 §11）。
4. 双方把对端注册进链接池。**同时互拨去重**：若同一 NodeId 已存在 link，用确定性规则裁决（NodeId 字节序小的一方保留自己的出站连接，另一方保留入站），避免两条链路并存造成环路与流量重复。

### 5.5 分帧、流级信用与路径切换

- **分帧**：TCP 是字节流，`payload_len` 定界即可。载荷超过 `MAX_FRAME_PAYLOAD` 时由发送方在同一 `stream_id` 下切分成多帧，接收方按序拼接 —— 因此**同一流内绝不允许乱序或重复**，这是下面路径切换约束的前提。
- **流级信用（`WindowUpdate`，v1 必做）**：**信用由出口侧生成** —— 出口节点把帧写进本地 socket、腾出缓冲后回收信用，经 `WindowUpdate`（绝对信用值，可批量合并回）传回该流的源节点。中间节点**只转发，既不产生也不消费信用**。
  - 发送方信用耗尽时**暂停该流的读取**（在源头就不再投递），因此**队列不会因为"发得太快"而满**。
  - **每条链路、每条流一个队列，容量 = 信用窗口**（默认 32 帧）。这个等式是关键：只要发送方守信用，中间队列就不可能溢出，于是**中间节点既不阻塞读任务、也不丢帧**。
  - **为什么必须做**：每条链路只有**一个**读任务。若采用"队列满就 `await` 阻塞"，一条慢流会把整条链路上的所有流一起卡死（链路级队头阻塞），"单流拥塞不阻塞其他流"的承诺随之失效。
  - **万一还是溢出**：说明对端不守信用或实现有 bug。此时**丢帧并立即关闭该流**，而不是静默跳过 —— 帧头没有流内序号，静默丢弃等同于静默数据损坏。计入 `stats.stream_dropped` 并告警。
- **唯一允许阻塞的地方是控制优先车道**：数据帧一律 `try_send`，不阻塞读任务；控制帧（心跳、`WindowUpdate`、`Unreachable`、`Gossip`）走一条容量小（64）的优先车道，用 `await` 写入。控制帧低频且极小，真到阻塞说明链路已经饱和，此时阻塞读任务是可以接受的。
- **`try_send` 失败 ≠ 链路故障**：`link.tx.try_send` 返回 `Closed` 才代表**链路已拆**，用于触发次优下一跳切换（§12）。**队列满是背压信号，不是故障信号**，两者必须分开处理，否则会出现"网络拥塞 → 误判链路故障 → 频繁改路"的震荡。
- **路径切换与分片顺序**（对应 §6.3 的 `alt`）：帧头**没有流内序号**，所以任何中途改路都可能重排或丢帧。设计上原写的是"等 `sent - acked == 0` 再切，长期繁忙则由 `route_switch_timeout_ms` 兜底强切"。**实现取了更保守也更简单的一档**：

  > **一条流一旦建立就把下一跳钉死，绝不中途改路。下一跳链路失效时，该流立即以 `Reset` 关闭，由应用层重试。**

  理由是：换路不仅会重排，还会**丢帧**；而帧头没有序号，丢帧无法被检测，等同于静默数据损坏 —— 比"连接被重置"糟得多（TCP 遇到断链也是 RST，应用层本来就该重试）。因此 `route_switch_timeout_ms` 目前**没有实际用途**，保留在配置里只作将来引入流内序号后的升级位（§17 风险 16）。
- **公平性**：每条流一个独立的有界队列，外加一条**控制优先车道**。写入任务按轮转（round-robin）取帧，控制帧（心跳、`WindowUpdate`、`Unreachable`、`Gossip`）永远不会被数据帧饿死。

### 5.6 零拷贝中继

帧在内存里始终是**一整块** `BytesMut`：头部 48 字节 + 载荷连续存放。

- 中继节点读入整块后，只改 `buf[3]`（ttl）这 1 个字节，`BytesMut::freeze()` 成 `Bytes` 直接投给下一跳通道。**无二次拷贝、无载荷解析**。
- `Bytes` 是引用计数，多路复制（如 gossip flood 到多条链路）不复制数据。
- **`dst_node` 在整个中继路径上保持不变**，始终是最终目的节点；中继只依据本地路由表决定下一跳。任何节点都不得改写 `src_node` / `dst_node` / `stream_id`，否则会破坏返回路径与流标识的唯一性。
- 本地消费时用 `Buf::split_to` 切出载荷视图，同样零拷贝。

---

### 5.7 共享类型定义

§5.3 的控制消息体与 §6 的组件引用了以下类型，统一定义在此，避免实现时各自发挥：

```rust
// ---- proto/types.rs ----
/// 广播哨兵 = v4-mapped 的 255.255.255.255（即 `::ffff:255.255.255.255`）。
/// 仅用于 Gossip 的多跳扩散（`gossip_flood_ttl > 0` 时），
/// 绝不作为业务帧的 dst，也不得替代真实节点地址。
pub const BROADCAST: NodeId = NodeId([0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF]);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Carrier { Direct, Lan }        // 跨网段白名单孔洞 / 同网段

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Proto { Tcp, Udp }             // v1 只实现 Tcp

/// 目标的"主机"部分：可能是 IP，也可能是域名。
/// 域名必须保持原始形式而不是预先解析出的 IP —— 解析发生在**出口节点**，
/// 因为企业内网普遍是 split-horizon DNS，同一域名在不同网段解析结果不同。
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Host { Ip(IpAddr), Name(String) }

/// 流的目标端点。SOCKS5 CONNECT 必然给出具体主机，故 `host` 不可为空。
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Endpoint { pub host: Host, pub port: u16 }

// ---- 路由规则（§9.4）。取代原 Serve/Reach 能力模型。----

/// 目标侧的匹配条件。规则是**有序列表、先匹配者胜**，
/// 因此这里不需要"具体度"枚举来隐式排序 —— 顺序由使用者显式表达。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HostMatcher {
    Any,              // *
    Exact(String),    // 10.1.2.9 或 api.corp.example.com（不做 DNS 解析，纯字面比对）
    Suffix(String),   // *.internal.example.com（存 internal.example.com）
    Cidr(IpNet),      // 10.9.0.0/16
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PortMatcher { Any, Exact(u16), Range(u16, u16) }

/// 命中后往哪走。这是规则的全部动作面。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EgressTarget {
    Auto,             // 交给内置网段规则：命中网段的声明者中选路由成本最低者
    SelfDirect,       // 本机直接 connect，不进 overlay（目标其实就在手边时省一跳）
    Node(NodeId),     // 钉死一个出口节点
    /// 钉死一个别名。**仅本地规则可用** —— `publish_rules` 会在发布前把别名解析成
    /// `NodeId`，解析不到的条目**拒绝发布**并报错，绝不把别名原样传给全网（§9.4.3）。
    Alias(String),
    /// 候选集，两种写法（§9.4.2）：
    /// - `group:<name>`：显式配置的集合，成员见 `route.groups`
    /// - `group:subnet:<cidr>`：**派生**集合，成员 = 声明了该网段的节点，随拓扑自动增减
    Group(GroupRef),
    Block,            // 拒绝（回 SOCKS5 0x02 connection not allowed）
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum GroupRef {
    Named(String),     // group:db
    Subnet(IpNet),     // group:subnet:10.9.0.0/16
}

/// 指定出口不可达时怎么办。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum OnUnreachable {
    ToAuto,   // 顺延到下一顺位匹配（最终落到内置网段规则）；仍无则报错
    Fail,     // 直接回 SOCKS5 错误，不静默改变路径
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub host: HostMatcher,
    pub port: PortMatcher,
    pub egress: EgressTarget,
    pub on_unreachable: OnUnreachable,
    pub label: Option<String>,   // 前端可读备注，不参与匹配
    pub enabled: bool,           // false = 仅留档不参与匹配
}

/// 本节点入向监听端点的广播（§6.5）。取代原 `dial_hints`，
/// 语义从"请你来拨我（默认关闭）"改为"我在这些地址上监听（默认开启，无来源过滤）"。
/// 差别在于：广播的是**客观事实**（我 bind 了什么），能不能拨通由请求方的防火墙决定，由试行失败退避兜住。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ListenAdvert {
    pub addrs: Vec<SocketAddr>,  // listen.bind × listen.ports 展开；不含回环
    pub issued_at: u64,          // 墙上时钟，仅用于展示与排障
    pub ttl_secs: u32,           // 过期即不再作为候选（默认 900）
}

/// 共享规则集：**整份**作为一个 LWW register 同步（§9.4.3）。
/// 不做逐条合并 —— 只有"整份替换"才能用 (revision, publisher) 全序裁决，
/// 从而不需要版本向量、不需要中心、任何节点独立计算都得到同一份。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RuleSetAd {
    pub publisher: NodeId,        // 谁发布的
    pub revision: u64,            // 发布者本地单调递增
    pub issued_at: u64,           // 仅用于展示与排障
    pub rules: Vec<Rule>,         // 顺序即优先级
    pub hmac: Option<[u8; 16]>,   // 可选：security.rule_token 的标签；未验签则整份忽略
}


/// 不可达原因码，回给源节点供前端展示。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum UnreachableReason { NoRoute = 0, TtlExhausted = 1, NextHopWriteFailed = 2, Refused = 3 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Establisher { Local, Remote }  // 谁是拨号方（决定谁负责保活重连）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health { Up, Degraded, Down }

pub struct LinkMeta {
    pub establisher: Establisher,
    pub carrier: Carrier,
    pub rtt_ms: u16,
    pub health: Health,
    pub since: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamState { Opening, Open, HalfClosedLocal, HalfClosedRemote, Closed }

/// 本地流上下文：一端是本机 socket，另一端是链路帧通道。
/// 发起方用 `origin` 把本地读到的字节投进链路；出口方用 `sink` 把收到的帧投给本地 socket 写泵。
pub struct StreamCtx {
    pub key: StreamKey,
    pub origin: mpsc::Sender<OutboundFrame>,
    pub sink: mpsc::Sender<Bytes>,
    pub state: AtomicU8,                // StreamState，避免 DashMap 上的二次加锁
    pub opened_at: Instant,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}
```

与加密、身份相关的类型（v1 只有 `NodeIdentity` 被用到，其余是为 v2 预留的接口形态）：

```rust
// ---- identity.rs ----
/// 本节点的运行期身份：**地址是身份**（§5.8），密钥只是凭证。
pub struct NodeIdentity {
    pub node_id: NodeId,            // = 本机地址（或 overlay_addr 覆盖值）
    pub alias: Option<String>,
    pub sig_key: Option<SigKey>,    // v2 才需要；用于连接认证，不参与身份派生
    pub listen: Vec<SocketAddr>,    // 实际监听的全部地址（多端口，§6.2.3）
}

/// 签名密钥对（v2：Ed25519）。
pub struct SigKey { pub public: [u8; 32], pub secret: [u8; 64] }

/// 两条链路握手后派生的会话密钥（v2）。
pub struct SharedSecret([u8; 32]);

/// 网段 → 能直达它的节点集合（§9.1）。这是本设计里**唯一**的"谁能到哪"索引。
pub type Segments = HashMap<IpNet, Vec<NodeId>>;

/// SOCKS5 入口消费的扁平规则视图：**本地规则在前，共享规则在后**（§9.4.3）。
/// 入口只按序匹配，不关心某条来自哪里；`shared_source/revision` 供前端展示"当前策略是谁下发的"。
/// 同时直接作为 `get_rules` 的 IPC 返回体，故 derive 序列化。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleTable {
    pub merged: Vec<Rule>,              // 先匹配者胜
    pub local_count: usize,             // merged[..local_count] 是本地规则
    pub shared_source: Option<NodeId>,
    pub shared_revision: u64,
}

/// 孤岛区域号：真冲突时系统自动派生（§9.3），种子 = 孤岛内字节序最小的 NodeId。
/// 节点独立计算即可得同一值，无需中心分配。`node.zone` 可手动冻结。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct ZoneId(pub u16);

impl ZoneId {
    pub fn derive(island_anchor: NodeId) -> Self;   // 确定性派生，任一节点结果一致
    pub fn map_target(&self, ip: IpAddr) -> Ipv6Addr;  // 真实 IP → overlay 地址（低位保留）
    pub fn unmap_target(&self, addr: Ipv6Addr) -> Option<IpAddr>; // 反向，可逆
}

/// 前端展示用：一个网段与能直达它的节点集合（对应原 `ServiceView`）。
/// 没有"服务目录"了 —— 全网可达目标 = 所有节点共享网段的并集，这张表就是它的展开。
pub struct SegmentView { pub net: IpNet, pub via: Vec<NodeId>, pub is_local: bool }
```

### 5.8 节点身份：地址即身份

**为什么不用生成的 UUID。** 生成一个随机 ID 之后，必须让**所有人**都学到「这个 ID 对应哪台机器」，才能把它写进任何配置：种子要写、单向规则要写、路由规则要写、日志要读。而本场景里每台机器的网络地址本来就是全局唯一、天然稳定、人已经记住的标识。把地址再映射成一个随机数，等于凭空插一层没有信息增量的间接层 —— 这正是「生成了 ID 却没有地方能用上」的根因。所以身份**就是**节点的网络地址。

**编码**（16 字节定长，与 IDEA 的字段宽度完全一致）：

| 地址族 | 编码 | 例 |
| :--- | :--- | :--- |
| IPv4 | v4-mapped IPv6：`::ffff:a.b.c.d` | `10.1.2.3` → `::ffff:10.1.2.3` |
| IPv6 | 原样 16 字节 | `fd00::1` |

选 v4-mapped 而非「IPv4 塞进前 4 字节」的理由：三种地址族共用一个定长字段，帧头布局无需分支；`std::net::Ipv6Addr` 自带 v4-mapped 判定，编解码不必自造约定；与 v2 端到端加密天然兼容 —— 密钥不再参与派生身份，只做认证。

`BROADCAST` 哨兵取 v4-mapped 的 `255.255.255.255`（即 `::ffff:255.255.255.255`），仅用于 Gossip 多跳扩散，任何业务帧都不得使用。

**反向可达性依然成立。** 身份是地址，不等于「必须能拨到这个地址」。§3.1 的核心机制没变：B 够不到 A 时，靠 A 拨进来的那条全双工会话回传数据。A 在握手时向 B 声明自己的地址（`Hello.node_addr`），B 此后就用这个地址填写 `dst_node`。**地址只是名字，可达性仍由会话与路由决定。**

**多网卡与地址变更。**
- 多网卡节点取**主网卡地址**作身份（默认按路由表 default route 所在接口判定），可用 `node.overlay_addr` 显式覆盖。身份只需**唯一**，不需要**可拨**。
- 地址变更（DHCP 换租约、主机迁移）即等同于换了一台机器：旧地址的链接会被拓扑清理，配置里引用旧地址的条目需同步更新。地址不固定的环境请钉死 `overlay_addr`。

**私网地址重叠的处理。** 两片互不连通的网段都用 `10.1.2.9` 时，会出现两个节点声称同一身份，路由表无法区分。解法不是退回 UUID，而是给重叠的那一侧在配置里显式指定全网唯一的 `overlay_addr`：

```toml
[node]
# 默认留空 = 用本机主网卡地址作身份。
# 仅当本网段地址与他人重叠时，才钉一个全网唯一地址（通常用 ULA：fd00::/8）。
overlay_addr = "fd00:1::9"
```

> 注意区分两套机制：`overlay_addr` 解决**节点自身身份**重叠（§5.8），`node.zone` 解决**目标地址**重叠（§9.3）。前者必须唯一否则无法建图，后者可自动派生。不要混用。

常见情况（地址唯一）零配置，罕见情况（地址重叠）由运维在**已经知道边界在哪**的地方显式声明一次。分层之下，未来若真需要「地址 + 域」的复合身份，可用 `ver_type` 的版本位引入，不影响 v1 节点。

---

## 6. 组件设计

### 6.1 组件 A：身份与链接池（Identity & LinkManager）

- **身份 = 节点地址**（§5.8），不做任何生成与持久化。启动时按「路由表 default route 所在接口的地址」判定自己的身份；配置了 `node.overlay_addr` 则用它。因此**不存在** `identity.json` 这类文件。
- `data/node.json` 预留 `keypair: Option<[u8;64]>`：v2 引入端到端加密时需要一对签名密钥，但它**只用于连接认证**，不再参与身份派生 —— 身份是地址，密钥是凭证，两者解耦。
- 链接池：`DashMap<NodeId, LinkHandle>`，比 IDEA 的 `Arc<RwLock<HashMap<...>>>` 粒度更细，避免高频读被写阻塞。
- 出站/入站一律注册为 `LinkHandle`，上层不区分方向，只关心"能不能给它发帧"。

```rust
pub struct LinkHandle {
    pub peer: NodeId,
    pub tx: mpsc::Sender<OutboundFrame>,   // 进公平调度器
    pub meta: LinkMeta,                    // establisher / carrier / rtt / health
    pub cancel: CancellationToken,         // 拆除本链路
}

pub struct OutboundFrame { pub header: HiveHeader, pub payload: Bytes }
```

### 6.2 组件 B：Dialer 与 Listener

**Listener**
- 绑定 `listen.ports` 里的每个端口（即 IT 授权给本机的入向端口，§6.2.3；未配置时兜底 5678）。接受连接后走 §5.4 握手，成功后 `spawn` 两个任务：读任务（解析帧 → `route_packet`）与写任务（公平调度器消费 `tx`）。
- 保护阈值：`max_links`（默认 16）与单 IP 连接数上限，超限直接 `Reject`，防止握手洪水打爆内存。

**Dialer**
- 数据来源三类，合并去重后统一调度：
  1. **静态种子 `peers.seeds`**：仅作**引导（bootstrap）**。跨网段的第一条链路只能靠它，无法自动化；但一旦接通任意一条，第 2、3 类就会自动把其余候选补齐，所以常态下每台机器写 **0~1 条**即可，而不是逐个对端都要写。
  2. 局域网发现到的同网段节点（§6.5 第 2 条）；
  3. gossip 广播的**监听端点** `GossipMsg.listen`：默认采信，但必须过 `ttl_secs` 有效期检查（§6.5 第 3 条）。**这一类来源不做地址过滤**；要整体关闭它，把 `accept_listen_adverts` 置 `false`。
- 候选总量上限 `max_dial_candidates`（默认 64）：超出时按"最近成功过 / 路由成本最低"优先保留，其余丢弃。这条是防止广播把候选集无限吹大。
- 每 `dial_interval_ms`（默认 5s）巡检一次，对无活链的目标发起连接；失败按指数退避（1s→2s→…→60s 上限），成功后立即重连不等待间隔。
- **关键行为：对已建立的链路持续保活，不因无流量而断开**。这是 B→A 方向可达性的唯一保证（见 §3.1）。空闲链路只跑心跳（默认 3s）。
- 避免惊群：同一目标同一时刻只允许一个在途拨号（per-node 的 dial mutex）。

#### 6.2.1 冷启动：A 如何连上「还没人连过」的 B

这是整套设计里最容易被误解的一环，先澄清一个前提：

**B 在那个端口上不是「没有 TCP 占用」，而是「B 自己的 hiveproxy 正在占用」。**

C2 约束是「全网运行同一个程序」。所以 B 上的 hiveproxy 启动后就会在**被授权的入向端口**上 `listen()`，该端口处于 `LISTEN`。防火墙的白名单孔洞打通的正是「A 的 SYN 能到达 B 这个 LISTEN socket」这条路。

这里有一个**前置条件必须成立**：**B 监听的端口必须等于 IT 授权的端口**。若 IT 放行的是 20000、而 B 只听了默认的 5678，那么 A 的 SYN 到达 B:20000 时无人接听，内核回 RST，连接失败 —— 这不是协议问题，是端口错位，排查与对齐见 §6.2.3。三个关键点：

1. **B 不需要预先知道 A 的存在。** 内核的监听 socket 带 accept 队列，`listen()` 之后任何来源的 SYN 只要被防火墙放行就能建连。B 是在 **accept 之后**、从 A 的 `Hello` 帧里**才第一次认识 A**（`Hello.node_addr`，§5.4）。所以「B 一开始不知道 A」不是问题 —— 识别发生在握手时，不在连接前。
2. **B 也不需要主动连 A。** B 是被动方，只负责 accept 与握手。A→B 方向的发起权在 A 手里，这正是「单向」的含义在软件层的体现。
3. **真正的风险是「B 的程序还没起来」。** 端口没人 listen 时 SYN 被回 RST，A 的 connect 立即失败。因此 dialer 常驻重连 + 指数退避（§6.2），B 稍后启动即自动接通，无需 A 侧任何人工干预。

反方向也值得点明：**A 的监听端口同样在 LISTEN**，但防火墙不放行 B→A 的 SYN，所以 B 永远拨不进来。这就是「单向」在软件层无需任何处理的原因，也是 §3.1「反向可达性靠会话复用」的由来。

#### 6.2.2 无端口规则：种子可以不写端口

**本节是备用路径，不是启动必经逻辑。** 它只适用于 IT 规则**不限端口**的情形（例如「A 网段可访问 B 网段任意端口」）。当前环境已知授权端口（§18 第 11、12 条），所以正常情况直接在 `seeds` 与 `listen.ports` 里写明确端口即可，无需探测。只有遇到「授权宽泛、对端监听端口未知」时，才回来用这里的试探能力。

当白名单不限端口时，让用户去猜 B 的 hiveproxy 监听在哪个端口是多余的负担。因此种子支持三种写法：

| 写法 | 语义 | dialer 行为 |
| :--- | :--- | :--- |
| `10.1.2.3:5678` | 明确端口 | 只拨这一个端口 |
| `10.1.2.3` | 不限端口 | 按 `probe_ports` 候选列表依次尝试 |
| `10.1.2.3:5678-5680` | 端口范围 | 在范围内依次尝试 |

`probe_ports` 默认 `[5678, 5679, 8000, 8080]`（可配）：无端口规则下依次试探的候选端口。5678 是默认监听端口，放首位以保证最常见情况一次命中。

**为什么必须做 `magic` 校验。** 无端口规则下 A 可能拨到 B 上**任意**一个 TCP 服务（SSH、Web、数据库…）。若不做区分，A 会把一个 HTTP 服务当成 hiveproxy 节点，握手帧发过去、收到的却是 HTTP 响应，造成误判甚至协议混淆。因此握手第一步就是验魔数：

1. A 发出 `Hello` 帧，首字节固定 `magic = 0x48`。
2. **真正的 hiveproxy 节点**读到 `0x48` 且后续字段合法 → 回 `HelloAck`，握手成功。
3. **非 hiveproxy 服务**的响应几乎不可能构成合法 `HiveHeader`（magic 不符，或 `ver_type`/`payload_len` 越界）→ A 判定「不是节点」，立即关闭连接并把该端口标记为「非节点」，不再反复尝试。

有了这条校验，「拨错端口」是一个廉价且确定性的失败，而不是一个难以诊断的挂起。

#### 6.2.3 端口对齐：防火墙授予的是通路，不是服务

这是「A 知道能访问 B:20000，但 B 没人监听 20000」这个死锁的正解。先把模型说清楚：

**IT 放行的从来不是「B 的 20000 端口」这个能力，而是一条 `(源, 目的, 端口)` 三元组的通行许可。许可只打开了一条路，路的尽头必须有监听套接字。** B 上没人 listen 20000 时，内核收到 SYN 直接回 RST，A 的 connect 立即失败 —— 这不是协议不匹配，是根本没人接听。同理，B「没有被要求监听」这个说法本身就包含了这个死锁：**防火墙规则不会替你在 B 上创建一个监听进程**，那是 hiveproxy 自己的职责。

所以破局只有一条路：**让 B 的 hiveproxy 监听在防火墙授权的那一个端口上**，而不是默认端口。这是配置对齐问题，不是协议问题。

| 侧 | 需要声明的事实 | 配置 |
| :--- | :--- | :--- |
| A（拨号方） | 我能到达谁、到达它的哪个端口 | `peers.seeds = ["10.1.2.3:20000"]` |
| B（被拨方） | IT 授权别人从哪个端口进来找我 | `listen.ports = [20000]` |

两侧写的是**同一个事实的两半**：同一条防火墙规则。在 A 侧写成 seed 端口、在 B 侧写成监听端口，一次对齐，长期有效。

**为什么不该用穷举端口。** 三个理由：

1. 授权端口是 IT **已经知道的事实**，扫描等于用暴力手段重新发现一个已知答案。
2. 授权是**按端口**放行的，未被授权的端口要么被防火墙静默丢弃、要么根本没监听 —— 扫描它们只会得到超时，纯属浪费。
3. 全端口扫描是教科书级的攻击特征，会触发 IDS/IPS 告警，在企业网里是给自己找麻烦。

**穷举唯一合理的形态是「有界试探」**（§6.2.2）：仅当 IT 规则本身**不限端口**时，B 用默认端口监听即可，A 按 `probe_ports` 试几个候选端口就能命中。那是「授权本就宽泛」时的便利，不是「授权端口未知」时的替代方案。

**B 可以一次监听多个端口**，这是让对齐变宽松的实用做法：

```toml
[listen]
# 监听**本机被授权的入向端口**（这就是 §6.2.3 那条事实的 B 侧）。可写多个，写几个就绑几个。
# 若 IT 给了多个授权端口，或你暂时不确定最终用哪个，就把候选都写上，哪条规则生效都能接。
ports = [20000]
```

代价极低（每个端口一个监听 fd），收益是运维不必一次就把对齐做对。但**不要监听大范围端口**：那既是把自己变成扫描目标，也白白消耗 fd。

**DNAT 的坑（本节仅作将来参考）。** 你的环境已确认是**纯放行（allow）**（§18 第 11 条），所以 A 连 20000 就到达 B 的 20000，B 直接 `listen.ports = [20000]` 即可，无需关心下面这段。仅当将来遇到转发型规则时再回来看。

防火墙规则有两种形态，配置正好相反：

| IT 规则形态 | A 拨的端口 | B 应该监听的端口 |
| :--- | :--- | :--- |
| 纯放行（allow） | `20000` | `20000`（A 看到的端口就是 B 的端口） |
| 端口转发（DNAT） | `20000` | **转发后的目标端口**（例如 5678） |

若是 DNAT，A 依然连 `20000`，但流量到达 B 时已被改写成别的端口，B 必须监听那个**改写后的端口**。判断方法：在 B 上 `tcpdump` 观察来自 A 的连接落在哪个端口，或直接问 IT 是「放行」还是「转发」。

**必须把失败原因区分开。** 这个死锁之所以难查，是因为三种失败看起来都像「连不上」，但成因完全不同：

| A 侧现象 | 含义 | 处理提示 |
| :--- | :--- | :--- |
| `ECONNREFUSED`（收到 RST） | 包**到了** B，但该端口无人监听 | 检查 B 的 `listen.ports` 是否包含该端口 |
| `ETIMEDOUT`（无响应） | 包**没到** B，被防火墙丢弃 | 检查 IT 规则是否真的放行了该 (源, 目的, 端口) |
| 连上但 `magic` 校验失败 | 该端口被**别的服务**占用，不是 hiveproxy | 换一个授权端口，或确认 B 是否真在跑 hiveproxy |

三种现象必须在前端与日志里给出**不同**的文案与建议，而不是统一报「连接失败」。这是把「难以诊断的挂起」变成「可操作提示」的关键。

**前置自检。** B 启动时若 `listen.ports` 中某个端口 bind 失败（被占用、权限不足），必须**显式告警到前端**，而不是静默降级 —— 否则运维会以为对齐做对了，实际 B 根本没在那个端口上听。

### 6.3 组件 C：Gossip 路由引擎

**拓扑存储**：`Topology` 持有"我收集到的别人的邻接表"，而不是我算出来的全网图。

```rust
pub struct Topology {
    pub adjacency: HashMap<NodeId, PeerAdj>,          // owner -> 它声明的邻居
    pub peers: HashMap<NodeId, NodeMeta>,             // alias / last_seen / incarnation / accepts_egress
    pub segments: HashMap<IpNet, Vec<NodeId>>,        // 网段 → 能直达它的节点集合（§9.1）
    pub listen_addrs: HashMap<NodeId, ListenAdvert>,  // 各节点广播的入向监听端点（§6.5）
    pub shared_rules: Option<RuleSetAd>,              // 当前生效的共享规则集（LWW，§9.4.3）
    pub version: u64,                                 // 任一变化即自增，用于路由缓存与规则表失效
}
pub struct PeerAdj { pub incarnation: u64, pub seq: u64, pub edges: Vec<AdjEntry>, pub updated_at: Instant }
pub struct NodeMeta {
    pub alias: Option<String>,
    pub accepts_egress: bool,     // §9.4.4 用它把不愿做出口的节点直接排除出候选
    pub last_seen: Instant,
    pub incarnation: u64,
}
```

**广播：两种模式（2026-10-12 修订）**

1. **变化驱动 flood（主）**：本节点的 `edges` / `subnets` / `listen` / `accepts_egress` / `rule_set` 任一变化，或 `incarnation` 自增时，**立即**广播一次，且该次广播**允许中继**（`ttl = gossip_flood_ttl`，默认 `4`），配合 `(owner, seq)` 的 LRU 去重把它扩散到全网。
2. **周期一跳刷新（辅）**：每 `gossip_interval_ms`（默认 5 s）向所有直连邻居发一次自己的公告，`ttl = 1`（**不允许中继**）。用于活性确认与稳态微调。

**为什么必须两种都有（这曾是本设计的致命缺陷）**：若只有一跳传播，每个节点只能知道"我的邻居"与"邻居的邻居"（2 跳邻域）。四节点链 `A—B—C—D` 里 A 永远收不到 C 的公告，因而**不知道 D 存在** —— 多跳路由、§3.2 的示例、监听端点扩散、§9.3 的孤岛判定会**同时失效**。把"变化"与"周期"分开之后：信息能到达全网，而稳态流量仍与网络规模解耦（稳态只有一跳刷新），与"避免在大网格里放大流量"的初衷一致。

**反熵补漏（`digest`）**：每个 `GossipMsg` 附带 `digest: Vec<(NodeId, u64)>` —— 本节点已知的每个节点的最新 `seq`。邻居收到后比对自身：

- 发现"对方有、我没有"的 `(owner, seq)` → 回一个 `Pull{owner, from_seq}` 请求补发；
- 发现"我有、对方没有"（说明对方重启过或错过了历史）→ 直接反向推给它。

这补上了两种缺口：**变化时那一次 flood 恰好丢包**，以及**节点重启后错过历史**。收敛不再依赖"那一次广播必须成功"。

**合并**：收到 `GossipMsg` 后：
- 若 `owner` 的 `incarnation` 比本地记录新 → 整体替换该 owner 的 `edges`；
- 若更旧 → 丢弃（陈旧信息不能覆盖新信息）；
- 若相等但 `seq` 更新 → 替换；
- **反驳（refutation）**：如果收到的邻接表描述的是**我自己**，且与我的真实状态不符，则 `incarnation += 1` 并立即重播，纠正全网误解。
- **自身身份冲突自检**：若收到的 `owner` 与我相同、但 `edges`/`subnets`/`listen` 与我的真实状态**长期**不符（反驳若干个周期后仍竞争），说明有另一台机器配成了同一个 `overlay_addr`。这是**配置错误**而非网络问题，必须显式告警到前端（"检测到另一节点声称的身份与你相同，请检查 `node.overlay_addr`"），否则会表现为拓扑反复抖动、难以定位。
- **共享规则集（LWW register，§9.4.3）**：`rule_set` 是**整份替换**语义，**不逐条合并**。比较键 `(revision, publisher)` 按字典序，大者胜；相等则保留现有的。因此多发布者并发时表现为"后发布者整体覆盖先发布者"，任何节点独立计算都得到同一份 —— 这就是不需要版本向量、不需要中心的原因。发布者必须先把本地 `revision += 1` 再广播。
- **监听端点与出口意愿**：`listen` 存入 `Topology.listen_addrs`（带 `ttl_secs` 过期）；`accepts_egress` 存入 `Topology.peers`，供 §9.4.4 在选出口时**直接排除**不愿做出口的节点，避免"选了它、被它拒绝"的无谓往返。

**中继广播帧的落点（实现时补充）**：`dst = BROADCAST` 的帧**不能交给路由器** —— 哨兵不在拓扑图里，查表必然得到"无路由"。多跳扩散的语义就是"发给**除来源之外**的每一条直连链路"。这一点在整个机制里是关键一环：C 的公告就是靠 B 这样转给 A 的（§6.5 第 3 条）。

**去重与中继**：`Gossip` 帧可中继，用 LRU 集合按 `(owner, seq)` 去重。**注意去重键取自载荷里的 `owner`/`seq`，而不是帧头的 `src`/`stream_id`** —— 中继别人的公告时 `src` 仍是原作者、`stream_id` 恒为 0（§5.1）。`ttl` 限制扩散半径：变化驱动广播用 `gossip_flood_ttl`（默认 4），周期刷新用 1（不中继）。

**选路**：`Router` 用 `petgraph::stable_graph::StableDiGraph<NodeId, u32>`，每次 `topology.version` 变化就重建图并失效缓存：

```rust
pub struct Router { graph: StableDiGraph<NodeId, u32>, index: HashMap<NodeId, NodeIndex>, cache: HashMap<NodeId, CachedRoute>, version: u64 }
pub struct CachedRoute { pub next_hop: NodeId, pub cost: u32, pub hops: u8, pub alt: Option<NodeId> }

impl Router {
    pub fn rebuild(&mut self, topo: &Topology, self_id: NodeId);
    pub fn next_hop(&mut self, topo: &Topology, dst: NodeId) -> Option<&CachedRoute>; // 懒计算 + 缓存
}
```

- 边权重：`cost = carrier_base + rtt_penalty + load_penalty`。`carrier_base`：同网段 `1`、跨网段拨号 `5`、中继跳 `+3/跳`。直觉是"能同网段就同网段，能直连就直连"。
- 同时保留次优下一跳 `alt`，主路径写失败时立即切换并触发重算。**切换的前提是该流在途帧数为 0**（复用信用账本，§5.5），否则会产生分片乱序；长期繁忙的流由 `route_switch_timeout_ms`（默认 30 s）兜底强制切换并告警。
- **图的边是双向的**：一次成功的单向拨号（A 拨 B）在「建立方向」上是有向的，但得到的会话**双向可用**（§3.1）。因此 `rebuild` 时对每条活链路添加**两条**弧，权重相同。只有链路 `health = Down` 时才移除。

### 6.4 组件 D：中继与本地 SOCKS5

- 本地监听 `127.0.0.1:1080`（可配），实现 SOCKS5 的 `CONNECT`（无认证或用户名密码）。`BIND`/`UDP ASSOCIATE` 不在 v1 范围。
- CONNECT 目标先经 §9.4 规则匹配 + §9.5 合流链选出出口节点，得到 `dst_node`；分配本节点内唯一的 `stream_id`，发 `StreamOpen`，等 `StreamAck`：
  - `ok` → 回 SOCKS5 成功应答，随后双向泵字节（本地 socket ⇄ 帧）；
  - `err` → 回 SOCKS5 对应的错误码（`0x03` 网络不可达 / `0x05` 连接被拒）。
  - **`dst_node == SELF` 时短路**：直接本地 `TcpStream::connect`，不给自己发帧（§9.4.4）。
- **流级信用**：源节点维护该流的发送信用（窗口 32 帧），**收到 `WindowUpdate` 才继续从本地 socket 读取**；出口节点把帧写进本地 socket、腾出缓冲后回收信用并回传（§5.5）。这是"慢消费者只影响自己那条流"的实现方式。
- 出口侧（收到 `StreamOpen` 的节点）在自己本地 `TcpStream::connect(endpoint)`，成功回 `StreamAck` 并起两个泵任务；失败回错误码。
- **中继转发（组件 D 的第二半）**：中间节点看到 `dst_node != self` 时，只改 TTL，按路由表投给下一跳，载荷一个字节都不看。

### 6.5 组件 E：发现（混合策略）

按你的回答设计成三层，互相补充：

1. **静态种子（引导，跨网段第一条链路必须）**：配置 `peers.seeds = ["10.1.2.3:20000"]`（端口写 IT 授权给对端的那个）。这是唯一能穿过白名单孔洞的方式，无法自动化 —— **但它只在冷启动时需要**：一旦本节点与任意一个远端节点接通，第 3 条的监听端点广播就会把其余候选自动带过来，所以 `seeds` 是"引火柴"而不是"对端清单"。白名单不限端口时可直接写地址不带端口（`"10.1.2.3"`），由 dialer 按 `probe_ports` 试探（§6.2.2）。
2. **局域网自动发现（同网段自动组网）**：UDP 向 `255.255.255.255:5679` 与各网卡定向广播地址周期性发送探针，内容为 `{magic, node_addr, listen_port, alias, nonce}`；收到即尝试 TCP 握手。同时监听自己的广播端口回包。可选 mDNS（`_hiveproxy._tcp.local.`）作为第二通道，在禁广播的网络里兜底。
   - 全网状问题：同网段 n 台机器若两两建链是 O(n²)。因此**同网段建链也走 `max_links` 上限与成本排序**，只保留到最近若干台的直链，其余走中继。局域网节点加入拓扑后仍会通过 gossip 扩散，保证跨网段可达。
3. **监听端点广播（网络聚合，默认开启）**：每个节点在 gossip 里带上 `listen: ListenAdvert`（自己 `listen.bind × listen.ports` 展开出的地址，§5.7），并**由邻居随邻接表一起转发出去**。效果是：A 拨通了 B，B 就把"A 在 `10.1.2.5:20000` 上监听"这个事实带给了 C；C 于是有了一个**自动发现的新候选拨号目标**，不必有人在 C 上手工写 `seeds`。

   采信规则（`accept_listen_adverts`，默认 `true`）：
   - **（2026-10-12 决策）不做地址过滤**：任何节点广播的任意地址都会被纳入候选并尝试连接。原 `allowed_cidrs` 白名单已删除，理由是把配置压到最简。代价与缓解见 §17 风险 18；要整体关闭这类来源，把 `accept_listen_adverts` 置 `false`。
   - 排除自己；同一 `NodeId` 已有活链路时不再重复拨。
   - 同一 `NodeId` 若握手（`HelloAck.listen_ports`）观测到的端点与广播不符，**以实测为准**并记录告警 —— 这是 §6.2.3 对齐自检的自然延伸。
   - 拨不通按指数退避；连续失败超过阈值后把该候选**降级**（慢速重试而非删除），因为对端可能只是还没启动（§6.2.1 第 3 点）。
   - 候选总量设上限 `max_dial_candidates`，按"最近成功过 / 成本最低"优先保留。

   **必须诚实说明它的能力边界：广播监听地址 ≠ 能拨通。** 谁能拨到谁由防火墙单向白名单决定，软件推不出来，只有试才知道。所以这套机制的作用是**把"已知候选"自动化**，而不是**保证连通**。真正的兜底仍是：种子引导 + 常驻重连 + 指数退避。它的价值在于把手工 `seeds` 从"每个对端写一行"降到"整个网段写一次引导"。

后续可选进阶（不在 v1）：UDP 打洞 + 会合点，适用于"仅 TCP 被过滤、UDP 可通"的环境。

### 6.6 组件 F：加密（占位与演进）

```rust
pub trait CryptoProvider: Send + Sync {
    fn keygen(&self) -> SigKey;
    // 注意：这里**没有** `node_id_of`。身份是地址（§5.8），不由密钥派生。
    // 密钥只证明「我确实是这个地址上的节点」，而不是定义我是谁。
    fn handshake(&self, local: &SigKey, peer_pk: &[u8], nonce: &[u8]) -> Result<SharedSecret>;
    fn seal_stream(&self, secret: &SharedSecret, stream_id: u64, plaintext: &[u8]) -> Bytes;
    fn open_stream(&self, secret: &SharedSecret, stream_id: u64, ciphertext: &[u8]) -> Result<Bytes>;
}
```

- v1：`PlaintextProvider`，`seal`/`open` 原样进出，`flags.ENCRYPTED` 恒为 0。全网可跑通、可中继、可观测。
- v2：Ed25519 身份 + X25519 ECDH + HKDF 派生每流密钥 + ChaCha20-Poly1305。`StreamOpen` 携带发起方临时公钥 `e2e_pk`，出口节点本地派生同一密钥。**中间节点没有密钥，看到 `flags.ENCRYPTED` 只做透传**，因此是真正的端到端，而不是逐跳。
- 链路层加密（逐跳，如 TLS/Noise 包在 TCP 上）作为独立槽位，与端到端加密正交，可单独启用。

### 6.7 组件 G：可观测性与 Tauri 集成

**分 crate**：`hiveproxy-core`（纯 Rust，无 Tauri 依赖，可独立测试与替换 UI）+ `hiveproxy-app`（Tauri 壳）。core 通过 `tokio::sync::broadcast` 对外发事件，Tauri 层转成前端事件。

事件契约：

| 事件 | 频率 | 载荷 |
| :--- | :--- | :--- |
| `hive://topology` | 拓扑变化时 + 每 5s | `{nodes:[{peer,alias,is_self,incarnation,subnets,listen,last_seen}], edges:[{from,to,cost,carrier,health,establisher,rtt_ms}]}` |
| `hive://rules` | 规则表变化时 | `{merged:[Rule…], local_count, shared_source, shared_revision}` |
| `hive://stats` | 每 1s | `{links, active_streams, bytes_relayed_in/out, frames_dropped, route_rebuilds}` |
| `hive://log` | 实时 | `{ts, level, module, msg}` |

Tauri 命令：

```rust
#[tauri::command] async fn list_nodes(state) -> Vec<NodeView>;
#[tauri::command] async fn get_config(state) -> Config;
#[tauri::command] async fn set_config(state, cfg: Config) -> Result<(), String>; // 热更新：ArcSwap 换配置，按需重建 dialer
#[tauri::command] async fn add_seed(state, addr: String) -> Result<(), String>;
#[tauri::command] async fn remove_seed(state, addr: String) -> Result<(), String>;
#[tauri::command] async fn ping_peer(state, peer: NodeId) -> Result<u32, String>; // 返回 RTT
#[tauri::command] async fn list_segments(state) -> Vec<SegmentView>;              // 全网网段并集
#[tauri::command] async fn list_groups(state) -> Vec<GroupView>;                  // route.groups + 网段派生的组

// ---- 规则 ----
#[tauri::command] async fn get_rules(state) -> RuleTable;                 // 本地+共享合并表，含本地/共享分界与来源 revision
#[tauri::command] async fn set_rules(state, rules: Vec<Rule>) -> Result<(), String>;   // 只改本地规则，**不**发布
#[tauri::command] async fn preview_rules(state, rules: Vec<Rule>) -> RulePreview;      // dry-run：影响面 + 永不命中的条目
#[tauri::command] async fn publish_rules(state, rules: Vec<Rule>) -> Result<u64, String>; // 发布前把 alias 解析成 NodeId；解析不到则整次拒绝
#[tauri::command] async fn revoke_shared_rules(state) -> Result<(), String>;  // 撤回：发布一份空规则集（revision 继续递增）
#[tauri::command] async fn set_rules_enabled(state, enabled: bool) -> Result<(), String>; // 全局旁路：false = 只跑内置网段匹配（§9.4.4）
#[tauri::command] async fn sort_rules_by_specificity(state, rules: Vec<Rule>) -> Vec<Rule>; // 一键按具体度重排（§9.4.2）
#[tauri::command] async fn get_rule_stats(state) -> Vec<RuleStat>;        // 每条规则的命中次数 / 最近生效出口 / 最近拒绝
#[tauri::command] async fn open_stream_probe(state, target: String) -> Result<u32, String>;

// ---- 配套视图类型（前端契约，与上面的 IPC 返回体、事件载荷一一对应）----
pub struct NodeView {
    pub peer: NodeId, pub alias: Option<String>, pub is_self: bool,
    pub subnets: Vec<IpNet>, pub listen: Vec<SocketAddr>,
    pub accepts_egress: bool, pub last_seen_ms: u64,
}
pub struct GroupView  { pub name: String, pub source: GroupSource, pub members: Vec<NodeId> }
pub enum GroupSource  { Explicit, Subnet(IpNet) }
pub struct RulePreview {
    pub changes: Vec<RuleChange>,      // 哪些目标会改道
    pub never_matched: Vec<usize>,     // 永远匹配不到的条目下标
    pub blackholes: Vec<usize>,        // 会把流量变成黑洞的条目下标
}
pub struct RuleStat { pub index: usize, pub hits: u64, pub last_egress: Option<NodeId>, pub last_rejected_at: Option<u64> }
```

### 6.8 组件 H：全局状态

```rust
pub struct HiveState {
    pub node: Arc<NodeIdentity>,                // 自己的地址 + 可选密钥 + 监听配置
    pub config: Arc<ArcSwap<Config>>,           // 支持热更新

    // ── 权威源：只有这一处可写 ──────────────────────────────
    pub topology: RwLock<Topology>,             // 邻接表 + segments + listen_addrs + shared_rules
    pub publish: RwLock<PublishState>,          // 本节点自己的发布状态（§9.4.3）

    // ── 派生缓存：由 topology.version / 规则版本重建，只读 ────
    pub router: RwLock<Router>,
    pub rules: RwLock<RuleTable>,               // = config.route.rules ++ topology.shared_rules
                                                //   （config.route.rules_enabled = false 时只有网段兜底）

    pub links: DashMap<NodeId, LinkHandle>,
    pub streams: DashMap<StreamKey, StreamCtx>, // (peer, stream_id) 本地端点
    pub stats: Arc<Stats>,
    pub events: broadcast::Sender<HiveEvent>,
    pub shutdown: CancellationToken,
}
pub struct StreamKey(pub NodeId, pub u64);

/// 发布侧状态。**必须持久化**（`data/publish_state.json`）：
/// 否则进程重启后 `own_revision` 归零，新发布的规则集会因
/// `(0, me) < (旧 revision, me)` 而被全网判为旧消息**永久忽略**（§9.4.3）。
pub struct PublishState { pub own_revision: u64, pub last_published: Vec<Rule> }
```

> 之前版本在 `HiveState` 里同时存在 `segments` 与 `rules` 两个可写字段，与 `Topology` 中的同名数据重复。现在**只保留 `Topology` 一个权威源**，`rules` 与 `router` 明确标注为派生缓存，`version` 变化时重建 —— 这样"谁是最新的"不再有歧义。

---

## 7. 核心数据结构与接口骨架

```rust
// ---- proto/header.rs ----
pub const MAGIC: u8 = 0x48;
pub const HEADER_LEN: usize = 48;
pub const MAX_FRAME_PAYLOAD: u32 = 256 * 1024;

/// 节点身份 = 节点地址。16 字节定长，IPv4 存 v4-mapped IPv6 形式（§5.8）。
/// 实现 Display / FromStr，使日志与配置里看到的都是 `10.1.2.3` 这样的普通地址。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    pub fn from_ip(ip: IpAddr) -> Self;      // IPv4 自动转 v4-mapped
    pub fn to_ip(&self) -> Option<IpAddr>;   // 非 v4-mapped 则按 IPv6 解析
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType { Reserved=0, Hello=1, Ping=2, Pong=3, Gossip=4, StreamOpen=5, StreamAck=6, StreamClose=7, WindowUpdate=8, Unreachable=9, Data=0xA }

#[derive(Clone, Copy, Debug)]
pub struct HiveHeader {
    pub version: u8,
    pub msg_type: MsgType,
    pub flags: u8,
    pub ttl: u8,
    pub src: NodeId,
    pub dst: NodeId,
    pub stream_id: u64,
    pub payload_len: u32,
}

impl HiveHeader {
    pub fn encode_into(&self, buf: &mut BytesMut);          // 写 48 字节
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError>;  // 读 48 字节，校验 magic/version/payload_len
    pub fn is_for(&self, me: NodeId) -> bool { self.dst == me }
    pub fn is_control(&self) -> bool { self.flags & flags::CONTROL != 0 }
}

// ---- proto/codec.rs ----
/// 从异步流中读出一整帧（头 + 载荷），返回头与载荷的共享缓冲。
/// 只分配一次：BytesMut::with_capacity(HEADER_LEN + payload_len)。
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(HiveHeader, BytesMut), ProtoError>;

/// 把一整帧写出去。relay 路径传入的就是从上游读到的同一块缓冲（ttl 已改）。
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, raw: &[u8]) -> Result<(), ProtoError>;

// ---- relay/mod.rs ----
pub async fn route_packet(state: Arc<HiveState>, header: HiveHeader, payload: Bytes) -> Result<(), RelayError>;
```

`read_frame` 的失败语义要区分"对端正常关闭"与"协议错误"：前者触发链路拆除 + 拓扑更新，后者立即拆链并记录（可能是恶意流量或版本不兼容）。

---

## 8. `route_packet` 路由分发逻辑

这是整个系统的中枢：每个链路读任务解析出一帧就调用它，判定"本地消费"还是"内存中继"。

```
route_packet(state, header, payload):
    # 0. 前置校验
    if header.ttl == 0:
        stats.dropped_ttl += 1
        send Unreachable{TtlExhausted} back to header.src   # 回执给上一跳，而不是静默丢弃
        return
    if header.version != 1:
        return  # 版本不符，丢弃（未来按 ver_min/ver_max 转换）

    # 1. 控制帧：优先车道处理
    if header.is_control():
        match header.msg_type:
            Gossip:
                msg = decode(payload)
                # ★ 去重键取自载荷 (owner, seq)，不是帧头 src/stream_id（§6.3）
                if seen((msg.owner, msg.seq)):
                    return
                topology.merge(msg)                     # 可能触发 version++
                router.invalidate_if_stale()
                # 反熵：比对 digest，发现对方有而我没有的，就回拉
                for (owner, seq) in msg.digest where seq > local_seq(owner):
                    send Pull{owner, from_seq: local_seq(owner)} to header.src
                if header.dst == BROADCAST:              # 变化驱动的 flood（ttl 由发送方设为 gossip_flood_ttl）
                    return relay(state, header, payload)
                return
            Pull:
                if header.dst == self: return send_announcements(msg.owner, msg.from_seq) to header.src
                else:                  return relay(state, header, payload)
            Ping:
                if header.dst == self: send_pong(back to src)
                else:                 return relay(state, header, payload)
            Hello:                   return drop()           # 握手不可中继
            StreamOpen | StreamAck | StreamClose | WindowUpdate | Unreachable:
                if header.dst == self: return handle_control_local(header, payload)
                else:                  return relay(state, header, payload)

    # 2. 数据帧
    if header.msg_type == Data:
        if header.is_for(self):
            # ---- 本地消费 ----
            match streams.get(StreamKey(header.src, header.stream_id)):
                Some(ctx) =>
                    # 信用窗口保证正常情况不溢出；真溢出说明对端不守信用 -> 关流，不静默跳过
                    match ctx.sink.try_send(payload)        # 无拷贝，直接进本地 socket 写泵
                        Ok(_)  => ctx.ack_frames(1)         # 攒够若干帧再批量回 WindowUpdate
                        Err(Full | Closed) => {
                            stats.stream_dropped += 1
                            ctx.close()                     # 无流内序号，静默丢 = 静默损坏
                        }
                    return
                None =>
                    send StreamClose(stream_id) back to header.src   # 未知流：让对方收尾
                    return
        else:
            # ---- 内存中继转发 ----
            return relay(state, header, payload)

    stats.unknown_type += 1

# 中继：唯一改动的字节是 ttl
relay(state, header, payload):
    header.ttl -= 1
    out = OutboundFrame{header, payload}
    # 快路径：目的就是直连邻居，省掉 Dijkstra
    if let Some(link) = links.get(header.dst):
        return link.tx.try_send(out)          # 数据帧不阻塞读任务（§5.5）
    # 慢路径：算下一跳
    match router.next_hop(header.dst):
        Some(route) =>
            match links.get(route.next_hop):
                Some(link) => link.tx.try_send(...)   # 载荷原样，dst 保持最终目标
                None       => { router.invalidate(); send Unreachable{NoRoute} back to src }
        None =>
            send Unreachable{NoRoute} back to src     # 无路由，回源
    # 注意：relay 全程不解 payload；ENCRYPTED 帧只透传
```

判定表：

| `dst` 是谁 | `msg_type` | 动作 |
| :--- | :--- | :--- |
| 我 | `Data` | 查 `streams` → 投给本地 socket 写泵 |
| 我 | 控制类 | 本地处理（gossip 合并 / open 发起本地连接 / ack 唤醒等待者） |
| 不是我 | `Data` | 改 TTL → 快路径直连或 Dijkstra 选下一跳 → 投出，**不解载荷** |
| 不是我 | 可中继控制 | 同 Data 路径，但 gossip 需去重、`Hello` 不可中继 |
| 任意 | `ttl == 0` | 丢弃 + `Unreachable` 回源 |

---

## 9. 寻址与出口选择

这是 IDEA.md 里最模糊、也是体验成败的关键点。客户端始终填**真实的** `目标ip:port`（或域名），hiveproxy 自己回答"这个目标该由谁去连"。2026-10-12 修订后，答案只有两级：**网段自动匹配**（零配置，§9.1）与**路由规则**（本地管理、可一键发布，§9.4）。

### 9.1 唯一的自动声明：本机网段

**新版里每个节点只广播两样东西**（§5.3）：`subnets`（我所在的本机网段）与 `listen`（我在哪些地址上监听）。没有 `services`、没有 `caps` —— **不需要任何人手工声明"我能到某域名/某服务"**。

- **默认（零配置）：自动共享本机所在子网**（§18 第 14 条）。节点启动时枚举本机所有非回环网卡，为每个网卡**所在的子网**（不是单个 IP）生成一条记录。语义是"从这个网络位置，我能直达这个网段里任意主机的任意端口"。全网共享，于是**所有节点的本地网段自动并成一个逻辑网络** —— 这就是"孤岛合并"，不需要任何人写一行配置。
- `auto_share_subnets = true`（默认）：上面这条自动共享。置 `false` = 本节点参与网络但**不告诉别人**自己的本地网段（敏感机器可用，代价是别人访问不了它那一片）。

> ⚠️ **「我自己能连什么」与「我告诉别人什么」是两件事，不能混。**
>
> | 概念 | 由谁决定 | 关掉它的后果 |
> | :--- | :--- | :--- |
> | **本机可达范围**（`NodeIdentity.subnets`） | 枚举网卡，**没有开关** | —— |
> | **是否广播这些网段**（`share.auto_share_subnets`） | 配置 | 别人看不到我那一片；**我自己照常访问** |
> | **是否替别人转发**（`egress.allow_egress`） | 配置 | 别人不能把流量交给我；**我自己照常出得去** |
>
> 早期版本把这三件事绑在一起，结果是：敏感机器一关 `auto_share_subnets`，**连自己局域网里的目标都访问不了了**；一关 `allow_egress`，连 `egress = "direct"` 的规则都失效。已修正，并在 `resolver.rs` 里用"`ResolveCtx` 根本不携带 `allow_egress` 字段"的方式把这个错误在**类型层面**堵死（§19.2 第 12、13 条）。
- `share_ports_only = []`：非空时自动共享只覆盖这些端口；留空 = 不限端口。**这个限制会随 `SubnetAd.ports` 一起广播出去**（§5.3）—— 接收方据此知道"这个网段只有这几个端口可用"，而不是盲目当成全端口。
- 收到后写入 `segments`（网段 → 能直达它的节点集合），这就是"谁能到哪"的**全部**索引。

**为什么这比"声明能力"好。** 原设计要求使用者手工声明"我能到 `api.corp.example.com:443`"这类能力，再由 gossip 汇聚成一张解析表；而网段是**机器自己就知道的事实**（枚举网卡即可），不需要人手写、不需要跨节点协商语义、也不需要额外的一致性机制。内网 IP 目标本来就落在某个节点的网段里，所以自动匹配能覆盖绝大多数情况，手工规则只剩残余场景。

**它覆盖不到什么（这正是 §9.4 存在的理由）**：域名目标，以及**不在任何节点网段内、但某个节点事实上够得着**的目标（静态路由、VPN、跳板机）。这两类只能靠规则显式指定出口 —— 不存在自动发现的可能，因为"够得着"是防火墙与路由表的事，软件推不出来。

### 9.2 SOCKS5 目标解析流程

客户端发来 `host:port` 后，按顺序走：

| 步骤 | 做什么 | 命中后 |
| :--- | :--- | :--- |
| 0 | **区域分流**：目标是 `z<zone>+ip:port` 或 overlay 地址时，先摘出 zone 前缀，把候选收敛到那一个孤岛（§9.3 情形二） | 跳到第 2 步，且只在孤岛内选出口 |
| 1 | **规则匹配**：把 `host:port` 与合并规则表（本地在前、共享在后）逐条比对，**先匹配者胜**（§9.4） | 按规则的 `egress` 定出口；`egress = auto` 时落到第 2 步 |
| 2 | **网段匹配（= 内置的最后一条规则）**：目标 IP 落在某个已知网段 → 在该网段的**声明者**中选路由成本最低者 | 得到出口节点 |
| 3 | **无匹配** | 回 SOCKS5 `0x04 Host unreachable`，并在日志与前端列出"当前可用的网段"，而不是静默本地直连 |

**两条旧的解析路径在新模型里换了表达，而不是被删掉**：

- 旧的「别名直连 `alias:port`」→ 规则里写 `egress = "alias:gpu-01"`；
- 旧的「约定后缀 `<node_addr>.hive:port`」→ 规则里写 `egress = "10.1.2.3"`（即 `EgressTarget::Node`）。

这样"日常规则"和"逃生口"共用一套语义与一套 UI，不必再维护两张并行的心智模型。第 0 步的 zone 前缀保留不变。

### 9.3 重叠与冲突处理

同一个 `ip:port` 被多个节点声明时，有**两种性质完全不同**的情形，必须先分开，否则会把正常情况误报成冲突。

**情形一：同一个局域网被多个节点声明（正常，不是冲突）。**

两个节点都在 `10.1.2.0/24`，且它们本身就在同一个 L2 广播域里。这时"两个来源"其实是**同一张网的两条冗余出口**。

**判定方法（实现时修正）：** 唯一能区分"同一片 L2"与"两片碰巧同号的隔离网"的信号，是**它们是否在同一个广播域里**，也就是链路被标成 `Carrier::Lan`。实现据此把"声明了同一 CIDR 的节点"按 Lan 边做连通分量，每个分量是一个孤岛。

为什么不能用别的判据：

- **"身份地址落在同一前缀内"不行** —— 两片隔离孤岛都用 `10.1.2.0/24` 时，两侧节点的身份地址也都在 `10.1.2.0/24` 里，这个判据只会得出"永远不冲突"。
- **"overlay 图上连通"不行** —— 孤岛之间正是被这张网连起来的。

**已知局限（保守方向）**：`max_links` 剪枝会让同一 L2 的节点之间没有直连边，从而被拆成多个孤岛 → **误报冲突**（系统多派生了几个 `zone`，用户被多要求写一次前缀，但不会走错路）；用 `node.overlay_addr` 覆盖身份时载体判定依据的是身份地址而非本机网卡，可能不准。两者都宁可多分一个 `zone`，也不要漏掉真冲突。

判定为同一网段后：

- 该网段只登记为**一个**逻辑网段、若干候选出口（不是多个来源）；
- 出口按"路由成本最低者"选取（同网段 > 跨网段直连 > 多跳），成本相同则按 `NodeId` 字节序稳定裁决，保证全网一致；
- 其余出口天然成为**备选路径**：主出口失联时立即切换，无需任何额外配置。这正对应"多路径选最近、其余备选、个别节点掉线不影响整体"。

用户对这种情形**完全无感**，也不需要任何消歧动作。

**情形二：两片不同的孤岛用了同一个私网网段（真冲突）。**

两个彼此隔离的局域网都用 `10.1.2.0/24`，此时 `10.1.2.5:3306` 字面上有两个互不相通的来源。**系统自动解决，不需要人工配置**：

1. **自动检测**：同一 CIDR 被**互不相邻**的孤岛分别声明时（情形一的判定不成立），判定为真冲突。
2. **自动分配唯一前缀**：为每个孤岛确定性地派生一个全网唯一的区域号 `zone`。种子取该孤岛内**字节序最小的 NodeId**，所以**任何节点独立计算都得到同一结果**，不需要任何中心协调或人工分配。前缀形如 `fd00:<zone>::/64`，短标签写作 `z<zone>`。
   - **孤岛成员从已有数据推导，协议层无需新增字段**：每个节点已经通过 gossip 持有全网 `segments`（谁声明了哪些网段，§9.1）与邻接关系（哪些节点同 L2，§9.3 情形一的判定）。把"声明了同一 CIDR 的节点"按 L2 相邻性分组，就得到孤岛划分；每个节点本地都算得出同一份划分，因而算出同一个 zone。
3. **确定性映射**：孤岛的真实网段映射到该 zone 前缀之下，真实 IP 保留在低位。例如孤岛 `z7` 的 `10.1.2.5` → `fd00:7::10.1.2.5`（也写作 `z7+10.1.2.5`）。映射双向可逆，任何节点都能从真实 IP + zone 算出 overlay 地址，反之亦然。
4. **解析优先级**（决定何时无感、何时需要 zone）：

| 情形 | 解析 | 用户感受 |
| :--- | :--- | :--- |
| 目标 IP 只属于一个孤岛 | 直接用真实 IP | **无感**（绝大多数情况） |
| 目标 IP 属于多个孤岛，请求方就在其中之一 | 选**请求方所在孤岛** | **无感**（"我自己那台 10.1.2.5"是天然直觉） |
| 目标 IP 属于多个孤岛，请求方在两片之外 | 用系统分配的 overlay 地址（`z7+10.1.2.5:3306`） | 需指定 zone，前端列出各孤岛对应地址 |

**代价，明说。** 这等于对内网地址做了一次**确定的、可逆的**翻译，只在「真冲突」这个罕见场景下生效。翻译规则全网一致、可离线推算，排障时拿 overlay 地址能反算出真实 IP 与所属孤岛，不会迷路。它换来的是**零人工配置**：不必有人预先知道边界在哪，系统自己发现并命名。

**为什么确定性派生、而非随机分配。** 随机分配需要引入一个分配者，与「无中心」矛盾，且分配者掉线会导致前缀漂移。用孤岛最小 NodeId 作种子，任何节点都能独立算出同一前缀，天然去中心。

**稳定性。** 若某孤岛的锚点节点离线导致 zone 前缀变化，系统在一个 gossip 周期内重新收敛；在途流沿用缓存路径不受影响，新解析使用新前缀。若运维希望前缀永久钉死，可用 `node.zone` 手动冻结（可选，默认自动）。

**与 §5.8 的呼应。** 情形二的根源与 §5.8 的身份重叠同源（两片网段用了同一地址空间），但处理对象不同：§5.8 处理**节点自身标识**的重叠（必须唯一，否则无法建图），这里处理**目标地址**的重叠（可用 zone 前缀在解析层消歧）。

**用户心智**：情形一与「目标只属于一个孤岛」这两类情况占绝大多数，用户照旧填它一直填的内网 `ip:port`，**完全零改变** —— hiveproxy 自己搞定"这个地址此刻该由谁去连"。只有真冲突且请求方在两片之外（罕见）才需要加 zone 限定，且前端会主动提示。

### 9.4 路由规则与出口选择（Rule-based Egress Selection）

§9.1 解决"目标落在谁的网段里"，本节解决"**由谁去连**"。2026-10-12 修订后，出口选择只剩两种来源：一个内置的网段规则，和一张使用者可写的规则表。

#### 9.4.1 为什么是规则，不是能力声明

旧设计让**出口方**声明"我能到 X"，再由全网汇聚成解析表。两个问题：

1. **出口方并不知道消费者的意图。** B 能到 `10.9.0.0/16`，但"谁来用它、由谁出口"是**消费者**的决定（这台机器到 B 的链路快、那台到 C 快）。由声明方替消费方做主是错位的。
2. **它把"我能到哪"变成了需要手工维护的配置。** 而这件事里唯一能被机器自动推导的部分（本机网段）已由 §9.1 免费做了；剩下的部分（防火墙、静态路由、VPN）本来就不可能自动。

所以改成：**出口选择是消费者本地的规则，规则里写"这个目标交给谁"**。出口方只声明它客观知道的两件事（网段、监听地址），不声明意图。

**协议层成本为零**：`StreamOpen` 本来就携带端点交给出口节点做本地 `connect`（§6.4），换出口只是改变 `dst_node` 的算法。

#### 9.4.2 规则表

规则是**有序列表，先匹配者胜**。顺序即优先级，由使用者在 UI 里拖拽决定 —— 因此不需要旧设计里那张"具体度 8 级表"来隐式排序，也不存在"具体度相同怎么办"的歧义。

```toml
# 规则表的顺序就是优先级，自上而下依次匹配，第一条命中即生效
[[route.rules]]
label  = "内网 API 走 gpu-01 出口"      # 可选，仅备注，不参与匹配
host   = "api.corp.example.com"        # "*" | 精确域名/IP | "*.internal.example.com" | "10.9.0.0/16"
port   = 443                           # "*" | 443 | "8000-9000"
egress = "node:10.1.2.3"               # 见下表；本地规则也允许 "alias:gpu-01"
on_unreachable = "fallback"            # fallback（顺延下一条）| fail，默认 fallback
enabled = true
```

**`egress` 的取值**（对应 §5.7 的 `EgressTarget`）—— **前缀式写法**：

| 写法 | 含义 | 典型用途 |
| :--- | :--- | :--- |
| `auto` | 交给内置网段规则：命中网段的声明者中选成本最低者 | "这类目标我不管，谁近谁去" |
| `direct` | 本机直接 connect，不进 overlay | 目标其实就在手边，省一跳 |
| `node:10.1.2.3` | 钉死一个出口节点（裸写 `"10.1.2.3"` 等价，按 `node:` 解析） | "只有这台够得着" |
| `alias:gpu-01` | 用别名写。**仅本地规则允许**，发布时会被解析成 `node:`（§9.4.3） | 地址会变、但语义不变时 |
| `group:db` | **显式集合**，成员见 `[[route.groups]]` | 一组自定义节点 |
| `group:subnet:10.9.0.0/16` | **派生集合**，成员 = 声明了该网段的节点，随拓扑自动增减 | **推荐**：零维护 |
| `block` | 拒绝 | 回 SOCKS5 `0x02` |

**`group` 为何重要**：若所有"只有某台够得着"的目标都写成 `node:X`，X 一停，一整片目标全断。建议这类目标用 `group` 给多个候选，让 §3.4 的"多路径选最近、其余备选"在这一层也生效。`group:subnet:<cidr>` 更是直接复用 §9.1 已有的 `segments` 数据 —— 节点上下线时成员自动跟着变，不需要任何维护。

**顺序由 UI 保证可读性。** 手写顺序即优先级，很容易把 `*` 写在最前面、把后面全部吃掉。因此前端提供两个辅助：

1. **「按具体度重排」按钮**：一键排成 `精确 host+port > 精确 host > 后缀+port > 后缀 > CIDR+port > CIDR > 通配 port > 纯通配`。重排后立即弹出"这次重排会改变哪些目标的出口"的差异，避免误操作。
2. **末尾物化的兜底行**：内置的网段匹配在 UI 里显示为规则表最后一条**只读合成规则**（`⤷ 目标落在已知网段 → 选最近的声明者`）。不可编辑、不可拖动，但用户能看到优先级全貌，代码里也不必再有一条特殊分支。

**匹配是字面对比，不做 DNS 解析**：`host = "api.corp.example.com"` 与 SOCKS5 `ATYP=0x03` 送来的**原始域名**逐字符比较；`host = "10.9.0.0/16"` 与目标 IP 做网段包含判断。

**域名解析必须发生在出口节点**。企业内网普遍是 split-horizon DNS：同一域名在 A 网段解析到内网地址、在 B 网段解析到公网或直接失败。因此 `StreamOpen` 必须携带**原始域名**而不是请求方预解析出的 IP。这是 §5.7 把 `Endpoint.host` 建成 `Host` 枚举的原因，也是 SOCKS5 的 `ATYP=0x03` 必须原样透传到出口的理由。

> **推论（重要）**：域名目标**永远不可能命中"网段匹配"**（没有 IP 可比）。所以删掉 `Reach` 声明后，**每一个"只有某台能解析/到达"的域名都必须有一条规则显式指向它**。这是本次修订最主要的代价，见 §17 风险 13。

**配置字面量与 Rust 类型的映射**：上面的 TOML 为了手写与前端编辑方便，`host` / `port` / `egress` 都写成字符串（`"*.internal.example.com"`、`"8000-9000"`、`"alias:gpu-01"`）。加载时它们被解析成 §5.7 的 `HostMatcher` / `PortMatcher` / `EgressTarget` —— 需要为 `Rule` 写自定义 `Deserialize`，把 `"*"`、`"*.suffix"`、CIDR、`"lo-hi"`、`"group:x"`、`"direct"`、`"block"` 这些字面量映射到对应变体，解析失败时报错而不是静默丢弃（与 `#[serde(deny_unknown_fields)]` 的取向一致）。

#### 9.4.3 本地管理与一键发布

**规则默认只存在于本机配置**。但使用者的真实处境常常是"我就是所有这些机器的管理者，同一条策略不想配 N 遍"，所以再提供**整份发布**：

```
本地规则 (config)  ──┐
                     ├──► 合并规则表（本地整体在前，共享整体在后）──► 逐条匹配
共享规则 (gossip)  ──┘
```

**发布语义 = 一整份 LWW register，不是逐条合并。** 这是本次设计里最关键的一个简化：

- 发布者把**整份规则集**打上 `(publisher, revision)` 广播（`RuleSetAd`，§5.7）；发布前 `revision += 1`。
- 接收方比较 `(revision, publisher)` 字典序，大者胜，**整份替换**。
- 因此**不需要版本向量、不需要共识、不需要中心** —— 每个节点独立比较就得到同一份结果。

对比"逐条合并"（每条规则各自带版本、逐条 LWW）：那才真正需要版本向量，还要额外定义"两条规则冲突"的语义。改成整份替换后，多写者问题坍缩成一个 register 的比较，代价只剩"后发布者整体覆盖先发布者"。

**为什么本地排在共享之前。** 顺序决定覆盖方向：本地规则位于合并列表前部，任何本地规则都先于共享规则被匹配。这保证两件事：

1. 管理者发布策略后，**个别机器仍能自行例外**（"这台机器我就是要它 direct"）；
2. 机器上**没有任何共享规则时行为完全不受影响** —— 合并表就退化成它自己的本地表。

**发布侧的三条要求**（缺一不可，否则"一键发布"要么无效、要么危险）：

1. **`revision` 必须持久化。** 发布前 `revision += 1` 并落盘（`data/publish_state.json`），然后广播。若只放内存里，进程重启后 `revision` 归零，新发布的 `(0, me)` 会被全网判为旧消息而**永久忽略** —— 这是最隐蔽的一种"我明明发布了，却没人听"。
2. **别名必须在发布前解析成 `NodeId`。** `alias:` 只允许出现在本地规则里；`publish_rules` 会把每条规则的 `alias:X` 按本机别名表（`peers.entry`）解析成地址，**解析不到就整次拒绝发布并指出是哪一条**。这样接收方拿到的规则集是**自足的**，不依赖任何本地状态 —— 否则会在别人的机器上静默失效。
3. **发布前必须能预览。** `preview_rules` 返回影响面（哪些目标会改道、有没有条目永远匹配不到、有没有会把流量变成黑洞的条目）。这是"一键"这个动作的安全带。

**接收侧的三个开关**（本场景默认全开，但不可信网格里必须能关）：

1. **本地校验可达性（不可关）。** 规则说"走 `node:X`"，X 对本节点可能根本不可达（§3.1 的不对称路由）。校验不过就按 `on_unreachable` 处理。**共享规则永远不是权威，只是默认值。**
2. **整体拒收开关。** `route.accept_shared_rules = false` 时忽略一切 `rule_set`。默认 `true`。
3. **验签开关。** `security.rule_token` 非空时，`RuleSetAd.hmac` 不符的整份丢弃，与 `join_token` 的处理一致。默认空（不校验）。

**关于「谁可以发布」：不设限制（2026-10-12 决策）。** 任何节点都可以广播 `rule_set`。这是**有意为之**的选择，代价要写清楚：内网里任何一台被接管的机器，都能把**未被本地规则覆盖**的流量改道到它的网络位置（在路 MITM 或黑洞）。结构上仍有一道硬防线 —— **本地规则整体排在共享规则之前**，所以攻击者**无法覆盖你写下的任何一条本地规则**，只能影响你本就没显式管理的目标。若将来环境可信度下降，开启 `rule_token` 或 `accept_shared_rules = false` 即可收紧，不需要改协议。

**撤回**：发布一份**空规则集**即可（`revoke_shared_rules`）。注意不是"删掉规则"，而是发一份空的、`revision` 更高的 —— LWW register 只有"写"没有"删"。

**多发布者的代价，明说**：两个管理员同时发布时，`revision` 小的一方被整体覆盖，且它的机器会忠于覆盖者。这是 LWW 的固有性质，不是 bug。缓解：前端在规则页顶部显著显示**"当前共享策略来自 `<节点>`，revision N，发布于 `<时间>`"**，让覆盖可见；需要更严格时只指定一台机器发布。

#### 9.4.4 选择算法

```
resolve(target: Endpoint, zone_hint: Option<ZoneId>) -> Result<NodeId, UnreachableReason>:
    # 0. 区域分流（§9.3 情形二）：带 zone 前缀时只在那个孤岛内选，不参与全局规则比较
    if let Some(z) = zone_hint:
        return zone_egress(z, target)      # = 在该孤岛内跑 subnet_match，要的就是确定性

    # 1. 规则匹配：合并表 = 本地规则 ++ 共享规则 ++ [只读的网段兜底行]
    #    rules_enabled = false 时整表退化为只剩那条兜底行（§9.4.2 的旁路开关）
    for rule in rules.merged:
        if !rule.enabled or !rule.matches(target): continue
        match rule.egress:
            Block            => return Err(Refused)
            SelfDirect       => return Ok(SELF)
            Node(n)          => if can_egress(n) { return Ok(n) } else { fallthrough(rule) }
            Alias(a)         => 仅本地规则会出现；解析不到等价于 can_egress == false
            Group(Subnet(c)) => if let Some(m) = min_by_cost(egress_candidates(segments.via(c)))
                                    { return Ok(m) } else { fallthrough(rule) }
            Group(Named(g))  => 同上，成员取自 route.groups[g]
            Auto             => if let Ok(m) = subnet_match(target) { return Ok(m) }
                                else { fallthrough(rule) }   # ★ 不再直接 return
    return Err(NoRoute)

# 规则命中但出口不可用时统一处理
fallthrough(rule):
    if rule.on_unreachable == Fail: return Err(NoRoute)
    else: continue      # 顺延下一顺位；最终由表尾兜底行或 NoRoute 收尾

# 出口可用性：有路由，且对端没有声明 accepts_egress = false（§6.3）
can_egress(n) = router.cost_to(n).is_some()
                and n != SELF
                and topology.peers[n].accepts_egress

# 网段匹配 —— 表尾那条只读兜底行的实现，也是 §9.2 第 2 步
subnet_match(target):
    if target.host is Name: return Err(NoRoute)   # ★ 域名没有 IP，永不参与网段匹配（§9.4.2）
    cands = [(n, router.cost_to(n)) for n in segments.via(target.ip)
             where can_egress(n) or n == SELF]
    if cands.is_empty(): return Err(NoRoute)      # 目标不落在任何已知网段（§9.5 第 4 步）
    return min_by(cands, key = (cost, node_addr_bytes))   # 成本相同按字节序稳定裁决
```

**三个最容易写错的地方**（都已在上面修正，实现时请对照）：

- **`Auto` 失败后必须继续往后找**，不能直接 `return` —— 否则一条 `egress = "auto"` 的规则会把它后面的所有规则全部屏蔽。
- **`Block` 返回 `Refused`** —— `UnreachableReason` 里没有 `Denied` 这个变体（§5.7）。
- **域名目标必须先判 `Host::Name`** —— 否则 `target.ip` 无从取值，实现时容易 panic 或走错分支。
- **本机直连不走 `resolve` 的 `SelfDirect` 分支**：`subnet_match` 已让 `SELF` 以成本 0 参选，自然胜出（见下文）。`resolve` 只返回 `NodeId`，调用方在发 `StreamOpen` 前若发现 `dst == SELF`，应短路成本地 `TcpStream::connect`，不给自己发帧。

**"最近"的定义**：`router.cost_to(node)` 已含载体权重（同网段 < 跨网段直连 < 多跳，§6.3）与实测 RTT，所以同网段的出口会自动胜出，符合直觉。

**规则层没有隐式成本比较。** 规则是显式排序的，使用者写什么顺序就是什么顺序；成本比较只出现在 `auto`、`group`、网段匹配这三处"需要在一组里挑一个"的地方。这个分工是刻意的：**人的意图用顺序表达，机器的优化用成本表达，两者不互相干扰。**

**本机访问本网段**：`SELF` 以成本 0 参与网段匹配，自然走直连，无需特殊分支（也可用 `egress = direct` 显式声明）。

**默认行为**（§18 第 14 条"默认即合岛"）：即使一条规则都不写，网段匹配也能覆盖绝大多数目标 —— 所以"一条规则都不写"是完全正常的用法，不是降级状态。

**故障转移**：出口回 `StreamAck{ok:false}`，或超过 `egress_ack_timeout_ms` 未响应时 —— 若该规则 `on_unreachable = fallback`，顺延到下一顺位匹配（最终落到网段规则）；否则直接回 SOCKS5 错误码。命中 `group` 时先在组内换一个成员。成功的选择缓存 `target → egress` 一段 `egress_cache_ttl_ms`（默认 30s），并在 `topology.version` 变化、规则表变化或该出口失联时立即失效。

**安全边界**：出口规则等于"允许把流量引到某个节点的网络位置并发出"。因此 `egress.allow_egress = false` 的节点会在 gossip 里广播 `accepts_egress = false`（§5.3），**请求方选出口时直接把它排除**，而不是"选了它、再被它拒绝"白费一次往返；出口节点自己在执行 `StreamOpen` 前仍会再校验一次，两道关。

**这个开关的作用域，说清楚**：它只约束「**别的节点**能不能把流量交给**我**」，**不约束我自己**。因此：

- 它**不**影响本机访问自己所在的网段 —— `SELF` 在出口候选里**永远可用**（成本 0）；
- 它**不**影响 `egress = "direct"` 的规则 —— "本机直接连"这件事本来就不经过任何网关角色；
- 它**不**影响本机访问"别人贡献出来的网段" —— 那是别人在做出口。

换句话说：**拒绝当网关，不等于自断网络。** 实现上 `ResolveCtx` 干脆不带这个字段，让"把 `allow_egress` 套到自己头上"这件事在类型层面就写不出来。

**全局旁路**：`route.rules_enabled = false` 时，合并表退化为只剩那条只读的网段兜底行 —— 等于回到"纯自动"状态。这是排障用的紧急开关（例如某条规则写错导致全网不通），前端应把它做成显眼的一键按钮并显示当前状态。

### 9.5 寻址链的合流

把 §9.1、§9.2、§9.4 拼起来，一次 SOCKS5 CONNECT 的完整决策链：

0. **区域分流**：目标若带区域限定（`z<zone>+ip:port` 或 overlay 地址），直接收敛到该孤岛选出口，跳过后续全局比较（§9.3 情形二）。
1. **规则匹配**：合并规则表（本地 ++ 共享）自上而下逐条比对 `host:port`，第一条命中者决定出口（§9.4.2）。
2. **就近选择**：步骤 1 得到的结果若是 `auto` / `group` 这类**候选集**，此时按 `router.cost_to` 选成本最低者 → 得到 `dst_node`。
3. **路径计算**：`router.next_hop(dst_node)` → 得到下一跳，配合 `stream_id` 定出投递方向。
4. **无匹配兜底**：规则未命中且目标不落在任何已知网段 → 回 SOCKS5 错误码。因为网段默认已共享（§9.1），这一步极少触发。

**整条链上只有一个"声明"环节**：节点广播自己的网段与监听端点（作为第 2、3 步的依据），其余全是消费者本地的规则与拓扑计算。**不存在跨节点的能力协商** —— 这是本次修订与旧设计最本质的差别。

---

## 10. 配置模型

配置文件 `data/hiveproxy.toml`（前端可编辑，热更新）：

```toml
[node]
# 身份 = 本机地址，无须生成、无须持久化（§5.8）。
# 默认留空 = 自动取 default route 所在网卡的地址。
# 仅当本网段地址与他人重叠时，才钉一个全网唯一地址（通常用 ULA）。
overlay_addr = ""
alias        = ""            # 可选可读名，用于 alias:port 寻址
# zone      = 7               # 可选：手动冻结自动派生的区域号；不写 = 系统自动派生（§9.3）

[listen]
bind = "0.0.0.0"                 # 监听的网卡地址（不含端口）
# 监听端口 = **IT 授权给本机的入向端口**（§6.2.3）。A 能看到你的哪个端口，这里就写哪个。
# 可写多个。未配置时兜底 5678，但那只是"尚未对齐"的默认值，不是固定的 overlay 端口。
ports = [20000]
max_links = 16
# 是否把 `bind × ports` 展开出的监听端点广播给全网，供其它节点自动纳入拨号候选（§6.5 第 3 条）。
# 只广播地址本身，无敏感信息。"能不能拨通"由对方防火墙决定，广播不构成承诺。
advertise = true

[peers]
# 跨网段单向孔洞的对端：现在只作**引导（bootstrap）**，不再是"对端清单"。
# 一旦本节点与任意远端接通，监听端点广播（§6.5 第 3 条）会自动把其余候选带过来，
# 所以常态下写 0~1 条就够，不必每个对端都写一行。
# 三种写法：ip:port（明确端口）/ ip（不限端口，按 probe_ports 试探）/ ip:lo-hi（端口范围）。
seeds = ["10.1.2.3:20000"]              # 写 IT 授权给对端的那个端口（§6.2.3）
probe_ports     = [5678, 5679, 8000, 8080]   # 仅当 seeds 未写端口时才用，按序试探（备用路径）
accept_listen_adverts = true            # 采信 gossip 广播的监听端点作为拨号候选（§6.5）
# 注意：广播候选**不做地址过滤**（2026-10-12 删除了 allowed_cidrs）。
# 任何节点广播的任意监听地址都会被纳入候选并尝试连接 —— 见 §17 风险 18。
# 不信任所在网络时，把 accept_listen_adverts 置 false 可整体关闭这类来源。

[[peers.entry]]                       # 可选：给对端起别名，用于 alias:port 寻址
address = "10.1.2.3:20000"
alias   = "b-gpu"

[discovery]
lan_udp      = true
udp_port     = 5679
mdns         = false
dial_interval_ms = 5000
backoff_max_ms   = 60000
max_dial_candidates = 64     # 拨号候选上限，超出按"最近成功过/成本最低"保留（§6.2）

[share]
# 默认即合岛：自动把本机所在子网作为可被全网使用的出口（§9.1、§18 第 14 条）
auto_share_subnets = true   # false = 参与网络但不贡献本地网段（敏感机器）
share_ports_only   = []     # 非空时：只共享这些端口；留空 = 不限端口。该限制随广播传出（§5.3）
# 注意：这里**没有** expose / capabilities。
# 新版不再需要任何"我能到哪个服务/域名"的声明（§9.4.1）—— 网段是自动的，
# 剩下的例外由**消费者**用下面的路由规则表达，而不是由提供方声明。
# （段名从 [services] 改成 [share]：它已经不含任何"服务"了。）

[egress]
allow_egress          = true   # false = 广播 accepts_egress = false，请求方直接跳过它（§9.4.4）
egress_ack_timeout_ms = 3000
egress_cache_ttl_ms   = 30000

[route]
ttl_default = 8               # 不设应用层跳数上限，只靠 TTL 兜底（§18 第 4 条）
gossip_interval_ms  = 5000    # 周期一跳刷新
gossip_flood_ttl    = 4       # 变化驱动 flood 的扩散半径（§6.3）
cost = { lan = 1, wan = 5, per_hop = 3 }
route_switch_timeout_ms = 30000  # 流长期繁忙时强制切路径的上限（§5.5）
rules_enabled = true          # 全局旁路：false = 忽略全部规则，只跑网段自动匹配（§9.4.4）

# 共享规则集（§9.4.3）
accept_shared_rules = true    # 接收侧：false = 忽略一切共享规则集
publish_enabled     = true    # 发布侧：是否允许本节点对外发布

# ── 显式候选集，供 `egress = "group:<name>"` 使用（§9.4.2）──────────────────
# 另一种写法 `egress = "group:subnet:10.9.0.0/16"` 无需在此定义，成员由网段自动派生。
[[route.groups]]
name    = "db"
members = ["10.1.2.3", "alias:db-2"]

# ── 本地路由规则：**有序列表，先匹配者胜**（§9.4.2）──────────────────────────
# 这些规则整体排在共享规则**之前**，所以本地永远能覆盖共享。
# 不写任何规则也完全正常：内置的网段匹配会兜住绝大多数目标（§9.4.4）。
[[route.rules]]
label  = "内网 API 只有 gpu-01 网段能解析"
host   = "api.corp.example.com"
port   = 443
egress = "alias:gpu-01"              # 别名只在本地规则可用；发布时解析成 node:（§9.4.3）
on_unreachable = "fallback"

[[route.rules]]
label  = "10.9.0.0/16 交给声明了该网段的节点（成员自动增减）"
host   = "10.9.0.0/16"
port   = "*"
egress = "group:subnet:10.9.0.0/16"

[[route.rules]]
label  = "本机直连白名单，不进 overlay"
host   = "10.1.2.99"
port   = "*"
egress = "direct"

# 提示：不需要写 `host = "*" → egress = "auto"` 这样的兜底规则 ——
# 内置的网段匹配就是最后一条规则，UI 里会以只读的合成行显示（§9.4.2）。

[proxy]
socks5_bind = "127.0.0.1:1080"
allow_remote_socks = false   # 是否允许非回环地址使用本地 SOCKS5

[security]
join_token = ""              # 空 = 不鉴权；填入即启用握手 HMAC 校验
rule_token = ""              # 空 = 不校验共享规则集签名；填入则验签不过的整份丢弃（§9.4.3）
e2e        = "off"           # off | required（v2 生效）

[log]
level = "info"
```

### 10.1 配置的 Rust 表示

与上面 TOML 一一对应的结构体。`ArcSwap<Config>` 承载它以实现热更新（§6.8）：

```rust
// ---- config.rs ----
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]           // 拼错的键直接报错，而不是静默忽略
pub struct Config {
    pub node: NodeCfg,
    pub listen: ListenCfg,
    pub peers: PeersCfg,
    pub discovery: DiscoveryCfg,
    pub share: ShareCfg,
    pub egress: EgressCfg,
    pub route: RouteCfg,
    pub proxy: ProxyCfg,
    pub security: SecurityCfg,
    pub log: LogCfg,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeCfg {
    pub overlay_addr: Option<IpAddr>,   // 留空 = 自动取 default route 网卡地址（§5.8）
    pub alias: Option<String>,
    pub zone: Option<ZoneId>,           // 可选：手动冻结自动派生的区域号；None = 自动（§9.3）
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListenCfg { pub bind: IpAddr, pub ports: Vec<u16>, pub max_links: usize, pub advertise: bool }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeersCfg {
    pub seeds: Vec<String>,             // "ip:port" | "ip" | "ip:lo-hi"（§6.2.2）—— 仅作引导
    pub probe_ports: Vec<u16>,
    pub accept_listen_adverts: bool,    // 采信 gossip 广播的监听端点（§6.5）
    pub entry: Vec<PeerEntry>,          // 别名表，供规则里的 `alias:` 出口解析（§9.4.2）
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerEntry { pub address: String, pub alias: String }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryCfg {
    pub lan_udp: bool, pub udp_port: u16, pub mdns: bool,
    pub dial_interval_ms: u64, pub backoff_max_ms: u64,
    pub max_dial_candidates: usize,     // 拨号候选上限，超出按"最近成功/成本最低"保留（§6.2）
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareCfg {                    // 段名原为 services，已无任何"服务"含义
    pub auto_share_subnets: bool,        // 默认 true：自动共享本机所在子网（§9.1）
    pub share_ports_only: Vec<u16>,      // 非空时自动共享只覆盖这些端口；随 SubnetAd.ports 广播
    // 没有 expose / capabilities —— 取消"提供方声明能力"，见 §9.4.1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressCfg {
    pub allow_egress: bool,                // false = 不参与出口候选，即使规则指名（§9.4.4）
    pub egress_ack_timeout_ms: u64,
    pub egress_cache_ttl_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteCfg {
    pub ttl_default: u8,               // 不设应用层跳数上限，TTL 就是唯一兜底
    pub gossip_interval_ms: u64,       // 周期一跳刷新间隔
    pub gossip_flood_ttl: u8,          // 变化驱动 flood 的扩散半径（默认 4，§6.3）
    pub route_switch_timeout_ms: u64,  // 流长期繁忙时强制切路径的上限（§5.5）
    pub cost: CostCfg,
    pub rules_enabled: bool,           // 全局旁路：false = 只跑网段匹配（§9.4.4）
    pub rules: Vec<Rule>,              // 本地规则，顺序即优先级（§9.4.2）
    pub groups: Vec<GroupCfg>,         // 显式候选集，供 `egress = "group:<name>"`（§9.4.2）
    pub accept_shared_rules: bool,     // 接收侧：忽略一切共享规则集（§9.4.3）
    pub publish_enabled: bool,         // 发布侧：是否允许本节点对外发布（§9.4.3）
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupCfg { pub name: String, pub members: Vec<String> }  // "10.1.2.3" | "alias:x"

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CostCfg { pub lan: u16, pub wan: u16, pub per_hop: u16 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyCfg { pub socks5_bind: SocketAddr, pub allow_remote_socks: bool }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityCfg {
    pub join_token: String,
    pub e2e: E2eMode,                    // off | required
    pub rule_token: String,              // §9.4.3：共享规则集的 HMAC 标签密钥，空 = 不校验
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum E2eMode { Off, Required }
```

`set_config` 的热更新语义要写清楚：改动 `listen` 需要重建 listener；改动 `peers`/`discovery`/`share` 需要重启 dialer 与网段共享任务；改动 `route.rules`/`route.groups`/`route.rules_enabled` 立即重建合并规则表并触发 `hive://rules` 事件（**不**自动发布到全网 —— 发布必须显式调用 `publish_rules`，§9.4.3）；改动 `log.level` 立即生效。实现上用 `ArcSwap::store` 换掉整个 `Config`，各子系统在下一轮循环读到新值时自愈，不做精细的差量应用。

"零配置"的准确含义（澄清 IDEA 里的矛盾）：**不写每台机器各自的转发配置文件，也不维护全网拓扑**。手工输入只剩两样，且都能压到很小：

1. **引导种子**（可选，0~1 条）：跨网段的**第一条**链路必须由它点火，这是物理防火墙策略决定的，软件无法自动推导。接通之后，监听端点广播会把其余候选补齐（§6.5 第 3 条），所以它是引火柴，不是对端清单。
2. **路由规则**（可选，**一条都不写也完全正常**）：只在目标不落在任何节点网段内、或需要指定特定出口时才写（§9.4.2）。需要多机一致时用一键发布（§9.4.3），不必逐台配置。

同网段内零配置（UDP 自动发现）。**跨网段从"每台配 1~2 条种子"进一步降到"整个网络配一次引导"。**

---

## 11. 安全模型与演进

| 阶段 | 能力 | 代价 |
| :--- | :--- | :--- |
| v1（当前） | 明文、无鉴权。任何人能连上本机的**授权入向端口**（§6.2.3）即可入网，中继节点可见业务明文 | 0，最快跑通目标 |
| v1.5 | 握手 `join_token` HMAC 校验（`security.join_token`）挡住未授权节点；共享规则集 `rule_token` 验签（`security.rule_token`）；流量仍明文 | 数行改动 |
| v2a | 链路层加密（逐跳 TLS/Noise）：防止链路上被抓包 | 需引入 rustls/snow，不影响帧格式 |
| v2b | **端到端加密**：Ed25519 密钥对（**仅用于连接认证，不参与身份派生** —— 身份仍是节点地址，§5.8）+ X25519 ECDH + 每流 ChaCha20-Poly1305。`StreamOpen` 带临时公钥，中间节点只透传 `ENCRYPTED` 帧 | 引入 dalek 系与 aead crate |

威胁模型要点：

- **入网门槛**：v1 里监听端口就是入网门票，必须保证该端口只对白名单网段与内网开放，不要暴露到公网。
- **中继节点的可见性**：v1 明文下，多跳路径上的每一跳都能看到业务内容。本设计**不设** `allow_relay` 开关，也**不限制跳数**（§18 第 3、4 条），因此这条暴露面只能靠 v2b 端到端加密收窄，或靠拓扑设计（避免不必要的多跳）规避。
- **监听端点广播没有任何地址过滤**（2026-10-12 决策删除 `allowed_cidrs`）：任意节点都能广播"我在某个地址上监听"，诱导他人向该地址发起连接。可用的开关只有两个：`accept_listen_adverts = false`（整体关闭这类候选）或 `join_token`（抬高入网门槛，让外部节点连握手都过不去）。详见 §17 风险 18。
- **共享规则集是路由劫持面**（2026-10-12 决策：**不限制发布者**）：任何节点都能广播 `rule_set`，所以内网里任何一台被接管的机器都能把**未被本地规则覆盖**的流量改道到它的网络位置（在路 MITM 或黑洞）。保留三道防线：`accept_shared_rules = false` 整体拒收、`security.rule_token` 验签、**以及"共享规则永远排在本地规则之后"**（本地始终能覆盖）。前两道默认分别是 `true` / 空（即不启用），所以**默认状态下的实际防线只有第三道** —— 这正是"本地规则优先"这个顺序不是可选优化、而是安全结构一部分的原因（§9.4.3）。
- **自身身份冲突**：两台机器配成同一个 `node.overlay_addr` 时，拓扑会反复抖动且极难定位（看起来像"网络不稳定"）。§6.3 的自身身份冲突自检必须在反驳若干周期后仍竞争时显式告警。
- **出口角色是横向移动面**：规则可以把流量引到任意节点的网络位置发出。因此 `egress.allow_egress = false` 可让敏感机器不参与出口候选（即使规则指名它）。
- **默认共享的边界**：默认自动共享本机所在子网（§9.1、§18 第 14 条）是「零配置合岛」的代价，它把本机**整个局域网**开放给全网访问。敏感机器应设 `auto_share_subnets = false`（只消费不贡献），或用 `share_ports_only` 收窄端口面。
- **拒绝服务**：`max_links`、单 IP 上限、`MAX_FRAME_PAYLOAD`、gossip 去重表容量上限共同构成资源上限。

---

## 12. 失败检测与收敛

| 机制 | 参数 | 行为 |
| :--- | :--- | :--- |
| 链路心跳 | 每 3s（空闲时） | 连续 3 次未响应（约 10s）判定 `Down`，拆链，从拓扑删边，**触发一次变化驱动 flood**（§6.3） |
| 世代号反驳 | `incarnation` | 收到关于自己的错误描述时 `+1` 并重播，纠正全网 |
| 自身身份冲突自检 | 反驳若干周期后仍竞争 | 显式告警"另一节点声称的身份与你相同"，指向 `node.overlay_addr` 配置错误（§6.3） |
| 陈旧信息丢弃 | 比较 `incarnation` / `seq` | 旧消息不能覆盖新状态，天然抗乱序 |
| 通道关闭即降级 | 实时 | `link.tx.try_send` 返回 `Closed` → 标记 `Down`、切换次优下一跳、触发重算，不等心跳超时。**队列满不是失败，是背压信号**（§5.5） |
| 流级背压 | 实时 | 出口侧回收信用 → `WindowUpdate` 回传 → 源节点暂停该流读取。**只影响该流**，其它流不受牵连（§5.5） |
| 无路由回执 | 实时 | 回 `Unreachable{last_hop}` 给源节点，源节点可据此提示"某段链路断了" |
| TTL 兜底 | `ttl_default = 8` | 即使图短暂不一致也不会形成永久环路；归零时**回 `Unreachable{TtlExhausted}`**，而不是静默丢弃 |
| 路径切换 | 流在途帧 = 0 | 有替代路径时立即切换；"无在途帧"是硬条件（防止分片乱序），长期繁忙由 `route_switch_timeout_ms` 兜底并告警（§5.5） |
| 收敛目标 | — | 单链路故障后：变化驱动 flood 秒级扩散 + 反熵补漏，目标 **≤ 2 个 gossip 周期（约 10s）**内全网重新可达 |

**不设应用层跳数上限**（§18 第 4 条已确认）：可达性只由帧头 TTL 兜底，`ttl_default = 8`。这意味着足够长的一串单向孔洞也能走通，代价是延迟与故障面随跳数增长。TTL 的作用是**防止图短暂不一致时成环**，而不是限制网络规模。

---

## 13. 性能与资源要点

- **零拷贝路径**：帧在内存中始终是一整块 `BytesMut`；中继只改 1 字节 TTL；`Bytes` 引用计数让多播/多跳不复制数据。
- **缓冲池**：`BytesMut` 从 `bytes` 的池化分配（或简单 slab）取用，避免每帧一次大分配。每帧容量按 `HEADER_LEN + payload_len` 一次性预留。
- **锁粒度**：高频路径（链接池、流表）用 `DashMap` 无全局锁；拓扑与路由用 `parking_lot::RwLock`，只在 gossip 合并与选路时短持有；路由计算结果带 `version` 缓存，稳态下每帧几乎零锁开销。
- **每帧开销**：48 字节固定头。在 1 Gbps 链路上以 256 KiB 帧计，头部开销约 0.02%，可忽略。
- **优化留档**：`ver_type` 高 4 位的版本号允许将来引入"链路本地别名索引"（握手时把 16 字节 NodeId 换成 u16 索引），把每帧头部从 48 字节压到约 20 字节。v1 不做，保留可演进性。
- **上限**：单帧载荷 256 KiB；建议 `max_links ≤ 32`；gossip 去重表 LRU 上限 4096 条。

### 13.1 依赖清单（v1）

| crate | 用途 |
| :--- | :--- |
| `tokio`（full） | 异步运行时、TCP、`mpsc`、`broadcast` |
| `tokio-util` | `CancellationToken`、流适配辅助 |
| `bytes` | 零拷贝缓冲（`Bytes` / `BytesMut` / `Buf`） |
| `serde` + `bincode` | 控制消息序列化 |
| `petgraph` | 拓扑图与 Dijkstra |
| `dashmap` | 链接池/流表等高频路径的无锁映射 |
| `parking_lot` | 拓扑与路由表的读写锁 |
| `arc-swap` | 配置热更新 |
| `ipnet` | CIDR 表示与匹配：规则的 `HostMatcher::Cidr`、网段索引 `Segments`、`ZoneId` 映射（§9.1、§9.3） |
| `if-addrs` | **网卡地址与掩码枚举**。§9.1 的"枚举本机所在子网"、§6.5 的定向广播地址都依赖它 —— `socket2` **不提供**接口地址列举 |
| `socket2` | 套接字选项：`SO_REUSEADDR`、`SO_BROADCAST`、绑定与超时控制 |
| `toml` | 配置文件解析 |
| `tracing` + `tracing-subscriber` | 结构化日志与前端日志事件 |
| `thiserror` | 错误类型 |
| `tauri` v2 | 桌面壳与 IPC |

v2 加密阶段再加：`ed25519-dalek`、`x25519-dalek`、`chacha20poly1305`、`hkdf`、`sha2`、`rand_core`。

---

## 14. 与 IDEA.md 的差异对照

| 项 | IDEA.md | 本设计 | 理由 |
| :--- | :--- | :--- | :--- |
| 帧头 | 46 字节，无 TTL/flags，`msg_type` 独占 1 字节 | 48 字节，加 `ttl` + `flags`，`msg_type` 与 `version` 共享 1 字节 | TTL 是成环唯一兜底；flags 是加密/优先级/演进位；版本号避免未来改布局 |
| **节点身份** | 启动生成 UUIDv4 作 `PeerId` 并持久化 | **取消生成**，`NodeId` 就是节点网络地址（IPv4 用 v4-mapped IPv6） | 全网寻址、单向规则、种子配置用的都是现有网络地址；额外生成 UUID 后没有任何地方能对上，是纯粹的间接层。字段宽度不变，故不影响帧头 |
| 私网地址重叠 | 未提 | 罕见情况用 `node.overlay_addr` 钉一个全网唯一地址 | 常见情况零配置；罕见情况在运维已经知道边界的地方显式声明一次，而不是为此给所有节点加 UUID |
| 冷启动的前提 | 未说明「B 的端口没人占用时 A 怎么连」 | 明确：端口由 **B 自己的 listener** 占用并 `LISTEN`，A 的 SYN 经白名单到达它；B 在 accept 后从 `Hello` 认识 A | 澄清「单向孔洞」的物理含义 —— 放行的是**到达 B 监听套接字**的 SYN，不需要 B 预先知道 A、也不需要 B 反向建连 |
| 种子的端口 | 未提，默认隐含「端口必填」 | 种子可不写端口或写端口范围，配 `probe_ports` 候选列表 + `magic` 校验 | 白名单常常不限端口；`magic` 校验让「拨到别的服务」成为确定性失败，而不是协议混淆 |
| 端口对齐 | 未提，隐含「对端已在某端口监听」 | B 的 `listen.ports` 与 A 的 `seeds` 写同一条 IT 授权事实；B 可一次监听多个端口；必须区分 RST / 超时 / 非节点三种失败 | 防火墙放行是**许可**不是**服务**，路的尽头必须有监听套接字；不区分失败原因会让「授权端口没人监听」这个死锁极难排查 |
| 单向孔洞下的双向访问 | 未说明 B 如何连回 A | 明确：**复用 A 建的那条 TCP 会话**，Dialer 常驻保活 | IDEA 的目标与约束之间缺一环，这是唯一可行解 |
| 发现策略 | "零配置"与"读本地配置的邻居 IP 数组"并存 | 混合：跨网段**引导种子** + 同网段 UDP 自动发现 + **监听端点全网广播**（§6.5） | 消除矛盾；跨网段**第一条**链路无法自动化，但后续候选可由广播自动汇聚，`seeds` 从"对端清单"降为"引火柴" |
| SOCKS5 目标 → NodeId | "读取其代理目标，将其映射为目标 NodeId"，未说映射来源 | **网段索引**由 gossip 自动汇聚 + **规则表**本地管理（§9.1、§9.4） | 客户端仍写 `ip:port`，用户心智零改变；默认即合岛，无需声明任何能力 |
| 连接池 | `Arc<RwLock<HashMap<NodeId, mpsc::Sender<Vec<u8>>>>>` | `DashMap<NodeId, LinkHandle>`，`Sender<OutboundFrame{header, Bytes}>`，附公平调度器 | 保留帧头给中继用（IDEA 的裸 `Vec<u8>` 丢了头信息，中继无法只改 TTL）；DashMap 避免高频路径锁争用 |
| 背压 | 未提 | 有界队列 + `await` 阻塞 + 每流轮转调度 | 无背压时慢目的端会把中继节点内存打爆；单队列会饿死心跳 |
| 路由缓存 | 每次 Dijkstra | 按 `topology.version` 失效的懒计算 + 次优下一跳 | 稳态零开销 + 故障快速切换 |
| 加密 | 未提 | `CryptoProvider` trait 分层插入，v1 空实现 | 满足"传输层解耦、协议可替换、先传输后加密" |
| 目标 → 出口的选择 | 「读取其代理目标，将其映射为目标 NodeId」，未说明多候选如何选 | **两级**：内置的**网段自动匹配**（零配置）+ 使用者可写的**路由规则**（有序列表、先匹配者胜、本地优先于共享）。原 `Serve`/`Reach` 能力模型整体删除（§9.4） | 出口选择是**消费者**的意图，不该由提供方声明；网段是机器自知的事实，能自动的部分全自动，剩下的一小部分才需要规则 |
| **规则的归属** | 未提 | **本地管理 + 整份一键发布**（`RuleSetAd` 作为 LWW register，`(revision, publisher)` 全序裁决，§9.4.3） | 兼顾"我是一台一台配"和"我是全网管理员、不想配 N 遍"；整份替换避免了逐条合并所需的版本向量与共识 |
| **"我能到哪"的声明方式** | 无此概念（IDEA 未涉及） | **只有本机网段是自动声明的**（枚举网卡即得）；域名与网段外目标一律由消费方的规则表达（§9.1、§9.4.1） | 提供方无法知道消费者的意图；且网段之外的可达性（防火墙、静态路由、VPN）本就无法自动推导 |
| **跨网段候选发现** | 只读本地邻居数组 | 节点广播自己的入向监听端点（`GossipMsg.listen`），由邻居转发扩散；**不做地址过滤**（§6.5 第 3 条） | 把手工 `seeds` 从"每对端一行"降到"全网一次引导"；同时明确其边界 —— 广播≠能拨通，防火墙仍是最终裁判。代价见 §17 风险 18 |
| 前端耦合 | Tauri 直接调后端 | `hiveproxy-core` 独立 crate + 事件/命令契约 | core 可独立测试与复用，UI 可替换 |

---

## 15. 里程碑与验收标准

| 阶段 | 内容 | 验收标准 |
| :--- | :--- | :--- |
| **M0** 链路骨架 | `NodeId`/`HiveHeader`/codec、握手、链接池、公平调度器 | 两台机器互拨后能收发自定义帧；`cargo test` 覆盖编解码往返与畸形帧拒绝 |
| **M1** 路由核心 | Topology、gossip 广播合并、petgraph + Dijkstra、`route_packet` 中继 | 三节点链式拓扑（A-B-C，B-C 只能 B 拨 C）下 A 能通过中继到达 C，中间节点日志证明未解析载荷 |
| **M2** SOCKS5 出口 | SOCKS5 服务端、`StreamOpen/Ack/Close/WindowUpdate`、网段索引、流级信用 | `curl --socks5 127.0.0.1:1080 http://<远端服务>` 成功，跨两跳也成功；一条被限速的流不拖慢同链路上的其它流 |
| **M2.5** 规则路由 | 规则表、显式/派生 group、本地/共享合并、一键发布（LWW register）、预览与重排、出口选择与故障转移 | 一条 `egress = "group:subnet:10.9.0.0/16"` 的规则能在该网段的声明者里选最近，且节点上下线时成员自动增减；`fallback` 在主出口失联时顺延；共享规则被本地规则整体压低；`rules_enabled = false` 能一键回到纯网段匹配；`preview_rules` 能指出永不命中的条目；**不写任何规则**时，B 仍能通过默认共享的网段访问 A 的局域网（§9.1） |
| **M2.6** 网段重叠消歧 | 孤岛检测、`ZoneId` 确定性派生、区域限定寻址 | 两片**真正隔离**的孤岛撞同一私网段时，系统自动派生出不同 zone 号且**各节点独立计算一致**；单孤岛目标直连无感；片内请求解析到本片；片外请求用 `z<zone>+ip:port` 命中指定孤岛；**同 L2 但未直连的节点不会被误判成真冲突**；锚点离线后 zone 在一个 gossip 周期内收敛 |
| **M2.7** 候选自动汇聚 | 监听端点广播、候选降级与退避、反熵补漏 | 只给 C 配一条指向 B 的种子，C 接通后能自动发现 A 的监听端点并尝试直连；**四节点链 A-B-C-D 下 A 能路由到 D**（验证变化驱动 flood 真的到达全网）；`accept_listen_adverts = false` 时完全不产生这类候选；连续失败的候选被降级而非反复重试；人为丢弃一次 flood 后，反熵摘要能把它补回来 |
| **M3** 健壮性 | 心跳、`incarnation` 反驳、TTL、次优切换、`Unreachable`、同网段多出口合并 | 拔掉中间链路后 ≤ 10s 自动改走备用路径；人为制造图不一致不成环；同一网段的多条冗余出口在主出口断开后自动切换 |
| **M4** UI | Tauri 拓扑图、统计面板、种子管理 | 前端实时看到节点与边、能看到 RTT 与流量计数 |
| **M5** 安全 | `join_token` → Ed25519 身份 → 每流端到端加密 | 中继节点抓包看不到业务明文；`node_addr` 与公钥可验证 |

每个里程碑都要有一条"真实环境验收"：至少两台不同网段的机器，且防火墙只允许单向。

**平台范围**：Windows / Linux / macOS 三平台都要支持（§18 第 5 条）。`hiveproxy-core` 不依赖平台特性，平台差异只落在打包与服务化层：Windows Service、systemd unit、launchd plist。

---

## 16. 测试策略

**单元测试**
- 帧编解码往返（各 `msg_type`、各种 `payload_len`，含 0 与边界 256 KiB）+ 畸形输入模糊测试（magic 错、`payload_len` 超限、截断流）。
- TTL 递减与归零丢弃。
- 身份编解码：`NodeId::from_ip` / `to_ip` 往返；IPv4 → v4-mapped 的字节布局逐字节断言；IPv6 原样通过；`BROADCAST` 不与任何合法地址冲突。
- 身份一致性：同一地址在 `Hello.node_addr`、gossip `owner`、帧 `src_node`、日志输出四处表示必须完全一致（防止实现里出现两套表示）。
- 无端口种子解析：`"10.1.2.3"` / `"10.1.2.3:5678"` / `"10.1.2.3:5678-5680"` 三种写法解析出正确的候选端口序列，且 `probe_ports` 顺序被遵守。
- **误拨非 hiveproxy 服务**：起一个纯 HTTP 服务监听某端口，把该端口写进种子，断言 A 能在收到响应后判定「非节点」、关闭连接、不 panic、不把它注册进链接池；断言该端口被标记后不会在后续巡检中被反复重试。
- 冷启动时序：先起 A（种子指向 B 的端口）后起 B，断言 A 在 B 启动后能自动接通，无需任何 A 侧干预。
- **端口对齐与失败分类**：构造三种情形 —— (a) B 未监听该端口（RST）、(b) 防火墙静默丢弃（超时）、(c) 该端口被非 hiveproxy 服务占用（连上但 magic 不符）—— 断言 A 侧分别给出**不同**的错误分类与文案，而不是统一报「连接失败」。
- 多端口绑定：`listen.ports = [5678, 20000]` 同时绑定成功；其中一个端口被占用时，断言剩余端口仍能服务，且前端收到明确的 bind 失败告警（不静默降级）。
- 对齐自检：当 A 与 B 建立了任意链路后，断言 A 能用 gossip/`HelloAck` 的 `listen_ports` 发现「我配的 seed 端口不在对端监听列表里」并告警。
- **默认即合岛**：N 个节点各在不同网段、零配置启动，断言任一节点的 SOCKS5 口都能访问所有节点网段内的任意 IP 与端口。
- **同网段多出口（§9.3 情形一）**：同一 `10.1.2.0/24` 内两个节点，断言目录把它们合并为**一个**逻辑网段、出口按成本选最近；主出口链路断开后自动切到另一个，无需重配。
- **真冲突（§9.3 情形二）**：两片隔离孤岛都用 `10.1.2.0/24`，断言系统为两片自动派生出不同的 zone 号且**各节点独立计算一致**；单孤岛目标无感直连；请求方在片内时解析到自己那片；片外方用 `z<zone>+10.1.2.5:3306` 能确定性命中；锚点离线后前缀在一个 gossip 周期内收敛。
- 自动共享开关：`auto_share_subnets = false` 的节点，断言它仍能访问别人的网段，但别人访问不到它的网段。
- 有向图 Dijkstra：包含"某边只能反向使用（会话复用）"这类非对称用例。
- 规则匹配：**顺序即优先级**（先匹配者胜）逐条覆盖；`host` 的四种形态（`*` / 精确 / `*.suffix` / CIDR）与 `port` 的三种形态（`*` / 精确 / 范围）两两组合匹配正确。
- 规则合并：断言一条**本地** `block` 能压住一条**共享**的 `node:X`（本地整体在前）。
- 规则故障转移：`fallback` 在指定出口不可达时顺延到下一顺位、最终落到网段匹配；`fail` 则直接回错误码而**不**改变路径；`group` 在成员失联时组内切换；全部候选不可达时回 SOCKS5 错误码（不是静默本地直连）。
- 共享规则 LWW：两个发布者先后发布，断言所有节点都收敛到 `(revision, publisher)` 较大的一份且**各节点独立计算结果一致**；`revision` 未递增的广播被忽略（防重放）；`revoke_shared_rules` 后全网规则表回到空。
- 共享规则的安全边界：`accept_shared_rules = false` 时整份忽略；`rule_token` 非空时 hmac 不符的整份丢弃；一条被注入的 `node:攻击者` 规则**不能**覆盖本地已有的规则。
- 监听端点广播：只给 C 配一条指向 B 的种子，断言 C 接通 B 后能自动学到 A 的监听端点并尝试直连；`accept_listen_adverts = false` 时不产生任何此类候选；连续失败的候选被降级且不无限重试；`advertise = false` 的节点不出现在他人候选里。
- 域名语义：断言出口节点收到的是**原始域名**而非调用方预解析的 IP。用一个 split-horizon DNS 桩构造 A 与 B 解析结果不同的场景，验证流量确实走了 A 的解析结果；并断言域名目标**不会**命中网段匹配，必须由规则显式指定。
- **变化驱动 flood 的可达性（本轮修订的核心回归，务必保留）**：四节点链 `A-B-C-D`，断言 A 能算出到 D 的路由并成功中继；再断言"周期一跳刷新"**不能**替代它（把变化驱动关掉就应当失败），防止将来有人把 flood 又改回裸一跳。
- **反熵补漏**：人为丢弃一次变化驱动 flood，断言在一个 gossip 周期内通过 `digest` 比对 + `Pull` 补齐。
- **流级信用隔离**：一条流的下游被限速（不回收信用），断言它被压停，而同一链路上另一条流吞吐不受影响；断言出口侧 `WindowUpdate` 回传后源节点恢复发送。
- **路径切换不乱序**：大流量传输中强制拆掉主路径，断言切换前该流在途帧为 0，接收端拼出的字节流与发送端**逐字节一致**；再构造"长期繁忙"场景，断言超时兜底切换会记一条告警。
- **规则边界**：`egress = "auto"` 命中但网段匹配失败时**继续匹配下一条规则**（而不是直接返回错误）；`block` 返回 `Refused` 而非不存在的 `Denied`；域名目标不会进入网段匹配。
- **派生 group**：`egress = "group:subnet:10.9.0.0/16"` 的成员等于该网段的声明者；某成员下线后组内自动切到另一成员。
- **别名发布**：本地规则含 `alias:gpu-01` 时，`publish_rules` 广播出的 `RuleSetAd` 里该条已变成 `node:<ip>`；别名解析不到时**整次发布被拒绝**并指出是哪一条。
- **发布 revision 持久化**：发布三次后重启进程，断言 `own_revision` 不回退，且第四次发布仍被全网采信（最容易漏测的一条）。
- **`rules_enabled` 旁路**：置 false 后规则表只剩网段兜底行，原先被规则改道的目标回到自动选择。
- **自身身份冲突自检**：构造两台同 `overlay_addr` 的节点，断言在若干反驳周期后给出明确告警，而不是无限抖动。
- `incarnation` 合并规则：旧盖新必须被拒。

**集成测试**
- 进程内起 N 个节点（tokio + 回环地址），注入一个 `ConnFilter` 模拟防火墙：拒绝 B→A 的拨号，放行 A→B。验证：
  1. A 能访问 B；
  2. B 能访问 A（走会话复用，这是最关键的回归测试）；
  3. C 只能连 B，A 能经 B 中继访问 C；
  4. 拆除 A→B 链路后，B→A 立即不可达（验证约束的真实性，避免设计里隐含"凭空反向可达"的错误假设）。
- 篡改/截断帧注入，验证进程不 panic、链路被拆除、统计计数正确。

**混沌测试**
- 随机杀链路与进程，断言网络在 2 个 gossip 周期内重新收敛，且无环路（用帧的 hop 计数观测上限）。

**性能测试**
- 单流吞吐（应接近链路带宽，验证零拷贝路径未引入明显瓶颈）。
- 100 条并发流的公平性（大流不饿死小流与心跳）。
- 16 节点全互联下的 gossip 带宽占用。

---

## 17. 已知风险与非目标

**风险**
1. **反向可达性的依赖**：B 能否访问 A 完全取决于 A 的 dialer 是否在保活。若 A 停机，B 无法主动补上。缓解：多种子/多条引导路径（让另一台能拨 A 的机器成为备用路径）、监听端点广播（让能拨到 A 的节点自动发现 A 的地址，§6.5）。
2. **私网地址重叠**：跨网段使用相同私网段时，两个节点会声称同一身份，路由表与网段索引都无法区分。缓解：§5.8 的 `node.overlay_addr` 钉全网唯一地址（根因层面解决），§9.3 的成本优先 + 稳定裁决 + 别名/规则指名出口作为辅助。
3. **中继节点成为瓶颈与信任边界**：v1 明文下多跳路径上的每一跳都能看到业务内容。本设计不设 `allow_relay` 开关、也不限制跳数（§18 第 3、4 条），所以缓解手段只剩两条：把敏感流量交给 v2b 端到端加密，或在拓扑上避免不必要的多跳。
4. **对称 NAT / 全封 TCP**：本设计完全依赖"白名单留下的 TCP 孔洞"存在。若某台机器一个入向孔洞都没有且无人拨它，它只能作为纯发起方。
5. **gossip 规模**：邻接表模型在数百节点规模内良好；上千节点时 gossip 周期与图重建开销需要分片或分层（见下）。
6. **地址即身份的代价**：节点地址变更即等同于换机，旧地址的链接与配置引用会失效。缓解：地址不固定的环境钉死 `node.overlay_addr`；或后续按 §5.8 末段用版本位引入「地址 + 域」复合身份。
7. **无端口规则下的探测开销**：白名单不限端口时，dialer 需要按 `probe_ports` 逐个试探，未命中的端口会各产生一次失败连接；若对端的 hiveproxy 监听在非默认端口，还会多出若干次无效往返。缓解：默认把 `5678` 放首位、命中即停止；对确认「非节点」的端口做持久标记不再重试；建议对端尽量使用默认端口。
8. **授权端口已被别的服务占用**：IT 打开 20000 常常是因为那里本来就跑着某个服务。此时 hiveproxy 无法复用该端口，这个入向孔洞对该节点不可用 —— 只能改用其他被授权的端口，或依赖出向链路/中继。缓解：§6.2.3 的前置自检会在启动时明确暴露这种情况，而不是静默失败。
9. **DNAT 形态造成的对齐错位**：若 IT 规则是端口转发而非纯放行，B 监听的应是**转发后的目标端口**；运维若按 A 看到的端口去配 B，会得到一个「A 报连接被拒、但 A、B 都觉得自己配对了」的诡异现象。缓解：§6.2.3 要求先与 IT 确认规则形态，或用 B 侧 `tcpdump` 实测连接落点。当前环境已确认是纯放行，此项仅作将来参考。
10. **`*:*` 类无边界规则被允许**（§18 第 8 条）：一条 `host = "*", port = "*"` 的规则等于把**所有**没被前面规则拦下的流量都引到指定出口，是横向移动的真实暴露面。设计上**不拦截**（由使用者负责），但前端在保存此类规则时必须给出显式警告，并在规则列表里把它标成「全局兜底规则」。
11. **默认共享放大暴露面**：默认即共享本机所在整个子网（§9.1、§18 第 14 条），一个节点被攻破等于它的整个局域网对全网开放。缓解：`auto_share_subnets = false`、`share_ports_only` 限端口、v2b 端到端加密。
12. **真实网段重叠**：两片隔离孤岛撞同一私网段时，`10.1.2.5:3306` 字面有两个互不相通的来源（§9.3 情形二）。缓解：系统自动派生唯一 zone 前缀做确定性映射，单孤岛目标与片内请求完全无感；片外方用 `z<zone>+ip:port`。代价是引入了确定的地址翻译（可逆、全网一致、可离线推算）。残余风险：锚点节点变更导致 zone 号漂移，靠 gossip 收敛 + 可选 `node.zone` 冻结。
13. **域名目标必须逐条写规则（本次修订的主要代价）**：删掉 `Reach` 声明后，`api.corp.example.com` 这类需要特定出口才能解析/到达的域名**不可能**被网段匹配命中（没有 IP 可比），必须由每个消费者各写一条规则。缓解：一键发布让管理者只写一次（§9.4.3）；前端可列出"当前会走 `auto` 的域名目标"，帮助发现遗漏。
14. **共享规则被覆盖是静默的**：LWW 语义下后发布的规则集整体覆盖先前的，被覆盖方除非看前端提示否则不会察觉。缓解：规则页顶部常驻显示"当前共享策略来自 `<节点>`，revision N，发布于 `<时间>`"；多管理员场景只指定一台机器发布。
15. **监听端点广播的边界容易被误解**：广播**不等于**可达。广播的只是"我 bind 了哪些地址"，能不能拨通由对方的防火墙单向白名单决定，只有试才知道。这条必须在 UI 与文档里说清楚，否则使用者会以为配了广播就不需要种子了。缓解：保留种子引导作为兜底；候选降级而非删除，让后来才启动的对端仍能被发现。
16. **路径切换在极端情况下仍可能乱序**：帧头没有流内序号，"无在途帧才切换"这个约束在流长期繁忙时会被 `route_switch_timeout_ms` 打破（§5.5）。届时可能产生一次重排，表现为应用层报错（TLS 记录错误、文件校验失败、视频花屏）。缓解：超时值取得较大（30 s）、切换时记显式告警。根治手段是给帧头加流内序号 —— 本次未采纳（§18 第 23 条），留作将来若真出现问题的升级路径。
17. **「默认共享网段」与「不限制发布者」的叠加暴露**：一个被接管的节点既能广播虚假监听端点（诱导别人来拨它），又能广播共享规则集（改道流量）。两者叠加时，攻击者可以把**未被本地规则覆盖**的流量同时引到自己这里并解析。这是"内网完全可信"这一前提的直接推论，必须在使用者须知里显式写明。缓解：`accept_shared_rules = false`、`accept_listen_adverts = false`、开启 `join_token`、v2b 端到端加密。
18. **监听端点广播没有地址过滤**（2026-10-12 决策删除 `allowed_cidrs`）：任何节点广播的任意地址都会被纳入拨号候选。三层后果：① 一个被接管的节点可以广播 `1.2.3.4:5678`，让全网机器**集体向一个公网地址发起 TCP 连接** —— 即使连不通，**连接尝试本身已经发出去了**，这是企业网里 EDR / 出口防火墙 / DLP 最典型的告警特征；② 广播一批内网地址即可把一组机器变成**分布式端口扫描器**；③ 若对方握手成功，它就成了这张网格的一员，能看拓扑、收转发流量、发布规则。**注意防火墙替代不了这个过滤** —— 它管得住"连不通"，管不住"发起连接"，判据在协议层之外。缓解：① 不信任所在网络时把 `accept_listen_adverts` 置 `false`（整体关闭这类候选）；② **开启 `join_token`** —— 这是更彻底的那一道，让外部节点连握手都过不去；③ 若将来确需收窄又不想加配置，可加一条零配置的**自洽校验**：只采信"落在发送方自己声明的网段内、或等于其身份地址"的监听地址。它能挡住上面最直白的谎报，但挡不住同时篡改 `subnets` 的对手（那会污染 `segments`，不过在拓扑图上看得见）。

**非目标（v1 明确不做）**
- TUN/TAP 与 L3 路由（硬约束）。
- UDP 转发 / `UDP ASSOCIATE`（SOCKS5 的 UDP 部分）。
- 跨网段穿透的反向打洞会合服务（无中心的 P2P 打洞需要至少一个可达的会合点，与"无中心服务端"有张力，留作后续可选组件）。
- 流量计费、配额、审计。
- 千节点级分层路由（可用 `ver_type` 版本位在未来演进）。

---

## 18. 待确认项：已全部确认

本节原列 13 个待确认项，后续追加 3 项（14–16），2026-10-12 修订再追加 3 项（17–19），同日设计方案评审后追加 8 项（20–27），收尾再追加 1 项（28），**共 28 项**，均已通过问答确认。结论记录如下，作为后续实现的依据。

| # | 议题 | 结论 |
| :--- | :--- | :--- |
| 1 | 端口 | SOCKS5 本地出口固定 `127.0.0.1:1080`；节点间监听端口**就是 IT 授权给本机的入向端口**，不另设"overlay 端口"概念（§6.2.3）。未配置时兜底 `5678`，但那只是"尚未对齐"的默认值，不是固定端口 |
| 2 | 服务暴露粒度 | ~~`auto_expose_nics`~~ **已由第 14 条取代**：不再暴露"本机网卡 IP"，而是共享"本机所在整个子网"（`auto_share_subnets`，§9.1）。2026-10-12 修订进一步删除 `expose` 这个手工补充项 —— 需要例外时由消费方的**路由规则**表达，而不是由提供方声明 |
| 3 | `allow_relay` 开关 | **不设**。所有节点都可以中继，无法把某台机器排除出网关角色（§17 风险 3） |
| 4 | 跳数上限 | **不限**，只靠帧头 TTL（`ttl_default = 8`）兜底（§12） |
| 5 | 平台 | Windows / Linux / macOS **三平台都要支持**（§15） |
| 6 | `petgraph` | **保留**，遵从 IDEA.md 的硬要求（§6.3） |
| 7 | 出口选择模型的传播范围 | ~~能力全网 gossip 扩散~~ **已由第 17 条取代**：旧模型让"我能到哪"全网广播，新模型只广播**客观事实**（本机网段、监听端点），"谁去连"改为**消费者本地的规则**（§9.4.1） |
| 8 | `*:*` 无边界规则 | **允许，不做限制**。规则写什么就生效，由使用者负责（§17 风险 10） |
| 9 | `Serve` vs `Reach` | ~~`Serve` 优先~~ **模型已取消**（第 17 条）。新模型里"自有服务优先"退化成一个更朴素的机制：目标 IP 落在本机网段内时，`SELF` 以成本 0 参选，自然走直连（§9.4.4） |
| 10 | 身份方案 | **取消 UUID**，身份 = 节点网络地址（§5.8）。这是对 IDEA.md C3 的**有意偏离** |
| 11 | IT 规则形态 | **纯放行（allow）**：A 连 20000 就到达 B 的 20000，B 直接监听 20000（§6.2.3） |
| 12 | 授权端口可知性 | **B 侧能拿到授权端口号**，直接写进 `listen.ports`，无需端口探测 |
| 13 | B 的出向权限 | **不重要**：单向 TCP 连接本身是全双工的，A 连上 B 即可双向传数据、具备双向代理条件（§3.1） |
| 14 | 默认可达性 | **全网共享，默认即合岛**：每个节点自动把自己所在的**整个子网**（全部 IP、全部端口）广播给全网。代理口的可达集 = 所有节点网段的**并集**，零配置完成孤岛合并（§9.1、§9.4.4）。这是本设计里**唯一**的自动"我能到哪"声明。这是对第 2 条的升级 |
| 15 | 「接管监听」的含义 | **overlay 入向端口**：hiveproxy 在 IT 授权端口上监听，接收其它节点拨入并建链（`listen.ports`）。**不是**在业务端口（如 22）上代管转发；业务流量统一走本地 SOCKS5 口（§6.2.3）。2026-10-12 修订后，该端点**默认广播全网**（第 19 条） |
| 16 | 网段重叠 | 分两种情形：**同一局域网的多节点 = 冗余出口**，合并为一个逻辑网段、多出口，选最近、其余备选，用户无感；**两个隔离孤岛撞同一私网段 = 真冲突**，**系统自动为每个孤岛派生唯一 zone 前缀**（种子取孤岛最小 NodeId，各节点独立算出同一结果，无中心），映射双向可逆；单孤岛目标与片内请求完全无感，片外请求用 `z<zone>+ip:port`（§9.3） |
| **17** | **出口选择模型**（2026-10-12） | **规则取代能力声明**：删除 `Serve`/`Reach`/`Pattern` 整套模型，改为「内置网段匹配 + 使用者可写的**有序规则表**」。理由：出口选择是**消费者**的意图，不该由提供方声明；能自动推导的（本机网段）已全自动，剩下的一小部分才需要规则（§9.4.1） |
| **18** | **规则的归属**（2026-10-12） | **本地管理 + 整份一键发布**。`RuleSetAd` 作为 LWW register，用 `(revision, publisher)` 全序裁决，**整份替换、不做逐条合并**（因此不需要版本向量或共识）；**本地规则整体排在共享规则之前**，本地永远能覆盖共享；接收方仍须本地校验可达性，共享规则永远只是默认值（§9.4.3） |
| **19** | **监听端点是否广播**（2026-10-12） | **默认广播**（`listen.advertise = true`），由邻居随邻接表扩散，**不做地址过滤**。目的：把手工 `seeds` 从"每对端一行"降为"全网一次引导"。**明确边界：广播 ≠ 可达**，能否拨通由防火墙决定（§6.5 第 3 条、§17 风险 15） |
| **20** | **gossip 传播模型**（2026-10-12 评审） | **变化驱动 flood + 周期一跳刷新 + 反熵摘要**。任一状态变化即 flood（`gossip_flood_ttl = 4`，按 `(owner, seq)` 去重），稳态只发一跳；`GossipMsg` 附 `digest`，邻居发现缺口就 `Pull` 回拉。**理由**：纯一跳只能看到 2 跳邻域，四节点链以上无法路由 —— §3.2 的旗舰示例在默认配置下都不成立，这是本设计曾经的致命缺陷（§6.3、§12） |
| **21** | **背压与流隔离**（2026-10-12 评审） | **每流有界队列 + 信用回压，`WindowUpdate` 进入 v1**。信用由**出口侧**生成并回传；每链路每流的队列容量 = 信用窗口，因此守信用的发送方不会让中间队列溢出；万一溢出则**丢帧并关流**（无流内序号，静默丢等于静默损坏）。唯一允许阻塞的是容量很小的控制优先车道（§5.5） |
| **22** | **共享规则集的发布信任**（2026-10-12 评审） | **不限制发布者**：任何节点都可广播 `rule_set`。结构性防线是「**本地规则整体排在共享规则之前**」—— 攻击者无法覆盖任何一条本地规则，只能影响未显式管理的目标。接收侧仍保留 `accept_shared_rules` 与 `rule_token` 两个可选收紧开关（§9.4.3、§17 风险 17） |
| **23** | **分片与路径切换**（2026-10-12 评审） | **用信用账本卡切换时机**（`sent - acked == 0` 才允许切），**不**新增帧内序号。零协议字段代价；长期繁忙由 `route_switch_timeout_ms`（30 s）兜底强制切换并告警。残余代价见 §17 风险 16（§5.5） |
| **24** | **`EgressTarget::Group` 的定义**（2026-10-12 评审） | **两种写法并存**：`group:<name>` 查显式配置的 `[[route.groups]]`；`group:subnet:<cidr>` 由 `segments` **自动派生**（成员 = 声明了该网段的节点，随拓扑增减）。后者零维护，优先推荐（§9.4.2） |
| **25** | **共享规则里的别名**（2026-10-12 评审） | **发布时解析成 `NodeId`**：`alias:` 只允许出现在本地规则中；`publish_rules` 按本机 `peers.entry` 解析，**解析不到就整次拒绝发布**。接收方拿到的规则集必须自足（§9.4.3） |
| **26** | **发布侧 `revision` 的持久化**（2026-10-12 评审） | **必须落盘**（`data/publish_state.json`）。否则重启后 `revision` 归零，新发布会被全网判为旧消息而**永久忽略**（§6.8、§9.4.3） |
| **27** | **v1 纳入的优化项**（2026-10-12 评审） | 全部纳入：`route.rules_enabled` 全局旁路、发布前 `preview_rules` dry-run、自身身份冲突自检、gossip 反熵摘要、规则表末尾物化兜底行、规则「按具体度重排」、每条规则的命中统计（§9.4.2、§9.4.4、§6.3、§6.7） |
| **28** | **`allowed_cidrs` 的去留**（2026-10-12 决策） | **删除**。监听端点广播改为一律采信，不再做地址过滤 —— 少一个必填项，配置更简单。代价如实记录在 §17 风险 18（被接管的节点可诱导全网机器向任意地址发起连接，产生外连告警或分布式扫描特征）。需要时用 `accept_listen_adverts = false` 整体关闭，或开启 `join_token` 抬高入网门槛 |

### 18.1 由这些结论带来的实现要点

- 配置里**去掉** `route.max_hops` 与 `route.allow_relay` 两个字段（§10、§10.1 已同步）。
- **2026-10-12 修订删除的配置/类型**：`[[capabilities]]`、`services.expose`、`peers.auto_dial_hints`、`egress.max_egress_attempts`、`security.capability_key`；类型 `CapKind`、`Pattern`、`CapabilityAd`、`ServiceAd`、`DialHint`、`ServiceDirectory`、`ServiceView`。
- **2026-10-12 修订新增的配置/类型**：`[[route.rules]]`（`Rule` / `HostMatcher` / `PortMatcher` / `EgressTarget` / `OnUnreachable`）、`route.accept_shared_rules`、`route.publish_enabled`、`listen.advertise`、`peers.accept_listen_adverts`、`security.rule_token`；类型 `RuleSetAd`、`ListenAdvert`、`RuleTable`、`SegmentView`；`[egress]` 段在 §10.1 中补为独立的 `EgressCfg`。
- `share` 段（原名 `services`）：`auto_share_subnets`（默认 `true`，替代原 `auto_expose_nics`）自动共享本机所在子网；`share_ports_only` 限端口并随广播传出；**不再有 `expose`**。
- `Topology` 增加 `segments: HashMap<IpNet, Vec<NodeId>>` 与 `listen_addrs`；删除 `services`，新增 `shared_rules`；区域号 `zone` 由系统按孤岛自动派生（§9.3），`node.zone` 仅作可选冻结；`ZoneId` 类型加入 §5.7。
- 规则的合并、持久化与发布：合并表在启动与每次拓扑/规则变化时重建；收到的共享规则集落盘 `data/shared_rules.toml` 以便重启保留；前端规则页必须常驻显示共享策略的来源与 revision（§9.4.3）。
- **2026-10-12 评审新增的配置/类型**：`route.rules_enabled`、`route.route_switch_timeout_ms`、`route.groups`（`GroupCfg`）、`discovery.max_dial_candidates`、`GossipMsg.digest`、`GossipMsg.accepts_egress`、`SubnetAd`、`PullMsg`、`WindowUpdateMsg`、`GroupRef`、`PublishState`；消息类型新增 `0xB Pull`。
- **2026-10-12 评审改动的语义**：`gossip_flood_ttl` 默认 `0 → 4`，语义从"每轮是否 flood"变为"**变化驱动的扩散半径**"（稳态仍是一跳）；`WindowUpdate` 从"可选优化"升为 **v1 必做**；`[services]` 段与 `ServicesCfg` 改名 `[share]` / `ShareCfg`（它已不含任何"服务"）。
- **必须持久化的两份状态**：接收到的共享规则集 → `data/shared_rules.toml`；本节点的发布状态（`own_revision`）→ `data/publish_state.json`。**两者缺一都会造成"静默失效"**（§9.4.3）。
- **2026-10-12 收尾删除的配置**：`peers.allowed_cidrs`。监听端点广播改为一律采信，关闭这类来源只剩 `accept_listen_adverts = false` 一个开关（§18 第 28 条、§17 风险 18）。
- 打包与服务化覆盖三平台：Windows Service、systemd unit、launchd plist。
- 对等与多路径是基础性质（§3.4）：任何节点都可同时充当端点与中继，路径冗余靠 `CachedRoute.alt` 自动切换实现，不做主动多路径复用。
- 端口探测能力（§6.2.2）保留为将来备用，但当前环境（第 11、12 条）用不到，**不是启动路径上的必经逻辑**。
---
---

## 19. 实现状态与偏差记录（2026-10-12）

本节记录**实际落地的代码**与上面设计的差异，以及实现过程中发现的设计缺陷。
代码在 `crates/hiveproxy-core`，测试见同一 crate 的单元测试与 `tests/integration.rs`。

### 19.1 已实现

| 层 | 内容 | 位置 |
| :--- | :--- | :--- |
| L2 帧 | 48 字节定长头、编解码、`RawFrame`（改 1 字节 TTL 的零拷贝中继）、探针式早失败 | `proto/` |
| L1 链路 | 控制优先车道 + 每流有界队列 + 轮转写出；握手与双向 `join_token` 认证；链路注册/拆除 | `link.rs`、`handshake.rs` |
| L3 路由 | 拓扑存储与 gossip 合并（含反驳、自身身份冲突自检）、petgraph + 双标签 Dijkstra（含 `alt`） | `topology.rs`、`router.rs` |
| 寻址 | 规则匹配与出口选择、内置网段匹配、`group:`、区域分流、`preview_rules` | `resolver.rs`、`rules.rs`、`zone.rs` |
| L4 会话 | 流上下文、流级信用（`WindowUpdate`）、双向数据泵、路径钉死与失效重置 | `session.rs`、`stream.rs` |
| 分发 | `route_packet`：本地消费 / 内存中继 / 广播扩散 | `relay.rs` |
| 发现 | 变化驱动 flood + 周期一跳 + 反熵摘要（`digest`/`Pull`）、LAN UDP、常驻重连与退避 | `gossip.rs`、`discovery.rs`、`dialer.rs` |
| L5 出口 | SOCKS5 `CONNECT`、错误码映射、直连短路 | `socks5.rs` |
| 持久化 | 配置、共享规则集、发布 `revision` | `persist.rs` |
| 编排与 UI | `HiveNode` API、Tauri v2 壳（含服务启停开关）、静态前端（概览/拓扑 DAG/规则/配置/日志） | `node.rs`、`src-tauri/`、`ui/` |
| 无界面运行 | 本地管理接口（Unix socket / 回环 TCP，JSON 与纯文本双协议）+ `hiveproxy-cli` | `admin.rs`、`crates/hiveproxy-cli/` |

### 19.2 实现过程中发现并修掉的设计缺陷

| # | 问题 | 处置 |
| :--- | :--- | :--- |
| 1 | **§5.2 的消息表缺 `HelloAck` / `Reject`** —— 而 §5.4 明确要求 Listener 回这两个 | 新增 `0xC HelloAck`、`0xD Reject`（§5.2 已补） |
| 2 | **§5.4 的 `auth` 公式发起方算不出来**（还不知道 `nonce_b`） | 改成双向各证一次（§5.4 已修正） |
| 3 | **广播帧无法中继**：`dst = BROADCAST` 交给路由器必然"无路由" | `relay` 对广播帧改为"发给除来源外的所有直连链路"（§6.3 已补）。**不修的话"邻居帮你转发 listen 端点"整条机制都是死的** |
| 4 | **注销流时会丢掉队列里未写出的帧** | 写出任务在注销前先把该流的队列排空（每次半关闭都会踩到） |
| 5 | **拨号器用"是不是本机 IP"跳过自己** → 误杀同机上另一个端口的节点（容器 / 多实例 / 测试） | 改为只跳过**自己的监听端点** |
| 6 | **退避闸门用了创建状态之前的时间戳** → 每个候选的第一次尝试必然被浪费一轮 | 比较时取当前时间 |
| 7 | `host = "127.0.0.1:8080"` 会静默产出一个**永远匹配不到**的模式 | `HostMatcher::parse` 明确报错并指路到 `port` 字段 |
| 8 | HTTP 响应的首字节 `'H'` **恰好等于 magic** | 早失败判定改为"前 2 字节（magic + 版本位）"，并写进注释与测试 |
| 9 | **多行响应被按行协议截断**：`hiveproxy-cli status` 只输出第一行 | 响应改为"以一个空行结尾"，客户端读到空行为止（§20.2） |
| 10 | 第 3 条（广播中继）的连带影响：`dst = BROADCAST` 也会走进 `send_control_routed` 而报"无路由" | 广播帧专门走"发给除来源外的所有直连链路" |
| 12 | **本机可达范围与"是否广播"被绑在一起**：`auto_share_subnets = false` 的敏感机器**连自己局域网都访问不了**（`NodeIdentity::resolve` 直接把 `subnets` 清空了） | 拆成两个概念：`subnets` 始终是网卡枚举结果（"我能连什么"），新增 `share_subnets` 单独控制"是否广播"（§9.1、§19.2 的第 13 条同源） |
| 13 | **`allow_egress = false` 把本机自己也排除了**：`can_egress(self)` 返回 `self_accepts_egress`，于是敏感机器访问自己网段返回 `NoRoute`，`egress = "direct"` 的规则也失效 | `can_egress(self)` 恒为 `true`；`ResolveCtx` **删掉** `self_accepts_egress` 字段，让这个错误在类型层面写不出来。新增端到端回归 `self_is_still_an_egress_when_it_refuses_to_serve_others`（§9.4.4） |
| 11 | **Tauri v2 的权限系统会让前端静默白屏**：没有 `capabilities` 声明时 `event.listen` 被拒，`DOMContentLoaded` 里的初始化整段中断，页面只剩初始 HTML（卡片、侧栏全空），而且原因不出现在任何日志里 | 新增 `src-tauri/capabilities/default.json`（含 `core:event:allow-listen` 等），并加了两条回归测试钉住它；同时**把前端报错回传到引擎日志**（`ui_log` 命令 + `window.onerror`），以后再出这类问题第一时间可见 |

### 19.3 有意保留的偏差

| 项 | 设计 | 实现 | 理由 |
| :--- | :--- | :--- | :--- |
| 路径切换 | 等 `sent-acked==0` 再切，超时强切 | **钉死下一跳，链路失效即重置该流** | 无流内序号时换路会丢帧，静默丢帧比"连接被重置"糟得多（§5.5） |
| `route_switch_timeout_ms` | 生效 | **暂时无效**，保留作升级位 | 同上；将来加流内序号后才需要 |
| 孤岛判定 | 身份地址在同一前缀内 | **按 Lan 载体边做连通分量** | 前者对"两片隔离孤岛撞同一私网段"根本不成立（§9.3） |
| `max_links` 对孤岛判定的影响 | 未讨论 | 会**误报冲突**（多派生 zone） | 保守方向：多要一步，不走错路 |
| 规则发布命令 | `publish_rules(rules)` | 保留该签名；CLI 的 `publish` 子命令发的是**当前本地规则** | 命令行上手更直觉；需要发布另一份时用 JSON `publish_rules` 显式传 |

### 19.4 尚未实现

| 项 | 状态 | 说明 |
| :--- | :--- | :--- |
| 端到端加密（v2b） | 未实现 | `CryptoProvider` 槽位与帧头 `ENCRYPTED` 位已就位；`StreamOpen.e2e_pk` 字段已预留 |
| 链路层加密（v2a） | 未实现 | 与端到端正交的独立槽位 |
| `join_token` 之外的准入控制 | 未实现 | 目前只有共享令牌 |
| mDNS 兜底发现 | 未实现 | 配置项 `discovery.mdns` 存在但未接线；UDP 广播被禁时只能每台配 seed |
| 三平台打包（Service / unit / plist） | 未实现 | `cargo build` 可产出可执行文件；安装包未做 |
| `data/node.json` 的 v2 密钥槽 | 未实现 | v1 不需要 |
| `share_ports_only` 的**端口级**约束 | **未生效** | 它随 `SubnetAd.ports` 广播出去了，但 `Topology.segments` 只索引到"网段 → 节点"，丢掉了端口信息，所以 `subnet_match` 不会按端口过滤。要真正生效需要把 `Segments` 的值从 `NodeId` 换成 `(NodeId, Option<Vec<u16>>)`。**当前它只是个不会兑现的承诺**，用之前请知道这一点 |

### 19.5 测试覆盖

```
cargo test --workspace
  hiveproxy-core 单元测试        190 passed
  hiveproxy-core 端到端组网测试    3 passed
```

端到端测试跑的是**真实两/三节点组网**（真实握手、真实中继、真实 SOCKS5）：

- `two_nodes_form_a_mesh_and_relay_a_socks5_stream` —— A 拨通 B、双向可见、SOCKS5 经过 overlay 到 B 出口，往返数据**逐字节一致**；
- `three_nodes_chain_routes_end_to_end` —— A 与 C 不直连，**必须经 B 中继**；同时断言 B 确实转发了帧；
- `block_rule_is_enforced_at_the_entry` —— 规则在入口就被执行。

§16 的测试策略里明确列出的回归项（变化驱动 flood 的可达性、反熵补漏、流级信用隔离、共享规则 LWW、`revision` 跨重启、规则合并顺序、别名发布解析、端口对齐失败分类……）都有对应单元测试。

---

## 20. 无界面运行：本地管理接口与 CLI（2026-10-12 追加）

GUI（Tauri）适合桌面；**服务器、容器、systemd 上没有图形界面**，所以同一套引擎必须有一个
命令行的入口。做法是：引擎照常跑，额外开一个**只绑回环 / Unix socket 的本地管理接口**，
CLI 通过它查询与下发（§6.7 的命令契约原样复用），因此**不需要重启、不需要额外的守护进程**。

### 20.1 配置

```toml
[admin]
# 本地管理接口。GUI 不需要它（Tauri 直接调引擎 API）；命令行/脚本靠它工作。
enabled = true
# Unix socket 路径。留空 = <数据目录>/hiveproxy.sock。仅 Unix 有效。
socket = ""
# 其它平台（没有 Unix socket）用回环 TCP。**只允许回环地址**。
tcp = "127.0.0.1:10800"
```

`admin.tcp` 默认值按平台给：Unix 上为 `None`（走 socket），其它平台为 `127.0.0.1:10800`。
**绑到非回环地址会被直接拒绝启动** —— 这个接口没有任何认证。

### 20.2 协议

刻意做得极简：**一行请求，一段响应**，响应以一个空行结束（文本命令的输出是多行的，
没有终止符的话按行读的客户端只能拿到第一行）。`nc` / `socat` 直接可用。

```bash
$ echo status | nc -U /run/hiveproxy.sock
$ echo '{"cmd":"probe","target":"10.4.0.9:3389"}' | nc -U /run/hiveproxy.sock
```

首字符是 `{` 走 JSON 请求/响应（`{"ok":true,"data":…}`）；是 `[` 则视为一个规则数组，
等价于 `set_rules`；否则按**空格分隔的纯文本命令**解析（对人更友好）。

| 纯文本 | JSON `cmd` | 作用 |
| :--- | :--- | :--- |
| `status` | `status` | 状态摘要 |
| `nodes` / `links` | `topology` | 拓扑节点 / 直连链路 |
| `rules` | `rules` | 规则表与命中统计 |
| `streams` | `streams` | 活跃流 |
| `zones` | `zones` | 网段真冲突与区域号 |
| `probe <ip:port>` | `probe` | 这个目标会走哪个出口 |
| `reload` | — | 重新读取 `hiveproxy.toml` 并热更新 |
| `publish` / `revoke` | `publish_rules` / `revoke_shared_rules` | 发布 / 撤回共享规则集 |
| `rules-enabled <bool>` | `rules_enabled` | 全局旁路开关 |
| `seed-add` / `seed-del` | `add_seed` / `remove_seed` | 增删引导种子 |
| `help` | — | 命令列表 |

### 20.3 CLI

`crates/hiveproxy-cli` 是一个**不加任何额外依赖**的薄壳：它把子命令翻译成上面的一条请求，
或者启动引擎本身。

```bash
hiveproxy-cli init                        # 生成配置模板
hiveproxy-cli check                       # 只校验配置，不启动
hiveproxy-cli run                         # 前台运行（systemd Type=simple 直接用）
hiveproxy-cli run --status-interval 30    # 顺便周期打印状态行（--json 可输出 JSON 行）
hiveproxy-cli status | nodes | rules | streams | zones
hiveproxy-cli probe 10.4.0.9:3389
hiveproxy-cli reload
hiveproxy-cli publish | revoke
hiveproxy-cli bypass true|false
hiveproxy-cli seed-add 10.1.2.3:20000
```

退出码：`0` 正常 / `1` 用法错 / `2` 配置错 / `3` 连不上运行中的节点 —— 便于脚本判断。

`run` 会捕获 `SIGINT` / `SIGTERM` 并优雅退出（拆链、落盘）。

### 20.4 systemd 示例

```ini
[Unit]
Description=hiveproxy
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hiveproxy-cli run --config /etc/hiveproxy/hiveproxy.toml --data-dir /var/lib/hiveproxy
Restart=always
RestartSec=3
# 管理接口默认是 Unix socket：/var/lib/hiveproxy/data/hiveproxy.sock
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

之后：

```bash
systemctl status hiveproxy
journalctl -u hiveproxy -f
hiveproxy-cli -c /etc/hiveproxy/hiveproxy.toml status
```
