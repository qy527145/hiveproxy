# hiveproxy

去中心化的传输层覆盖网络代理。**全网运行同一个程序**，利用企业防火墙既有的单向白名单孔洞
把分散在不同网段的机器连成一张网，在本地释放一个统一的 SOCKS5 出口 —— 之后你照常填
真实的内网 `ip:端口`，由 hiveproxy 自己决定"这个目标该由谁去连"。

- 不用 TUN/TAP，不需要 Administrator / root
- 不依赖 FRP 那类多级转发配置
- 无中心服务端：拓扑靠 gossip 自发收敛，路径靠 Dijkstra 计算
- 走通单向孔洞：A 能连 B、B 连不回 A 的环境下依然双向可用（复用那条 TCP 会话）

完整的系统设计见 **[docs/DESIGN.md](docs/DESIGN.md)**；面向装机的操作说明见 **[docs/USAGE.md](docs/USAGE.md)**。

---

## 三种入口，同一套引擎

| 入口 | 产物 | 面向 |
| :--- | :--- | :--- |
| 桌面版 | `hiveproxy`（Tauri v2） | 日常使用：拓扑 DAG、规则编辑、配置表单、日志 |
| 命令行版 | `hiveproxy-cli` | **无界面的 Linux 服务器 / 容器 / systemd** |
| 库 | `hiveproxy-core` | 嵌入到别的程序里 |

CLI 与 GUI 通过同一个**本地管理接口**操作同一个引擎，能力完全一致：

```bash
hiveproxy-cli init && vi hiveproxy.toml     # 生成并编辑配置
hiveproxy-cli check                          # 只校验配置
hiveproxy-cli run --status-interval 30       # 前台运行（systemd 直接用）
hiveproxy-cli status | nodes | rules | probe 10.4.0.9:3389
hiveproxy-cli reload | publish | revoke | bypass false | seed-add 10.1.2.3:20000
```

这些子命令是在**跟正在运行的节点说话**，不需要重启。`nc` 也能直接用：

```bash
echo status | nc -U /var/lib/hiveproxy/data/hiveproxy.sock
```

详见 [docs/DESIGN.md](docs/DESIGN.md) §20。

## 工程结构

```
.
├── Cargo.toml                 工作区
├── crates/hiveproxy-core/     纯 Rust 引擎（不依赖任何 UI 框架，可独立测试与复用）
│   ├── src/
│   │   ├── proto/             L2 帧层：48 字节定长头、编解码、共享类型
│   │   ├── link.rs            L1 链路层：控制优先车道 + 每流有界队列 + 轮转写出
│   │   ├── handshake.rs       握手、join_token 双向认证、链路注册与拆除
│   │   ├── topology.rs        拓扑存储与 gossip 合并（唯一权威源）
│   │   ├── router.rs          L3 路由：petgraph + Dijkstra（每节点 2 个首跳标签，含 alt）
│   │   ├── resolver.rs        出口选择：规则匹配 + 内置网段匹配
│   │   ├── rules.rs           规则模型与 TOML 字面量编解码
│   │   ├── session.rs         L4 会话：流上下文与流级信用
│   │   ├── stream.rs          流生命周期与双向数据泵
│   │   ├── relay.rs           route_packet：本地消费 or 内存中继
│   │   ├── gossip.rs          变化驱动 flood + 周期一跳 + 反熵摘要
│   │   ├── dialer.rs          常驻重连 + 指数退避 + 「不是节点」的持久标记
│   │   ├── listener.rs        入向监听与端口对齐自检
│   │   ├── discovery.rs       LAN UDP 自动发现
│   │   ├── socks5.rs          L5 本地出口
│   │   ├── node.rs            编排器（Tauri 层唯一依赖的入口）
│   │   └── persist.rs         配置 / 共享规则集 / 发布 revision 的落盘
│   └── tests/integration.rs   端到端组网测试（真实握手 + 真实中继 + 真实 SOCKS5）
│   │   ├── admin.rs           本地管理接口（Unix socket / 回环 TCP）
│   │   └── zone.rs            网段重叠消歧（§9.3 情形二）
├── crates/hiveproxy-cli/      无界面命令行版本（服务器 / 容器 / systemd）
├── src-tauri/                 Tauri v2 桌面壳（只做事件转发与命令暴露）
└── ui/                        静态前端：左侧菜单 + SVG 拓扑 DAG + 配置表单（无构建步骤）
```

## 构建与运行

需要 Rust 1.75+ 与（Windows 上）系统自带的 WebView2。

```bash
# 跑全部测试（含端到端组网）
cargo test --workspace

# 编译桌面应用（首次会拉取较多依赖）
cargo build -p hiveproxy-app --release

# 编译命令行版本
cargo build -p hiveproxy-cli --release

# 运行
./target/release/hiveproxy            # 桌面版
./target/release/hiveproxy-cli run    # 命令行版
```

数据目录（配置、持久化状态）：

| 平台 | 路径 |
| :--- | :--- |
| Windows | `%APPDATA%\com.hiveproxy.desktop\` |
| Linux | `~/.local/share/com.hiveproxy.desktop/` |
| macOS | `~/Library/Application Support/com.hiveproxy.desktop/` |

首次启动会写一份 `hiveproxy.toml` 模板。**改完配置直接改这个文件**，UI 里的改动会热更新并落盘。

## 三步上手

1. **每台机器**装程序，改 `[listen] ports` 为 **IT 授权给这台机器的入向端口**；
2. **每个网段**挑一台"锚"，在 `[peers] seeds` 里写一条它拨得通的地址（通常指向另一个网段的锚）；
3. 把应用或浏览器的 SOCKS5 代理指向 `127.0.0.1:1080`，然后照常访问内网地址。

访问域名时**务必让代理在出口解析**（curl 用 `--socks5-hostname`），因为内网普遍是
split-horizon DNS —— 同一个域名在不同网段解析结果不同。

## 它是怎么工作的（一句话版）

- **身份 = 本机地址**，不生成 UUID、不落盘任何身份文件；
- 每个节点自动把**自己所在的整个子网**广播给全网 → 所有节点网段自动并成一张网，零配置；
- 目标不在任何已知网段、或需要指定出口时，写**路由规则**（有序列表，先匹配者胜）；
- 规则可以**一键发布**给全网，但本地规则永远排在共享规则之前，本地永远能覆盖共享；
- 中继节点只改 TTL 那 1 个字节，**不解业务载荷**。

## 安全边界（请务必读一遍）

- v1 是**明文**的：多跳路径上的每一跳都能看到业务内容。敏感流量等 v2 端到端加密。
- **默认自动共享本机所在子网**：一个节点被攻破等于它的整个局域网对全网开放。
  敏感机器设 `[share] auto_share_subnets = false`（只消费不贡献）。
- **共享规则集不限制发布者**：任何节点都能广播规则集，把**未被本地规则覆盖**的流量改道。
  默认防线是"本地规则优先"。需要收紧时开启 `security.rule_token` 或
  `[route] accept_shared_rules = false`。
- **监听端点广播不做地址过滤**：任何节点广播的任意地址都会被尝试连接。
  详见 [docs/DESIGN.md](docs/DESIGN.md) §17 风险 18。

## 排障

界面出问题时先看引擎日志 —— **前端的报错会回传到引擎日志**（`ui_log` 命令 + `window.onerror`），
所以 `RUST_LOG=info hiveproxy` 的终端输出里能看到浏览器侧的问题：

```
INFO  hiveproxy: ui: 界面渲染完成：服务 运行中，卡片 12，节点 1，规则 0（本地），自检通过视图 [拓扑 规则 分区 配置 日志]
```

启动时每个视图的渲染函数都会先跑一遍自检，切页前就能发现渲染错误。

## 状态

引擎已完整实现并通过测试（单元 + 端到端组网）。未实现的部分在
[docs/DESIGN.md](docs/DESIGN.md) §18 的决策表与 §17 风险里有明确记录。
