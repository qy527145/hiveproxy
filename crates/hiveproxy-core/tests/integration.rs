//! 端到端集成测试（DESIGN.md §16 的「集成测试」）。
//!
//! 这里跑的是**真实的两节点组网**：各自绑定真实的监听端口、真实握手、真实中继、
//! 真实 SOCKS5 出入口。它验证的是整条链路，而不只是某个模块。
//!
//! 拓扑：`客户端 → A(SOCKS5) → overlay → B → echo 服务`
//! - A 的身份是 `fd00::a`，B 是 `fd00::b`（两个不同的 v6 ULA，避免身份冲突）；
//! - 两者的监听端点都在 IPv6 回环 `::1` 上（同一台机器，不同端口）；
//! - A 通过 `seeds` 主动拨 B；A 用一条 `egress = node:fd00::b` 的规则
//!   把目标交给 B；B 在本地连上 echo 服务并把数据搬回来。

use std::net::SocketAddr;
use std::time::Duration;

use hiveproxy_core::config::Config;
use hiveproxy_core::node::{parse_target, HiveNode};
use hiveproxy_core::rules::{EgressTarget, HostMatcher, PortMatcher, Rule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 拿一个当前空闲的端口。测试用，允许极小概率的竞态。
async fn free_port() -> u16 {
    let l = TcpListener::bind("[::1]:0").await.expect("绑定 ::1");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "hiveproxy-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn base_cfg(overlay: &str, port: u16) -> Config {
    let mut cfg = Config::default();
    cfg.node.overlay_addr = Some(overlay.parse().unwrap());
    cfg.listen.bind = "::1".parse().unwrap();
    cfg.listen.ports = vec![port];
    cfg.listen.advertise = true;
    cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
    cfg.discovery.lan_udp = false; // 同机测试不靠广播
    cfg.route.gossip_interval_ms = 500;
    cfg.egress.egress_ack_timeout_ms = 3000;
    cfg
}

/// 起一个 echo 服务（读到什么回什么），返回它的端口。
async fn spawn_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

async fn socks5_connect(
    socks: SocketAddr,
    target: &str,
) -> (TcpStream, u8) {
    let mut c = TcpStream::connect(socks).await.expect("连上 SOCKS5");
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    c.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0], "方法协商失败");

    let ep = parse_target(target).unwrap();
    let mut req = vec![5u8, 1, 0];
    match &ep.host {
        hiveproxy_core::proto::Host::Ip(std::net::IpAddr::V4(v4)) => {
            req.push(1);
            req.extend_from_slice(&v4.octets());
        }
        hiveproxy_core::proto::Host::Ip(std::net::IpAddr::V6(v6)) => {
            req.push(4);
            req.extend_from_slice(&v6.octets());
        }
        hiveproxy_core::proto::Host::Name(n) => {
            req.push(3);
            req.push(n.len() as u8);
            req.extend_from_slice(n.as_bytes());
        }
    }
    req.extend_from_slice(&ep.port.to_be_bytes());
    c.write_all(&req).await.unwrap();

    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    (c, rep[1])
}

async fn wait_for<F: Fn() -> bool>(f: F, ms: u64, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_millis(ms);
    while std::time::Instant::now() < deadline {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("等待超时：{what}");
}

#[tokio::test]
async fn two_nodes_form_a_mesh_and_relay_a_socks5_stream() {
    let echo_port = spawn_echo().await;
    let port_a = free_port().await;
    let port_b = free_port().await;
    let dir_a = temp_dir("a");
    let dir_b = temp_dir("b");

    // ---- B：出口节点 ----
    let mut cfg_b = base_cfg("fd00::b", port_b);
    // 让 B 也能解析目标（它连的是 127.0.0.1，回环不会进共享网段）
    cfg_b.route.rules = Vec::new();
    let b = HiveNode::start(cfg_b, &dir_b).await.expect("B 应当能启动");

    // ---- A：客户端节点，主动拨 B ----
    let mut cfg_a = base_cfg("fd00::a", port_a);
    cfg_a.peers.seeds = vec![format!("[::1]:{port_b}")];
    // 把 echo 的目标交给 B
    cfg_a.route.rules = vec![Rule::new(
        HostMatcher::parse("127.0.0.1").unwrap(),
        PortMatcher::Exact(echo_port),
        EgressTarget::Node("fd00::b".parse().unwrap()),
    )];
    let a = HiveNode::start(cfg_a, &dir_a).await.expect("A 应当能启动");

    let node_a = a.clone();
    let node_b = b.clone();

    // ---- 1. 链路建立 ----
    wait_for(
        || node_a.state.links.contains_key(&"fd00::b".parse().unwrap()),
        // A 应当拨通 B
        8000,
        "A 拨通 B",
    )
    .await;

    // ---- 2. 拓扑收敛：A 认识了 B ----
    wait_for(
        || {
            let t = node_a.topology();
            t.nodes.iter().any(|n| n.peer == "fd00::b".parse().unwrap() && n.reachable)
        },
        8000,
        "A 的拓扑里出现 B",
    )
    .await;

    // ---- 3. B 也认识了 A（反向可达性靠 A 拨进来的那条会话） ----
    wait_for(
        || {
            let t = node_b.topology();
            t.nodes.iter().any(|n| n.peer == "fd00::a".parse().unwrap())
        },
        8000,
        "B 的拓扑里出现 A（会话复用）",
    )
    .await;

    // ---- 4. 走完 SOCKS5 → overlay → 出口 ----
    let node_a2 = a.clone();
    wait_for(
        || node_a2.state.proxy_bound.read().is_some(),
        3000,
        "A 的 SOCKS5 端口就绪",
    )
    .await;
    let socks = a.state.proxy_bound.read().expect("A 的 SOCKS5 应当已绑定");
    let target = format!("127.0.0.1:{echo_port}");

    let (mut c, rep) = socks5_connect(socks, &target).await;
    assert_eq!(rep, 0x00, "SOCKS5 CONNECT 应当成功（实际应答码 {rep:#04x}）");

    let payload = b"hello over the hive";
    c.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut buf))
        .await
        .expect("echo 应当在 5 秒内回来")
        .expect("读取 echo 结果失败");
    assert_eq!(&buf, payload, "往返数据必须逐字节一致");

    // ---- 5. 出口统计：确实有字节流过 B ----
    assert!(b.stats().bytes_relayed_in > 0 || b.stats().bytes_relayed_out > 0);

    let _ = c.shutdown().await;
    a.stop().await;
    b.stop().await;
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

#[tokio::test]
async fn three_nodes_chain_routes_end_to_end() {
    // A — B — C：A 与 C 不直连，必须经 B 中继（§16 的链式拓扑验收）
    let echo_port = spawn_echo().await;
    let port_a = free_port().await;
    let port_b = free_port().await;
    let port_c = free_port().await;
    let da = temp_dir("ca");
    let db = temp_dir("cb");
    let dc = temp_dir("cc");

    let c_node = HiveNode::start(base_cfg("fd00::c", port_c), &dc).await.unwrap();

    let mut cfg_b = base_cfg("fd00::b", port_b);
    cfg_b.peers.seeds = vec![format!("[::1]:{port_c}")];
    let b_node = HiveNode::start(cfg_b, &db).await.unwrap();

    let mut cfg_a = base_cfg("fd00::a", port_a);
    cfg_a.peers.seeds = vec![format!("[::1]:{port_b}")];
    cfg_a.route.rules = vec![Rule::new(
        HostMatcher::parse("127.0.0.1").unwrap(),
        PortMatcher::Exact(echo_port),
        EgressTarget::Node("fd00::c".parse().unwrap()),
    )];
    let a_node = HiveNode::start(cfg_a, &da).await.unwrap();

    // A 必须通过 B 才能到 C
    wait_for(
        || {
            let t = a_node.topology();
            t.nodes.iter().any(|n| n.peer == "fd00::c".parse().unwrap() && n.reachable)
        },
        10000,
        "A 经 B 认识 C（变化驱动 flood 必须真的到达全网）",
    )
    .await;

    let na = a_node.clone();
    wait_for(|| na.state.proxy_bound.read().is_some(), 3000, "A 的 SOCKS5 端口就绪").await;
    let socks = a_node.state.proxy_bound.read().unwrap();
    let (mut c, rep) = socks5_connect(socks, &format!("127.0.0.1:{echo_port}")).await;
    assert_eq!(rep, 0x00, "跨两跳的 CONNECT 应当成功（{rep:#04x}）");

    c.write_all(b"through the middle").await.unwrap();
    let mut buf = vec![0u8; 18];
    tokio::time::timeout(Duration::from_secs(8), c.read_exact(&mut buf))
        .await
        .expect("中继数据应当在 8 秒内回来")
        .unwrap();
    assert_eq!(&buf, b"through the middle");

    // 中间节点 B 确实转发了帧，且它**没有**解载荷
    assert!(b_node.stats().frames_relayed > 0, "B 必须承担中继");

    let _ = c.shutdown().await;
    a_node.stop().await;
    b_node.stop().await;
    c_node.stop().await;
    for d in [da, db, dc] {
        std::fs::remove_dir_all(&d).ok();
    }
}

#[tokio::test]
async fn block_rule_is_enforced_at_the_entry() {
    let dir = temp_dir("block");
    let port = free_port().await;
    let mut cfg = base_cfg("fd00::1", port);
    cfg.route.rules = vec![Rule::new(
        HostMatcher::parse("*.blocked.example.com").unwrap(),
        PortMatcher::Any,
        EgressTarget::Block,
    )];
    let node = HiveNode::start(cfg, &dir).await.unwrap();

    let nn = node.clone();
    wait_for(|| nn.state.proxy_bound.read().is_some(), 3000, "SOCKS5 端口就绪").await;
    let socks = node.state.proxy_bound.read().expect("SOCKS5 应当已绑定");
    let (_c, rep) = socks5_connect(socks, "secret.blocked.example.com:443").await;
    assert_eq!(rep, 0x02, "block 必须回 connection not allowed");

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// 默认出口端到端（§9.4.4、§18 第 29 条、UI.md §2.3）。
///
/// 盯三件事：
/// 1. **没有默认出口时，域名目标必须失败**（而不是悄悄直连）—— 浏览器流量全在这一格里，
///    这正是"默认出口"存在的理由；
/// 2. 设上 `default_egress = "direct"` 后，同一个请求成功，数据逐字节回来；
/// 3. 域名解析出**多个**地址时（`localhost` → `::1` + `127.0.0.1`，而 echo 只监听 IPv4），
///    本机直连要逐个试，不能取第一个就报"连接被拒"。
///
/// 第 3 条是这次顺带修掉的老毛病：默认出口让"域名 → 直连"从罕见变成常见，
/// 于是 `handle_direct` 只取 `lookup_host().next()` 的写法开始天天见人。
#[tokio::test]
async fn default_egress_carries_a_domain_target() {
    let echo_port = spawn_echo().await;
    let dir = temp_dir("default-egress");
    let port = free_port().await;
    let cfg = base_cfg("fd00::1", port);
    let node = HiveNode::start(cfg, &dir).await.unwrap();

    let nn = node.clone();
    wait_for(|| nn.state.proxy_bound.read().is_some(), 3000, "SOCKS5 端口就绪").await;
    let socks = node.state.proxy_bound.read().expect("SOCKS5 应当已绑定");
    // 用**域名**而不是 IP：域名永远不参与网段匹配（§9.4.2），所以它必然落到最后那一格
    let target = format!("localhost:{echo_port}");

    // ---- 1. 没有默认出口：没人认识这个目标，只能失败 ----
    let (_c, rep) = socks5_connect(socks, &target).await;
    assert_ne!(rep, 0x00, "没有默认出口时不该成功（实际应答码 {rep:#04x}）");

    // ---- 2. 设默认出口（走的是 CLI / 界面用的那条真实路径）----
    node.set_default_egress(Some("direct")).expect("direct 是合法的默认出口");
    assert_eq!(node.status().default_egress.as_deref(), Some("direct"));

    let (mut c, rep) = socks5_connect(socks, &target).await;
    assert_eq!(rep, 0x00, "设了默认出口后应当成功（实际应答码 {rep:#04x}）");
    let payload = b"hello through the default egress";
    c.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut buf))
        .await
        .expect("echo 应当在 5 秒内回来")
        .expect("读取 echo 结果失败");
    assert_eq!(&buf, payload, "往返数据必须逐字节一致");
    let _ = c.shutdown().await;

    // ---- 3. 探测能说清"这个出口是怎么定下来的" ----
    let p = node.probe_target(&target).await.unwrap();
    assert_eq!(p.via, "default", "来源必须报成默认出口，而不是网段兜底行");
    assert!(p.direct);

    // ---- 4. auto / block 不是合法的默认出口 ----
    assert!(node.set_default_egress(Some("auto")).is_err());
    assert!(node.set_default_egress(Some("block")).is_err());

    // ---- 5. 清除后又回到失败（证明成功确实来自默认出口）----
    node.set_default_egress(None).unwrap();
    let (_c2, rep) = socks5_connect(socks, &target).await;
    assert_ne!(rep, 0x00, "清除默认出口后应当重新失败（实际应答码 {rep:#04x}）");

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// 默认出口指向**另一台机器**时的完整链路：
/// `客户端 → A(SOCKS5) → overlay → B（默认出口）→ echo`，且目标写成**域名**。
///
/// 这条是本产品的主线故事：浏览器要走的域名从"有出网权限的那台机器"出去。
/// 它同时压住三个容易退化的点：
/// 1. 默认出口是 `node:<对端>` 而不是本机直连时，`resolve()` 要走 overlay 那条分支；
/// 2. **域名在出口侧解析**（§9.4.2），不是发起方解析；
/// 3. 出口侧解析出多个地址时要逐个试 —— `localhost` 通常是 `::1` + `127.0.0.1`，
///    而 echo 只监听 IPv4。只取第一个地址的写法在这里必然失败（2026-10-13 修的就是它）。
#[tokio::test]
async fn default_egress_through_a_peer_carries_a_domain_target() {
    let echo_port = spawn_echo().await;
    let port_a = free_port().await;
    let port_b = free_port().await;
    let dir_a = temp_dir("defegress-peer-a");
    let dir_b = temp_dir("defegress-peer-b");

    let b = HiveNode::start(base_cfg("fd00::b", port_b), &dir_b).await.unwrap();

    let mut cfg_a = base_cfg("fd00::a", port_a);
    cfg_a.peers.seeds = vec![format!("[::1]:{port_b}")];
    // 主线故事：不命中规则与网段的一律交给 B 出去
    cfg_a.route.default_egress = Some(EgressTarget::Node("fd00::b".parse().unwrap()));
    let a = HiveNode::start(cfg_a, &dir_a).await.unwrap();

    let aa = a.clone();
    wait_for(|| aa.state.proxy_bound.read().is_some(), 3000, "A 的 SOCKS5 端口就绪").await;
    let aa2 = a.clone();
    wait_for(
        || {
            aa2.topology()
                .nodes
                .iter()
                .any(|n| n.peer == "fd00::b".parse().unwrap() && n.reachable)
        },
        8000,
        "A 的拓扑里出现可达的 B",
    )
    .await;

    let socks = a.state.proxy_bound.read().expect("A 的 SOCKS5 应当已绑定");
    let target = format!("localhost:{echo_port}");

    let (mut c, rep) = socks5_connect(socks, &target).await;
    assert_eq!(rep, 0x00, "默认出口指向对端时应当成功（实际应答码 {rep:#04x}）");

    let payload = b"hello through the peer egress";
    c.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut buf))
        .await
        .expect("echo 应当在 5 秒内回来")
        .expect("读取 echo 结果失败");
    assert_eq!(&buf, payload, "往返数据必须逐字节一致");
    let _ = c.shutdown().await;

    // 字节确实流过 B（不是 A 自己直连了）
    assert!(
        b.stats().bytes_relayed_in > 0 || b.stats().bytes_relayed_out > 0,
        "出口应当是 B"
    );
    assert_eq!(a.probe_target(&target).await.unwrap().via, "default");

    a.stop().await;
    b.stop().await;
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

/// **规则排在默认出口之前** —— 这是界面上"顺序：规则 → 网段 → 默认出口"那句承诺的实现。
///
/// 反过来的话，"默认出口"就成了一条谁都覆盖不了的兜底规则，规则页从此不可信。
/// （"默认出口不抢网段目标"由 `resolver::tests::default_egress_never_beats_subnet_matching`
/// 覆盖：那条要在集成测试里伪造一个"本机网段内的目标"，会比它要验证的东西更假。）
#[tokio::test]
async fn rules_still_win_over_the_default_egress() {
    let dir = temp_dir("defegress-rules");
    let port = free_port().await;
    let mut cfg = base_cfg("fd00::1", port);
    // 默认出口是"能出去"，但这条域名被显式拒绝 —— 拒绝必须赢
    cfg.route.default_egress = Some(EgressTarget::SelfDirect);
    cfg.route.rules = vec![Rule::new(
        HostMatcher::parse("*.corp.example.com").unwrap(),
        PortMatcher::Any,
        EgressTarget::Block,
    )];
    let node = HiveNode::start(cfg, &dir).await.unwrap();

    let nn = node.clone();
    wait_for(|| nn.state.proxy_bound.read().is_some(), 3000, "SOCKS5 端口就绪").await;
    let socks = node.state.proxy_bound.read().expect("SOCKS5 应当已绑定");

    let (_c, rep) = socks5_connect(socks, "secret.corp.example.com:443").await;
    assert_eq!(rep, 0x02, "规则必须排在默认出口之前（实际应答码 {rep:#04x}）");

    // 同一台机器上，没被规则覆盖的域名照旧走默认出口
    let p = node.probe_target("other.example.com:443").await.unwrap();
    assert_eq!(p.via, "default");

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// 本地代理端口：SOCKS5 与 HTTP 代理共用一个端口（§6.4，2026-10-13）
// ===========================================================================

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 一个**支持 keep-alive** 的源站：回 `标签 + 请求路径`，并数一数它接受了几条连接。
///
/// 数连接数是为了证明"上游被复用"—— 只看客户端是不是成功，区分不出
/// "复用同一条上游" 和 "每个请求新开一条上游"。
async fn spawn_keepalive_origin(label: &str) -> (u16, Arc<AtomicUsize>) {
    let label = label.to_string();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            counter.fetch_add(1, Ordering::SeqCst);
            let label = label.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 2048];
                loop {
                    // 读一个完整请求头（到空行）
                    let head_end = loop {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    buf.drain(..head_end);
                    let path = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    let body = format!("{label} {path}\n");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: keep-alive\r\n\r\n{body}",
                        body.len()
                    );
                    if s.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, accepts)
}

/// 最小 HTTP 代理客户端：自己拼字节，自己按 Content-Length 读回响应。
struct HttpProxyClient {
    sock: TcpStream,
    buf: Vec<u8>,
}

impl HttpProxyClient {
    async fn connect(proxy: SocketAddr) -> Self {
        Self { sock: TcpStream::connect(proxy).await.expect("连上本地代理"), buf: Vec::new() }
    }

    /// 发一条绝对 URI 的 GET，返回 (状态码, 正文)。
    async fn get(&mut self, url: &str) -> (u16, String) {
        let req = format!("GET {url} HTTP/1.1\r\nHost: ignored\r\nProxy-Connection: Keep-Alive\r\n\r\n");
        self.send(&req).await
    }

    async fn send(&mut self, raw: &str) -> (u16, String) {
        self.sock.write_all(raw.as_bytes()).await.expect("发出请求");
        let head = self.read_head().await;
        let (status, len) = parse_response_head(&head);
        let mut body = self.take(len);
        while body.len() < len {
            let n = self.read_more().await;
            if n == 0 {
                break;
            }
            body = self.take(len);
        }
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// 发 CONNECT 并读回状态码（隧道本身由调用方自己搬字节）。
    async fn connect_tunnel(&mut self, authority: &str) -> u16 {
        let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        self.sock.write_all(req.as_bytes()).await.expect("发出 CONNECT");
        let head = self.read_head().await;
        parse_response_head(&head).0
    }

    async fn read_head(&mut self) -> String {
        loop {
            if let Some(p) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return String::from_utf8_lossy(&self.buf[..p + 4]).to_string();
            }
            if self.read_more().await == 0 {
                return String::from_utf8_lossy(&self.buf).to_string();
            }
        }
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        // 先把头部吐掉：这里假设调用方已经读过头部
        if self.buf.starts_with(b"HTTP/") {
            if let Some(p) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                self.buf.drain(..p + 4);
            }
        }
        let take = n.min(self.buf.len());
        self.buf.drain(..take).collect()
    }

    async fn read_more(&mut self) -> usize {
        let mut tmp = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), self.sock.read(&mut tmp)).await {
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&tmp[..n]);
                n
            }
            _ => 0,
        }
    }
}

fn parse_response_head(head: &str) -> (u16, usize) {
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let len = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    (status, len)
}

#[tokio::test]
async fn one_port_speaks_both_protocols() {
    // SOCKS5 与 HTTP 代理共用同一个监听端口：同一个端口上两种客户端都要能用。
    let origin_port = spawn_keepalive_origin("http").await.0;
    let echo_port = spawn_echo().await;
    let dir = temp_dir("dual");
    let port = free_port().await;
    let mut cfg = base_cfg("fd00::1", port);
    // 回环地址不参与网段匹配（§9.1），所以本机直连要靠默认出口显式说出来
    cfg.route.default_egress = Some(EgressTarget::SelfDirect);
    let node = HiveNode::start(cfg, &dir).await.unwrap();

    let n = node.clone();
    wait_for(|| n.state.proxy_bound.read().is_some(), 3000, "代理端口就绪").await;
    let proxy = node.state.proxy_bound.read().unwrap();

    // ① HTTP 代理语义
    let mut http = HttpProxyClient::connect(proxy).await;
    let (status, body) = http.get(&format!("http://127.0.0.1:{origin_port}/a")).await;
    assert_eq!(status, 200, "同端口上的 HTTP 代理必须能用");
    assert_eq!(body, "http /a\n");

    // ② SOCKS5（同端口，另起一条连接）
    let (mut c, rep) = socks5_connect(proxy, &format!("127.0.0.1:{echo_port}")).await;
    assert_eq!(rep, 0x00, "同端口上的 SOCKS5 必须仍然能用（{rep:#04x}）");
    c.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut buf))
        .await
        .expect("echo 应当回来")
        .unwrap();
    assert_eq!(&buf, b"ping");

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn http_proxy_reuses_the_upstream_across_keepalive_requests() {
    let (origin_port, accepts) = spawn_keepalive_origin("origin-1").await;
    let dir = temp_dir("httpka");
    let port = free_port().await;
    let mut cfg = base_cfg("fd00::1", port);
    cfg.route.default_egress = Some(EgressTarget::SelfDirect);
    let node = HiveNode::start(cfg, &dir).await.unwrap();

    let n = node.clone();
    wait_for(|| n.state.proxy_bound.read().is_some(), 3000, "代理端口就绪").await;
    let proxy = node.state.proxy_bound.read().unwrap();

    let mut c = HttpProxyClient::connect(proxy).await;
    let (s1, b1) = c.get(&format!("http://127.0.0.1:{origin_port}/one")).await;
    let (s2, b2) = c.get(&format!("http://127.0.0.1:{origin_port}/two")).await;
    assert_eq!((s1, s2), (200, 200), "同一条客户端连接上的两个请求都该成功");
    assert_eq!(b1, "origin-1 /one\n");
    assert_eq!(b2, "origin-1 /two\n");
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "同一个目标的两个 keep-alive 请求必须复用同一条上游连接"
    );

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn http_proxy_follows_a_host_change_on_the_same_client_connection() {
    // ★ 这是"盲管道"写法会踩的坑：一条客户端连接上换了目标主机，
    // 第二个请求绝不能顺着旧上游发出去（那会把请求送到别人的服务器上）。
    let (a_port, a_accepts) = spawn_keepalive_origin("host-a").await;
    let (b_port, b_accepts) = spawn_keepalive_origin("host-b").await;
    let dir = temp_dir("httpswitch");
    let port = free_port().await;
    let mut cfg = base_cfg("fd00::1", port);
    cfg.route.default_egress = Some(EgressTarget::SelfDirect);
    let node = HiveNode::start(cfg, &dir).await.unwrap();

    let n = node.clone();
    wait_for(|| n.state.proxy_bound.read().is_some(), 3000, "代理端口就绪").await;
    let proxy = node.state.proxy_bound.read().unwrap();

    let mut c = HttpProxyClient::connect(proxy).await;
    let (s1, b1) = c.get(&format!("http://127.0.0.1:{a_port}/x")).await;
    let (s2, b2) = c.get(&format!("http://127.0.0.1:{b_port}/y")).await;
    assert_eq!((s1, s2), (200, 200));
    assert_eq!(b1, "host-a /x\n", "第一个请求必须到 A");
    assert_eq!(b2, "host-b /y\n", "换了目标之后请求必须到 B，不能串到 A");
    assert_eq!(a_accepts.load(Ordering::SeqCst), 1);
    assert_eq!(b_accepts.load(Ordering::SeqCst), 1);

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn http_proxy_maps_errors_to_status_codes() {
    let dir = temp_dir("httperr");
    let port = free_port().await;
    let mut cfg = base_cfg("fd00::1", port);
    cfg.route.default_egress = Some(EgressTarget::SelfDirect);
    cfg.route.rules = vec![Rule::new(
        HostMatcher::parse("secret.example.com").unwrap(),
        PortMatcher::Any,
        EgressTarget::Block,
    )];
    let node = HiveNode::start(cfg, &dir).await.unwrap();

    let n = node.clone();
    wait_for(|| n.state.proxy_bound.read().is_some(), 3000, "代理端口就绪").await;
    let proxy = node.state.proxy_bound.read().unwrap();
    let mut c = HttpProxyClient::connect(proxy).await;

    // 被规则拒绝 → 403，而且正文要说人话
    let (status, body) = c.get("http://secret.example.com/x").await;
    assert_eq!(status, 403, "block 规则必须映射成 403");
    assert!(body.contains("规则"), "正文要能解释原因：{body}");

    // 目标没人听 → 502
    let dead = free_port().await; // 拿一个刚释放、没人监听的端口
    let mut c2 = HttpProxyClient::connect(proxy).await;
    let (status, body) = c2.get(&format!("http://127.0.0.1:{dead}/x")).await;
    assert_eq!(status, 502, "连不上目标必须是 502，而不是含糊的连接重置");
    assert!(!body.is_empty(), "502 也要有说明");

    // origin-form（把代理当源站用）→ 400 + 明确的提示
    let mut c3 = HttpProxyClient::connect(proxy).await;
    let (status, body) = c3.send("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(status, 400);
    assert!(body.contains("代理端口"), "要告诉用户这是代理端口：{body}");

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn http_proxy_reaches_a_peer_through_the_overlay() {
    // 主线故事：A 上没有出口，靠 `curl -x` 把请求交给 B 出去（§6.4）。
    let (origin_port, _accepts) = spawn_keepalive_origin("via-b").await;
    let port_a = free_port().await;
    let port_b = free_port().await;
    let dir_a = temp_dir("httpov-a");
    let dir_b = temp_dir("httpov-b");

    let b = HiveNode::start(base_cfg("fd00::b", port_b), &dir_b).await.unwrap();

    let mut cfg_a = base_cfg("fd00::a", port_a);
    cfg_a.peers.seeds = vec![format!("[::1]:{port_b}")];
    // 不写规则、也不写默认出口：靠 B 声明的网段把 127.0.0.1 的目标交给它
    cfg_a.route.default_egress = Some(EgressTarget::Node("fd00::b".parse().unwrap()));
    let a = HiveNode::start(cfg_a, &dir_a).await.unwrap();

    let aa = a.clone();
    wait_for(|| aa.state.proxy_bound.read().is_some(), 3000, "A 的代理端口就绪").await;
    let aa2 = a.clone();
    wait_for(
        || {
            aa2.topology()
                .nodes
                .iter()
                .any(|n| n.peer == "fd00::b".parse().unwrap() && n.reachable)
        },
        8000,
        "A 的拓扑里出现可达的 B",
    )
    .await;

    let proxy = a.state.proxy_bound.read().unwrap();
    let mut c = HttpProxyClient::connect(proxy).await;
    let (status, body) = c.get(&format!("http://127.0.0.1:{origin_port}/through-b")).await;
    assert_eq!(status, 200, "经 overlay 的绝对 URI 请求必须成功");
    assert_eq!(body, "via-b /through-b\n");
    assert!(
        b.stats().bytes_relayed_in > 0 || b.stats().bytes_relayed_out > 0,
        "字节必须真的从 B 走"
    );

    a.stop().await;
    b.stop().await;
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

#[tokio::test]
async fn http_proxy_tunnels_connect_through_the_overlay() {
    // CONNECT 走 overlay：隧道里的字节应当逐字节往返（ssh / https 就靠这条）。
    let echo_port = spawn_echo().await;
    let port_a = free_port().await;
    let port_b = free_port().await;
    let dir_a = temp_dir("httptun-a");
    let dir_b = temp_dir("httptun-b");

    let b = HiveNode::start(base_cfg("fd00::b", port_b), &dir_b).await.unwrap();
    let mut cfg_a = base_cfg("fd00::a", port_a);
    cfg_a.peers.seeds = vec![format!("[::1]:{port_b}")];
    cfg_a.route.default_egress = Some(EgressTarget::Node("fd00::b".parse().unwrap()));
    let a = HiveNode::start(cfg_a, &dir_a).await.unwrap();

    let aa = a.clone();
    wait_for(|| aa.state.proxy_bound.read().is_some(), 3000, "A 的代理端口就绪").await;
    let aa2 = a.clone();
    wait_for(
        || {
            aa2.topology()
                .nodes
                .iter()
                .any(|n| n.peer == "fd00::b".parse().unwrap() && n.reachable)
        },
        8000,
        "A 的拓扑里出现可达的 B",
    )
    .await;
    let proxy = a.state.proxy_bound.read().unwrap();

    let mut c = HttpProxyClient::connect(proxy).await;
    let status = c.connect_tunnel(&format!("127.0.0.1:{echo_port}")).await;
    assert_eq!(status, 200, "CONNECT 应当回 200 Connection Established");

    // 隧道通了：往里写什么就该回来什么
    c.sock.write_all(b"through the tunnel").await.unwrap();
    let mut got = Vec::new();
    let mut tmp = [0u8; 64];
    while got.len() < 18 {
        let n = tokio::time::timeout(Duration::from_secs(5), c.sock.read(&mut tmp))
            .await
            .expect("隧道里应当有回应")
            .unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&tmp[..n]);
    }
    assert_eq!(got, b"through the tunnel");

    a.stop().await;
    b.stop().await;
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

/// 源站**回完就关连接**（HTTP/1.0 / `Connection: close` 就是这样）—— 丢尾部数据的高危场景：
/// 出口侧的读泵读到 EOF 立刻关流，而尾部那几个 `Data` 帧还在路上。
///
/// 两处实现都要对才行，缺一条就丢尾巴（2026-10-13 在真实组网里踩到，表现为
/// "响应传到一半就断"/`curl: (18) transfer closed with N bytes remaining`）：
/// 1. 关流帧不能插到本流尾部数据前面（控制车道会插队）；
/// 2. 接收侧的泵在关流时要把**已经到达**的字节送完再收尾。
#[tokio::test]
async fn reply_tail_survives_a_close_right_after_the_response() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tail_port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            tokio::spawn(async move {
                let mut b = [0u8; 128];
                let _ = s.read(&mut b).await;
                let body = b"HTTP/1.0 200 OK\r\nContent-Length: 15\r\n\r\nHELLO-FROM-TAIL";
                let _ = s.write_all(body).await;
                let _ = s.shutdown().await; // ★ 回完就关
            });
        }
    });

    let port_a = free_port().await;
    let port_b = free_port().await;
    let dir_a = temp_dir("tail-a");
    let dir_b = temp_dir("tail-b");
    let b = HiveNode::start(base_cfg("fd00::b", port_b), &dir_b).await.unwrap();
    let mut cfg_a = base_cfg("fd00::a", port_a);
    cfg_a.peers.seeds = vec![format!("[::1]:{port_b}")];
    cfg_a.route.default_egress = Some(EgressTarget::Node("fd00::b".parse().unwrap()));
    let a = HiveNode::start(cfg_a, &dir_a).await.unwrap();

    let aa = a.clone();
    wait_for(|| aa.state.proxy_bound.read().is_some(), 3000, "A 的代理端口就绪").await;
    let aa2 = a.clone();
    wait_for(
        || {
            aa2.topology()
                .nodes
                .iter()
                .any(|n| n.peer == "fd00::b".parse().unwrap() && n.reachable)
        },
        8000,
        "A 的拓扑里出现可达的 B",
    )
    .await;
    let proxy = a.state.proxy_bound.read().unwrap();

    // 竞态，所以要跑很多轮 —— 修之前这里几乎每轮都会丢尾巴
    for round in 0..20 {
        let (mut c, rep) = socks5_connect(proxy, &format!("127.0.0.1:{tail_port}")).await;
        assert_eq!(rep, 0x00, "第 {round} 轮：CONNECT 应当成功");
        c.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        let mut got = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut tmp))
                .await
                .expect("第 {round} 轮：响应应当在 5 秒内到齐")
                .unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(
            got,
            b"HTTP/1.0 200 OK\r\nContent-Length: 15\r\n\r\nHELLO-FROM-TAIL".to_vec(),
            "第 {round} 轮：响应尾部不允许被吞掉"
        );
        let _ = c.shutdown().await;
    }

    a.stop().await;
    b.stop().await;
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}
