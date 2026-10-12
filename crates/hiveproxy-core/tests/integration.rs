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
    cfg.proxy.socks5_bind = "127.0.0.1:0".parse().unwrap();
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
        || node_a2.state.socks5_bound.read().is_some(),
        3000,
        "A 的 SOCKS5 端口就绪",
    )
    .await;
    let socks = a.state.socks5_bound.read().expect("A 的 SOCKS5 应当已绑定");
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
    wait_for(|| na.state.socks5_bound.read().is_some(), 3000, "A 的 SOCKS5 端口就绪").await;
    let socks = a_node.state.socks5_bound.read().unwrap();
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
    wait_for(|| nn.state.socks5_bound.read().is_some(), 3000, "SOCKS5 端口就绪").await;
    let socks = node.state.socks5_bound.read().expect("SOCKS5 应当已绑定");
    let (_c, rep) = socks5_connect(socks, "secret.blocked.example.com:443").await;
    assert_eq!(rep, 0x02, "block 必须回 connection not allowed");

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}
