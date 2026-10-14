//! 链路生命周期的资源回归测试。
//!
//! 起因是线上症状：hiveproxy 连续跑几小时/几天后，浏览器打开网页报
//! `ERR_NO_BUFFER_SPACE`（macOS 的 `ENOBUFS` —— 内核 socket 缓冲 / mbuf 被占光），
//! **关掉 hiveproxy 立刻恢复**。
//!
//! 用两个真实进程在同一网卡上复现出的链条：
//!
//! 1. 对端重启（或任何一次链路断开）→ `lose_peer` 把它从拓扑里摘掉（这一步是对的）；
//! 2. 它重启后重新广播的公告在 `relay::handle_gossip` 里被 gossip 去重表按 `(owner, seq)`
//!    **整条丢掉** —— 重启后 `incarnation`/`seq` 都从初始值重新开始，与已经见过的键撞车。
//!    于是"拓扑里没有它、links 里却有它"：`covered_by_existing_link` 失效，拨号器
//!    **每个巡检周期都重拨一次**，次次"拨通"（这一环的回归用例是 `relay` 模块里的
//!    `a_restarted_peer_comes_back_even_with_the_same_seq`）；
//! 3. 每次"拨通"都走 `register_link` 的同向重复分支，把上一条 `LinkHandle`
//!    **从表里换掉却从不 cancel** —— 旧 socket 与它的读/写任务就此失联，永不回收。
//!    本文件就是这一环的回归测试。
//!
//! 实测数据（两个 `hiveproxy-cli run --no-web`，kill -9 其中一个并重启 6 次）：
//! 幸存方 `lsof` 从 17 涨到 23 条 fd，多出来的全是发起向僵尸进程的 ESTABLISHED 连接，
//! 且管理接口问它自己时 `nodes` 里**再也看不到对端**。默认 `dial_interval_ms = 5000`
//! ⇒ 每个对端每小时约 720 条泄漏 socket，每条都占着内核收发缓冲 —— 这就是那个
//! "长时间运行后浏览器 ENOBUFS"。

use std::sync::Arc;
use std::time::{Duration, Instant};

use hiveproxy_core::config::Config;
use hiveproxy_core::handshake::{register_link, Established};
use hiveproxy_core::heartbeat::HeartbeatParams;
use hiveproxy_core::identity::NodeIdentity;
use hiveproxy_core::proto::{Establisher, NodeId};
use hiveproxy_core::state::HiveState;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

fn state_for(ip: &str) -> Arc<HiveState> {
    let mut cfg = Config::default();
    cfg.node.overlay_addr = Some(ip.parse().unwrap());
    cfg.listen.bind = ip.parse().unwrap();
    cfg.listen.ports = vec![0];
    cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
    cfg.discovery.lan_udp = false;
    cfg.admin.enabled = false;
    let id = Arc::new(NodeIdentity::resolve(&cfg).unwrap());
    HiveState::new(id, cfg)
}

/// 一对已连通的 TCP（回环）。
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move { l.accept().await.unwrap().0 });
    let c = TcpStream::connect(addr).await.unwrap();
    let s = h.await.unwrap();
    (c, s)
}

fn established(peer: NodeId, s: TcpStream, session_id: u64) -> Established {
    let (reader, writer) = tokio::io::split(s);
    Established {
        peer,
        session_id,
        listen_ports: Vec::new(),
        features: 0,
        reader,
        writer,
        remote_addr: "127.0.0.1:1".parse().unwrap(),
    }
}

/// 从链路对端一直读到 **EOF**。
///
/// `register_link` 会顺手广播一次拓扑（`broadcast_now`），所以对端 socket 上通常先到
/// 一个 gossip 帧 —— "第一次 read 就是 0" 这种断言立不住，必须排到真的 EOF 为止。
/// 返回 `true` = 确实关掉了。
async fn read_until_eof(s: &mut TcpStream, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        match tokio::time::timeout(left, s.read(&mut buf)).await {
            Ok(Ok(0)) => return true,      // 干净的 FIN
            Ok(Ok(_)) => continue,         // 还有帧（gossip / 心跳），继续排
            Ok(Err(_)) => return true,     // RST 也算关掉了
            Err(_) => return false,        // 超时：还开着
        }
    }
}

/// 这条连接在 `window` 内**没有**被关掉（有帧在流、或者干脆没动静，都算活着）。
async fn still_open(s: &mut TcpStream, window: Duration) -> bool {
    !read_until_eof(s, window).await
}

/// 链路被替换/顶掉时，旧 socket 必须真的关掉。
///
/// `register_link` 里有两条"换掉旧链路"的路：互拨去重判"保留新的"，以及同向重复。
/// 两条路上旧 `LinkHandle` 都只是从表里被丢掉，`cancel` 从不触发。
#[tokio::test]
async fn replacing_a_link_must_close_the_old_socket() {
    // 本机地址**小于**对端：`decide_keep` 在"新链路是入向、旧链路是自己拨出的"时
    // 判定保留新的那条（互拨去重的既有语义），走的正是"换掉旧的"这条路。
    let st = state_for("10.0.0.1");
    let peer: NodeId = "10.0.0.2".parse().unwrap();

    let (mine1, mut peer_side1) = tcp_pair().await;
    register_link(&st, established(peer, mine1, 1), Establisher::Local);
    let old = st.links.get(&peer).expect("第一条链路应当在表里").value().clone();

    let (mine2, _peer_side2) = tcp_pair().await;
    register_link(&st, established(peer, mine2, 2), Establisher::Remote);

    let now = st.links.get(&peer).expect("第二条链路应当在表里").value().clone();
    assert_eq!(now.session_id, 2, "互拨去重保留下来的应当是新的那条");
    assert!(
        old.cancel.is_cancelled(),
        "★ 被顶掉的旧链路没有拆：socket 与它的读/写任务都还活着（每次重连漏一条）"
    );
    assert!(
        read_until_eof(&mut peer_side1, Duration::from_secs(2)).await,
        "★ 旧 socket 必须真的发出 FIN，而不是一直挂着"
    );
}

/// 同向重复（本机重复拨同一个对端）必须**保留既有的、丢掉新的**。
///
/// 现有注释一直写的是"同向重复：保留既有的"，代码做的却是替换 —— 于是同一个对端被
/// 反复拨通时，每一次都漏掉上一条连接。这是实测中增长最快的那条路径
/// （拓扑里缺了端点 → 每个巡检周期重拨一次）。
#[tokio::test]
async fn a_duplicate_dial_never_replaces_the_live_link() {
    let st = state_for("10.0.0.1");
    let peer: NodeId = "10.0.0.2".parse().unwrap();

    let (mine1, mut peer_side1) = tcp_pair().await;
    register_link(&st, established(peer, mine1, 11), Establisher::Local);
    let first = st.links.get(&peer).unwrap().value().clone();

    // 又拨了一次（本机拨出，方向相同）
    let (mine2, mut peer_side2) = tcp_pair().await;
    register_link(&st, established(peer, mine2, 12), Establisher::Local);

    let now = st.links.get(&peer).unwrap().value().clone();
    assert_eq!(now.session_id, 11, "同向重复必须保留既有的那条");
    assert!(!first.cancel.is_cancelled(), "既有的链路不该被牵连");

    assert!(
        read_until_eof(&mut peer_side2, Duration::from_secs(2)).await,
        "多余的那条连接必须立刻关掉（否则每次重拨漏一条 socket）"
    );
    assert!(
        still_open(&mut peer_side1, Duration::from_millis(200)).await,
        "既有的那条必须还活着"
    );
}

/// 被顶掉的链路，它的读任务退出时**不能**把接力上来的活链路一起拆掉。
///
/// `link_reader_task` 退出时会 `teardown_link(peer)`；没有身份校验的话，一个被替换掉的
/// 僵尸链路读到 EOF 就会把当前那条删掉 —— 表现为"刚拨通就被拆"，每次抖动还带一次重连
/// 与一次 gossip flood。
#[tokio::test]
async fn a_stale_reader_cannot_tear_down_the_live_link() {
    let st = state_for("10.0.0.1");
    let peer: NodeId = "10.0.0.2".parse().unwrap();

    let (mine1, peer_side1) = tcp_pair().await;
    register_link(&st, established(peer, mine1, 1), Establisher::Local);
    let stale_session = st.links.get(&peer).unwrap().session_id;

    let (mine2, mut peer_side2) = tcp_pair().await;
    register_link(&st, established(peer, mine2, 2), Establisher::Remote);
    assert_eq!(st.links.get(&peer).unwrap().session_id, 2);

    // 模拟"僵尸链路的读任务退出"：目标会话已经不是当前那条了
    hiveproxy_core::handshake::teardown_link(&st, peer, stale_session, "链路关闭").await;
    assert!(
        st.links.contains_key(&peer),
        "★ 已经过期的会话不得拆掉当前这条链路（否则刚拨通就被拆，反复抖动）"
    );
    drop(peer_side1);

    // 当前那条依然能正常工作
    assert!(still_open(&mut peer_side2, Duration::from_millis(200)).await);
}

/// 对端"静默消失"（socket 仍 ESTABLISHED、但永不回应）时必须被判死拆链。
///
/// DESIGN.md §12 写着"链路心跳：每 3s（空闲时），连续 3 次未响应（约 10s）判定 Down、拆链"。
/// 2026-10-14 之前代码里**没有这个心跳**：`rtt_ms` 写死 0，`Pong` 到手就丢。
/// 对端睡眠 / 关机 / 拔网线（内核不发 RST）时，链路一直留在 `links` 里，socket 不释放，
/// 拨号器也不会重连（因为"链路还在"）。
///
/// 节奏从 `HiveState::heartbeat` 注入，所以这里是**亚秒级确定性**的，不等 10 秒真时间。
#[tokio::test]
async fn a_silent_peer_must_be_detected_and_torn_down() {
    let st = state_for("10.0.0.1");
    st.set_heartbeat(HeartbeatParams { interval: Duration::from_millis(50), misses: 3 });
    let peer: NodeId = "10.0.0.2".parse().unwrap();

    let (me, peer_side) = tcp_pair().await;
    register_link(&st, established(peer, me, 7), Establisher::Local);
    let handle = st.links.get(&peer).unwrap().value().clone();

    // 对端只收不发也不关连接：模拟拔网线 / 睡眠 / 被 kill -9 之后内核还没发 RST
    let keep = peer_side;

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !st.links.contains_key(&peer) {
            assert!(handle.unanswered() >= 3, "判死的依据必须是'连续几次没等到 Pong'");
            assert!(handle.cancel.is_cancelled(), "拆链必须真的把这条链路的资源放掉");
            drop(keep);
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(keep);
    panic!("静默的对端没有被判死：这条链路（socket + 读/写任务 + 心跳任务）会永远留着");
}

/// 心跳活着的时候不该误伤：对端回 Pong 的链路要一直留着，并把 RTT 量出来。
///
/// 这条同时钉住"心跳不是单向判死"：只要按间隔回 Pong，链路就永远不拆。
#[tokio::test]
async fn a_responding_peer_keeps_the_link_and_reports_rtt() {
    let st = state_for("10.0.0.1");
    st.set_heartbeat(HeartbeatParams { interval: Duration::from_millis(50), misses: 3 });
    let peer: NodeId = "10.0.0.2".parse().unwrap();

    let (me, mut peer_side) = tcp_pair().await;
    register_link(&st, established(peer, me, 9), Establisher::Local);
    let handle = st.links.get(&peer).unwrap().value().clone();

    // 演一个"活着的对端"：读到 Ping 就回一个 Pong（先把 gossip 之类的帧读掉）
    let me = st.self_id();
    let responder = tokio::spawn(async move {
        loop {
            match hiveproxy_core::proto::read_frame(&mut peer_side).await {
                Ok(Some(f)) => {
                    if f.header.msg_type == hiveproxy_core::proto::MsgType::Ping {
                        // 故意拖一下，好让量出来的 RTT 明显不为 0（回环本身 <1ms）
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        // 与生产代码同一套构造：src = 我（对端侧），dst = 拨方
                        let pong = hiveproxy_core::msg::control_header(
                            hiveproxy_core::proto::MsgType::Pong,
                            peer,
                            me,
                            1,
                        );
                        let raw = hiveproxy_core::proto::RawFrame::build(pong, b"").unwrap();
                        use tokio::io::AsyncWriteExt;
                        if peer_side.write_all(&raw.raw).await.is_err() {
                            return;
                        }
                    }
                }
                _ => return,
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(st.links.contains_key(&peer), "回了 Pong 的链路不得被判死");
    assert_eq!(handle.unanswered(), 0, "收到 Pong 必须清零未回应计数");

    // RTT 必须真的量出来并写回 LinkMeta（那是 router 成本项的一半来源）
    let rtt = handle.rtt_ms();
    assert!(
        (20..=60).contains(&rtt),
        "对端拖了 25ms 才回 Pong，RTT 应当落在 10ms 分桶的 20~60 之间，实际 {rtt}"
    );

    responder.abort();
}