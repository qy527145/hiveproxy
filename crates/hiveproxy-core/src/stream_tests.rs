//! `stream` 模块的单元测试。之所以单独成文件，是因为测试里要起真实的链路写出任务
//! 并通过 duplex 观察线格式帧，与实现代码混在一起会很难读。

use super::*;
use crate::proto::{read_frame, Carrier, RawFrame};
use crate::testutil::nid;

use crate::testutil::{attach_link, expect_no_frame, next_frame, state_for};

fn st(ip: &str) -> Arc<HiveState> {
    state_for(ip, crate::config::Config::default())
}

#[tokio::test]
async fn deliver_to_unknown_stream_sends_close() {
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    deliver_data(&st, peer, 999, Bytes::from_static(b"x")).await;
    let f = next_frame(&mut obs).await;
    assert_eq!(f.header.msg_type, MsgType::StreamClose);
    let msg: StreamCloseMsg = crate::proto::decode_payload(f.payload()).unwrap();
    assert_eq!(msg.reason, CloseReason::UnknownStream);
}

#[tokio::test]
async fn open_stream_times_out_when_no_ack_arrives() {
    let st = st("10.0.0.1");
    {
        let mut cfg = st.cfg().as_ref().clone();
        cfg.egress.egress_ack_timeout_ms = 150;
        st.config.store(Arc::new(cfg));
    }
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;

    let res = open_stream(
        st.clone(),
        Endpoint::new(Host::Name("example.invalid".into()), 80),
        peer,
        None,
    )
    .await;
    assert!(matches!(res, Err(OpenError::Timeout)), "无 ack 时必须超时返回");
    let f = next_frame(&mut obs).await;
    assert_eq!(f.header.msg_type, MsgType::StreamOpen);
    assert!(st.streams.is_empty(), "超时后必须清理流上下文");
    assert!(st.pending_opens.is_empty());
}

#[tokio::test]
async fn open_stream_happy_path() {
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;

    let st2 = st.clone();
    tokio::spawn(async move {
        if let Ok(Some(f)) = read_frame(&mut obs).await {
            assert_eq!(f.header.msg_type, MsgType::StreamOpen);
            tokio::time::sleep(Duration::from_millis(10)).await;
            handle_stream_ack(
                &st2,
                f.header.stream_id,
                StreamAckMsg { ok: true, code: 0, reason: String::new() },
            );
        }
    });

    let opened = open_stream(
        st.clone(),
        Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 443),
        peer,
        Some(0),
    )
    .await
    .expect("应当成功打开");
    assert_eq!(opened.ctx.state(), StreamState::Open);
    assert_eq!(opened.ctx.key.0, peer);
    assert_eq!(st.streams.len(), 1);

    let rules = vec![crate::rules::Rule::new(
        crate::rules::HostMatcher::Any,
        crate::rules::PortMatcher::Any,
        crate::rules::EgressTarget::Auto,
    )];
    assert_eq!(st.rule_hits.snapshot(&rules)[0].hits, 1, "命中统计必须被记录");
}

#[tokio::test]
async fn rejected_open_surfaces_the_reason() {
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    let st2 = st.clone();
    tokio::spawn(async move {
        if let Ok(Some(f)) = read_frame(&mut obs).await {
            handle_stream_ack(
                &st2,
                f.header.stream_id,
                StreamAckMsg { ok: false, code: 5, reason: "连接被拒".into() },
            );
        }
    });
    let res = open_stream(
        st.clone(),
        Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 443),
        peer,
        None,
    )
    .await;
    match res {
        Err(OpenError::Rejected { code, reason }) => {
            assert_eq!(code, 5);
            assert_eq!(reason, "连接被拒");
        }
        _ => panic!("应当被拒绝"),
    }
    assert!(st.streams.is_empty());
}

#[tokio::test]
async fn open_to_self_is_a_self_loop() {
    let st = st("10.0.0.1");
    let me = st.self_id();
    let r = open_stream(
        st.clone(),
        Endpoint::new(Host::Ip("10.0.0.1".parse().unwrap()), 80),
        me,
        None,
    )
    .await;
    assert!(matches!(r, Err(OpenError::SelfLoop)));
}

#[tokio::test]
async fn link_loss_resets_streams_pinned_to_that_hop() {
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    let st2 = st.clone();
    tokio::spawn(async move {
        if let Ok(Some(f)) = read_frame(&mut obs).await {
            handle_stream_ack(
                &st2,
                f.header.stream_id,
                StreamAckMsg { ok: true, code: 0, reason: String::new() },
            );
        }
    });
    let opened = open_stream(
        st.clone(),
        Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 443),
        peer,
        None,
    )
    .await
    .unwrap();
    assert_eq!(st.streams.len(), 1);

    fail_all_streams_via(&st, peer, "链路断开").await;
    assert!(st.streams.is_empty(), "钉在失效下一跳上的流必须被重置（§5.5）");
    assert!(opened.ctx.reset_due_to_link_loss.load(Ordering::Relaxed));
}

#[tokio::test]
async fn window_update_reaches_the_ctx() {
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    let st2 = st.clone();
    tokio::spawn(async move {
        if let Ok(Some(f)) = read_frame(&mut obs).await {
            handle_stream_ack(
                &st2,
                f.header.stream_id,
                StreamAckMsg { ok: true, code: 0, reason: String::new() },
            );
        }
    });
    let opened = open_stream(
        st.clone(),
        Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 443),
        peer,
        None,
    )
    .await
    .unwrap();
    while opened.ctx.take_credit() {}
    handle_window_update(&st, peer, WindowUpdateMsg { stream_id: opened.ctx.key.1, credit: 7 });
    assert_eq!(opened.ctx.send_credit.load(Ordering::Relaxed), 7);
}

#[tokio::test]
async fn overflow_closes_the_stream_instead_of_silently_dropping() {
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    let st2 = st.clone();
    tokio::spawn(async move {
        if let Ok(Some(f)) = read_frame(&mut obs).await {
            handle_stream_ack(
                &st2,
                f.header.stream_id,
                StreamAckMsg { ok: true, code: 0, reason: String::new() },
            );
        }
    });
    let opened = open_stream(
        st.clone(),
        Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 443),
        peer,
        None,
    )
    .await
    .unwrap();
    let sid = opened.ctx.key.1;
    for _ in 0..(STREAM_WINDOW + 2) {
        deliver_data(&st, peer, sid, Bytes::from_static(b"chunk")).await;
    }
    assert!(st.streams.is_empty(), "超出窗口必须关流");
    assert!(opened.ctx.closed());
    assert!(st.stats.streams_dropped.load(Ordering::Relaxed) >= 1);
}

async fn origin_ctx(st: &Arc<HiveState>, peer: NodeId, stream_id: u64) -> Arc<StreamCtx> {
    let (sink_tx, _sink_rx) = mpsc::channel(STREAM_WINDOW as usize);
    let out = st.stream_queue(peer, stream_id).unwrap();
    let ctx = Arc::new(StreamCtx::new(
        StreamKey(peer, stream_id),
        Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 80),
        peer,
        peer,
        StreamRole::Origin,
        None,
        sink_tx,
        out,
    ));
    ctx.set_state(StreamState::Open);
    ctx
}

#[tokio::test]
async fn pump_moves_bytes_from_local_into_frames() {
    use tokio::io::AsyncWriteExt as _;
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    let ctx = origin_ctx(&st, peer, 1).await;

    let (mut a, b) = tokio::io::duplex(1024);
    let st2 = st.clone();
    let ctx2 = ctx.clone();
    tokio::spawn(async move { pump_local_to_overlay(st2, ctx2, b).await });

    a.write_all(b"hello hive").await.unwrap();
    a.shutdown().await.unwrap();

    let f = next_frame(&mut obs).await;
    assert_eq!(f.header.msg_type, MsgType::Data);
    assert_eq!(f.header.stream_id, 1);
    assert_eq!(f.payload(), b"hello hive");
    assert_eq!(
        ctx.send_credit.load(Ordering::Relaxed),
        STREAM_WINDOW - 1,
        "每发一帧扣一格信用"
    );
}

#[tokio::test]
async fn pump_stops_when_credit_is_exhausted() {
    use tokio::io::AsyncWriteExt as _;
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    let ctx = origin_ctx(&st, peer, 1).await;
    ctx.set_credit(0);

    let (mut a, b) = tokio::io::duplex(4096);
    let st2 = st.clone();
    let ctx2 = ctx.clone();
    tokio::spawn(async move { pump_local_to_overlay(st2, ctx2, b).await });
    a.write_all(b"should not be sent").await.unwrap();

    expect_no_frame(&mut obs).await;
}

#[tokio::test]
async fn pump_recovers_credit_and_emits_window_updates() {
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    let (sink_tx, sink_rx) = mpsc::channel(STREAM_WINDOW as usize);
    let out = st.stream_queue(peer, 1).unwrap();
    let ctx = Arc::new(StreamCtx::new(
        StreamKey(peer, 1),
        Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 80),
        peer,
        peer,
        StreamRole::Egress,
        None,
        sink_tx.clone(),
        out,
    ));
    ctx.set_state(StreamState::Open);

    let st2 = st.clone();
    let ctx2 = ctx.clone();
    tokio::spawn(async move { pump_overlay_to_local(st2, ctx2, sink_rx, tokio::io::sink()).await });

    for _ in 0..crate::session::WINDOW_UPDATE_BATCH {
        assert!(ctx.on_frame_received());
        sink_tx.send(Bytes::from_static(b"data")).await.unwrap();
    }

    let f = next_frame(&mut obs).await;
    assert_eq!(f.header.msg_type, MsgType::WindowUpdate);
    let wu: WindowUpdateMsg = crate::proto::decode_payload(f.payload()).unwrap();
    assert!(wu.credit >= STREAM_WINDOW - 1, "消费后应当回收信用: {}", wu.credit);
}

#[test]
fn resolve_endpoints_handles_ip_directly() {
    let ep = Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 3389);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let a = rt.block_on(resolve_endpoints(&ep)).unwrap();
    assert_eq!(a, vec!["10.4.0.9:3389".parse().unwrap()]);
}

#[test]
fn resolve_endpoints_returns_every_address_for_a_name() {
    // ★ 这里必须回**全部**地址：`localhost` 通常是 `::1` + `127.0.0.1`，
    // 只取第一个的话，目标只监听 IPv4 时就会白报一次"连接被拒"（2026-10-13 修）。
    let ep = Endpoint::new(Host::Name("localhost".into()), 9);
    let rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(resolve_endpoints(&ep)) {
        Ok(addrs) => assert!(
            addrs.iter().all(|a| a.port() == 9),
            "端口必须原样带过去: {addrs:?}"
        ),
        // 有些环境没有 localhost 的解析结果（容器里很常见）—— 那不算失败
        Err(e) => assert!(e.contains("无解析结果"), "{e}"),
    }
}

#[tokio::test]
async fn egress_refuses_when_allow_egress_is_false() {
    let mut cfg = crate::config::Config::default();
    cfg.node.overlay_addr = Some("10.0.0.1".parse().unwrap());
    cfg.listen.bind = "10.0.0.1".parse().unwrap();
    cfg.egress.allow_egress = false;
    let id = Arc::new(crate::identity::NodeIdentity::resolve(&cfg).unwrap());
    let st = HiveState::new(id, cfg);
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;

    let msg = StreamOpenMsg {
        endpoint: Endpoint::new(Host::Ip("10.4.0.9".parse().unwrap()), 80),
        proto: Proto::Tcp,
        flags: 0,
        e2e_pk: None,
    };
    let payload = crate::proto::encode_payload(&msg).unwrap();
    let mut h = HiveHeader::new(MsgType::StreamOpen, peer, nid("10.0.0.1"), 8);
    h.stream_id = 5;
    h.flags |= crate::proto::flags::CONTROL;
    let frame = RawFrame::build(h, &payload).unwrap();
    handle_stream_open(st.clone(), frame).await;

    let f = next_frame(&mut obs).await;
    assert_eq!(f.header.msg_type, MsgType::StreamAck);
    let ack: StreamAckMsg = crate::proto::decode_payload(f.payload()).unwrap();
    assert!(!ack.ok);
    assert_eq!(ack.code, 3, "拒绝做出口时回 Refused（§9.4.4）");
}

#[tokio::test]
async fn egress_connects_to_a_real_local_socket_and_echoes_back() {
    // 起一个本地 TCP echo 服务，验证出口侧真的连上去并把数据搬回来。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut buf = [0u8; 32];
            if let Ok(n) = s.read(&mut buf).await {
                let _ = s.write_all(&buf[..n]).await;
            }
            let _ = s.shutdown().await;
        }
    });

    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;

    let msg = StreamOpenMsg {
        endpoint: Endpoint::new(Host::Ip("127.0.0.1".parse().unwrap()), port),
        proto: Proto::Tcp,
        flags: 0,
        e2e_pk: None,
    };
    let payload = crate::proto::encode_payload(&msg).unwrap();
    let mut h = HiveHeader::new(MsgType::StreamOpen, peer, nid("10.0.0.1"), 8);
    h.stream_id = 77;
    h.flags |= crate::proto::flags::CONTROL;
    handle_stream_open(st.clone(), RawFrame::build(h, &payload).unwrap()).await;

    let ack = next_frame(&mut obs).await;
    assert_eq!(ack.header.msg_type, MsgType::StreamAck, "第一帧应当是 StreamAck");
    let ack: StreamAckMsg = crate::proto::decode_payload(ack.payload()).unwrap();
    assert!(ack.ok, "出口应当连上本地 echo 服务: {ack:?}");
    assert_eq!(st.streams.len(), 1, "出口侧必须登记流上下文");

    deliver_data(&st, peer, 77, Bytes::from_static(b"ping")).await;

    let mut got_echo = false;
    for _ in 0..8 {
        let f = match tokio::time::timeout(Duration::from_secs(2), read_frame(&mut obs)).await {
            Ok(Ok(Some(f))) => f,
            _ => break,
        };
        if f.header.msg_type == MsgType::Data && f.payload() == b"ping" {
            got_echo = true;
            break;
        }
    }
    assert!(got_echo, "本地 socket 的回应必须被搬回 overlay");
}

#[test]
fn stream_open_msg_roundtrips_on_the_wire() {
    let msg = StreamOpenMsg {
        endpoint: Endpoint::new(Host::Ip("127.0.0.1".parse().unwrap()), 8080),
        proto: Proto::Tcp,
        flags: 0,
        e2e_pk: None,
    };
    let b = crate::proto::encode_payload(&msg).unwrap();
    let back: StreamOpenMsg = crate::proto::decode_payload(&b).unwrap();
    assert_eq!(back, msg);
}

#[tokio::test]
async fn manual_control_send_is_observable() {
    let st = st("10.0.0.1");
    let peer = nid("10.0.0.2");
    let mut obs = attach_link(&st, peer, Carrier::Direct).await;
    st.try_send_control_to(
        peer,
        crate::link::OutboundFrame::new(
            crate::proto::HiveHeader::new(MsgType::Ping, st.self_id(), peer, 4),
            Bytes::new(),
        ),
    )
    .unwrap();
    let f = next_frame(&mut obs).await;
    assert_eq!(f.header.msg_type, MsgType::Ping);
}
