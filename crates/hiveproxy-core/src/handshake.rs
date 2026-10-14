//! L1 链路建立与读写任务（DESIGN.md §5.4）。
//!
//! 握手**同时承担「端口探测」职责**：首字节 magic + 版本位必须在拿到前 2 字节时就判定，
//! 这样"拨到非 hiveproxy 服务"是一个廉价且确定性的失败，而不是等满 48 字节或等超时
//! （§6.2.2、§6.2.3）。
//!
//! ## 认证（v1.5 的 `join_token`）
//!
//! §5.4 原式 `HMAC(token, nonce_a || nonce_b || addr_a || addr_b)` 发起方算不出来
//! （它还不知道 `nonce_b`）。因此实现成**双向各证一次**：
//!
//! - `Hello.auth  = HMAC(token, "hello" || nonce_a || addr_a)` —— 证明**拨入方**持令牌；
//! - `HelloAck.auth = HMAC(token, "ack" || nonce_a || nonce_b || addr_a || addr_b)` ——
//!   证明**被拨方**持令牌。
//!
//! 两侧各验一次，任何一侧没有令牌都握不上手。`join_token` 为空时两个字段都是 `None`。

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::events::HiveEvent;
use crate::link::LinkHandle;
use crate::msg::control_header;
use crate::proto::{
    decode_payload, encode_payload, HelloAckMsg, HelloMsg, MsgType, NodeId, RawFrame,
    RejectMsg, RejectReason, VERSION,
};
use crate::error::ProtoError;
use crate::state::HiveState;

type HmacSha256 = Hmac<Sha256>;

/// 握手超时。
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum HandshakeError {
    Io(std::io::Error),
    Proto(ProtoError),
    /// 版本区间没有交集。
    VersionMismatch { mine: (u8, u8), theirs: (u8, u8) },
    /// 对端拒绝。
    Rejected(RejectReason),
    /// 令牌校验失败。
    AuthFailed,
    /// 超时（对端没有按时回 `HelloAck`）。
    Timeout,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O 错误: {e}"),
            Self::Proto(e) => write!(f, "协议错误: {e}"),
            Self::VersionMismatch { mine, theirs } => {
                write!(f, "版本不兼容：本机 {mine:?}，对端 {theirs:?}")
            }
            Self::Rejected(r) => write!(f, "对端拒绝: {r:?}"),
            Self::AuthFailed => write!(f, "join_token 校验失败"),
            Self::Timeout => write!(f, "握手超时"),
        }
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ProtoError> for HandshakeError {
    fn from(e: ProtoError) -> Self {
        Self::Proto(e)
    }
}

pub fn random_nonce() -> [u8; 16] {
    let mut n = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

fn hmac32(token: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC 接受任意长度密钥");
    for p in parts {
        mac.update(p);
    }
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// 拨入方证明自己持令牌（§5.4 的 `Hello.auth`）。
pub fn hello_auth(token: &str, nonce_a: &[u8; 16], addr_a: NodeId) -> [u8; 32] {
    hmac32(token, &[b"hello", nonce_a, &addr_a.0])
}

/// 被拨方证明自己持令牌（§5.4 的 `HelloAck.auth`）。
pub fn ack_auth(
    token: &str,
    nonce_a: &[u8; 16],
    nonce_b: &[u8; 16],
    addr_a: NodeId,
    addr_b: NodeId,
) -> [u8; 32] {
    hmac32(token, &[b"ack", nonce_a, nonce_b, &addr_a.0, &addr_b.0])
}

/// 握手成功后的产物。
#[derive(Debug)]
pub struct Established {
    pub peer: NodeId,
    pub session_id: u64,
    /// 对端实际在听的端口，供端口对齐自检（§6.2.3）。
    pub listen_ports: Vec<u16>,
    pub features: u32,
    pub reader: tokio::io::ReadHalf<TcpStream>,
    pub writer: tokio::io::WriteHalf<TcpStream>,
    pub remote_addr: SocketAddr,
}

/// 拨入方：连接 → `Hello` → 等 `HelloAck`。
pub async fn dial_and_handshake(
    state: &Arc<HiveState>,
    addr: SocketAddr,
) -> Result<Established, HandshakeError> {
    let timeout = HANDSHAKE_TIMEOUT;
    match tokio::time::timeout(timeout, dial_inner(state, addr)).await {
        Ok(r) => r,
        Err(_) => Err(HandshakeError::Timeout),
    }
}

/// 链路 socket 的内核级保活。
///
/// macOS 默认**不开** `SO_KEEPALIVE`，所以对端拔网线/关机之后（内核不会发 RST），
/// 这条连接在系统眼里可以永远 ESTABLISHED —— 带着它的收发缓冲一起挂着。
/// 应用层心跳（`heartbeat.rs`）负责判死，这里是**兜底**：万一心跳那边有 bug，
/// 内核也会在分钟级把半开连接回收掉，不至于让 socket 缓冲无限积累。
fn set_keepalive(stream: &TcpStream) {
    use std::time::Duration as StdDuration;
    let s = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new().with_time(StdDuration::from_secs(30));
    // 平台不认 `with_time`（部分 BSD/Windows 组合）也要把开关本身打开
    let _ = s.set_tcp_keepalive(&ka);
    let _ = s.set_keepalive(true);
}

async fn dial_inner(
    state: &Arc<HiveState>,
    addr: SocketAddr,
) -> Result<Established, HandshakeError> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();
    set_keepalive(&stream);
    let (mut reader, mut writer) = tokio::io::split(stream);

    let cfg = state.cfg();
    let nonce_a = random_nonce();
    let me = state.self_id();
    let hello = HelloMsg {
        ver_min: VERSION,
        ver_max: VERSION,
        node_addr: me,
        nonce: nonce_a,
        features: crate::proto::features::NONE,
        auth: if cfg.security.join_token.is_empty() {
            None
        } else {
            Some(hello_auth(&cfg.security.join_token, &nonce_a, me))
        },
    };

    let payload = encode_payload(&hello)?;
    let frame = RawFrame::build(
        control_header(MsgType::Hello, me, crate::proto::BROADCAST, 1),
        &payload,
    )?;
    writer.write_all(&frame.raw).await?;

    // 读回执。magic/version 由 read_frame 在 2 字节内判定 —— 拨到别的服务会在这里确定性失败。
    let resp = match tokio::time::timeout(HANDSHAKE_TIMEOUT, crate::proto::read_frame(&mut reader))
        .await
    {
        Ok(Ok(Some(f))) => f,
        Ok(Ok(None)) => return Err(HandshakeError::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        ))),
        Ok(Err(e)) => return Err(HandshakeError::Proto(e)),
        Err(_) => return Err(HandshakeError::Timeout),
    };

    match resp.header.msg_type {
        MsgType::HelloAck => {
            let ack: HelloAckMsg = decode_payload(resp.payload())?;
            // 版本区间取交集
            let _ = (ack.features, ack.session_id);
            if !token_ok_ack(&cfg.security.join_token, &nonce_a, &ack, me) {
                return Err(HandshakeError::AuthFailed);
            }
            let tcp = reunite(reader, writer)?;
            let (r, w) = tokio::io::split(tcp);
            Ok(Established {
                peer: ack.node_addr,
                session_id: ack.session_id,
                listen_ports: ack.listen_ports,
                features: ack.features,
                reader: r,
                writer: w,
                remote_addr: addr,
            })
        }
        MsgType::Reject => {
            let rej: RejectMsg = decode_payload(resp.payload())?;
            Err(HandshakeError::Rejected(rej.reason))
        }
        other => {
            // 对端回了别的东西 —— 当作协议错误
            Err(HandshakeError::Proto(ProtoError::UnknownMsgType(other as u8)))
        }
    }
}

fn token_ok_ack(token: &str, nonce_a: &[u8; 16], ack: &HelloAckMsg, me: NodeId) -> bool {
    if token.is_empty() {
        return true;
    }
    match ack.auth {
        None => false,
        Some(got) => {
            let want = ack_auth(token, nonce_a, &ack.nonce, me, ack.node_addr);
            constant_time_eq(&got, &want)
        }
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn reunite(
    r: tokio::io::ReadHalf<TcpStream>,
    w: tokio::io::WriteHalf<TcpStream>,
) -> Result<TcpStream, HandshakeError> {
    // `unsplit` 只在两端来自同一个 split 时失败，这里必定成功。
    Ok(r.unsplit(w))
}

/// 被拨方：读 `Hello` → 回 `HelloAck`。
///
/// 返回 `Ok(None)` 表示这是一次**正常的拒绝**（版本不符、认证失败、超过 `max_links`），
/// 调用方只需关闭连接。
pub async fn accept_and_handshake(
    state: &Arc<HiveState>,
    stream: TcpStream,
    remote_addr: SocketAddr,
) -> Result<Option<Established>, HandshakeError> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, accept_inner(state, stream, remote_addr)).await {
        Ok(r) => r,
        Err(_) => Ok(None),
    }
}

async fn accept_inner(
    state: &Arc<HiveState>,
    stream: TcpStream,
    remote_addr: SocketAddr,
) -> Result<Option<Established>, HandshakeError> {
    let cfg = state.cfg();
    stream.set_nodelay(true).ok();
    set_keepalive(&stream);
    let (mut reader, mut writer) = tokio::io::split(stream);

    let first = match tokio::time::timeout(HANDSHAKE_TIMEOUT, crate::proto::read_frame(&mut reader))
        .await
    {
        Ok(Ok(Some(f))) => f,
        // 对端连上就关，或者根本不是 hiveproxy —— 静默丢弃即可
        Ok(_) => return Ok(None),
        Err(_) => return Ok(None),
    };

    if first.header.msg_type != MsgType::Hello {
        return Ok(None);
    }
    let hello: HelloMsg = match decode_payload(first.payload()) {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };

    // 版本区间必须有交集
    if hello.ver_max < VERSION || hello.ver_min > VERSION {
        let msg = RejectMsg { reason: RejectReason::VersionMismatch };
        let _ = reply(&mut writer, MsgType::Reject, &msg).await;
        return Ok(None);
    }

    // 入网门槛：`join_token`
    if !cfg.security.join_token.is_empty() {
        let ok = match hello.auth {
            None => false,
            Some(got) => {
                constant_time_eq(&got, &hello_auth(&cfg.security.join_token, &hello.nonce, hello.node_addr))
            }
        };
        if !ok {
            let msg = RejectMsg { reason: RejectReason::AuthFailed };
            let _ = reply(&mut writer, MsgType::Reject, &msg).await;
            return Ok(None);
        }
    }

    // 保护阈值
    if state.links.len() >= cfg.listen.max_links {
        let msg = RejectMsg { reason: RejectReason::TooManyLinks };
        let _ = reply(&mut writer, MsgType::Reject, &msg).await;
        return Ok(None);
    }

    let nonce_b = random_nonce();
    let me = state.self_id();
    let session_id = rand::random::<u64>();
    let ack = HelloAckMsg {
        node_addr: me,
        nonce: nonce_b,
        features: crate::proto::features::NONE,
        session_id,
        listen_ports: state.listen_ports_live(),
        auth: if cfg.security.join_token.is_empty() {
            None
        } else {
            Some(ack_auth(&cfg.security.join_token, &hello.nonce, &nonce_b, hello.node_addr, me))
        },
    };
    if reply(&mut writer, MsgType::HelloAck, &ack).await.is_err() {
        return Ok(None);
    }

    Ok(Some(Established {
        peer: hello.node_addr,
        session_id,
        listen_ports: Vec::new(),
        features: hello.features,
        reader,
        writer,
        remote_addr,
    }))
}

async fn reply<T: serde::Serialize>(
    w: &mut WriteHalf<TcpStream>,
    ty: MsgType,
    msg: &T,
) -> Result<(), HandshakeError> {
    let payload = encode_payload(msg)?;
    let frame = RawFrame::build(
        control_header(ty, crate::proto::BROADCAST, crate::proto::BROADCAST, 1),
        &payload,
    )?;
    w.write_all(&frame.raw).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 注册链路
// ---------------------------------------------------------------------------

/// 把一条已握手的连接注册成链路：起写出任务与读任务，更新拓扑并广播。
pub fn register_link(
    state: &Arc<HiveState>,
    est: Established,
    establisher: crate::proto::Establisher,
) -> NodeId {
    let peer = est.peer;
    let cancel = CancellationToken::new();

    let (sender, _writer_task) = crate::link::spawn_link(est.writer, cancel.clone());

    // 同网段载体成本更低（§3.3）
    let carrier = match (peer.to_ip(), state.self_id().to_ip()) {
        (Some(a), Some(b)) if crate::net::is_same_subnet(a, b) => crate::proto::Carrier::Lan,
        _ => crate::proto::Carrier::Direct,
    };

    let handle = Arc::new(LinkHandle {
        peer,
        meta: parking_lot::RwLock::new(crate::proto::LinkMeta {
            establisher,
            carrier,
            rtt_ms: 0,
            health: crate::proto::Health::Up,
            since: Instant::now(),
        }),
        cancel: cancel.clone(),
        sender,
        session_id: est.session_id,
        establisher,
        ping: parking_lot::Mutex::new(crate::link::PingState::default()),
    });

    // 互拨去重：同一 NodeId 已经有链路时，按字节序裁决保留哪一条（§5.4 第 4 条）；
    // 同向重复（多拨了一次）则保留既有的。
    //
    // ★ **谁出局，谁就必须被真的拆掉。** 两条路都要显式 `cancel`：
    // - 保留既有的 → 拆掉这次多拨出来的新连接；
    // - 保留新的 → 用 `insert` 的返回值把被顶掉的旧连接拆掉。
    //
    // 早先只做 `links.insert(peer, handle)`，旧 `LinkHandle` 只是从表里被丢掉，
    // `cancel` 从不触发 —— 那条 TCP 连接与它的读/写任务就此失联，永不回收。
    // 对一个每巡检周期都会重拨的对端（见 `tests/link_lifecycle.rs`），
    // 这就是每小时几百条泄漏 socket，最终吃光整台机器的 socket 缓冲。
    //
    // 用 `entry` 而不是 get+insert：决定用哪条与换表必须是同一次临界区，
    // 否则两个并发 accept 会各看各的"既有链路"。
    {
        use dashmap::mapref::entry::Entry;
        match state.links.entry(peer) {
            Entry::Occupied(mut o) => {
                if decide_keep(
                    state.self_id(),
                    peer,
                    establishing_is_local(establisher),
                    establishing_is_local(o.get().establisher),
                ) {
                    cancel.cancel();
                    state.log(
                        "debug",
                        "link",
                        format!("{peer} 已有一条链路，这次拨号是多余的（已丢弃新连接）"),
                    );
                    return peer;
                }
                let displaced = o.insert(handle.clone());
                displaced.cancel.cancel();
            }
            Entry::Vacant(v) => {
                v.insert(handle.clone());
            }
        }
    }
    state.stats.links.store(state.links.len(), Ordering::Relaxed);
    state.stats.handshakes_ok.fetch_add(1, Ordering::Relaxed);

    let state_r = state.clone();
    tokio::spawn(link_reader_task(state_r, peer, est.reader, handle.clone()));

    // 心跳（§12）：没有它，对端睡眠 / 关机 / 拔网线（内核不发 RST）时这条链路会一直是
    // "up"，socket 不回收、拨号器也不重连。只在**这里**起 —— `testutil::attach_link`
    // 那种纯内存链路不该有定时器。
    crate::heartbeat::spawn(state.clone(), handle.clone());

    state.log(
        "info",
        "link",
        format!(
            "{} {}（{}）",
            if establishing_is_local(establisher) { "已连接" } else { "已接受" },
            peer,
            est.remote_addr
        ),
    );
    state.emit(HiveEvent::PeerUp {
        peer,
        establisher: format!("{establisher:?}").to_lowercase(),
        carrier: carrier.as_str().to_string(),
    });

    // 链路变化 → 立即变化驱动 flood（§6.3）
    let st = state.clone();
    tokio::spawn(async move { crate::gossip::broadcast_now(&st, true).await });

    peer
}

fn establishing_is_local(e: crate::proto::Establisher) -> bool {
    matches!(e, crate::proto::Establisher::Local)
}

/// 互拨去重：字节序小的一方保留**自己的出站**连接，另一方保留入站（§5.4）。
///
/// 返回 `true` = 保留既有的那条（调用方负责把**新**来的拆掉）。
///
/// - **同向重复**（本机重复拨了同一个对端，或对端重复拨了本机）：保留既有的、丢掉新的。
///   这时两条走的是同一个方向，谈不上"哪个方向更该活"，留一条就够 ——
///   而"丢掉"必须是**真的拆掉**，否则就是每次多拨漏一条 socket。
/// - **互拨**（我出站 + 他入站，即 A→B 与 B→A 同时存在）：按字节序裁决，
///   保证两侧算出的结果指向**同一条** TCP 连接（否则两边各留各的，两条都会被对方关掉）。
fn decide_keep(
    me: NodeId,
    peer: NodeId,
    mine_is_local: bool,
    theirs_is_local: bool,
) -> bool {
    if mine_is_local == theirs_is_local {
        return true; // 同向重复：保留既有的
    }
    // 我出站、他入站 => 两条分别是 A→B 和 B→A。按字节序裁决。
    if me < peer {
        mine_is_local
    } else {
        theirs_is_local
    }
}

/// 链路读任务：解析帧 → `route_packet`；退出时清理链路与拓扑。
pub async fn link_reader_task(
    state: Arc<HiveState>,
    peer: NodeId,
    mut reader: tokio::io::ReadHalf<TcpStream>,
    handle: Arc<LinkHandle>,
) {
    loop {
        tokio::select! {
            _ = handle.cancel.cancelled() => break,
            _ = state.shutdown.cancelled() => break,
            r = crate::proto::read_frame(&mut reader) => {
                match r {
                    Ok(Some(frame)) => {
                        crate::relay::route_packet(state.clone(), frame).await;
                    }
                    Ok(None) => {
                        state.log("info", "link", format!("{peer} 正常关闭连接"));
                        break;
                    }
                    Err(e) => {
                        state.log("warn", "link", format!("{peer} 协议错误，拆链: {e}"));
                        break;
                    }
                }
            }
        }
    }

    teardown_link(&state, peer, handle.session_id, "链路关闭").await;
}

/// 拆除一条链路：摘掉链接池、拓扑条目、相关流，并广播。
///
/// `session_id` 是**发起拆除的那条链路**的身份。链路可能已经被别的链路顶替掉了
/// （见 [`register_link`] 里的互拨去重）：那时候它的读任务退出会走到这里，
/// 但**绝不能**把表里接力上来的新链路一起拆掉 —— 那表现为"刚拨通就被拆"的永久抖动，
/// 每次抖动还会连带一次重连与一次 gossip flood。
pub async fn teardown_link(state: &Arc<HiveState>, peer: NodeId, session_id: u64, reason: &str) {
    let current = { state.links.get(&peer).map(|r| r.session_id) };
    if current != Some(session_id) {
        return; // 我已经不是当前那条链路了，什么都不做
    }
    let Some((_, handle)) = state.links.remove(&peer) else { return };
    handle.set_down();
    handle.cancel.cancel();
    state.stats.links.store(state.links.len(), Ordering::Relaxed);

    {
        let mut topo = state.topology.write();
        topo.lose_peer(peer);
    }
    state.rebuild_router();
    state.refresh_aliases();

    state.emit(HiveEvent::PeerDown { peer, reason: reason.to_string() });
    state.log("warn", "link", format!("{peer} 链路断开（{reason}）"));

    // 钉在这条下一跳上的流必须重置（§5.5）
    crate::stream::fail_all_streams_via(state, peer, reason).await;

    // 链路变化 → 立即变化驱动 flood
    crate::gossip::broadcast_now(state, true).await;
    state.emit_topology();
}

/// 便捷：把 `listen_ports` 与配置做对齐自检，返回告警文案（§6.2.3）。
pub fn port_alignment_warning(configured_ports: &[u16], remote_listen: &[u16], remote: NodeId) -> Option<String> {
    if remote_listen.is_empty() || configured_ports.is_empty() {
        return None;
    }
    let bad: Vec<u16> = configured_ports
        .iter()
        .copied()
        .filter(|p| !remote_listen.contains(p))
        .collect();
    if bad.is_empty() {
        None
    } else {
        Some(format!(
            "你配置的 seed 端口 {bad:?} 不在 {remote} 的监听列表 {remote_listen:?} 里 —— 这条防火墙授权可能没对齐（§6.2.3）"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::nid;

    #[test]
    fn auth_is_symmetric_when_tokens_match() {
        let token = "s3cret";
        let na = [1u8; 16];
        let nb = [2u8; 16];
        let a = nid("10.0.0.1");
        let b = nid("10.0.0.2");

        let ha = hello_auth(token, &na, a);
        // 对端用同样的输入能算出同一个值
        assert_eq!(ha, hello_auth(token, &na, a));
        // 换个 token 就不对了
        assert_ne!(ha, hello_auth("other", &na, a));

        let aa = ack_auth(token, &na, &nb, a, b);
        assert_eq!(aa, ack_auth(token, &na, &nb, a, b));
        assert_ne!(aa, ack_auth(token, &na, &nb, b, a), "地址顺序变了值也必须变");
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(&[1u8; 32], &[1u8; 32]));
        let mut b = [1u8; 32];
        b[31] = 2;
        assert!(!constant_time_eq(&[1u8; 32], &b));
    }

    #[test]
    fn mutual_dial_dedup_picks_a_stable_winner() {
        let small = nid("10.0.0.1");
        let big = nid("10.0.0.2");
        // 小的一方保留自己的出站
        assert!(decide_keep(small, big, true, false));
        assert!(!decide_keep(small, big, false, true));
        // 大的一方保留自己的入站（即让步）
        assert!(!decide_keep(big, small, true, false));
        assert!(decide_keep(big, small, false, true));
        // 同向重复（多拨了一次）：保留既有的 —— 返回值 true = "把新来的那条丢掉"。
        // 早先这里返回 false（于是新链路把旧链路顶掉），而被顶掉的那条**不会被拆**：
        // 每次重复拨号漏一条 socket（连它的读写任务），见 tests/link_lifecycle.rs。
        assert!(decide_keep(small, big, true, true));
        assert!(decide_keep(big, small, true, true));
        assert!(decide_keep(big, small, false, false));
    }

    #[test]
    fn port_alignment_warning_detects_mismatch() {
        let peer = nid("10.1.2.5");
        assert!(port_alignment_warning(&[20000], &[20000], peer).is_none());
        let w = port_alignment_warning(&[20000], &[5678], peer).expect("应当告警");
        assert!(w.contains("20000"));
        assert!(port_alignment_warning(&[], &[5678], peer).is_none());
    }

    #[tokio::test]
    async fn real_handshake_over_loopback_succeeds() {
        let mut cfg_a = crate::config::Config::default();
        cfg_a.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg_a.listen.bind = "127.0.0.1".parse().unwrap();
        cfg_a.listen.ports = vec![20001];
        let id_a = Arc::new(crate::identity::NodeIdentity::resolve(&cfg_a).unwrap());
        let a = HiveState::new(id_a, cfg_a);

        let mut cfg_b = crate::config::Config::default();
        cfg_b.node.overlay_addr = Some("127.0.0.2".parse().unwrap());
        cfg_b.listen.bind = "127.0.0.2".parse().unwrap();
        cfg_b.listen.ports = vec![20002];
        let id_b = Arc::new(crate::identity::NodeIdentity::resolve(&cfg_b).unwrap());
        let b = HiveState::new(id_b, cfg_b);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let b2 = b.clone();
        tokio::spawn(async move {
            let (stream, remote) = listener.accept().await.unwrap();
            accept_and_handshake(&b2, stream, remote).await.unwrap()
        });

        let est = dial_and_handshake(&a, addr).await.expect("握手应当成功");
        assert_eq!(est.peer, nid("127.0.0.2"));
        // 被拨方把自己的监听端口回给了拨入方（§6.2.3 的对齐自检依据）
        assert_eq!(est.listen_ports, vec![20002]);
    }

    #[tokio::test]
    async fn handshake_fails_against_a_non_hiveproxy_service() {
        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        let id = Arc::new(crate::identity::NodeIdentity::resolve(&cfg).unwrap());
        let st = HiveState::new(id, cfg);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let e = dial_and_handshake(&st, addr).await.unwrap_err();
        assert!(
            matches!(e, HandshakeError::Proto(ProtoError::BadVersion(5))),
            "HTTP 的首字节 'H' 与 magic 相同，真正拦下它的是版本位；实际 {e:?}"
        );
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_join_token() {
        let mut cfg_a = crate::config::Config::default();
        cfg_a.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg_a.security.join_token = "correct".into();
        let id_a = Arc::new(crate::identity::NodeIdentity::resolve(&cfg_a).unwrap());
        let a = HiveState::new(id_a, cfg_a);

        let mut cfg_b = crate::config::Config::default();
        cfg_b.node.overlay_addr = Some("127.0.0.2".parse().unwrap());
        cfg_b.security.join_token = "wrong".into();
        let id_b = Arc::new(crate::identity::NodeIdentity::resolve(&cfg_b).unwrap());
        let b = HiveState::new(id_b, cfg_b);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, remote) = listener.accept().await.unwrap();
            let _ = accept_and_handshake(&b, stream, remote).await;
        });

        let e = dial_and_handshake(&a, addr).await.unwrap_err();
        assert!(
            matches!(e, HandshakeError::Rejected(RejectReason::AuthFailed)),
            "令牌不符时被拨方应当明确回 Reject(AuthFailed)，而不是静默断开；实际 {e:?}"
        );
    }

    #[tokio::test]
    async fn matching_join_token_handshakes_fine() {
        let mut cfg_a = crate::config::Config::default();
        cfg_a.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg_a.security.join_token = "same".into();
        let id_a = Arc::new(crate::identity::NodeIdentity::resolve(&cfg_a).unwrap());
        let a = HiveState::new(id_a, cfg_a);

        let mut cfg_b = crate::config::Config::default();
        cfg_b.node.overlay_addr = Some("127.0.0.2".parse().unwrap());
        cfg_b.listen.ports = vec![20003];
        cfg_b.security.join_token = "same".into();
        let id_b = Arc::new(crate::identity::NodeIdentity::resolve(&cfg_b).unwrap());
        let b = HiveState::new(id_b, cfg_b);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, remote) = listener.accept().await.unwrap();
            let _ = accept_and_handshake(&b, stream, remote).await;
        });

        let est = dial_and_handshake(&a, addr).await.expect("同令牌应当握手成功");
        assert_eq!(est.peer, nid("127.0.0.2"));
    }
}
