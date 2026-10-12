//! 流生命周期与数据泵（DESIGN.md §6.4、§5.5）。
//!
//! - **发起方**（SOCKS5 侧）：`open_stream` → 等 `StreamAck` → 用 `pump_local_to_overlay`
//!   与 `pump_overlay_to_local` 双向搬运；
//! - **出口方**：`handle_stream_open` 在本地 `TcpStream::connect`（**域名在这里解析**，§9.4.2）
//!   → 回 `StreamAck` → 起同样的两个泵。
//!
//! 两侧的泵完全对称，所以只有一份实现。

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::events::now_unix;
use crate::link::{OutboundFrame, STREAM_WINDOW};
use crate::msg::control_frame_stream;
use crate::proto::{
    decode_payload, CloseReason, Endpoint, HiveHeader, Host, MsgType, NodeId, Proto, RawFrame,
    StreamAckMsg, StreamCloseMsg, StreamKey, StreamOpenMsg, StreamState, WindowUpdateMsg,
    MAX_FRAME_PAYLOAD,
};
use crate::session::{StreamCtx, StreamRole};
use crate::state::HiveState;

/// 出口侧连接目标的超时。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum OpenError {
    /// 调用方应当走本地直连（目标就是本机网段且 SELF 胜出）。
    SelfLoop,
    /// 无路由到出口节点。
    NoRoute,
    /// 被规则拒绝。
    Refused,
    /// 出口在超时内没有回应。
    Timeout,
    /// 出口明确拒绝。
    Rejected { code: u16, reason: String },
}

/// 一条打开好的 overlay 流。
pub struct OpenedStream {
    pub ctx: Arc<StreamCtx>,
    /// 从 overlay 收到的字节 —— 调用方负责写进本地 socket，
    /// 并用 [`pump_overlay_to_local`] 顺带回收信用。
    pub sink: mpsc::Receiver<Bytes>,
}

/// 求下一跳。
fn hop_toward(state: &Arc<HiveState>, dst: NodeId) -> Option<NodeId> {
    if state.links.contains_key(&dst) {
        return Some(dst);
    }
    state.router.read().next_hop(dst).map(|r| r.next_hop)
}

// ---------------------------------------------------------------------------
// 发起方
// ---------------------------------------------------------------------------

/// 打开一条流（SOCKS5 侧调用）。
pub async fn open_stream(
    state: Arc<HiveState>,
    target: Endpoint,
    egress_node: NodeId,
    matched_rule: Option<usize>,
) -> Result<OpenedStream, OpenError> {
    if egress_node == state.self_id() {
        return Err(OpenError::SelfLoop);
    }
    let hop = hop_toward(&state, egress_node).ok_or(OpenError::NoRoute)?;
    let stream_id = state.alloc_stream_id();
    let key = StreamKey(egress_node, stream_id);

    let (sink_tx, sink_rx) = mpsc::channel(STREAM_WINDOW as usize);
    let out = state.stream_queue(hop, stream_id).ok_or(OpenError::NoRoute)?;

    let ctx = Arc::new(StreamCtx::new(
        key,
        target.clone(),
        egress_node,
        hop,
        StreamRole::Origin,
        matched_rule,
        sink_tx,
        out,
    ));
    state.streams.insert(key, ctx.clone());
    state.stats.active_streams.store(state.streams.len(), Ordering::Relaxed);

    let (ack_tx, ack_rx) = oneshot::channel();
    state.pending_opens.insert(stream_id, ack_tx);

    let msg = StreamOpenMsg {
        endpoint: target.clone(),
        proto: Proto::Tcp,
        flags: 0,
        e2e_pk: None,
    };
    let frame = match control_frame_stream(&state, MsgType::StreamOpen, egress_node, stream_id, &msg)
    {
        Ok(f) => f,
        Err(e) => {
            cleanup(&state, hop, key, stream_id).await;
            state.log("error", "stream", format!("StreamOpen 编码失败: {e}"));
            return Err(OpenError::NoRoute);
        }
    };
    if state.send_control_routed(egress_node, frame).is_err() {
        cleanup(&state, hop, key, stream_id).await;
        return Err(OpenError::NoRoute);
    }

    let cfg = state.cfg();
    let timeout = Duration::from_millis(cfg.egress.egress_ack_timeout_ms.max(100));
    match tokio::time::timeout(timeout, ack_rx).await {
        Ok(Ok(ack)) if ack.ok => {
            ctx.set_state(StreamState::Open);
            record_rule_hit(&state, matched_rule, egress_node);
            state.emit(crate::events::HiveEvent::StreamOpened {
                peer: egress_node,
                stream_id,
                target: target.to_string(),
                egress: egress_node,
                direct: false,
                matched_rule,
            });
            Ok(OpenedStream { ctx, sink: sink_rx })
        }
        Ok(Ok(ack)) => {
            cleanup(&state, hop, key, stream_id).await;
            record_rule_reject(&state, matched_rule);
            Err(OpenError::Rejected { code: ack.code, reason: ack.reason })
        }
        Ok(Err(_)) => {
            cleanup(&state, hop, key, stream_id).await;
            Err(OpenError::Rejected { code: 0, reason: "出口未响应".into() })
        }
        Err(_) => {
            cleanup(&state, hop, key, stream_id).await;
            Err(OpenError::Timeout)
        }
    }
}

fn record_rule_hit(state: &Arc<HiveState>, rule: Option<usize>, egress: NodeId) {
    if let Some(i) = rule {
        state.rule_hits.record_hit(i, egress, now_unix());
    }
}

fn record_rule_reject(state: &Arc<HiveState>, rule: Option<usize>) {
    if let Some(i) = rule {
        state.rule_hits.record_rejected(i, now_unix());
    }
}

pub fn handle_stream_ack(state: &Arc<HiveState>, stream_id: u64, msg: StreamAckMsg) {
    if let Some((_, tx)) = state.pending_opens.remove(&stream_id) {
        let _ = tx.send(msg);
    }
}

// ---------------------------------------------------------------------------
// 出口方
// ---------------------------------------------------------------------------

/// 处理 `StreamOpen`：在本节点发起真实连接（§6.4）。
pub async fn handle_stream_open(state: Arc<HiveState>, frame: RawFrame) {
    let origin = frame.header.src;
    let stream_id = frame.header.stream_id;
    let Ok(msg) = decode_payload::<StreamOpenMsg>(frame.payload()) else { return };
    let cfg = state.cfg();

    // 安全边界：不允许做出口时直接拒绝（§9.4.4）
    if !cfg.egress.allow_egress {
        send_ack(&state, origin, stream_id, false, 3, "本节点不参与出口候选").await;
        return;
    }

    // ★ 域名在这里解析 —— split-horizon DNS 意味着调用方解析会走错路（§9.4.2）
    let addr = match resolve_endpoint(&msg.endpoint).await {
        Ok(a) => a,
        Err(e) => {
            send_ack(&state, origin, stream_id, false, 4, &format!("域名解析失败: {e}")).await;
            return;
        }
    };

    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            send_ack(&state, origin, stream_id, false, 5, &format!("连接被拒: {e}")).await;
            return;
        }
        Err(_) => {
            send_ack(&state, origin, stream_id, false, 6, "连接超时").await;
            return;
        }
    };

    let key = StreamKey(origin, stream_id);
    let Some(hop) = hop_toward(&state, origin) else {
        send_ack(&state, origin, stream_id, false, 3, "无法回程到发起方").await;
        return;
    };

    let (sink_tx, sink_rx) = mpsc::channel(STREAM_WINDOW as usize);
    let Some(out) = state.stream_queue(hop, stream_id) else {
        send_ack(&state, origin, stream_id, false, 3, "下一跳不可用").await;
        return;
    };

    let ctx = Arc::new(StreamCtx::new(
        key,
        msg.endpoint.clone(),
        state.self_id(),
        hop,
        StreamRole::Egress,
        None,
        sink_tx,
        out,
    ));
    ctx.set_state(StreamState::Open);
    state.streams.insert(key, ctx.clone());
    state.stats.active_streams.store(state.streams.len(), Ordering::Relaxed);

    send_ack(&state, origin, stream_id, true, 0, "").await;
    state.emit(crate::events::HiveEvent::StreamOpened {
        peer: origin,
        stream_id,
        target: msg.endpoint.to_string(),
        egress: state.self_id(),
        direct: true,
        matched_rule: None,
    });

    // 两个泵：本地 TCP ⇄ overlay
    let (rd, wr) = tcp.into_split();
    let st1 = state.clone();
    let ctx1 = ctx.clone();
    tokio::spawn(async move {
        pump_local_to_overlay(st1.clone(), ctx1.clone(), rd).await;
        close_stream(&st1, key, CloseReason::Normal).await;
    });
    let st2 = state.clone();
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        pump_overlay_to_local(st2.clone(), ctx2, sink_rx, wr).await;
    });
}

async fn resolve_endpoint(ep: &Endpoint) -> Result<std::net::SocketAddr, String> {
    match &ep.host {
        Host::Ip(ip) => Ok(std::net::SocketAddr::new(*ip, ep.port)),
        Host::Name(name) => {
            let mut it = tokio::net::lookup_host((name.as_str(), ep.port))
                .await
                .map_err(|e| e.to_string())?;
            it.next().ok_or_else(|| format!("{name} 无解析结果"))
        }
    }
}

async fn send_ack(
    state: &Arc<HiveState>,
    dst: NodeId,
    stream_id: u64,
    ok: bool,
    code: u16,
    reason: &str,
) {
    let msg = StreamAckMsg { ok, code, reason: reason.to_string() };
    if let Ok(f) = control_frame_stream(state, MsgType::StreamAck, dst, stream_id, &msg) {
        let _ = state.send_control_routed(dst, f);
    }
}

// ---------------------------------------------------------------------------
// 数据面
// ---------------------------------------------------------------------------

/// 本地读到字节 → overlay（§5.5 的发送侧）。
pub async fn pump_local_to_overlay<R: AsyncRead + Unpin>(
    state: Arc<HiveState>,
    ctx: Arc<StreamCtx>,
    mut r: R,
) {
    let ttl = state.cfg().route.ttl_default;
    let dst = ctx.key.0;

    loop {
        if ctx.closed() || state.shutdown.is_cancelled() {
            break;
        }

        // 信用耗尽就停下来等 WindowUpdate（§5.5）
        if !ctx.has_credit() {
            tokio::select! {
                _ = ctx.credit_notify.notified() => continue,
                _ = state.shutdown.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
            }
        }

        let mut buf = BytesMut::with_capacity(64 * 1024);
        let n = match r.read_buf(&mut buf).await {
            Ok(0) => break, // 本地端关闭
            Ok(n) => n,
            Err(e) => {
                tracing::debug!("local read end: {e}");
                break;
            }
        };

        if !ctx.take_credit() {
            continue; // 竞态：重新等
        }

        let take = n.min(MAX_FRAME_PAYLOAD as usize);
        let payload = buf.split_to(take).freeze();
        let header = HiveHeader::new(MsgType::Data, state.self_id(), dst, ttl)
            .with_stream(ctx.key.1);
        let frame = OutboundFrame::new(header, payload);

        if ctx.out.send(frame).await.is_err() {
            close_stream(&state, ctx.key, CloseReason::Reset).await;
            break;
        }
        ctx.bytes_from_local.fetch_add(take as u64, Ordering::Relaxed);
        state.stats.bytes_relayed_out.fetch_add(take as u64, Ordering::Relaxed);
    }
}

/// overlay 收到字节 → 本地（§5.5 的接收侧，负责回收信用）。
pub async fn pump_overlay_to_local<W: AsyncWrite + Unpin>(
    state: Arc<HiveState>,
    ctx: Arc<StreamCtx>,
    mut sink: mpsc::Receiver<Bytes>,
    mut w: W,
) {
    while let Some(chunk) = sink.recv().await {
        if ctx.closed() {
            break;
        }
        let len = chunk.len();
        if w.write_all(&chunk).await.is_err() {
            close_stream(&state, ctx.key, CloseReason::Reset).await;
            break;
        }
        ctx.bytes_to_local.fetch_add(len as u64, Ordering::Relaxed);
        state.stats.bytes_relayed_in.fetch_add(len as u64, Ordering::Relaxed);

        // 回收信用，攒够一批回 WindowUpdate（§5.5）
        if let Some(credit) = ctx.on_frame_consumed() {
            let msg = WindowUpdateMsg { stream_id: ctx.key.1, credit };
            if let Ok(f) = control_frame_stream(&state, MsgType::WindowUpdate, ctx.key.0, ctx.key.1, &msg)
            {
                let _ = state.send_control_routed(ctx.key.0, f);
            }
        }
    }
    let _ = w.shutdown().await;
}

/// 收到属于本机某条流的数据帧。
pub async fn deliver_data(state: &Arc<HiveState>, src: NodeId, stream_id: u64, payload: Bytes) {
    let key = StreamKey(src, stream_id);
    let Some(ctx) = state.streams.get(&key).map(|r| r.value().clone()) else {
        // 未知流：让对方收尾（§8）
        let msg = StreamCloseMsg { stream_id, reason: CloseReason::UnknownStream };
        if let Ok(f) = control_frame_stream(state, MsgType::StreamClose, src, stream_id, &msg) {
            let _ = state.send_control_routed(src, f);
        }
        return;
    };

    if ctx.closed() {
        return;
    }

    // 超出窗口 → 对端不守信用或实现有 bug：丢帧并关流，绝不静默跳过（§5.5）
    if !ctx.on_frame_received() {
        state.stats.streams_dropped.fetch_add(1, Ordering::Relaxed);
        state.log("warn", "stream", format!(
            "流 {stream_id} 收到超出信用窗口的帧，已关闭该流（对端未守信用）"
        ));
        close_stream(state, key, CloseReason::Overflow).await;
        return;
    }

    if ctx.sink.try_send(payload).is_err() {
        state.stats.streams_dropped.fetch_add(1, Ordering::Relaxed);
        close_stream(state, key, CloseReason::Overflow).await;
    }
}

pub fn handle_window_update(state: &Arc<HiveState>, src: NodeId, msg: WindowUpdateMsg) {
    let key = StreamKey(src, msg.stream_id);
    if let Some(ctx) = state.streams.get(&key).map(|r| r.value().clone()) {
        ctx.set_credit(msg.credit);
    }
}

pub async fn handle_stream_close(state: &Arc<HiveState>, src: NodeId, msg: StreamCloseMsg) {
    let key = StreamKey(src, msg.stream_id);
    close_stream(state, key, msg.reason).await;
}

/// 关闭一条流：摘掉上下文与队列，唤醒所有等待者。
pub async fn close_stream(state: &Arc<HiveState>, key: StreamKey, reason: CloseReason) {
    let Some((_, ctx)) = state.streams.remove(&key) else { return };
    state.stats.active_streams.store(state.streams.len(), Ordering::Relaxed);
    ctx.set_state(StreamState::Closed);
    state.drop_stream_queue(ctx.hop, key.1);
    ctx.credit_notify.notify_waiters();

    state.emit(crate::events::HiveEvent::StreamClosed {
        peer: key.0,
        stream_id: key.1,
        bytes_in: ctx.bytes_from_local.load(Ordering::Relaxed),
        bytes_out: ctx.bytes_to_local.load(Ordering::Relaxed),
        reason: format!("{reason:?}"),
    });

    // 通知对端收尾（除非是对方发起的关闭）
    if !matches!(reason, CloseReason::UnknownStream) {
        let msg = StreamCloseMsg { stream_id: key.1, reason };
        if let Ok(f) = control_frame_stream(state, MsgType::StreamClose, key.0, key.1, &msg) {
            let _ = state.send_control_routed(key.0, f);
        }
    }
}

/// 某条链路失效：所有**钉在该下一跳**上的流立即以 `Reset` 关闭。
///
/// 帧头没有流内序号，静默换路会造成无法检测的丢帧 —— 等价于静默数据损坏，
/// 所以这里选择让应用层重试（§5.5、§17 风险 16）。
pub async fn fail_all_streams_via(state: &Arc<HiveState>, hop: NodeId, reason: &str) {
    let victims: Vec<StreamKey> = state
        .streams
        .iter()
        .filter(|kv| kv.value().hop == hop)
        .map(|kv| *kv.key())
        .collect();
    for k in &victims {
        if let Some(ctx) = state.streams.get(k).map(|r| r.value().clone()) {
            ctx.reset_due_to_link_loss.store(true, Ordering::Relaxed);
        }
    }
    if !victims.is_empty() {
        state.log("warn", "stream", format!(
            "下一跳 {hop} 失效（{reason}），{} 条流被重置",
            victims.len()
        ));
    }
    for k in victims {
        close_stream(state, k, CloseReason::Reset).await;
    }
}

async fn cleanup(state: &Arc<HiveState>, hop: NodeId, key: StreamKey, stream_id: u64) {
    state.pending_opens.remove(&stream_id);
    state.streams.remove(&key);
    state.drop_stream_queue(hop, stream_id);
}


#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
