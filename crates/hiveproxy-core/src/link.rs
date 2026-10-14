//! L1 链路层：链路句柄、控制优先车道、**每流有界队列 + 轮转写出**的公平调度器。
//!
//! 这是 DESIGN.md §5.5 的实现。要点：
//! - 数据帧走**每流独立的有界队列**（容量 = 信用窗口），`try_send` 不阻塞读任务；
//! - 控制帧走**容量很小的优先车道**，用 `await` 写入 —— 这是唯一允许阻塞的地方；
//! - 写出任务对数据队列做轮转（round-robin），一条流不会饿死别的流。

use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;

use crate::proto::{HiveHeader, LinkMeta, NodeId};
use crate::stats::Stats;

/// 控制优先车道容量（§5.5）。
pub const CONTROL_LANE_CAPACITY: usize = 64;
/// 数据队列容量 = 信用窗口（§5.5）。
pub const STREAM_WINDOW: u32 = 32;

/// 待发送的一帧。
#[derive(Clone, Debug)]
pub struct OutboundFrame {
    pub header: HiveHeader,
    pub payload: Bytes,
}

impl OutboundFrame {
    pub fn new(header: HiveHeader, payload: Bytes) -> Self {
        Self { header, payload }
    }

    /// 组装成「48 字节头 + 载荷」的连续缓冲（§5.6）。
    pub fn encode(&self) -> bytes::BytesMut {
        let mut h = self.header;
        h.payload_len = self.payload.len() as u32;
        let mut buf = bytes::BytesMut::with_capacity(crate::proto::HEADER_LEN + self.payload.len());
        h.encode_into(&mut buf);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn size(&self) -> usize {
        crate::proto::HEADER_LEN + self.payload.len()
    }
}

pub(crate) enum WriterCmd {
    Register { id: u64, rx: mpsc::Receiver<OutboundFrame> },
    Unregister { id: u64 },
}

fn apply_register(
    id: u64,
    rx: mpsc::Receiver<OutboundFrame>,
    streams: &mut Vec<(u64, mpsc::Receiver<OutboundFrame>)>,
) {
    if let Some(slot) = streams.iter_mut().find(|(i, _)| *i == id) {
        slot.1 = rx;
    } else {
        streams.push((id, rx));
    }
}

/// 写一块字节；**被取消时立刻放弃这次写**。
///
/// 对端死了而内核没发 RST 时，`write_all` 会一直卡在"发送缓冲满"上 —— 那一刻
/// 取消令牌是唯一还能叫醒它的东西。少了这一步，拆链之后这条 socket 仍然带着满缓冲
/// 挂在系统里（"长时间运行后 socket 缓冲被吃光"的一种形态）。
async fn write_or_cancel<W: AsyncWrite + Unpin>(
    w: &mut W,
    bytes: &[u8],
    cancel: &CancellationToken,
) -> bool {
    tokio::select! {
        r = w.write_all(bytes) => r.is_ok(),
        _ = cancel.cancelled() => false,
    }
}

/// 注销一条流，但**先把已经入队的帧全部写完**。
///
/// 这一步不能省：调用方通常是"本地读到 EOF → 发完最后一帧 → 关闭流"，
/// 如果注销时直接丢弃队列，每一次半关闭都会丢掉流的尾部数据。
async fn drain_then_unregister<W: AsyncWrite + Unpin>(
    id: u64,
    streams: &mut Vec<(u64, mpsc::Receiver<OutboundFrame>)>,
    w: &mut W,
    cancel: &CancellationToken,
) -> bool {
    let Some(pos) = streams.iter().position(|(i, _)| *i == id) else {
        return true;
    };
    let (_, mut rx) = streams.remove(pos);
    loop {
        match rx.try_recv() {
            Ok(f) => {
                if !write_or_cancel(w, &f.encode(), cancel).await {
                    return false;
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
        }
    }
    true
}

/// 写出任务：控制车道优先 + 数据队列轮转。
pub(crate) async fn link_writer_task<W: AsyncWrite + Unpin>(
    mut w: W,
    mut control: mpsc::Receiver<OutboundFrame>,
    mut cmd: mpsc::UnboundedReceiver<WriterCmd>,
    notify: Arc<Notify>,
    cancel: CancellationToken,
) {
    let mut streams: Vec<(u64, mpsc::Receiver<OutboundFrame>)> = Vec::new();
    let mut rr = 0usize;
    let mut pending: Vec<WriterCmd> = Vec::new();

    loop {
        // 1. 收取注册/注销命令（注销要先把队列写空，所以放在这里而不是独立函数里）
        let mut cmds: Vec<WriterCmd> = pending.drain(..).collect();
        while let Ok(c) = cmd.try_recv() {
            cmds.push(c);
        }
        for c in cmds {
            match c {
                WriterCmd::Register { id, rx } => apply_register(id, rx, &mut streams),
                WriterCmd::Unregister { id } => {
                    if !drain_then_unregister(id, &mut streams, &mut w, &cancel).await {
                        cancel.cancel();
                        return;
                    }
                }
            }
        }

        let mut wrote_any = false;

        // 2. 控制优先车道：永远先写
        loop {
            match control.try_recv() {
                Ok(f) => {
                    if !write_or_cancel(&mut w, &f.encode(), &cancel).await {
                        cancel.cancel();
                        return;
                    }
                    wrote_any = true;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        }

        // 3. 数据队列：轮转，每流最多取一帧
        if !streams.is_empty() {
            let rounds = streams.len();
            for _ in 0..rounds {
                if streams.is_empty() {
                    break;
                }
                rr %= streams.len();
                let mut drop_id = None;
                match streams[rr].1.try_recv() {
                    Ok(f) => {
                        if !write_or_cancel(&mut w, &f.encode(), &cancel).await {
                            cancel.cancel();
                            return;
                        }
                        wrote_any = true;
                        rr += 1;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => rr += 1,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        drop_id = Some(streams[rr].0);
                    }
                }
                if let Some(id) = drop_id {
                    streams.retain(|(i, _)| *i != id);
                }
            }
        }

        // 4. 本轮没写出任何东西 → 等事件
        if !wrote_any {
            tokio::select! {
                _ = cancel.cancelled() => break,
                r = cmd.recv() => match r {
                    Some(c) => pending.push(c),
                    None => break,
                },
                r = control.recv() => match r {
                    Some(f) => {
                        if !write_or_cancel(&mut w, &f.encode(), &cancel).await {
                            cancel.cancel();
                            break;
                        }
                    }
                    None => break,
                },
                // 生产者推入数据后会 notify —— 没有丢唤醒（Notify 会存一个 permit）
                _ = notify.notified() => {}
            }
        }
    }

    if let Err(e) = w.shutdown().await {
        tracing::debug!("link writer shutdown: {e}");
    }
}

/// 一条流在某条链路上的数据队列发送端。
///
/// 包装 `mpsc::Sender` 的唯一目的：**推入后唤醒写出任务**。
/// 写出任务在空闲时只 select 在控制车道/注册命令/`Notify` 上，
/// 不会轮询每条流的队列 —— 所以生产者必须主动叫醒它。
#[derive(Clone)]
pub struct StreamSender {
    tx: mpsc::Sender<OutboundFrame>,
    notify: Arc<Notify>,
}

impl StreamSender {
    pub fn new(tx: mpsc::Sender<OutboundFrame>, notify: Arc<Notify>) -> Self {
        Self { tx, notify }
    }

    pub async fn send(&self, f: OutboundFrame) -> Result<(), ()> {
        let r = self.tx.send(f).await.map_err(|_| ());
        self.notify.notify_one();
        r
    }

    pub fn try_send(
        &self,
        f: OutboundFrame,
    ) -> Result<(), mpsc::error::TrySendError<OutboundFrame>> {
        let r = self.tx.try_send(f);
        self.notify.notify_one();
        r
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// 上层用来给某条链路发帧的句柄（可克隆）。
#[derive(Clone)]
pub struct LinkSender {
    control: mpsc::Sender<OutboundFrame>,
    cmd: mpsc::UnboundedSender<WriterCmd>,
    notify: Arc<Notify>,
}

impl LinkSender {
    pub(crate) fn new(
        control: mpsc::Sender<OutboundFrame>,
        cmd: mpsc::UnboundedSender<WriterCmd>,
        notify: Arc<Notify>,
    ) -> Self {
        Self { control, cmd, notify }
    }

    /// 控制帧：低频小帧，允许 `await` 阻塞（§5.5）。
    pub async fn send_control(&self, f: OutboundFrame) -> Result<(), ()> {
        self.control.send(f).await.map_err(|_| ())
    }

    /// 控制帧的非阻塞写入；队列满说明链路已经饱和。
    pub fn try_send_control(&self, f: OutboundFrame) -> Result<(), ()> {
        self.control.try_send(f).map_err(|_| ())
    }

    /// 为一条流登记数据队列；返回的 `StreamSender` 即该流的投递口。
    ///
    /// 队列容量 = 信用窗口，因此"守信用"的发送方永远不会让它溢出（§5.5）。
    pub fn register_stream(&self, id: u64) -> StreamSender {
        let (tx, rx) = mpsc::channel(STREAM_WINDOW as usize);
        let _ = self.cmd.send(WriterCmd::Register { id, rx });
        self.notify.notify_one();
        StreamSender::new(tx, self.notify.clone())
    }

    pub fn unregister_stream(&self, id: u64) {
        let _ = self.cmd.send(WriterCmd::Unregister { id });
    }

    pub fn notify(&self) {
        self.notify.notify_one();
    }
}

/// 组装一条链路的发送侧与写出任务。
///
/// 返回 `(发送句柄, 任务句柄)`；把底层通道的细节挡在外面，调用方不需要知道 `WriterCmd`。
pub fn spawn_link<W: AsyncWrite + Unpin + Send + 'static>(
    w: W,
    cancel: CancellationToken,
) -> (LinkSender, tokio::task::JoinHandle<()>) {
    let (control_tx, control_rx) = mpsc::channel(CONTROL_LANE_CAPACITY);
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let notify = Arc::new(Notify::new());
    let handle = tokio::spawn(link_writer_task(
        w,
        control_rx,
        cmd_rx,
        notify.clone(),
        cancel,
    ));
    (LinkSender::new(control_tx, cmd_tx, notify), handle)
}

/// 心跳账本（§12）：**连续几次 Ping 没等到 Pong**。
///
/// 只数 Ping/Pong，不看数据帧：数据面忙不代表对端还在（比如它不是被压住、
/// 而是真的走了），而 Pong 是对方进程还活着、还能回帧的唯一直接证据。
#[derive(Default, Debug)]
pub struct PingState {
    /// 连续未回应次数（收到 Pong 清零）。
    pub unanswered: u32,
    /// 最近一次 Ping 发出的时刻，用来算 RTT。
    pub last_ping_at: Option<tokio::time::Instant>,
}

/// 一条已建立的链路。
pub struct LinkHandle {
    pub peer: NodeId,
    pub meta: parking_lot::RwLock<LinkMeta>,
    pub cancel: CancellationToken,
    pub sender: LinkSender,
    pub session_id: u64,
    /// 本机是否为拨号方（决定谁负责重连保活，§3.3）。
    pub establisher: crate::proto::Establisher,
    /// 心跳账本（§12）。
    pub ping: parking_lot::Mutex<PingState>,
}

/// RTT 按 10 ms 分桶。
///
/// ★ 不是为了好看：`router::arc_weight` 的惩罚项就是 `rtt_ms / 10`，而拓扑的
/// `same_edges` 会拿 `rtt_ms` 比"边变了没有" —— 每 3 秒抖 1 ms 就等于每 3 秒
/// 一次 `seq += 1` + 一次变化驱动 flood。分桶之后只有真的跨了桶才动。
pub fn bucket_rtt_ms(ms: u64) -> u16 {
    let bucket = ((ms + 5) / 10) * 10;
    bucket.min(u16::MAX as u64) as u16
}

impl LinkHandle {
    pub fn health(&self) -> crate::proto::Health {
        self.meta.read().health
    }

    pub fn rtt_ms(&self) -> u16 {
        self.meta.read().rtt_ms
    }

    pub fn carrier(&self) -> crate::proto::Carrier {
        self.meta.read().carrier
    }

    pub fn set_down(&self) {
        self.meta.write().health = crate::proto::Health::Down;
    }

    /// 拆掉这条链路。
    pub fn close(&self) {
        self.cancel.cancel();
    }

    /// 记一次"Ping 已发出"，返回累计未回应次数。
    pub fn note_ping_sent(&self) -> u32 {
        let mut p = self.ping.lock();
        p.last_ping_at = Some(tokio::time::Instant::now());
        p.unanswered = p.unanswered.saturating_add(1);
        p.unanswered
    }

    /// 记一次"这一轮连 Ping 都没问出去"（控制车道卡住）—— 同样算没回应。
    pub fn note_miss(&self) -> u32 {
        let mut p = self.ping.lock();
        p.unanswered = p.unanswered.saturating_add(1);
        p.unanswered
    }

    /// 收到 `Pong`：清零未回应计数，并把这一趟的 RTT 写进 `meta`。
    ///
    /// 返回 `Some(rtt)` 表示 RTT **跨过了 10 ms 的桶**（调用方据此决定要不要广播）。
    pub fn note_pong(&self) -> Option<u16> {
        let rtt = {
            let mut p = self.ping.lock();
            p.unanswered = 0;
            p.last_ping_at.map(|t| bucket_rtt_ms(t.elapsed().as_millis() as u64))
        };
        let rtt = rtt?;
        let mut meta = self.meta.write();
        if meta.rtt_ms == rtt {
            return None;
        }
        meta.rtt_ms = rtt;
        Some(rtt)
    }

    /// 未回应次数（供界面与测试断言）。
    pub fn unanswered(&self) -> u32 {
        self.ping.lock().unanswered
    }
}

/// 给统计用的辅助：链路数变化。
pub fn note_link(stats: &Stats, delta: isize) {
    if delta > 0 {
        stats.links.fetch_add(delta as usize, Ordering::Relaxed);
    } else {
        let cur = stats.links.load(Ordering::Relaxed);
        stats.links.store(cur.saturating_sub((-delta) as usize), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{read_frame, MsgType, RawFrame};
    use tokio::io::AsyncReadExt;

    fn frame(ty: MsgType, stream: u64, payload: &[u8]) -> OutboundFrame {
        let mut h = HiveHeader::new(
            ty,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            8,
        );
        h.stream_id = stream;
        OutboundFrame::new(h, Bytes::copy_from_slice(payload))
    }

    async fn spawn_writer(
        w: tokio::io::DuplexStream,
    ) -> (LinkSender, CancellationToken) {
        let (control_tx, control_rx) = mpsc::channel(CONTROL_LANE_CAPACITY);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let notify = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        tokio::spawn(link_writer_task(w, control_rx, cmd_rx, notify.clone(), cancel.clone()));
        (LinkSender::new(control_tx, cmd_tx, notify), cancel)
    }

    #[tokio::test]
    async fn control_and_data_frames_reach_the_wire() {
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let (sender, _cancel) = spawn_writer(a).await;

        sender.send_control(frame(MsgType::Ping, 0, b"ping")).await.unwrap();
        let data = sender.register_stream(7);
        data.send(frame(MsgType::Data, 7, b"hello")).await.unwrap();
        sender.notify();

        let f1 = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(f1.header.msg_type, MsgType::Ping);
        assert_eq!(f1.payload(), b"ping");

        let f2 = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(f2.header.stream_id, 7);
        assert_eq!(f2.payload(), b"hello");
    }

    #[tokio::test]
    async fn control_lane_jumps_ahead_of_a_backlogged_data_stream() {
        // §5.5：一条大上传不能把心跳饿死。
        let (a, mut b) = tokio::io::duplex(1024 * 1024);
        let (sender, _cancel) = spawn_writer(a).await;

        let big = sender.register_stream(1);
        for i in 0..8u8 {
            big.send(frame(MsgType::Data, 1, &[i; 1024])).await.unwrap();
        }
        sender.send_control(frame(MsgType::Ping, 0, b"beat")).await.unwrap();
        sender.notify();

        // 第一条读到的必须是控制帧，而不是积压的数据帧
        let first = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(
            first.header.msg_type,
            MsgType::Ping,
            "控制优先车道必须插到积压数据前面"
        );
    }

    #[tokio::test]
    async fn two_streams_are_served_round_robin() {
        let (a, mut b) = tokio::io::duplex(1024 * 1024);
        let (sender, _cancel) = spawn_writer(a).await;

        let s1 = sender.register_stream(1);
        let s2 = sender.register_stream(2);
        for i in 0..4u8 {
            s1.send(frame(MsgType::Data, 1, &[0xAA, i])).await.unwrap();
            s2.send(frame(MsgType::Data, 2, &[0xBB, i])).await.unwrap();
        }
        sender.notify();

        let mut order = Vec::new();
        for _ in 0..8 {
            let f = read_frame(&mut b).await.unwrap().unwrap();
            order.push(f.header.stream_id);
        }
        // 前 4 条应当是交替的（轮转），而不是 1,1,1,1
        assert_eq!(&order[..4], &[1, 2, 1, 2], "多流必须轮转而不是先到先服务：{order:?}");
    }

    #[tokio::test]
    async fn unregister_flushes_queued_frames_before_closing() {
        // ★ 注销一条流时必须**先把已经入队的帧写完**。
        // 调用方通常是"本地读到 EOF → 发完最后一帧 → 关闭流"，
        // 直接丢弃队列会导致每一次半关闭都丢掉流的尾部数据。
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let (sender, _cancel) = spawn_writer(a).await;
        let s1 = sender.register_stream(1);
        s1.send(frame(MsgType::Data, 1, b"x")).await.unwrap();
        sender.notify();
        let f = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(f.payload(), b"x");

        s1.try_send(frame(MsgType::Data, 1, b"tail-1")).unwrap();
        s1.try_send(frame(MsgType::Data, 1, b"tail-2")).unwrap();
        sender.unregister_stream(1);
        sender.send_control(frame(MsgType::Ping, 0, b"after")).await.unwrap();
        sender.notify();

        // 控制帧插到数据前面是设计使然（§5.5 的优先车道）；
        // 这里要保证的真正不变量是：**已入队的尾部数据一帧都不能丢**。
        let mut tails: Vec<Vec<u8>> = Vec::new();
        let mut saw_ping = false;
        for _ in 0..3 {
            let f = read_frame(&mut b).await.unwrap().unwrap();
            match f.header.msg_type {
                MsgType::Data => tails.push(f.payload().to_vec()),
                MsgType::Ping => saw_ping = true,
                other => panic!("意外帧 {other:?}"),
            }
        }
        assert!(tails.contains(&b"tail-1".to_vec()), "尾部第一帧不得丢失");
        assert!(tails.contains(&b"tail-2".to_vec()), "尾部第二帧不得丢失");
        assert!(saw_ping, "控制车道仍然要能写出");
    }

    #[tokio::test]
    async fn backpressure_does_not_block_the_writer_loop() {
        // 一条流的队列满了，另一条流仍然能正常写出（§5.5 流级隔离）。
        let (a, mut b) = tokio::io::duplex(8); // 很小的管道，制造真实背压
        let (sender, _cancel) = spawn_writer(a).await;

        let slow = sender.register_stream(1);
        let fast = sender.register_stream(2);
        // 塞满 slow 的队列（容量 = STREAM_WINDOW）
        let mut filled = 0;
        while slow.try_send(frame(MsgType::Data, 1, &[0u8; 128])).is_ok() {
            filled += 1;
            if filled > STREAM_WINDOW + 4 {
                break;
            }
        }
        assert!(filled > 0);

        // fast 仍然能排进去
        assert!(fast.try_send(frame(MsgType::Data, 2, b"ok")).is_ok(), "另一条流不受影响");
        sender.notify();

        // 排空一些，确认能读到 stream 2 的帧
        let mut seen_stream2 = false;
        for _ in 0..64 {
            match tokio::time::timeout(std::time::Duration::from_millis(300), read_frame(&mut b)).await {
                Ok(Ok(Some(f))) => {
                    if f.header.stream_id == 2 {
                        seen_stream2 = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(seen_stream2, "被压住的流不该让另一条流也发不出去");
    }

    #[tokio::test]
    async fn cancellation_terminates_the_writer() {
        let (a, mut b) = tokio::io::duplex(4096);
        let (sender, cancel) = spawn_writer(a).await;
        let _ = sender.send_control(frame(MsgType::Ping, 0, b"x")).await;
        cancel.cancel();
        // 取消后 writer 会 shutdown 写半边 → 读端先读到已写内容，然后 EOF
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), b.read_to_end(&mut buf)).await;
    }

    #[test]
    fn encode_sets_payload_len() {
        let f = frame(MsgType::Data, 3, b"abc");
        let raw = f.encode();
        let parsed = RawFrame { header: crate::proto::HiveHeader::decode(&raw[..48]).unwrap(), raw };
        assert_eq!(parsed.header.payload_len, 3);
        assert_eq!(parsed.payload(), b"abc");
    }
}
