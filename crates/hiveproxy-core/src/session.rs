//! L4 会话层：流上下文、流级信用、半关闭（DESIGN.md §5.5、§6.4）。
//!
//! ## 信用模型
//!
//! 信用是**端到端、按流**的，由**接收侧**生成：
//! - 每侧维护 `allowed`（对端还能发多少帧给我），初始 = 窗口；
//! - 每收到一帧 → `allowed -= 1`；
//! - 每把一帧写进本地 socket → `allowed += 1`，攒够一批再回 `WindowUpdate{绝对信用值}`；
//! - 发送侧 `send_credit` 同理，收到 `WindowUpdate` 时直接**赋值**（绝对值语义，
//!   乱序/丢包都不会造成信用漂移）。
//!
//! ## 路径切换
//!
//! 帧头**没有流内序号**，因此本实现采取比 §5.5 更保守也更安全的做法：
//! **一条流一旦建立就钉死它的下一跳，绝不中途改路。** 下一跳链路失效时，该流立即以
//! `Reset` 关闭（让应用重试），而不是静默换一条路 —— 换路会丢帧，而没有序号就无法
//! 检测缺口，静默丢帧等同于静默数据损坏。

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::{mpsc, Notify};

use crate::link::{StreamSender, STREAM_WINDOW};
use crate::proto::{Endpoint, NodeId, StreamKey, StreamState};

/// 攒够多少帧的信用变化才回一次 `WindowUpdate`（§5.5 的"批量回"）。
pub const WINDOW_UPDATE_BATCH: u32 = STREAM_WINDOW / 4;

/// 本节点在这条流里的角色。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamRole {
    /// 发起方（SOCKS5 那侧）。
    Origin,
    /// 出口方（在本地发起 TCP 连接那侧）。
    Egress,
}

pub struct StreamCtx {
    pub key: StreamKey,
    pub target: Endpoint,
    /// 最终目的节点。
    pub egress: NodeId,
    /// **钉死**的下一跳，永不中途改变（见模块文档）。
    pub hop: NodeId,
    pub role: StreamRole,
    pub matched_rule: Option<usize>,
    pub opened_at: Instant,

    pub state: AtomicU8,
    /// 从本地读入并送进 overlay 的字节数。
    pub bytes_from_local: AtomicU64,
    /// 从 overlay 收到并写进本地的字节数。
    pub bytes_to_local: AtomicU64,

    /// 收到的帧 → 本地 socket 写泵。
    pub sink: mpsc::Sender<Bytes>,
    /// 本地读到的帧 → overlay（已登记在 `hop` 那条链路的流队列上）。
    pub out: StreamSender,

    /// 本方向还能发多少帧（绝对信用值）。
    pub send_credit: AtomicU32,
    /// 对端还能发多少帧给我。
    pub allowed: AtomicU32,
    /// 自上次 `WindowUpdate` 以来攒下的信用增量。
    pub pending_ack: AtomicU32,
    /// 信用变化唤醒读泵。
    pub credit_notify: Notify,

    pub dropped: AtomicU64,
    /// 是否因为链路失效而被迫中断（用于告警，§17 风险 16）。
    pub reset_due_to_link_loss: AtomicBool,
}

impl StreamCtx {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: StreamKey,
        target: Endpoint,
        egress: NodeId,
        hop: NodeId,
        role: StreamRole,
        matched_rule: Option<usize>,
        sink: mpsc::Sender<Bytes>,
        out: StreamSender,
    ) -> Self {
        Self {
            key,
            target,
            egress,
            hop,
            role,
            matched_rule,
            opened_at: Instant::now(),
            state: AtomicU8::new(StreamState::Opening as u8),
            bytes_from_local: AtomicU64::new(0),
            bytes_to_local: AtomicU64::new(0),
            sink,
            out,
            send_credit: AtomicU32::new(STREAM_WINDOW),
            allowed: AtomicU32::new(STREAM_WINDOW),
            pending_ack: AtomicU32::new(0),
            credit_notify: Notify::new(),
            dropped: AtomicU64::new(0),
            reset_due_to_link_loss: AtomicBool::new(false),
        }
    }

    pub fn state(&self) -> StreamState {
        match self.state.load(Ordering::Relaxed) {
            0 => StreamState::Opening,
            1 => StreamState::Open,
            2 => StreamState::HalfClosedLocal,
            3 => StreamState::HalfClosedRemote,
            _ => StreamState::Closed,
        }
    }

    pub fn set_state(&self, s: StreamState) {
        self.state.store(s as u8, Ordering::Relaxed);
    }

    pub fn closed(&self) -> bool {
        self.state() == StreamState::Closed
    }

    /// 发送侧：能否再发一帧。
    pub fn has_credit(&self) -> bool {
        self.send_credit.load(Ordering::Acquire) > 0
    }

    /// 发送侧：占用一格信用。返回是否成功（信用耗尽即失败，调用方应当回去等）。
    pub fn take_credit(&self) -> bool {
        let mut cur = self.send_credit.load(Ordering::Acquire);
        loop {
            if cur == 0 {
                return false;
            }
            match self.send_credit.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }

    /// 收到 `WindowUpdate`：**赋值**而不是累加（绝对信用语义）。
    pub fn set_credit(&self, credit: u32) {
        self.send_credit.store(credit.min(STREAM_WINDOW), Ordering::Release);
        self.credit_notify.notify_waiters();
    }

    /// 接收侧：收到一帧。返回 false 表示超出了窗口（对端不守信用）。
    pub fn on_frame_received(&self) -> bool {
        let cur = self.allowed.load(Ordering::Acquire);
        if cur == 0 {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.allowed.fetch_sub(1, Ordering::AcqRel);
        true
    }

    /// 接收侧：一帧已写进本地 socket，回收信用。返回应当发给对端的绝对信用值。
    pub fn on_frame_consumed(&self) -> Option<u32> {
        self.allowed.fetch_add(1, Ordering::AcqRel);
        let pending = self.pending_ack.fetch_add(1, Ordering::AcqRel) + 1;
        if pending >= WINDOW_UPDATE_BATCH {
            self.pending_ack.store(0, Ordering::Release);
            Some(self.allowed.load(Ordering::Acquire).min(STREAM_WINDOW))
        } else {
            None
        }
    }

    /// 对端还能发多少帧给我（供 UI 与调试）。
    pub fn allowed_credit(&self) -> u32 {
        self.allowed.load(Ordering::Acquire)
    }

    /// 等待信用（或取消）。
    pub async fn wait_for_credit(&self) {
        let notified = self.credit_notify.notified();
        if self.has_credit() {
            return;
        }
        notified.await;
    }
}

/// 关闭原因 → `CloseReason`。
pub fn close_reason_for_link_loss() -> crate::proto::CloseReason {
    crate::proto::CloseReason::Reset
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Host;

    fn ctx(role: StreamRole) -> StreamCtx {
        let (sink, _s) = mpsc::channel(4);
        let (out_tx, _o) = mpsc::channel(4);
        let out = StreamSender::new(out_tx, std::sync::Arc::new(Notify::new()));
        StreamCtx::new(
            StreamKey("10.0.0.1".parse().unwrap(), 1),
            Endpoint::new(Host::Name("a.example.com".into()), 443),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            role,
            None,
            sink,
            out,
        )
    }

    #[test]
    fn credit_starts_at_window_and_drains() {
        let s = ctx(StreamRole::Origin);
        assert_eq!(s.send_credit.load(Ordering::Relaxed), STREAM_WINDOW);
        for _ in 0..STREAM_WINDOW {
            assert!(s.take_credit());
        }
        assert!(!s.take_credit(), "信用耗尽后必须停止发送（§5.5）");
        assert!(!s.has_credit());
    }

    #[test]
    fn window_update_assigns_absolute_value() {
        let s = ctx(StreamRole::Origin);
        while s.take_credit() {}
        s.set_credit(5);
        assert_eq!(s.send_credit.load(Ordering::Relaxed), 5);
        // 绝对值语义：再来一个更小的更新不会把它加回去
        s.set_credit(2);
        assert_eq!(s.send_credit.load(Ordering::Relaxed), 2);
        assert!(s.has_credit());
    }

    #[test]
    fn credit_is_clamped_to_window() {
        let s = ctx(StreamRole::Origin);
        s.set_credit(u32::MAX);
        assert_eq!(s.send_credit.load(Ordering::Relaxed), STREAM_WINDOW, "不得被对端抬到窗口以上");
    }

    #[test]
    fn receiving_more_than_the_window_drops() {
        let s = ctx(StreamRole::Egress);
        for _ in 0..STREAM_WINDOW {
            assert!(s.on_frame_received());
        }
        assert!(!s.on_frame_received(), "超出窗口的帧必须被丢弃并计数");
        assert_eq!(s.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn window_update_is_batched() {
        let s = ctx(StreamRole::Egress);
        let mut acks = 0;
        for _ in 0..STREAM_WINDOW {
            s.on_frame_received();
            if s.on_frame_consumed().is_some() {
                acks += 1;
            }
        }
        assert_eq!(acks as u32, STREAM_WINDOW / WINDOW_UPDATE_BATCH, "攒批回，避免小消息风暴");
    }

    #[test]
    fn consumed_frames_restore_credit() {
        let s = ctx(StreamRole::Egress);
        s.on_frame_received();
        assert_eq!(s.allowed_credit(), STREAM_WINDOW - 1);
        s.on_frame_consumed();
        assert_eq!(s.allowed_credit(), STREAM_WINDOW);
    }

    #[test]
    fn state_transitions() {
        let s = ctx(StreamRole::Origin);
        assert_eq!(s.state(), StreamState::Opening);
        s.set_state(StreamState::Open);
        assert_eq!(s.state(), StreamState::Open);
        assert!(!s.closed());
        s.set_state(StreamState::Closed);
        assert!(s.closed());
    }

    #[tokio::test]
    async fn wait_for_credit_returns_immediately_when_available() {
        let s = ctx(StreamRole::Origin);
        tokio::time::timeout(std::time::Duration::from_millis(50), s.wait_for_credit())
            .await
            .expect("有信用时应当立刻返回");
    }

    #[tokio::test]
    async fn wait_for_credit_wakes_on_window_update() {
        let s = std::sync::Arc::new(ctx(StreamRole::Origin));
        while s.take_credit() {}
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            s2.set_credit(3);
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), s.wait_for_credit())
            .await
            .expect("WindowUpdate 必须唤醒等待中的读泵");
    }
}
