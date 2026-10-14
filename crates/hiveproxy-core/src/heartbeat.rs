//! 链路心跳与 RTT（DESIGN.md §12）。
//!
//! §12 从第一版设计起就写着「每 3s（空闲时）发心跳，连续 3 次未响应（约 10s）判定 Down、
//! 拆链，从拓扑删边」—— 但直到 2026-10-14 才真正实现：在那之前
//! `relay` 里 `Pong` 分支的注释写着"RTT 由链路层心跳处理"，而**没有任何组件发 Ping**，
//! `register_link` 也把 `rtt_ms` 写死 0。后果有两个，都是实测出来的：
//!
//! 1. **对端"静默消失"时链路永远不判死**。对端睡眠 / 关机 / 拔网线（内核不发 RST）之后，
//!    我们这边那条 socket 一直 ESTABLISHED、读任务一直挂在 `read_frame` 上，
//!    拨号器还因为"链路还在"而不去重连 —— 对端就在拓扑里阴魂不散。
//! 2. **RTT 恒为 0**，于是 `router::arc_weight` 的 rtt 惩罚项从不生效，界面也一直显示 0 ms。
//!
//! ## 为什么只数 Ping/Pong，不看数据帧
//!
//! "收到过数据帧"看似更天然的判活信号，但数据面忙**不能**证明对端还在（可能只是我们单方向
//! 在往里灌），而 `Pong` 是对方进程活着、且控制车道还能回帧的直接证据。控制优先车道本来就是
//! 为了让心跳不被大流量饿死而存在的（§5.5），所以这条判据在任何负载下都成立。
//!
//! ## 为什么发 Ping 要 `await` 加超时
//!
//! 不能 `try_send_control`：控制车道满（gossip flood）时丢掉的 Ping 会被自己误判成
//! "对端没回应"，把一条健康的链路拆掉。但也不能无限 `await`：对端死了而内核没发 RST 时，
//! 写出任务会**卡在 `write_all`** 上，车道迟早填满，那一刻 `await` 就是永久阻塞。
//! 所以给一次发送一个间隔长度的超时：发不出去 = 这一轮就算没回应。

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::link::{LinkHandle, OutboundFrame};
use crate::msg::control_header;
use crate::proto::MsgType;
use crate::state::HiveState;

/// 心跳间隔（§12：每 3s）。
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
/// 连续几次没等到 `Pong` 就判死（§12：连续 3 次未响应 ≈ 10s）。
pub const HEARTBEAT_MISSES: u32 = 3;

/// 心跳节奏。默认就是 §12 的两个常量。
///
/// **刻意不进配置文件**：它不是需要按网络环境调的东西，而是一个"多久算死"的判定阈值；
/// 放在 `HiveState` 的字段上只是为了让测试能把节奏调快（50ms 级），从而**确定性地**验证
/// 判死逻辑，而不是让测试等 10 秒真时间。
#[derive(Clone, Copy, Debug)]
pub struct HeartbeatParams {
    pub interval: Duration,
    pub misses: u32,
}

impl Default for HeartbeatParams {
    fn default() -> Self {
        Self { interval: HEARTBEAT_INTERVAL, misses: HEARTBEAT_MISSES }
    }
}

/// 判定阈值：超过这个时间没有任何 `Pong` 就算死（供文案与测试使用）。
impl HeartbeatParams {
    pub fn deadline(&self) -> Duration {
        self.interval * self.misses
    }
}

/// 给一条链路起心跳任务。
pub fn spawn(state: Arc<HiveState>, handle: Arc<LinkHandle>) {
    tokio::spawn(run(state, handle));
}

async fn run(state: Arc<HiveState>, handle: Arc<LinkHandle>) {
    let params = state.heartbeat();
    let mut ticker = tokio::time::interval(params.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // 第一次立刻返回，丢掉

    loop {
        tokio::select! {
            _ = handle.cancel.cancelled() => return,
            _ = state.shutdown.cancelled() => return,
            _ = ticker.tick() => {}
        }

        let peer = handle.peer;
        let frame = OutboundFrame::new(
            control_header(MsgType::Ping, state.self_id(), peer, 1),
            Bytes::new(),
        );
        // 发得出去才算"问过一次"；发不出去（车道卡住）= 这一轮也算没回应。
        let asked = tokio::time::timeout(params.interval, handle.sender.send_control(frame))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
        let unanswered = if asked {
            handle.note_ping_sent()
        } else {
            handle.note_miss()
        };

        if unanswered >= params.misses {
            state.log(
                "warn",
                "link",
                format!(
                    "{peer} 连续 {unanswered} 次心跳没有回应（约 {} 秒）—— 判定链路已失效并拆掉",
                    params.deadline().as_secs()
                ),
            );
            crate::handshake::teardown_link(&state, peer, handle.session_id, "心跳超时").await;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_matches_the_documented_ten_seconds() {
        let p = HeartbeatParams::default();
        assert_eq!(p.interval, Duration::from_secs(3));
        assert_eq!(p.misses, 3);
        assert_eq!(p.deadline(), Duration::from_secs(9));
    }
}