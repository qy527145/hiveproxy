//! Listener：在被授权的入向端口上接受连接并握手（DESIGN.md §6.2、§6.2.3）。
//!
//! **每个端口 bind 失败都必须显式告警到前端**，而不是静默降级 ——
//! 否则运维会以为端口对齐做对了，实际这台机器根本没在那个端口上听（§6.2.3 的前置自检）。

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::handshake::accept_and_handshake;
use crate::proto::Establisher;
use crate::state::HiveState;

/// 绑定一个端口；返回 `Err(原因)` 时调用方必须告警（不静默降级）。
pub async fn bind_one(bind: std::net::IpAddr, port: u16) -> Result<TcpListener, String> {
    TcpListener::bind((bind, port))
        .await
        .map_err(|e| format!("{bind}:{port} 绑定失败：{e}"))
}

/// 在**已经绑好**的监听器上起 accept loop，返回任务句柄。
///
/// ★ 返回句柄是必需的，不是顺手：取消令牌是**异步**的 —— 取消之后旧任务要等到被调度
/// 才会丢掉那个 `TcpListener`。改端口时如果不等它真的死掉就去绑新端口，
/// 换端口重叠的场景必然 `EADDRINUSE`（这个 bug 是被 `tests/rebind.rs` 抓出来的）。
/// `abort()` + `await` 才能让"旧端口已经腾出来"变成确定的事。
///
/// 绑端口不在这里做：冷启动与重绑要共用同一段"先绑、再起"的代码，
/// 而冷启动对单个端口绑失败是**容忍**的（§6.2.3，只告警不阻断启动），
/// 重绑则是全有全无。两种策略只能在调用方选。
pub fn spawn_on(state: Arc<HiveState>, listeners: Vec<TcpListener>) -> Vec<JoinHandle<()>> {
    listeners
        .into_iter()
        .map(|listener| {
            let st = state.clone();
            tokio::spawn(async move {
                if let Ok(addr) = listener.local_addr() {
                    st.log("info", "listener", format!("正在监听 {addr}（IT 授权给本机的入向端口）"));
                }
                accept_loop(st, listener).await;
            })
        })
        .collect()
}

async fn accept_loop(state: Arc<HiveState>, listener: TcpListener) {
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, remote) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        state.log("warn", "listener", format!("accept 失败：{e}"));
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let st = state.clone();
                tokio::spawn(async move {
                    // 保护阈值（§6.2）
                    if st.links.len() >= st.cfg().listen.max_links {
                        st.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                        st.log("warn", "listener", format!(
                            "{remote} 入向连接被拒：已达 max_links = {}",
                            st.cfg().listen.max_links
                        ));
                        return;
                    }
                    match accept_and_handshake(&st, stream, remote).await {
                        Ok(Some(est)) => {
                            let peer = est.peer;
                            crate::handshake::register_link(&st, est, Establisher::Remote);
                            st.log("info", "listener", format!("接受来自 {peer}（{remote}）的入向链路"));
                        }
                        Ok(None) => {
                            st.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            st.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                            st.log("warn", "listener", format!("{remote} 握手失败：{e}"));
                        }
                    }
                });
            }
        }
    }
}
