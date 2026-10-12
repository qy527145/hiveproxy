//! Listener：在被授权的入向端口上接受连接并握手（DESIGN.md §6.2、§6.2.3）。
//!
//! **每个端口 bind 失败都必须显式告警到前端**，而不是静默降级 ——
//! 否则运维会以为端口对齐做对了，实际这台机器根本没在那个端口上听（§6.2.3 的前置自检）。

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::handshake::accept_and_handshake;
use crate::proto::Establisher;
use crate::state::HiveState;

/// 绑定一个端口；返回 `Err(原因)` 时调用方必须告警（不静默降级）。
pub async fn bind_one(bind: std::net::IpAddr, port: u16) -> Result<TcpListener, String> {
    TcpListener::bind((bind, port))
        .await
        .map_err(|e| format!("{bind}:{port} 绑定失败：{e}"))
}

/// 启动全部监听端口。
pub fn spawn_listeners(state: Arc<HiveState>, cancel: CancellationToken) {
    let cfg = state.cfg();
    let bind = cfg.listen.bind;
    let ports = if cfg.listen.ports.is_empty() { vec![5678] } else { cfg.listen.ports.clone() };

    for port in ports {
        let st = state.clone();
        let c = cancel.clone();
        tokio::spawn(async move {
            match bind_one(bind, port).await {
                Ok(listener) => {
                    st.log("info", "listener", format!("正在监听 {bind}:{port}（IT 授权给本机的入向端口）"));
                    accept_loop(st, listener, c).await;
                }
                Err(e) => {
                    // ★ 必须显式告警：静默降级会让"端口对齐"变成一个看不见的失败
                    st.log("error", "listener", format!(
                        "{e} —— 这个入向孔洞对本机不可用，其它节点拨不进来（§6.2.3）。\
                         端口可能已被别的服务占用，或需要更高权限。"
                    ));
                }
            }
        });
    }
}

async fn accept_loop(state: Arc<HiveState>, listener: TcpListener, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
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
