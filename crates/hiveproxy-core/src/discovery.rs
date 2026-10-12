//! LAN 自动发现（DESIGN.md §6.5 第 2 条）。
//!
//! UDP 向 `255.255.255.255` 与各网卡定向广播地址周期发探针；收到即纳入拨号候选，
//! 让同网段零配置组网。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::proto::{MAGIC, NodeId};
use crate::state::HiveState;

/// UDP 探针（明文 JSON —— 内容本身不含秘密，只是"我在这儿"）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Probe {
    pub magic: u8,
    pub node_addr: NodeId,
    pub listen_ports: Vec<u16>,
    pub alias: Option<String>,
}

impl Probe {
    pub fn is_valid(&self) -> bool {
        self.magic == MAGIC && !self.listen_ports.is_empty()
    }
}

/// 绑定一个可以发广播的 UDP socket。
pub fn bind_broadcast(port: u16) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// 启动 LAN 发现。
pub fn spawn_discovery(state: Arc<HiveState>, cancel: CancellationToken) {
    let cfg = state.cfg();
    if !cfg.discovery.lan_udp {
        return;
    }
    let port = cfg.discovery.udp_port;
    tokio::spawn(async move {
        let sock = match bind_broadcast(port) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                state.log("warn", "discovery", format!("LAN 发现不可用（UDP {port} 绑定失败：{e}）"));
                return;
            }
        };
        state.log("info", "discovery", format!("LAN 发现已启用（UDP {port}）"));

        // 收：把探针变成拨号候选
        {
            let st = state.clone();
            let s = sock.clone();
            let c = cancel.clone();
            tokio::spawn(async move { recv_loop(st, s, c).await });
        }

        // 发
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = state.shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    let probe = Probe {
                        magic: MAGIC,
                        node_addr: state.self_id(),
                        listen_ports: state.node.listen_ports(),
                        alias: state.node.alias.clone(),
                    };
                    let Ok(bytes) = serde_json::to_vec(&probe) else { continue };
                    let mut targets: Vec<Ipv4Addr> = vec![Ipv4Addr::BROADCAST];
                    targets.extend(crate::net::directed_broadcasts());
                    targets.dedup();
                    for t in targets {
                        let _ = sock.send_to(&bytes, SocketAddr::new(IpAddr::V4(t), port)).await;
                    }
                }
            }
        }
    });
}

async fn recv_loop(state: Arc<HiveState>, sock: Arc<UdpSocket>, cancel: CancellationToken) {
    let mut buf = vec![0u8; 2048];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = state.shutdown.cancelled() => break,
            r = sock.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { continue };
                let Ok(probe) = serde_json::from_slice::<Probe>(&buf[..n]) else { continue };
                if !probe.is_valid() {
                    continue;
                }
                if probe.node_addr == state.self_id() {
                    continue; // 自己的广播被环回了
                }
                // 用**收到的源地址**而不是探针自称的地址来拨（更可信，且能穿透 NAT）
                for p in &probe.listen_ports {
                    let addr = SocketAddr::new(from.ip(), *p);
                    if state.lan_candidates.write().insert(addr) {
                        state.log("debug", "discovery", format!(
                            "发现同网段节点 {}（{addr}）",
                            probe.alias.clone().unwrap_or_else(|| probe.node_addr.to_string())
                        ));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_validation() {
        let good = Probe {
            magic: MAGIC,
            node_addr: "10.1.2.5".parse().unwrap(),
            listen_ports: vec![20000],
            alias: Some("a".into()),
        };
        assert!(good.is_valid());

        let bad_magic = Probe { magic: 0x00, ..good.clone() };
        assert!(!bad_magic.is_valid());

        let no_ports = Probe { listen_ports: vec![], ..good.clone() };
        assert!(!no_ports.is_valid());
    }

    #[test]
    fn probe_roundtrips_as_json() {
        let p = Probe {
            magic: MAGIC,
            node_addr: "10.1.2.5".parse().unwrap(),
            listen_ports: vec![20000, 5678],
            alias: None,
        };
        let b = serde_json::to_vec(&p).unwrap();
        let back: Probe = serde_json::from_slice(&b).unwrap();
        assert_eq!(back.node_addr, p.node_addr);
        assert_eq!(back.listen_ports, p.listen_ports);
    }

    #[tokio::test]
    async fn recv_loop_turns_probes_into_dial_candidates() {
        use crate::testutil::{nid, state_for};

        let st = state_for("10.1.2.5", crate::config::Config::default());
        let sock = Arc::new(bind_broadcast(0).unwrap());
        let port = sock.local_addr().unwrap().port();

        let cancel = CancellationToken::new();
        tokio::spawn({
            let st = st.clone();
            let s = sock.clone();
            let c = cancel.clone();
            async move { recv_loop(st, s, c).await }
        });

        let sender = bind_broadcast(0).unwrap();
        let probe = Probe {
            magic: MAGIC,
            node_addr: nid("10.1.2.6"),
            listen_ports: vec![20000, 20001],
            alias: Some("b".into()),
        };
        sender
            .send_to(
                &serde_json::to_vec(&probe).unwrap(),
                SocketAddr::new("127.0.0.1".parse().unwrap(), port),
            )
            .await
            .unwrap();

        for _ in 0..50 {
            if !st.lan_candidates.read().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let cands = st.lan_candidates.read().clone();
        assert_eq!(cands.len(), 2, "探针里的每个监听端口都应当成为候选: {cands:?}");
        assert!(cands.iter().all(|a| a.port() == 20000 || a.port() == 20001));
        cancel.cancel();
    }

    #[tokio::test]
    async fn own_probe_is_ignored() {
        use crate::testutil::state_for;

        let st = state_for("10.1.2.5", crate::config::Config::default());
        let sock = Arc::new(bind_broadcast(0).unwrap());
        let port = sock.local_addr().unwrap().port();
        let cancel = CancellationToken::new();
        tokio::spawn({
            let st = st.clone();
            let s = sock.clone();
            let c = cancel.clone();
            async move { recv_loop(st, s, c).await }
        });

        let sender = bind_broadcast(0).unwrap();
        let probe = Probe {
            magic: MAGIC,
            node_addr: st.self_id(), // 自称是本机
            listen_ports: vec![20000],
            alias: None,
        };
        sender
            .send_to(
                &serde_json::to_vec(&probe).unwrap(),
                SocketAddr::new("127.0.0.1".parse().unwrap(), port),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(st.lan_candidates.read().is_empty(), "自己的广播被环回时必须忽略");
        cancel.cancel();
    }
}
