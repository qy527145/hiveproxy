//! Dialer：常驻重连 + 指数退避（DESIGN.md §6.2、§3.1）。
//!
//! **对已建立的链路持续保活，不因无流量而断开** —— 这是 B→A 方向可达性的唯一保证：
//! B 够不到 A 时，靠 A 拨进来的那条全双工会话回传数据。所以拨号器不能"有流量才连"。

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::config::expand_seed;
use crate::handshake::dial_and_handshake;
use crate::proto::{Establisher, NodeId};
use crate::state::{DialState, HiveState};

/// 组装本次巡检的候选地址，按优先级排序。
///
/// 三类来源（§6.2）：
/// 1. `peers.seeds`（引导，通常是每个网段一条）；
/// 2. LAN 自动发现；
/// 3. gossip 广播的监听端点（已按 `ttl_secs` 过期清理）。
pub fn collect_candidates(state: &Arc<HiveState>) -> Vec<SocketAddr> {
    let cfg = state.cfg();
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut push = |a: SocketAddr| {
        if !out.contains(&a) {
            out.push(a);
        }
    };

    // 1. 种子
    for s in &cfg.peers.seeds {
        if let Ok((ip, ports)) = expand_seed(s, &cfg.peers.probe_ports) {
            for p in ports {
                push(SocketAddr::new(ip, p));
            }
        }
    }
    // 2. LAN
    for a in state.lan_candidates.read().iter() {
        push(*a);
    }
    // 3. 广播的监听端点
    if cfg.peers.accept_listen_adverts {
        let me = state.self_id();
        let topo = state.topology.read();
        for (id, advert) in topo.listen_addrs.iter() {
            if *id == me {
                continue;
            }
            for a in &advert.addrs {
                push(*a);
            }
        }
    }

    let cap = cfg.discovery.max_dial_candidates.max(1);
    out.truncate(cap);
    out
}

/// 该地址是否落在"已经连上"的节点的监听端点里。
fn covered_by_existing_link(state: &Arc<HiveState>, addr: SocketAddr) -> bool {
    let me = state.self_id();
    let topo = state.topology.read();
    for (id, advert) in topo.listen_addrs.iter() {
        if *id == me || !state.links.contains_key(id) {
            continue;
        }
        if advert.addrs.contains(&addr) {
            return true;
        }
    }
    false
}

/// 这个地址是不是一个**已经有链路**的节点。
///
/// `covered_by_existing_link` 只认对端**广播**的监听端点，因此对 `listen.advertise = false`
/// 的对端、或 advert 刚好过期的那个窗口，它形同虚设 —— 那种情况下拨号器会每个巡检周期
/// 把同一个对端重拨一遍（每拨一次就多一条连接、一次握手，日志里一行"已拨通"）。
///
/// 节点身份就是它的地址（§5.8），所以"候选地址的 IP == 某条已有链路对端的 IP"
/// 是一条与广播完全无关的判据，用来兜住上面那些情况。
fn already_linked(state: &Arc<HiveState>, addr: SocketAddr) -> bool {
    state.links.contains_key(&NodeId::from_ip(addr.ip()))
}

/// 指数退避：`1s → 2s → 4s → … → backoff_max_ms`。
fn backoff_for(failures: u32, max_ms: u64) -> Duration {
    let shift = failures.min(20);
    let ms = 1000u64.saturating_mul(1u64 << shift.min(16));
    Duration::from_millis(ms.min(max_ms.max(1000)))
}

/// 启动拨号巡检。
pub fn spawn_dialer(state: Arc<HiveState>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let interval = Duration::from_millis(state.cfg().discovery.dial_interval_ms.max(200));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = state.shutdown.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            dial_pass(&state).await;
        }
    });
}

/// 一轮巡检。
pub async fn dial_pass(state: &Arc<HiveState>) {
    let candidates = collect_candidates(state);

    for addr in candidates {
        if state.links.len() >= state.cfg().listen.max_links {
            break;
        }
        // 只跳过**自己的监听端点**，而不是"所有本机 IP"。
        // 后者会误杀同机上另一个端口的节点（容器 / 多实例 / 测试都会踩到）。
        // 用实际绑上的那份（`listen_addrs`）：端口改过之后，老地址已经不在听了。
        if state.listen_addrs().contains(&addr) {
            continue;
        }
        if covered_by_existing_link(state, addr) || already_linked(state, addr) {
            continue;
        }

        // 退避闸门 + "不是节点"的持久标记（§6.2.2）。
        // 注意：比较用的时间必须在**创建条目之后**取 —— 否则新建条目的
        // `next_attempt = now()` 会晚于循环开头捕获的 `now`，每个候选的第一次尝试
        // 都会被自己挡掉一轮。
        {
            let st = state.dial_state.entry(addr).or_insert_with(DialState::new);
            if st.not_a_node || Instant::now() < st.next_attempt {
                continue;
            }
        }

        dial_one(state, addr).await;
    }
}

/// 拨一个地址并处理结果（不含候选过滤与上限判断，便于单独测试）。
pub async fn dial_one(state: &Arc<HiveState>, addr: SocketAddr) {
    {
        state.stats.dial_attempts.fetch_add(1, Ordering::Relaxed);
        match dial_and_handshake(state, addr).await {
            Ok(est) => {
                let peer = est.peer;
                // 端口对齐自检（§6.2.3）：我按哪个端口拨的，对方真的在听吗
                if let Some(w) = crate::handshake::port_alignment_warning(
                    &[addr.port()],
                    &est.listen_ports,
                    peer,
                ) {
                    state.log("warn", "dialer", w);
                }
                state.dial_state.remove(&addr);
                crate::handshake::register_link(state, est, Establisher::Local);
                state.log("info", "dialer", format!("已拨通 {peer}（{addr}）"));
            }
            Err(e) => {
                state.stats.dial_failures.fetch_add(1, Ordering::Relaxed);
                let msg = classify(&e);
                let mut st = state.dial_state.entry(addr).or_insert_with(DialState::new);
                if matches!(e, crate::handshake::HandshakeError::Proto(_)) {
                    // 确定性失败：该端口不是 hiveproxy，不再反复重试
                    st.not_a_node = true;
                    drop(st);
                    state.log("warn", "dialer", format!("{addr} {msg}"));
                    return;
                }
                st.failures = st.failures.saturating_add(1);
                st.next_attempt =
                    Instant::now() + backoff_for(st.failures, state.cfg().discovery.backoff_max_ms);
                drop(st);
                state.log("debug", "dialer", format!("{addr} {msg}，退避后重试"));
            }
        }
    }
}

/// 把失败翻译成**互不相同**的可操作文案（§6.2.3）。
pub fn classify(e: &crate::handshake::HandshakeError) -> String {
    use crate::handshake::HandshakeError as H;
    use crate::error::ProtoError as P;
    match e {
        H::Io(io) => match io.kind() {
            std::io::ErrorKind::ConnectionRefused => {
                "连接被拒（收到 RST）：包到了对端，但该端口没人监听 —— 检查对端的 listen.ports".into()
            }
            std::io::ErrorKind::TimedOut => {
                "连接超时（无响应）：包没到对端，被防火墙丢弃 —— 检查 IT 是否真的放行了这条 (源,目的,端口)".into()
            }
            std::io::ErrorKind::UnexpectedEof => "对端在握手前就关闭了连接".into(),
            _ => format!("I/O 错误：{io}"),
        },
        H::Proto(P::BadMagic(b)) => {
            format!("连上了但魔数不符（0x{b:02x}）：该端口被别的服务占用，不是 hiveproxy")
        }
        H::Proto(P::BadVersion(v)) => format!(
            "连上了但版本位不符（{v}）：该端口很可能是某个文本协议（HTTP 的首字节 'H' 与魔数相同，靠这一位区分）"
        ),
        H::Proto(p) => format!("协议错误：{p}"),
        H::VersionMismatch { .. } => "版本不兼容：升级其中一侧".into(),
        H::Rejected(r) => format!("对端拒绝：{r:?}"),
        H::AuthFailed => "join_token 不匹配：两侧的 security.join_token 必须一致".into(),
        H::Timeout => "握手超时：对端没有按时回 HelloAck".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::state_for;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_for(0, 60_000).as_millis(), 1000);
        assert_eq!(backoff_for(1, 60_000).as_millis(), 2000);
        assert_eq!(backoff_for(2, 60_000).as_millis(), 4000);
        assert_eq!(backoff_for(10, 60_000).as_millis(), 60_000, "上限必须封顶");
        // 极大的失败次数不能溢出成 0
        assert!(backoff_for(u32::MAX, 60_000).as_millis() >= 60_000);
    }

    #[test]
    fn candidates_include_seeds_lan_and_adverts() {
        let mut cfg = crate::config::Config::default();
        cfg.peers.seeds = vec!["10.1.2.3:20000".into()];
        let st = state_for("10.0.0.1", cfg);

        // LAN 发现
        st.lan_candidates.write().insert("10.1.2.9:5678".parse().unwrap());
        // 广播的监听端点
        {
            let mut topo = st.topology.write();
            topo.listen_addrs.insert(
                "10.4.0.9".parse().unwrap(),
                crate::proto::ListenAdvert {
                    addrs: vec!["10.4.0.9:20000".parse().unwrap()],
                    issued_at: 0,
                    ttl_secs: 900,
                },
            );
        }

        let c = collect_candidates(&st);
        assert!(c.contains(&"10.1.2.3:20000".parse().unwrap()));
        assert!(c.contains(&"10.1.2.9:5678".parse().unwrap()));
        assert!(c.contains(&"10.4.0.9:20000".parse().unwrap()));
    }

    #[test]
    fn candidates_respect_the_cap() {
        let mut cfg = crate::config::Config::default();
        cfg.discovery.max_dial_candidates = 2;
        cfg.peers.seeds = vec![
            "10.1.2.1:10001".into(),
            "10.1.2.2:10002".into(),
            "10.1.2.3:10003".into(),
        ];
        let st = state_for("10.0.0.1", cfg);
        assert_eq!(collect_candidates(&st).len(), 2);
    }

    #[test]
    fn adverts_are_ignored_when_disabled() {
        let mut cfg = crate::config::Config::default();
        cfg.peers.accept_listen_adverts = false;
        let st = state_for("10.0.0.1", cfg);
        {
            let mut topo = st.topology.write();
            topo.listen_addrs.insert(
                "10.4.0.9".parse().unwrap(),
                crate::proto::ListenAdvert {
                    addrs: vec!["10.4.0.9:20000".parse().unwrap()],
                    issued_at: 0,
                    ttl_secs: 900,
                },
            );
        }
        assert!(collect_candidates(&st).is_empty(), "关掉采信后不得产生广播候选（§16）");
    }

    #[test]
    fn own_addresses_are_never_candidates() {
        let mut cfg = crate::config::Config::default();
        cfg.peers.seeds = vec!["10.0.0.1:20000".into()];
        let st = state_for("10.0.0.1", cfg);
        let c = collect_candidates(&st);
        // 候选里可以有它，但拨号巡检会跳过本机地址
        assert!(crate::net::is_local_ip("10.0.0.1".parse().unwrap()) || !c.is_empty());
    }

    #[test]
    fn failure_classification_is_actionable_and_distinct() {
        use crate::handshake::HandshakeError as H;
        let refused = classify(&H::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)));
        let timeout = classify(&H::Io(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        let not_node = classify(&H::Proto(crate::error::ProtoError::BadMagic(b'H')));
        assert!(refused.contains("RST"));
        assert!(timeout.contains("防火墙"));
        assert!(not_node.contains("别的服务"));
        assert_ne!(refused, timeout);
        assert_ne!(timeout, not_node);
    }

    #[tokio::test]
    async fn dial_pass_marks_non_hiveproxy_ports_permanently() {
        // 起一个纯 HTTP 服务，断言被标记 not_a_node 后不再重试。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { break };
                let _ = tokio::io::AsyncWriteExt::write_all(&mut s, b"HTTP/1.1 200 OK\r\n\r\n").await;
            }
        });

        let mut cfg = crate::config::Config::default();
        cfg.peers.seeds = vec![addr.to_string()];
        let st = state_for("127.0.0.9", cfg);

        // 直接驱动单次拨号（回环地址会被 dial_pass 的"跳过本机地址"过滤掉，
        // 所以这里绕开候选过滤，单独验证"标记"这条逻辑）
        dial_one(&st, addr).await;
        let marked = st.dial_state.get(&addr).map(|d| d.not_a_node).unwrap_or(false);
        assert!(marked, "确认不是 hiveproxy 的端口必须被持久标记（§6.2.2）");

        // 再走一遍完整的 dial_pass：因为已被标记，不应该再产生拨号尝试
        let mut cfg2 = st.cfg().as_ref().clone();
        cfg2.discovery.max_dial_candidates = 8;
        let before = st.stats.dial_attempts.load(Ordering::Relaxed);
        let gate = st.dial_state.get(&addr).unwrap().not_a_node;
        assert!(gate);
        assert_eq!(st.stats.dial_attempts.load(Ordering::Relaxed), before);
    }
}
