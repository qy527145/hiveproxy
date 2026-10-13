//! L5 本地出口：SOCKS5 `CONNECT`（DESIGN.md §6.4）。
//!
//! 只实现 `CONNECT`（TCP）。`BIND` / `UDP ASSOCIATE` 不在 v1 范围（§17 非目标）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::events::HiveEvent;
use crate::proto::{Endpoint, Host};
use crate::resolver::{self, Egress, ResolveCtx, ResolveError, Resolved};
use crate::state::HiveState;
use crate::stream::{self, OpenError};
use crate::zone::{self, ZoneResolution};

// SOCKS5 常量
const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// 应答码
const REP_OK: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NET_UNREACH: u8 = 0x03;
const REP_HOST_UNREACH: u8 = 0x04;
const REP_REFUSED: u8 = 0x05;
const REP_CMD_UNSUPPORTED: u8 = 0x07;

/// 启动 SOCKS5 服务。
pub fn spawn_socks5(state: Arc<HiveState>, cancel: CancellationToken) {
    let bind = state.cfg().proxy.socks5_bind;
    let allow_remote = state.cfg().proxy.allow_remote_socks;
    tokio::spawn(async move {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                state.log("error", "socks5", format!("{bind} 绑定失败：{e} —— 本地应用将无法使用代理"));
                return;
            }
        };
        let actual = listener.local_addr().unwrap_or(bind);
        *state.socks5_bound.write() = Some(actual);
        state.log("info", "socks5", format!("SOCKS5 出口已就绪：{actual}"));
        if allow_remote && !bind.ip().is_loopback() {
            state.log("warn", "socks5", format!(
                "SOCKS5 监听在非回环地址 {bind} 且 allow_remote_socks = true —— \
                 同网段任何人都能借用你的网络位置（§11）"
            ));
        }

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = state.shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            state.log("warn", "socks5", format!("accept 失败：{e}"));
                            continue;
                        }
                    };
                    if !allow_remote && !peer.ip().is_loopback() {
                        state.log("warn", "socks5", format!(
                            "拒绝 {peer}：allow_remote_socks = false 时本地出口只服务回环地址"
                        ));
                        continue;
                    }
                    let st = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(st.clone(), stream).await {
                            st.log("debug", "socks5", format!("连接结束：{e}"));
                        }
                    });
                }
            }
        }
    });
}

#[derive(Debug)]
pub enum SocksError {
    Io(std::io::Error),
    /// 客户端不是 SOCKS5。
    BadVersion(u8),
    /// 没有可接受的方法。
    NoAcceptableMethod,
    /// 只支持 CONNECT。
    UnsupportedCommand(u8),
    /// 目标地址族不认识。
    BadAddressType(u8),
    /// 解析/选路失败。
    Resolve(ResolveError),
    /// 打开流失败。
    Open(OpenError),
}

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::BadVersion(v) => write!(f, "非 SOCKS5 客户端（version = {v}）"),
            Self::NoAcceptableMethod => write!(f, "没有可接受的认证方法"),
            Self::UnsupportedCommand(c) => write!(f, "不支持的命令 0x{c:02x}（v1 只支持 CONNECT）"),
            Self::BadAddressType(t) => write!(f, "不支持的目标地址类型 0x{t:02x}"),
            Self::Resolve(e) => write!(f, "选路失败：{e:?}"),
            Self::Open(e) => write!(f, "打开流失败：{e:?}"),
        }
    }
}

impl From<std::io::Error> for SocksError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// 处理一个 SOCKS5 客户端连接。
pub async fn handle_client(state: Arc<HiveState>, mut client: TcpStream) -> Result<(), SocksError> {
    client.set_nodelay(true).ok();

    // ---- 1. 方法协商 ----
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(SocksError::BadVersion(head[0]));
    }
    let n = head[1] as usize;
    let mut methods = vec![0u8; n];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        client.write_all(&[VER, 0xFF]).await?;
        return Err(SocksError::NoAcceptableMethod);
    }
    client.write_all(&[VER, 0x00]).await?; // 不需要认证

    // ---- 2. 请求 ----
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != VER {
        return Err(SocksError::BadVersion(req[0]));
    }
    if req[1] != CMD_CONNECT {
        reply(&mut client, REP_CMD_UNSUPPORTED).await?;
        // 优雅关闭：直接 drop 会让对端读到 RST 而不是我们刚写下的应答
        let _ = client.shutdown().await;
        return Err(SocksError::UnsupportedCommand(req[1]));
    }

    let target = match read_target(&mut client, req[3]).await {
        Ok(t) => t,
        Err(e) => {
            reply(&mut client, REP_GENERAL).await?;
            return Err(e);
        }
    };

    // ---- 3. 区域分流（§9.3 情形二）----
    // 用户把 `z7+10.1.2.5` 写成目标时，SOCKS5 会以 ATYP=3（域名）送过来，
    // 所以这里要把 zone 前缀从"域名"里摘出来。
    let (target, mut zone) = extract_zone(target);
    let mut island: Option<std::collections::HashSet<crate::proto::NodeId>> = None;

    if zone.is_none() {
        if let Host::Ip(ip) = &target.host {
            let self_zone = state.self_zone();
            let resolution = state.zones.read().resolve_ip(*ip, self_zone);
            match resolution {
                ZoneResolution::Ambiguous(zs) => {
                    reply(&mut client, REP_HOST_UNREACH).await?;
                    let _ = client.shutdown().await;
                    let labels: Vec<String> = zs.iter().map(|z| z.label()).collect();
                    state.log("warn", "socks5", format!(
                        "{target} 在多个孤岛里都存在（{}）—— 请用 z<zone>+{ip}:{port} 指定你要连哪一片",
                        labels.join(", "), port = target.port
                    ));
                    return Err(SocksError::Resolve(ResolveError::NoRoute));
                }
                // 请求方就在其中之一 → 自动收敛到自己那片，用户无感
                ZoneResolution::PreferLocal(z) => zone = Some(z),
                ZoneResolution::Unique(_) | ZoneResolution::Unknown => {}
            }
        }
    }
    if let Some(z) = zone {
        island = state.island_filter(z);
        if island.is_none() {
            state.log("warn", "socks5", format!("指定的孤岛 {} 当前没有成员，按全局处理", z.label()));
        }
    }

    // ---- 4. 选路 ----
    state.log("debug", "socks5", format!("请求 {target}"));

    let resolved = {
        let cfg = state.cfg();
        let topo = state.topology.read();
        state.rebuild_router();
        let router = state.router.read();
        let rules = state.rules.read();
        let aliases = state.aliases.read();
        let ctx = ResolveCtx {
            rules: &rules,
            topo: &topo,
            router: &router,
            self_id: state.self_id(),
            alias_table: &aliases,
            groups: &cfg.route.groups,
            default_egress: cfg.route.default_egress.as_ref(),
            island_filter: island.as_ref(),
        };
        resolver::resolve(&ctx, &target)
    };

    let resolved = match resolved {
        Ok(r) => r,
        Err(e) => {
            let code = match e {
                ResolveError::Refused => REP_NOT_ALLOWED,
                ResolveError::NoRoute => REP_HOST_UNREACH,
            };
            reply(&mut client, code).await?;
            let _ = client.shutdown().await;
            // 每台机器"没有可用网段"时的提示（§9.2 第 3 步）
            let segs = state.topology.read().segments.len();
            state.log("warn", "socks5", format!(
                "{target} 无匹配失败（当前已知网段 {segs} 个）：规则未命中，且目标不落在任何节点共享的网段内"
            ));
            return Err(SocksError::Resolve(e));
        }
    };

    match resolved.egress {
        Egress::Direct => handle_direct(state, client, target, resolved).await,
        Egress::Node(egress) => handle_overlay(state, client, target, egress, resolved).await,
    }
}

/// 本机直连（`egress = "direct"`，或者 subnet 匹配里 SELF 以成本 0 胜出）。
async fn handle_direct(
    state: Arc<HiveState>,
    mut client: TcpStream,
    target: Endpoint,
    resolved: Resolved,
) -> Result<(), SocksError> {
    state.emit(HiveEvent::StreamOpened {
        peer: state.self_id(),
        stream_id: 0,
        target: target.to_string(),
        egress: state.self_id(),
        direct: true,
        matched_rule: resolved.source.rule_index(),
    });

    // 域名在**本机**解析（这不是 SOCKS5 的 `socks5h`；`socks5h` 会把域名交给出口）。
    // ★ 解析结果可能多个（典型：`localhost` → `::1` + `127.0.0.1`），必须**逐个试**，
    // 不能只取第一个：目标只监听 IPv4 时，取到 `::1` 就会白报一个"连接被拒"。
    let addrs: Vec<SocketAddr> = match &target.host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
        Host::Name(n) => match tokio::net::lookup_host((n.as_str(), target.port)).await {
            Ok(it) => it.collect(),
            Err(_) => Vec::new(),
        },
    };
    if addrs.is_empty() {
        reply(&mut client, REP_HOST_UNREACH).await?;
        return Err(SocksError::Resolve(ResolveError::NoRoute));
    }

    let deadline = Duration::from_secs(10);
    let mut upstream: Option<TcpStream> = None;
    let mut last_err: Option<std::io::Error> = None;
    for addr in &addrs {
        match tokio::time::timeout(deadline, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                upstream = Some(s);
                break;
            }
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => last_err = None, // 超时
        }
    }
    let Some(upstream) = upstream else {
        let code = match &last_err {
            Some(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => REP_REFUSED,
            _ => REP_HOST_UNREACH,
        };
        reply(&mut client, code).await?;
        return Err(SocksError::Resolve(ResolveError::NoRoute));
    };
    upstream.set_nodelay(true).ok();

    reply(&mut client, REP_OK).await?;

    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = upstream.into_split();
    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut cr, &mut sw).await;
        let _ = sw.shutdown().await;
    });
    let down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut sr, &mut cw).await;
        let _ = cw.shutdown().await;
    });
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    Ok(())
}

/// 走 overlay：`open_stream` → 双向泵。
async fn handle_overlay(
    state: Arc<HiveState>,
    mut client: TcpStream,
    target: Endpoint,
    egress: crate::proto::NodeId,
    resolved: Resolved,
) -> Result<(), SocksError> {
    let opened = match stream::open_stream(state.clone(), target.clone(), egress, resolved.source.rule_index())
        .await
    {
        Ok(o) => o,
        Err(e) => {
            let code = match &e {
                OpenError::Refused => REP_NOT_ALLOWED,
                OpenError::NoRoute => REP_NET_UNREACH,
                OpenError::Timeout => REP_HOST_UNREACH,
                OpenError::Rejected { code, .. } => match code {
                    5 => REP_REFUSED,
                    4 => REP_HOST_UNREACH,
                    _ => REP_GENERAL,
                },
                OpenError::SelfLoop => REP_GENERAL,
            };
            reply(&mut client, code).await?;
            return Err(SocksError::Open(e));
        }
    };

    reply(&mut client, REP_OK).await?;

    let ctx = opened.ctx.clone();
    let sink = opened.sink;

    let st1 = state.clone();
    let ctx1 = ctx.clone();
    let (cr, cw) = client.into_split();
    let up = tokio::spawn(async move { stream::pump_local_to_overlay(st1, ctx1, cr).await });
    let st2 = state.clone();
    let ctx2 = ctx.clone();
    let down = tokio::spawn(async move {
        stream::pump_overlay_to_local(st2, ctx2, sink, cw).await
    });

    // 任一方向结束就收尾
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    stream::close_stream(&state, ctx.key, crate::proto::CloseReason::Normal).await;
    state.stats.active_streams.store(state.streams.len(), Ordering::Relaxed);
    Ok(())
}

/// 从目标里摘出 `z<zone>+` 前缀（§9.3 情形二）。
///
/// SOCKS5 客户端会把 `z7+10.1.2.5` 当成一个域名送过来，所以这里要重新解析一次。
fn extract_zone(target: Endpoint) -> (Endpoint, Option<zone::ZoneId>) {
    let Host::Name(n) = &target.host else { return (target, None) };
    match zone::parse_zoned_target(&format!("{}:{}", n, target.port)) {
        Ok(p) if p.zone.is_some() => (Endpoint::new(p.host, p.port), p.zone),
        _ => (target, None),
    }
}

/// 读 SOCKS5 的目标地址。
async fn read_target(c: &mut TcpStream, atyp: u8) -> Result<Endpoint, SocksError> {
    let host = match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            c.read_exact(&mut b).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            c.read_exact(&mut b).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize];
            c.read_exact(&mut b).await?;
            let name = String::from_utf8(b).map_err(|_| SocksError::BadAddressType(atyp))?;
            Host::Name(name)
        }
        other => return Err(SocksError::BadAddressType(other)),
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).await?;
    Ok(Endpoint::new(host, u16::from_be_bytes(p)))
}

/// 回 SOCKS5 应答（绑定地址一律填 0.0.0.0:0）。
async fn reply(c: &mut TcpStream, code: u8) -> Result<(), std::io::Error> {
    c.write_all(&[VER, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await?;
    c.flush().await
}

/// 供测试用：把一段请求字节喂给解析逻辑。
pub fn parse_request(ver: u8, cmd: u8, atyp: u8) -> Result<(), SocksError> {
    if ver != VER {
        return Err(SocksError::BadVersion(ver));
    }
    if cmd != CMD_CONNECT {
        return Err(SocksError::UnsupportedCommand(cmd));
    }
    if !matches!(atyp, ATYP_IPV4 | ATYP_IPV6 | ATYP_DOMAIN) {
        return Err(SocksError::BadAddressType(atyp));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{nid, state_for, topology};

    #[test]
    fn request_validation() {
        assert!(parse_request(5, 1, 1).is_ok());
        assert!(matches!(parse_request(4, 1, 1), Err(SocksError::BadVersion(4))));
        assert!(matches!(parse_request(5, 2, 1), Err(SocksError::UnsupportedCommand(2))));
        assert!(matches!(parse_request(5, 1, 9), Err(SocksError::BadAddressType(9))));
        assert!(parse_request(5, 1, 3).is_ok(), "域名类型的 CONNECT 必须支持（split-horizon DNS）");
    }

    /// 起一个 SOCKS5 服务端到环回，返回其地址。
    async fn spawn_socks(st: Arc<HiveState>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let st2 = st.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let s = st2.clone();
                tokio::spawn(async move {
                    let _ = handle_client(s, stream).await;
                });
            }
        });
        addr
    }

    async fn negotiate(c: &mut TcpStream) {
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 0]);
    }

    async fn read_reply(c: &mut TcpStream) -> u8 {
        let mut r = [0u8; 10];
        c.read_exact(&mut r).await.unwrap();
        r[1]
    }

    #[tokio::test]
    async fn direct_egress_reaches_a_local_service() {
        // 目标就是本机网段 → SELF 以成本 0 胜出 → 直连，不进 overlay
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut b = [0u8; 16];
                let n = s.read(&mut b).await.unwrap_or(0);
                let _ = s.write_all(&b[..n]).await;
            }
        });

        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg.listen.bind = "127.0.0.1".parse().unwrap();
        // 回环地址不会被当作"可共享网段"（§9.1 排除回环），所以这里显式用 direct 规则
        cfg.route.rules = vec![crate::rules::Rule::new(
            crate::rules::HostMatcher::parse("127.0.0.0/8").unwrap(),
            crate::rules::PortMatcher::Any,
            crate::rules::EgressTarget::SelfDirect,
        )];
        let st = state_for("127.0.0.1", cfg);
        st.rebuild_rules();
        let socks = spawn_socks(st).await;

        let mut c = TcpStream::connect(socks).await.unwrap();
        negotiate(&mut c).await;
        c.write_all(&[5, 1, 0, 1, 127, 0, 0, 1]).await.unwrap();
        c.write_all(&port.to_be_bytes()).await.unwrap();
        assert_eq!(read_reply(&mut c).await, REP_OK);

        c.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn block_rule_maps_to_not_allowed() {
        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg.route.rules = vec![crate::rules::Rule::new(
            crate::rules::HostMatcher::Any,
            crate::rules::PortMatcher::Any,
            crate::rules::EgressTarget::Block,
        )];
        let st = state_for("127.0.0.1", cfg);
        st.rebuild_rules();
        let socks = spawn_socks(st).await;

        let mut c = TcpStream::connect(socks).await.unwrap();
        negotiate(&mut c).await;
        c.write_all(&[5, 1, 0, 1, 10, 9, 9, 9]).await.unwrap();
        c.write_all(&80u16.to_be_bytes()).await.unwrap();
        assert_eq!(read_reply(&mut c).await, REP_NOT_ALLOWED, "block 必须回 0x02（§5.7 Refused）");
    }

    #[tokio::test]
    async fn no_route_maps_to_host_unreachable() {
        // 目标不落在任何已知网段，且没有任何规则命中
        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some("10.0.0.1".parse().unwrap());
        cfg.listen.bind = "10.0.0.1".parse().unwrap();
        let st = state_for("10.0.0.1", cfg);
        let socks = spawn_socks(st).await;

        let mut c = TcpStream::connect(socks).await.unwrap();
        negotiate(&mut c).await;
        c.write_all(&[5, 1, 0, 1, 8, 8, 8, 8]).await.unwrap();
        c.write_all(&443u16.to_be_bytes()).await.unwrap();
        assert_eq!(read_reply(&mut c).await, REP_HOST_UNREACH);
    }

    #[tokio::test]
    async fn unsupported_command_is_rejected() {
        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some("10.0.0.1".parse().unwrap());
        let st = state_for("10.0.0.1", cfg);
        let socks = spawn_socks(st).await;

        let mut c = TcpStream::connect(socks).await.unwrap();
        negotiate(&mut c).await;
        // BIND (0x02)
        c.write_all(&[5, 2, 0, 1, 10, 0, 0, 1]).await.unwrap();
        c.write_all(&80u16.to_be_bytes()).await.unwrap();
        assert_eq!(read_reply(&mut c).await, REP_CMD_UNSUPPORTED);
    }

    #[tokio::test]
    async fn non_socks_client_is_dropped() {
        let mut cfg = crate::config::Config::default();
        cfg.node.overlay_addr = Some("10.0.0.1".parse().unwrap());
        let st = state_for("10.0.0.1", cfg);
        let socks = spawn_socks(st).await;

        let mut c = TcpStream::connect(socks).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        // 服务端应当直接关连接（我们只断言不 panic 且连接结束）
        let mut buf = [0u8; 4];
        let _ = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await;
    }

    #[tokio::test]
    async fn domain_target_routes_through_the_overlay() {
        // 一条规则把域名指到远端出口，断言走的是 overlay 而不是本地解析
        let st = {
            let mut cfg = crate::config::Config::default();
            cfg.node.overlay_addr = Some("10.0.0.1".parse().unwrap());
            cfg.listen.bind = "10.0.0.1".parse().unwrap();
            cfg.egress.egress_ack_timeout_ms = 200;
            let st = state_for("10.0.0.1", cfg);
            // 让本机认识一个远端节点
            let t = topology("10.0.0.1", &[("10.0.0.1", "10.4.0.9")], &[], &[]);
            {
                let mut topo = st.topology.write();
                for (k, v) in t.adjacency {
                    topo.adjacency.insert(k, v);
                }
            }
            st.rebuild_router();
            st
        };
        {
            let mut cfg = st.cfg().as_ref().clone();
            cfg.route.rules = vec![crate::rules::Rule::new(
                crate::rules::HostMatcher::parse("*.internal.example.com").unwrap(),
                crate::rules::PortMatcher::Any,
                crate::rules::EgressTarget::Node(nid("10.4.0.9")),
            )];
            st.config.store(Arc::new(cfg));
            st.rebuild_rules();
        }

        let socks = spawn_socks(st).await;
        let mut c = TcpStream::connect(socks).await.unwrap();
        negotiate(&mut c).await;
        let name = b"api.internal.example.com";
        c.write_all(&[5, 1, 0, 3, name.len() as u8]).await.unwrap();
        c.write_all(name).await.unwrap();
        c.write_all(&443u16.to_be_bytes()).await.unwrap();

        // 拓扑上有路由、但没有真实链路 → "网络不可达"（0x03）才是正确语义；
        // 关键是它**没有退化成本地直连**（那才会是 0x00）。
        assert_eq!(read_reply(&mut c).await, REP_NET_UNREACH);
    }
}
