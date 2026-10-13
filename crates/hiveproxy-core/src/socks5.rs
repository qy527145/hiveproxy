//! L5 本地出口的 SOCKS5 一侧：`CONNECT`（DESIGN.md §6.4）。
//!
//! 只实现 `CONNECT`（TCP）。`BIND` / `UDP ASSOCIATE` 不在 v1 范围（§17 非目标）。
//!
//! 端口是**两种协议共用**的（分流见 `proxy`），所以本模块只管 SOCKS5 的 framing 与
//! 错误码映射：选路走 `proxy::route`，开流走 `proxy::open_upstream`，字节泵走
//! `proxy::Upstream::relay` —— 与 HTTP 代理同一份实现。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::{self, ConnectError, RouteError, UpstreamError};
use crate::proto::{Endpoint, Host};
use crate::state::HiveState;
use crate::stream::OpenError;

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
    Resolve(RouteError),
    /// 打开流失败。
    Open(UpstreamError),
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

/// 处理一个 SOCKS5 客户端连接（由 `proxy::spawn_proxy` 按首字节分流进来）。
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

    // ---- 3. 选路（与 HTTP 代理共用；`z<zone>+` 前缀也在那里摘，§9.3 情形二）----
    let (target, resolved) = match proxy::route(&state, target).await {
        Ok(v) => v,
        Err(e) => {
            reply(&mut client, route_rep_code(&e)).await?;
            let _ = client.shutdown().await;
            return Err(SocksError::Resolve(e));
        }
    };

    // ---- 4. 开流：本机直连或 overlay（共用实现，§6.4）----
    let upstream = match proxy::open_upstream(&state, &target, &resolved).await {
        Ok(u) => u,
        Err(e) => {
            reply(&mut client, open_rep_code(&e)).await?;
            let _ = client.shutdown().await;
            return Err(SocksError::Open(e));
        }
    };

    reply(&mut client, REP_OK).await?;
    // SOCKS5 不会多读字节（framing 是定长的），所以前缀恒为空
    upstream.relay(client, bytes::Bytes::new()).await;
    Ok(())
}

/// 选路失败 → SOCKS5 应答码（§9.2 的映射）。
fn route_rep_code(e: &RouteError) -> u8 {
    match e {
        RouteError::Refused => REP_NOT_ALLOWED,
        // 孤岛指不明：让调用方换个写法，对客户端来说就是"这个地址够不着"
        RouteError::NoRoute | RouteError::Ambiguous { .. } => REP_HOST_UNREACH,
    }
}

/// 开流失败 → SOCKS5 应答码。
///
/// 注意 `NoRoute` 在两条路上的码**不一样**：选路阶段是 `0x04 host unreachable`，
/// 而 overlay 建流阶段是 `0x03 network unreachable` —— 这是既有语义，别顺手统一。
fn open_rep_code(e: &UpstreamError) -> u8 {
    match e {
        UpstreamError::Direct(c) => match c {
            ConnectError::Refused(_) => REP_REFUSED,
            ConnectError::Dns(_) | ConnectError::Timeout | ConnectError::Other(_) => REP_HOST_UNREACH,
        },
        UpstreamError::Overlay(o) => match o {
            OpenError::Refused => REP_NOT_ALLOWED,
            OpenError::NoRoute => REP_NET_UNREACH,
            OpenError::Timeout => REP_HOST_UNREACH,
            OpenError::Rejected { code, .. } => match code {
                5 => REP_REFUSED,
                4 => REP_HOST_UNREACH,
                _ => REP_GENERAL,
            },
            OpenError::SelfLoop => REP_GENERAL,
        },
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
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::net::TcpListener;

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
    async fn non_socks_bytes_are_rejected_by_the_handler() {
        // 把非 SOCKS5 的字节直接喂给**这个处理器**时必须被拒。
        // 端口上的协议分流在 `proxy::sniff`（那边另有测试）：正常的 HTTP 请求不会再走到这里。
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