//! L5 本地出口的 HTTP 代理一侧（DESIGN.md §6.4）。
//!
//! 与 SOCKS5 共用同一个端口（分流见 `proxy`），支持两件事：
//! - **`CONNECT host:port`**：打隧道（https、ssh、git-over-ssh 都走这条）；
//! - **绝对 URI 的转发**：`GET http://host/path HTTP/1.1` —— 改写请求行成 origin-form
//!   再交给上游，响应原样搬回。**支持 keep-alive**：同一条客户端连接上的多个请求
//!   可以复用同一条上游连接（键 = 目标 authority + 出口，§9.4）。
//!
//! ## 为什么要有这一侧
//!
//! `curl -x 127.0.0.1:1080`（不带 scheme）与浏览器的"HTTP 代理"输入框都是 HTTP 代理语义。
//! 端口上只有 SOCKS5 时，这类流量会被静默丢弃，用户只看到"连接被重置"（2026-10-13）。
//!
//! ## 刻意不做的事（§17 非目标）
//!
//! - **不做代理认证**：不回 407，`Proxy-Authorization` 一律**删掉不转发**（凭据绝不流向源站）。
//!   安全边界与 SOCKS5 一致：默认只服务回环地址（`proxy.allow_remote` 打开才会对外）。
//! - **不转发 `Expect: 100-continue`**：我们**自己**先回 `100 Continue` 再传请求体，
//!   这样等待 100 的客户端不会卡住，也不用处理上游的 1xx 与请求体的交错。
//! - **半双工**：请求体传完才读响应（不做"边传边读"）。源站在收完请求体前就回大响应
//!   的连接会慢一拍，但不会丢字节；这是刻意的简化。
//! - **不做 h2c**：见到 HTTP/2 明文前言直接回 400 并说明原因。

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use httparse::{Status, EMPTY_HEADER};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::{self, ConnectError, RouteError, Upstream, UpstreamError, UpstreamParts};
use crate::proto::{Endpoint, Host};
use crate::state::HiveState;
use crate::stream::OpenError;

/// 请求头 / 响应头的大小上限（超过就 431 / 关掉上游）。
const MAX_HEAD: usize = 64 * 1024;
/// 一行（chunked 的长度行等）的上限。
const MAX_LINE: usize = 8 * 1024;
/// 头部里最多认多少个字段。
const MAX_HEADERS: usize = 64;
/// 复用的上游空闲多久就丢掉（源站的 keep-alive 多半先过期）。
const IDLE_KEEPALIVE: Duration = Duration::from_secs(75);

#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    /// 已经回过 4xx/5xx，或这条连接没法继续了。
    Rejected(String),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Rejected(m) => write!(f, "{m}"),
        }
    }
}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

fn bad<T>(msg: impl Into<String>) -> Result<T, HttpError> {
    Err(HttpError::Rejected(msg.into()))
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

/// 处理一条客户端连接（可能承载多个 keep-alive 请求）。
pub async fn handle_conn(state: Arc<HiveState>, mut client: TcpStream) -> Result<(), HttpError> {
    client.set_nodelay(true).ok();
    // 客户端方向已经读进来、还没消费掉的字节（头部之后可能跟着请求体，甚至是下一个请求）
    let mut cbuf = BytesMut::with_capacity(16 * 1024);
    // 一条客户端连接内复用上游：键 = 目标 authority + 出口
    let mut pool: Option<(String, UpstreamParts, Instant)> = None;

    loop {
        // 空转太久的上游先丢掉 —— 带着一条半死的连接发请求只会换来一次 502
        if let Some((_, _, last)) = &pool {
            if last.elapsed() > IDLE_KEEPALIVE {
                pool = None;
            }
        }

        let Some(head) = read_request_head(&mut client, &mut cbuf).await? else {
            return Ok(()); // 干净收尾
        };

        // ---- CONNECT：隧道，一次性，之后这条客户端连接不再复用（§6.4）----
        if head.method.eq_ignore_ascii_case("CONNECT") {
            return connect_tunnel(state, client, cbuf, head).await;
        }

        // ---- 绝对 URI → 目标（代理只认绝对形式；origin-form 说明客户端把代理当源站用了）----
        let abs = match absolute_target(&head.target) {
            Ok(a) => a,
            Err(why) => {
                reply_error(&mut client, 400, &why).await?;
                return Ok(());
            }
        };

        // ---- 选路：**每个请求都重算**（规则、默认出口、网段都可能中途变）----
        let endpoint = Endpoint::new(abs.host.clone(), abs.port);
        let (endpoint, resolved) = match proxy::route(&state, endpoint).await {
            Ok(v) => v,
            Err(e) => {
                reply_error(&mut client, route_status(&e), &route_reason(&e)).await?;
                return Ok(());
            }
        };

        // 目标可能被 `z<zone>+` 前缀修正过，Host 头要以修正后的为准（源站不认识孤岛前缀）
        let host_header = authority_of(&endpoint, abs.default_port);

        // ---- 取上游：同 authority 且同出口才复用 ----
        let key = format!("{host_header}|{}", egress_key(&resolved.egress));
        let mut parts = match pool.take() {
            Some((k, p, _)) if k == key => p,
            Some((_, p, _)) => {
                drop(p); // 目标变了：丢掉旧上游（Drop 会通知对端收流）
                match open(state.clone(), &endpoint, &resolved).await {
                    Ok(p) => p,
                    Err((code, why)) => {
                        reply_error(&mut client, code, &why).await?;
                        return Ok(());
                    }
                }
            }
            None => match open(state.clone(), &endpoint, &resolved).await {
                Ok(p) => p,
                Err((code, why)) => {
                    reply_error(&mut client, code, &why).await?;
                    return Ok(());
                }
            },
        };

        // ---- 请求体分帧（先校验，再原样转发校验过的那一种；§6.4 的防走私规则）----
        let body = match request_body(&head) {
            Ok(b) => b,
            Err(why) => {
                reply_error(&mut client, 400, &why).await?;
                return Ok(());
            }
        };

        // ---- 请求头：改写请求行为 origin-form，去掉代理专用头 ----
        let rewritten = rewrite_request_head(&head, &abs.origin_form, &host_header);
        if parts.tx.write_all(&rewritten).await.is_err() {
            reply_error(&mut client, 502, "上游在收到请求前就断开了（keep-alive 连接可能已被源站关闭）").await?;
            return Ok(());
        }

        // 等待 100 的客户端先拿到我们合成的 100（内容由我们自己补，绝不转发 Expect）
        if body != Body::None && wants_continue(&head) {
            client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        }
        if let Err(e) = forward_body(&mut client, &mut cbuf, &body, &mut parts.tx).await {
            // 客户端自己断了，或者上游写失败：先试着把上游可能已经回来的错误响应读出来
            if e.client_gone {
                return Ok(());
            }
        }
        if parts.tx.flush().await.is_err() {
            reply_error(&mut client, 502, "上游在收到完整请求前就断开了").await?;
            return Ok(());
        }

        // ---- 响应 ----
        let mut rbuf = BytesMut::with_capacity(16 * 1024);
        let resp = loop {
            let Some(r) = read_response_head(&mut parts.rx, &mut rbuf).await? else {
                reply_error(&mut client, 502, "上游在返回响应前就断开了").await?;
                return Ok(());
            };
            if (100..200).contains(&r.status) && r.status != 101 {
                // 信息性响应（100 / 103…）：原样透传，然后继续等真正的响应
                client.write_all(&r.raw).await?;
                continue;
            }
            break r;
        };

        // 101：客户端要升级协议（WebSocket 之类）→ 之后就是字节管道，不再解析
        if resp.status == 101 {
            client.write_all(&resp.raw).await?;
            client.flush().await?;
            let up = Upstream::from_parts(parts);
            up.relay(client, cbuf.freeze()).await;
            return Ok(());
        }

        // 复用判定：客户端想不想 keep-alive、响应结束得是否精确、上游是否说了 close
        let client_keepalive = client_wants_keepalive(&head);
        let upstream_close = says_close(&resp.headers);
        let framing = response_body(&resp, &head.method);
        let reuse = framing != RespBody::UntilEof
            && !upstream_close
            && resp.version == 1; // HTTP/1.0 的上游默认会关连接
        let keep_client = client_keepalive && !upstream_close && framing != RespBody::UntilEof;

        // 响应头重建：去掉逐跳的代理头，自己声明这一跳的 Connection
        let rebuilt = rebuild_response_head(&resp, if keep_client { "keep-alive" } else { "close" });
        client.write_all(&rebuilt).await?;

        if let Err(e) = relay_response_body(&mut parts.rx, &mut rbuf, framing, &mut client).await {
            // 响应搬到一半断了：状态码已经发出去，改不了 —— 只能关掉客户端连接（唯一诚实的做法）
            state.log("warn", "http", format!("{host_header} 的响应搬到一半中断：{e}"));
            return Ok(());
        }
        client.flush().await?;

        if keep_client && reuse {
            pool = Some((key, parts, Instant::now()));
            continue;
        }
        drop(parts);
        if !keep_client {
            // 明确告诉客户端"这条连接到此为止"（有些客户端在 EOF 上会犹豫）
            let _ = client.shutdown().await;
            return Ok(());
        }
        // 客户端还想复用，只是上游不能复用：换一条上游继续（对客户端无感）
    }
}

/// 建一条上游，并把失败翻译成"HTTP 状态码 + 人话"。
async fn open(
    state: Arc<HiveState>,
    endpoint: &Endpoint,
    resolved: &crate::resolver::Resolved,
) -> Result<UpstreamParts, (u16, String)> {
    match proxy::open_upstream(&state, endpoint, resolved).await {
        Ok(u) => Ok(u.into_parts()),
        Err(e) => Err((upstream_status(&e), upstream_reason(&e))),
    }
}

/// `CONNECT` 隧道：选路 → 建流 → 回 200 → 之后就是字节管道。
async fn connect_tunnel(
    state: Arc<HiveState>,
    mut client: TcpStream,
    cbuf: BytesMut,
    head: ReqHead,
) -> Result<(), HttpError> {
    let Some((host, port)) = parse_host_port(&head.target, 0) else {
        reply_error(&mut client, 400, "CONNECT 的目标必须写成 host:port").await?;
        return Ok(());
    };
    let endpoint = Endpoint::new(host, port);
    let (endpoint, resolved) = match proxy::route(&state, endpoint).await {
        Ok(v) => v,
        Err(e) => {
            reply_error(&mut client, route_status(&e), &route_reason(&e)).await?;
            return Ok(());
        }
    };
    let upstream = match proxy::open_upstream(&state, &endpoint, &resolved).await {
        Ok(u) => u,
        Err(e) => {
            reply_error(&mut client, upstream_status(&e), &upstream_reason(&e)).await?;
            return Ok(());
        }
    };

    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    client.flush().await?;
    // 客户端可能在等 200 的同时就把隧道里的第一批字节发过来了，一并搬过去
    upstream.relay(client, cbuf.freeze()).await;
    Ok(())
}

fn egress_key(e: &crate::resolver::Egress) -> String {
    match e {
        crate::resolver::Egress::Direct => "direct".to_string(),
        crate::resolver::Egress::Node(n) => n.to_string(),
    }
}

// ---------------------------------------------------------------------------
// 错误 → 状态码（与 SOCKS5 的错误码是同一套判断，见 socks5::open_rep_code）
// ---------------------------------------------------------------------------

fn route_status(e: &RouteError) -> u16 {
    match e {
        RouteError::Refused => 403,
        RouteError::NoRoute | RouteError::Ambiguous { .. } => 502,
    }
}

fn route_reason(e: &RouteError) -> String {
    match e {
        RouteError::Refused => "被本地规则拒绝（egress = block）".to_string(),
        RouteError::NoRoute => {
            "没有可用出口：规则未命中，目标也不在任何节点共享的网段内；默认出口没配，或者当前还够不到（拓扑可能尚未收敛）".to_string()
        }
        RouteError::Ambiguous { target, zones } => format!(
            "{target} 在多个孤岛里都存在（{}）—— 请用 z<zone>+<ip>:<port> 指定连哪一片",
            zones.join(", ")
        ),
    }
}

fn upstream_status(e: &UpstreamError) -> u16 {
    match e {
        UpstreamError::Direct(c) => match c {
            ConnectError::Timeout => 504,
            _ => 502,
        },
        UpstreamError::Overlay(o) => match o {
            OpenError::Refused => 403,
            OpenError::Timeout => 504,
            OpenError::Rejected { code, .. } if *code == 6 => 504,
            _ => 502,
        },
    }
}

fn upstream_reason(e: &UpstreamError) -> String {
    match e {
        UpstreamError::Direct(c) => c.why(),
        UpstreamError::Overlay(o) => match o {
            OpenError::Refused => "出口拒绝：规则不允许这个目标（egress = block）".to_string(),
            OpenError::NoRoute => "没有到出口节点的路由".to_string(),
            OpenError::Timeout => "出口节点没有在超时内回应".to_string(),
            OpenError::Rejected { code, reason } => {
                format!("出口侧连不上目标（code {code}）：{reason}")
            }
            OpenError::SelfLoop => "出口就是自己（不该发生）".to_string(),
        },
    }
}

/// 回一个短小的文本错误（比"连接被重置"信息量大得多）。
async fn reply_error<W: AsyncWrite + Unpin>(
    client: &mut W,
    status: u16,
    reason: &str,
) -> std::io::Result<()> {
    let body = format!("{reason}\n");
    let head = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        status_title(status),
        body.len()
    );
    client.write_all(head.as_bytes()).await?;
    client.write_all(body.as_bytes()).await?;
    client.flush().await
}

fn status_title(s: u16) -> &'static str {
    match s {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

// ---------------------------------------------------------------------------
// 报文解析
// ---------------------------------------------------------------------------

/// 请求头。
struct ReqHead {
    method: String,
    target: String,
    /// 0 = HTTP/1.0，1 = HTTP/1.1
    version: u8,
    headers: Vec<(String, String)>,
}

/// 响应头。
struct RespHead {
    status: u16,
    reason: String,
    version: u8,
    headers: Vec<(String, String)>,
    /// 原始头字节（1xx 与 101 要**原样**透传，不能重建）
    raw: Bytes,
}

fn collect_headers<'a, I>(headers: I) -> Vec<(String, String)>
where
    I: Iterator<Item = (String, &'a [u8])>,
{
    headers
        .map(|(n, v)| (n, String::from_utf8_lossy(v).into_owned()))
        .collect()
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn header_all<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

fn says_close(headers: &[(String, String)]) -> bool {
    header(headers, "connection")
        .map(|v| v.to_ascii_lowercase().contains("close"))
        .unwrap_or(false)
}

fn client_wants_keepalive(req: &ReqHead) -> bool {
    let conn = header(&req.headers, "connection").map(|v| v.to_ascii_lowercase());
    match req.version {
        0 => conn.map(|c| c.contains("keep-alive")).unwrap_or(false),
        _ => !conn.map(|c| c.contains("close")).unwrap_or(false),
    }
}

fn wants_continue(req: &ReqHead) -> bool {
    header(&req.headers, "expect")
        .map(|v| v.to_ascii_lowercase().contains("100-continue"))
        .unwrap_or(false)
}

/// 读一个请求头。`Ok(None)` = 对端在请求边界上干净收尾。
async fn read_request_head<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut BytesMut,
) -> Result<Option<ReqHead>, HttpError> {
    loop {
        let complete = {
            let mut headers = [EMPTY_HEADER; MAX_HEADERS];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(buf) {
                Ok(Status::Complete(n)) => Some((
                    n,
                    ReqHead {
                        method: req.method.unwrap_or_default().to_string(),
                        target: req.path.unwrap_or_default().to_string(),
                        version: req.version.unwrap_or(1),
                        headers: collect_headers(
                            req.headers.iter().map(|h| (h.name.to_string(), h.value)),
                        ),
                    },
                )),
                Ok(Status::Partial) => None,
                Err(e) => {
                    return bad(format!(
                        "HTTP 请求头解析失败：{e}。\
                         （这里是代理端口：请求必须是绝对 URI 形式 `GET http://主机/路径` 或 `CONNECT 主机:端口`；\
                         如果是 HTTP/2 明文（h2c）客户端，请改用 HTTP/1.1）"
                    ))
                }
            }
        };
        if let Some((n, head)) = complete {
            buf.advance(n);
            return Ok(Some(head));
        }
        if buf.len() > MAX_HEAD {
            return bad("请求头太大");
        }
        if io.read_buf(buf).await? == 0 {
            return Ok(None);
        }
    }
}

/// 读一个响应头。`Ok(None)` = 上游收尾。
async fn read_response_head<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut BytesMut,
) -> Result<Option<RespHead>, HttpError> {
    loop {
        let complete = {
            let mut headers = [EMPTY_HEADER; MAX_HEADERS];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(buf) {
                Ok(Status::Complete(n)) => {
                    let raw = Bytes::copy_from_slice(&buf[..n]);
                    Some((
                        n,
                        RespHead {
                            status: resp.code.unwrap_or(0),
                            reason: resp.reason.unwrap_or_default().to_string(),
                            version: resp.version.unwrap_or(1),
                            headers: collect_headers(
                                resp.headers.iter().map(|h| (h.name.to_string(), h.value)),
                            ),
                            raw,
                        },
                    ))
                }
                Ok(Status::Partial) => None,
                Err(e) => return bad(format!("上游响应头解析失败：{e}")),
            }
        };
        if let Some((n, head)) = complete {
            buf.advance(n);
            return Ok(Some(head));
        }
        if buf.len() > MAX_HEAD {
            return bad("上游响应头太大");
        }
        if io.read_buf(buf).await? == 0 {
            return Ok(None);
        }
    }
}

/// 绝对 URI 的解析结果。
#[derive(Debug)]
struct AbsTarget {
    host: Host,
    port: u16,
    /// 端口是否显式写在 URI 里（决定 Host 头要不要带端口）
    default_port: u16,
    /// 转发给源站的 origin-form（含查询串）
    origin_form: String,
}

fn absolute_target(target: &str) -> Result<AbsTarget, String> {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Err(
            "https 不能这样走正向代理：请让客户端用 CONNECT（curl 与浏览器对 https 都会自动这么做）"
                .to_string(),
        );
    }
    let Some(rest) = target.strip_prefix("http://").or_else(|| target.get(7..).filter(|_| lower.starts_with("http://"))) else {
        return Err(
            "这是代理端口，不是 Web 服务：请求必须用绝对 URI（`GET http://主机/路径`）或 `CONNECT 主机:端口`。\
             浏览器请把「HTTP 代理」与「HTTPS 代理」都指向这个地址。"
                .to_string(),
        );
    };
    // 去掉 userinfo（凭据不该流向源站，也不该出现在日志里）
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let mut authority = &rest[..authority_end];
    if let Some(at) = authority.rfind('@') {
        authority = &authority[at + 1..];
    }
    let Some((host, port)) = parse_host_port(authority, 80) else {
        return Err(format!("目标主机不合法：{authority}"));
    };
    let tail = &rest[authority_end..];
    let origin_form = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}") // `http://host?q` 这种写法
    };
    Ok(AbsTarget { host, port, default_port: 80, origin_form })
}

/// 解析 `host[:port]`，支持 `[v6]:port`。`default_port = 0` 表示必须带端口。
fn parse_host_port(auth: &str, default_port: u16) -> Option<(Host, u16)> {
    if auth.is_empty() {
        return None;
    }
    if let Some(rest) = auth.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let ip: std::net::Ipv6Addr = h.parse().ok()?;
        let port = match tail {
            "" if default_port != 0 => default_port,
            _ => tail.strip_prefix(':')?.parse().ok()?,
        };
        return Some((Host::Ip(std::net::IpAddr::V6(ip)), port));
    }
    // 没加方括号的冒号 = 端口分隔符；未加方括号的 IPv6 只能拒绝
    match auth.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port = p.parse().ok()?;
            Some((parse_host(h)?, port))
        }
        Some(_) => None,
        None if default_port != 0 => Some((parse_host(auth)?, default_port)),
        None => None,
    }
}

fn parse_host(h: &str) -> Option<Host> {
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return Some(Host::Ip(ip));
    }
    if h.is_empty() || h.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return None;
    }
    Some(Host::Name(h.to_string()))
}

/// 由 `Endpoint` 还原 `Host` 头的值（IPv6 要带方括号）。
fn authority_of(ep: &Endpoint, default_port: u16) -> String {
    let host = match &ep.host {
        Host::Ip(std::net::IpAddr::V6(v6)) => format!("[{v6}]"),
        Host::Ip(std::net::IpAddr::V4(v4)) => v4.to_string(),
        Host::Name(n) => n.clone(),
    };
    if ep.port == default_port {
        host
    } else {
        format!("{host}:{}", ep.port)
    }
}

// ---------------------------------------------------------------------------
// 分帧
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Body {
    None,
    Length(u64),
    Chunked,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RespBody {
    None,
    Length(u64),
    Chunked,
    /// 没有长度也没有 chunked：只能读到连接结束（这条上游也就不能复用了）。
    UntilEof,
}

/// 请求体的分帧。**矛盾就拒绝**（请求走私的经典手法，§17 风险）：宁可回 400，
/// 也不转发一个我们没完全校验过的分帧。
fn request_body(req: &ReqHead) -> Result<Body, String> {
    let cls: Vec<u64> = {
        let mut v = Vec::new();
        for c in header_all(&req.headers, "content-length") {
            v.push(
                c.trim()
                    .parse::<u64>()
                    .map_err(|_| format!("Content-Length 不是数字：{c}"))?,
            );
        }
        v
    };
    let te = header(&req.headers, "transfer-encoding").map(|v| v.trim().to_ascii_lowercase());

    if te.is_some() && !cls.is_empty() {
        return Err(
            "请求同时带 Content-Length 与 Transfer-Encoding —— 分帧矛盾，代理拒绝转发（防请求走私）"
                .to_string(),
        );
    }
    if let Some(t) = te {
        return match t.as_str() {
            "chunked" => Ok(Body::Chunked),
            other => Err(format!(
                "不支持的 Transfer-Encoding：{other}（只支持 chunked；压缩等编码请由端点自己协商）"
            )),
        };
    }
    if cls.is_empty() {
        return Ok(Body::None);
    }
    if cls.windows(2).any(|w| w[0] != w[1]) {
        return Err("Content-Length 出现了互相矛盾的多个值".to_string());
    }
    Ok(if cls[0] == 0 { Body::None } else { Body::Length(cls[0]) })
}

fn response_body(resp: &RespHead, method: &str) -> RespBody {
    if method.eq_ignore_ascii_case("HEAD")
        || resp.status == 204
        || resp.status == 304
        || (100..200).contains(&resp.status)
    {
        return RespBody::None;
    }
    if let Some(te) = header(&resp.headers, "transfer-encoding") {
        return if te.to_ascii_lowercase().contains("chunked") {
            RespBody::Chunked
        } else {
            RespBody::UntilEof
        };
    }
    if let Some(cl) = header(&resp.headers, "content-length") {
        if let Ok(n) = cl.trim().parse::<u64>() {
            return RespBody::Length(n);
        }
    }
    RespBody::UntilEof
}

/// 改写请求头：请求行换成 origin-form，去掉代理专用头，必要时补 `Host`。
fn rewrite_request_head(req: &ReqHead, origin_form: &str, host_header: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(format!("{} {} HTTP/1.{}\r\n", req.method, origin_form, req.version).as_bytes());
    let mut has_host = false;
    for (n, v) in &req.headers {
        let ln = n.to_ascii_lowercase();
        // Proxy-* 是这一跳的私有语义，Expect 由我们自己回 100（见模块文档）
        if ln.starts_with("proxy-") || ln == "expect" {
            continue;
        }
        if ln == "host" {
            has_host = true;
        }
        out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
    }
    if !has_host {
        out.extend_from_slice(format!("Host: {host_header}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// 重建响应头：去掉逐跳的代理头，并由**我们**声明这一跳的 `Connection`
/// （客户端还要不要复用这条连接，只有我们知道）。
fn rebuild_response_head(resp: &RespHead, connection: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(
        format!("HTTP/1.{} {} {}\r\n", resp.version, resp.status, resp.reason).as_bytes(),
    );
    for (n, v) in &resp.headers {
        let ln = n.to_ascii_lowercase();
        if ln.starts_with("proxy-") || ln == "connection" || ln == "keep-alive" {
            continue;
        }
        out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Connection: {connection}\r\n\r\n").as_bytes());
    out
}

// ---------------------------------------------------------------------------
// 字节搬运（一律原样透传，只按分帧确定边界）
// ---------------------------------------------------------------------------

/// 从 `io` 精确搬 `n` 字节到 `w`（先把 `buf` 里已读的吐出去）。
async fn copy_exact<R, W>(io: &mut R, buf: &mut BytesMut, n: u64, w: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut left = n;
    while left > 0 {
        if buf.is_empty() && io.read_buf(buf).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "报文声明的长度还没读完，对端就断了",
            ));
        }
        let take = (left as usize).min(buf.len());
        let chunk = buf.split_to(take);
        w.write_all(&chunk).await?;
        left -= take as u64;
    }
    Ok(())
}

/// 一直搬到对端收尾（响应既没有 Content-Length 也没有 chunked 时用）。
async fn copy_until_eof<R, W>(io: &mut R, buf: &mut BytesMut, w: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while !buf.is_empty() || io.read_buf(buf).await? > 0 {
        if buf.is_empty() {
            break;
        }
        let chunk = buf.split();
        w.write_all(&chunk).await?;
    }
    Ok(())
}

/// chunked 体**原样**透传：长度行、块数据、终止块与 trailer 一个字节都不改，
/// 只是靠解析长度行确定"体在哪里结束"（下一个请求/响应的起点）。
async fn copy_chunked<R, W>(io: &mut R, buf: &mut BytesMut, w: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let line = read_line(io, buf, MAX_LINE).await?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "chunked 体中途结束")
        })?;
        let size = parse_chunk_size(&line)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "块长度不是十六进制"))?;
        w.write_all(&line).await?;
        if size == 0 {
            // 终止块之后是 trailer，直到一个空行为止
            loop {
                let Some(l) = read_line(io, buf, MAX_HEAD).await? else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "chunked 体的 trailer 中途结束",
                    ));
                };
                let empty = l == b"\r\n";
                w.write_all(&l).await?;
                if empty {
                    return Ok(());
                }
            }
        }
        copy_exact(io, buf, size + 2, w).await?; // 块数据 + 结尾 CRLF
    }
}

/// 读一行（含 `\r\n`）。`Ok(None)` = 还没读到行就结束了。
async fn read_line<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut BytesMut,
    max: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    loop {
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf.split_to(pos + 2);
            return Ok(Some(line.to_vec()));
        }
        if buf.len() > max {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "行太长"));
        }
        if io.read_buf(buf).await? == 0 {
            return Ok(None);
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(line).ok()?;
    let s = s.trim_end_matches(['\r', '\n']);
    let hex = s.split(';').next()?.trim();
    u64::from_str_radix(hex, 16).ok()
}

/// 搬运请求体的结果：客户端走了的话就不必再往下走了。
struct BodyForward {
    client_gone: bool,
}

async fn forward_body(
    client: &mut TcpStream,
    cbuf: &mut BytesMut,
    body: &Body,
    tx: &mut tokio::io::WriteHalf<Box<dyn proxy::ByteStream>>,
) -> Result<(), BodyForward> {
    let r = match body {
        Body::None => Ok(()),
        Body::Length(n) => copy_exact(client, cbuf, *n, tx).await,
        Body::Chunked => copy_chunked(client, cbuf, tx).await,
    };
    match r {
        Ok(()) => Ok(()),
        Err(e) => {
            // 读客户端失败 = 客户端走了；写上游失败 = 上游断了（还可能带着一个错误响应）
            Err(BodyForward { client_gone: e.kind() == std::io::ErrorKind::UnexpectedEof && cbuf.is_empty() })
        }
    }
}

async fn relay_response_body<R, W>(
    rx: &mut R,
    rbuf: &mut BytesMut,
    framing: RespBody,
    client: &mut W,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        RespBody::None => Ok(()),
        RespBody::Length(n) => copy_exact(rx, rbuf, n, client).await,
        RespBody::Chunked => copy_chunked(rx, rbuf, client).await,
        RespBody::UntilEof => copy_until_eof(rx, rbuf, client).await,
    }
}

#[cfg(test)]
#[path = "http_proxy_tests.rs"]
mod tests;