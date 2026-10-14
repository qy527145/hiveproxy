//! L5 本地出口：**一个端口两种协议**（SOCKS5 与 HTTP 代理，DESIGN.md §6.4）。
//!
//! 本模块负责三件事：
//! 1. **端口与分流**：绑 [`spawn_proxy`]，按首字节把连接交给 `socks5` 或 `http_proxy`（[`sniff`]）；
//! 2. **两个协议共用的选路**（[`route`]）：摘孤岛前缀 → 孤岛收敛 → 规则 / 网段 / 默认出口（§9.4）；
//! 3. **两个协议共用的开流与字节泵**（[`open_upstream`]、[`Upstream`]）：本机直连或 overlay 流。
//!
//! ## 为什么一个端口讲两种协议
//!
//! `curl -x 127.0.0.1:1080`（不带 scheme）与浏览器的"HTTP 代理"输入框都是 **HTTP 代理**语义 ——
//! 客户端发的是 `GET http://host/ HTTP/1.1`。原来这个端口只讲 SOCKS5，读到首字节不是 `0x05`
//! 就 drop 连接，客户端只看到一句含糊的"连接被重置"（2026-10-13 的用户反馈）。
//!
//! ## 分流规则
//!
//! 只看**首字节**，不做进一步猜测：`0x05` = SOCKS5；方法名（全大写 A–Z）+ 空格 = HTTP；
//! `0x04`（SOCKS4）、`0x16`（TLS 握手）、`PRI *`（HTTP/2 明文前言）以及其余一切
//! **都给一条看得懂的 warn 之后优雅关闭** —— 拒绝必须是可见的，这正是这次要修的东西。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::proto::{Endpoint, Host, NodeId};
use crate::resolver::{self, Egress, ResolveCtx, ResolveError, Resolved};
use crate::session::StreamCtx;
use crate::state::HiveState;
use crate::stream::{self, OpenError};
use crate::zone::{self, ZoneResolution};

/// 直连目标的超时（与构建文档 §9.4.2 一致）。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 首字节判断的最长等待：超过它还没凑够可判定的字节就按"不认识"处理（慢速发送的防护）。
pub const SNIFF_TIMEOUT: Duration = Duration::from_secs(2);

/// overlay ⇄ 字节流之间的桥接缓冲。HTTP 代理要分帧读写上游，所以借 `duplex` 把
/// "帧 + 信用"的世界挡在另一侧（`stream` 的两个泵一行都不用改）。
const BRIDGE_BUF: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// 端口与分流
// ---------------------------------------------------------------------------

/// 绑定本地代理端口。**一个端口同时讲 SOCKS5 与 HTTP 代理**。
///
/// 绑与起分开是刻意的：冷启动对绑失败是容忍的（告警、节点照起），
/// 改端口时则是全有全无 —— 两种策略由调用方选（见 `HiveNode::spawn_bound`）。
pub async fn bind_one(bind: std::net::SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(bind)
        .await
        .map_err(|e| format!("{bind} 绑定失败：{e} —— 本地应用将无法使用代理"))
}

/// 在**已经绑好**的监听器上开始服务，返回任务句柄（改端口时要 `abort` 它才能确定地释放端口）。
pub fn spawn_on(state: Arc<HiveState>, listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move { serve(state, listener).await })
}

async fn serve(state: Arc<HiveState>, listener: TcpListener) {
    let bind = state.cfg().proxy.bind;
    let allow_remote = state.cfg().proxy.allow_remote;
    let actual = listener.local_addr().unwrap_or(bind);
    *state.proxy_bound.write() = Some(actual);
    state.log("info", "proxy", format!("本地代理端口已就绪：{actual}（SOCKS5 与 HTTP 代理共用）"));
    if allow_remote && !bind.ip().is_loopback() {
        state.log("warn", "proxy", format!(
            "本地代理监听在非回环地址 {bind} 且 allow_remote = true —— \
             同网段任何人都能借用你的网络位置，HTTP 正向代理尤其容易被滥用（§11）"
        ));
    }

    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        state.log("warn", "proxy", format!("accept 失败：{e}"));
                        continue;
                    }
                };
                // ★ 每个连接现读一次配置（和 listener 的 max_links 一样），
                // 这样 `proxy.allow_remote` 改完就是**热生效** —— 否则它会被
                // 下面那次启动时的快照钉死，"界面显示改了、实际没改"。
                if !state.cfg().proxy.allow_remote && !peer.ip().is_loopback() {
                    state.log("warn", "proxy", format!(
                        "拒绝 {peer}：allow_remote = false 时本地代理只服务回环地址"
                    ));
                    continue;
                }
                let st = state.clone();
                tokio::spawn(async move { handle_conn(st, stream, peer).await });
            }
        }
    }
}

/// 一个连接上认出来的协议。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sniff {
    Socks5,
    Http,
    /// SOCKS4 —— 明确不认识，给专门的提示。
    Socks4,
    /// 直接说 TLS —— 多半是把 https 服务地址当成了代理地址。
    Tls,
    /// HTTP/2 明文前言（`PRI * HTTP/2.0`）。
    Http2Preface,
    /// 什么都不是。
    Garbage,
    /// 还没说话就断了。
    Closed,
}

impl Sniff {
    /// 给用户看的一句话。**必须说清"你该改什么"**，不能只说"未知协议"。
    pub fn hint(self) -> &'static str {
        match self {
            Sniff::Socks4 => {
                "像是 SOCKS4 客户端 —— 这里只支持 SOCKS5；请把客户端改成 socks5 / socks5h"
            }
            Sniff::Tls => {
                "像是在直接说 TLS —— 这个地址是代理端口，不是 Web 服务。\
                 请把客户端配成 HTTP 代理或 SOCKS5 代理，而不是直接把 https:// 指向它"
            }
            Sniff::Http2Preface => {
                "像是 HTTP/2 明文（h2c）—— 代理端口只讲 HTTP/1.1；\
                 走 HTTPS 时客户端会先 CONNECT，不需要 h2 prior knowledge"
            }
            Sniff::Garbage => {
                "既不是 SOCKS5 也不是 HTTP 代理请求（首字节对不上）—— \
                 请确认客户端连的是本地代理，而不是把别的协议接到了这个端口"
            }
            _ => "连接结束",
        }
    }
}

async fn handle_conn(state: Arc<HiveState>, client: TcpStream, peer: SocketAddr) {
    client.set_nodelay(true).ok();

    match sniff(&client).await {
        Sniff::Socks5 => {
            if let Err(e) = crate::socks5::handle_client(state.clone(), client).await {
                state.log("debug", "socks5", format!("连接结束：{e}"));
            }
        }
        Sniff::Http => {
            if let Err(e) = crate::http_proxy::handle_conn(state.clone(), client).await {
                state.log("debug", "http", format!("连接结束：{e}"));
            }
        }
        Sniff::Closed => {
            state.log("debug", "proxy", format!("{peer} 什么都没发就断开了"));
        }
        other => {
            // ★ 一定要 warn：debug 级在界面上是看不见的，而"被静默 drop"
            // 正是用户当初只看到"连接被重置"的原因（2026-10-13）。
            // 顺带把开头几个字节记下来 —— 认不出是什么的时候，这行字节就是唯一的线索。
            let mut peek = [0u8; 8];
            let n = client.peek(&mut peek).await.unwrap_or(0);
            let hex: Vec<String> = peek[..n].iter().map(|b| format!("{b:02x}")).collect();
            state.log("warn", "proxy", format!("{peer}：{}（首字节 {}）", other.hint(), hex.join(" ")));
            graceful_close(client).await;
        }
    }
}

/// 优雅关闭：先关写半边（发 FIN），再把对端**已经发来的**字节读掉。
///
/// 直接 drop 一个还有未读数据的 socket，内核发的是 **RST**，客户端看到的就是那句含糊的
/// "连接被重置"；把队列读干净才能让它拿到干净的 EOF。
async fn graceful_close(mut client: TcpStream) {
    let _ = client.shutdown().await;
    let mut sink = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_millis(250), async {
        loop {
            match client.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// 看首字节认出协议（用 `peek`，**不消费** —— 之后各自的处理器还要从头读）。
pub async fn sniff(client: &TcpStream) -> Sniff {
    let mut buf = [0u8; 8];
    let mut have = 0usize;
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;

    loop {
        match classify(&buf[..have]) {
            Some(s) => return s,
            None if have >= buf.len() => return Sniff::Garbage, // 8 字节里都没见空格：不可能是方法名
            None => {}
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Sniff::Garbage;
        }
        // peek 可能只返回当前已到达的部分（分片）：那就接着等剩下的
        match tokio::time::timeout(left, client.peek(&mut buf[have..])).await {
            Err(_) => return Sniff::Garbage,
            Ok(Err(_)) | Ok(Ok(0)) => return Sniff::Closed,
            Ok(Ok(n)) => have += n,
        }
    }
}

/// `None` = 现有字节还定不下来，要再等一点。
fn classify(b: &[u8]) -> Option<Sniff> {
    let first = *b.first()?;
    match first {
        0x05 => Some(Sniff::Socks5),
        0x04 => Some(Sniff::Socks4),
        0x16 => Some(Sniff::Tls),
        _ => {
            // HTTP 请求行 = 方法名（token，全大写）+ 一个空格
            let sp = b.iter().position(|&c| c == b' ')?;
            if sp == 0 || !b[..sp].iter().all(|c| c.is_ascii_uppercase()) {
                return Some(Sniff::Garbage);
            }
            if &b[..sp] == b"PRI" {
                return Some(Sniff::Http2Preface);
            }
            Some(Sniff::Http)
        }
    }
}

// ---------------------------------------------------------------------------
// 共用选路（§9.4）
// ---------------------------------------------------------------------------

/// 选路失败。
#[derive(Debug)]
pub enum RouteError {
    /// 被规则拒绝（`egress = block`，§5.7）。
    Refused,
    /// 没有可用出口。
    NoRoute,
    /// 同一个 IP 在多个孤岛里都存在，而本机不在其中任何一片。
    Ambiguous { target: Endpoint, zones: Vec<String> },
}

/// 从目标地址选出出口。两个协议共用，所以诊断日志也集中在这里发。
///
/// 返回**摘掉孤岛前缀之后**的目标 —— SOCKS5 与 HTTP 都可能把 `z7+10.1.2.5` 当域名送进来。
pub async fn route(state: &Arc<HiveState>, target: Endpoint) -> Result<(Endpoint, Resolved), RouteError> {
    let (target, mut zone) = extract_zone(target);
    let mut island: Option<std::collections::HashSet<NodeId>> = None;

    if zone.is_none() {
        if let Host::Ip(ip) = &target.host {
            let self_zone = state.self_zone();
            match state.zones.read().resolve_ip(*ip, self_zone) {
                ZoneResolution::Ambiguous(zs) => {
                    let labels: Vec<String> = zs.iter().map(|z| z.label()).collect();
                    state.log("warn", "proxy", format!(
                        "{target} 在多个孤岛里都存在（{}）—— 请用 z<zone>+{ip}:{port} 指定你要连哪一片",
                        labels.join(", "), port = target.port
                    ));
                    return Err(RouteError::Ambiguous { target, zones: labels });
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
            state.log("warn", "proxy", format!("指定的孤岛 {} 当前没有成员，按全局处理", z.label()));
        }
    }

    state.log("debug", "proxy", format!("请求 {target}"));

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

    match resolved {
        Ok(r) => Ok((target, r)),
        Err(e) => {
            // 每台机器"没有可用网段"时的提示（§9.2 第 3 步）
            let segs = state.topology.read().segments.len();
            state.log("warn", "proxy", format!(
                "{target} 无匹配失败（当前已知网段 {segs} 个）：规则未命中，且目标不落在任何节点共享的网段内"
            ));
            Err(match e {
                ResolveError::Refused => RouteError::Refused,
                ResolveError::NoRoute => RouteError::NoRoute,
            })
        }
    }
}

/// 从目标里摘出 `z<zone>+` 前缀（§9.3 情形二）。
///
/// SOCKS5 会把 `z7+10.1.2.5` 当成域名（ATYP=3）送过来，HTTP 请求行里则是
/// `GET http://z7+10.1.2.5:3306/` —— 两条路都要在这里摘掉。
pub fn extract_zone(target: Endpoint) -> (Endpoint, Option<zone::ZoneId>) {
    let Host::Name(n) = &target.host else { return (target, None) };
    match zone::parse_zoned_target(&format!("{}:{}", n, target.port)) {
        Ok(p) if p.zone.is_some() => (Endpoint::new(p.host, p.port), p.zone),
        _ => (target, None),
    }
}

// ---------------------------------------------------------------------------
// 共用开流（本机直连 或 overlay）
// ---------------------------------------------------------------------------

/// 本机直连的失败原因。
#[derive(Debug)]
pub enum ConnectError {
    /// 域名解析不出来。
    Dns(String),
    /// 目标拒绝连接。
    Refused(String),
    /// 连接超时。
    Timeout,
    /// 别的 I/O 错。
    Other(String),
}

impl ConnectError {
    /// 给日志与人看的一句话。
    pub fn why(&self) -> String {
        match self {
            Self::Dns(e) => format!("域名解析失败：{e}"),
            Self::Refused(e) => format!("连接被拒：{e}"),
            Self::Timeout => "连接超时".into(),
            Self::Other(e) => format!("连接失败：{e}"),
        }
    }
}

/// 开不出上游。
///
/// 刻意保留 `OpenError` 的原始分支：SOCKS5 的错误码映射与 HTTP 的状态码映射
/// 对"无路由 / 被拒 / 超时"的区分并不一样，不能在这里先合并掉。
#[derive(Debug)]
pub enum UpstreamError {
    /// 本机直连失败。
    Direct(ConnectError),
    /// overlay 侧失败（出口拒绝、无路由、ack 超时……）。
    Overlay(OpenError),
}

/// 一条建好的上游连接。
///
/// 统一成 `AsyncRead + AsyncWrite` 之后，HTTP 侧就能用 `tokio::io::split` / `copy` /
/// `read_until` 这些现成的东西去分帧读写，而不用为"两种上游"各写一套读写。
pub struct Upstream {
    io: Box<dyn ByteStream>,
    guard: Option<OverlayGuard>,
}

/// 只为了让 `Box<dyn …>` 能表达"既能读又能写"。
pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ByteStream for T {}

/// overlay 上游的收尾凭据：拆分后的两半各持一份克隆。
#[derive(Clone)]
pub struct OverlayGuard(Arc<HiveState>, Arc<StreamCtx>);

impl OverlayGuard {
    /// 通知对端收流，并把本地上下文摘掉。
    pub async fn close(&self) {
        stream::close_stream(&self.0, self.1.key, crate::proto::CloseReason::Normal).await;
    }
}

impl Drop for OverlayGuard {
    /// 兜底：**任何**丢掉上游的路径都要告诉对端收流，不能只在 `close()` 那条路上做。
    /// （HTTP 侧在错误路径上常常是直接 `drop(parts)`：不通知的话，对端那条流会一直挂着，
    /// 而它的本地 socket 可能还开着 —— 一个源站不动就漏一条流。）
    ///
    /// 异步动作只能在 Drop 里 spawn 出去；不在运行时上下文里（比如同步测试）就跳过。
    fn drop(&mut self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        let (state, ctx) = (self.0.clone(), self.1.clone());
        handle.spawn(async move {
            stream::close_stream(&state, ctx.key, crate::proto::CloseReason::Normal).await;
        });
    }
}

/// 上游拆开后的读写两半（HTTP 代理要边写请求体边读响应）。
pub struct UpstreamParts {
    pub rx: tokio::io::ReadHalf<Box<dyn ByteStream>>,
    pub tx: tokio::io::WriteHalf<Box<dyn ByteStream>>,
    pub guard: Option<OverlayGuard>,
}

impl Upstream {
    /// 拆成读写两半。
    pub fn into_parts(self) -> UpstreamParts {
        let (rx, tx) = tokio::io::split(self.io);
        UpstreamParts { rx, tx, guard: self.guard }
    }

    /// 把拆开的两半拼回一整条流（101 升级之后要按"盲管道"搬字节时用得上）。
    pub fn from_parts(p: UpstreamParts) -> Self {
        let UpstreamParts { rx, tx, guard } = p;
        Self { io: rx.unsplit(tx), guard }
    }

    /// 盲搬运：两个方向互相搬字节，一侧结束就整体收尾（SOCKS5 与 HTTP CONNECT 走这条）。
    ///
    /// `prefix` 是**已经读进来、但还没搬过去**的字节：解析请求头时顺手多读的那几个字节
    /// 必须先反向补上，否则隧道里的头几个字节会被吞掉。
    pub async fn relay(self, mut client: TcpStream, prefix: Bytes) {
        let Upstream { mut io, guard } = self;
        if !prefix.is_empty() && io.write_all(&prefix).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut io).await;
        if let Some(g) = guard {
            g.close().await;
        }
        let _ = client.shutdown().await;
    }
}


/// 按选路结果开一条上游：本机直连，或经 overlay。
///
/// 直连成功时会补一条 `StreamOpened` 事件（`stream_id = 0`），让「活跃流」和探测
/// 这两处也能看到本机直连（overlay 侧由 `stream::open_stream` 负责发）。
pub async fn open_upstream(
    state: &Arc<HiveState>,
    target: &Endpoint,
    resolved: &Resolved,
) -> Result<Upstream, UpstreamError> {
    match resolved.egress {
        Egress::Direct => {
            let tcp = connect_direct(target).await.map_err(UpstreamError::Direct)?;
            state.emit(crate::events::HiveEvent::StreamOpened {
                peer: state.self_id(),
                stream_id: 0,
                target: target.to_string(),
                egress: state.self_id(),
                direct: true,
                matched_rule: resolved.source.rule_index(),
            });
            Ok(Upstream { io: Box::new(tcp), guard: None })
        }
        Egress::Node(egress) => {
            let opened = stream::open_stream(
                state.clone(),
                target.clone(),
                egress,
                resolved.source.rule_index(),
            )
            .await
            .map_err(UpstreamError::Overlay)?;
            let guard = OverlayGuard(state.clone(), opened.ctx.clone());
            let io = bridge_overlay(state, opened.ctx, opened.sink);
            Ok(Upstream { io: Box::new(io), guard: Some(guard) })
        }
    }
}

/// 本机直连：域名在**本机**解析（这不是 `socks5h`），解析结果可能多个，**逐个试**。
///
/// ★ 不能只取第一个：`localhost` 通常是 `::1` + `127.0.0.1`，目标只监听 IPv4 时，
/// 取到 `::1` 就会白报一次"连接被拒"（2026-08-… 起的老毛病，2026-10-13 修）。
pub async fn connect_direct(target: &Endpoint) -> Result<TcpStream, ConnectError> {
    let addrs = stream::resolve_endpoints(target).await.map_err(ConnectError::Dns)?;

    let mut last: Option<std::io::Error> = None;
    let mut timed_out = false;
    for addr in &addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true).ok();
                return Ok(s);
            }
            Ok(Err(e)) => last = Some(e),
            Err(_) => timed_out = true,
        }
    }
    if timed_out {
        return Err(ConnectError::Timeout);
    }
    match last {
        Some(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            Err(ConnectError::Refused(e.to_string()))
        }
        Some(e) => Err(ConnectError::Other(e.to_string())),
        // 理论上不会到这（解析不出地址时上面已经返回了）
        None => Err(ConnectError::Dns("没有可用地址".into())),
    }
}

/// 把一条 overlay 流包成 `AsyncRead + AsyncWrite`：另一端挂在 `stream` 的两个既有泵上。
///
/// 这样 HTTP 代理就能用 `copy_bidirectional` / `BufReader` 这套现成的东西去分帧读写，
/// 而**信用账本仍然只有一份实现**（`stream::pump_*`）—— 桥接本身不参与流控。
fn bridge_overlay(
    state: &Arc<HiveState>,
    ctx: Arc<StreamCtx>,
    sink: tokio::sync::mpsc::Receiver<Bytes>,
) -> tokio::io::DuplexStream {
    let (mine, theirs) = tokio::io::duplex(BRIDGE_BUF);
    let (r, w) = tokio::io::split(theirs);
    tokio::spawn(stream::pump_local_to_overlay(state.clone(), ctx.clone(), r));
    tokio::spawn(stream::pump_overlay_to_local(state.clone(), ctx.clone(), sink, w));
    mine
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognises_the_two_protocols() {
        assert_eq!(classify(&[0x05, 0x01, 0x00]), Some(Sniff::Socks5));
        assert_eq!(classify(b"GET "), Some(Sniff::Http));
        assert_eq!(classify(b"CONNECT "), Some(Sniff::Http));
        // 分片：只到 "GE" 时还定不下来（还要再看有没有空格）
        assert_eq!(classify(b"GE"), None);
        assert_eq!(classify(b"G"), None);
    }

    #[test]
    fn classify_names_the_likely_mistake() {
        assert_eq!(classify(&[0x04, 0x01]), Some(Sniff::Socks4));
        assert_eq!(classify(&[0x16, 0x03, 0x01]), Some(Sniff::Tls));
        assert_eq!(classify(b"PRI * HTTP/2.0"), Some(Sniff::Http2Preface));
        // 方法名里有非大写 → 不是 HTTP 请求行
        assert_eq!(classify(b"Get /"), Some(Sniff::Garbage));
        assert_eq!(classify(b" OPENSSH"), Some(Sniff::Garbage));
        // 首字节既不是 0x05 也不是大写方法名：还得再看几个字节才能下结论
        assert_eq!(classify(&[0x00, 0xff]), None);
        assert_eq!(classify(&[0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff]), None);
    }

    #[test]
    fn hints_are_actionable() {
        // 提示必须说清"该改什么"，而不是只说"未知"
        for s in [Sniff::Socks4, Sniff::Tls, Sniff::Http2Preface, Sniff::Garbage] {
            let h = s.hint();
            assert!(h.contains("SOCKS5") || h.contains("代理"), "{s:?} 的提示太空：{h}");
        }
    }
}