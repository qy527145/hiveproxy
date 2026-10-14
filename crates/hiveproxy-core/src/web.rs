//! Web 界面（docs/WEBUI.md）。给**无界面的机器**用：引擎照常跑，额外开一个 HTTP 服务，
//! 浏览器里打开就是桌面端那一份界面。
//!
//! 三件事决定了这个文件的结构：
//!
//! 1. **它只由 `hiveproxy-cli` 启动**。桌面端（Tauri）从不调 `spawn` ——
//!    "只做 CLI 侧"是一条代码上的硬边界，不是约定。
//! 2. **它的生命周期与引擎无关**（`ServiceHandle`）。引擎起不来或正在重建时，
//!    界面照样打得开 —— 无界面机器上最容易卡死的就是"配置改坏了、引擎起不来、
//!    终端里只能干瞪眼"。
//! 3. **命令的实现全在 `crate::api`**。这里只有一张路由表，端点名与 Tauri 命令名逐字相同，
//!    参数形状就是 `invoke` 的 args。`routes_match_the_tauri_commands` 那条测试钉住这件事。
//!
//! HTTP/1.1 是手写的（复用已有的 `httparse`），**不引入任何新依赖** ——
//! 本机 crates.io 出口不稳，而且 core 一直保持依赖精简。要的东西只有：
//! 增量解析请求头、按行写响应、SSE、一张静态文件表，这几样各几十行。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::api;
use crate::config::Config;
use crate::rules::RawRule;
use crate::service::ServiceHandle;

mod assets {
    include!(concat!(env!("OUT_DIR"), "/assets.rs"));
}

/// 会话默认寿命（滑动续期）。够长到"开着标签页放一晚上"，又不至于永久有效。
const SESSION_TTL_SECS: u64 = 12 * 3600;
/// 请求头上限。超过就是有人在灌垃圾，直接断。
const MAX_HEADER_BYTES: usize = 32 * 1024;
/// 请求体上限。最大的一份是整份配置或规则表，几 MB 绰绰有余。
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// SSE 心跳间隔。反代与浏览器都会掐掉"太久没动静"的连接。
const SSE_PING_SECS: u64 = 15;

// ---------------------------------------------------------------------------
// 启动句柄
// ---------------------------------------------------------------------------

pub struct WebHandle {
    /// 实际绑定的地址（`bind` 配 0 端口时由系统分配）。
    pub addr: SocketAddr,
    /// **首次**启动时生成的一次性令牌，供 CLI 打印一次。已经改过令牌就是 `None`。
    pub initial_token: Option<String>,
    /// 令牌还是初始的那个 —— 界面会强制用户改掉（docs/WEBUI.md §6.1）。
    pub must_change: bool,
    /// 这台机器上**别人够得着**的地址（已排掉虚拟网卡与排除段）。
    ips: Vec<IpAddr>,
    cancel: CancellationToken,
}

impl WebHandle {
    /// 浏览器里能打开它的地址。把本机所有可用地址都列出来，
    /// 是因为"我该输哪个 IP"是无界面机器上第一个会卡住人的问题。
    pub fn urls(&self) -> Vec<String> {
        let port = self.addr.port();
        let mut v: Vec<String> = self.ips.iter().map(|ip| format!("http://{ip}:{port}/")).collect();
        if self.addr.ip().is_loopback() || v.is_empty() {
            v.push(format!("http://127.0.0.1:{port}/"));
        }
        v
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

/// `IpAddr` 上没有 `is_link_local`（只有 `Ipv4Addr` 有），两边补一下。
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// 这台机器上"别人够得着"的地址。
///
/// ★ 必须走排除表（`share.subnet_deny*`），不能直接列网卡：Clash / sing-box 这类工具的
/// TUN 假地址池默认落在 `198.18.0.0/15`，本机一定会有这么一个地址 ——
/// 把它打印成"打开这个地址"等于指路到一个谁都够不着的地方（§9.1 的同一个坑）。
/// 排除后一个都不剩时退回未过滤的那份：宁可挑个可疑的，也比不打印强。
fn reachable_ips(cfg: &Config) -> Vec<IpAddr> {
    let deny_cidrs = cfg.share.deny_cidrs();
    let deny_ifaces = cfg.share.deny_ifaces();
    let ifaces = crate::net::list_interfaces();

    let pick = |filtered: bool| -> Vec<IpAddr> {
        let mut v: Vec<IpAddr> = ifaces
            .iter()
            .filter(|i| !i.is_loopback && !is_link_local(i.ip))
            .filter(|i| {
                !filtered
                    || (!crate::net::iface_denied(&i.name, &deny_ifaces)
                        && !deny_cidrs.iter().any(|d| d.contains(&i.ip)))
            })
            .map(|i| i.ip)
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let clean = pick(true);
    if clean.is_empty() {
        pick(false)
    } else {
        clean
    }
}

/// 起一个 web 服务。
///
/// - `assets_dir`：`Some` 时界面从磁盘读（开发用，改完 `bun run build` 刷新即可），
///   `None` 时用编译期内嵌的那份。
pub async fn spawn(
    handle: Arc<ServiceHandle>,
    cfg: &Config,
    assets_dir: Option<PathBuf>,
) -> Result<WebHandle, String> {
    let (auth, initial_token) = Auth::load_or_init(&handle.base_dir())?;
    let must_change = auth.must_change();

    let listener = TcpListener::bind(cfg.web.bind)
        .await
        .map_err(|e| format!("web.bind = {} 绑定失败：{e}", cfg.web.bind))?;
    let addr = listener.local_addr().unwrap_or(cfg.web.bind);

    let cancel = CancellationToken::new();
    let ctx = Arc::new(Ctx {
        handle,
        auth,
        assets_dir,
        allowed_hosts: cfg.web.allowed_hosts.clone(),
        limiter: Limiter::default(),
    });

    {
        let ctx = ctx.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    r = listener.accept() => {
                        let Ok((stream, peer)) = r else { continue };
                        let ctx = ctx.clone();
                        let cancel = cancel.clone();
                        tokio::spawn(async move { serve_conn(ctx, stream, peer, cancel).await });
                    }
                }
            }
        });
    }

    Ok(WebHandle { addr, initial_token, must_change, ips: reachable_ips(cfg), cancel })
}

struct Ctx {
    handle: Arc<ServiceHandle>,
    auth: Arc<Auth>,
    assets_dir: Option<PathBuf>,
    allowed_hosts: Vec<String>,
    limiter: Limiter,
}

// ---------------------------------------------------------------------------
// 令牌与会话
// ---------------------------------------------------------------------------

/// `data/web_auth.json`（0600）。**只存令牌的哈希**，从不存明文。
#[derive(Serialize, Deserialize, Default)]
struct AuthFile {
    /// 十六进制盐。每个部署一份。
    salt: String,
    /// `sha256(salt ‖ token)`。
    token_hash: String,
    /// 令牌还是启动时生成的那个 —— 界面会强制改掉。
    must_change: bool,
    /// 会话 cookie 的签名密钥。**与引擎无关**，所以引擎重建不掉登录态。
    session_secret: String,
    changed_at: Option<u64>,
}

struct Auth {
    path: PathBuf,
    state: parking_lot::RwLock<AuthFile>,
}

impl Auth {
    /// 读令牌文件；不存在就生成一份，并把**明文令牌**返回给调用方打印一次。
    fn load_or_init(base_dir: &Path) -> Result<(Arc<Self>, Option<String>), String> {
        let path = crate::persist::data_dir(base_dir).join("web_auth.json");
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(f) = serde_json::from_str::<AuthFile>(&text) {
                if !f.token_hash.is_empty() && !f.session_secret.is_empty() {
                    return Ok((Arc::new(Self { path, state: parking_lot::RwLock::new(f) }), None));
                }
            }
        }

        let token = generate_token();
        let f = AuthFile {
            salt: hex(&rand_bytes(16)),
            token_hash: String::new(),
            must_change: true,
            session_secret: hex(&rand_bytes(32)),
            changed_at: None,
        };
        let mut f = f;
        // ★ 存的是**归一化之后**那份的哈希：`verify` 也会先归一化（去分隔符、大小写、
        // Crockford 那几个易混字母）。不这么做的话，界面上照抄回来的令牌会永远校验不过 ——
        // 而这个测试第一版就是这么红的。
        f.token_hash = hex(&sha256_cat(&f.salt, &normalize_token(&token)));
        write_secret(&path, &f)?;
        Ok((Arc::new(Self { path, state: parking_lot::RwLock::new(f) }), Some(token)))
    }

    fn must_change(&self) -> bool {
        self.state.read().must_change
    }

    /// 校验令牌（常量时间比较）。输入容忍大小写、破折号与空格。
    fn verify(&self, token: &str) -> bool {
        let norm = normalize_token(token);
        if norm.is_empty() {
            return false;
        }
        let f = self.state.read();
        let want = match hex_decode(&f.token_hash) {
            Some(v) => v,
            None => return false,
        };
        ct_eq(&sha256_cat(&f.salt, &norm), &want)
    }

    /// 换令牌。`must_change` 随之落地 —— 用户自己设的令牌不再强制更换。
    fn set_token(&self, new: &str) -> Result<(), String> {
        let norm = normalize_token(new);
        if norm.chars().count() < 8 {
            return Err("新令牌太短：至少 8 位（建议直接用界面生成的随机串）".into());
        }
        let mut f = self.state.write();
        f.token_hash = hex(&sha256_cat(&f.salt, &norm));
        f.must_change = false;
        f.changed_at = Some(crate::events::now_unix());
        write_secret(&self.path, &f)
    }

    /// 造一个会话 cookie 值：`<过期时间>.<签名>`。签名覆盖过期时间，改不了也续不了。
    fn issue_session(&self, now: u64) -> String {
        let exp = now + SESSION_TTL_SECS;
        let secret = self.state.read().session_secret.clone();
        format!("{exp}.{}", hex(&hmac_sha256(&secret, &exp.to_string())))
    }

    fn session_valid(&self, cookie: &str, now: u64) -> bool {
        let Some((exp, sig)) = cookie.split_once('.') else { return false };
        let Ok(exp) = exp.parse::<u64>() else { return false };
        if exp < now {
            return false;
        }
        let secret = self.state.read().session_secret.clone();
        ct_eq(
            &hmac_sha256(&secret, &exp.to_string()),
            &hex_decode(sig).unwrap_or_default(),
        )
    }

    fn changed_at(&self) -> Option<u64> {
        self.state.read().changed_at
    }
}

fn write_secret(path: &Path, f: &AuthFile) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败：{e}"))?;
    }
    let text = serde_json::to_string_pretty(f).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("写 {} 失败：{e}", path.display()))?;
    // ★ 令牌文件的权限必须是 0600：它虽然不含明文，但含哈希与会话签名密钥，
    // 落到同机的别的用户手里等于把会话伪造权给出去了。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// 生成一次性令牌：12 字节（96 bit）→ Crockford base32 → `XXXX-XXXX-XXXX-XXXX-XXXX`。
///
/// 96 bit 对"监听局域网 + 登录限速"这个场景足够；分组是为了让人能照抄不抄错。
fn generate_token() -> String {
    let bytes = rand_bytes(12);
    let s = base32(&bytes);
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// 容忍人手输：大小写、破折号、空格，以及 Crockford 那几个"看着像"的字母。
fn normalize_token(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t' | '_'))
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            o => o,
        })
        .collect()
}

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(CROCKFORD[((acc >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn rand_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn sha256_cat(salt: &str, token: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(token.as_bytes());
    h.finalize().to_vec()
}

fn hmac_sha256(key: &str, msg: &str) -> Vec<u8> {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes())
        .expect("HMAC 接受任意长度密钥");
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex(v: &[u8]) -> String {
    let mut s = String::with_capacity(v.len() * 2);
    for b in v {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// 常量时间比较。令牌与签名都走它 —— 提前返回的 `==` 会把比较次数漏成时间信号。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

// ---------------------------------------------------------------------------
// 登录限速
// ---------------------------------------------------------------------------

/// 同一个来源**连续失败到第 N 次之后**才退避（1s / 2s / 4s …，上限 30s）。
///
/// 令牌有 96 bit，撞库本身不现实；这条挡的是"脚本一直试"把日志刷满，
/// 以及给运维一个"有人在撞我"的信号。
///
/// ★ **前两次失败不锁**：人输错一次令牌是常态，第一次输错就锁两秒的话，
/// 用户看到的是"我明明改对了它还说太频繁"—— 会以为界面坏了。
const FREE_MISSES: u32 = 2;

#[derive(Default)]
struct Limiter {
    inner: parking_lot::Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Limiter {
    fn blocked_for(&self, ip: IpAddr) -> Option<u64> {
        let g = self.inner.lock();
        let (fails, until) = g.get(&ip)?;
        if *fails <= FREE_MISSES {
            return None;
        }
        let now = Instant::now();
        if *until > now {
            Some((*until - now).as_secs() + 1)
        } else {
            None
        }
    }

    fn note_failure(&self, ip: IpAddr) -> u32 {
        let mut g = self.inner.lock();
        let e = g.entry(ip).or_insert((0, Instant::now()));
        e.0 = e.0.saturating_add(1);
        if e.0 > FREE_MISSES {
            let backoff = Duration::from_secs((1u64 << (e.0 - FREE_MISSES - 1).min(5)).min(30));
            e.1 = Instant::now() + backoff;
        }
        e.0
    }

    fn note_success(&self, ip: IpAddr) {
        self.inner.lock().remove(&ip);
    }
}

// ---------------------------------------------------------------------------
// 连接
// ---------------------------------------------------------------------------

/// 一条连接：读请求 → 应答 → 若还是 keep-alive 就接着读下一条。
///
/// keep-alive 不是锦上添花：界面每 2 秒发一轮轻量刷新（十来条命令），
/// 每条都新开一个 TCP 连接的话，几小时下来就是一堆 TIME_WAIT。
async fn serve_conn(ctx: Arc<Ctx>, mut stream: TcpStream, peer: SocketAddr, cancel: CancellationToken) {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let req = tokio::select! {
            _ = cancel.cancelled() => return,
            r = read_request(&mut stream, &mut buf) => match r {
                Ok(Some(req)) => req,
                Ok(None) => return,
                Err(e) => {
                    let _ = write_response(&mut stream, plain(400, &e), false).await;
                    return;
                }
            },
        };

        // SSE 会把连接占住直到对端断开，所以它不走"应答-继续"那条路
        if req.method == "GET" && req.path == "/api/events" {
            if let Err(resp) = ctx.authorize(&req) {
                let _ = write_response(&mut stream, resp, false).await;
                return;
            }
            sse(ctx.clone(), &mut stream, cancel.clone()).await;
            return;
        }

        let keep = req.keep_alive;
        let resp = ctx.handle(req, peer).await;
        if write_response(&mut stream, resp, keep).await.is_err() || !keep {
            return;
        }
    }
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    keep_alive: bool,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }

    fn cookie(&self, name: &str) -> Option<String> {
        let raw = self.header("cookie")?;
        for part in raw.split(';') {
            let (k, v) = part.split_once('=')?;
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
        None
    }
}

/// 读一条完整请求（请求头 + 按 `Content-Length` 的请求体）。
///
/// `buf` 在多次调用之间**复用**：上一条请求读多了的字节（`stream.read` 是按块返回的）
/// 留在里面，下一条从这里接着解析，不会丢。
async fn read_request<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<Request>, String> {
    // 这几个都在 `break` 之前赋值，循环没有别的出口（出错一律 return），
    // 所以不需要初值 —— 给个初值反而会被 `unused_assignments` 记一笔。
    let head_len;
    let method;
    let path;
    let http10;
    let mut headers: HashMap<String, String> = HashMap::new();

    loop {
        {
            let mut hs = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut hs);
            match req.parse(buf) {
                Ok(httparse::Status::Complete(n)) => {
                    head_len = n;
                    method = req.method.unwrap_or("").to_string();
                    // 路径里的 ?query 一律丢掉：这个服务没有任何按 query 取值的接口
                    path = req.path.unwrap_or("/").split('?').next().unwrap_or("/").to_string();
                    // httparse 用 0 表示 HTTP/1.0，1 表示 HTTP/1.1
                    http10 = req.version == Some(0);
                    for h in req.headers.iter() {
                        let name = h.name.to_ascii_lowercase();
                        let value = String::from_utf8_lossy(h.value).trim().to_string();
                        // ★ 参与安全判断的头**出现两次就直接拒绝**。
                        // 只留最后一个的话，攻击者可以送两个 `Host`：反代按第一个转发、
                        // 我按第二个校验 —— 于是 rebinding 的校验形同虚设。
                        // （这个洞是端到端测试发现的：测试客户端自己多送了一个 Host。）
                        if is_single_valued(&name) && headers.contains_key(&name) {
                            return Err(format!("`{name}` 头出现了两次，拒绝"));
                        }
                        headers.insert(name, value);
                    }
                    break;
                }
                Ok(httparse::Status::Partial) => {}
                Err(e) => return Err(format!("请求不是合法的 HTTP：{e}")),
            }
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("请求头过大".into());
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None) // 干净的对端关闭
            } else {
                Err("请求没发完就断了".into())
            };
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(format!("请求体过大（{content_length} 字节）"));
    }
    while buf.len() < head_len + content_length {
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("请求体没发完就断了".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let body = buf[head_len..head_len + content_length].to_vec();
    buf.drain(..head_len + content_length);

    // HTTP/1.1 默认长连接；HTTP/1.0 默认短连接
    let keep_alive = match headers.get("connection").map(|s| s.as_str()) {
        Some(v) if v.eq_ignore_ascii_case("close") => false,
        Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
        _ => !http10,
    };

    Ok(Some(Request { method, path, headers, body, keep_alive }))
}

// ---------------------------------------------------------------------------
// 应答
// ---------------------------------------------------------------------------

struct Response {
    status: u16,
    ctype: &'static str,
    body: Vec<u8>,
    extra: Vec<(&'static str, String)>,
}

impl Response {
    fn json(status: u16, v: serde_json::Value) -> Self {
        Self {
            status,
            ctype: "application/json; charset=utf-8",
            body: serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec()),
            extra: Vec::new(),
        }
    }

    fn ok(v: serde_json::Value) -> Self {
        Self::json(200, v)
    }

    fn error(status: u16, msg: impl Into<String>) -> Self {
        Self::json(status, serde_json::json!({ "error": msg.into() }))
    }
}

fn plain(status: u16, msg: &str) -> Response {
    Response {
        status,
        ctype: "text/plain; charset=utf-8",
        body: msg.as_bytes().to_vec(),
        extra: Vec::new(),
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

async fn write_response(stream: &mut TcpStream, resp: Response, keep_alive: bool) -> std::io::Result<()> {
    let mut head = String::new();
    head.push_str(&format!("HTTP/1.1 {} {}\r\n", resp.status, status_text(resp.status)));
    head.push_str(&format!("Content-Type: {}\r\n", resp.ctype));
    head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    // 这两条对所有应答都成立：不允许嗅探类型、不允许被嵌进别人的页面
    head.push_str("X-Content-Type-Options: nosniff\r\n");
    head.push_str("Referrer-Policy: no-referrer\r\n");
    for (k, v) in &resp.extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&resp.body).await?;
    stream.flush().await
}

// ---------------------------------------------------------------------------
// 路由与鉴权
// ---------------------------------------------------------------------------

impl Ctx {
    async fn handle(self: &Arc<Self>, req: Request, peer: SocketAddr) -> Response {
        // ① Host 校验（DNS rebinding）：攻击页面必然带着一个域名来。
        //    这一条在鉴权之前 —— 一个能被 rebinding 到内网 IP 的页面连登录接口都不该摸到。
        if let Some(host) = req.header("host") {
            if !self.host_ok(host) {
                return Response::error(
                    403,
                    format!("Host `{host}` 不在允许列表里。反代用了域名的话，把它加进 web.allowed_hosts"),
                );
            }
        } else if req.headers.contains_key("origin") {
            // 浏览器发的请求一定有 Host；有 Origin 却没 Host 说明有人在手搓请求
            return Response::error(403, "缺少 Host 头");
        }

        let path = req.path.clone();
        if let Some(rest) = path.strip_prefix("/api/") {
            return self.handle_api(rest, req, peer).await;
        }
        static_response(&req.path, self.assets_dir.as_deref())
    }

    fn host_ok(&self, host: &str) -> bool {
        let bare = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
        let bare = bare.trim_start_matches('[').trim_end_matches(']');
        if bare.eq_ignore_ascii_case("localhost") {
            return true;
        }
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return crate::net::is_local_ip(ip);
        }
        self.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(bare))
    }

    /// 会话校验。SSE 复用同一套（它只是换了个 GET）。
    fn authorize(&self, req: &Request) -> Result<(), Response> {
        let now = crate::events::now_unix();
        let Some(cookie) = req.cookie(SESSION_COOKIE) else {
            return Err(Response::error(401, "未登录"));
        };
        if !self.auth.session_valid(&cookie, now) {
            return Err(Response::error(401, "会话已过期，请重新登录"));
        }
        Ok(())
    }

    /// CSRF：跨站的写请求一律拒绝。
    ///
    /// 会话 cookie 已经是 `SameSite=Strict`（浏览器跨站根本不会带上它），这是第二道。
    /// 没有 `Origin` 的（curl / 脚本）放行 —— 它们本来就不带 cookie 到处跑。
    fn origin_ok(&self, req: &Request) -> bool {
        let Some(origin) = req.header("origin") else { return true };
        let Some(host) = req.header("host") else { return false };
        let bare = |s: &str| s.trim_start_matches("http://").trim_start_matches("https://").to_string();
        bare(origin) == bare(host)
    }

    async fn handle_api(self: &Arc<Self>, route: &str, req: Request, peer: SocketAddr) -> Response {
        match (req.method.as_str(), route) {
            ("POST", "login") => self.login(req, peer).await,
            ("POST", "logout") => self.logout(req),
            ("POST", "token") => self.change_token(req),
            ("GET", "session") => self.session(req),
            ("POST", cmd) => self.command(cmd, req).await,
            _ => Response::error(404, format!("没有这个端点：{} {}", req.method, req.path)),
        }
    }

    async fn login(self: &Arc<Self>, req: Request, peer: SocketAddr) -> Response {
        if !self.origin_ok(&req) {
            return Response::error(403, "跨站请求被拒绝");
        }
        if !json_content_type(&req) {
            return Response::error(415, "登录请求必须是 application/json");
        }
        if let Some(secs) = self.limiter.blocked_for(peer.ip()) {
            return Response::error(429, format!("尝试过于频繁，请 {secs} 秒后再试"));
        }

        #[derive(Deserialize)]
        struct Body {
            token: String,
        }
        let Ok(b) = serde_json::from_slice::<Body>(&req.body) else {
            return Response::error(400, "请求体应当是 {\"token\":\"…\"}");
        };

        if !self.auth.verify(&b.token) {
            let fails = self.limiter.note_failure(peer.ip());
            tracing::warn!(target: "hiveproxy", "web: 来自 {} 的令牌校验失败（第 {fails} 次）", peer.ip());
            return Response::error(401, "令牌不对");
        }
        self.limiter.note_success(peer.ip());

        let now = crate::events::now_unix();
        tracing::info!(target: "hiveproxy", "web: {} 已登录", peer.ip());
        let mut resp = Response::ok(serde_json::json!({
            "must_change": self.auth.must_change(),
            "never_changed": self.auth.changed_at().is_none(),
        }));
        resp.extra.push(("Set-Cookie", session_cookie(&self.auth.issue_session(now), now)));
        resp
    }

    fn logout(&self, req: Request) -> Response {
        if !self.origin_ok(&req) {
            return Response::error(403, "跨站请求被拒绝");
        }
        let mut resp = Response::ok(serde_json::json!(null));
        resp.extra.push(("Set-Cookie", format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")));
        resp
    }

    fn change_token(&self, req: Request) -> Response {
        if !self.origin_ok(&req) {
            return Response::error(403, "跨站请求被拒绝");
        }
        if let Err(e) = self.authorize(&req) {
            return e;
        }
        if !json_content_type(&req) {
            return Response::error(415, "改令牌的请求必须是 application/json");
        }

        #[derive(Deserialize)]
        struct Body {
            old: String,
            new: String,
        }
        let Ok(b) = serde_json::from_slice::<Body>(&req.body) else {
            return Response::error(400, "请求体应当是 {\"old\":\"…\",\"new\":\"…\"}");
        };
        if !self.auth.verify(&b.old) {
            return Response::error(401, "当前令牌不对");
        }
        if let Err(e) = self.auth.set_token(&b.new) {
            return Response::error(400, e);
        }
        tracing::info!(target: "hiveproxy", "web: 访问令牌已更换");

        let now = crate::events::now_unix();
        let mut resp = Response::ok(serde_json::json!({ "ok": true }));
        // 换完令牌顺手换一份会话，免得"改完就被踢回登录页"
        resp.extra.push(("Set-Cookie", session_cookie(&self.auth.issue_session(now), now)));
        resp
    }

    /// 会话查询。**未登录也返回 200**，只是 `authed: false` ——
    /// 界面靠它决定画登录页还是主界面，用 401 表达"没登录"会让这条查询本身报错。
    fn session(&self, req: Request) -> Response {
        let authed = self.authorize(&req).is_ok();
        Response::ok(serde_json::json!({
            "authed": authed,
            "must_change": authed && self.auth.must_change(),
            "engine_running": self.handle.peek().is_some(),
            "last_error": self.handle.last_error(),
        }))
    }

    /// 命令路由。**端点名 = Tauri 命令名**（docs/WEBUI.md §3.1）。
    async fn command(self: &Arc<Self>, cmd: &str, req: Request) -> Response {
        if !self.origin_ok(&req) {
            return Response::error(403, "跨站请求被拒绝");
        }
        if let Err(e) = self.authorize(&req) {
            return e;
        }
        if !json_content_type(&req) {
            return Response::error(
                415,
                "命令请求必须是 application/json（这条也是 CSRF 防护：表单编码的请求发不出这个头）",
            );
        }

        let args: serde_json::Value = if req.body.is_empty() {
            serde_json::json!({})
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v @ serde_json::Value::Object(_)) => v,
                Ok(_) => return Response::error(400, "请求体应当是一个 JSON 对象"),
                Err(e) => return Response::error(400, format!("请求体不是合法 JSON：{e}")),
            }
        };

        macro_rules! arg {
            ($name:literal, $ty:ty) => {
                match serde_json::from_value::<$ty>(args[$name].clone()) {
                    Ok(v) => v,
                    // 手写 curl 时最常见的错是**参数名打错**，那时候 serde 只会说
                    // "invalid type: null" —— 于是这里分两种话说，别让人对着 null 发愣。
                    Err(e) => {
                        let msg = if args.get($name).is_none() {
                            format!("缺少参数 `{}` —— 检查一下名字有没有打错", $name)
                        } else {
                            format!("参数 `{}` 不对：{e}", $name)
                        };
                        return Response::error(400, msg);
                    }
                }
            };
        }

        let h = &self.handle;
        let out: Result<serde_json::Value, String> = match cmd {
            // ── 服务 ──
            "service_state" => Ok(json(api::service_state(h))),
            "service_start" => api::service_start(h).await.map(json),
            "service_stop" => api::service_stop(h).await.map(json),
            "ui_log" => {
                api::ui_log(h, &arg!("level", String), arg!("msg", String));
                Ok(serde_json::Value::Null)
            }
            // ── 只读快照 ──
            "status" => api::status(h).map(json),
            "topology" => api::topology(h).map(json),
            "stats" => api::stats(h).map(json),
            "groups" => api::groups(h).map(json),
            "zones" => api::zones(h).map(json),
            "rule_stats" => api::rule_stats(h).map(json),
            "shared_rules_status" => api::shared_rules_status(h).map(json),
            "active_streams" => api::active_streams(h).map(json),
            "close_stream" => api::close_stream(h, arg!("peer", crate::proto::NodeId), arg!("stream_id", u64)).await.map(|_| serde_json::Value::Null),
            "ping_peer" => api::ping_peer(h, arg!("peer", crate::proto::NodeId)).map(json),
            // ── 配置 ──
            "get_config" => api::get_config(h).map(json),
            "set_config" => api::set_config(h, arg!("cfg", Config)).await.map(|_| serde_json::Value::Null),
            "data_dir" => Ok(serde_json::json!(api::data_dir(h))),
            "validate_config" => Ok(json(api::validate_config(&arg!("cfg", Config)))),
            "config_to_toml" => api::config_to_toml(h).map(json),
            "config_from_toml" => api::config_from_toml(&arg!("text", String)).map(json),
            // ── 规则 ──
            "get_rules" => api::get_rules(h).map(json),
            "set_rules" => api::set_rules(h, arg!("rules", Vec<RawRule>)).map(|_| serde_json::Value::Null),
            "check_rules" => api::check_rules(h, arg!("rules", Vec<RawRule>)).map(json),
            "preview_rules" => api::preview_rules(h, arg!("rules", Vec<RawRule>)).map(json),
            "publish_rules" => api::publish_rules(h, arg!("rules", Vec<RawRule>)).await.map(json),
            "revoke_shared_rules" => api::revoke_shared_rules(h).await.map(json),
            "set_rules_enabled" => {
                api::set_rules_enabled(h, arg!("enabled", bool)).map(|_| serde_json::Value::Null)
            }
            "sort_rules" => api::sort_rules(h, arg!("rules", Vec<RawRule>)).map(json),
            // ── 种子与探测 ──
            "add_seed" => api::add_seed(h, arg!("addr", String)).map(|_| serde_json::Value::Null),
            "remove_seed" => api::remove_seed(h, arg!("addr", String)).map(|_| serde_json::Value::Null),
            "probe_target" => api::probe_target(h, arg!("target", String)).await.map(json),
            "probe_exits" => api::probe_exits(h, arg!("target", String)).map(json),
            "probe_dial" => {
                api::probe_dial(h, arg!("target", String), arg!("via", crate::proto::NodeId)).await.map(json)
            }
            other => return Response::error(404, format!("没有这个命令：{other}")),
        };

        match out {
            Ok(v) => Response::ok(v),
            // 引擎没跑是 **503** 而不是 500：界面据此显示"引擎未运行"+ 上次失败原因，
            // 而不是一句"服务器错误"（这正是"web 与引擎分开控制"要撑住的那个场景）
            Err(e) => {
                if self.handle.peek().is_none() {
                    Response::error(503, e)
                } else {
                    Response::error(400, e)
                }
            }
        }
    }
}

/// 这些头只允许出现一次。它们要么直接决定鉴权/路由（Host、Cookie、Origin），
/// 要么决定我们要读多少字节（Content-Length）—— 两份就是两种解读，只能拒绝。
fn is_single_valued(name: &str) -> bool {
    matches!(name, "host" | "cookie" | "origin" | "content-length" | "content-type")
}

const SESSION_COOKIE: &str = "hive_session";

fn session_cookie(value: &str, _now: u64) -> String {
    // HttpOnly：脚本偷不到。SameSite=Strict：跨站请求根本不会带上它 —— CSRF 的第一道防线。
    format!(
        "{SESSION_COOKIE}={value}; Path=/; Max-Age={SESSION_TTL_SECS}; HttpOnly; SameSite=Strict"
    )
}

fn json_content_type(req: &Request) -> bool {
    req.header("content-type")
        .map(|v| v.to_ascii_lowercase().starts_with("application/json"))
        .unwrap_or(false)
}

fn json(v: impl Serialize) -> serde_json::Value {
    serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
}

// ---------------------------------------------------------------------------
// SSER:事件流
// ---------------------------------------------------------------------------

/// 事件流。**引擎重建也接得上**：不持有一条固定的订阅，而是循环重订阅，
/// 所以"内核重启不影响 web"在事件这条线上也是真的（docs/WEBUI.md §3.3）。
async fn sse(ctx: Arc<Ctx>, stream: &mut TcpStream, cancel: CancellationToken) {
    let head = "HTTP/1.1 200 OK\r\n\
                Content-Type: text/event-stream; charset=utf-8\r\n\
                Cache-Control: no-cache\r\n\
                Connection: keep-alive\r\n\
                X-Content-Type-Options: nosniff\r\n\
                X-Accel-Buffering: no\r\n\
                \r\n";
    if stream.write_all(head.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        return;
    }

    // 先发一条注释，让浏览器立刻认为"连上了"（否则要等第一个事件）
    if stream.write_all(b": hiveproxy\n\n").await.is_err() {
        return;
    }

    let mut ping = tokio::time::interval(Duration::from_secs(SSE_PING_SECS));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // 第一次立刻返回，丢掉

    loop {
        let Some(node) = ctx.handle.peek() else {
            // 引擎没跑：告诉界面一声（它本来就该显示"引擎未运行"），
            // 然后一秒看一次 —— 引擎一起来就自动接上，不需要刷新页面。
            let ev = serde_json::json!({
                "event": "log", "ts_ms": 0, "level": "warn", "module": "service",
                "msg": "引擎未运行（web 界面仍在，可以直接改配置再启）",
            });
            if send_sse(stream, &ev).await.is_err() {
                return;
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
            }
        };

        let mut rx = node.subscribe();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = ping.tick() => {
                    if stream.write_all(b": ping\n\n").await.is_err() { return; }
                    let _ = stream.flush().await;
                }
                r = rx.recv() => match r {
                    Ok(ev) => {
                        if send_sse(stream, &json(ev)).await.is_err() { return; }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        let ev = serde_json::json!({
                            "event": "log", "ts_ms": 0, "level": "warn", "module": "ui",
                            "msg": format!("前端事件积压，丢弃了 {n} 条（界面跟不上引擎速度）"),
                        });
                        if send_sse(stream, &ev).await.is_err() { return; }
                    }
                    // 引擎被停掉/重建 → 回到外层循环重订阅，**不关连接**
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
            }
        }
    }
}

async fn send_sse(stream: &mut TcpStream, v: &serde_json::Value) -> std::io::Result<()> {
    let line = format!("data: {v}\n\n");
    stream.write_all(line.as_bytes()).await?;
    stream.flush().await
}

// ---------------------------------------------------------------------------
// 静态资源
// ---------------------------------------------------------------------------

fn static_response(path: &str, assets_dir: Option<&Path>) -> Response {
    let rel = if path == "/" { "/index.html" } else { path };

    if let Some(dir) = assets_dir {
        if let Some(resp) = read_asset_from_disk(dir, rel) {
            return resp;
        }
        return plain(404, &format!("{} 里没有 {rel}", dir.display()));
    }

    if assets::ASSETS.is_empty() {
        return plain(
            200,
            "这个 hiveproxy-cli 构建没有内嵌 web 界面。\n\
             重新构建时先 `bun run build`，或者运行时用 `--web-assets <dist 目录>` 指一份。\n",
        );
    }
    match lookup(rel) {
        Some(r) => r,
        // SPA fallback：界面用 hash 路由，理论上用不到，但比 404 白屏强
        None => lookup("/index.html").unwrap_or_else(|| plain(404, "没有内嵌 index.html")),
    }
}

fn lookup(rel: &str) -> Option<Response> {
    assets::ASSETS
        .iter()
        .find(|(p, _, _)| *p == rel)
        .map(|(_, body, ctype)| Response {
            status: 200,
            ctype,
            body: body.to_vec(),
            extra: vec![("Cache-Control", cache_control(rel).to_string())],
        })
}

/// `/assets/*` 的文件名带内容哈希，可以永久缓存；`index.html` 绝不能缓存。
fn cache_control(rel: &str) -> &'static str {
    if rel.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// 开发模式：从磁盘读，改完前端刷新浏览器即可（不必重编 Rust）。
///
/// ★ 路径必须挡住 `..`：这个服务监听局域网，一个 `GET /../../etc/shadow`
/// 就能把整台机器读出去。
fn read_asset_from_disk(dir: &Path, rel: &str) -> Option<Response> {
    let clean = rel.trim_start_matches('/');
    if clean.split('/').any(|seg| seg == ".." || seg.is_empty()) {
        return None;
    }
    let path = dir.join(clean);
    let body = std::fs::read(&path).ok()?;
    Some(Response {
        status: 200,
        ctype: mime_of(&path),
        body,
        extra: vec![("Cache-Control", "no-cache".into())],
    })
}

fn mime_of(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// 路由守卫
// ---------------------------------------------------------------------------

/// 令牌的当前状态（`hiveproxy-cli web-token` 打印它）。
pub struct TokenStatus {
    /// 文件已经存在（= 已经初始化过，不是这次刚生成的）。
    pub initialized: bool,
    /// 还是初始令牌 —— 界面会强制用户改掉。
    pub must_change: bool,
    pub changed_at: Option<u64>,
}

/// 读令牌状态，**不生成**新令牌。
pub fn token_status(base_dir: &Path) -> Result<TokenStatus, String> {
    let path = crate::persist::data_dir(base_dir).join("web_auth.json");
    if !path.exists() {
        return Ok(TokenStatus { initialized: false, must_change: false, changed_at: None });
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("读 {} 失败：{e}", path.display()))?;
    let f: AuthFile =
        serde_json::from_str(&text).map_err(|e| format!("{} 不是合法 JSON：{e}", path.display()))?;
    Ok(TokenStatus { initialized: true, must_change: f.must_change, changed_at: f.changed_at })
}

/// 重新生成一个一次性令牌并返回明文 —— **忘了令牌时的唯一出路**。
///
/// 换出来的令牌和首次启动一样是"必须改"的，所以它只会出现在这一次的输出里。
pub fn reset_token(base_dir: &Path) -> Result<String, String> {
    let path = crate::persist::data_dir(base_dir).join("web_auth.json");
    let mut f: AuthFile = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    if f.salt.is_empty() {
        f.salt = hex(&rand_bytes(16));
    }
    // ★ 顺手换掉会话签名密钥：现有会话**全部作废**。
    // "重置令牌"多半意味着"我觉得令牌可能泄了"，那种情况下留着已发的会话等于没重置。
    // 代价只是自己的浏览器要重新登录一次。
    f.session_secret = hex(&rand_bytes(32));
    let token = generate_token();
    f.token_hash = hex(&sha256_cat(&f.salt, &normalize_token(&token)));
    f.must_change = true;
    f.changed_at = None;
    write_secret(&path, &f)?;
    Ok(token)
}

/// 所有能被 `POST /api/<cmd>` 调到的命令名。
///
/// ★ **加命令时这里和 `src-tauri/src/lib.rs` 的 `generate_handler!` 必须一起改。**
/// 漏了的话症状是"桌面上能用、web 上点了没反应"，而且两边都不报错 ——
/// 这条清单就是 `routes_match_the_tauri_commands` 那条测试的输入。
pub const COMMAND_ROUTES: &[&str] = &[
    "service_state",
    "service_start",
    "service_stop",
    "ui_log",
    "status",
    "topology",
    "stats",
    "get_config",
    "set_config",
    "get_rules",
    "set_rules",
    "preview_rules",
    "publish_rules",
    "revoke_shared_rules",
    "set_rules_enabled",
    "sort_rules",
    "rule_stats",
    "shared_rules_status",
    "groups",
    "zones",
    "add_seed",
    "remove_seed",
    "ping_peer",
    "active_streams",
    "close_stream",
    "probe_target",
    "probe_exits",
    "probe_dial",
    "check_rules",
    "data_dir",
    "validate_config",
    "config_to_toml",
    "config_from_toml",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ 路由表与 Tauri 命令表必须**完全相同**。
    ///
    /// 防的是"加了一个 Tauri 命令，忘了加 web 路由" —— 症状是桌面上能用、
    /// web 上点了没反应，而且两边都不报错。照 `lib.rs` 里那道 capabilities 守卫的思路。
    #[test]
    fn routes_match_the_tauri_commands() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src-tauri/src/lib.rs");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读不到 {}：{e}", path.display()));

        let start = text
            .find("generate_handler![")
            .expect("lib.rs 里应当有 generate_handler!");
        let rest = &text[start + "generate_handler![".len()..];
        let end = rest.find(']').expect("generate_handler! 的列表应当以 ] 收尾");
        let mut tauri: Vec<String> = rest[..end]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        tauri.sort();

        let mut web: Vec<String> = COMMAND_ROUTES.iter().map(|s| s.to_string()).collect();
        web.sort();

        let missing_in_web: Vec<&String> = tauri.iter().filter(|c| !web.contains(c)).collect();
        let missing_in_tauri: Vec<&String> = web.iter().filter(|c| !tauri.contains(c)).collect();
        assert!(
            missing_in_web.is_empty(),
            "这些命令 Tauri 有、web 没有（web 上点了会没反应）：{missing_in_web:?}"
        );
        assert!(
            missing_in_tauri.is_empty(),
            "这些路由 web 有、Tauri 没有（多半是名字打错了）：{missing_in_tauri:?}"
        );
    }

    #[test]
    fn token_is_grouped_and_normalizes_back() {
        let t = generate_token();
        assert_eq!(t.replace('-', "").len(), 20, "12 字节 = 20 个 base32 字符: {t}");
        assert!(t.contains('-'), "分组是给人照抄用的: {t}");

        // 手输要容错：小写、空格、以及 Crockford 里那几个看着像的字母
        let messy = format!(" {} ", t.to_lowercase().replace('-', " "));
        assert_eq!(normalize_token(&messy), normalize_token(&t));
    }

    #[test]
    fn auth_roundtrip_and_session() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("hiveproxy-web-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (auth, token) = Auth::load_or_init(&dir).unwrap();
        let token = token.expect("第一次应当生成令牌");
        assert!(auth.must_change(), "初始令牌必须强制更换");

        assert!(auth.verify(&token), "自己刚生成的令牌要能过");
        assert!(!auth.verify("AAAA-BBBB-CCCC-DDDD-EEEE"), "别的令牌不能过");

        // 令牌**不以明文落盘**
        let raw = std::fs::read_to_string(dir.join("data/web_auth.json")).unwrap();
        assert!(!raw.contains(&token), "令牌文件里不能有明文令牌");
        assert!(!raw.contains(&token.replace('-', "")), "也不能有去掉分隔符的版本");

        // 会话：签过、能过期、改一个字节就废
        let now = 1_000_000u64;
        let s = auth.issue_session(now);
        assert!(auth.session_valid(&s, now));
        assert!(auth.session_valid(&s, now + SESSION_TTL_SECS - 1), "没过期就该一直有效");
        assert!(!auth.session_valid(&s, now + SESSION_TTL_SECS + 1), "过期要无效");
        assert!(!auth.session_valid("1000000.deadbeef", now), "签名不对要无效");

        // 换令牌 → 不再强制更换，旧令牌立刻失效
        auth.set_token("my-own-passphrase").unwrap();
        assert!(!auth.must_change());
        assert!(auth.verify("my-own-passphrase"));
        assert!(!auth.verify(&token), "换了之后旧令牌必须作废");
        assert!(auth.changed_at().is_some());

        // 太短的令牌直接拒绝
        assert!(auth.set_token("short").is_err());

        // 重新加载（进程重启）：令牌仍然有效，且**不再**返回明文
        let (again, fresh) = Auth::load_or_init(&dir).unwrap();
        assert!(fresh.is_none(), "重启不该再生成新令牌");
        assert!(again.verify("my-own-passphrase"));
        assert!(!again.must_change());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn limiter_backs_off_and_forgives() {
        let l = Limiter::default();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(l.blocked_for(ip).is_none());

        // ★ 头两次失败**不锁**：输错一次令牌是常态，锁了用户会以为界面坏了
        l.note_failure(ip);
        assert!(l.blocked_for(ip).is_none(), "第一次输错不该被锁");
        l.note_failure(ip);
        assert!(l.blocked_for(ip).is_none(), "第二次也不锁");

        l.note_failure(ip);
        assert!(l.blocked_for(ip).is_some(), "第三次开始退避");

        l.note_success(ip);
        assert!(l.blocked_for(ip).is_none(), "成功一次就该清零");
    }

    /// 重复的 `Host` 头必须整条拒绝 —— 只留最后一个的话，反代按第一个转发、
    /// 我们按第二个校验，Host 校验就形同虚设（端到端测试踩出来过）。
    #[tokio::test]
    async fn duplicated_host_header_is_refused() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example.net\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let err = match read_request(&mut b, &mut buf).await {
            Err(e) => e,
            Ok(_) => panic!("重复的 Host 必须被拒绝"),
        };
        assert!(err.contains("host"), "应当点名是哪个头重复了：{err}");
    }

    #[test]
    fn host_check_blocks_rebinding() {
        let dir = std::env::temp_dir().join(format!("hiveproxy-web-host-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (auth, _) = Auth::load_or_init(&dir).unwrap();
        let ctx = Ctx {
            handle: crate::service::ServiceHandle::new(&dir),
            auth,
            assets_dir: None,
            allowed_hosts: vec!["hive.example.com".into()],
            limiter: Limiter::default(),
        };

        assert!(ctx.host_ok("127.0.0.1"), "回环");
        assert!(ctx.host_ok("localhost"));
        assert!(ctx.host_ok("localhost:10801"), "带端口要能认出来");
        assert!(ctx.host_ok("[::1]:10801"), "IPv6 字面量");
        assert!(ctx.host_ok("hive.example.com"), "白名单里的域名");
        // ★ 这一条就是 DNS rebinding：攻击页面带的是它自己的域名
        assert!(!ctx.host_ok("evil.example.net"), "不在白名单里的域名必须拒绝");
        assert!(!ctx.host_ok("evil.example.net:10801"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disk_assets_cannot_escape_the_directory() {
        let dir = std::env::temp_dir().join(format!("hiveproxy-web-disk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), b"<html>ok</html>").unwrap();

        assert!(read_asset_from_disk(&dir, "/index.html").is_some());
        assert!(read_asset_from_disk(&dir, "/../../etc/hosts").is_none(), "路径穿越必须挡住");
        assert!(read_asset_from_disk(&dir, "/../index.html").is_none());
        assert!(read_asset_from_disk(&dir, "/nope.html").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }
}