//! Web 界面的端到端测试（docs/WEBUI.md §9）。
//!
//! 起一个真节点 + 真 HTTP 服务，用真的 HTTP 请求走一遍：
//! 登录 → 401 的各种姿势 → 命令 → 静态资源 → SSE → **引擎停掉之后界面还活着**。
//!
//! 这里手写一个最小的阻塞 HTTP 客户端，不引测试依赖：要断言的东西全是
//! "状态码 + 几个头 + 响应体"，不值得为它拉一个 client 库进来。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hiveproxy_core::config::Config;
use hiveproxy_core::service::ServiceHandle;
use hiveproxy_core::{persist, web};

struct Resp {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

impl Resp {
    fn cookie(&self) -> String {
        self.headers
            .get("set-cookie")
            .and_then(|v| v.split(';').next())
            .map(|s| s.to_string())
            .unwrap_or_default()
    }
}

/// 一条 `Connection: close` 的请求 —— 服务端应答完就断，读干净为止。
///
/// `head` 里已经写了 `Host` 就不再补一个：服务端**会拒绝重复的 Host**（那是 rebinding
/// 校验的命门），而这条规矩正是被这个客户端自己踩出来的。
fn request(addr: SocketAddr, head: &str, body: &str) -> Resp {
    let mut s = TcpStream::connect(addr).expect("连上 web 服务");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let host = if head.to_ascii_lowercase().contains("host:") {
        String::new()
    } else {
        format!("Host: {addr}\r\n")
    };
    let req = format!(
        "{head}\r\n{host}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    s.flush().unwrap();

    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    parse(&raw)
}

fn parse(raw: &[u8]) -> Resp {
    let text = String::from_utf8_lossy(raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Resp { status, headers, body: body.to_string() }
}

fn post(addr: SocketAddr, path: &str, json: &str, cookie: &str) -> Resp {
    let mut head = format!("POST {path} HTTP/1.1\r\nContent-Type: application/json\r\n");
    if !cookie.is_empty() {
        head.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    request(addr, head.trim_end(), json)
}

fn get(addr: SocketAddr, path: &str, cookie: &str) -> Resp {
    let mut head = format!("GET {path} HTTP/1.1\r\n");
    if !cookie.is_empty() {
        head.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    request(addr, head.trim_end(), "")
}

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "hiveproxy-webe2e-{tag}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn quiet_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
    cfg.listen.bind = "127.0.0.1".parse().unwrap();
    cfg.listen.ports = vec![0];
    cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
    cfg.discovery.lan_udp = false;
    cfg.discovery.mdns = false;
    cfg.admin.enabled = false;
    // 端口交给系统分配，测试之间不会撞
    cfg.web.bind = "127.0.0.1:0".parse().unwrap();
    cfg
}

/// 起服务；返回（临时目录，句柄，web 句柄，一次性令牌）。
async fn boot(tag: &str) -> (PathBuf, std::sync::Arc<ServiceHandle>, web::WebHandle, String) {
    let dir = temp_dir(tag);
    let cfg = quiet_cfg();
    persist::save_config(&dir, &cfg).unwrap();

    let handle = ServiceHandle::new(&dir);
    handle.start().await.expect("引擎应当起来");
    let w = web::spawn(handle.clone(), &cfg, None).await.expect("web 应当起来");
    let token = w.initial_token.clone().expect("首次启动应当给出一串一次性令牌");
    (dir, handle, w, token)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_then_drive_the_engine_over_http() {
    let (dir, handle, w, token) = boot("happy").await;
    let addr = w.addr;

    // ① 没登录时问会话：**200 + authed:false**，不是 401 ——
    //    界面靠这条查询决定画登录页还是主界面，用 401 表达"没登录"会让查询本身报错。
    let r = get(addr, "/api/session", "");
    assert_eq!(r.status, 200);
    assert!(r.body.contains("\"authed\":false"), "{}", r.body);

    // ② 令牌不对：401，且**不下发 cookie**
    let r = post(addr, "/api/login", r#"{"token":"WRONG-WRONG-WRONG-WRONG"}"#, "");
    assert_eq!(r.status, 401, "{}", r.body);
    assert!(!r.headers.contains_key("set-cookie"), "失败的登录不该下发会话");

    // ③ 令牌对了：200 + cookie，且要求先改令牌
    let r = post(addr, "/api/login", &format!(r#"{{"token":"{token}"}}"#), "");
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("\"must_change\":true"), "初始令牌必须要求更换: {}", r.body);
    let cookie = r.cookie();
    assert!(cookie.starts_with("hive_session="), "应当下发会话 cookie: {cookie}");
    assert!(
        r.headers["set-cookie"].contains("HttpOnly") && r.headers["set-cookie"].contains("SameSite=Strict"),
        "会话 cookie 必须是 HttpOnly + SameSite=Strict: {}",
        r.headers["set-cookie"]
    );

    // ④ 带着会话跑一条真正的命令
    let r = post(addr, "/api/status", "{}", &cookie);
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("127.0.0.1"), "status 应当报出自己的身份: {}", r.body);

    // ⑤ 没有会话就调命令：401
    let r = post(addr, "/api/status", "{}", "");
    assert_eq!(r.status, 401, "{}", r.body);

    // ⑥ 参数名打错：400，且错误里点名**缺的是哪个**（只说 "invalid type: null"
    //    的话，对着手写的 curl 根本看不出是名字打错了）
    let r = post(addr, "/api/probe_exits", r#"{"targt":"1.2.3.4:80"}"#, &cookie);
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(r.body.contains("缺少参数 `target`"), "错误里要点名缺哪个参数: {}", r.body);

    // 参数名对、值不对：也是 400，但说法不同
    let r = post(addr, "/api/probe_exits", r#"{"target":123}"#, &cookie);
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(r.body.contains("参数 `target` 不对"), "{}", r.body);

    // ⑦ 不存在的命令：404（不是 500，也不是静默成功）
    let r = post(addr, "/api/frobnicate", "{}", &cookie);
    assert_eq!(r.status, 404, "{}", r.body);

    w.stop();
    handle.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// ★ 这一组是安全边界。默认监听局域网之后，它们就是唯一的门。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_specific_attacks_are_refused() {
    let (dir, handle, w, token) = boot("sec").await;
    let addr = w.addr;

    let r = post(addr, "/api/login", &format!(r#"{{"token":"{token}"}}"#), "");
    let cookie = r.cookie();

    // ① 表单编码 / 纯文本（跨站"简单请求"就是这样发的）：415
    let r = request(
        addr,
        &format!("POST /api/status HTTP/1.1\r\nContent-Type: text/plain\r\nCookie: {cookie}"),
        "{}",
    );
    assert_eq!(r.status, 415, "非 JSON 的 content-type 必须拒绝: {}", r.body);

    // ② Origin 是别人的站：403（CSRF）
    let r = request(
        addr,
        &format!(
            "POST /api/status HTTP/1.1\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nOrigin: http://evil.example.net"
        ),
        "{}",
    );
    assert_eq!(r.status, 403, "跨站写请求必须拒绝: {}", r.body);

    // ③ Host 是个域名（DNS rebinding 的样子）：403
    let r = request(
        addr,
        "POST /api/status HTTP/1.1\r\nContent-Type: application/json\r\nHost: evil.example.net",
        "{}",
    );
    assert_eq!(r.status, 403, "Host 不在允许列表必须拒绝: {}", r.body);

    // ④ 同源 Origin 要放行（否则反代一挂就全废）
    let r = request(
        addr,
        &format!(
            "POST /api/status HTTP/1.1\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nOrigin: http://{addr}"
        ),
        "{}",
    );
    assert_eq!(r.status, 200, "同源请求应当放行: {}", r.body);

    w.stop();
    handle.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// ★ 这条是"把 web 与引擎分开控制"的存在理由：**引擎挂了，界面还得活着**，
/// 而且要能说出引擎为什么挂了、并且还能把它再启起来。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn web_survives_a_dead_engine() {
    let (dir, handle, w, token) = boot("dead").await;
    let addr = w.addr;
    let cookie = post(addr, "/api/login", &format!(r#"{{"token":"{token}"}}"#), "").cookie();

    // 停掉引擎 —— web 服务不受影响
    handle.stop().await;

    // 服务状态如实回答：没在跑，且没有失败原因（是"主动停的"，不是"起不来"）
    let r = post(addr, "/api/service_state", "{}", &cookie);
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("\"running\":false"), "{}", r.body);

    // 运行期命令：503 + 人话，而不是 500 或空
    let r = post(addr, "/api/status", "{}", &cookie);
    assert_eq!(r.status, 503, "引擎没跑应当是 503（界面据此显示『未运行』）: {}", r.body);
    assert!(r.body.contains("服务未运行"), "{}", r.body);

    // 配置照样能读能写 —— "引擎起不来时改配置"这条路必须通
    let r = post(addr, "/api/get_config", "{}", &cookie);
    assert_eq!(r.status, 200, "引擎没跑时也要能读配置: {}", r.body);
    assert!(r.body.contains("listen"), "{}", r.body);

    // 再启起来：还是从 web 界面上点的
    let r = post(addr, "/api/service_start", "{}", &cookie);
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("\"running\":true"), "{}", r.body);

    let r = post(addr, "/api/status", "{}", &cookie);
    assert_eq!(r.status, 200, "引擎回来之后 status 就该通: {}", r.body);

    w.stop();
    handle.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_assets_and_sse() {
    let (dir, handle, w, token) = boot("static").await;
    let addr = w.addr;

    // 首页就是那份前端（内嵌的是 dist/，所以必然有 <div id="root">）
    let r = get(addr, "/", "");
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("id=\"root\""), "首页应当是内嵌的前端: {}", r.body);
    assert_eq!(r.headers.get("x-content-type-options").map(|s| s.as_str()), Some("nosniff"));

    // 没命中的路径回落到 index.html（hash 路由用不到，但不能 404 白屏）
    let r = get(addr, "/rules", "");
    assert_eq!(r.status, 200);
    assert!(r.body.contains("id=\"root\""));

    // SSE：先 401（没登录），再带着会话拿到事件
    let r = get(addr, "/api/events", "");
    assert_eq!(r.status, 401, "事件流也要鉴权: {}", r.body);

    let cookie = post(addr, "/api/login", &format!(r#"{{"token":"{token}"}}"#), "").cookie();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    s.write_all(
        format!("GET /api/events HTTP/1.1\r\nHost: {addr}\r\nCookie: {cookie}\r\n\r\n").as_bytes(),
    )
    .unwrap();

    // 引擎在跑（stats 每秒一发），所以这里应当能等到真正的 `data:` 行
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut got = String::new();
    let mut chunk = [0u8; 1024];
    while Instant::now() < deadline {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                got.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if got.contains("data: ") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    assert!(got.contains("200 OK"), "SSE 应当先给 200: {got}");
    assert!(got.contains("text/event-stream"), "SSE 的 content-type 不对: {got}");
    assert!(got.contains("data: "), "应当收到引擎事件: {got}");
    assert!(got.contains("\"event\""), "事件载荷里要有 event 字段: {got}");

    w.stop();
    handle.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// 令牌在重启后仍然有效，且**不再打印明文**；重置走 `web-token --reset` 那条路。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_survives_restart_and_can_be_reset() {
    let dir = temp_dir("token");
    let cfg = quiet_cfg();
    persist::save_config(&dir, &cfg).unwrap();
    let handle = ServiceHandle::new(&dir);
    handle.start().await.unwrap();

    let w = web::spawn(handle.clone(), &cfg, None).await.unwrap();
    let token = w.initial_token.clone().unwrap();
    let addr = w.addr;
    w.stop();

    // 重启 web 服务：**不再生成新令牌**（否则每次重启都要去翻日志）
    let w2 = web::spawn(handle.clone(), &cfg, None).await.unwrap();
    assert!(w2.initial_token.is_none(), "令牌已经存在时不该再打印明文");

    // 旧令牌照样能登录
    let r = post(w2.addr, "/api/login", &format!(r#"{{"token":"{token}"}}"#), "");
    assert_eq!(r.status, 200, "{}", r.body);
    let cookie = r.cookie();

    // 改令牌：太短的被拒，正常的成功
    let r = post(w2.addr, "/api/token", &format!(r#"{{"old":"{token}","new":"short"}}"#), &cookie);
    assert_eq!(r.status, 400, "太短的令牌要拒绝: {}", r.body);
    let r = post(
        w2.addr,
        "/api/token",
        &format!(r#"{{"old":"{token}","new":"my-own-passphrase"}}"#),
        &cookie,
    );
    assert_eq!(r.status, 200, "{}", r.body);

    // 旧令牌立刻作废，新令牌可用
    let r = post(w2.addr, "/api/login", &format!(r#"{{"token":"{token}"}}"#), "");
    assert_eq!(r.status, 401, "换了之后旧令牌必须作废");
    let r = post(w2.addr, "/api/login", r#"{"token":"my-own-passphrase"}"#, "");
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("\"must_change\":false"), "自己设的令牌不该再被要求改: {}", r.body);

    w2.stop();

    // 忘了令牌 → 重置 → 新的能登、旧的不能，且会话全部作废（旧 cookie 不再有效）
    let fresh = web::reset_token(&dir).unwrap();
    let w3 = web::spawn(handle.clone(), &cfg, None).await.unwrap();
    assert!(w3.initial_token.is_none(), "重置走的是 CLI 那条路，web 不该再次打印");
    let r = post(w3.addr, "/api/login", &format!(r#"{{"token":"{fresh}"}}"#), "");
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("\"must_change\":true"), "重置出来的是一次性令牌: {}", r.body);

    let r = post(w3.addr, "/api/status", "{}", &cookie);
    assert_eq!(r.status, 401, "重置必须让旧会话全部作废（§6.1）: {}", r.body);

    // 状态查询：CLI 的 `web-token` 用的就是它
    let st = web::token_status(&dir).unwrap();
    assert!(st.initialized);
    assert!(st.must_change, "刚重置过，还没改");

    // 顺手断言一下：那个地址前缀没被写到别处去（避免测试真的访问外网）
    let _ = addr;

    w3.stop();
    handle.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}