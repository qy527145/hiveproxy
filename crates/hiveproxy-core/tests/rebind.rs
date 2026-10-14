//! 档位②（引擎内重绑）的回归测试 —— docs/WEBUI.md §5.2、§9。
//!
//! 这是这次改动里**最容易写出 bug 的地方**：改完配置、界面显示保存成功、
//! 实际一个端口都没在听。所以这里不测"函数返回了 Ok"，而是**真的去连那个端口**：
//! 连得上才算在听，连不上才算真的关掉了。
//!
//! 三条：
//! 1. 改端口 → 新端口真的在听、老端口真的关了，而且身份（node_id）没变；
//! 2. 新端口被占 → 整体失败、**回滚**，老端口继续在听、磁盘上的配置没被改坏；
//! 3. 重绑**不断在途连接** —— 这是"改端口不用重启引擎"能成立的全部依据。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hiveproxy_core::config::Config;
use hiveproxy_core::node::HiveNode;
use hiveproxy_core::persist;

/// 同一个进程里的测试是**并行**跑的：光靠"pid + 纳秒"命名临时目录会撞
/// （macOS 上 `SystemTime::now()` 的粒度足够粗，并行线程能拿到同一个值，
/// 于是两个测试共用一个目录，互相把配置写花）。加个原子计数器才是真的唯一。
static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "hiveproxy-rebind-{tag}-{}-{}-{}",
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

fn base_cfg(listen_port: u16, proxy_port: u16) -> Config {
    let mut cfg = Config::default();
    cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
    cfg.listen.bind = "127.0.0.1".parse().unwrap();
    cfg.listen.ports = vec![listen_port];
    cfg.proxy.bind = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    cfg.discovery.lan_udp = false;
    // mDNS 走同一个 UDP 广播口，测试之间会互相干扰
    cfg.discovery.mdns = false;
    cfg.admin.enabled = false;
    cfg
}

async fn start(cfg: Config) -> (Arc<HiveNode>, PathBuf) {
    let dir = temp_dir("n");
    persist::save_config(&dir, &cfg).unwrap();
    let node = HiveNode::start(cfg, &dir).await.expect("节点应当起来");
    // 监听是异步绑的，等它真的绑上（否则测试会看运气）
    for _ in 0..100 {
        if !node.state.listen_bound.read().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (node, dir)
}

fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(500),
    )
    .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changing_the_port_rebinds_and_the_new_port_really_listens() {
    let a = free_port();
    let (node, dir) = start(base_cfg(a, 0)).await;
    let id_before = node.status().node_id;

    assert!(listening(a), "改之前老端口应当在听");
    assert!(
        node.status().listen.iter().any(|s| s.ends_with(&format!(":{a}"))),
        "status 应当报出实际端口：{:?}",
        node.status().listen
    );

    let b = free_port();
    let mut cfg = node.config();
    cfg.listen.ports = vec![b];
    node.apply_config(cfg).await.expect("换到一个空端口应当成功");

    assert!(listening(b), "新端口必须真的在听（这是这条测试的重点）");
    assert!(!listening(a), "老端口必须已经关掉，否则等于两个都在听");
    assert!(
        node.status().listen.iter().any(|s| s.ends_with(&format!(":{b}"))),
        "status 要跟着变，否则界面显示的和实际听的对不上：{:?}",
        node.status().listen
    );
    // 同一个节点，没被重建
    assert_eq!(node.status().node_id, id_before, "换端口不该换身份");

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// ★ 这条是"最易写出 bug"的那一条：新端口绑不上时，**必须回滚**。
/// 不能出现"界面显示保存成功、实际一个端口都没在听"。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_busy_port_rolls_back_and_keeps_the_old_listener() {
    let a = free_port();
    let (node, dir) = start(base_cfg(a, 0)).await;
    assert!(listening(a));

    // 占住 b 不放
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let b = squatter.local_addr().unwrap().port();

    let mut cfg = node.config();
    cfg.listen.ports = vec![b];
    let err = node
        .apply_config(cfg)
        .await
        .expect_err("绑一个被占的端口必须失败");
    assert!(err.contains("已保留原端口"), "错误要说清回滚的结果：{err}");

    assert!(listening(a), "回滚之后老端口必须还在听");
    // `listening(b)` 在这里没法当判据 —— b 上本来就有那个占用者听着。
    // 要断言的是"我们没把 b 当成自己的"，所以查的是自己的状态。
    assert!(
        !node.status().listen.iter().any(|s| s.ends_with(&format!(":{b}"))),
        "失败的那次绑定不该被记进监听列表：{:?}",
        node.status().listen
    );

    // 磁盘上的配置**没被改坏** —— 否则重启一次就起不来了
    let on_disk = persist::load_config(&dir).unwrap();
    assert_eq!(on_disk.listen.ports, vec![a], "失败的改动不能写进配置文件");
    assert_eq!(node.config().listen.ports, vec![a], "运行期配置也要回滚");

    drop(squatter);
    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// ★ "在途连接不受影响"是文档里的原话，所以它得有一条测试撑着。
///
/// 已接受的连接是各自 detached 的任务，换监听 socket 的位置碰不到它们。
///
/// ⚠️ "在途"的边界要说准：**已经 accept、正在被服务**的连接不受影响；
/// 刚刚三次握手完、**还躺在 backlog 里没被 accept** 的那种会被 RST 掉
/// （监听 socket 一关，内核就把未 accept 的连接重置）。这是内核行为，躲不掉，
/// 也没有实际影响 —— 客户端会立刻重连，而重连到的是新端口。所以这条测试
/// 必须先完成一次协议往返来确认"已经被 accept 了"，否则它测的是 backlog 那个边界。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_connections_survive_a_rebind() {
    let proxy_a = free_port();
    let (node, dir) = start(base_cfg(free_port(), proxy_a)).await;

    let mut live = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], proxy_a)),
        Duration::from_millis(500),
    )
    .expect("本地代理应当在听");
    live.set_read_timeout(Some(Duration::from_millis(500))).unwrap();

    // 走完 SOCKS5 的"选方法"这一步：拿到 0x05 0x00 才说明这条连接**已经被 accept**
    live.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut hello = [0u8; 2];
    live.read_exact(&mut hello).expect("应当收到选方法应答");
    assert_eq!(hello, [0x05, 0x00], "SOCKS5 选方法应答不对");

    // 换本地代理端口
    let proxy_b = free_port();
    let mut cfg = node.config();
    cfg.proxy.bind = SocketAddr::from(([127, 0, 0, 1], proxy_b));
    node.apply_config(cfg).await.expect("换代理端口应当成功");

    assert!(listening(proxy_b), "新代理端口要在听");
    assert!(!listening(proxy_a), "老代理端口要关掉");

    // ★ 关键：那条老连接**不只是开着，还在被服务** —— 让它真的去连一次
    //   （127.0.0.1:1 必然被拒），能拿回 SOCKS5 的失败应答就说明整条链路还活着。
    live.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x01]).unwrap();
    let mut reply = [0u8; 10];
    match live.read(&mut reply) {
        Ok(0) => panic!("在途连接被重绑掐断了（读到 EOF）"),
        Ok(n) => {
            assert!(n >= 2, "SOCKS5 应答至少要有 2 字节，收到 {n}");
            assert_eq!(reply[0], 0x05, "应答的版本号不对：{reply:?}");
            assert_ne!(reply[1], 0x00, "连一个必然被拒的端口不该成功：{reply:?}");
        }
        Err(e) => panic!("在途连接应当还能用，实际 {e:?}"),
    }

    drop(live);
    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// 代理端口绑不上时，**入向端口照样要如实报出来**。
///
/// 这条是被 CLI 的冒烟测试抓到的：`spawn_bound` 在代理绑失败时提前 return，
/// `listen_bound` 于是没被写；`status().listen` 退回身份里那份**猜测值** ——
/// 看上去在听，其实一个端口都没绑上。正是这个代码库最反感的"静默失效"。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_proxy_bind_does_not_hide_the_listen_ports() {
    let a = free_port();
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_proxy = squatter.local_addr().unwrap().port();

    let (node, dir) = start(base_cfg(a, busy_proxy)).await;

    assert!(listening(a), "入向端口绑得上，就该在听");
    assert!(
        node.status().listen.iter().any(|s| s.ends_with(&format!(":{a}"))),
        "入向端口必须出现在 status 里：{:?}",
        node.status().listen
    );
    assert!(
        node.state.proxy_bound.read().is_none(),
        "代理没绑上就不能报一个绑定地址出来"
    );

    drop(squatter);
    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// ★ 只改入向端口时，**代理端口被占不该有任何影响**。
///
/// 第一版把两侧捆在一起重绑：代理端口被别的程序占着（这在本机上就是常态）→ 整体失败 →
/// 而且回滚同样在代理那一步就退出了 → **一个端口都不在听**。
/// 这台开发机的 1080 恰好被人占着，CLI 冒烟测试直接把它踩了出来。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_occupied_proxy_port_does_not_break_a_listen_change() {
    let a = free_port();
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_proxy = squatter.local_addr().unwrap().port();

    let (node, dir) = start(base_cfg(a, busy_proxy)).await;
    assert!(listening(a), "入向端口应当在听");
    assert!(node.state.proxy_bound.read().is_none(), "代理端口被占，本来就没绑上");

    let b = free_port();
    let mut cfg = node.config();
    cfg.listen.ports = vec![b];
    node.apply_config(cfg)
        .await
        .expect("代理端口被占不该影响『改入向端口』");

    assert!(listening(b), "新入向端口必须真的在听");
    assert!(!listening(a), "老入向端口要关掉");
    assert!(
        node.state.proxy_bound.read().is_none(),
        "从来没绑上的代理不该被顺手绑上"
    );

    drop(squatter);
    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// 通配绑定（`0.0.0.0`）要展开成具体地址：界面要回答的是"我该拨哪个地址"。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wildcard_bind_reports_concrete_addresses() {
    let a = free_port();
    let mut cfg = base_cfg(a, 0);
    cfg.listen.bind = "0.0.0.0".parse().unwrap();

    let (node, dir) = start(cfg).await;
    let listen = node.status().listen;
    assert!(
        !listen.iter().any(|s| s.starts_with("0.0.0.0:")),
        "不该把 0.0.0.0 直接丢给界面：{listen:?}"
    );
    assert!(listen.iter().any(|s| s.ends_with(&format!(":{a}"))), "{listen:?}");

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}

/// 热字段（`max_links` 这种每个连接现读的）不该触发重绑 ——
/// 触发的话就会去绑**同一个端口**，必然 `EADDRINUSE`。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_fields_do_not_trigger_a_rebind() {
    let a = free_port();
    let (node, dir) = start(base_cfg(a, 0)).await;

    let mut cfg = node.config();
    cfg.listen.max_links = 3;
    let change = node.apply_config(cfg).await.expect("只改 max_links 应当安静地成功");
    assert!(change.is_hot(), "max_links 是热生效档：{change:?}");
    assert!(listening(a), "老端口当然还在听");

    // 把它算进重绑档的话，这一次就会绑同一个端口而失败
    let mut cfg = node.config();
    cfg.listen.max_links = 5;
    node.apply_config(cfg).await.expect("再来一次也应当成功");
    assert_eq!(node.config().listen.max_links, 5);

    node.stop().await;
    std::fs::remove_dir_all(&dir).ok();
}