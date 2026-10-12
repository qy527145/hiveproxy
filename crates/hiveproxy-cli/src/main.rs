//! hiveproxy 的无界面命令行版本。
//!
//! 面向**没有图形界面的 Linux 服务器 / 容器 / systemd**。所有能力与 GUI 一致，
//! 只是入口换成了命令行 + 配置文件 + 一个本地管理 socket（§20）。
//!
//! ```text
//! hiveproxy-cli init                     生成配置模板
//! hiveproxy-cli check                    只校验配置，不启动
//! hiveproxy-cli run                      前台运行（适合 systemd）
//! hiveproxy-cli run --status-interval 30 运行并周期打印状态
//! hiveproxy-cli status | nodes | rules | streams | zones
//! hiveproxy-cli probe 10.4.0.9:3389
//! hiveproxy-cli reload                   重新读取配置并热更新
//! hiveproxy-cli publish | revoke
//! hiveproxy-cli bypass true|false        全局旁路开关
//! hiveproxy-cli seed-add 10.1.2.3:20000
//! ```
//!
//! 这些子命令都是在**跟正在运行的节点说话**（通过本地管理 socket），
//! 所以不需要重启，也不需要额外的守护进程。

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use hiveproxy_core::config::Config;
use hiveproxy_core::node::HiveNode;

/// 退出码：0 正常 / 1 用法错 / 2 配置错 / 3 连接不上运行中的节点
const EXIT_USAGE: u8 = 1;
const EXIT_CONFIG: u8 = 2;
const EXIT_NO_NODE: u8 = 3;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("无法创建异步运行时：{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    ExitCode::from(rt.block_on(run(args)))
}

struct Opts {
    command: String,
    config: PathBuf,
    data_dir: Option<PathBuf>,
    status_interval: u64,
    json: bool,
    force: bool,
    args: Vec<String>,
}

fn parse_args(argv: &[String]) -> Result<Opts, String> {
    let mut command = String::new();
    let mut config: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut status_interval: u64 = 0;
    let mut json = false;
    let mut force = false;
    let mut rest: Vec<String> = Vec::new();

    let mut it = argv.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--config" => {
                config = Some(PathBuf::from(it.next().ok_or("--config 后面要跟路径")?));
            }
            "-d" | "--data-dir" => {
                data_dir = Some(PathBuf::from(it.next().ok_or("--data-dir 后面要跟路径")?));
            }
            "-i" | "--status-interval" => {
                let v = it.next().ok_or("--status-interval 后面要跟秒数")?;
                status_interval = v.parse().map_err(|_| format!("无效秒数 `{v}`"))?;
            }
            "--json" => json = true,
            "-f" | "--force" => force = true,
            "-h" | "--help" => {
                command = "help".into();
            }
            "-V" | "--version" => {
                command = "version".into();
            }
            other if other.starts_with('-') => {
                return Err(format!("未知选项 `{other}`（-h 看用法）"));
            }
            other => {
                if command.is_empty() {
                    command = other.to_string();
                } else {
                    rest.push(other.to_string());
                }
            }
        }
    }
    if command.is_empty() {
        command = "help".into();
    }

    let config = config.unwrap_or_else(|| PathBuf::from("hiveproxy.toml"));
    Ok(Opts { command, config, data_dir, status_interval, json, force, args: rest })
}

/// 配置所在目录就是数据目录（除非显式指定）。
fn base_dir(o: &Opts) -> PathBuf {
    if let Some(d) = &o.data_dir {
        return d.clone();
    }
    o.config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn load_config(o: &Opts) -> Result<Config, String> {
    if !o.config.exists() {
        return Err(format!(
            "配置文件 {} 不存在。先跑 `hiveproxy-cli init` 生成一份模板。",
            o.config.display()
        ));
    }
    let text = std::fs::read_to_string(&o.config).map_err(|e| format!("读配置失败：{e}"))?;
    Config::from_toml(&text).map_err(|e| format!("配置解析失败：{e}"))
}

async fn run(argv: Vec<String>) -> u8 {
    let o = match parse_args(&argv) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return EXIT_USAGE;
        }
    };

    match o.command.as_str() {
        "help" | "-h" | "--help" => {
            print_help();
            0
        }
        "version" | "-V" | "--version" => {
            println!("hiveproxy-cli {}", hiveproxy_core::VERSION);
            0
        }
        "init" => cmd_init(&o),
        "check" => cmd_check(&o),
        "run" => cmd_run(&o).await,
        // 其余都是在跟运行中的节点说话
        _ => cmd_query(&o).await,
    }
}

fn print_help() {
    println!(
        r#"hiveproxy-cli {ver} —— 无界面版本

用法：
  hiveproxy-cli [选项] <命令> [参数]

选项：
  -c, --config <路径>        配置文件（默认 ./hiveproxy.toml）
  -d, --data-dir <路径>      数据目录（默认取配置文件所在目录）
  -i, --status-interval <秒> run 时周期性打印状态；0 = 不打印（默认）
      --json                 输出 JSON（便于脚本处理）
  -f, --force                init 时覆盖已存在的配置
  -h, --help                 本帮助
  -V, --version              版本号

命令：
  init                       生成配置模板并退出
  check                      只校验配置，不启动
  run                        前台运行（适合 systemd / 容器）

  以下命令通过本地管理 socket 与**正在运行的节点**对话（无需重启）：
  status                     状态摘要
  nodes / links              拓扑里的节点 / 直连链路
  rules                      规则表与命中统计
  streams                    活跃流
  zones                      网段真冲突与区域号
  probe <ip:port>            这个目标会走哪个出口
  reload                     重新读取配置文件并热更新
  publish                    把当前本地规则整份发布到全网
  revoke                     撤回共享规则集
  bypass <true|false>        全局旁路开关
  seed-add / seed-del <地址>  增删引导种子

快速开始：
  hiveproxy-cli init
  vi hiveproxy.toml          # 至少改 [listen] ports 与 [peers] seeds
  hiveproxy-cli check
  hiveproxy-cli run
"#,
        ver = hiveproxy_core::VERSION
    );
}

fn cmd_init(o: &Opts) -> u8 {
    if o.config.exists() && !o.force {
        eprintln!("{} 已存在（要覆盖请加 --force）", o.config.display());
        return EXIT_USAGE;
    }
    let cfg = Config::default();
    if let Some(dir) = o.config.parent() {
        if !dir.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(dir);
        }
    }
    let text = format!(
        "# hiveproxy 配置。**至少**要改这两项：\n\
         #   [listen] ports  = IT 授权给这台机器的入向端口（别人就是拨这个端口找到你）\n\
         #   [peers]  seeds  = 你能拨通的另一台机器的地址（跨网段的第一条链路只能靠它点火）\n\
         #\n\
         # 其余全部有合理默认值。详细说明见 docs/USAGE.md。\n\
         \n{}",
        cfg.to_toml()
    );
    match std::fs::write(&o.config, text) {
        Ok(()) => {
            println!("已写入 {}", o.config.display());
            println!("提示：用 `hiveproxy-cli check` 校验，`hiveproxy-cli run` 启动。");
            0
        }
        Err(e) => {
            eprintln!("写入失败：{e}");
            EXIT_CONFIG
        }
    }
}

fn cmd_check(o: &Opts) -> u8 {
    let cfg = match load_config(o) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ {e}");
            return EXIT_CONFIG;
        }
    };
    let warns = cfg.validate();
    println!("✓ 配置可解析：{}", o.config.display());
    println!("  数据目录：{}", base_dir(o).display());
    println!("  身份：{}", cfg.node.overlay_addr.map(|a| a.to_string()).unwrap_or_else(|| "（自动取本机主网卡地址）".into()));
    println!("  监听：{} × {:?}", cfg.listen.bind, cfg.listen.ports);
    println!("  种子：{}", if cfg.peers.seeds.is_empty() { "（无 —— 同网段可靠 UDP 发现，跨网段必须至少一条）".into() } else { cfg.peers.seeds.join(", ") });
    println!("  SOCKS5：{}", cfg.proxy.socks5_bind);
    println!("  规则：{} 条本地{}", cfg.route.rules.len(), if cfg.route.rules_enabled { "" } else { "（★ 全局旁路中，全部规则会被忽略）" });
    if let Some(ep) = HiveNode::resolve_admin_endpoint(&base_dir(o), &cfg) {
        println!("  管理接口：{ep}");
    }
    if warns.is_empty() {
        println!("  没有告警。");
        0
    } else {
        println!("\n{} 条告警：", warns.len());
        for w in warns {
            println!("  ⚠ {w}");
        }
        0
    }
}

async fn cmd_run(o: &Opts) -> u8 {
    let cfg = match load_config(o) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ {e}");
            return EXIT_CONFIG;
        }
    };
    let dir = base_dir(o);

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.log.level)),
        )
        .with_target(true)
        .init();

    // 配置自检只告警，不阻断启动
    for w in cfg.validate() {
        tracing::warn!("配置告警：{w}");
    }

    let node = match HiveNode::start(cfg, &dir).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("✗ 启动失败：{e}");
            return EXIT_CONFIG;
        }
    };

    eprintln!();
    eprintln!("hiveproxy {} 已在数据目录 {} 启动", hiveproxy_core::VERSION, dir.display());
    if let Some(ep) = node.admin_endpoint() {
        eprintln!("管理接口：{ep}");
        eprintln!("          例如 `hiveproxy-cli status`，或 `echo status | nc -U {}`", ep.trim_start_matches("unix "));
    }
    eprintln!("按 Ctrl-C 退出。");
    eprintln!();

    // 可选：周期性打印一行状态（便于 systemd journal / docker logs 里看）
    if o.status_interval > 0 {
        let n = node.clone();
        let secs = o.status_interval;
        let json = o.json;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let st = n.status();
                let s = n.stats();
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "node_id": st.node_id.to_string(),
                            "uptime_secs": st.uptime_secs,
                            "links": s.links,
                            "active_streams": s.active_streams,
                            "bytes_in": s.bytes_relayed_in,
                            "bytes_out": s.bytes_relayed_out,
                            "frames_relayed": s.frames_relayed,
                            "frames_dropped": s.frames_dropped,
                            "handshakes_ok": s.handshakes_ok,
                            "handshakes_failed": s.handshakes_failed,
                            "rules_enabled": st.rules_enabled,
                        })
                    );
                } else {
                    println!(
                        "[{}] 链路 {} · 流 {} · 入 {} B / 出 {} B · 中继 {} 帧 · 丢 {} · 握手 {}/{}",
                        st.uptime_secs,
                        s.links,
                        s.active_streams,
                        s.bytes_relayed_in,
                        s.bytes_relayed_out,
                        s.frames_relayed,
                        s.frames_dropped,
                        s.handshakes_ok,
                        s.handshakes_failed
                    );
                }
            }
        });
    }

    // 等退出信号
    wait_for_shutdown().await;
    eprintln!("正在退出…");
    node.stop().await;
    0
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut int = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

// ---------------------------------------------------------------------------
// 与运行中的节点对话（走管理 socket）
// ---------------------------------------------------------------------------

/// 把 CLI 子命令翻译成管理接口的一条请求行。
fn to_admin_line(o: &Opts) -> Result<String, String> {
    let arg0 = o.args.first().cloned();
    let line = match o.command.as_str() {
        "status" => "status".into(),
        "nodes" => "nodes".into(),
        "links" => "links".into(),
        "rules" => "rules".into(),
        "streams" => "streams".into(),
        "zones" => "zones".into(),
        "reload" => "reload".into(),
        "publish" => "publish".into(),
        "revoke" => "revoke".into(),
        "probe" => {
            let t = arg0.ok_or("用法：hiveproxy-cli probe <ip:port>")?;
            format!("probe {t}")
        }
        "bypass" => {
            let v = arg0.ok_or("用法：hiveproxy-cli bypass <true|false>")?;
            format!("rules-enabled {v}")
        }
        "seed-add" => {
            let v = arg0.ok_or("用法：hiveproxy-cli seed-add <ip[:port]>")?;
            format!("seed-add {v}")
        }
        "seed-del" => {
            let v = arg0.ok_or("用法：hiveproxy-cli seed-del <ip[:port]>")?;
            format!("seed-del {v}")
        }
        other => return Err(format!("未知命令 `{other}`（-h 看用法）")),
    };
    Ok(line)
}

async fn cmd_query(o: &Opts) -> u8 {
    let line = match to_admin_line(o) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            return EXIT_USAGE;
        }
    };
    let cfg = match load_config(o) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ {e}");
            return EXIT_CONFIG;
        }
    };
    let ep = match HiveNode::resolve_admin_endpoint(&base_dir(o), &cfg) {
        Some(e) => e,
        None => {
            eprintln!("配置里 admin.enabled = false，没有可用的管理接口。");
            return EXIT_NO_NODE;
        }
    };

    match send_line(&ep, &line, o.json).await {
        Ok(resp) => {
            print!("{resp}");
            if resp.starts_with('{') {
                // JSON 模式下 ok=false 也返回 0，让调用方自己判断；纯文本模式同理
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
                    if v.get("ok").and_then(|b| b.as_bool()) == Some(false) {
                        return EXIT_USAGE;
                    }
                }
            }
            0
        }
        Err(e) => {
            eprintln!("✗ 连不上管理接口（{ep}）：{e}");
            eprintln!("  节点在跑吗？用 `hiveproxy-cli run` 启动，或看 systemd 状态。");
            EXIT_NO_NODE
        }
    }
}

async fn send_line(endpoint: &str, line: &str, json: bool) -> Result<String, String> {
    // 附带 --json 时把纯文本命令升级成等价 JSON 请求，便于脚本消费
    let payload = if json {
        to_json_request(line)
    } else {
        line.to_string()
    };

    if let Some(addr) = endpoint.strip_prefix("tcp ") {
        let s = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| "连接超时".to_string())?
            .map_err(|e| e.to_string())?;
        return read_until_blank(s, &payload).await;
    }

    #[cfg(unix)]
    {
        let path = endpoint.strip_prefix("unix ").unwrap_or(endpoint);
        let s = tokio::time::timeout(Duration::from_secs(5), tokio::net::UnixStream::connect(path))
            .await
            .map_err(|_| "连接超时".to_string())?
            .map_err(|e| e.to_string())?;
        read_until_blank(s, &payload).await
    }
    #[cfg(not(unix))]
    {
        let _ = (payload, json);
        Err("本平台不支持 Unix socket，请在配置里用 admin.tcp".into())
    }
}

/// 发一行请求，读到**空行**为止 —— 文本命令的响应是多行的，只读一行会截断。
async fn read_until_blank<S>(stream: S, payload: &str) -> Result<String, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();
    w.write_all(format!("{payload}\n").as_bytes()).await.map_err(|e| e.to_string())?;
    w.flush().await.map_err(|e| e.to_string())?;

    let mut body = String::new();
    let deadline = Duration::from_secs(10);
    let fut = async {
        loop {
            match lines.next_line().await {
                Ok(Some(l)) if l.trim().is_empty() => break,
                Ok(Some(l)) => {
                    body.push_str(&l);
                    body.push('\n');
                }
                Ok(None) => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok::<(), String>(())
    };
    match tokio::time::timeout(deadline, fut).await {
        Ok(Ok(())) => {
            if body.is_empty() {
                Err("对端没有回响应".into())
            } else {
                Ok(body)
            }
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err("等响应超时".into()),
    }
}

/// 纯文本命令 → 等价的 JSON 请求（`--json` 时用）。
fn to_json_request(line: &str) -> String {
    let mut it = line.split_whitespace();
    let cmd = it.next().unwrap_or("");
    let rest: Vec<&str> = it.collect();
    let v = match cmd {
        "status" | "topology" | "stats" | "zones" | "groups" | "rules" | "streams" | "config" => {
            serde_json::json!({ "cmd": cmd })
        }
        "nodes" => serde_json::json!({ "cmd": "topology" }),
        "links" => serde_json::json!({ "cmd": "topology" }),
        "probe" => serde_json::json!({ "cmd": "probe", "target": rest.first().copied().unwrap_or("") }),
        "rules-enabled" | "bypass" => serde_json::json!({
            "cmd": "rules_enabled",
            "enabled": matches!(rest.first().copied(), Some("true") | Some("1") | Some("on"))
        }),
        "seed-add" => serde_json::json!({ "cmd": "add_seed", "addr": rest.first().copied().unwrap_or("") }),
        "seed-del" => serde_json::json!({ "cmd": "remove_seed", "addr": rest.first().copied().unwrap_or("") }),
        "publish" => serde_json::json!({ "cmd": "publish_rules", "rules": [] }),
        "revoke" => serde_json::json!({ "cmd": "revoke_shared_rules" }),
        "reload" => serde_json::json!({ "cmd": "reload" }),
        other => serde_json::json!({ "cmd": other }),
    };
    v.to_string()
}

/// 让 `Path` 在非 unix 分支下也被引用。
#[allow(dead_code)]
fn _keep(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(cmd: &str, args: &[&str]) -> Opts {
        Opts {
            command: cmd.into(),
            config: PathBuf::from("hiveproxy.toml"),
            data_dir: None,
            status_interval: 0,
            json: false,
            force: false,
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn parses_flags_and_subcommands() {
        let a: Vec<String> = ["-c", "/etc/hiveproxy.toml", "probe", "10.0.0.1:80"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = parse_args(&a).unwrap();
        assert_eq!(o.command, "probe");
        assert_eq!(o.config, PathBuf::from("/etc/hiveproxy.toml"));
        assert_eq!(o.args, vec!["10.0.0.1:80"]);

        let a: Vec<String> = ["run", "--status-interval", "30", "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = parse_args(&a).unwrap();
        assert_eq!(o.command, "run");
        assert_eq!(o.status_interval, 30);
        assert!(o.json);

        assert!(parse_args(&["--nope".to_string()]).is_err());
        assert!(parse_args(&["-c".to_string()]).is_err());
    }

    #[test]
    fn no_command_means_help() {
        let o = parse_args(&[]).unwrap();
        assert_eq!(o.command, "help");
    }

    #[test]
    fn maps_subcommands_to_admin_lines() {
        assert_eq!(to_admin_line(&opts("status", &[])).unwrap(), "status");
        assert_eq!(to_admin_line(&opts("nodes", &[])).unwrap(), "nodes");
        assert_eq!(
            to_admin_line(&opts("probe", &["10.4.0.9:3389"])).unwrap(),
            "probe 10.4.0.9:3389"
        );
        assert_eq!(to_admin_line(&opts("bypass", &["true"])).unwrap(), "rules-enabled true");
        assert_eq!(
            to_admin_line(&opts("seed-add", &["10.1.2.3:20000"])).unwrap(),
            "seed-add 10.1.2.3:20000"
        );
        // 参数缺失必须报用法错，而不是发一条空请求
        assert!(to_admin_line(&opts("probe", &[])).is_err());
        assert!(to_admin_line(&opts("frobnicate", &[])).is_err());
    }

    #[test]
    fn json_upgrade_produces_valid_requests() {
        for line in ["status", "nodes", "links", "zones", "rules", "streams"] {
            let j = to_json_request(line);
            let v: serde_json::Value = serde_json::from_str(&j).unwrap();
            assert!(v.get("cmd").is_some(), "{line} -> {j}");
        }
        let v: serde_json::Value = serde_json::from_str(&to_json_request("probe 1.2.3.4:80")).unwrap();
        assert_eq!(v["cmd"], "probe");
        assert_eq!(v["target"], "1.2.3.4:80");

        let v: serde_json::Value = serde_json::from_str(&to_json_request("bypass false")).unwrap();
        let v2: serde_json::Value =
            serde_json::from_str(&to_json_request("rules-enabled true")).unwrap();
        assert_eq!(v2["enabled"], true);
        assert_eq!(v["cmd"], "rules_enabled");
        assert_eq!(v["enabled"], false);
    }

    #[test]
    fn base_dir_defaults_to_config_parent() {
        let mut o = opts("run", &[]);
        o.config = PathBuf::from("/etc/hiveproxy/hiveproxy.toml");
        assert_eq!(base_dir(&o), PathBuf::from("/etc/hiveproxy"));

        let mut o = opts("run", &[]);
        o.config = PathBuf::from("hiveproxy.toml");
        assert_eq!(base_dir(&o), PathBuf::from("."));

        let mut o = opts("run", &[]);
        o.data_dir = Some(PathBuf::from("/var/lib/hiveproxy"));
        assert_eq!(base_dir(&o), PathBuf::from("/var/lib/hiveproxy"));
    }
}
