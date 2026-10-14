//! 本地管理接口（DESIGN.md §20）。
//!
//! 给**无界面的服务器**用：CLI 与脚本通过一个本地 socket 查询状态、下发规则、增删种子。
//! GUI 不需要它（Tauri 直接调 `HiveNode` 的 API）。
//!
//! 协议刻意做得极简，`nc`/`socat` 就能用：
//!
//! ```text
//! $ echo status | nc -U /run/hiveproxy.sock
//! $ echo '{"cmd":"probe","target":"10.4.0.9:3389"}' | nc -U /run/hiveproxy.sock
//! ```
//!
//! 首字符是 `{` 走 JSON 请求/响应；否则按**空格分隔的纯文本命令**解析（对人更友好）。
//! 每行一个请求，同一条连接可以连续发多行。

use std::sync::Arc;

use serde_json::{json, Value};

use crate::node::HiveNode;
use crate::proto::NodeId;
use crate::rules::Rule;

/// 处理一条请求行，返回一行响应。
pub async fn handle_line(node: &Arc<HiveNode>, line: &str) -> String {
    let line = line.trim();
    if line.is_empty() {
        return String::new();
    }
    if line.starts_with('{') {
        match serde_json::from_str::<Value>(line) {
            Ok(v) => json_response(node, &v).await,
            Err(e) => err(format!("请求不是合法 JSON：{e}")),
        }
    } else if line.starts_with('[') {
        // 语法糖：直接给一个规则数组等价于 set_rules
        match serde_json::from_str::<Vec<Rule>>(line) {
            Ok(rules) => match node.set_local_rules(rules) {
                Ok(()) => ok(json!("本地规则已保存（未发布）")),
                Err(e) => err(e),
            },
            Err(e) => err(format!("规则数组解析失败：{e}")),
        }
    } else {
        text_command(node, line).await
    }
}

async fn json_response(node: &Arc<HiveNode>, v: &Value) -> String {
    let cmd = v.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
    let arg = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
    match cmd {
        "status" => ok(serde_json::to_value(node.status()).unwrap_or(Value::Null)),
        "topology" => ok(serde_json::to_value(node.topology()).unwrap_or(Value::Null)),
        "stats" => ok(serde_json::to_value(node.stats()).unwrap_or(Value::Null)),
        "zones" => ok(serde_json::to_value(node.zones()).unwrap_or(Value::Null)),
        "groups" => ok(serde_json::to_value(node.groups()).unwrap_or(Value::Null)),
        "rules" => ok(serde_json::to_value(node.rules_view()).unwrap_or(Value::Null)),
        "shared_rules" => ok(serde_json::to_value(node.shared_rules_status()).unwrap_or(Value::Null)),
        "rule_stats" => ok(serde_json::to_value(node.rule_stats()).unwrap_or(Value::Null)),
        "config" => ok(serde_json::to_value(node.config()).unwrap_or(Value::Null)),
        "streams" => ok(json!(node.active_streams()
            .into_iter()
            .map(|(p, id, t)| json!({"peer": p.to_string(), "stream_id": id, "target": t}))
            .collect::<Vec<_>>())),
        "probe" => match arg("target") {
            Some(t) => match node.probe_target(&t).await {
                Ok(r) => ok(serde_json::to_value(r).unwrap_or(Value::Null)),
                Err(e) => err(e),
            },
            None => err("缺少 target"),
        },
        "probe_exits" => match arg("target") {
            Some(t) => match node.probe_exits(&t) {
                Ok(list) => ok(serde_json::to_value(list).unwrap_or(Value::Null)),
                Err(e) => err(e),
            },
            None => err("缺少 target"),
        },
        "probe_dial" => match (arg("target"), arg("via")) {
            (Some(t), Some(v)) => match v.parse::<NodeId>() {
                Ok(id) => match node.probe_dial(&t, id).await {
                    Ok(r) => ok(serde_json::to_value(r).unwrap_or(Value::Null)),
                    Err(e) => err(e),
                },
                Err(_) => err(format!("`{v}` 不是合法节点地址")),
            },
            _ => err("缺少 target 或 via"),
        },
        // 逐行校验：收原始规则数组（与 set_rules 同一个形态），回出错的行
        "check_rules" => match v.get("rules").cloned() {
            Some(rj) => match serde_json::from_value::<Vec<crate::rules::RawRule>>(rj) {
                Ok(rows) => ok(serde_json::to_value(node.check_rules(rows)).unwrap_or(Value::Null)),
                Err(e) => err(format!("规则解析失败：{e}")),
            },
            None => err("缺少 rules"),
        },
        "default_egress" => match v.get("value") {
            // 不带 value = 只读
            None => ok(json!(node
                .config()
                .route
                .default_egress
                .map(|e| e.to_config_string()))),
            Some(val) => {
                let text = val.as_str().map(|s| s.to_string());
                if val.is_null() || text.as_deref() == Some("none") {
                    match node.set_default_egress(None) {
                        Ok(()) => ok(json!(Value::Null)),
                        Err(e) => err(e),
                    }
                } else {
                    match text {
                        Some(t) => match node.set_default_egress(Some(&t)) {
                            Ok(()) => ok(json!(t)),
                            Err(e) => err(e),
                        },
                        None => err("value 必须是字符串或 null"),
                    }
                }
            }
        },
        "set_rules" => match v.get("rules").cloned() {
            Some(rj) => match serde_json::from_value::<Vec<Rule>>(rj) {
                Ok(rules) => match node.set_local_rules(rules) {
                    Ok(()) => ok(json!("本地规则已保存（未发布）")),
                    Err(e) => err(e),
                },
                Err(e) => err(format!("规则解析失败：{e}")),
            },
            None => err("缺少 rules"),
        },
        "publish_rules" => match v.get("rules").cloned() {
            Some(rj) => match serde_json::from_value::<Vec<Rule>>(rj) {
                Ok(rules) => match node.publish_rules(rules).await {
                    Ok(r) => ok(serde_json::to_value(r).unwrap_or(Value::Null)),
                    Err(e) => err(e),
                },
                Err(e) => err(format!("规则解析失败：{e}")),
            },
            None => err("缺少 rules"),
        },
        "revoke_shared_rules" => match node.revoke_shared_rules().await {
            Ok(r) => ok(serde_json::to_value(r).unwrap_or(Value::Null)),
            Err(e) => err(e),
        },
        "rules_enabled" => match v.get("enabled").and_then(|b| b.as_bool()) {
            Some(b) => match node.set_rules_enabled(b) {
                Ok(()) => ok(json!(b)),
                Err(e) => err(e),
            },
            None => err("缺少 enabled"),
        },
        "add_seed" => match arg("addr") {
            Some(a) => match node.add_seed(a) {
                Ok(()) => ok(json!("已添加")),
                Err(e) => err(e),
            },
            None => err("缺少 addr"),
        },
        "remove_seed" => match arg("addr") {
            Some(a) => match node.remove_seed(a) {
                Ok(()) => ok(json!("已移除")),
                Err(e) => err(e),
            },
            None => err("缺少 addr"),
        },
        "shutdown" => {
            node.state.shutdown.cancel();
            ok(json!("正在退出"))
        }
        other => err(format!("未知命令 `{other}`")),
    }
}

async fn text_command(node: &Arc<HiveNode>, line: &str) -> String {
    let mut it = line.split_whitespace();
    let cmd = it.next().unwrap_or("");
    let rest: Vec<&str> = it.collect();
    match cmd {
        "help" => HELP.to_string(),
        "status" => human_status(node),
        "nodes" => human_nodes(node),
        "links" => human_links(node),
        "rules" => human_rules(node),
        "streams" => human_streams(node),
        "zones" => human_zones(node),
        "reload" | "config" => match std::fs::read_to_string(node.base_dir().join("hiveproxy.toml")) {
            Ok(t) => match crate::config::Config::from_toml(&t) {
                // ★ 走 `apply_config` 而不是 `set_config`：手工把端口改在文件里再 reload，
                // 过去是"存下来但不生效"（只留一行 warn）。现在端口会真的重新绑定。
                //
                // 身份/网段表那一档在这条路上处理不了 —— 重建引擎要 `ServiceHandle`，
                // 而管理接口只握着一个正在跑的 node。如实拒绝，不要收下一个不会生效的配置。
                Ok(cfg) if crate::config::classify_change(&node.config(), &cfg).engine => err(
                    "这份配置改了身份或网段表（node.* / share.subnet_deny* / admin.*），\
                     需要重启进程才生效（文档里的第 ③ 档）",
                ),
                Ok(cfg) => match node.apply_config(cfg).await {
                    Ok(_) => format!("配置已重新加载：{}\n", node.base_dir().join("hiveproxy.toml").display()),
                    Err(e) => err(e),
                },
                Err(e) => err(format!("配置解析失败：{e}")),
            },
            Err(e) => err(format!("读配置失败：{e}")),
        },
        "probe" => match rest.first() {
            Some(t) => match node.probe_target(t).await {
                Ok(r) => format!(
                    "目标      {}\n出口      {}{}\n来源      {}\n",
                    r.target,
                    r.egress,
                    if r.direct { "（本机直连）" } else { "" },
                    via_label(&r),
                ),
                Err(e) => err(e),
            },
            None => err("用法：probe <ip:port>"),
        },
        // 候选出口清单（§18 第 31 条）：成本、跳数、是否声明该网段、哪个是自动选中
        "probe-exits" => match rest.first() {
            Some(t) => match node.probe_exits(t) {
                Ok(list) => {
                    let mut s = format!("目标 {t} 的候选出口（共 {} 个）：\n", list.len());
                    for c in &list {
                        s.push_str(&format!(
                            "  {}{}  {}  {}{}\n",
                            if c.selected { "●" } else { "○" },
                            c.node,
                            c.alias.as_ref().map(|a| format!("（{a}）")).unwrap_or_default(),
                            match (c.cost, c.hops) {
                                (Some(cost), Some(h)) =>
                                    format!("{} 跳 成本 {cost}", if c.is_self { 0 } else { h }),
                                _ => "不可达".to_string(),
                            },
                            match (&c.unusable, c.declares_target, c.is_self) {
                                (Some(why), _, _) => format!("  ✗ {why}"),
                                (None, true, _) => "  ← 它自己的网段里就有这个 IP".to_string(),
                                (None, _, true) => "  ← 本机直连".to_string(),
                                _ => String::new(),
                            }
                        ));
                    }
                    s
                }
                Err(e) => err(e),
            },
            None => err("用法：probe-exits <ip:port>"),
        },
        // 实测：让该出口真的连一次目标（会在网络上产生一次真实连接）
        "dial" => match (rest.first(), rest.get(2)) {
            (Some(t), Some(via)) if rest.get(1).map(|s| s.as_ref()) == Some("via") => {
                match via.parse::<NodeId>() {
                    Ok(id) => match node.probe_dial(t, id).await {
                        Ok(r) => format!(
                            "{}  {}\n出口  {}{}\n耗时  {} ms\n",
                            if r.ok { "✓ 通了" } else { "✗ 不通" },
                            r.detail,
                            r.via,
                            if r.direct { "（本机直连）" } else { "" },
                            r.rtt_ms
                        ),
                        Err(e) => err(e),
                    },
                    Err(_) => err(format!("`{via}` 不是合法节点地址")),
                }
            }
            _ => err("用法：dial <ip:port> via <节点地址>"),
        },
        "default-egress" => match rest.first() {
            None => {
                let cur = node
                    .config()
                    .route
                    .default_egress
                    .map(|e| e.to_config_string())
                    .unwrap_or_else(|| "（未设置）".into());
                format!("默认出口    {cur}\n")
            }
            Some(v) => match node.set_default_egress(Some(v)) {
                Ok(()) if matches!(v.trim(), "none" | "clear" | "") => "默认出口已清除\n".to_string(),
                Ok(()) => format!("默认出口已设为 {v}\n"),
                Err(e) => err(e),
            },
        },
        "rules-enabled" => match rest.first() {
            Some(v) => {
                let b = *v == "true" || *v == "1" || *v == "on";
                match node.set_rules_enabled(b) {
                    Ok(()) => format!("路由规则已{}\n", if b { "启用" } else { "全局旁路（忽略全部规则）" }),
                    Err(e) => err(e),
                }
            }
            None => err("用法：rules-enabled true|false"),
        },
        "seed-add" => match rest.first() {
            Some(a) => match node.add_seed(a.to_string()) {
                Ok(()) => "已添加\n".into(),
                Err(e) => err(e),
            },
            None => err("用法：seed-add <ip[:port]>"),
        },
        "seed-del" => match rest.first() {
            Some(a) => match node.remove_seed(a.to_string()) {
                Ok(()) => "已移除\n".into(),
                Err(e) => err(e),
            },
            None => err("用法：seed-del <ip[:port]>"),
        },
        "publish" => {
            // 把当前本地规则整份发布
            let rules = node.config().route.rules;
            match node.publish_rules(rules).await {
                Ok(r) => format!("已发布 revision {}（{} 条）\n", r.revision, r.rules),
                Err(e) => err(e),
            }
        }
        "revoke" => match node.revoke_shared_rules().await {
            Ok(r) => format!("已撤回（revision {}）\n", r.revision),
            Err(e) => err(e),
        },
        other => err(format!("未知命令 `{other}`，输入 help 看可用命令")),
    }
}

const HELP: &str = "\
可用命令（也可以发一行 JSON，如 {\"cmd\":\"status\"}）：

  status              本机状态摘要
  nodes               拓扑里的节点
  links               直连链路
  rules               生效的规则表与命中统计
  streams             活跃流
  zones               网段真冲突与区域号
  probe <ip:port>     这个目标会走哪个出口
  probe-exits <ip:port> 候选出口清单（成本 / 跳数 / 是否声明该网段）
  dial <ip:port> via <节点>  实测：让该出口真的连一次目标（会产生真实连接）
  default-egress [<出口>|none]  读 / 写默认出口
  reload              重新读取 hiveproxy.toml 并热更新
  publish             把当前本地规则整份发布到全网
  revoke              撤回共享规则集
  rules-enabled <bool> 全局旁路开关
  seed-add <addr>     添加引导种子
  seed-del <addr>     移除引导种子
  help                本帮助

JSON 命令：status / topology / stats / zones / groups / rules / shared_rules /
  rule_stats / config / streams / probe / probe_exits / probe_dial / check_rules /
  default_egress / set_rules / publish_rules / revoke_shared_rules / rules_enabled /
  add_seed / remove_seed / shutdown
";

/// 探测结果里"出口是怎么定下来的"那行文字。
fn via_label(r: &crate::view::StreamProbe) -> String {
    match r.via.as_str() {
        "rule" => match r.matched_rule {
            Some(i) => format!("规则 #{}", i + 1),
            None => "规则".to_string(),
        },
        "default" => "默认出口（route.default_egress）".to_string(),
        _ => "内置网段兜底行".to_string(),
    }
}

fn human_status(node: &Arc<HiveNode>) -> String {
    let st = node.status();
    let s = node.stats();
    format!(
        "节点        {}{}\n监听        {}\n本机网段    {}\n对外声明    {}\n本地代理    {}\n做出口      {}\n规则        {} 条本地 + {} 条共享（{}）\n链路/流     {} / {}\n中继字节    入 {} / 出 {}\n丢帧/重置    {} / {}\n运行时长    {}s\n",
        st.node_id,
        st.alias.map(|a| format!("（{a}）")).unwrap_or_default(),
        if st.listen.is_empty() { "（无）".into() } else { st.listen.join(", ") },
        if st.subnets.is_empty() { "（无）".into() } else { st.subnets.join(", ") },
        if st.share_subnets { "已广播（邻居可把我当出口）" } else { "不广播（只消费不贡献）" },
        st.proxy_bind,
        if st.accepts_egress { "是" } else { "否（只自己不替他人转发）" },
        st.rule_count,
        st.shared_rule_count,
        if st.rules_enabled { "规则生效" } else { "★ 全局旁路中" },
        s.links,
        s.active_streams,
        s.bytes_relayed_in,
        s.bytes_relayed_out,
        s.frames_dropped,
        s.streams_dropped,
        st.uptime_secs
    )
}

fn human_nodes(node: &Arc<HiveNode>) -> String {
    let t = node.topology();
    if t.nodes.is_empty() {
        return "还没有任何节点。\n".into();
    }
    let mut out = format!("{:<16} {:<10} {:<7} {:<6} {:<7} {:<8} {}\n", "节点", "别名", "跳数", "成本", "直连", "做出口", "网段");
    for n in t.nodes {
        out.push_str(&format!(
            "{:<16} {:<10} {:<7} {:<6} {:<7} {:<8} {}\n",
            format!("{}{}", n.peer, if n.is_self { "*" } else { "" }),
            n.alias.unwrap_or_default(),
            n.hops.map(|h| h.to_string()).unwrap_or_else(|| "-".into()),
            n.cost.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
            if n.direct { "是" } else { "中继" },
            if n.accepts_egress { "是" } else { "否" },
            n.subnets.join(",")
        ));
    }
    out
}

fn human_links(node: &Arc<HiveNode>) -> String {
    let t = node.topology();
    if t.edges.is_empty() {
        return "没有直连链路。\n".into();
    }
    let mut out = format!("{:<16} {:<8} {:<8} {:<10} {}\n", "对端", "载体", "健康", "拨号方", "RTT");
    for e in t.edges {
        out.push_str(&format!(
            "{:<16} {:<8} {:<8} {:<10} {} ms\n",
            e.to, e.carrier, e.health,
            if e.establisher == "local" { "本机拨出" } else { "对方拨入" },
            e.rtt_ms
        ));
    }
    out
}

fn human_rules(node: &Arc<HiveNode>) -> String {
    let view = node.rules_view();
    let stats = node.rule_stats();
    let mut out = format!(
        "规则表（{} 条合并，其中 {} 条本地；{}）\n",
        view.table.merged.len(),
        view.table.local_count,
        if view.table.rules_enabled { "规则生效" } else { "★ 全局旁路中" }
    );
    out.push_str(&format!("{:<4} {:<26} {:<10} {:<22} {:<8} {}\n", "#", "host", "port", "egress", "命中", "备注"));
    for (i, r) in view.table.merged.iter().enumerate() {
        let st = stats.get(i);
        out.push_str(&format!(
            "{:<4} {:<26} {:<10} {:<22} {:<8} {}\n",
            i + 1,
            r.host.to_config_string(),
            r.port.to_config_string(),
            r.egress.to_config_string(),
            st.map(|s| s.hits.to_string()).unwrap_or_else(|| "-".into()),
            r.label.clone().unwrap_or_default()
        ));
    }
    out.push_str("\n（最后一行是内置的网段兜底：目标落在已知网段 → 选最近的声明者）\n");
    let sr = node.shared_rules_status();
    match sr.source {
        Some(s) => out.push_str(&format!(
            "共享规则集来自 {}，revision {}，{} 条{}\n",
            s,
            sr.revision,
            sr.rules,
            if sr.accepted { "" } else { "（已拒收）" }
        )),
        None => out.push_str("共享规则集：无\n"),
    }
    out
}

fn human_streams(node: &Arc<HiveNode>) -> String {
    let v = node.active_streams();
    if v.is_empty() {
        return "没有活跃流。\n".into();
    }
    let mut out = String::new();
    for (peer, id, target) in v {
        out.push_str(&format!("{peer} #{id} → {target}\n"));
    }
    out
}

fn human_zones(node: &Arc<HiveNode>) -> String {
    let zs = node.zones();
    if zs.is_empty() {
        return "没有网段真冲突。\n".into();
    }
    let mut out = String::new();
    for z in zs {
        out.push_str(&format!("网段 {} 被 {} 片孤岛分别声明：\n", z.net, z.islands.len()));
        for i in z.islands {
            out.push_str(&format!(
                "  {:<8} 成员 {}（可达 {}）　片外请填 {}\n",
                i.label,
                i.members.iter().map(|m| m.to_string()).collect::<Vec<_>>().join(","),
                i.reachable,
                i.suggestion
            ));
        }
    }
    out
}

fn ok(data: Value) -> String {
    let mut s = serde_json::to_string(&json!({"ok": true, "data": data})).unwrap_or_default();
    s.push('\n');
    s
}

fn err(msg: impl Into<String>) -> String {
    let mut s = serde_json::to_string(&json!({"ok": false, "error": msg.into()})).unwrap_or_default();
    s.push('\n');
    s
}

// ---------------------------------------------------------------------------
// 传输层：Unix socket（首选）/ 回环 TCP（Windows 与测试）
// ---------------------------------------------------------------------------

/// 启动管理接口。返回它实际监听的位置描述，便于日志与 CLI 打印。
pub fn spawn_admin(
    node: std::sync::Arc<HiveNode>,
    cancel: tokio_util::sync::CancellationToken,
) -> Option<String> {
    let cfg = node.config();
    if !cfg.admin.enabled {
        return None;
    }

    // 显式配了回环 TCP 就用它（跨平台，Windows 只能走这条）
    if let Some(addr) = cfg.admin.tcp {
        if !addr.ip().is_loopback() {
            node.state.log(
                "error",
                "admin",
                format!("admin.tcp = {addr} 不是回环地址，拒绝启动管理接口（它没有任何认证）"),
            );
            return None;
        }
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => {
                    node.state.log("info", "admin", format!("管理接口已就绪：tcp {addr}"));
                    tcp_accept_loop(node, l, cancel).await;
                }
                Err(e) => node.state.log("error", "admin", format!("tcp {addr} 绑定失败：{e}")),
            }
        });
        return Some(format!("tcp {addr}"));
    }

    #[cfg(unix)]
    {
        let path = if cfg.admin.socket.is_empty() {
            crate::persist::data_dir(node.base_dir()).join("hiveproxy.sock")
        } else {
            std::path::PathBuf::from(&cfg.admin.socket)
        };
        let desc = format!("unix {}", path.display());
        let desc_log = desc.clone();
        tokio::spawn(async move {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            // 上次异常退出可能留下陈旧的 socket 文件
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
            match tokio::net::UnixListener::bind(&path) {
                Ok(l) => {
                    node.state
                        .log("info", "admin", format!("管理接口已就绪：{desc_log}"));
                    unix_accept_loop(node, l, cancel).await;
                }
                Err(e) => node
                    .state
                    .log("error", "admin", format!("{desc_log} 绑定失败：{e}")),
            }
        });
        return Some(desc);
    }

    #[cfg(not(unix))]
    {
        // 默认值里已经给了回环 TCP，走到这里说明用户显式清空了它
        node.state
            .log("debug", "admin", "管理接口未配置端点（admin.tcp 为空且本平台无 Unix socket）");
        None
    }
}

#[cfg(unix)]
async fn unix_accept_loop(
    node: std::sync::Arc<HiveNode>,
    listener: tokio::net::UnixListener,
    cancel: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = node.state.shutdown.cancelled() => break,
            r = listener.accept() => {
                let Ok((stream, _)) = r else { continue };
                let n = node.clone();
                tokio::spawn(async move { serve_stream(n, stream).await });
            }
        }
    }
}

async fn tcp_accept_loop(
    node: std::sync::Arc<HiveNode>,
    listener: tokio::net::TcpListener,
    cancel: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = node.state.shutdown.cancelled() => break,
            r = listener.accept() => {
                let Ok((stream, peer)) = r else { continue };
                if !peer.ip().is_loopback() {
                    continue; // 只服务本机
                }
                let n = node.clone();
                tokio::spawn(async move { serve_stream(n, stream).await });
            }
        }
    }
}

/// 一条连接：按行读请求、按行写响应。同一条连接可以连续发多行。
async fn serve_stream<S>(node: std::sync::Arc<HiveNode>, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let resp = handle_line(&node, &line).await;
                if resp.is_empty() {
                    continue;
                }
                // ★ 响应以**一个空行**结尾。文本命令的输出是多行的，
                // 没有终止符的话，按行读的客户端只能拿到第一行。
                let mut out = resp.trim_end_matches('\n').to_string();
                out.push_str("\n\n");
                if w.write_all(out.as_bytes()).await.is_err() {
                    break;
                }
                let _ = w.flush().await;
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// 每个用例一个独立目录。
    ///
    /// ★ 名字里必须带上一个**进程内的自增序号**：只靠"纳秒时间戳"是不够的 ——
    /// `SystemTime` 的实际分辨率在 macOS 上并不保证到纳秒，而这个测试模块里二十来个用例
    /// 是并行启动的，撞上同一个时间戳的用例会共用目录；其中一个用例收尾时
    /// `remove_dir_all` 正好把另一个用例的目录删掉，那个用例随后写配置就是
    /// `I/O 错误: No such file or directory`（实测每 5 次全量跑就红一次，
    /// 与本次会话改的链路代码无关，是测试自身的隔离问题）。
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // ★ 名字要**短**：管理接口的 Unix socket 路径有 `SUN_LEN`（104 字节）硬上限，
        // 而 macOS 的临时目录本来就有三十多个字符 —— 名字里再塞时间戳就会顶到上限，
        // `unix_socket_roundtrip` 会以 "path must be shorter than SUN_LEN" 失败。
        let mut p = std::env::temp_dir();
        p.push(format!("hp-adm-{tag}-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    async fn node() -> (std::sync::Arc<HiveNode>, std::path::PathBuf) {
        let dir = temp_dir("t");
        let mut cfg = Config::default();
        cfg.node.overlay_addr = Some("127.0.0.1".parse().unwrap());
        cfg.listen.bind = "127.0.0.1".parse().unwrap();
        cfg.listen.ports = vec![0];
        cfg.proxy.bind = "127.0.0.1:0".parse().unwrap();
        cfg.discovery.lan_udp = false;
        cfg.admin.enabled = false; // 测试里手动跑，避免端口冲突
        let n = HiveNode::start(cfg, &dir).await.unwrap();
        (n, dir)
    }

    #[tokio::test]
    async fn text_status_reports_identity() {
        let (n, dir) = node().await;
        let out = handle_line(&n, "status").await;
        assert!(out.contains("127.0.0.1"), "{out}");
        assert!(out.contains("本地代理"), "状态里要能看到本地代理端口: {out}");
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn json_status_is_machine_readable() {
        let (n, dir) = node().await;
        let out = handle_line(&n, r#"{"cmd":"status"}"#).await;
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["node_id"], "127.0.0.1");
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn set_rules_via_json_then_read_back() {
        let (n, dir) = node().await;
        let req = r#"{"cmd":"set_rules","rules":[{"host":"*.corp.example.com","port":443,"egress":"block","on_unreachable":"fallback","enabled":true}]}"#;
        let out = handle_line(&n, req).await;
        assert!(serde_json::from_str::<Value>(&out).unwrap()["ok"] == true, "{out}");

        let back = handle_line(&n, r#"{"cmd":"config"}"#).await;
        let v: Value = serde_json::from_str(&back).unwrap();
        assert_eq!(v["data"]["route"]["rules"][0]["host"], "*.corp.example.com");
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rule_array_sugar_is_accepted() {
        let (n, dir) = node().await;
        let out = handle_line(&n, r#"[{"host":"10.9.0.0/16","port":"*","egress":"auto"}]"#).await;
        assert!(serde_json::from_str::<Value>(&out).unwrap()["ok"] == true, "{out}");
        assert_eq!(n.config().route.rules.len(), 1);
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn unknown_command_is_an_error_not_a_panic() {
        let (n, dir) = node().await;
        let out = handle_line(&n, "frobnicate").await;
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("frobnicate"));
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn help_lists_commands() {
        let (n, dir) = node().await;
        let out = handle_line(&n, "help").await;
        for c in [
            "status",
            "nodes",
            "rules",
            "probe",
            "probe-exits",
            "dial",
            "default-egress",
            "check_rules",
            "publish",
            "reload",
        ] {
            assert!(out.contains(c), "help 里应当列出 {c}");
        }
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn default_egress_over_the_wire() {
        let (n, dir) = node().await;

        // 不带参数 = 只读
        let out = handle_line(&n, "default-egress").await;
        assert!(out.contains("未设置"), "{out}");

        // 写入（`node.set_default_egress` 是界面/CLI 共用的那条路径）
        let out = handle_line(&n, "default-egress 10.0.0.5").await;
        assert!(out.contains("已设为"), "{out}");
        let back = handle_line(&n, r#"{"cmd":"default_egress"}"#).await;
        assert_eq!(serde_json::from_str::<Value>(&back).unwrap()["data"], "node:10.0.0.5");

        // 清除
        let out = handle_line(&n, "default-egress none").await;
        assert!(out.contains("已清除"), "{out}");
        assert!(n.config().route.default_egress.is_none());

        // 非法取值必须报错，而不是静默收下
        let out = handle_line(&n, "default-egress auto").await;
        assert!(serde_json::from_str::<Value>(&out).unwrap()["ok"] == false, "{out}");

        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn probe_exits_over_the_wire_lists_at_least_self() {
        let (n, dir) = node().await;
        let out = handle_line(&n, r#"{"cmd":"probe_exits","target":"10.4.0.7:3389"}"#).await;
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true, "{out}");
        let list = v["data"].as_array().unwrap();
        assert!(list.iter().any(|c| c["is_self"] == true), "本机直连必须在候选里: {out}");
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn dial_text_form_parses_target_and_via() {
        let (n, dir) = node().await;

        // 笨写法（少了 `via`）必须报用法错，而不是把第二个参数当成目标的一部分
        let out = handle_line(&n, "dial 127.0.0.1:9 127.0.0.1").await;
        assert!(out.contains("用法"), "{out}");

        // 实测一个**没人监听**的端口：必须回一条"不通"，而不是 panic 或空白
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = l.local_addr().unwrap();
        drop(l);
        let out = handle_line(&n, &format!("dial {dead} via 127.0.0.1")).await;
        assert!(out.contains("不通"), "{out}");

        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn check_rules_over_the_wire_names_the_row() {
        let (n, dir) = node().await;
        let out = handle_line(
            &n,
            r#"{"cmd":"check_rules","rules":[{"host":"10.1.2.9:8080","port":"*","egress":"auto"}]}"#,
        )
        .await;
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true, "{out}");
        assert_eq!(v["data"][0]["index"], 0);
        assert_eq!(v["data"][0]["field"], "host");
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rules_enabled_bypass_works_over_the_wire() {
        let (n, dir) = node().await;
        let out = handle_line(&n, "rules-enabled false").await;
        assert!(out.contains("旁路"), "{out}");
        assert!(!n.status().rules_enabled);
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_roundtrip() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (n, dir) = node().await;
        let sock = dir.join("admin.sock");
        {
            let mut cfg = n.config();
            cfg.admin.enabled = true;
            cfg.admin.socket = sock.to_string_lossy().to_string();
            n.set_config(cfg).unwrap();
        }
        let cancel = tokio_util::sync::CancellationToken::new();
        let where_ = spawn_admin(n.clone(), cancel.clone()).expect("应当能启动");
        assert!(where_.starts_with("unix "));

        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let s = tokio::net::UnixStream::connect(&sock).await.expect("连上管理 socket");
        let (r, mut w) = tokio::io::split(s);
        let mut lines = BufReader::new(r).lines();

        // 响应是**多行**的，以一个空行收尾（§20.2）—— 所以不能只读一行：
        // 只读一行会把剩下的行留在缓冲区里，下一条请求读到的是上一条的残渣。
        // （这个测试一直这么坏着：它把 `status` 输出的第二行当成 JSON 去解析。）
        w.write_all(b"status\n").await.unwrap();
        let text = read_response(&mut lines).await;
        assert!(text[0].contains("127.0.0.1"), "{text:?}");
        assert!(text.iter().any(|l| l.contains("本地代理")), "多行输出要能完整读到: {text:?}");

        w.write_all(br#"{"cmd":"status"}"#).await.unwrap();
        w.write_all(b"\n").await.unwrap();
        let json = read_response(&mut lines).await;
        let v: Value = serde_json::from_str(&json[0]).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["node_id"], "127.0.0.1");

        cancel.cancel();
        n.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 读到空行（响应终止符）为止，返回非空行。
    async fn read_response<R: tokio::io::AsyncRead + Unpin>(
        lines: &mut tokio::io::Lines<tokio::io::BufReader<R>>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(l) = lines.next_line().await.unwrap() {
            if l.is_empty() {
                break;
            }
            out.push(l);
        }
        out
    }
}
