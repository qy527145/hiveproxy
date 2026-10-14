//! 引擎的生命周期句柄（docs/WEBUI.md §2.1）。
//!
//! **存在的理由只有一个**：无界面机器上最容易卡死的场景是"配置改坏了、引擎起不来"——
//! 如果 web 界面跟着引擎一起生灭，这时候浏览器也打不开，用户只能回到终端。
//! 把"引擎跑不跑"和"进程活着"拆成两件事之后：**引擎起不来，web 界面照常打开**，
//! 页面上显示失败原因，直接改配置、点重启。
//!
//! 这个形状不是新发明的 —— `src-tauri` 的 `AppState` 一直是它，连 `last_error`
//! 的用途（"上次启动失败的原因，供 UI 显示，而不是静默白屏"）都一模一样。
//! 现在两边共用这一份。

use std::path::PathBuf;
use std::sync::Arc;

use crate::config::Config;
use crate::node::HiveNode;
use crate::persist;
use crate::view::ServiceState;

/// 引擎启动成功后的回调（Tauri 用它挂事件转发器）。
///
/// **不是可有可无的便利**：改了身份/网段表之后引擎会原地重建，旧的事件通道随之关闭、
/// 旧的转发器自己退出 —— 没有这个钩子，重建之后界面就再也收不到事件了。
type StartHook = Box<dyn Fn(Arc<HiveNode>) + Send + Sync>;

struct Inner {
    node: Option<Arc<HiveNode>>,
    last_error: Option<String>,
}

pub struct ServiceHandle {
    base_dir: PathBuf,
    inner: parking_lot::Mutex<Inner>,
    hooks: parking_lot::Mutex<Vec<StartHook>>,
}

impl ServiceHandle {
    pub fn new(base_dir: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            base_dir: base_dir.into(),
            inner: parking_lot::Mutex::new(Inner { node: None, last_error: None }),
            hooks: parking_lot::Mutex::new(Vec::new()),
        })
    }

    pub fn base_dir(&self) -> PathBuf {
        self.base_dir.clone()
    }

    /// 注册引擎启动回调。可注册多个（Tauri 一个、将来别的壳一个）。
    pub fn on_start(&self, f: impl Fn(Arc<HiveNode>) + Send + Sync + 'static) {
        self.hooks.lock().push(Box::new(f));
    }

    /// 判活，不报错。
    pub fn peek(&self) -> Option<Arc<HiveNode>> {
        self.inner.lock().node.clone()
    }

    /// 取节点；没跑时返回**上次失败的原因**（而不是干巴巴一句"服务未运行"——
    /// 界面要能回答"为什么没跑"）。
    pub fn node(&self) -> Result<Arc<HiveNode>, String> {
        let g = self.inner.lock();
        g.node
            .clone()
            .ok_or_else(|| g.last_error.clone().unwrap_or_else(|| "服务未运行".to_string()))
    }

    pub fn last_error(&self) -> Option<String> {
        self.inner.lock().last_error.clone()
    }

    /// 当前生效的配置：在跑就读运行期那份，没跑就读磁盘，读不到给默认值。
    ///
    /// ★ 判档位（`classify_change`）必须用这一份，不能用界面上那份可能已经过期的副本 ——
    /// 后者会把别人刚改的东西当成"没变"，于是该重绑的没重绑。
    pub fn current_config(&self) -> Config {
        if let Some(n) = self.peek() {
            return n.config();
        }
        persist::load_config(&self.base_dir).unwrap_or_default()
    }

    /// 启动引擎。**没有配置文件就写一份默认的** —— 这就是"启动不需要准备配置文件"。
    ///
    /// 已经在跑时是空操作，返回现有那个节点。失败原因记进 `last_error` 再往上抛。
    pub async fn start(&self) -> Result<Arc<HiveNode>, String> {
        if let Some(n) = self.peek() {
            return Ok(n);
        }
        // ★ 读/建配置也可能是失败的那一步（数据目录打不开、TOML 写坏了），
        // 而且它发生在 `start_with` 之前 —— 不在这里记一笔的话 `last_error` 会是空的，
        // 界面就退回到"服务没跑，但不知道为什么"。
        let cfg = match persist::load_or_init_config(&self.base_dir) {
            Ok(c) => c,
            Err(e) => return Err(self.fail(e.to_string())),
        };
        self.start_with(cfg).await
    }

    /// 用给定配置启动（配置会被落盘）。
    pub async fn start_with(&self, cfg: Config) -> Result<Arc<HiveNode>, String> {
        // 先落盘：`HiveNode::start` 会去读发布状态与共享规则，而配置是同一批状态的一部分；
        // 而且启动失败时用户得能看到自己写坏的那份配置，才有得改。
        persist::save_config(&self.base_dir, &cfg).map_err(|e| e.to_string())?;
        match HiveNode::start(cfg, &self.base_dir).await {
            Ok(node) => {
                {
                    let mut g = self.inner.lock();
                    g.node = Some(node.clone());
                    g.last_error = None;
                }
                for h in self.hooks.lock().iter() {
                    h(node.clone());
                }
                Ok(node)
            }
            Err(e) => Err(self.fail(e)),
        }
    }

    /// 记下失败原因再把它抛出去（唯一的写 `last_error` 的地方）。
    fn fail(&self, err: String) -> String {
        self.inner.lock().last_error = Some(err.clone());
        err
    }

    /// 停引擎。web 服务、登录态、会话都不受影响 —— 这正是"分开控制"的意思。
    pub async fn stop(&self) {
        let node = self.inner.lock().node.take();
        if let Some(n) = node {
            n.stop().await;
        }
    }

    /// 原地重建引擎（重新读磁盘上的配置）。web 界面在这个过程中不断线。
    pub async fn restart(&self) -> Result<Arc<HiveNode>, String> {
        self.stop().await;
        self.start().await
    }

    /// 服务状态快照。
    pub fn state(&self) -> ServiceState {
        let cfg = self.current_config();
        let g = self.inner.lock();

        let (node_id, proxy_bind) = match &g.node {
            Some(n) => {
                let st = n.status();
                (st.node_id.to_string(), st.proxy_bind)
            }
            None => {
                // 未运行时也要能显示"我是谁、代理挂哪儿"，所以从配置/网卡现算
                let id = cfg
                    .node
                    .overlay_addr
                    .map(|a| a.to_string())
                    .or_else(|| crate::net::primary_ip().map(|a| a.to_string()))
                    .unwrap_or_else(|| "—".into());
                (id, cfg.proxy.bind.to_string())
            }
        };

        ServiceState {
            running: g.node.is_some(),
            autostart: cfg.service.autostart,
            node_id,
            proxy_bind,
            admin_endpoint: g.node.as_ref().and_then(|n| n.admin_endpoint()),
            data_dir: persist::data_dir(&self.base_dir).to_string_lossy().to_string(),
            last_error: g.last_error.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "hiveproxy-service-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
        cfg.service.autostart = false;
        cfg
    }

    /// ★ 这条是这次改动的存在理由：**引擎起不来，句柄还要能回答为什么**，
    /// 而且还能再启一次。web 服务就是靠它，在引擎挂掉时把界面撑住。
    #[tokio::test]
    async fn failed_start_keeps_the_reason_and_can_be_retried() {
        let dir = tmp("fail");

        // 制造一个必然启动失败的数据目录：拿一个**文件**当目录用（`--data-dir` 打错就是这样）。
        //
        // ★ 别用"端口被占"或"身份地址不是本机"：前者是**非致命**的（§6.2.3，只告警不阻断启动），
        // 后者压根没有被校验（`IdentityError::OverlayAddrNotLocal` 现在是个没人抛的死变体）。
        // 这个测试的前两版分别栽在这两处。
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let h = ServiceHandle::new(blocker.join("sub"));

        let err = match h.start().await {
            Ok(_) => panic!("数据目录建不出来时不该启动成功"),
            Err(e) => e,
        };
        assert!(!err.is_empty());
        assert!(h.peek().is_none(), "失败之后不能留下半个节点");
        assert_eq!(h.last_error().as_deref(), Some(err.as_str()), "失败原因必须留着");
        match h.node() {
            Err(e) => assert_eq!(e, err, "node() 要说出原因而不是一句『服务未运行』"),
            Ok(_) => panic!("刚刚启动失败，node() 不该给回一个节点"),
        }

        // 换一个**正常**的数据目录 → 还能再启（同一套 API，从失败里恢复）
        let good = dir.join("good");
        let h = ServiceHandle::new(&good);
        persist::save_config(&good, &quiet_cfg()).unwrap();
        h.start().await.expect("换个能用的数据目录之后应当能起来");
        assert!(h.state().running);
        assert!(h.last_error().is_none(), "起来了就要把上次的失败原因清掉");

        h.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 没有配置文件时 `start()` 自己写一份 —— "启动不需要准备配置文件"。
    #[tokio::test]
    async fn start_creates_a_config_when_there_is_none() {
        let dir = tmp("init");
        let h = ServiceHandle::new(&dir);
        assert!(!persist::config_path(&dir).exists());

        // 默认配置会绑 0.0.0.0:5678 —— 端口冲突会让测试互相干扰，所以只断言落盘这件事
        let _ = h.start().await;
        assert!(persist::config_path(&dir).exists(), "首次启动应当落一份模板配置");

        h.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 引擎重建（③档）之后，钩子必须再被调一次 —— 旧的事件通道已经关了，
    /// 不重挂的话界面从此收不到任何事件。
    #[tokio::test]
    async fn restart_fires_the_hook_again() {
        let dir = tmp("hook");
        let h = ServiceHandle::new(&dir);
        persist::save_config(&dir, &quiet_cfg()).unwrap();

        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        {
            let seen = seen.clone();
            h.on_start(move |n| seen.lock().push(n.status().node_id));
        }

        h.start().await.unwrap();
        h.restart().await.unwrap();
        assert_eq!(seen.lock().len(), 2, "启动 + 重建各一次");
        assert!(h.state().running);

        h.stop().await;
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 服务状态在没跑的时候也要给得出"我是谁、代理挂哪儿"。
    #[tokio::test]
    async fn state_is_useful_while_stopped() {
        let dir = tmp("state");
        let h = ServiceHandle::new(&dir);
        persist::save_config(&dir, &quiet_cfg()).unwrap();

        let st = h.state();
        assert!(!st.running);
        assert_eq!(st.node_id, "127.0.0.1");
        assert_eq!(st.proxy_bind, "127.0.0.1:0");
        assert!(st.last_error.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}