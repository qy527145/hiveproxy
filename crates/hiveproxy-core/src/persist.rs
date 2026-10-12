//! 配置与运行期状态的持久化（DESIGN.md §9.4.3、§18.1）。
//!
//! **两份状态缺一都会造成"静默失效"**：
//! - 接收到的共享规则集 → `data/shared_rules.toml`
//! - 本节点的发布状态（`own_revision`）→ `data/publish_state.json`

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::ConfigError;
use crate::proto::RuleSetAd;
use crate::state::PublishState;

/// 运行期数据目录。
pub fn data_dir(base: &Path) -> PathBuf {
    base.join("data")
}

pub fn ensure_dir(p: &Path) -> std::io::Result<()> {
    if !p.exists() {
        std::fs::create_dir_all(p)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

pub fn config_path(base: &Path) -> PathBuf {
    base.join("hiveproxy.toml")
}

/// 读配置；文件不存在时返回默认值并写入一份带注释的模板。
pub fn load_or_init_config(base: &Path) -> Result<Config, ConfigError> {
    let path = config_path(base);
    if !path.exists() {
        let cfg = Config::default();
        save_config(base, &cfg)?;
        return Ok(cfg);
    }
    let text = std::fs::read_to_string(&path)?;
    Ok(Config::from_toml(&text)?)
}

pub fn load_config(base: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(config_path(base))?;
    Ok(Config::from_toml(&text)?)
}

pub fn save_config(base: &Path, cfg: &Config) -> Result<(), ConfigError> {
    ensure_dir(base)?;
    std::fs::write(config_path(base), cfg.to_toml())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 发布状态
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct PublishFile {
    own_revision: u64,
    last_published_toml: Option<String>,
}

/// TOML 的顶层不能直接是数组，所以套一层表。
#[derive(Serialize, Deserialize, Default)]
struct RulesDoc {
    #[serde(default)]
    rules: Vec<crate::rules::Rule>,
}

pub fn publish_state_path(base: &Path) -> PathBuf {
    data_dir(base).join("publish_state.json")
}

/// 读发布状态。**读不到时返回 revision = 0**，调用方必须保证"发布前先 +1"。
pub fn load_publish_state(base: &Path) -> PublishState {
    let p = publish_state_path(base);
    let Ok(text) = std::fs::read_to_string(&p) else {
        return PublishState::default();
    };
    let Ok(f) = serde_json::from_str::<PublishFile>(&text) else {
        return PublishState::default();
    };
    let last = f
        .last_published_toml
        .and_then(|t| toml::from_str::<RulesDoc>(&t).ok())
        .map(|d| d.rules)
        .unwrap_or_default();
    PublishState { own_revision: f.own_revision, last_published: last }
}

pub fn save_publish_state(base: &Path, st: &PublishState) -> std::io::Result<()> {
    ensure_dir(&data_dir(base))?;
    let rules_toml = toml::to_string(&RulesDoc { rules: st.last_published.clone() }).unwrap_or_default();
    let f = PublishFile {
        own_revision: st.own_revision,
        last_published_toml: Some(rules_toml),
    };
    let text = serde_json::to_string_pretty(&f).unwrap_or_default();
    std::fs::write(publish_state_path(base), text)
}

// ---------------------------------------------------------------------------
// 共享规则集
// ---------------------------------------------------------------------------

pub fn shared_rules_path(base: &Path) -> PathBuf {
    data_dir(base).join("shared_rules.toml")
}

#[derive(Serialize, Deserialize)]
struct SharedRulesFile {
    publisher: String,
    revision: u64,
    issued_at: u64,
    rules: Vec<crate::rules::Rule>,
    hmac: Option<Vec<u8>>,
}

pub fn load_shared_rules(base: &Path) -> Option<RuleSetAd> {
    let text = std::fs::read_to_string(shared_rules_path(base)).ok()?;
    let f: SharedRulesFile = toml::from_str(&text).ok()?;
    let publisher = f.publisher.parse().ok()?;
    let hmac = f.hmac.and_then(|v| {
        if v.len() == 16 {
            let mut a = [0u8; 16];
            a.copy_from_slice(&v);
            Some(a)
        } else {
            None
        }
    });
    Some(RuleSetAd { publisher, revision: f.revision, issued_at: f.issued_at, rules: f.rules, hmac })
}

pub fn save_shared_rules(base: &Path, rs: &RuleSetAd) -> std::io::Result<()> {
    ensure_dir(&data_dir(base))?;
    let f = SharedRulesFile {
        publisher: rs.publisher.to_string(),
        revision: rs.revision,
        issued_at: rs.issued_at,
        rules: rs.rules.clone(),
        hmac: rs.hmac.map(|h| h.to_vec()),
    };
    let text = toml::to_string_pretty(&f).unwrap_or_default();
    std::fs::write(shared_rules_path(base), text)
}

pub fn clear_shared_rules(base: &Path) -> std::io::Result<()> {
    let p = shared_rules_path(base);
    if p.exists() {
        std::fs::remove_file(p)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{EgressTarget, HostMatcher, PortMatcher, Rule};

    fn tmp() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "hiveproxy-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn config_roundtrip_and_init() {
        let d = tmp();
        let cfg = load_or_init_config(&d).unwrap();
        assert_eq!(cfg.listen.ports, vec![5678]);
        assert!(config_path(&d).exists(), "首次启动应当落一份模板配置");

        let mut c2 = cfg.clone();
        c2.listen.ports = vec![20000];
        save_config(&d, &c2).unwrap();
        assert_eq!(load_config(&d).unwrap().listen.ports, vec![20000]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn publish_state_survives_restart() {
        // 这是最容易漏测的一条：revision 不落盘 → 重启后发布被全网永久忽略。
        let d = tmp();
        assert_eq!(load_publish_state(&d).own_revision, 0);

        let st = PublishState {
            own_revision: 7,
            last_published: vec![Rule::new(
                HostMatcher::parse("*.corp.example.com").unwrap(),
                PortMatcher::Exact(443),
                EgressTarget::Block,
            )],
        };
        save_publish_state(&d, &st).unwrap();

        let back = load_publish_state(&d);
        assert_eq!(back.own_revision, 7, "revision 必须跨重启保持");
        assert_eq!(back.last_published, st.last_published);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn shared_rules_survive_restart() {
        let d = tmp();
        assert!(load_shared_rules(&d).is_none());

        let rs = RuleSetAd {
            publisher: "10.1.2.3".parse().unwrap(),
            revision: 12,
            issued_at: 1_700_000_000,
            rules: vec![Rule::new(
                HostMatcher::parse("10.9.0.0/16").unwrap(),
                PortMatcher::Any,
                EgressTarget::Auto,
            )],
            hmac: Some([9u8; 16]),
        };
        save_shared_rules(&d, &rs).unwrap();
        let back = load_shared_rules(&d).expect("应当能读回");
        assert_eq!(back, rs);

        clear_shared_rules(&d).unwrap();
        assert!(load_shared_rules(&d).is_none());
        std::fs::remove_dir_all(&d).ok();
    }
}
