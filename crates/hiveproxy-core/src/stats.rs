//! 运行期统计（DESIGN.md §6.7、§13）。

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::proto::NodeId;
use crate::view::StatsSnapshot;

#[derive(Debug, Default)]
pub struct Stats {
    pub links: AtomicUsize,
    pub active_streams: AtomicUsize,
    pub bytes_relayed_in: AtomicU64,
    pub bytes_relayed_out: AtomicU64,
    pub frames_relayed: AtomicU64,
    pub frames_dropped_ttl: AtomicU64,
    pub frames_dropped_queue: AtomicU64,
    pub streams_dropped: AtomicU64,
    pub route_rebuilds: AtomicU64,
    pub handshakes_ok: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub unreachable_received: AtomicU64,
    pub gossip_sent: AtomicU64,
    pub gossip_received: AtomicU64,
    pub pulls_sent: AtomicU64,
    pub dial_attempts: AtomicU64,
    pub dial_failures: AtomicU64,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        let dropped = self.frames_dropped_ttl.load(Ordering::Relaxed)
            + self.frames_dropped_queue.load(Ordering::Relaxed);
        StatsSnapshot {
            links: self.links.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            bytes_relayed_in: self.bytes_relayed_in.load(Ordering::Relaxed),
            bytes_relayed_out: self.bytes_relayed_out.load(Ordering::Relaxed),
            frames_relayed: self.frames_relayed.load(Ordering::Relaxed),
            frames_dropped: dropped,
            streams_dropped: self.streams_dropped.load(Ordering::Relaxed),
            route_rebuilds: self.route_rebuilds.load(Ordering::Relaxed),
            handshakes_ok: self.handshakes_ok.load(Ordering::Relaxed),
            handshakes_failed: self.handshakes_failed.load(Ordering::Relaxed),
            unreachable_received: self.unreachable_received.load(Ordering::Relaxed),
            gossip_sent: self.gossip_sent.load(Ordering::Relaxed),
            gossip_received: self.gossip_received.load(Ordering::Relaxed),
            pulls_sent: self.pulls_sent.load(Ordering::Relaxed),
            dial_attempts: self.dial_attempts.load(Ordering::Relaxed),
            dial_failures: self.dial_failures.load(Ordering::Relaxed),
        }
    }
}

/// 每条规则的命中统计（§9.4.2 的"命中统计"优化项）。
#[derive(Debug, Default)]
pub struct RuleHits {
    inner: parking_lot::RwLock<Vec<Hit>>,
}

#[derive(Clone, Debug, Default)]
struct Hit {
    hits: u64,
    last_egress: Option<NodeId>,
    last_rejected_at: Option<u64>,
}

impl RuleHits {
    /// 规则表变化时按新的长度重置。
    pub fn resize(&self, n: usize) {
        let mut g = self.inner.write();
        g.resize(n, Hit::default());
    }

    pub fn record_hit(&self, idx: usize, egress: NodeId, now_unix: u64) {
        let mut g = self.inner.write();
        if g.len() <= idx {
            g.resize(idx + 1, Hit::default());
        }
        if let Some(h) = g.get_mut(idx) {
            h.hits += 1;
            h.last_egress = Some(egress);
            h.last_rejected_at = None;
        }
        let _ = now_unix;
    }

    pub fn record_rejected(&self, idx: usize, now_unix: u64) {
        let mut g = self.inner.write();
        if g.len() <= idx {
            g.resize(idx + 1, Hit::default());
        }
        if let Some(h) = g.get_mut(idx) {
            h.last_rejected_at = Some(now_unix);
        }
    }

    pub fn snapshot(&self, rules: &[crate::rules::Rule]) -> Vec<crate::view::RuleStat> {
        let g = self.inner.read();
        rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let h = g.get(i).cloned().unwrap_or_default();
                crate::view::RuleStat {
                    index: i,
                    label: r.label.clone(),
                    rule: format!(
                        "{}:{} → {}",
                        r.host.to_config_string(),
                        r.port.to_config_string(),
                        r.egress.to_config_string()
                    ),
                    hits: h.hits,
                    last_egress: h.last_egress,
                    last_rejected_at: h.last_rejected_at,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_totals_drops() {
        let s = Stats::default();
        s.frames_dropped_ttl.store(3, Ordering::Relaxed);
        s.frames_dropped_queue.store(4, Ordering::Relaxed);
        assert_eq!(s.snapshot().frames_dropped, 7);
    }

    #[test]
    fn rule_hits_resize_and_record() {
        use crate::rules::{EgressTarget, HostMatcher, PortMatcher, Rule};
        let rules = vec![Rule::new(HostMatcher::Any, PortMatcher::Any, EgressTarget::Auto)];
        let h = RuleHits::default();
        h.resize(rules.len());
        h.record_hit(0, "10.1.2.5".parse().unwrap(), 100);
        let snap = h.snapshot(&rules);
        assert_eq!(snap[0].hits, 1);
        assert_eq!(snap[0].last_egress, Some("10.1.2.5".parse().unwrap()));

        // 越界写入不 panic
        h.record_hit(99, "10.1.2.5".parse().unwrap(), 1);
        // 缩容后旧的统计被丢弃但长度对齐
        h.resize(0);
        assert!(h.snapshot(&[]).is_empty());
    }
}
