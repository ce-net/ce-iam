//! Access audit log for the authenticated mesh KV ([`crate::authkv`]) — "who read/wrote/deleted what,
//! when, allowed or denied".
//!
//! This is the *monitoring* half of access control: [`crate::authkv`] decides allow/deny; the audit
//! makes every decision observable. It is a bounded in-memory event ring plus unbounded per-`(actor,
//! target)` counters, so an operator can answer "how many times did node X read `s.cast-key-youtube`,
//! and when last?" — and a DENIED attempt is recorded too, so probing is visible even when (during a
//! staged rollout) it is not yet blocked.
//!
//! It was lifted verbatim-in-spirit from `cast-control`'s private audit so every vault/KV in the mesh
//! shares ONE audit shape instead of each app re-inventing it (gap #4: one shared standard).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The kind of access being audited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// A KV record was read (`get`/`list`) — audited only for SENSITIVE keys (high-volume otherwise).
    KvRead,
    /// A KV record was written (`put`).
    KvWrite,
    /// A KV record was deleted (`del`).
    KvDelete,
}

/// One audited access event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix seconds when it happened (when).
    pub at: u64,
    /// The authenticated mesh NodeId that made the request (who).
    pub actor: String,
    /// What kind of access.
    pub action: Action,
    /// The key/record name touched (what).
    pub target: String,
    /// The vault namespace the access was scoped to (where).
    pub ns: String,
    /// Whether it was allowed (false = an authorization failure was recorded — visible probing).
    pub allowed: bool,
}

/// Per-`(actor, target)` running totals, so "how many reads, last when" is O(1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    pub allowed: u64,
    pub denied: u64,
    pub last_at: u64,
}

/// The maximum number of events retained in the ring (older events are dropped; counters are kept
/// forever so totals never lose history).
pub const MAX_EVENTS: usize = 4096;

/// The audit log: a bounded event ring + unbounded per-`(actor, target)` counters.
pub struct Audit {
    ns: String,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    events: VecDeque<Event>,
    counters: HashMap<(String, String), Counter>,
}

/// Unix seconds now (0 on a clock error — never panics).
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Audit {
    /// A fresh audit log scoped to vault namespace `ns`.
    pub fn new(ns: impl Into<String>) -> Self {
        Audit { ns: ns.into(), inner: Mutex::new(Inner::default()) }
    }

    /// Record one access. Returns the event (so the caller can emit it on the mesh). Never panics: a
    /// poisoned lock degrades to dropping the record rather than taking down the serve loop.
    pub fn record(&self, actor: &str, action: Action, target: &str, allowed: bool) -> Event {
        let ev = Event {
            at: now_secs(),
            actor: actor.to_string(),
            action,
            target: target.to_string(),
            ns: self.ns.clone(),
            allowed,
        };
        if let Ok(mut g) = self.inner.lock() {
            let c = g.counters.entry((ev.actor.clone(), ev.target.clone())).or_default();
            if allowed {
                c.allowed += 1;
            } else {
                c.denied += 1;
            }
            c.last_at = ev.at;
            g.events.push_back(ev.clone());
            while g.events.len() > MAX_EVENTS {
                g.events.pop_front();
            }
        }
        ev
    }

    /// The most recent `limit` events, newest last.
    pub fn recent(&self, limit: usize) -> Vec<Event> {
        self.inner
            .lock()
            .map(|g| g.events.iter().rev().take(limit).rev().cloned().collect())
            .unwrap_or_default()
    }

    /// A snapshot of the per-`(actor, target)` counters.
    pub fn counters(&self) -> Vec<(String, String, Counter)> {
        self.inner
            .lock()
            .map(|g| g.counters.iter().map(|((a, t), c)| (a.clone(), t.clone(), c.clone())).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_counts_allowed_and_denied() {
        let a = Audit::new("vault-1");
        a.record("nodeA", Action::KvWrite, "s.cast-key-youtube", true);
        a.record("nodeA", Action::KvWrite, "s.cast-key-youtube", true);
        a.record("nodeB", Action::KvRead, "s.cast-key-youtube", false); // a denied probe is recorded

        let counters = a.counters();
        let na = counters.iter().find(|(act, t, _)| act == "nodeA" && t == "s.cast-key-youtube").unwrap();
        assert_eq!(na.2.allowed, 2);
        assert_eq!(na.2.denied, 0);
        let nb = counters.iter().find(|(act, _, _)| act == "nodeB").unwrap();
        assert_eq!(nb.2.denied, 1, "denied attempts are visible");

        let recent = a.recent(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent.last().unwrap().actor, "nodeB");
        assert!(!recent.last().unwrap().allowed);
        assert_eq!(recent[0].ns, "vault-1");
    }

    #[test]
    fn event_ring_is_bounded_but_counters_persist() {
        let a = Audit::new("v");
        for _ in 0..(MAX_EVENTS + 50) {
            a.record("n", Action::KvWrite, "s.k", true);
        }
        assert_eq!(a.recent(usize::MAX).len(), MAX_EVENTS, "ring is capped");
        let c = a.counters();
        let total: u64 = c.iter().map(|(_, _, c)| c.allowed).sum();
        assert_eq!(total, (MAX_EVENTS + 50) as u64, "counters keep full history");
    }
}
