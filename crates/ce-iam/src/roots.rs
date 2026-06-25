//! Accepted-root management and rotation.
//!
//! A verifier honors a capability chain only if it roots at a key the verifier *accepts*: its own
//! node id (always) plus any configured extra roots ([`Iam::with_accepted_roots`](crate::Iam)). For an
//! organization rooted at a long-lived signing key, **rotating** that key safely is a real operational
//! need: you cannot flip every node and every issued token at once, so a new root must be accepted
//! *alongside* the old one for an overlap window, during which live grants are re-issued under the new
//! root, before the old root is finally retired.
//!
//! This module is that workflow. [`Roots`] is a durable set of accepted roots, each with an optional
//! validity window (`not_before`/`not_after`, unix seconds). [`Roots::accepted_at`] returns the roots
//! valid at a given time — feed it to the verifier so an expired root stops being honored automatically.
//! [`Iam::reissue_under`](crate::Iam::reissue_under) migrates a live root grant to a new root key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::IamError;
use crate::principal::Principal;
use crate::store::{atomic_write_json, load_json_or_default};
use ce_identity::NodeId;

/// Max accepted roots retained. Bounds growth; an org has a handful of roots across rotations.
pub const MAX_ROOTS: usize = 1024;

/// One accepted root key with an optional validity window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootEntry {
    /// The root node id (64-hex on the wire).
    pub key: Principal,
    /// Optional label (e.g. `"org-2026"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Unix seconds before which this root is not yet accepted. `0` = accepted from any time.
    #[serde(default)]
    pub not_before: u64,
    /// Unix seconds after which this root is no longer accepted (retired). `0` = never retires.
    #[serde(default)]
    pub not_after: u64,
}

impl RootEntry {
    /// Is this root accepted at `now`?
    pub fn accepted_at(&self, now: u64) -> bool {
        if self.not_before != 0 && now < self.not_before {
            return false;
        }
        if self.not_after != 0 && now > self.not_after {
            return false;
        }
        true
    }
}

/// A durable set of accepted root keys, keyed by hex so each key appears at most once.
///
/// ```
/// use ce_iam::{Principal, Roots};
/// # fn demo() -> Result<(), ce_iam::IamError> {
/// let mut roots = Roots::in_memory();
/// let old = Principal([1u8; 32]);
/// let new = Principal([2u8; 32]);
/// // Old root valid until t=1000; new root valid from t=500 — they overlap in [500, 1000].
/// roots.add(old, Some("old".into()), 0, 1000)?;
/// roots.add(new, Some("new".into()), 500, 0)?;
/// assert_eq!(roots.accepted_at(750).len(), 2);   // both honored during overlap
/// assert_eq!(roots.accepted_at(1500), vec![new.node_id()]); // only the new root after retirement
/// # Ok(()) }
/// # demo().unwrap();
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Roots {
    roots: BTreeMap<String, RootEntry>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl Roots {
    /// Open (or create) the roots store at `<iam_dir>/roots.json`.
    pub fn open(dir: &Path) -> Result<Roots, IamError> {
        let path = dir.join("roots.json");
        let mut r: Roots = load_json_or_default(&path)?;
        r.path = Some(path);
        Ok(r)
    }

    /// An in-memory roots set with no backing file.
    pub fn in_memory() -> Roots {
        Roots::default()
    }

    fn save(&self) -> Result<(), IamError> {
        match &self.path {
            Some(p) => atomic_write_json(p, self),
            None => Ok(()),
        }
    }

    /// Number of configured roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// True if no roots are configured.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Add (or replace) an accepted root with a validity window. A `not_after` earlier than a
    /// non-zero `not_before` is rejected (an empty window accepts nothing — almost certainly a
    /// mistake). Persists atomically.
    pub fn add(
        &mut self,
        key: Principal,
        label: Option<String>,
        not_before: u64,
        not_after: u64,
    ) -> Result<(), IamError> {
        if not_before != 0 && not_after != 0 && not_after < not_before {
            return Err(IamError::BadPolicy(
                "root not_after is before not_before (empty validity window)".into(),
            ));
        }
        if !self.roots.contains_key(&key.hex()) && self.roots.len() >= MAX_ROOTS {
            return Err(IamError::BadPolicy(format!(
                "roots set is full ({MAX_ROOTS})"
            )));
        }
        self.roots.insert(
            key.hex(),
            RootEntry {
                key,
                label,
                not_before,
                not_after,
            },
        );
        self.save()
    }

    /// Retire a root at time `at`: set its `not_after` to `at` so it stops being accepted afterward
    /// (an overlap-safe retirement, vs. an immediate hard delete). Returns `false` if the root is
    /// unknown. Persists if changed.
    pub fn retire(&mut self, key: &Principal, at: u64) -> Result<bool, IamError> {
        match self.roots.get_mut(&key.hex()) {
            Some(e) => {
                e.not_after = at;
                self.save()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Hard-remove a root entirely. Returns whether anything was removed; persists if so.
    pub fn remove(&mut self, key: &Principal) -> Result<bool, IamError> {
        let removed = self.roots.remove(&key.hex()).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// All configured roots, in hex order (includes retired/not-yet-valid ones — use
    /// [`Roots::accepted_at`] to filter by time).
    pub fn all(&self) -> Vec<&RootEntry> {
        self.roots.values().collect()
    }

    /// The root node ids accepted at `now` — feed this to
    /// [`Iam::with_accepted_roots`](crate::Iam::with_accepted_roots) so the verifier honors exactly
    /// the roots inside their validity window at the request time.
    pub fn accepted_at(&self, now: u64) -> Vec<NodeId> {
        self.roots
            .values()
            .filter(|e| e.accepted_at(now))
            .map(|e| e.key.node_id())
            .collect()
    }

    /// Is `key` an accepted root at `now`?
    pub fn is_accepted(&self, key: &NodeId, now: u64) -> bool {
        self.roots
            .values()
            .any(|e| &e.key.node_id() == key && e.accepted_at(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(b: u8) -> Principal {
        Principal([b; 32])
    }

    fn dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("ce-iam-roots-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn add_and_accept_within_window() {
        let mut r = Roots::in_memory();
        r.add(p(1), Some("a".into()), 100, 200).unwrap();
        assert!(!r.is_accepted(&p(1).node_id(), 50));
        assert!(r.is_accepted(&p(1).node_id(), 150));
        assert!(!r.is_accepted(&p(1).node_id(), 250));
        assert_eq!(r.accepted_at(150), vec![p(1).node_id()]);
        assert!(r.accepted_at(50).is_empty());
    }

    #[test]
    fn no_window_means_always() {
        let mut r = Roots::in_memory();
        r.add(p(2), None, 0, 0).unwrap();
        assert!(r.is_accepted(&p(2).node_id(), 0));
        assert!(r.is_accepted(&p(2).node_id(), u64::MAX));
    }

    #[test]
    fn rotation_overlap_window() {
        // old root valid until 1000; new root valid from 500 — both accepted in [500,1000].
        let mut r = Roots::in_memory();
        r.add(p(1), Some("old".into()), 0, 1000).unwrap();
        r.add(p(2), Some("new".into()), 500, 0).unwrap();
        // During overlap both are honored.
        let mut at750 = r.accepted_at(750);
        at750.sort();
        let mut want = vec![p(1).node_id(), p(2).node_id()];
        want.sort();
        assert_eq!(at750, want);
        // After the old root retires, only the new one remains.
        assert_eq!(r.accepted_at(1500), vec![p(2).node_id()]);
    }

    #[test]
    fn retire_sets_not_after() {
        let mut r = Roots::in_memory();
        r.add(p(1), None, 0, 0).unwrap();
        assert!(r.is_accepted(&p(1).node_id(), 1000));
        assert!(r.retire(&p(1), 500).unwrap());
        assert!(r.is_accepted(&p(1).node_id(), 499));
        assert!(!r.is_accepted(&p(1).node_id(), 501));
        assert!(!r.retire(&p(9), 0).unwrap());
    }

    #[test]
    fn rejects_empty_window() {
        let mut r = Roots::in_memory();
        assert!(matches!(
            r.add(p(1), None, 200, 100).unwrap_err(),
            IamError::BadPolicy(_)
        ));
    }

    #[test]
    fn persists_and_reloads() {
        let d = dir("persist");
        {
            let mut r = Roots::open(&d).unwrap();
            r.add(p(1), Some("k".into()), 10, 20).unwrap();
        }
        let r2 = Roots::open(&d).unwrap();
        assert_eq!(r2.len(), 1);
        assert!(r2.is_accepted(&p(1).node_id(), 15));
    }
}
