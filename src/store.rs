//! Durable, atomic JSON persistence for the managed IAM surface.
//!
//! The security core ([`crate::Iam`]) is stateless on purpose. But the *managed product* parts —
//! the role/policy [`Catalog`](crate::Catalog), the held-grant [`WalletStore`](crate::WalletStore),
//! and the accepted-[`Roots`](crate::Roots) set — are durable single-node stores. This module gives
//! them all one tested persistence primitive: **atomic** JSON write (temp-file + fsync + rename) so a
//! crash mid-write can never corrupt the on-disk file, plus a tolerant load that treats a missing file
//! as the type's `Default`.
//!
//! ## Why this is "real ce-coord, sliced"
//!
//! ce-coord's replicated map is a single-writer, version-ordered op-log applied deterministically on
//! every replica. The [`Catalog`](crate::Catalog) already *is* that deterministic state machine. What
//! was missing — and what this module supplies — is the **durable writer half**: an on-disk op-log
//! ([`CatalogStore`]) that appends each [`CatalogOp`](crate::CatalogOp), persists it atomically, and
//! reconstructs the catalog by replay on load. That is exactly what a ce-coord writer node persists
//! locally before it broadcasts. The mesh-broadcast/await-version half (multi-node replication) is the
//! part that needs a running node and is documented as **deferred** in the README; the durable,
//! reload-stable, op-logged store this module provides is fully real and tested.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::catalog::{Catalog, CatalogLog, CatalogOp};
use crate::error::IamError;
use crate::principal::Principal;

/// Hard cap on the size of any IAM state file we will read, in bytes. A catalog/wallet/roots file
/// larger than this is treated as corrupt rather than loaded — bounding memory for a store that an
/// attacker (or a bug) might have grown without limit. 64 MiB is enormous for text JSON of
/// roles/grants yet still safely bounded.
pub const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;

/// Resolve the IAM data directory (`<data_dir>/iam`), creating it if missing. With no explicit
/// `data_dir`, uses the standard CE data dir so ce-iam shares the node's layout.
pub fn iam_dir(explicit: Option<&Path>) -> Result<PathBuf, IamError> {
    let base = match explicit {
        Some(p) => p.to_path_buf(),
        None => directories::ProjectDirs::from("", "", "ce")
            .map(|d| d.data_dir().to_path_buf())
            .ok_or_else(|| {
                IamError::Node("cannot determine the default CE data dir; pass --data-dir".into())
            })?,
    };
    let dir = base.join("iam");
    fs::create_dir_all(&dir)
        .map_err(|e| IamError::Node(format!("creating iam dir {}: {e}", dir.display())))?;
    Ok(dir)
}

/// Atomically write `value` as pretty JSON to `path`: serialize to a sibling temp file, fsync it,
/// then rename over the target. A crash at any point leaves either the old file or the new file
/// intact — never a half-written one. The temp file carries the process id so concurrent writers in
/// different processes do not collide on the scratch name.
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), IamError> {
    let parent = path
        .parent()
        .ok_or_else(|| IamError::Node(format!("path {} has no parent dir", path.display())))?;
    fs::create_dir_all(parent)
        .map_err(|e| IamError::Node(format!("creating {}: {e}", parent.display())))?;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| IamError::Node(format!("serializing store: {e}")))?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| IamError::Node(format!("path {} has no file name", path.display())))?;
    let tmp = parent.join(format!(".{}.{}.tmp", file_name, std::process::id()));

    // Write + flush + fsync the temp file, then rename. Scope the file handle so it is closed
    // before the rename on platforms (Windows) that dislike renaming an open file.
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| IamError::Node(format!("creating temp {}: {e}", tmp.display())))?;
        f.write_all(&bytes)
            .map_err(|e| IamError::Node(format!("writing temp {}: {e}", tmp.display())))?;
        f.flush()
            .map_err(|e| IamError::Node(format!("flushing temp {}: {e}", tmp.display())))?;
        // Best-effort durability; a failed fsync is surfaced.
        f.sync_all()
            .map_err(|e| IamError::Node(format!("fsync temp {}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        // Clean up the temp file on a failed rename so we do not leak scratch files.
        let _ = fs::remove_file(&tmp);
        IamError::Node(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(())
}

/// Load a JSON store from `path`, returning [`Default`] if the file is absent. Enforces
/// [`MAX_STORE_BYTES`] before reading so an oversized file cannot exhaust memory, and surfaces a
/// clear error (never a panic) on a corrupt/oversized/unreadable file.
pub fn load_json_or_default<T: DeserializeOwned + Default>(path: &Path) -> Result<T, IamError> {
    match fs::metadata(path) {
        Ok(meta) => {
            if meta.len() > MAX_STORE_BYTES {
                return Err(IamError::Node(format!(
                    "store {} is {} bytes, exceeding the {MAX_STORE_BYTES}-byte limit",
                    path.display(),
                    meta.len()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(e) => {
            return Err(IamError::Node(format!("stat {}: {e}", path.display())));
        }
    }
    let text = fs::read_to_string(path)
        .map_err(|e| IamError::Node(format!("reading {}: {e}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|e| IamError::Node(format!("parsing {}: {e}", path.display())))
}

/// A bound on how many ops a single catalog op-log file may hold before [`CatalogStore`] refuses
/// further writes. This is the unbounded-growth guard for the on-disk catalog: roles/policies are
/// keyed maps (bounded by distinct names), but the op-log and audit trail grow per write. Past this
/// many ops, an operator should compact (see [`CatalogStore::compact`]).
pub const MAX_CATALOG_OPS: usize = 100_000;

/// A durable, single-writer, op-logged catalog store.
///
/// This is the persisted writer half of the ce-coord model: it keeps the full [`CatalogLog`] on
/// disk and reconstructs the live [`Catalog`] by replaying it on load. Every mutating call appends
/// one [`CatalogOp`], persists the log atomically, and folds the op into the in-memory catalog — so
/// the on-disk log and the in-memory state never diverge, and a reload reproduces the exact catalog
/// (the reload round-trip property tested in `tests/store.rs`).
#[derive(Debug, Clone)]
pub struct CatalogStore {
    path: PathBuf,
    log: CatalogLog,
    catalog: Catalog,
}

impl CatalogStore {
    /// Open (or create) the catalog store at `<iam_dir>/catalog.json`. A missing file yields an
    /// empty catalog; an existing one is replayed into the live catalog.
    pub fn open(dir: &Path) -> Result<CatalogStore, IamError> {
        let path = dir.join("catalog.json");
        let log: CatalogLog = load_json_or_default(&path)?;
        if log.len() > MAX_CATALOG_OPS {
            return Err(IamError::Node(format!(
                "catalog op-log at {} has {} ops, exceeding the {MAX_CATALOG_OPS} limit",
                path.display(),
                log.len()
            )));
        }
        let catalog = log.replay();
        Ok(CatalogStore { path, log, catalog })
    }

    /// The live (replayed) catalog. Read-only; mutate through the store's methods so writes persist.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The number of ops in the durable log (== the catalog version).
    pub fn op_count(&self) -> usize {
        self.log.len()
    }

    /// Apply one op: validate it against the *current* catalog (so attach-of-missing-role etc. is
    /// rejected before it ever touches disk), append to the log, persist atomically, then fold it in.
    /// On a persistence failure the in-memory state is left untouched, so the store and disk stay
    /// consistent.
    pub fn apply(&mut self, op: CatalogOp, actor: Option<&Principal>) -> Result<(), IamError> {
        if self.log.len() >= MAX_CATALOG_OPS {
            return Err(IamError::Node(format!(
                "catalog op-log is full ({MAX_CATALOG_OPS} ops); compact before writing more"
            )));
        }
        self.validate(&op)?;
        // Persist first against a candidate log; only commit memory once the disk write succeeds.
        let mut next = self.log.clone();
        next.record(op.clone(), actor);
        atomic_write_json(&self.path, &next)?;
        self.log = next;
        self.catalog.apply(op, actor);
        Ok(())
    }

    /// Validate an op against the live catalog using the same rules the in-memory [`Catalog`]
    /// enforces, so a durable write can never record an invalid op.
    fn validate(&self, op: &CatalogOp) -> Result<(), IamError> {
        match op {
            CatalogOp::PutRole(r) if r.name.trim().is_empty() => {
                Err(IamError::BadPolicy("role name must not be empty".into()))
            }
            CatalogOp::PutPolicy { name, .. } if name.trim().is_empty() => {
                Err(IamError::BadPolicy("policy name must not be empty".into()))
            }
            CatalogOp::AttachRole { role, .. } if self.catalog.get_role(role).is_none() => Err(
                IamError::BadPolicy(format!("no such role '{role}' to attach")),
            ),
            _ => Ok(()),
        }
    }

    /// Compact the store: snapshot the current catalog state into a minimal op-log (one `PutRole` /
    /// `PutPolicy` per surviving object, then the attachments), discarding history and the audit
    /// trail. The live catalog is unchanged in *content* (same roles/policies/attachments) but its
    /// version resets to the compacted op count. Persisted atomically. This bounds on-disk growth for
    /// a long-lived catalog without losing any effective state.
    pub fn compact(&mut self) -> Result<(), IamError> {
        let mut log = CatalogLog::new();
        for name in self.catalog.list_roles() {
            if let Some(r) = self.catalog.get_role(&name) {
                log.record(CatalogOp::PutRole(r.clone()), None);
            }
        }
        for name in self.catalog.list_policies() {
            if let Some(p) = self.catalog.get_policy(&name) {
                log.record(
                    CatalogOp::PutPolicy {
                        name: name.clone(),
                        policy: p.clone(),
                    },
                    None,
                );
            }
        }
        for (principal, role) in self.catalog.all_attachments() {
            log.record(CatalogOp::AttachRole { principal, role }, None);
        }
        atomic_write_json(&self.path, &log)?;
        self.log = log.clone();
        self.catalog = log.replay();
        Ok(())
    }

    /// The on-disk file path (for diagnostics / CLI display).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Conditions, Policy, ResourceMatch, Role};

    fn tmp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("ce-iam-store-{}-{n}-{tag}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn reader_role(name: &str) -> Role {
        Role::new(
            name,
            Policy::allow(
                vec!["storage:read".into()],
                ResourceMatch::Any,
                Conditions::default(),
            ),
        )
    }

    #[derive(Default, serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Sample {
        a: u32,
        b: String,
    }

    #[test]
    fn atomic_write_then_load_round_trips() {
        let dir = tmp_dir("rt");
        let path = dir.join("x.json");
        let v = Sample {
            a: 7,
            b: "hi".into(),
        };
        atomic_write_json(&path, &v).unwrap();
        let back: Sample = load_json_or_default(&path).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn load_missing_file_is_default() {
        let dir = tmp_dir("missing");
        let back: Sample = load_json_or_default(&dir.join("nope.json")).unwrap();
        assert_eq!(back, Sample::default());
    }

    #[test]
    fn load_oversize_file_errors() {
        let dir = tmp_dir("oversize");
        let path = dir.join("big.json");
        // Write a > MAX_STORE_BYTES file cheaply by setting the length.
        let f = fs::File::create(&path).unwrap();
        f.set_len(MAX_STORE_BYTES + 1).unwrap();
        let r: Result<Sample, _> = load_json_or_default(&path);
        assert!(matches!(r, Err(IamError::Node(_))));
    }

    #[test]
    fn no_temp_files_left_after_write() {
        let dir = tmp_dir("notemp");
        let path = dir.join("y.json");
        atomic_write_json(&path, &Sample::default()).unwrap();
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no .tmp scratch files should survive a successful write"
        );
    }

    #[test]
    fn catalog_store_persists_and_reloads() {
        let dir = tmp_dir("cat");
        {
            let mut store = CatalogStore::open(&dir).unwrap();
            store
                .apply(CatalogOp::PutRole(reader_role("reader")), None)
                .unwrap();
            store
                .apply(
                    CatalogOp::AttachRole {
                        principal: Principal([1u8; 32]),
                        role: "reader".into(),
                    },
                    None,
                )
                .unwrap();
            assert_eq!(store.op_count(), 2);
        }
        // Reopen: the replayed catalog matches what we wrote.
        let store = CatalogStore::open(&dir).unwrap();
        assert!(store.catalog().get_role("reader").is_some());
        assert_eq!(
            store.catalog().roles_for(&Principal([1u8; 32])),
            vec!["reader".to_string()]
        );
        assert_eq!(store.op_count(), 2);
    }

    #[test]
    fn catalog_store_rejects_invalid_op_before_disk() {
        let dir = tmp_dir("reject");
        let mut store = CatalogStore::open(&dir).unwrap();
        // Attaching an unknown role must fail and must not have been persisted.
        let err = store
            .apply(
                CatalogOp::AttachRole {
                    principal: Principal([2u8; 32]),
                    role: "ghost".into(),
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, IamError::BadPolicy(_)));
        assert_eq!(store.op_count(), 0);
        // Reopen confirms nothing was written.
        let reopened = CatalogStore::open(&dir).unwrap();
        assert_eq!(reopened.op_count(), 0);
    }

    #[test]
    fn compact_preserves_state_and_shrinks_log() {
        let dir = tmp_dir("compact");
        let mut store = CatalogStore::open(&dir).unwrap();
        store
            .apply(CatalogOp::PutRole(reader_role("r")), None)
            .unwrap();
        // Churn: attach, detach, re-attach — many ops, same final state.
        store
            .apply(
                CatalogOp::AttachRole {
                    principal: Principal([3u8; 32]),
                    role: "r".into(),
                },
                None,
            )
            .unwrap();
        store
            .apply(
                CatalogOp::DetachRole {
                    principal: Principal([3u8; 32]),
                    role: "r".into(),
                },
                None,
            )
            .unwrap();
        store
            .apply(
                CatalogOp::AttachRole {
                    principal: Principal([3u8; 32]),
                    role: "r".into(),
                },
                None,
            )
            .unwrap();
        let before = store.op_count();
        store.compact().unwrap();
        assert!(
            store.op_count() < before,
            "compaction must shrink the op-log"
        );
        // State preserved: role still attached.
        assert_eq!(
            store.catalog().roles_for(&Principal([3u8; 32])),
            vec!["r".to_string()]
        );
        // And it survives a reload.
        let reopened = CatalogStore::open(&dir).unwrap();
        assert_eq!(
            reopened.catalog().roles_for(&Principal([3u8; 32])),
            vec!["r".to_string()]
        );
    }
}
