//! A wallet for held grant tokens.
//!
//! A capability is a bearer token: to *use* a grant you must hold its hex token and present it. The
//! CE capability model (`ce wallet add ... --cap <token>`) assumes a place to keep those tokens; this
//! module is ce-iam's: a labeled, durable store of grants the principal holds, so a minted or received
//! token can be saved under a name, listed, inspected, and looked up by label instead of pasted by
//! hand.
//!
//! The wallet is purely local convenience. It never affects authorization: a token's authority is
//! fixed by its signed bytes, and storing it in a wallet neither broadens nor narrows it. Labels are
//! metadata for humans. The store persists atomically (temp-file + rename) via [`crate::store`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::IamError;
use crate::grant::Iam;
use crate::store::{atomic_write_json, load_json_or_default};

/// Max number of entries a wallet may hold. Bounds growth for a long-lived store; far more than any
/// human juggles by hand.
pub const MAX_WALLET_ENTRIES: usize = 10_000;

/// Max byte length of a single stored token. A capability chain token is hex-encoded bincode; even a
/// deep chain is a few KiB. This bounds what a forged/garbage label entry can cost and matches the
/// verifier's own token-size guard (see [`Iam::with_max_token_bytes`]).
pub const MAX_TOKEN_BYTES: usize = 256 * 1024;

/// Max length of a wallet label.
pub const MAX_LABEL_LEN: usize = 256;

/// One held grant: its label, the hex token, and the time it was added (unix seconds, `0` if
/// unknown). The token is stored verbatim — never re-signed or mutated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletEntry {
    /// Human label, unique within the wallet.
    pub label: String,
    /// The hex capability-chain token.
    pub token: String,
    /// When this entry was added (unix seconds). `0` = unknown.
    #[serde(default)]
    pub added_at: u64,
    /// Optional free-text note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A durable, labeled store of held grant tokens.
///
/// ```
/// use ce_iam::{Iam, Principal, ResourceMatch, Conditions, WalletStore, simple_policy};
/// use ce_iam::Identity;
/// # fn demo() -> Result<(), ce_iam::IamError> {
/// let iam = Iam::new().with_action_universe(["storage:read".into()]);
/// let issuer = Identity::from_secret_bytes(&[7u8; 32]);
/// let pol = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
/// let grant = iam.mint(&issuer, Principal(issuer.node_id()), &pol, 1)?;
///
/// let mut wallet = WalletStore::in_memory();
/// wallet.add(&iam, "my-grant", &grant.token, None, 0)?;
/// assert_eq!(wallet.token("my-grant"), Some(grant.token.as_str()));
/// assert!(wallet.remove("my-grant")?);
/// # Ok(()) }
/// # demo().unwrap();
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WalletStore {
    /// label -> entry, `BTreeMap` so serialization/listing is deterministic.
    entries: BTreeMap<String, WalletEntry>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl WalletStore {
    /// Open (or create) the wallet at `<iam_dir>/wallet.json`. A missing file yields an empty wallet.
    pub fn open(dir: &Path) -> Result<WalletStore, IamError> {
        let path = dir.join("wallet.json");
        let mut w: WalletStore = load_json_or_default(&path)?;
        w.path = Some(path);
        Ok(w)
    }

    /// An in-memory wallet with no backing file (for tests / ephemeral use). [`WalletStore::save`]
    /// is a no-op until a path is attached.
    pub fn in_memory() -> WalletStore {
        WalletStore::default()
    }

    /// Persist the wallet atomically. No-op if the wallet has no backing path.
    fn save(&self) -> Result<(), IamError> {
        match &self.path {
            Some(p) => atomic_write_json(p, self),
            None => Ok(()),
        }
    }

    /// Number of stored grants.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the wallet is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Validate and decode `token`, then store it under `label`. The token is *parsed* with `iam`
    /// before storing so a wallet never accumulates undecodeable junk; a malformed token is an `Err`.
    /// Returns [`IamError::BadPolicy`] for a bad label, an oversized token, a full wallet, or a label
    /// that already exists (use [`WalletStore::remove`] first to overwrite).
    pub fn add(
        &mut self,
        iam: &Iam,
        label: impl Into<String>,
        token: impl Into<String>,
        note: Option<String>,
        now: u64,
    ) -> Result<(), IamError> {
        let label = label.into();
        let token = token.into();
        if label.trim().is_empty() {
            return Err(IamError::BadPolicy("wallet label must not be empty".into()));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(IamError::BadPolicy(format!(
                "wallet label exceeds {MAX_LABEL_LEN} bytes"
            )));
        }
        if token.len() > MAX_TOKEN_BYTES {
            return Err(IamError::BadPolicy(format!(
                "token exceeds the {MAX_TOKEN_BYTES}-byte wallet limit"
            )));
        }
        if self.entries.contains_key(&label) {
            return Err(IamError::BadPolicy(format!(
                "wallet already has a grant labeled '{label}' (remove it first to replace)"
            )));
        }
        if self.entries.len() >= MAX_WALLET_ENTRIES {
            return Err(IamError::BadPolicy(format!(
                "wallet is full ({MAX_WALLET_ENTRIES} entries)"
            )));
        }
        // Decode-check: a wallet only ever holds tokens that parse to a chain.
        iam.decode(&token)?;
        self.entries.insert(
            label.clone(),
            WalletEntry {
                label,
                token,
                added_at: now,
                note,
            },
        );
        self.save()
    }

    /// Look up a stored grant by label.
    pub fn get(&self, label: &str) -> Option<&WalletEntry> {
        self.entries.get(label)
    }

    /// The token for a label, if present.
    pub fn token(&self, label: &str) -> Option<&str> {
        self.entries.get(label).map(|e| e.token.as_str())
    }

    /// All entries, in label order.
    pub fn list(&self) -> Vec<&WalletEntry> {
        self.entries.values().collect()
    }

    /// Remove a grant by label. Returns whether anything was removed; persists if so.
    pub fn remove(&mut self, label: &str) -> Result<bool, IamError> {
        let removed = self.entries.remove(label).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Conditions, ResourceMatch};
    use crate::{Identity, Principal, ce_cloud_action_universe, simple_policy};

    fn iam() -> Iam {
        Iam::new().with_action_universe(ce_cloud_action_universe())
    }

    fn tmp_token(iam: &Iam) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ce-iam-wallet-id-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let issuer = Identity::load_or_generate(&dir).unwrap();
        let pol = simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Any,
            Conditions::default(),
        );
        iam.mint(&issuer, Principal(issuer.node_id()), &pol, 1)
            .unwrap()
            .token
    }

    fn dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("ce-iam-wallet-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn add_get_list_remove() {
        let iam = iam();
        let mut w = WalletStore::in_memory();
        let t = tmp_token(&iam);
        w.add(&iam, "mygrant", &t, None, 100).unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w.token("mygrant"), Some(t.as_str()));
        assert_eq!(w.get("mygrant").unwrap().added_at, 100);
        assert_eq!(w.list().len(), 1);
        assert!(w.remove("mygrant").unwrap());
        assert!(w.is_empty());
        assert!(!w.remove("mygrant").unwrap());
    }

    #[test]
    fn add_rejects_bad_inputs() {
        let iam = iam();
        let mut w = WalletStore::in_memory();
        let t = tmp_token(&iam);
        assert!(matches!(
            w.add(&iam, "  ", &t, None, 0).unwrap_err(),
            IamError::BadPolicy(_)
        ));
        // Malformed token is rejected on add.
        assert!(w.add(&iam, "bad", "zzzz", None, 0).is_err());
        // Oversized token.
        let huge = "a".repeat(MAX_TOKEN_BYTES + 2);
        assert!(matches!(
            w.add(&iam, "huge", &huge, None, 0).unwrap_err(),
            IamError::BadPolicy(_)
        ));
    }

    #[test]
    fn add_duplicate_label_errors() {
        let iam = iam();
        let mut w = WalletStore::in_memory();
        let t = tmp_token(&iam);
        w.add(&iam, "dup", &t, None, 0).unwrap();
        assert!(matches!(
            w.add(&iam, "dup", &t, None, 0).unwrap_err(),
            IamError::BadPolicy(_)
        ));
    }

    #[test]
    fn persists_and_reloads() {
        let iam = iam();
        let d = dir("persist");
        let t = {
            let mut w = WalletStore::open(&d).unwrap();
            let t = tmp_token(&iam);
            w.add(&iam, "g1", &t, Some("note".into()), 5).unwrap();
            t
        };
        let w2 = WalletStore::open(&d).unwrap();
        assert_eq!(w2.token("g1"), Some(t.as_str()));
        assert_eq!(w2.get("g1").unwrap().note.as_deref(), Some("note"));
    }
}
