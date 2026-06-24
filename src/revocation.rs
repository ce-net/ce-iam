//! On-chain revocation view.
//!
//! Revocation in CE is on the chain: an issuer submits a `RevokeCapability` tx keyed by
//! `(issuer, nonce)`, and the node exposes the resulting set at `GET /capabilities/revoked`
//! (wrapped by [`ce_rs::CeClient::revoked`]). Revoking any link's `(issuer, nonce)` invalidates
//! that link and its whole subtree.
//!
//! This module turns that endpoint into the `is_revoked` predicate the verifier needs. The set is
//! fetched once into a [`RevocationSet`] (a snapshot) so verification stays a fast, offline,
//! in-memory lookup — you refresh the snapshot on whatever cadence your freshness needs demand.
//!
//! **Failure injection:** a node that is down, returns 5xx, or returns garbage must never crash a
//! verifier. [`RevocationSet::fetch`] returns an `Err` that the caller can handle (e.g. fall back
//! to a cached snapshot or fail closed); it never panics. [`RevocationSet::empty`] is the safe
//! offline default (revokes nothing — combine with short capability expiries for liveness).

use crate::error::IamError;
use crate::store::{atomic_write_json, load_json_or_default};
use ce_identity::NodeId;
use std::collections::HashSet;
use std::path::Path;

/// An immutable snapshot of the on-chain revoked `(issuer, nonce)` set.
#[derive(Debug, Clone, Default)]
pub struct RevocationSet {
    revoked: HashSet<(NodeId, u64)>,
}

impl RevocationSet {
    /// An empty set (revokes nothing) — the safe offline default.
    pub fn empty() -> RevocationSet {
        RevocationSet {
            revoked: HashSet::new(),
        }
    }

    /// Build directly from `(issuer_node_id, nonce)` pairs (testing / custom sources).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (NodeId, u64)>) -> RevocationSet {
        RevocationSet {
            revoked: pairs.into_iter().collect(),
        }
    }

    /// Build from the wire form returned by [`ce_rs::CeClient::revoked`]: `(issuer_hex, nonce)`.
    ///
    /// Malformed issuer hex is skipped (it cannot match any real link's id anyway) rather than
    /// failing the whole snapshot — a single bad row must not deny every grant.
    pub fn from_hex_pairs(pairs: &[(String, u64)]) -> RevocationSet {
        let mut revoked = HashSet::new();
        for (issuer_hex, nonce) in pairs {
            if let Ok(bytes) = hex::decode(issuer_hex.trim())
                && let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice())
            {
                revoked.insert((arr, *nonce));
            }
        }
        RevocationSet { revoked }
    }

    /// Fetch the current revoked set from a CE node over HTTP. Network/decoding failures are
    /// returned as [`IamError::Node`]; this never panics on a dropped peer or a 4xx/5xx.
    pub async fn fetch(client: &ce_rs::CeClient) -> Result<RevocationSet, IamError> {
        let pairs = client
            .revoked()
            .await
            .map_err(|e| IamError::Node(format!("fetching revoked set: {e}")))?;
        Ok(RevocationSet::from_hex_pairs(&pairs))
    }

    /// Is `(issuer, nonce)` revoked?
    pub fn is_revoked(&self, issuer: &NodeId, nonce: u64) -> bool {
        self.revoked.contains(&(*issuer, nonce))
    }

    /// Number of revoked entries.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// True if nothing is revoked.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// A predicate closure suitable for [`crate::Iam::verify`]'s `is_revoked` argument.
    pub fn predicate(&self) -> impl Fn(&NodeId, u64) -> bool + '_ {
        move |issuer: &NodeId, nonce: u64| self.is_revoked(issuer, nonce)
    }
}

/// How a verifier should behave when the live revocation set cannot be fetched.
///
/// Revocation is freshness-sensitive: between fetches, a verifier works from a snapshot. When the
/// node is unreachable, the operator must choose a stance. [`RevocationPolicy::FailOpen`] keeps
/// verifying against the last-known-good (or empty) snapshot — favoring availability, relying on
/// short capability expiries for safety. [`RevocationPolicy::FailClosed`] denies everything when the
/// snapshot is stale and unrefreshable — favoring safety over availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationPolicy {
    /// On fetch failure, keep using the last-known-good snapshot (deny nothing extra).
    FailOpen,
    /// On fetch failure past the TTL, deny all verification until a fresh snapshot is obtained.
    FailClosed,
}

/// A last-known-good revocation snapshot with a freshness timestamp, persisted so a verifier can keep
/// enforcing across a transient node outage instead of choosing between "block everything" and "drop
/// revocation entirely".
///
/// `fetched_at` is the unix time the snapshot was obtained; `ttl_secs` is how long it is considered
/// fresh. [`CachedRevocationSet::refresh`] tries to fetch a new snapshot, updating the cache on
/// success and leaving the previous one in place on failure. [`CachedRevocationSet::is_fresh`] tells a
/// verifier whether the snapshot is still within its TTL at `now`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CachedRevocationSet {
    /// The revoked `(issuer_hex, nonce)` pairs of the last good fetch.
    pairs: Vec<(String, u64)>,
    /// Unix seconds the snapshot was fetched. `0` = never fetched.
    pub fetched_at: u64,
    /// Freshness window in seconds. `0` = treat any snapshot as fresh forever (no TTL).
    pub ttl_secs: u64,
}

impl CachedRevocationSet {
    /// Load a cached snapshot from `path`, or a never-fetched default if absent. `ttl_secs` sets the
    /// freshness window applied going forward.
    pub fn load(path: &Path, ttl_secs: u64) -> Result<CachedRevocationSet, IamError> {
        let mut c: CachedRevocationSet = load_json_or_default(path)?;
        c.ttl_secs = ttl_secs;
        Ok(c)
    }

    /// The materialized [`RevocationSet`] from the cached pairs.
    pub fn set(&self) -> RevocationSet {
        RevocationSet::from_hex_pairs(&self.pairs)
    }

    /// Is the snapshot still fresh at `now` (fetched, and within the TTL)? A `ttl_secs` of `0` means
    /// "no TTL": any obtained snapshot is fresh. A never-fetched snapshot is never fresh.
    pub fn is_fresh(&self, now: u64) -> bool {
        if self.fetched_at == 0 {
            return false;
        }
        if self.ttl_secs == 0 {
            return true;
        }
        now.saturating_sub(self.fetched_at) <= self.ttl_secs
    }

    /// Try to refresh the snapshot from the node. On success, replace the cached pairs and stamp
    /// `fetched_at = now`, optionally persisting to `path`. On failure, the previous snapshot is kept
    /// and the error is returned (the caller decides fail-open vs fail-closed using [`is_fresh`]).
    ///
    /// [`is_fresh`]: CachedRevocationSet::is_fresh
    pub async fn refresh(
        &mut self,
        client: &ce_rs::CeClient,
        now: u64,
        path: Option<&Path>,
    ) -> Result<(), IamError> {
        let pairs = client
            .revoked()
            .await
            .map_err(|e| IamError::Node(format!("fetching revoked set: {e}")))?;
        self.pairs = pairs;
        self.fetched_at = now;
        if let Some(p) = path {
            atomic_write_json(p, self)?;
        }
        Ok(())
    }
}

/// Submit an on-chain `RevokeCapability` for a `(this-node, nonce)` grant the local node issued.
///
/// This is the one CE endpoint [`ce_rs`] does not wrap (`POST /capabilities/revoke`), so we issue
/// the authenticated request directly. `base_url` is the node API (e.g. `http://127.0.0.1:8844`);
/// `api_token` is the node's API token (see [`ce_rs::discover_api_token`]). Returns the submitted
/// transaction id. Network/HTTP failures are [`IamError::Node`], never a panic.
pub async fn submit_revoke(
    base_url: &str,
    api_token: Option<&str>,
    nonce: u64,
) -> Result<String, IamError> {
    let url = format!("{}/capabilities/revoke", base_url.trim_end_matches('/'));
    let mut req = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "nonce": nonce }));
    if let Some(t) = api_token.map(str::trim).filter(|t| !t.is_empty()) {
        req = req.bearer_auth(t);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| IamError::Node(format!("POST {url}: {e}")))?;
    if !resp.status().is_success() {
        let code = resp.status();
        // Surface the body when readable; note (rather than silently swallow) a body-read failure so
        // an operator can see why the read failed instead of seeing an empty reason.
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => format!("<failed to read response body: {e}>"),
        };
        return Err(IamError::Node(format!("revoke rejected ({code}): {body}")));
    }
    #[derive(serde::Deserialize)]
    struct R {
        #[serde(default)]
        tx_id: String,
    }
    let r: R = resp
        .json()
        .await
        .map_err(|e| IamError::Node(format!("decoding revoke response: {e}")))?;
    Ok(r.tx_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_revokes_nothing() {
        let set = RevocationSet::empty();
        assert!(set.is_empty());
        assert!(!set.is_revoked(&[0u8; 32], 0));
    }

    #[test]
    fn from_pairs_and_lookup() {
        let issuer = [7u8; 32];
        let set = RevocationSet::from_pairs([(issuer, 42)]);
        assert_eq!(set.len(), 1);
        assert!(set.is_revoked(&issuer, 42));
        assert!(!set.is_revoked(&issuer, 43));
        assert!(!set.is_revoked(&[0u8; 32], 42));
    }

    #[test]
    fn from_hex_pairs_decodes() {
        let issuer = [0xabu8; 32];
        let hexpairs = vec![(hex::encode(issuer), 5u64)];
        let set = RevocationSet::from_hex_pairs(&hexpairs);
        assert!(set.is_revoked(&issuer, 5));
    }

    #[test]
    fn from_hex_pairs_skips_malformed_rows_without_failing() {
        let good = [0x11u8; 32];
        let hexpairs = vec![
            ("not-hex".to_string(), 1u64),
            ("abcd".to_string(), 2u64), // valid hex, wrong length
            (hex::encode(good), 3u64),
        ];
        let set = RevocationSet::from_hex_pairs(&hexpairs);
        // Only the good row survives; the bad ones are skipped, not fatal.
        assert_eq!(set.len(), 1);
        assert!(set.is_revoked(&good, 3));
    }

    #[test]
    fn predicate_matches_set() {
        let issuer = [9u8; 32];
        let set = RevocationSet::from_pairs([(issuer, 1)]);
        let pred = set.predicate();
        assert!(pred(&issuer, 1));
        assert!(!pred(&issuer, 2));
    }

    #[test]
    fn cached_freshness_semantics() {
        // Never fetched => never fresh.
        let mut c = CachedRevocationSet {
            ttl_secs: 100,
            ..Default::default()
        };
        assert!(!c.is_fresh(1000));
        // Fetched at 1000, TTL 100 => fresh through 1100.
        c.fetched_at = 1000;
        assert!(c.is_fresh(1000));
        assert!(c.is_fresh(1100));
        assert!(!c.is_fresh(1101));
        // TTL 0 => fresh forever once fetched.
        c.ttl_secs = 0;
        assert!(c.is_fresh(u64::MAX));
    }

    #[test]
    fn cached_set_materializes_pairs() {
        let good = [0x22u8; 32];
        let c = CachedRevocationSet {
            pairs: vec![(hex::encode(good), 7)],
            fetched_at: 1,
            ttl_secs: 0,
        };
        let set = c.set();
        assert!(set.is_revoked(&good, 7));
    }

    #[test]
    fn cached_load_missing_is_default() {
        let dir = std::env::temp_dir().join(format!("ce-iam-rev-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = CachedRevocationSet::load(&dir.join("nope.json"), 60).unwrap();
        assert_eq!(c.fetched_at, 0);
        assert_eq!(c.ttl_secs, 60);
        assert!(!c.is_fresh(1000));
    }
}
