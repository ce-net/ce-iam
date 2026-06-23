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
use ce_identity::NodeId;
use std::collections::HashSet;

/// An immutable snapshot of the on-chain revoked `(issuer, nonce)` set.
#[derive(Debug, Clone, Default)]
pub struct RevocationSet {
    revoked: HashSet<(NodeId, u64)>,
}

impl RevocationSet {
    /// An empty set (revokes nothing) — the safe offline default.
    pub fn empty() -> RevocationSet {
        RevocationSet { revoked: HashSet::new() }
    }

    /// Build directly from `(issuer_node_id, nonce)` pairs (testing / custom sources).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (NodeId, u64)>) -> RevocationSet {
        RevocationSet { revoked: pairs.into_iter().collect() }
    }

    /// Build from the wire form returned by [`ce_rs::CeClient::revoked`]: `(issuer_hex, nonce)`.
    ///
    /// Malformed issuer hex is skipped (it cannot match any real link's id anyway) rather than
    /// failing the whole snapshot — a single bad row must not deny every grant.
    pub fn from_hex_pairs(pairs: &[(String, u64)]) -> RevocationSet {
        let mut revoked = HashSet::new();
        for (issuer_hex, nonce) in pairs {
            if let Ok(bytes) = hex::decode(issuer_hex.trim()) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    revoked.insert((arr, *nonce));
                }
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
    let mut req = reqwest::Client::new().post(&url).json(&serde_json::json!({ "nonce": nonce }));
    if let Some(t) = api_token.map(str::trim).filter(|t| !t.is_empty()) {
        req = req.bearer_auth(t);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| IamError::Node(format!("POST {url}: {e}")))?;
    if !resp.status().is_success() {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
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
}
