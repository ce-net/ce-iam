//! `AuthKv` — the ONE authenticated, mesh-native key/value store, owned by ce-iam.
//!
//! Every CE vault (the ce-iam secrets vault, the ce-cast studio vault, the browser vault) used to talk
//! to a per-app, hand-rolled `ce-kv/<ns>/1` service. `cast-control` grew the first real authorization
//! on that surface (sensitive-key classification + a `kv:write` cap gate + an audit log); but it lived
//! privately inside ce-cast, and it gated only WRITES. This module folds that into ce-iam as the single
//! standard so every app converges on one store with one trust model (gap #4), and adds the missing
//! half — capability-gated READS of sensitive records (gap #3).
//!
//! ## What it is
//!
//! A last-writer-wins map per namespace, replicated by [`ce_coord::Replicated`] (op-log + blob
//! snapshots), served over [`ce_rs::serve`]. The wire is byte-compatible with the legacy cast/`ce-kv`
//! protocol so the live `vault-<id>` collections keep converging across the browser vault, the
//! `ce-iam` CLI, and any mesh peer:
//!
//!   * `{ "op": "get",  "key": "<k>", "caps": "<hex?>" }`              -> `{ "value": <json|null> }`
//!   * `{ "op": "put",  "key": "<k>", "value": <json>, "caps": "<hex?>" }` -> `{ "ok": true }`
//!   * `{ "op": "del",  "key": "<k>", "caps": "<hex?>" }`              -> `{ "ok": true }`
//!   * `{ "op": "list", "prefix": "<p>", "limit": N, "caps": "<hex?>" }` -> `{ "items": [{key,value}, …] }`
//!
//! ## The trust model
//!
//! `from` is the mesh-authenticated sender (the local node verified it). A record's key prefix says
//! whether it is sensitive ([`is_sensitive_key`]): secrets (`s.`), device records (`d.`), grants
//! (`g.`), and the vault `meta`. Pairing requests (`p.*`) are the un-enrolled bootstrap and are NOT
//! sensitive (a new device must be able to ask to pair without already holding a cap).
//!
//!   * The WRITER node's own ops (`from == self`) — including browser writes proxied through this
//!     node's bearer-token-gated HTTP API, which self-deliver as this node id — are always allowed.
//!     This is what lets enforcement be ON without breaking the live local browser vault.
//!   * A REMOTE peer mutating a sensitive record must present a `kv:write` capability chain rooted at
//!     an accepted root; reading a sensitive record must present `kv:read`. Both verify OFFLINE via
//!     [`crate::Iam`] (the same attenuating ce-cap chains the rest of ce-iam mints).
//!   * Every sensitive decision — allow or deny — is recorded in the [`Audit`] so probing is visible.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ce_coord::Replicated;
use ce_coord::replicated::StateMachine;
use ce_identity::NodeId;
use ce_rs::CeClient;
use ce_rs::serve::{Handler, Request};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::{Action, Audit};
use crate::{Iam, Principal};

/// The ability a remote peer must hold to WRITE (`put`/`del`) a sensitive record.
pub const ABILITY_KV_WRITE: &str = "kv:write";
/// The ability a remote peer must hold to READ (`get`/`list`) a sensitive record.
pub const ABILITY_KV_READ: &str = "kv:read";

/// Whether a KV key is a SENSITIVE vault record whose access is capability-gated: secrets (`s.`),
/// device records (`d.`), grants (`g.`), and the vault `meta`. Pairing requests (`p.*`) are the
/// un-enrolled bootstrap (inert until an enrolled device approves them), so a new device can still ask
/// to pair without a cap.
pub fn is_sensitive_key(key: &str) -> bool {
    key == "meta" || key.starts_with("s.") || key.starts_with("d.") || key.starts_with("g.")
}

/// The mesh topic this KV is served on for a namespace (e.g. `vault-c0be11e0ce`): `ce-kv/<ns>/1`.
pub fn kv_topic(ns: &str) -> String {
    format!("ce-kv/{ns}/1")
}

/// The ce-coord collection name backing a namespace's KV: `ce-kv/<ns>`.
pub fn kv_collection(ns: &str) -> String {
    format!("ce-kv/{ns}")
}

/// The DHT service name a KV node advertises so clients discover which node hosts a namespace's KV
/// without hardcoding a node id. Slash-free (the node's `/discovery/find/:service` route is a single
/// path segment): `ce-kv-<ns>`.
pub fn kv_service(ns: &str) -> String {
    format!("ce-kv-{ns}")
}

/// A last-writer-wins map (per namespace), replicated by ce-coord. Wire-compatible with the legacy
/// cast `KvMap`: the serde shape (`{ "m": { … } }`) and the [`KvOp`] variant names are unchanged, so
/// existing `ce-kv/<ns>` op-logs replay into this type without a migration.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct AuthKvMap {
    pub m: BTreeMap<String, Value>,
}

/// The ce-coord op log for [`AuthKvMap`]. Variant names match the legacy cast `KvOp` for wire compat.
#[derive(Clone, Serialize, Deserialize)]
pub enum KvOp {
    Put { key: String, value: Value },
    Del { key: String },
}

impl StateMachine for AuthKvMap {
    type Op = KvOp;
    fn apply(&mut self, op: KvOp) {
        match op {
            KvOp::Put { key, value } => {
                self.m.insert(key, value);
            }
            KvOp::Del { key } => {
                self.m.remove(&key);
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum KvReq {
    Get {
        key: String,
        /// Hex ce-cap chain authorizing a sensitive READ (empty for non-sensitive / writer-local).
        #[serde(default)]
        caps: String,
    },
    Put {
        key: String,
        value: Value,
        /// Hex ce-cap chain authorizing a sensitive WRITE.
        #[serde(default)]
        caps: String,
    },
    Del {
        key: String,
        #[serde(default)]
        caps: String,
    },
    List {
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        limit: usize,
        #[serde(default)]
        caps: String,
    },
}

/// A revocation predicate: `(issuer, nonce) -> revoked?`. Default never-revoked.
type RevokeFn = Arc<dyn Fn(&NodeId, u64) -> bool + Send + Sync>;

/// The authenticated mesh KV server for one namespace. Holds the ce-coord writer, the ce-iam verifier
/// (carrying its accepted roots), the audit log, and the enforcement flags. Implements
/// [`ce_rs::serve::Handler`], so [`serve`] drives it directly over the mesh.
pub struct AuthKv {
    ns: String,
    self_id_hex: String,
    self_id: NodeId,
    kv: Replicated<AuthKvMap>,
    iam: Iam,
    audit: Audit,
    /// Enforce `kv:write` on sensitive writes from remote peers. Default OFF (migration: audit-only)
    /// until remote clients present caps; flip on once the fleet mints them.
    enforce_write: bool,
    /// Enforce `kv:read` on sensitive reads from remote peers. Default OFF; the records are ciphertext,
    /// so this is defense-in-depth (gap #3) you turn on for shared/cross-tenant namespaces.
    enforce_read: bool,
    is_revoked: RevokeFn,
}

/// Unix seconds now (0 on a clock error).
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn enc(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

impl AuthKv {
    /// Open the authenticated KV for namespace `ns` as the ce-coord WRITER on `coord`, verifying
    /// against `iam` (which carries the accepted roots an owner-issued `kv:read`/`kv:write` cap must
    /// chain to). Enforcement is OFF by default — turn it on with [`AuthKv::enforcing`].
    pub async fn open(coord: ce_coord::Coord, ns: impl Into<String>, iam: Iam) -> Result<Self> {
        let ns = ns.into();
        let self_id_hex = coord.node_id().to_string();
        let self_id = parse_node_id(&self_id_hex)
            .with_context(|| format!("local node id is not 64-hex: {self_id_hex}"))?;
        let kv = Replicated::<AuthKvMap>::writer(coord, &kv_collection(&ns))
            .await
            .context("open authkv coord writer")?;
        Ok(Self {
            audit: Audit::new(ns.clone()),
            ns,
            self_id_hex,
            self_id,
            kv,
            iam,
            enforce_write: false,
            enforce_read: false,
            is_revoked: Arc::new(|_, _| false),
        })
    }

    /// Turn on capability enforcement: `write` gates sensitive `put`/`del`; `read` gates sensitive
    /// `get`/`list`. The writer node's own ops are always allowed regardless.
    pub fn enforcing(mut self, write: bool, read: bool) -> Self {
        self.enforce_write = write;
        self.enforce_read = read;
        self
    }

    /// Supply a revocation predicate so a revoked cap link kills its subtree at verify time. Default
    /// never-revoked. Build one from an on-chain view (`ce_rs`) or a [`crate::RevocationSet`] snapshot.
    pub fn with_revocation(
        mut self,
        f: impl Fn(&NodeId, u64) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.is_revoked = Arc::new(f);
        self
    }

    /// This KV's namespace.
    pub fn ns(&self) -> &str {
        &self.ns
    }

    /// The mesh topic this KV serves on.
    pub fn topic(&self) -> String {
        kv_topic(&self.ns)
    }

    /// The DHT service name to advertise for discovery.
    pub fn service(&self) -> String {
        kv_service(&self.ns)
    }

    /// The audit log (for an admin/monitor read).
    pub fn audit(&self) -> &Audit {
        &self.audit
    }

    /// Verify that `from` holds `ability` over this KV via the presented `caps` chain. Returns
    /// `Ok(())` if authorized. The writer's own ops bypass (handled by the callers).
    fn authorize(&self, from: &str, caps: &str, ability: &str) -> Result<(), String> {
        let requester = Principal::parse(from)
            .map_err(|_| format!("sender {from} is not a verifiable node id"))?;
        let revoked = self.is_revoked.clone();
        let pred = move |issuer: &NodeId, nonce: u64| revoked(issuer, nonce);
        self.iam
            .verify(&self.self_id, &[], now_secs(), &requester, ability, caps, &pred)
            .map_err(|e| e.to_string())
    }

    /// Is a sensitive WRITE by `from` allowed? Writer-local always; otherwise pass-through when not
    /// enforcing (audit-only migration), else a real `kv:write` check.
    fn write_allowed(&self, from: &str, caps: &str) -> Result<(), String> {
        if from == self.self_id_hex {
            return Ok(());
        }
        if !self.enforce_write {
            return Ok(());
        }
        self.authorize(from, caps, ABILITY_KV_WRITE)
    }

    /// Is a sensitive READ by `from` allowed? Writer-local always; otherwise pass-through when not
    /// enforcing reads (gap #3 is opt-in), else a real `kv:read` check.
    fn read_allowed(&self, from: &str, caps: &str) -> Result<(), String> {
        if from == self.self_id_hex {
            return Ok(());
        }
        if !self.enforce_read {
            return Ok(());
        }
        self.authorize(from, caps, ABILITY_KV_READ)
    }

    /// Handle one decoded KV request and return the JSON reply bytes. Public so tests and the cast
    /// migration can drive it directly, bypassing the mesh.
    pub async fn handle_request(&self, from: &str, payload: &[u8]) -> Vec<u8> {
        let req: KvReq = match serde_json::from_slice(payload) {
            Ok(r) => r,
            Err(e) => return enc(&serde_json::json!({ "error": format!("bad kv request: {e}") })),
        };
        let resp = match req {
            KvReq::Get { key, caps } => {
                if is_sensitive_key(&key) {
                    if let Err(reason) = self.read_allowed(from, &caps) {
                        self.audit.record(from, Action::KvRead, &key, false);
                        return enc(&serde_json::json!({ "error": format!("kv read denied: {reason}") }));
                    }
                    self.audit.record(from, Action::KvRead, &key, true);
                }
                let v = self.kv.read(|m| m.m.get(&key).cloned());
                serde_json::json!({ "value": v })
            }
            KvReq::Put { key, value, caps } => {
                if let Err(reason) = self.write_allowed(from, &caps) {
                    self.audit.record(from, Action::KvWrite, &key, false);
                    serde_json::json!({ "error": format!("kv write denied: {reason}") })
                } else {
                    if is_sensitive_key(&key) {
                        self.audit.record(from, Action::KvWrite, &key, true);
                    }
                    match self.kv.propose(KvOp::Put { key, value }).await {
                        Ok(_) => serde_json::json!({ "ok": true }),
                        Err(e) => serde_json::json!({ "error": format!("put failed: {e}") }),
                    }
                }
            }
            KvReq::Del { key, caps } => {
                if let Err(reason) = self.write_allowed(from, &caps) {
                    self.audit.record(from, Action::KvDelete, &key, false);
                    serde_json::json!({ "error": format!("kv delete denied: {reason}") })
                } else {
                    if is_sensitive_key(&key) {
                        self.audit.record(from, Action::KvDelete, &key, true);
                    }
                    match self.kv.propose(KvOp::Del { key }).await {
                        Ok(_) => serde_json::json!({ "ok": true }),
                        Err(e) => serde_json::json!({ "error": format!("del failed: {e}") }),
                    }
                }
            }
            KvReq::List { prefix, limit, caps } => {
                // A list whose prefix can reach sensitive keys is a sensitive read (the empty prefix
                // lists everything). Gate it the same way as `get`.
                let touches_sensitive = prefix.is_empty() || is_sensitive_key(&prefix);
                if touches_sensitive {
                    if let Err(reason) = self.read_allowed(from, &caps) {
                        self.audit.record(from, Action::KvRead, &format!("{prefix}*"), false);
                        return enc(&serde_json::json!({ "error": format!("kv list denied: {reason}") }));
                    }
                }
                let cap = if limit == 0 { 1000 } else { limit };
                let items = self.kv.read(|m| {
                    m.m.iter()
                        .filter(|(k, _)| k.starts_with(&prefix))
                        .take(cap)
                        .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
                        .collect::<Vec<_>>()
                });
                serde_json::json!({ "items": items })
            }
        };
        enc(&resp)
    }
}

impl Handler for AuthKv {
    async fn handle(&self, req: Request) -> Vec<u8> {
        self.handle_request(&req.from, &req.payload).await
    }
}

/// Advertise this KV's service and serve it over the mesh until `shutdown` resolves. The one-call
/// entry point for `ce-iam`'s vault host: open an [`AuthKv`], then hand it here.
pub async fn serve(
    client: &CeClient,
    authkv: &AuthKv,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let service = authkv.service();
    if let Err(e) = client.advertise_service(&service).await {
        tracing::info!(error = %e, %service, "authkv advertise failed (continuing)");
    }
    let topic = authkv.topic();
    tracing::info!(ns = %authkv.ns(), %topic, "authkv serving");
    ce_rs::serve::serve(client, &[topic.as_str()], authkv, shutdown).await
}

/// Parse a 64-hex node id into a [`NodeId`].
fn parse_node_id(hexstr: &str) -> Option<NodeId> {
    hex::decode(hexstr.trim()).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kvmap_applies_put_del_wire_compatible() {
        let mut m = AuthKvMap::default();
        m.apply(KvOp::Put { key: "p.A".into(), value: serde_json::json!({ "label": "phone" }) });
        assert_eq!(m.m.get("p.A").unwrap()["label"], "phone");
        m.apply(KvOp::Del { key: "p.A".into() });
        assert!(m.m.is_empty());
        // Wire shape must stay `{ "m": { … } }` and KvOp variants `Put`/`Del` for legacy op-log replay.
        let op = KvOp::Put { key: "s.x".into(), value: serde_json::json!(1) };
        let j = serde_json::to_value(&op).unwrap();
        assert!(j.get("Put").is_some(), "KvOp must serialize as {{Put:…}} (legacy compat)");
    }

    #[test]
    fn topics_and_service() {
        assert_eq!(kv_topic("vault-c0be11e0ce"), "ce-kv/vault-c0be11e0ce/1");
        assert_eq!(kv_collection("vault-c0be11e0ce"), "ce-kv/vault-c0be11e0ce");
        assert_eq!(kv_service("vault-c0be11e0ce"), "ce-kv-vault-c0be11e0ce");
    }

    #[test]
    fn sensitivity_classification() {
        assert!(is_sensitive_key("s.cast-key-youtube"));
        assert!(is_sensitive_key("d.abc"));
        assert!(is_sensitive_key("g.gid"));
        assert!(is_sensitive_key("meta"));
        // Pairing requests are the un-enrolled bootstrap — NOT sensitive.
        assert!(!is_sensitive_key("p.ABCD"));
    }
}
