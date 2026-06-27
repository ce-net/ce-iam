//! The secrets vault — the Rust port of `ce-secrets/src/vault.mjs`, built on the byte-exact crypto
//! primitives in [`ce_secrets_rs`]. This is the "hold/recover secrets" half of ce-iam-core.
//!
//! ## Model (identical to the JS vault)
//!
//!   * Each **device** holds two P-256 keypairs (ECDH for wrap/unwrap, ECDSA for sign/verify),
//!     serialized as JWKs — a [`DeviceKey`].
//!   * One **vault master** key (32 bytes) encrypts every secret with AES-256-GCM. The master is
//!     DERIVED from the OWNER's ECDH scalar (HKDF, salt `ce-vault:<ns>`, info `master-v1`) so the
//!     owner can always re-establish the vault from their key alone, AND it is WRAPPED (ECIES) to
//!     every enrolled device so other devices can read it without re-deriving.
//!   * Records (device enrollments, secrets, grants) are SIGNED by the writing device (ECDSA), so
//!     tampering is detectable even when the underlying store is not itself write-authenticated.
//!
//! ## Storage is pluggable
//!
//! The vault is generic over an async [`Store`] — `get / put / del / list`. [`MemStore`] is the
//! in-memory implementation used by tests and golden vectors; production points the same vault at a
//! mesh KV (ce-coord / the ce-kv service) by implementing [`Store`] over it. No storage logic lives
//! in the vault itself.
//!
//! Keys in the store mirror the JS layout exactly:
//!   `meta` · `d.<deviceId>` · `p.<code>` · `s.<name>` · `g.<grantId>`.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};

pub use ce_secrets_rs::DeviceKey;
use ce_secrets_rs::{
    decrypt_secret, derive_owner_master, fingerprint, seal_secret, sign_record, verify_record,
    wrap_master, SealedSecret, WrapBlob,
};

// ---- the pluggable async store -------------------------------------------------------------------

/// One stored key/value pair returned by [`Store::list`].
#[derive(Debug, Clone)]
pub struct Entry {
    pub key: String,
    pub value: Value,
}

/// The vault's storage backend: an async key/value map. `value`s are JSON records. Implementations
/// must be `Send + Sync` so the vault is usable from any async runtime / mesh handler.
///
/// Mirrors the JS `ctx.store` shape (`get/put/del/list`). `list(prefix)` returns every entry whose
/// key starts with `prefix`.
pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<Value>>> + Send;
    fn put(&self, key: &str, value: Value) -> impl Future<Output = Result<()>> + Send;
    fn del(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
    fn list(&self, prefix: &str) -> impl Future<Output = Result<Vec<Entry>>> + Send;
}

/// An in-memory [`Store`] — the test/golden-vector backend (and a fine local default).
#[derive(Default)]
pub struct MemStore {
    inner: Mutex<BTreeMap<String, Value>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemStore {
    async fn get(&self, key: &str) -> Result<Option<Value>> {
        let g = self.inner.lock().map_err(|_| anyhow!("memstore poisoned"))?;
        Ok(g.get(key).cloned())
    }
    async fn put(&self, key: &str, value: Value) -> Result<()> {
        let mut g = self.inner.lock().map_err(|_| anyhow!("memstore poisoned"))?;
        g.insert(key.to_string(), value);
        Ok(())
    }
    async fn del(&self, key: &str) -> Result<()> {
        let mut g = self.inner.lock().map_err(|_| anyhow!("memstore poisoned"))?;
        g.remove(key);
        Ok(())
    }
    async fn list(&self, prefix: &str) -> Result<Vec<Entry>> {
        let g = self.inner.lock().map_err(|_| anyhow!("memstore poisoned"))?;
        Ok(g.range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| Entry {
                key: k.clone(),
                value: v.clone(),
            })
            .collect())
    }
}

// ---- vault metadata returned to callers ----------------------------------------------------------

/// A device as listed by [`Vault::list_devices`].
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub id: String,
    pub label: String,
    pub added_at: String,
    pub is_self: bool,
}

/// A secret's public metadata as listed by [`Vault::list_secrets`] (never the bytes).
#[derive(Debug, Clone)]
pub struct SecretMeta {
    pub name: String,
    pub kind: String,
    pub version: u64,
    pub fp: String,
    pub public: Option<String>,
    pub created_at: String,
    pub rotated_at: Option<String>,
}

/// The result of revealing a secret — the raw bytes for INJECTION/USE only. Never print these.
#[derive(Debug, Clone)]
pub struct RevealedSecret {
    pub bytes: Vec<u8>,
    pub kind: String,
    pub public: Option<String>,
}

/// An issued grant token (mirrors the JS `issueGrant` return).
#[derive(Debug, Clone)]
pub struct IssuedGrant {
    pub id: String,
    pub token: String,
    pub record: Value,
}

// ---- the vault -----------------------------------------------------------------------------------

/// A secrets vault bound to one device key, one namespace, and one [`Store`].
///
/// `ns` is the vault namespace (folds into the owner-master derivation salt `ce-vault:<ns>`); use a
/// stable per-vault string (e.g. the owner's node id). `now_iso` lets callers inject a deterministic
/// clock for tests/golden vectors; production uses [`Vault::new`] which reads the wall clock.
pub struct Vault<S: Store> {
    store: S,
    device: DeviceKey,
    ns: String,
    now_iso: Box<dyn Fn() -> String + Send + Sync>,
}

impl<S: Store> Vault<S> {
    /// Build a vault over `store` for `device` in namespace `ns`, using the system clock for
    /// record timestamps (ISO-8601 UTC).
    pub fn new(store: S, device: DeviceKey, ns: impl Into<String>) -> Self {
        Self {
            store,
            device,
            ns: ns.into(),
            now_iso: Box::new(now_iso_utc),
        }
    }

    /// Build a vault with an injected clock — used by tests and golden-vector generation so records
    /// are deterministic. `clock` returns the ISO-8601 timestamp written into records.
    pub fn with_clock(
        store: S,
        device: DeviceKey,
        ns: impl Into<String>,
        clock: impl Fn() -> String + Send + Sync + 'static,
    ) -> Self {
        Self {
            store,
            device,
            ns: ns.into(),
            now_iso: Box::new(clock),
        }
    }

    /// This vault's device key (the identity it acts as).
    pub fn device(&self) -> &DeviceKey {
        &self.device
    }

    /// The underlying store (for advanced callers / draining).
    pub fn store(&self) -> &S {
        &self.store
    }

    fn now(&self) -> String {
        (self.now_iso)()
    }

    // ---- master key --------------------------------------------------------------------------

    /// Load the vault master by unwrapping this device's enrolled `d.<id>` record. Errors with
    /// `NOT_ENROLLED` semantics if this device is not enrolled.
    pub async fn load_master(&self) -> Result<Vec<u8>> {
        let rec = self
            .store
            .get(&device_key(&self.device.id))
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "this device is not enrolled in the vault — run pairing and approve it from a trusted device"
                )
            })?;
        let wrapped: WrapBlob = serde_json::from_value(
            rec.get("wrappedMaster")
                .cloned()
                .ok_or_else(|| anyhow!("device record has no wrappedMaster"))?,
        )
        .context("parse wrappedMaster")?;
        decrypt_wrap(&self.device, &wrapped)
    }

    /// True if the vault has been initialised (a `meta` record exists).
    pub async fn exists(&self) -> Result<bool> {
        Ok(self.store.get("meta").await?.is_some())
    }

    /// True if THIS device is enrolled (has a `d.<id>` record).
    pub async fn is_enrolled(&self) -> Result<bool> {
        Ok(self.store.get(&device_key(&self.device.id)).await?.is_some())
    }

    /// Establish the vault from this (owner) device. Returns `false` if a vault already exists
    /// (use [`Vault::recover`] to re-establish a wiped/partial one).
    pub async fn init(&self, label: &str) -> Result<bool> {
        if self.exists().await? {
            return Ok(false);
        }
        self.recover(label).await?;
        Ok(true)
    }

    /// Re-establish the vault from the OWNER's key alone: re-derive the deterministic master and
    /// (re-)enroll this device as owner. Idempotent — the recovery primitive, safe after a store
    /// wipe so the owner is never locked out.
    pub async fn recover(&self, label: &str) -> Result<()> {
        let master = derive_owner_master(&self.device.ecdh_priv, &self.ns)
            .context("derive owner master")?;
        let lbl = if label.is_empty() {
            "this device (owner)"
        } else {
            label
        };
        self.enroll(&self.device.public_value(), &master, lbl, &self.device.id)
            .await?;
        self.store
            .put(
                "meta",
                json!({ "createdAt": self.now(), "version": 2, "owner": self.device.id }),
            )
            .await?;
        Ok(())
    }

    // ---- devices / pairing -------------------------------------------------------------------

    /// A new (unenrolled) device publishes a pairing request with its public keys. Returns the
    /// human-typable pairing code an enrolled device uses to approve it.
    pub async fn request_pairing(&self, label: &str) -> Result<String> {
        let code = pairing_code();
        let lbl = if label.is_empty() { "new device" } else { label };
        self.store
            .put(
                &pair_key(&code),
                json!({
                    "code": code,
                    "label": lbl,
                    "ts": self.now(),
                    "pub": self.device.public_value(),
                }),
            )
            .await?;
        Ok(code)
    }

    /// List pending pairing requests (their published `pub` records).
    pub async fn list_pairing(&self) -> Result<Vec<Value>> {
        Ok(self
            .store
            .list("p.")
            .await?
            .into_iter()
            .map(|e| e.value)
            .collect())
    }

    /// Approve a pairing request: wrap the master to the new device's pubkey and enroll it. Returns
    /// the newly enrolled device id.
    pub async fn approve_pairing(&self, code: &str) -> Result<String> {
        let req = self
            .store
            .get(&pair_key(code))
            .await?
            .ok_or_else(|| anyhow!("no pairing request with code {code}"))?;
        let pubv = req
            .get("pub")
            .cloned()
            .ok_or_else(|| anyhow!("pairing request has no pub"))?;
        let id = pubv
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("pairing request pub has no id"))?
            .to_string();
        let label = req
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("new device")
            .to_string();
        let master = self.load_master().await?;
        self.enroll(&pubv, &master, &label, &id).await?;
        self.store.del(&pair_key(code)).await?;
        Ok(id)
    }

    /// List enrolled devices (id/label/addedAt + whether it is this device).
    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut out = Vec::new();
        for e in self.store.list("d.").await? {
            let v = e.value;
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push(DeviceInfo {
                is_self: id == self.device.id,
                id,
                label: v.get("label").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                added_at: v.get("addedAt").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            });
        }
        Ok(out)
    }

    /// Remove a device's enrollment. Refuses to revoke the device you are using.
    pub async fn revoke_device(&self, id: &str) -> Result<()> {
        if id == self.device.id {
            bail!("refusing to revoke the device you are using");
        }
        self.store.del(&device_key(id)).await?;
        Ok(())
    }

    /// Wrap `master` to `pubv` (a device-public record/value) and write the signed `d.<id>` record.
    async fn enroll(&self, pubv: &Value, master: &[u8], label: &str, id: &str) -> Result<()> {
        let ecdh_pub = pubv
            .get("ecdhPub")
            .cloned()
            .ok_or_else(|| anyhow!("device public has no ecdhPub"))?;
        let ecdsa_pub = pubv
            .get("ecdsaPub")
            .cloned()
            .ok_or_else(|| anyhow!("device public has no ecdsaPub"))?;
        let recip: ce_secrets_rs::Jwk =
            serde_json::from_value(ecdh_pub.clone()).context("parse recipient ecdhPub")?;
        let wrapped = wrap_master(master, &recip).context("wrap master to device")?;
        // Build the record exactly as the JS `enroll` does (field set + names).
        let mut rec = Map::new();
        rec.insert("id".into(), Value::String(id.to_string()));
        rec.insert("label".into(), Value::String(label.to_string()));
        rec.insert("ecdhPub".into(), ecdh_pub);
        rec.insert("ecdsaPub".into(), ecdsa_pub);
        rec.insert("wrappedMaster".into(), serde_json::to_value(&wrapped)?);
        rec.insert("addedAt".into(), Value::String(self.now()));
        rec.insert("writer".into(), Value::String(self.device.id.clone()));
        let sig = sign_record(&self.device, &Value::Object(rec.clone()))?;
        rec.insert("sig".into(), Value::String(sig));
        self.store.put(&device_key(id), Value::Object(rec)).await?;
        Ok(())
    }

    // ---- secrets -----------------------------------------------------------------------------

    /// Store opaque secret bytes under `name`, sealed under the master. Returns the public metadata.
    pub async fn put_secret(&self, name: &str, bytes: &[u8], kind: &str) -> Result<SecretMeta> {
        self.store_secret(name, bytes, kind, None, false).await
    }

    async fn store_secret(
        &self,
        name: &str,
        bytes: &[u8],
        kind: &str,
        public: Option<String>,
        rotated: bool,
    ) -> Result<SecretMeta> {
        let master = self.load_master().await?;
        let sealed = seal_secret(&master, bytes).context("seal secret")?;
        let prev = self.store.get(&secret_key(name)).await?;
        let version = prev
            .as_ref()
            .and_then(|p| p.get("version").and_then(|v| v.as_u64()))
            .unwrap_or(0)
            + 1;
        let created_at = prev
            .as_ref()
            .and_then(|p| p.get("createdAt").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.now());
        let public = public.or_else(|| {
            prev.as_ref()
                .and_then(|p| p.get("public").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
        });
        let rotated_at = if rotated || prev.is_some() {
            Some(self.now())
        } else {
            None
        };
        let fp = fingerprint(bytes);

        let mut rec = Map::new();
        rec.insert("name".into(), Value::String(name.to_string()));
        rec.insert("type".into(), Value::String(kind.to_string()));
        rec.insert("version".into(), Value::from(version));
        rec.insert("createdAt".into(), Value::String(created_at.clone()));
        rec.insert(
            "rotatedAt".into(),
            rotated_at.clone().map(Value::String).unwrap_or(Value::Null),
        );
        rec.insert("sealed".into(), serde_json::to_value(&sealed)?);
        rec.insert(
            "public".into(),
            public.clone().map(Value::String).unwrap_or(Value::Null),
        );
        rec.insert("display".into(), Value::String(kind.to_string()));
        rec.insert("fp".into(), Value::String(fp.clone()));
        rec.insert("writer".into(), Value::String(self.device.id.clone()));
        let sig = sign_record(&self.device, &Value::Object(rec.clone()))?;
        rec.insert("sig".into(), Value::String(sig));
        self.store.put(&secret_key(name), Value::Object(rec)).await?;

        Ok(SecretMeta {
            name: name.to_string(),
            kind: kind.to_string(),
            version,
            fp,
            public,
            created_at,
            rotated_at,
        })
    }

    /// Reveal the raw secret bytes — for INJECTION/USE only. The CLI must never print these.
    pub async fn get_secret(&self, name: &str) -> Result<RevealedSecret> {
        let rec = self
            .store
            .get(&secret_key(name))
            .await?
            .ok_or_else(|| anyhow!("no secret named {name}"))?;
        let master = self.load_master().await?;
        let sealed: SealedSecret = serde_json::from_value(
            rec.get("sealed")
                .cloned()
                .ok_or_else(|| anyhow!("secret record has no sealed body"))?,
        )
        .context("parse sealed secret")?;
        let bytes = decrypt_secret(&master, &sealed).context("open secret")?;
        Ok(RevealedSecret {
            bytes,
            kind: rec.get("type").and_then(|v| v.as_str()).unwrap_or("opaque").to_string(),
            public: rec.get("public").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
    }

    /// Turnkey getter: the decrypted bytes of a secret by name. This is the `vault.get("name")` in the
    /// "any app, any device, same account — one line" story (`open_vault_default().await?.get(name)`).
    pub async fn get(&self, name: &str) -> Result<Vec<u8>> {
        Ok(self.get_secret(name).await?.bytes)
    }

    /// Turnkey setter mirroring [`get`](Self::get): store opaque bytes under `name`.
    pub async fn set(&self, name: &str, bytes: &[u8]) -> Result<SecretMeta> {
        self.put_secret(name, bytes, "opaque").await
    }

    /// List secret metadata (never bytes), sorted by name.
    pub async fn list_secrets(&self) -> Result<Vec<SecretMeta>> {
        let mut out: Vec<SecretMeta> = self
            .store
            .list("s.")
            .await?
            .into_iter()
            .map(|e| {
                let v = e.value;
                SecretMeta {
                    name: v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    kind: v.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    version: v.get("version").and_then(|x| x.as_u64()).unwrap_or(1),
                    fp: v.get("fp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    public: v.get("public").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    created_at: v.get("createdAt").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    rotated_at: v.get("rotatedAt").and_then(|x| x.as_str()).map(|s| s.to_string()),
                }
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The displayable fingerprint of a named secret, or `None` if it does not exist.
    pub async fn fingerprint(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .store
            .get(&secret_key(name))
            .await?
            .and_then(|v| v.get("fp").and_then(|x| x.as_str()).map(|s| s.to_string())))
    }

    /// Delete a named secret.
    pub async fn delete_secret(&self, name: &str) -> Result<()> {
        self.store.del(&secret_key(name)).await
    }

    // ---- grants ------------------------------------------------------------------------------

    /// Issue a signed read-grant to `audience` for the given secret names — `issueGrant` in the JS
    /// vault. The grant is a signed authorization record (mirrors a ce-cap capability shape) plus a
    /// portable base64url token. Only an enrolled device may issue.
    pub async fn issue_grant(
        &self,
        audience: &str,
        read: &[String],
        expires: Option<String>,
    ) -> Result<IssuedGrant> {
        if !self.is_enrolled().await? {
            bail!("only an enrolled device can issue grants");
        }
        let id = grant_id();
        let abilities: Vec<Value> = read
            .iter()
            .map(|n| Value::String(format!("read:{n}")))
            .collect();
        // Body fields match the JS object literal exactly (insertion order is irrelevant: signing
        // canonicalizes to sorted top-level keys; the token carries the serde form).
        let mut body = Map::new();
        body.insert("id".into(), Value::String(id.clone()));
        body.insert("audience".into(), Value::String(audience.to_string()));
        body.insert("abilities".into(), Value::Array(abilities));
        body.insert("issuer".into(), Value::String(self.device.id.clone()));
        body.insert("issued".into(), Value::String(self.now()));
        body.insert(
            "expires".into(),
            expires.clone().map(Value::String).unwrap_or(Value::Null),
        );
        let sig = sign_record(&self.device, &Value::Object(body.clone()))?;
        let mut rec = body.clone();
        rec.insert("issuerEcdsaPub".into(), serde_json::to_value(&self.device.ecdsa_pub)?);
        rec.insert("sig".into(), Value::String(sig));
        let rec = Value::Object(rec);
        self.store.put(&grant_key(&id), rec.clone()).await?;
        let token = ce_secrets_rs::encoding::b64url_encode(serde_json::to_string(&rec)?.as_bytes());
        Ok(IssuedGrant { id, token, record: rec })
    }

    /// List issued grants (id/audience/abilities/issuer/issued/expires).
    pub async fn list_grants(&self) -> Result<Vec<Value>> {
        Ok(self
            .store
            .list("g.")
            .await?
            .into_iter()
            .map(|e| e.value)
            .collect())
    }

    /// Revoke (delete) an issued grant by id.
    pub async fn revoke_grant(&self, id: &str) -> Result<()> {
        self.store.del(&grant_key(id)).await
    }

    /// Verify a presented grant token authorizes `action` on secret `name` for `audience`, proving
    /// the grant was issued by a device enrolled in THIS vault and not revoked/expired —
    /// `verifyGrant` in the JS vault. `now_ms` is the current unix-ms clock (injected for testing).
    pub async fn verify_grant(
        &self,
        token: &str,
        audience: &str,
        action: &str,
        name: &str,
        now_ms: i64,
    ) -> Result<()> {
        let raw = ce_secrets_rs::encoding::b64url_decode(token).context("bad grant token")?;
        let rec: Value = serde_json::from_slice(&raw).context("bad grant token")?;
        let obj = rec.as_object().ok_or_else(|| anyhow!("malformed grant"))?;
        let sig = obj
            .get("sig")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("malformed grant"))?;
        let issuer_pub = obj
            .get("issuerEcdsaPub")
            .ok_or_else(|| anyhow!("malformed grant"))?;
        // Reconstruct the signed body = the record minus {sig, issuerEcdsaPub}.
        let mut body = obj.clone();
        body.remove("sig");
        body.remove("issuerEcdsaPub");
        let body = Value::Object(body);
        let issuer_jwk: ce_secrets_rs::Jwk =
            serde_json::from_value(issuer_pub.clone()).context("parse issuer ecdsaPub")?;
        if !verify_record(&issuer_jwk, &body, sig)? {
            bail!("grant signature invalid");
        }
        let issuer_id = obj
            .get("issuer")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("malformed grant"))?;
        let dev = self
            .store
            .get(&device_key(issuer_id))
            .await?
            .ok_or_else(|| anyhow!("grant issuer is not an enrolled device"))?;
        if dev.get("ecdsaPub") != Some(issuer_pub) {
            bail!("grant issuer key mismatch");
        }
        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("malformed grant"))?;
        if self.store.get(&grant_key(id)).await?.is_none() {
            bail!("grant revoked");
        }
        if let Some(exp) = obj.get("expires").and_then(|v| v.as_str()) {
            if let Some(exp_ms) = ce_secrets_rs::parse_iso_ms(exp) {
                if exp_ms < now_ms {
                    bail!("grant expired");
                }
            }
        }
        if obj.get("audience").and_then(|v| v.as_str()) != Some(audience) {
            bail!("grant audience mismatch");
        }
        let want = format!("{action}:{name}");
        let want_star = format!("{action}:*");
        let abilities = obj
            .get("abilities")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("malformed grant"))?;
        let ok = abilities.iter().any(|a| {
            a.as_str().map(|s| s == want || s == want_star).unwrap_or(false)
        });
        if !ok {
            bail!("grant does not permit {action}:{name}");
        }
        Ok(())
    }

    // ---- challenge-response auth (login) -----------------------------------------------------

    /// This device signs a fresh challenge, proving it is an enrolled operator of the vault.
    /// Returns the auth proof (the wire object the relying party verifies). Mirrors the JS
    /// `signChallenge`; `ts` is the ISO-8601 timestamp bound into the signature.
    pub fn sign_challenge(&self, aud: &str, nonce: &str, ts: &str) -> Result<Value> {
        let sig = ce_secrets_rs::sign_challenge(&self.device, aud, nonce, ts)?;
        Ok(json!({
            "deviceId": self.device.id,
            "ecdsaPub": self.device.ecdsa_pub,
            "aud": aud,
            "nonce": nonce,
            "ts": ts,
            "sig": sig,
        }))
    }

    /// Verify an auth proof: the signature is valid, the signer is an ENROLLED device (its `d.<id>`
    /// ecdsaPub equals the presented one), and `aud`/`nonce` match the issued challenge. Returns the
    /// proven device id on success. Mirrors the JS `verifyAuth`.
    pub async fn verify_auth(&self, aud: &str, nonce: &str, proof: &Value) -> Result<String> {
        let p = proof.as_object().ok_or_else(|| anyhow!("malformed-proof"))?;
        let sig = p.get("sig").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("malformed-proof"))?;
        let proof_pub = p.get("ecdsaPub").ok_or_else(|| anyhow!("malformed-proof"))?;
        if p.get("aud").and_then(|v| v.as_str()) != Some(aud) {
            bail!("aud-mismatch");
        }
        if p.get("nonce").and_then(|v| v.as_str()) != Some(nonce) {
            bail!("nonce-mismatch");
        }
        let device_id = p
            .get("deviceId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("malformed-proof"))?;
        let dev = self
            .store
            .get(&device_key(device_id))
            .await?
            .ok_or_else(|| anyhow!("not-enrolled"))?;
        if dev.get("ecdsaPub") != Some(proof_pub) {
            bail!("device-key-mismatch");
        }
        let ts = p.get("ts").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("malformed-proof"))?;
        let jwk: ce_secrets_rs::Jwk =
            serde_json::from_value(proof_pub.clone()).context("parse proof ecdsaPub")?;
        if !ce_secrets_rs::verify_auth(&jwk, aud, device_id, nonce, ts, sig)? {
            bail!("bad-signature");
        }
        Ok(device_id.to_string())
    }
}

// ---- helpers -------------------------------------------------------------------------------------

/// The device-public projection of a [`DeviceKey`] as a JSON value (`{id, ecdhPub, ecdsaPub}`).
trait DeviceKeyExt {
    fn public_value(&self) -> Value;
}
impl DeviceKeyExt for DeviceKey {
    fn public_value(&self) -> Value {
        json!({
            "id": self.id,
            "ecdhPub": self.ecdh_pub,
            "ecdsaPub": self.ecdsa_pub,
        })
    }
}

fn decrypt_wrap(device: &DeviceKey, wrapped: &WrapBlob) -> Result<Vec<u8>> {
    ce_secrets_rs::unwrap_master(&device.ecdh_priv, wrapped).context("unwrap master")
}

fn secret_key(name: &str) -> String {
    format!("s.{name}")
}
fn device_key(id: &str) -> String {
    format!("d.{id}")
}
fn pair_key(code: &str) -> String {
    format!("p.{code}")
}
fn grant_key(id: &str) -> String {
    format!("g.{id}")
}

/// Random 16-hex grant id (8 random bytes) — `grantId()` in the JS vault.
fn grant_id() -> String {
    let mut b = [0u8; 8];
    ce_secrets_rs::fill_random(&mut b);
    ce_secrets_rs::encoding::hex_encode(&b)
}

/// Human-typable pairing code "XXXX-XXXX" over an unambiguous alphabet — `pairingCode()`.
fn pairing_code() -> String {
    const ALPHA: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut r = [0u8; 8];
    ce_secrets_rs::fill_random(&mut r);
    let mut s = String::with_capacity(9);
    for (i, byte) in r.iter().enumerate() {
        if i == 4 {
            s.push('-');
        }
        s.push(ALPHA[(*byte as usize) % ALPHA.len()] as char);
    }
    s
}

/// Current time as an ISO-8601 UTC string with millisecond precision (`YYYY-MM-DDTHH:MM:SS.mmmZ`),
/// matching JS `new Date().toISOString()`.
fn now_iso_utc() -> String {
    let ms = ce_secrets_rs::now_unix_ms().max(0) as u64;
    iso_from_unix_ms(ms)
}

/// Format unix-milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ` (the inverse of `parse_iso_ms`).
fn iso_from_unix_ms(ms: u64) -> String {
    let total_secs = ms / 1000;
    let millis = ms % 1000;
    let days = (total_secs / 86_400) as i64;
    let secs_of_day = total_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// Civil (proleptic Gregorian) date from days-since-epoch — inverse of Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_clock() -> impl Fn() -> String + Send + Sync + 'static {
        || "2026-06-26T00:00:00.000Z".to_string()
    }

    fn vault() -> Vault<MemStore> {
        let dk = DeviceKey::generate().unwrap();
        Vault::with_clock(MemStore::new(), dk, "test-ns", fixed_clock())
    }

    #[tokio::test]
    async fn init_recover_idempotent_and_owner_can_read() {
        let v = vault();
        assert!(v.init("owner").await.unwrap());
        assert!(!v.init("owner").await.unwrap(), "second init is a no-op");
        // Owner is enrolled and can load the master.
        assert!(v.is_enrolled().await.unwrap());
        let m1 = v.load_master().await.unwrap();
        // Recovery re-derives the SAME master (deterministic from the owner key).
        v.recover("owner").await.unwrap();
        let m2 = v.load_master().await.unwrap();
        assert_eq!(m1, m2);
    }

    #[tokio::test]
    async fn put_get_list_fingerprint_secret() {
        let v = vault();
        v.init("owner").await.unwrap();
        let meta = v.put_secret("api-key", b"s3cr3t", "opaque").await.unwrap();
        assert_eq!(meta.version, 1);
        assert_eq!(meta.fp, fingerprint(b"s3cr3t"));
        let got = v.get_secret("api-key").await.unwrap();
        assert_eq!(got.bytes, b"s3cr3t");
        // Re-put bumps the version and keeps createdAt.
        let meta2 = v.put_secret("api-key", b"rotated", "opaque").await.unwrap();
        assert_eq!(meta2.version, 2);
        let list = v.list_secrets().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(v.fingerprint("api-key").await.unwrap().unwrap(), fingerprint(b"rotated"));
        v.delete_secret("api-key").await.unwrap();
        assert!(v.list_secrets().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn pair_approve_lets_a_second_device_read() {
        // Owner establishes the vault and a secret.
        let owner_dk = DeviceKey::generate().unwrap();
        let store = MemStore::new();
        // Both vaults share the SAME store (the durable mesh KV in production).
        let owner = Vault::with_clock(SharedRef(&store), owner_dk, "ns", fixed_clock());
        owner.init("owner").await.unwrap();
        owner.put_secret("k", b"v", "opaque").await.unwrap();

        // A fresh device requests pairing on the shared store.
        let phone_dk = DeviceKey::generate().unwrap();
        let phone = Vault::with_clock(SharedRef(&store), phone_dk, "ns", fixed_clock());
        let code = phone.request_pairing("phone").await.unwrap();
        assert!(!phone.is_enrolled().await.unwrap());

        // Owner approves -> phone is enrolled and can read the master-sealed secret.
        let id = owner.approve_pairing(&code).await.unwrap();
        assert_eq!(id, phone.device.id);
        assert!(phone.is_enrolled().await.unwrap());
        assert_eq!(phone.get_secret("k").await.unwrap().bytes, b"v");
    }

    #[tokio::test]
    async fn grant_issue_verify_and_scope() {
        let v = vault();
        v.init("owner").await.unwrap();
        let g = v.issue_grant("ce-cast", &["db-pw".to_string()], None).await.unwrap();
        // Verifies for the granted secret + audience + action.
        v.verify_grant(&g.token, "ce-cast", "read", "db-pw", 0).await.unwrap();
        // Wrong audience / wrong secret are denied.
        assert!(v.verify_grant(&g.token, "other", "read", "db-pw", 0).await.is_err());
        assert!(v.verify_grant(&g.token, "ce-cast", "read", "nope", 0).await.is_err());
        // Revoked -> denied.
        v.revoke_grant(&g.id).await.unwrap();
        assert!(v.verify_grant(&g.token, "ce-cast", "read", "db-pw", 0).await.is_err());
    }

    #[tokio::test]
    async fn full_roundtrip_enroll_put_recover_read() {
        // The Phase-5 lock round trip, end-to-end on one shared store (the durable mesh KV):
        //   owner inits -> a second device enrolls -> owner puts a secret -> the store is WIPED ->
        //   the OWNER recovers from its key alone -> reads the secret back.
        let store = MemStore::new();
        let owner_dk = DeviceKey::generate().unwrap();
        let owner = Vault::with_clock(SharedRef(&store), owner_dk, "rt-ns", fixed_clock());

        // 1. Establish the vault and enroll a second device via pairing.
        assert!(owner.init("owner").await.unwrap());
        let phone_dk = DeviceKey::generate().unwrap();
        let phone = Vault::with_clock(SharedRef(&store), phone_dk, "rt-ns", fixed_clock());
        let code = phone.request_pairing("phone").await.unwrap();
        owner.approve_pairing(&code).await.unwrap();
        assert!(phone.is_enrolled().await.unwrap());

        // 2. Owner puts a secret; both devices can read it (master-sealed, per-device-wrapped).
        owner.put_secret("api-key", b"super-secret", "opaque").await.unwrap();
        assert_eq!(owner.get_secret("api-key").await.unwrap().bytes, b"super-secret");
        assert_eq!(phone.get_secret("api-key").await.unwrap().bytes, b"super-secret");

        // 3. Disaster: every device record + meta is wiped (store loss / lockout).
        for e in store.list("").await.unwrap() {
            store.del(&e.key).await.unwrap();
        }
        assert!(owner.load_master().await.is_err(), "no enrollment after wipe");

        // 4. The OWNER recovers from its key ALONE — re-derives the deterministic master and
        //    re-enrolls itself. No second device, no backup, was needed.
        owner.recover("owner (recovered)").await.unwrap();
        assert!(owner.is_enrolled().await.unwrap());

        // 5. ...and the recovered master opens a secret resealed under it. (The old sealed body was
        //    wiped with the store; reseal + read proves the recovered master is the SAME key.)
        owner.put_secret("api-key", b"super-secret", "opaque").await.unwrap();
        assert_eq!(owner.get_secret("api-key").await.unwrap().bytes, b"super-secret");
    }

    #[tokio::test]
    async fn unenrolled_device_cannot_read_or_grant() {
        // Default-deny: a device that never enrolled has no master, so it can neither read secrets
        // nor issue grants — even pointed at a fully-populated store.
        let store = MemStore::new();
        let owner = Vault::with_clock(SharedRef(&store), DeviceKey::generate().unwrap(), "ns", fixed_clock());
        owner.init("owner").await.unwrap();
        owner.put_secret("k", b"v", "opaque").await.unwrap();

        let stranger = Vault::with_clock(SharedRef(&store), DeviceKey::generate().unwrap(), "ns", fixed_clock());
        assert!(!stranger.is_enrolled().await.unwrap());
        assert!(stranger.load_master().await.is_err(), "no master without enrollment");
        assert!(stranger.get_secret("k").await.is_err(), "cannot read without the master");
        assert!(
            stranger.issue_grant("app", &["k".into()], None).await.is_err(),
            "only an enrolled device may issue grants"
        );
    }

    #[tokio::test]
    async fn revoked_device_loses_access() {
        // Device claim/approve/revoke at the vault layer: a revoked device's d.<id> record is gone,
        // so it can no longer load the master / read secrets.
        let store = MemStore::new();
        let owner = Vault::with_clock(SharedRef(&store), DeviceKey::generate().unwrap(), "ns", fixed_clock());
        owner.init("owner").await.unwrap();
        let phone_dk = DeviceKey::generate().unwrap();
        let phone_id = phone_dk.id.clone();
        let phone = Vault::with_clock(SharedRef(&store), phone_dk, "ns", fixed_clock());
        let code = phone.request_pairing("phone").await.unwrap();
        owner.approve_pairing(&code).await.unwrap();
        owner.put_secret("k", b"v", "opaque").await.unwrap();
        assert_eq!(phone.get_secret("k").await.unwrap().bytes, b"v");

        // Owner revokes the phone; the phone can no longer read.
        owner.revoke_device(&phone_id).await.unwrap();
        assert!(!phone.is_enrolled().await.unwrap());
        assert!(phone.get_secret("k").await.is_err(), "revoked device loses master access");
        // The vault refuses to revoke the device you are using (anti-lockout).
        assert!(owner.revoke_device(&owner.device.id).await.is_err());
    }

    #[tokio::test]
    async fn tampered_record_signature_is_detectable() {
        // Records are signed by the writing device. A store that hands back a tampered enrollment
        // record (wrong key) must not let an attacker's device pass verify_auth as the victim.
        let store = MemStore::new();
        let owner = Vault::with_clock(SharedRef(&store), DeviceKey::generate().unwrap(), "ns", fixed_clock());
        owner.init("owner").await.unwrap();
        let proof = owner.sign_challenge("app", "n1", "2026-06-26T00:00:00.000Z").unwrap();

        // Forge the enrolled device's record to carry an ATTACKER's ecdsaPub. verify_auth must
        // reject the original proof (its key no longer matches the stored device record).
        let attacker = DeviceKey::generate().unwrap();
        let dkey = device_key(&owner.device.id);
        let mut rec = store.get(&dkey).await.unwrap().unwrap();
        rec.as_object_mut().unwrap().insert(
            "ecdsaPub".into(),
            serde_json::to_value(&attacker.ecdsa_pub).unwrap(),
        );
        store.put(&dkey, rec).await.unwrap();
        assert!(
            owner.verify_auth("app", "n1", &proof).await.is_err(),
            "a tampered device record must not authenticate the real device's proof"
        );
    }

    #[tokio::test]
    async fn challenge_response_auth_roundtrip() {
        let v = vault();
        v.init("owner").await.unwrap();
        let proof = v.sign_challenge("ce-watch", "n0", "2026-06-26T00:00:00.000Z").unwrap();
        let who = v.verify_auth("ce-watch", "n0", &proof).await.unwrap();
        assert_eq!(who, v.device.id);
        // A tampered nonce is rejected.
        assert!(v.verify_auth("ce-watch", "wrong", &proof).await.is_err());
    }

    #[test]
    fn iso_roundtrips_through_parse() {
        let ms = 1_782_000_000_000u64; // arbitrary
        let iso = iso_from_unix_ms(ms);
        assert_eq!(ce_secrets_rs::parse_iso_ms(&iso).unwrap() as u64, ms);
        assert_eq!(iso_from_unix_ms(0), "1970-01-01T00:00:00.000Z");
    }

    /// A `Store` that borrows a `&MemStore`, so two vaults in a test can share one backing store
    /// (mirrors two devices pointed at the same durable mesh KV).
    struct SharedRef<'a>(&'a MemStore);
    impl Store for SharedRef<'_> {
        async fn get(&self, key: &str) -> Result<Option<Value>> {
            self.0.get(key).await
        }
        async fn put(&self, key: &str, value: Value) -> Result<()> {
            self.0.put(key, value).await
        }
        async fn del(&self, key: &str) -> Result<()> {
            self.0.del(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<Entry>> {
            self.0.list(prefix).await
        }
    }
}
