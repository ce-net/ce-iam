//! The mesh ce-kv backend for the secrets [`Vault`](ce_iam_core::secrets::Vault).
//!
//! The vault is generic over an async [`Store`](ce_iam_core::secrets::Store) (`get/put/del/list`).
//! This module implements that trait against the **ce-kv mesh service** — the same durable,
//! ce-coord-backed KV the browser vault and the `ce-secrets` JS CLI write to, so pairing and secrets
//! converge across every device. There is NO bespoke storage here: we speak the existing
//! `ce-kv/<ns>/1` request protocol over the LOCAL CE node's `POST /mesh/request`, exactly as
//! `ce-secrets/src/store.mjs::meshStore` does.
//!
//! Protocol (request/reply payloads are JSON, carried hex-encoded in `payload_hex`):
//!   * `{ "op": "get",  "key": "<k>" }`                 -> `{ "value": <json|null> }`
//!   * `{ "op": "put",  "key": "<k>", "value": <json> }`-> `{ }`
//!   * `{ "op": "del",  "key": "<k>" }`                 -> `{ }`
//!   * `{ "op": "list", "prefix": "<p>", "limit": N }`  -> `{ "items": [{ "key", "value" }, …] }`
//!
//! Discovery of the serving node mirrors the JS: an explicit `CE_KV_NODE` override wins; otherwise we
//! ask the local node's DHT view (`GET /discovery/find/ce-kv-<ns>`); otherwise we fall back to the
//! ce-net relay (the infra node that runs the vault KV). The node's HTTP API token is attached so the
//! mutating `/mesh/request` call is authorized.

use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use ce_iam_core::secrets::{Entry, Store};
use serde_json::{Value, json};

/// The 64-hex node id of the ce-net relay — the default ce-kv host when DHT discovery is unresolved
/// (the same constant `ce-secrets/src/store.mjs` falls back to).
const CE_NET_RELAY: &str = "21f5c206ffbf88d7bebdf9078d687e30be5b9a3c6e7ac752e018a559faf171d4";

/// A [`Store`] that proxies every op to the mesh `ce-kv/<ns>/1` service via the local node's
/// `POST /mesh/request`. Construct with [`MeshKvStore::connect`].
pub struct MeshKvStore {
    /// Local CE node HTTP base (e.g. `http://127.0.0.1:8844` or a public `…/ce` proxy).
    node_url: String,
    /// The ce-kv topic for this namespace: `ce-kv/<ns>/1`.
    topic: String,
    /// The node id serving this namespace's KV (resolved once, then memoized).
    to_node: Mutex<Option<String>>,
    /// The advertised service name for discovery: `ce-kv-<ns>`.
    service: String,
    /// The local node's API token (sent only to a plain-http local node, matching the JS).
    token: Option<String>,
    /// Optional hex ce-cap chain attached to every op as `"caps"`, so this store can read/write a
    /// REMOTE [`crate::authkv::AuthKv`] that enforces `kv:read`/`kv:write`. `None` for the local
    /// owner-vault path, where the writer node trusts its own self-delivered ops.
    caps: Option<String>,
    http: reqwest::Client,
}

impl MeshKvStore {
    /// Connect a mesh-KV store for namespace `ns` against the local node at `node_url`. Resolution of
    /// the serving node is lazy (on first op). `token` is the local node's HTTP API token (discover it
    /// with [`ce_rs::discover_api_token`]); pass `None` to omit it.
    pub fn connect(ns: &str, node_url: impl Into<String>, token: Option<String>) -> Self {
        let node_url = node_url.into();
        Self {
            topic: format!("ce-kv/{ns}/1"),
            service: format!("ce-kv-{ns}"),
            node_url,
            to_node: Mutex::new(std::env::var("CE_KV_NODE").ok().filter(|s| !s.trim().is_empty())),
            token,
            caps: None,
            http: reqwest::Client::new(),
        }
    }

    /// Attach a hex ce-cap chain (a `kv:read`+`kv:write` grant) to every op, so this store can reach a
    /// REMOTE [`crate::authkv::AuthKv`] that enforces capability access. The local owner-vault path does
    /// not need this — the writer node trusts its own self-delivered ops.
    pub fn with_caps(mut self, caps: impl Into<String>) -> Self {
        let caps = caps.into();
        self.caps = if caps.trim().is_empty() { None } else { Some(caps) };
        self
    }

    /// The `Authorization` header value, sent only to a plain-`http://` local node (a public `…/ce`
    /// proxy injects its own and must not see ours — matches `meshStore.authH`).
    fn auth_header(&self) -> Option<String> {
        match &self.token {
            Some(t) if !t.is_empty() && self.node_url.starts_with("http://") => {
                Some(format!("Bearer {t}"))
            }
            _ => None,
        }
    }

    /// Resolve (and memoize) the node id hosting this namespace's KV: `CE_KV_NODE` override, else the
    /// local node's DHT view, else the ce-net relay fallback.
    async fn resolve_node(&self) -> Result<String> {
        if let Some(n) = self.to_node.lock().map_err(|_| anyhow!("kv store poisoned"))?.clone() {
            return Ok(n);
        }
        // DHT discovery via the local node.
        let mut req = self
            .http
            .get(format!("{}/discovery/find/{}", self.node_url, self.service));
        if let Some(h) = self.auth_header() {
            req = req.header("Authorization", h);
        }
        let found = match req.send().await {
            Ok(r) if r.status().is_success() => r
                .json::<Value>()
                .await
                .ok()
                .and_then(|j| first_node_id(&j)),
            _ => None,
        };
        let node = found.unwrap_or_else(|| {
            std::env::var("CE_NET_RELAY")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| CE_NET_RELAY.to_string())
        });
        *self.to_node.lock().map_err(|_| anyhow!("kv store poisoned"))? = Some(node.clone());
        Ok(node)
    }

    /// Issue one ce-kv request and return the decoded reply object.
    async fn call(&self, mut request: Value) -> Result<Value> {
        let to = self.resolve_node().await?;
        // Attach our capability chain (if any) so a remote enforcing AuthKv can authorize the op.
        if let (Some(caps), Some(obj)) = (&self.caps, request.as_object_mut()) {
            obj.insert("caps".into(), Value::String(caps.clone()));
        }
        let op = request.get("op").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let payload_hex = hex::encode(serde_json::to_vec(&request).context("encode kv request")?);
        let body = json!({
            "to": to,
            "topic": self.topic,
            "payload_hex": payload_hex,
            "timeout_ms": 8000,
        });
        let mut http = self
            .http
            .post(format!("{}/mesh/request", self.node_url))
            .json(&body);
        if let Some(h) = self.auth_header() {
            http = http.header("Authorization", h);
        }
        let resp = http.send().await.with_context(|| format!("mesh kv {op}: request failed"))?;
        if !resp.status().is_success() {
            bail!("mesh kv {op}: HTTP {}", resp.status());
        }
        let v: Value = resp.json().await.context("decode /mesh/request reply")?;
        let reply_hex = v
            .get("payload_hex")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("mesh kv {op}: empty reply"))?;
        let raw = hex::decode(reply_hex).context("decode reply payload_hex")?;
        let out: Value = serde_json::from_slice(&raw).context("parse kv reply")?;
        if let Some(err) = out.get("error").and_then(|e| e.as_str()) {
            bail!("mesh kv {op}: {err}");
        }
        Ok(out)
    }
}

impl Store for MeshKvStore {
    async fn get(&self, key: &str) -> Result<Option<Value>> {
        let out = self.call(json!({ "op": "get", "key": key })).await?;
        Ok(match out.get("value") {
            Some(Value::Null) | None => None,
            Some(v) => Some(v.clone()),
        })
    }

    async fn put(&self, key: &str, value: Value) -> Result<()> {
        self.call(json!({ "op": "put", "key": key, "value": value })).await?;
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<()> {
        self.call(json!({ "op": "del", "key": key })).await?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<Entry>> {
        let out = self
            .call(json!({ "op": "list", "prefix": prefix, "limit": 1000 }))
            .await?;
        let items = out.get("items").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        Ok(items
            .into_iter()
            .filter_map(|e| {
                let key = e.get("key")?.as_str()?.to_string();
                let value = e.get("value").cloned().unwrap_or(Value::Null);
                Some(Entry { key, value })
            })
            .collect())
    }
}

/// Pull the first usable node id out of a `/discovery/find` reply, which may be a bare array of
/// strings, an array of `{node_id|id}` objects, or `{providers|nodes|node_ids: [...]}`.
fn first_node_id(j: &Value) -> Option<String> {
    let list = if let Some(a) = j.as_array() {
        a.clone()
    } else {
        ["providers", "nodes", "node_ids"]
            .iter()
            .find_map(|k| j.get(*k).and_then(|v| v.as_array()).cloned())?
    };
    list.into_iter().find_map(|x| match x {
        Value::String(s) if !s.is_empty() => Some(s),
        Value::Object(_) => x
            .get("node_id")
            .or_else(|| x.get("id"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_node_id_shapes() {
        assert_eq!(first_node_id(&json!(["abc", "def"])), Some("abc".into()));
        assert_eq!(first_node_id(&json!([{ "node_id": "n1" }])), Some("n1".into()));
        assert_eq!(first_node_id(&json!({ "providers": [{ "id": "p1" }] })), Some("p1".into()));
        assert_eq!(first_node_id(&json!({ "nodes": ["x"] })), Some("x".into()));
        assert_eq!(first_node_id(&json!([])), None);
        assert_eq!(first_node_id(&json!({})), None);
    }

    #[test]
    fn auth_header_only_for_local_http() {
        let s = MeshKvStore::connect("ns", "http://127.0.0.1:8844", Some("tok".into()));
        assert_eq!(s.auth_header(), Some("Bearer tok".into()));
        let s = MeshKvStore::connect("ns", "https://app.ce-net.com/ce", Some("tok".into()));
        assert_eq!(s.auth_header(), None, "never send our token to a public proxy");
        let s = MeshKvStore::connect("ns", "http://127.0.0.1:8844", None);
        assert_eq!(s.auth_header(), None);
    }
}
