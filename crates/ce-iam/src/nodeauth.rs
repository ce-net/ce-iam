//! `nodeauth` — the LOCAL-NODE side of passwordless "your node is your login".
//!
//! North star (Leif): you never log into a website; your own CE node vouches for you. A browser tab
//! (the spacegame start menu, or any ce-net app) runs an in-tab libp2p peer, finds the CE node you are
//! running, and asks it to vouch. This module is the node-side responder for that handshake. It is the
//! exact counterpart of `spacegame-wasm/account.js` (layer B) — keep the wire in lock-step:
//!
//!   * ANNOUNCE — periodically publish `{ nodeId, label, owner }` on `ce-iam/nodes/announce` so a
//!     browser's `discoverNodes()` can list the nodes you run.
//!   * REQUEST  — listen on `ce-iam/auth/req/<myNodeId>` for `{ peerId, name, nonce }` from a browser.
//!   * RESPONSE — after approval, mint a node-SIGNED capability and publish `{ nonce, cap, nodeId,
//!     name }` on `ce-iam/auth/resp/<peerId>`. The browser stores `cap` on the account and presents it
//!     when it joins a service (e.g. spacegame), which verifies it OFFLINE rooted at this node id.
//!
//! ## What the capability says
//!
//! ce-cap abilities are opaque strings, so the vouch is expressed entirely as abilities — no new cap
//! fields, no peer-id↔node-id encoding conversion:
//!
//!   * `account:login`            — "this is a real account vouched for by me (the node)".
//!   * `account:peer:<peerId>`    — binds the browser's libp2p peer id.
//!   * `account:name:<name>`      — binds the chosen display name (so a peer cannot claim another name).
//!
//! The cap is minted with the node's own identity as both issuer (root) and audience. A relying app
//! (spacegame) accepts this node id as a root and checks the chain authorizes `account:login` AND
//! `account:peer:<claimed-id>` AND `account:name:<claimed-name>`. (Strict mesh `from == peerId`
//! binding — proving the joining sender IS that peer — is the one live-integration follow-up; it needs
//! the in-tab peer's mesh sender id, which the relay currently rewrites.)

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use ce_identity::Identity;
use ce_rs::CeClient;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use crate::{Conditions, Iam, Principal, ResourceMatch, simple_policy};

/// The well-known topic CE nodes announce themselves on for browser discovery.
pub const T_ANNOUNCE: &str = "ce-iam/nodes/announce";
/// The ability asserting "a node vouches this is a real account".
pub const ABILITY_LOGIN: &str = "account:login";

/// The per-node request topic a browser publishes its vouch request to.
pub fn t_req(node_id: &str) -> String {
    format!("ce-iam/auth/req/{node_id}")
}
/// The per-peer response topic the node publishes the signed cap back on.
pub fn t_resp(peer_id: &str) -> String {
    format!("ce-iam/auth/resp/{peer_id}")
}
/// The ability binding a browser peer id into a vouch cap.
pub fn ability_peer(peer_id: &str) -> String {
    format!("account:peer:{peer_id}")
}
/// The ability binding a chosen display name into a vouch cap.
pub fn ability_name(name: &str) -> String {
    format!("account:name:{name}")
}

/// A browser's vouch request (`{ peerId, name, nonce, abilities }`, camelCase to match `account.js`).
///
/// `abilities` is the generalization that turns this from a fixed identity vouch into the reusable
/// app-authorization primitive: an app declares the abilities it needs (e.g. `cast:publish`,
/// `cast:control`) and the node grants exactly those it is willing to (the allow-policy). Absent /
/// empty ⇒ a pure identity vouch (the original spacegame behavior).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthReq {
    peer_id: String,
    #[serde(default)]
    name: String,
    nonce: String,
    /// App abilities the requester wants bound into the cap (besides the identity abilities).
    #[serde(default)]
    abilities: Vec<String>,
}

/// The local-node browser-auth responder. Drive it with [`NodeAuthResponder::run`].
pub struct NodeAuthResponder {
    client: CeClient,
    identity: Identity,
    node_id_hex: String,
    iam: Iam,
    label: String,
    owner: Option<String>,
    /// Auto-issue a cap for any request. When false, requests are logged and ignored (the operator
    /// must approve out of band — interactive approval is a follow-up). Default true so the browser
    /// flow works end to end.
    auto_approve: bool,
    /// App-ability prefixes this node is willing to grant (e.g. `cast:`). A requested ability is
    /// granted iff it begins with one of these. Identity abilities (`account:`) are ALWAYS granted.
    /// Empty ⇒ grant every requested ability (preserves the original open auto-approve; logged). This
    /// is the "what I give an app" consent surface — `ce app install` can populate it per app.
    allowed_prefixes: Vec<String>,
    /// Monotonic per-issuer cap nonce (seeded from the wall clock so it does not collide across runs).
    nonce: AtomicU64,
}

impl NodeAuthResponder {
    /// Build a responder that signs vouch caps as `identity` (the node's own key, so a relying app can
    /// root-accept this node id). `iam` need not carry roots — minting only signs.
    pub fn new(
        client: CeClient,
        identity: Identity,
        iam: Iam,
        label: impl Into<String>,
        owner: Option<String>,
        auto_approve: bool,
    ) -> Self {
        Self::with_allowed(client, identity, iam, label, owner, auto_approve, Vec::new())
    }

    /// As [`NodeAuthResponder::new`] but with an explicit app-ability allow-list (prefixes). See
    /// [`NodeAuthResponder::allowed_prefixes`].
    pub fn with_allowed(
        client: CeClient,
        identity: Identity,
        iam: Iam,
        label: impl Into<String>,
        owner: Option<String>,
        auto_approve: bool,
        allowed_prefixes: Vec<String>,
    ) -> Self {
        let node_id_hex = identity.node_id_hex();
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            client,
            identity,
            node_id_hex,
            iam,
            label: label.into(),
            owner,
            auto_approve,
            allowed_prefixes,
            nonce: AtomicU64::new(seed),
        }
    }

    /// Filter requested app abilities to those this node will grant. `account:` identity abilities are
    /// never passed here (they are added unconditionally by the caller). An empty allow-list grants
    /// everything requested (the original open behavior).
    fn grantable(&self, requested: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|a| {
                self.allowed_prefixes.is_empty()
                    || self.allowed_prefixes.iter().any(|p| a.starts_with(p.as_str()))
            })
            .cloned()
            .collect()
    }

    /// This node's id (hex).
    pub fn node_id(&self) -> &str {
        &self.node_id_hex
    }

    fn announce_payload(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "nodeId": self.node_id_hex,
            "label": self.label,
            "owner": self.owner,
        }))
        .unwrap_or_default()
    }

    /// Mint a node-signed vouch capability binding `peer_id` + `name`, plus any granted `app_abilities`
    /// (already filtered through the allow-policy). Returns `(hex token, all abilities in the cap)`.
    pub fn vouch_token(
        &self,
        peer_id: &str,
        name: &str,
        app_abilities: &[String],
    ) -> Result<(String, Vec<String>)> {
        let mut actions = vec![
            ABILITY_LOGIN.to_string(),
            ability_peer(peer_id),
            ability_name(name),
        ];
        actions.extend(app_abilities.iter().cloned());
        let policy = simple_policy(actions.clone(), ResourceMatch::Any, Conditions::default());
        let audience = Principal(self.identity.node_id());
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let grant = self
            .iam
            .mint(&self.identity, audience, &policy, nonce)
            .map_err(|e| anyhow!("mint vouch cap: {e}"))?;
        Ok((grant.token, actions))
    }

    /// Handle one decoded vouch request: mint the cap (with the app abilities this node will grant) and
    /// publish the response carrying the cap + the abilities actually granted.
    async fn handle_req(&self, payload: &[u8]) -> Result<()> {
        let req: AuthReq = serde_json::from_slice(payload).context("decode auth request")?;
        let name = if req.name.is_empty() { "pilot".to_string() } else { req.name.clone() };
        if !self.auto_approve {
            warn!(peer = %req.peer_id, %name, "vouch request received but auto-approve is OFF — ignoring");
            return Ok(());
        }
        let granted = self.grantable(&req.abilities);
        if granted.len() != req.abilities.len() {
            let denied: Vec<&String> = req.abilities.iter().filter(|a| !granted.contains(a)).collect();
            warn!(peer = %req.peer_id, ?denied, "node-auth: denied abilities not in allow-list");
        }
        let (token, abilities) = self.vouch_token(&req.peer_id, &name, &granted)?;
        let resp = json!({
            "nonce": req.nonce,
            "cap": token,
            "nodeId": self.node_id_hex,
            "name": name,
            "abilities": abilities,
        });
        self.client
            .publish(&t_resp(&req.peer_id), &serde_json::to_vec(&resp)?)
            .await
            .context("publish auth response")?;
        info!(peer = %req.peer_id, %name, ?granted, "vouched (node-signed capability issued)");
        Ok(())
    }

    /// Run the responder until `shutdown` resolves: announce every 10s, and answer vouch requests on
    /// `ce-iam/auth/req/<myNodeId>`. Reconnects to the message stream with capped backoff.
    pub async fn run(&self, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
        use futures_util::StreamExt as _;

        let req_topic = t_req(&self.node_id_hex);
        self.client.subscribe(&req_topic).await.context("subscribe auth req topic")?;
        let _ = self.client.publish(T_ANNOUNCE, &self.announce_payload()).await;
        info!(node = %self.node_id_hex, label = %self.label, "node-auth responder running");

        tokio::pin!(shutdown);
        let mut announce = tokio::time::interval(Duration::from_secs(10));
        announce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut backoff_ms = 250u64;

        loop {
            let stream = match self.client.messages_stream().await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "node-auth: messages_stream failed; backing off");
                    tokio::select! {
                        _ = &mut shutdown => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                    }
                    backoff_ms = (backoff_ms * 2).min(10_000);
                    continue;
                }
            };
            backoff_ms = 250;
            tokio::pin!(stream);
            loop {
                tokio::select! {
                    _ = &mut shutdown => return Ok(()),
                    _ = announce.tick() => {
                        let _ = self.client.publish(T_ANNOUNCE, &self.announce_payload()).await;
                    }
                    item = stream.next() => match item {
                        Some(Ok(m)) if m.topic == req_topic => {
                            match m.payload() {
                                Ok(p) => {
                                    if let Err(e) = self.handle_req(&p).await {
                                        warn!(error = %e, "node-auth: vouch request failed");
                                    }
                                }
                                Err(e) => warn!(error = %e, "node-auth: undecodable request payload"),
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => {
                            warn!(error = %e, "node-auth: stream error; reconnecting");
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_match_account_js() {
        assert_eq!(T_ANNOUNCE, "ce-iam/nodes/announce");
        assert_eq!(t_req("NODE"), "ce-iam/auth/req/NODE");
        assert_eq!(t_resp("PEER"), "ce-iam/auth/resp/PEER");
        assert_eq!(ability_peer("12D3Koo"), "account:peer:12D3Koo");
        assert_eq!(ability_name("Ada"), "account:name:Ada");
    }
}
