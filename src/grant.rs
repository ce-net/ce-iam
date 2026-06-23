//! The IAM service: mint, attenuate, verify, and inspect grants.
//!
//! A **grant** is the IAM-facing name for a [`ce_cap`] capability chain: a signed, attenuating
//! statement that some issuer authorizes some audience to perform a set of actions on a node-set,
//! subject to conditions. This module is the small, heavily-tested compiler/verifier that maps the
//! familiar AWS-IAM verbs onto that primitive:
//!
//! | AWS-IAM                              | ce-iam                                  | ce-cap                          |
//! |-------------------------------------|-----------------------------------------|---------------------------------|
//! | attach policy to user               | [`Iam::mint`] (policy → root grant)     | `SignedCapability::issue`       |
//! | `sts:AssumeRole` with scoped policy | [`Iam::attenuate`] (narrow + re-sign)   | child link in the chain         |
//! | request authorization / IsAuthorized| [`Iam::verify`]                         | `ce_cap::authorize`             |
//! | inspect a token's scope             | [`Iam::inspect`]                        | walk the chain                  |
//!
//! ### Action universe and wildcards
//!
//! Capabilities must *enumerate* their abilities so attenuation stays a pure set-subset test, but
//! IAM authors expect `"storage:*"` and `"*"`. We square this by expanding wildcards at **mint
//! time** against a closed [`Iam::action_universe`]: minting `"storage:*"` against a universe that
//! contains `storage:read`/`storage:write` produces a capability listing both, and the runtime
//! verifier never sees a glob. A wildcard that matches nothing in the universe is a [`IamError`],
//! not a silent empty grant.

use crate::error::IamError;
use crate::policy::{Conditions, Effect, Policy, ResourceMatch};
use crate::principal::Principal;
use ce_cap::{
    Caveats, Resource, SignedCapability, authorize, decode_chain, encode_chain,
};
use ce_identity::{Identity, NodeId};

/// The IAM service handle. Holds the action universe used for wildcard expansion and the set of
/// accepted root keys used during verification. Stateless beyond that — it issues and checks
/// capability chains, holding no chain database of its own.
#[derive(Debug, Clone, Default)]
pub struct Iam {
    /// Closed set of action strings wildcards may expand to (e.g. `storage:read`, `db:write`).
    /// Empty means "no wildcards allowed" — literal actions still work.
    action_universe: Vec<String>,
    /// Extra root keys (besides a verifying node's own id) whose chains this service will honor.
    accepted_roots: Vec<NodeId>,
}

/// A minted grant: the capability chain plus its portable hex token. The token is what you hand to
/// an audience; the chain is the structured form for inspection.
#[derive(Debug, Clone)]
pub struct Grant {
    /// The capability chain (root-first).
    pub chain: Vec<SignedCapability>,
    /// Portable hex token (`ce_cap::encode_chain`) — copy-paste into a wallet or CLI flag.
    pub token: String,
}

impl Grant {
    fn from_chain(chain: Vec<SignedCapability>) -> Grant {
        let token = encode_chain(&chain);
        Grant { chain, token }
    }

    /// The leaf (held by the final audience).
    pub fn leaf(&self) -> &SignedCapability {
        // A Grant is always constructed non-empty by this crate.
        &self.chain[self.chain.len() - 1]
    }

    /// The audience that holds this grant.
    pub fn audience(&self) -> Principal {
        Principal(self.leaf().cap.audience)
    }
}

/// A human-readable description of a grant's scope — what [`Iam::inspect`] returns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Scope {
    /// Root issuer (64-hex) — the authority the chain ultimately derives from.
    pub root_issuer: String,
    /// Final audience (64-hex) — who may exercise the grant.
    pub audience: String,
    /// Number of links (delegation depth).
    pub depth: usize,
    /// The effective abilities (the leaf's abilities — already the narrowest in a valid chain).
    pub abilities: Vec<String>,
    /// The effective resource match, rendered.
    pub resource: String,
    /// Effective expiry (unix seconds, `0` = never).
    pub not_after: u64,
    /// Per-link summary, root-first.
    pub links: Vec<LinkInfo>,
}

/// One link's summary inside [`Scope`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LinkInfo {
    pub issuer: String,
    pub audience: String,
    pub abilities: Vec<String>,
    pub resource: String,
    pub nonce: u64,
    pub not_after: u64,
}

impl Iam {
    /// A new service with no wildcard universe and no extra roots.
    pub fn new() -> Iam {
        Iam::default()
    }

    /// Set the closed action universe used for wildcard expansion. Returns `self` for chaining.
    pub fn with_action_universe(mut self, actions: impl IntoIterator<Item = String>) -> Iam {
        self.action_universe = actions.into_iter().collect();
        self.action_universe.sort();
        self.action_universe.dedup();
        self
    }

    /// Add accepted root keys (besides the verifier's own id) honored during [`Iam::verify`].
    pub fn with_accepted_roots(mut self, roots: impl IntoIterator<Item = NodeId>) -> Iam {
        self.accepted_roots.extend(roots);
        self
    }

    /// The configured action universe.
    pub fn action_universe(&self) -> &[String] {
        &self.action_universe
    }

    /// Expand a list of action strings (which may include `"*"` or `"prefix:*"`) into a concrete,
    /// deduplicated, sorted ability set against the action universe.
    ///
    /// * `"*"` → the whole universe.
    /// * `"storage:*"` → every universe action starting with `"storage:"`.
    /// * a literal `"storage:read"` → itself (whether or not it is in the universe; literal grants
    ///   are always allowed so apps can use actions the IAM service was not told about).
    ///
    /// A wildcard that matches nothing is rejected, so a typo can never silently mint an empty grant.
    pub fn expand_actions(&self, actions: &[String]) -> Result<Vec<String>, IamError> {
        let mut out: Vec<String> = Vec::new();
        for a in actions {
            let a = a.trim();
            if a.is_empty() {
                return Err(IamError::BadAction("empty action string".into()));
            }
            if a == "*" {
                if self.action_universe.is_empty() {
                    return Err(IamError::BadAction(
                        "'*' used but the action universe is empty".into(),
                    ));
                }
                out.extend(self.action_universe.iter().cloned());
            } else if let Some(prefix) = a.strip_suffix('*') {
                let matched: Vec<String> = self
                    .action_universe
                    .iter()
                    .filter(|u| u.starts_with(prefix))
                    .cloned()
                    .collect();
                if matched.is_empty() {
                    return Err(IamError::BadAction(format!(
                        "wildcard '{a}' matched no action in the universe"
                    )));
                }
                out.extend(matched);
            } else {
                out.push(a.to_string());
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Compile a single-statement Allow policy into `(abilities, resource, caveats)`.
    ///
    /// Multi-statement policies are flattened: every Allow statement must share one resource and one
    /// set of conditions (the capability model carries exactly one of each), and their actions are
    /// unioned. Any `Deny` statement is rejected — see [`IamError::DenyUnsupported`].
    fn compile(&self, policy: &Policy) -> Result<(Vec<String>, Resource, Caveats), IamError> {
        let allows: Vec<_> = policy
            .statements
            .iter()
            .filter(|s| matches!(s.effect, Effect::Allow))
            .collect();
        if policy.statements.iter().any(|s| matches!(s.effect, Effect::Deny)) {
            return Err(IamError::DenyUnsupported);
        }
        if allows.is_empty() {
            return Err(IamError::BadPolicy("policy grants nothing".into()));
        }
        // Resource and conditions must be uniform across allow statements — a single capability
        // carries one resource + one caveat set. (Authors needing several distinct scopes mint
        // several grants.)
        let resource = &allows[0].resource;
        let conditions = &allows[0].conditions;
        for s in &allows[1..] {
            if &s.resource != resource {
                return Err(IamError::BadPolicy(
                    "all Allow statements must target the same resource to compile to one grant".into(),
                ));
            }
            if &s.conditions != conditions {
                return Err(IamError::BadPolicy(
                    "all Allow statements must share the same conditions to compile to one grant".into(),
                ));
            }
        }
        let mut actions: Vec<String> = Vec::new();
        for s in &allows {
            actions.extend(s.actions.iter().cloned());
        }
        let abilities = self.expand_actions(&actions)?;
        if abilities.is_empty() {
            return Err(IamError::BadAction("policy expanded to no actions".into()));
        }
        let cap_resource = resource.to_cap_resource()?;
        Ok((abilities, cap_resource, conditions.to_caveats()))
    }

    /// Mint a **root grant**: issue a fresh capability from `issuer` to `audience` embodying
    /// `policy`. The issuer signs as a root (no parent), so the resulting chain is honored by any
    /// node that accepts `issuer` as a root (always true on the issuer's own node).
    ///
    /// `nonce` names this grant for revocation; choose a value unique per issuer.
    pub fn mint(
        &self,
        issuer: &Identity,
        audience: Principal,
        policy: &Policy,
        nonce: u64,
    ) -> Result<Grant, IamError> {
        let (abilities, resource, caveats) = self.compile(policy)?;
        let cap = SignedCapability::issue(
            issuer,
            audience.node_id(),
            abilities,
            resource,
            caveats,
            nonce,
            None,
        );
        Ok(Grant::from_chain(vec![cap]))
    }

    /// Mint a root grant **from a named role in a [`Catalog`]**, attaching the role to the audience
    /// in passing. This is the managed-product convenience: instead of handing [`Iam::mint`] a raw
    /// policy, name a role the catalog already stores. The resulting capability is, as always, an
    /// immutable signed token — a *later* edit to the catalog role can never broaden it.
    ///
    /// Returns [`IamError::BadPolicy`] if `role` is not in the catalog.
    pub fn mint_role(
        &self,
        issuer: &Identity,
        audience: Principal,
        catalog: &crate::catalog::Catalog,
        role: &str,
        nonce: u64,
    ) -> Result<Grant, IamError> {
        let r = catalog
            .get_role(role)
            .ok_or_else(|| IamError::BadPolicy(format!("no such role '{role}' in catalog")))?;
        self.mint(issuer, audience, &r.policy, nonce)
    }

    /// **Attenuate** (sub-delegate) an existing grant: the current holder `holder` issues a
    /// *narrower* grant to a new `audience`. This is `sts:AssumeRole` with a more-restrictive
    /// session policy.
    ///
    /// The new link must be no broader than the leaf it extends. We check that **before** signing
    /// and return [`IamError::WouldAmplify`] if it would broaden, so a caller never produces a
    /// chain that the verifier will later reject — attenuation can never amplify, by construction.
    ///
    /// `holder` must be the audience of the current leaf (you can only delegate what you hold).
    pub fn attenuate(
        &self,
        holder: &Identity,
        parent: &Grant,
        audience: Principal,
        narrower: &Policy,
        nonce: u64,
    ) -> Result<Grant, IamError> {
        let leaf = parent.leaf();
        if leaf.cap.audience != holder.node_id() {
            return Err(IamError::WouldAmplify(
                "delegating identity does not hold the parent grant (not its audience)".into(),
            ));
        }
        let (abilities, resource, caveats) = self.compile(narrower)?;

        // Enforce attenuation up front (the verifier enforces it again at check time).
        if !abilities.iter().all(|a| leaf.cap.abilities.contains(a)) {
            return Err(IamError::WouldAmplify(format!(
                "child abilities {abilities:?} exceed parent {:?}",
                leaf.cap.abilities
            )));
        }
        if !resource.is_subset_of(&leaf.cap.resource) {
            return Err(IamError::WouldAmplify(
                "child resource is broader than the parent resource".into(),
            ));
        }
        if !caveats.is_narrower_or_equal(&leaf.cap.caveats) {
            return Err(IamError::WouldAmplify(
                "child conditions are broader than the parent conditions".into(),
            ));
        }

        let child = SignedCapability::issue(
            holder,
            audience.node_id(),
            abilities,
            resource,
            caveats,
            nonce,
            Some(leaf.id()),
        );
        let mut chain = parent.chain.clone();
        chain.push(child);
        Ok(Grant::from_chain(chain))
    }

    /// **Verify**: decide whether `requester` may perform `action` on the node identified by
    /// (`self_id`, `self_tags`) at time `now`, given the grant `token` (a hex chain) and the
    /// `is_revoked` predicate (typically backed by the on-chain revocation view).
    ///
    /// This is offline and local: no policy server, no network. Errors are returned as
    /// [`IamError::MalformedChain`] (token could not be decoded) or [`IamError::Denied`] (the chain
    /// decoded but did not authorize the action — wrong issuer, expired, revoked, attenuation
    /// violated, etc.). A malformed token is always an `Err`, never a panic.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        self_id: &NodeId,
        self_tags: &[String],
        now: u64,
        requester: &Principal,
        action: &str,
        token: &str,
        is_revoked: &dyn Fn(&NodeId, u64) -> bool,
    ) -> Result<(), IamError> {
        let chain = decode_chain(token).map_err(|e| IamError::MalformedChain(e.to_string()))?;
        authorize(
            self_id,
            &self.accepted_roots,
            self_tags,
            now,
            &requester.node_id(),
            action,
            &chain,
            is_revoked,
        )
        .map_err(IamError::Denied)
    }

    /// Like [`Iam::verify`] but takes an already-decoded chain (avoids re-decoding when you hold
    /// the structured form, e.g. from a [`Grant`]).
    #[allow(clippy::too_many_arguments)]
    pub fn verify_chain(
        &self,
        self_id: &NodeId,
        self_tags: &[String],
        now: u64,
        requester: &Principal,
        action: &str,
        chain: &[SignedCapability],
        is_revoked: &dyn Fn(&NodeId, u64) -> bool,
    ) -> Result<(), IamError> {
        authorize(
            self_id,
            &self.accepted_roots,
            self_tags,
            now,
            &requester.node_id(),
            action,
            chain,
            is_revoked,
        )
        .map_err(IamError::Denied)
    }

    /// **Inspect** a grant token: decode it and summarize its scope for humans, without verifying
    /// against any particular node. A malformed token is an `Err`, never a panic.
    pub fn inspect(&self, token: &str) -> Result<Scope, IamError> {
        let chain = decode_chain(token).map_err(|e| IamError::MalformedChain(e.to_string()))?;
        self.inspect_chain(&chain)
    }

    /// [`Iam::inspect`] on an already-decoded chain.
    pub fn inspect_chain(&self, chain: &[SignedCapability]) -> Result<Scope, IamError> {
        if chain.is_empty() {
            return Err(IamError::MalformedChain("empty chain".into()));
        }
        let root = &chain[0].cap;
        let leaf = &chain[chain.len() - 1].cap;
        let links = chain
            .iter()
            .map(|l| LinkInfo {
                issuer: hex::encode(l.cap.issuer),
                audience: hex::encode(l.cap.audience),
                abilities: l.cap.abilities.clone(),
                resource: render_resource(&l.cap.resource),
                nonce: l.cap.nonce,
                not_after: l.cap.caveats.not_after,
            })
            .collect();
        Ok(Scope {
            root_issuer: hex::encode(root.issuer),
            audience: hex::encode(leaf.audience),
            depth: chain.len(),
            abilities: leaf.abilities.clone(),
            resource: render_resource(&leaf.resource),
            not_after: leaf.caveats.not_after,
            links,
        })
    }

    /// Decode a grant token into a structured [`Grant`] (chain + token).
    pub fn decode(&self, token: &str) -> Result<Grant, IamError> {
        let chain = decode_chain(token).map_err(|e| IamError::MalformedChain(e.to_string()))?;
        if chain.is_empty() {
            return Err(IamError::MalformedChain("empty chain".into()));
        }
        Ok(Grant::from_chain(chain))
    }
}

/// Render a [`Resource`] back to the CLI/string spelling used by [`ResourceMatch::parse`].
pub fn render_resource(r: &Resource) -> String {
    match r {
        Resource::Any => "*".to_string(),
        Resource::Node(n) => hex::encode(n),
        Resource::Tag(t) => format!("tag:{t}"),
        Resource::AllOf(ts) => format!("all-of:{}", ts.join(",")),
    }
}

/// Convenience: build the single-statement Allow policy for the common
/// `grant <actions> on <resource> [until <ts>]` case used by the CLI.
pub fn simple_policy(
    actions: Vec<String>,
    resource: ResourceMatch,
    conditions: Conditions,
) -> Policy {
    Policy::allow(actions, resource, conditions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn id(tag: &str) -> Identity {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ce-iam-test-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn never_revoked(_: &NodeId, _: u64) -> bool {
        false
    }

    fn iam() -> Iam {
        Iam::new().with_action_universe([
            "storage:read".to_string(),
            "storage:write".to_string(),
            "db:read".to_string(),
            "db:write".to_string(),
        ])
    }

    // ---- wildcard expansion ----

    #[test]
    fn expand_literal_action_passes_through() {
        let out = iam().expand_actions(&["storage:read".into()]).unwrap();
        assert_eq!(out, vec!["storage:read".to_string()]);
    }

    #[test]
    fn expand_prefix_wildcard() {
        let out = iam().expand_actions(&["storage:*".into()]).unwrap();
        assert_eq!(out, vec!["storage:read".to_string(), "storage:write".to_string()]);
    }

    #[test]
    fn expand_star_is_whole_universe() {
        let out = iam().expand_actions(&["*".into()]).unwrap();
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn expand_unmatched_wildcard_errors() {
        let err = iam().expand_actions(&["nope:*".into()]).unwrap_err();
        assert!(matches!(err, IamError::BadAction(_)));
    }

    #[test]
    fn expand_empty_action_errors() {
        assert!(matches!(iam().expand_actions(&["  ".into()]).unwrap_err(), IamError::BadAction(_)));
    }

    #[test]
    fn expand_star_with_empty_universe_errors() {
        assert!(matches!(
            Iam::new().expand_actions(&["*".into()]).unwrap_err(),
            IamError::BadAction(_)
        ));
    }

    #[test]
    fn literal_action_outside_universe_is_allowed() {
        // Apps may grant actions the IAM service was never told about.
        let out = iam().expand_actions(&["meet:join".into()]).unwrap();
        assert_eq!(out, vec!["meet:join".to_string()]);
    }

    // ---- mint + verify happy path ----

    #[test]
    fn mint_and_verify_root_grant() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let policy = simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Any,
            Conditions::default(),
        );
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        // The issuer's own node honors its own root.
        assert!(iam
            .verify(
                &issuer.node_id(),
                &[],
                1000,
                &Principal(alice.node_id()),
                "storage:read",
                &grant.token,
                &never_revoked,
            )
            .is_ok());
        // An action not granted is denied.
        assert!(matches!(
            iam.verify(
                &issuer.node_id(),
                &[],
                1000,
                &Principal(alice.node_id()),
                "storage:write",
                &grant.token,
                &never_revoked,
            )
            .unwrap_err(),
            IamError::Denied(_)
        ));
    }

    #[test]
    fn mint_expands_wildcard_into_abilities() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let policy = simple_policy(vec!["storage:*".into()], ResourceMatch::Any, Conditions::default());
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        let abilities = &grant.leaf().cap.abilities;
        assert!(abilities.contains(&"storage:read".to_string()));
        assert!(abilities.contains(&"storage:write".to_string()));
        assert!(!abilities.contains(&"db:read".to_string()));
    }

    // ---- wrong issuer / wrong audience ----

    #[test]
    fn verify_rejects_unaccepted_root_on_other_node() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let other_node = id("other-node");
        let policy = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        // A *different* node that does not accept `issuer` as a root must deny.
        let err = iam
            .verify(
                &other_node.node_id(),
                &[],
                1000,
                &Principal(alice.node_id()),
                "storage:read",
                &grant.token,
                &never_revoked,
            )
            .unwrap_err();
        assert!(matches!(err, IamError::Denied(_)));
    }

    #[test]
    fn verify_honors_configured_accepted_root() {
        let issuer = id("org-root");
        let alice = id("alice");
        let node = id("node");
        let iam = iam().with_accepted_roots([issuer.node_id()]);
        let policy = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        assert!(iam
            .verify(&node.node_id(), &[], 1000, &Principal(alice.node_id()), "storage:read", &grant.token, &never_revoked)
            .is_ok());
    }

    #[test]
    fn verify_rejects_wrong_audience() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let bob = id("bob");
        let policy = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        let err = iam
            .verify(&issuer.node_id(), &[], 1000, &Principal(bob.node_id()), "storage:read", &grant.token, &never_revoked)
            .unwrap_err();
        assert!(matches!(err, IamError::Denied(_)));
    }

    // ---- attenuation ----

    #[test]
    fn attenuate_narrows_and_verifies() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let bob = id("bob");
        let root = simple_policy(
            vec!["storage:read".into(), "storage:write".into()],
            ResourceMatch::Any,
            Conditions::default(),
        );
        let parent = iam.mint(&issuer, Principal(alice.node_id()), &root, 1).unwrap();
        // Alice delegates only storage:read to Bob.
        let narrow = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let child = iam.attenuate(&alice, &parent, Principal(bob.node_id()), &narrow, 2).unwrap();
        assert_eq!(child.chain.len(), 2);
        // Bob may read.
        assert!(iam
            .verify(&issuer.node_id(), &[], 1000, &Principal(bob.node_id()), "storage:read", &child.token, &never_revoked)
            .is_ok());
        // Bob may NOT write (never delegated).
        assert!(iam
            .verify(&issuer.node_id(), &[], 1000, &Principal(bob.node_id()), "storage:write", &child.token, &never_revoked)
            .is_err());
    }

    #[test]
    fn attenuate_rejects_amplification_before_signing() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let bob = id("bob");
        let root = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let parent = iam.mint(&issuer, Principal(alice.node_id()), &root, 1).unwrap();
        // Alice tries to delegate storage:write, which she never held.
        let wider = simple_policy(vec!["storage:write".into()], ResourceMatch::Any, Conditions::default());
        let err = iam.attenuate(&alice, &parent, Principal(bob.node_id()), &wider, 2).unwrap_err();
        assert!(matches!(err, IamError::WouldAmplify(_)));
    }

    #[test]
    fn attenuate_rejects_resource_broadening() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let bob = id("bob");
        let root = simple_policy(vec!["storage:read".into()], ResourceMatch::Tag("gpu".into()), Conditions::default());
        let parent = iam.mint(&issuer, Principal(alice.node_id()), &root, 1).unwrap();
        let wider = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let err = iam.attenuate(&alice, &parent, Principal(bob.node_id()), &wider, 2).unwrap_err();
        assert!(matches!(err, IamError::WouldAmplify(_)));
    }

    #[test]
    fn attenuate_rejects_expiry_extension() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let bob = id("bob");
        let root = simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Any,
            Conditions { not_after: Some(500), ..Default::default() },
        );
        let parent = iam.mint(&issuer, Principal(alice.node_id()), &root, 1).unwrap();
        // Child tries to live past parent's expiry.
        let longer = simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Any,
            Conditions { not_after: Some(9999), ..Default::default() },
        );
        let err = iam.attenuate(&alice, &parent, Principal(bob.node_id()), &longer, 2).unwrap_err();
        assert!(matches!(err, IamError::WouldAmplify(_)));
    }

    #[test]
    fn attenuate_rejects_non_holder() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let mallory = id("mallory");
        let bob = id("bob");
        let root = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let parent = iam.mint(&issuer, Principal(alice.node_id()), &root, 1).unwrap();
        // Mallory (not the audience) tries to delegate alice's grant.
        let p = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let err = iam.attenuate(&mallory, &parent, Principal(bob.node_id()), &p, 2).unwrap_err();
        assert!(matches!(err, IamError::WouldAmplify(_)));
    }

    // ---- expiry + revocation at verify time ----

    #[test]
    fn verify_honors_expiry() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let policy = simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Any,
            Conditions { not_after: Some(500), ..Default::default() },
        );
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        assert!(iam
            .verify(&issuer.node_id(), &[], 499, &Principal(alice.node_id()), "storage:read", &grant.token, &never_revoked)
            .is_ok());
        assert!(iam
            .verify(&issuer.node_id(), &[], 501, &Principal(alice.node_id()), "storage:read", &grant.token, &never_revoked)
            .is_err());
    }

    #[test]
    fn verify_honors_revocation() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let policy = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 42).unwrap();
        let revoke_42 = |_: &NodeId, nonce: u64| nonce == 42;
        let err = iam
            .verify(&issuer.node_id(), &[], 1000, &Principal(alice.node_id()), "storage:read", &grant.token, &revoke_42)
            .unwrap_err();
        assert!(matches!(err, IamError::Denied(_)));
    }

    // ---- malformed input never panics ----

    #[test]
    fn verify_malformed_token_is_err_not_panic() {
        let iam = iam();
        let node = id("node");
        let who = id("who");
        for bad in ["", "zzz", "not-hex!!", "abcd", &"ff".repeat(10)] {
            let r = iam.verify(&node.node_id(), &[], 1, &Principal(who.node_id()), "x", bad, &never_revoked);
            assert!(r.is_err(), "expected Err for {bad:?}");
            assert!(matches!(r.unwrap_err(), IamError::MalformedChain(_) | IamError::Denied(_)));
        }
    }

    #[test]
    fn inspect_reports_scope() {
        let iam = iam();
        let issuer = id("issuer");
        let alice = id("alice");
        let bob = id("bob");
        let root = simple_policy(
            vec!["storage:read".into(), "storage:write".into()],
            ResourceMatch::Tag("gpu".into()),
            Conditions { not_after: Some(777), ..Default::default() },
        );
        let parent = iam.mint(&issuer, Principal(alice.node_id()), &root, 1).unwrap();
        let narrow = simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Tag("gpu".into()),
            Conditions { not_after: Some(700), ..Default::default() },
        );
        let child = iam.attenuate(&alice, &parent, Principal(bob.node_id()), &narrow, 2).unwrap();
        let scope = iam.inspect(&child.token).unwrap();
        assert_eq!(scope.depth, 2);
        assert_eq!(scope.root_issuer, hex::encode(issuer.node_id()));
        assert_eq!(scope.audience, hex::encode(bob.node_id()));
        assert_eq!(scope.abilities, vec!["storage:read".to_string()]);
        assert_eq!(scope.resource, "tag:gpu");
        assert_eq!(scope.not_after, 700);
        assert_eq!(scope.links.len(), 2);
    }

    #[test]
    fn inspect_malformed_is_err() {
        assert!(matches!(iam().inspect("zz").unwrap_err(), IamError::MalformedChain(_)));
    }

    #[test]
    fn compile_rejects_deny() {
        let iam = iam();
        let policy = Policy {
            version: "ce-iam-policy-v1".into(),
            statements: vec![crate::policy::Statement {
                sid: None,
                effect: Effect::Deny,
                actions: vec!["storage:read".into()],
                resource: ResourceMatch::Any,
                conditions: Conditions::default(),
            }],
        };
        assert!(matches!(iam.compile(&policy).unwrap_err(), IamError::DenyUnsupported));
    }

    #[test]
    fn render_resource_round_trips_via_parse() {
        for r in [
            Resource::Any,
            Resource::Tag("gpu".into()),
            Resource::AllOf(vec!["gpu".into(), "linux".into()]),
            Resource::Node([0x11u8; 32]),
        ] {
            let s = render_resource(&r);
            let back = ResourceMatch::parse(&s).unwrap().to_cap_resource().unwrap();
            assert_eq!(back, r, "round trip for {s}");
        }
    }
}
