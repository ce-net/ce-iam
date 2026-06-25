//! # ce-iam — IAM over CE capabilities
//!
//! `ce-iam` is identity-and-access-management as a managed product over the [`ce_cap`] capability
//! primitive. It gives you the familiar AWS-IAM vocabulary — **principals**, **roles**,
//! **policies**, mint/attenuate/verify/revoke — implemented as signed, attenuating CE capability
//! chains. Nothing here is a new node feature: it is an SDK/app tier composing
//! [`ce_cap`] (authz), [`ce_identity`] (keys), and [`ce_rs`] (the on-chain revocation view).
//!
//! ## Why capabilities, not ACLs
//!
//! AWS-IAM is a *policy server*: a central service evaluates `(principal, action, resource)` against
//! stored rules on every request. CE has no such server. A [`ce_cap`] **capability** is the inverse:
//! a portable, signed *grant* the holder carries and presents, verified **offline** by the resource
//! owner in microseconds. This buys three properties ACLs cannot:
//!
//! 1. **Attenuating** — a holder can sub-delegate only a *subset* of what it holds, recursively, and
//!    the math guarantees a delegation can never broaden authority (the central invariant this crate
//!    property-tests).
//! 2. **Offline-verifiable** — no policy server, no `O(shares)` host-side state; the token *is* the
//!    proof.
//! 3. **Uniformly revocable** — short expiries (offline), on-chain `RevokeCapability` keyed by
//!    `(issuer, nonce)` (revoking any link kills its subtree), and root rotation.
//!
//! ## The mapping
//!
//! | AWS-IAM concept        | ce-iam type / fn                                    |
//! |------------------------|-----------------------------------------------------|
//! | Principal (user/role)  | [`Principal`] — a CE node id                         |
//! | Policy document        | [`Policy`] / [`Statement`] / [`Effect`]             |
//! | Role (named policy)    | [`Role`]                                             |
//! | Action (`s3:GetObject`)| ability string inside a statement                   |
//! | Resource ARN           | [`ResourceMatch`] → [`ce_cap::Resource`]            |
//! | Condition              | [`Conditions`] → [`ce_cap::Caveats`]                |
//! | Attach policy          | [`Iam::mint`]                                        |
//! | AssumeRole (scoped)    | [`Iam::attenuate`]                                  |
//! | IsAuthorized           | [`Iam::verify`]                                     |
//! | Inspect a token        | [`Iam::inspect`]                                    |
//! | Revoke                 | on-chain `RevokeCapability` + [`RevocationSet`]      |
//!
//! ## Quick start
//!
//! ```no_run
//! use ce_iam::{Iam, Principal, ResourceMatch, Conditions, simple_policy};
//! use ce_identity::Identity;
//! # fn demo() -> anyhow::Result<()> {
//! let issuer = Identity::load_or_generate(std::path::Path::new("/tmp/iam-demo"))?;
//! let alice: Principal = Principal::parse(&"ab".repeat(32))?;
//!
//! // An IAM service with a closed action universe (so wildcards can expand).
//! let iam = Iam::new().with_action_universe(["storage:read".into(), "storage:write".into()]);
//!
//! // Mint a root grant: "alice may storage:read on any node".
//! let policy = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
//! let grant = iam.mint(&issuer, alice, &policy, /*nonce*/ 1)?;
//! println!("token = {}", grant.token);
//!
//! // Later, on the resource owner's node, verify offline:
//! let ok = iam.verify(
//!     &issuer.node_id(), &[], /*now*/ 0, &alice, "storage:read", &grant.token,
//!     &|_issuer, _nonce| false, // never-revoked predicate
//! );
//! assert!(ok.is_ok());
//! # Ok(()) }
//! ```

pub mod bridge;
pub mod catalog;
pub mod error;
pub mod grant;
pub mod policy;
pub mod principal;
pub mod revocation;
pub mod roots;
pub mod store;
pub mod wallet;

// The lightweight half lives in `ce-iam-core`. Re-export it whole so existing consumers keep using
// `ce_iam::device`, `ce_iam::secrets`, `ce_iam::Identity`, `ce_iam::Caveats`, etc. unchanged.
pub use ce_iam_core as core;
/// Device enrollment + the P-256<->NodeId binding (in `ce-iam-core`; re-exported as `ce_iam::device`).
pub use ce_iam_core::device;
/// The secrets vault (in `ce-iam-core`; re-exported as `ce_iam::secrets`).
pub use ce_iam_core::secrets;
pub use ce_iam_core::{
    Device, DeviceKey, DeviceStore, MemStore, ROLE_ADMIN, ROLE_PENDING, RevokeOutcome, Store, Vault,
};

// The cap-minting bridge MINTS (needs the issuing core), so it stays in the big crate.
pub use bridge::{ABILITY_OPERATOR, CapBridge, ability_for_aud};
pub use catalog::{AuditEntry, Catalog, CatalogLog, CatalogOp, EffectiveGrant};
pub use error::IamError;
pub use grant::{Grant, Iam, LinkInfo, Scope, render_resource, simple_policy};
pub use policy::{Conditions, Effect, Policy, ResourceMatch, Role, Statement};
pub use principal::Principal;
pub use revocation::{CachedRevocationSet, RevocationPolicy, RevocationSet};
pub use roots::{RootEntry, Roots};
pub use store::{CatalogStore, iam_dir};
pub use wallet::{WalletEntry, WalletStore};

// Re-export the substrate types apps need so they can depend on `ce-iam` alone.
pub use ce_cap::{Caveats, Resource, SignedCapability};
pub use ce_identity::{Identity, NodeId};

/// A conventional starting action universe for the CE Cloud suite — the abilities the published
/// products (`ce-storage`, `ce-db`, `ce-run`/`ce-fn`, `ce-drive`, tunnel) understand. Apps are free
/// to supply their own; abilities are opaque strings owned by each consuming product.
pub const CE_CLOUD_ACTIONS: &[&str] = &[
    "storage:read",
    "storage:write",
    "storage:list",
    "storage:delete",
    "db:read",
    "db:write",
    "db:admin",
    "run:deploy",
    "run:invoke",
    "run:kill",
    "drive:read",
    "drive:write",
    "drive:share",
    "exec",
    "sync",
    "tunnel",
];

/// The default action universe as owned `String`s, for [`Iam::with_action_universe`].
pub fn ce_cloud_action_universe() -> Vec<String> {
    CE_CLOUD_ACTIONS.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_universe_is_nonempty_and_sorted_after_install() {
        let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
        // with_action_universe sorts+dedups.
        let u = iam.action_universe();
        assert!(!u.is_empty());
        let mut sorted = u.to_vec();
        sorted.sort();
        assert_eq!(u, sorted.as_slice());
    }

    #[test]
    fn end_to_end_three_level_delegation() {
        use std::sync::atomic::{AtomicU64, Ordering};
        fn id(tag: &str) -> Identity {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("ce-iam-e2e-{}-{n}-{tag}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Identity::load_or_generate(&dir).unwrap()
        }

        let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
        let org = id("org");
        let alice = id("alice");
        let bob = id("bob");

        // org → alice: all storage on any node.
        let root = simple_policy(
            vec![
                "storage:read".into(),
                "storage:write".into(),
                "storage:list".into(),
            ],
            ResourceMatch::Any,
            Conditions::default(),
        );
        let g1 = iam
            .mint(&org, Principal(alice.node_id()), &root, 1)
            .unwrap();

        // alice → bob: only read, only on tag:gpu.
        let narrow = simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Tag("gpu".into()),
            Conditions::default(),
        );
        let g2 = iam
            .attenuate(&alice, &g1, Principal(bob.node_id()), &narrow, 2)
            .unwrap();

        let tags = vec!["gpu".to_string(), "linux".to_string()];
        // Bob can read on a gpu node...
        assert!(
            iam.verify(
                &org.node_id(),
                &tags,
                0,
                &Principal(bob.node_id()),
                "storage:read",
                &g2.token,
                &|_, _| false
            )
            .is_ok()
        );
        // ...but cannot write (never delegated)...
        assert!(
            iam.verify(
                &org.node_id(),
                &tags,
                0,
                &Principal(bob.node_id()),
                "storage:write",
                &g2.token,
                &|_, _| false
            )
            .is_err()
        );
        // ...and cannot act on a non-gpu node.
        assert!(
            iam.verify(
                &org.node_id(),
                &["linux".to_string()],
                0,
                &Principal(bob.node_id()),
                "storage:read",
                &g2.token,
                &|_, _| false
            )
            .is_err()
        );

        // Revoke the root link → the whole subtree dies.
        let revset = RevocationSet::from_pairs([(org.node_id(), 1)]);
        assert!(
            iam.verify(
                &org.node_id(),
                &tags,
                0,
                &Principal(bob.node_id()),
                "storage:read",
                &g2.token,
                &revset.predicate()
            )
            .is_err()
        );
    }
}
