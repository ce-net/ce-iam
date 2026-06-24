//! Property tests for the central IAM security invariants.
//!
//! These are the tests that make ce-iam trustworthy as a foundation. They assert, over randomized
//! grants and chains, the properties the design promises:
//!
//! 1. **Attenuation can never amplify** — a child grant produced by [`Iam::attenuate`] only ever
//!    authorizes a *subset* of what its parent authorizes. We never find an action the child allows
//!    that the parent denies.
//! 2. **Expiry is honored** — a grant that has expired at `now` never verifies, and one within its
//!    window does (all else equal).
//! 3. **Revocation is honored** — revoking any link's `(issuer, nonce)` denies the whole chain.
//! 4. **Wrong issuer / wrong audience is rejected** — a chain rooted at an unaccepted key, or
//!    presented by the wrong principal, never authorizes.
//! 5. **Malformed input never panics** — arbitrary byte strings fed to `verify`/`inspect`/`decode`
//!    return `Err`, never crash.
//! 6. **Token serialization round-trips** — encode→decode is identity for any valid grant.

use ce_iam::{Conditions, Iam, Principal, ResourceMatch, RevocationSet, simple_policy};
use ce_iam::{Identity, NodeId};
use proptest::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn fresh_identity() -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-iam-prop-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn never_revoked(_: &NodeId, _: u64) -> bool {
    false
}

/// The fixed action universe used by these tests.
const UNIVERSE: &[&str] = &["a:read", "a:write", "a:list", "b:read", "b:write"];

fn iam() -> Iam {
    Iam::new().with_action_universe(UNIVERSE.iter().map(|s| s.to_string()))
}

/// Strategy: a non-empty subset of the universe (as a sorted, deduped Vec).
fn action_subset() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(0..UNIVERSE.len(), 1..=UNIVERSE.len()).prop_map(|idxs| {
        let mut v: Vec<String> = idxs.into_iter().map(|i| UNIVERSE[i].to_string()).collect();
        v.sort();
        v.dedup();
        v
    })
}

proptest! {
    /// Attenuation can never amplify: for any parent action-set P and any child action-set C,
    /// the child grant authorizes an action iff that action is in C AND C ⊆ P. In particular it
    /// never authorizes an action the parent does not authorize.
    #[test]
    fn attenuation_never_amplifies(parent_actions in action_subset(), child_actions in action_subset()) {
        let iam = iam();
        let issuer = fresh_identity();
        let alice = fresh_identity();
        let bob = fresh_identity();

        let root = simple_policy(parent_actions.clone(), ResourceMatch::Any, Conditions::default());
        let parent = iam.mint(&issuer, Principal(alice.node_id()), &root, 1).unwrap();

        let narrow = simple_policy(child_actions.clone(), ResourceMatch::Any, Conditions::default());
        let child_result = iam.attenuate(&alice, &parent, Principal(bob.node_id()), &narrow, 2);

        let child_is_subset = child_actions.iter().all(|a| parent_actions.contains(a));

        if child_is_subset {
            // A valid (narrowing) delegation: the child must authorize exactly its own actions and
            // nothing outside the parent.
            let child = child_result.expect("subset delegation must succeed");
            for action in UNIVERSE {
                let allowed = iam
                    .verify(&issuer.node_id(), &[], 0, &Principal(bob.node_id()), action, &child.token, &never_revoked)
                    .is_ok();
                let expected = child_actions.iter().any(|a| a == action);
                prop_assert_eq!(allowed, expected, "action {} mismatch", action);
                // Never amplify: anything the child allows, the parent must also allow.
                if allowed {
                    prop_assert!(parent_actions.iter().any(|a| a == action),
                        "child allowed {} but parent did not", action);
                }
            }
        } else {
            // A broadening delegation must be refused before signing — it can never produce a token.
            prop_assert!(child_result.is_err(), "broadening delegation must be rejected");
        }
    }

    /// Expiry is honored: a grant with not_after = E verifies iff now <= E (E=0 means never expire).
    #[test]
    fn expiry_is_honored(expiry in 1u64..1_000_000, now in 0u64..2_000_000) {
        let iam = iam();
        let issuer = fresh_identity();
        let alice = fresh_identity();
        let policy = simple_policy(
            vec!["a:read".into()],
            ResourceMatch::Any,
            Conditions { not_after: Some(expiry), ..Default::default() },
        );
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        let ok = iam
            .verify(&issuer.node_id(), &[], now, &Principal(alice.node_id()), "a:read", &grant.token, &never_revoked)
            .is_ok();
        prop_assert_eq!(ok, now <= expiry);
    }

    /// Revoking any link's nonce denies the whole chain.
    #[test]
    fn revocation_denies_chain(revoke_root in any::<bool>()) {
        let iam = iam();
        let issuer = fresh_identity();
        let alice = fresh_identity();
        let bob = fresh_identity();
        let root = simple_policy(vec!["a:read".into(), "a:write".into()], ResourceMatch::Any, Conditions::default());
        let parent = iam.mint(&issuer, Principal(alice.node_id()), &root, 10).unwrap();
        let narrow = simple_policy(vec!["a:read".into()], ResourceMatch::Any, Conditions::default());
        let child = iam.attenuate(&alice, &parent, Principal(bob.node_id()), &narrow, 20).unwrap();

        // Sanity: without revocation it verifies.
        prop_assert!(iam
            .verify(&issuer.node_id(), &[], 0, &Principal(bob.node_id()), "a:read", &child.token, &never_revoked)
            .is_ok());

        // Revoke either the root or the child link.
        let revoked_nonce = if revoke_root { 10 } else { 20 };
        let revset = RevocationSet::from_pairs([
            (if revoke_root { issuer.node_id() } else { alice.node_id() }, revoked_nonce),
        ]);
        prop_assert!(iam
            .verify(&issuer.node_id(), &[], 0, &Principal(bob.node_id()), "a:read", &child.token, &revset.predicate())
            .is_err());
    }

    /// A chain rooted at an unaccepted key never authorizes on a node that doesn't accept it.
    #[test]
    fn wrong_issuer_is_rejected(_seed in any::<u8>()) {
        let iam = iam();
        let issuer = fresh_identity();
        let alice = fresh_identity();
        let other_node = fresh_identity();
        let policy = simple_policy(vec!["a:read".into()], ResourceMatch::Any, Conditions::default());
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        // A node that is neither the issuer nor configured to accept it must deny.
        prop_assert!(iam
            .verify(&other_node.node_id(), &[], 0, &Principal(alice.node_id()), "a:read", &grant.token, &never_revoked)
            .is_err());
    }

    /// The wrong principal presenting a grant is rejected.
    #[test]
    fn wrong_audience_is_rejected(_seed in any::<u8>()) {
        let iam = iam();
        let issuer = fresh_identity();
        let alice = fresh_identity();
        let mallory = fresh_identity();
        let policy = simple_policy(vec!["a:read".into()], ResourceMatch::Any, Conditions::default());
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        prop_assert!(iam
            .verify(&issuer.node_id(), &[], 0, &Principal(mallory.node_id()), "a:read", &grant.token, &never_revoked)
            .is_err());
    }

    /// Malformed tokens never panic: verify/inspect/decode return Err for arbitrary bytes.
    #[test]
    fn malformed_tokens_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let iam = iam();
        let node = fresh_identity();
        let who = fresh_identity();
        let token = hex::encode(&bytes);
        // None of these may panic; all must be Err (decode could occasionally succeed into a chain
        // that then fails authorize — still Err, never Ok for a random blob).
        let v = iam.verify(&node.node_id(), &[], 0, &Principal(who.node_id()), "a:read", &token, &never_revoked);
        prop_assert!(v.is_err());
        let _ = iam.inspect(&token); // must not panic (may be Err)
        let _ = iam.decode(&token);  // must not panic (may be Err)
        // Non-hex strings too.
        let weird = format!("{}!!not-hex", token);
        prop_assert!(iam.verify(&node.node_id(), &[], 0, &Principal(who.node_id()), "a:read", &weird, &never_revoked).is_err());
    }

    /// Token encode→decode is identity for any valid minted grant.
    #[test]
    fn token_round_trips(actions in action_subset()) {
        let iam = iam();
        let issuer = fresh_identity();
        let alice = fresh_identity();
        let policy = simple_policy(actions, ResourceMatch::Any, Conditions::default());
        let grant = iam.mint(&issuer, Principal(alice.node_id()), &policy, 1).unwrap();
        let decoded = iam.decode(&grant.token).unwrap();
        prop_assert_eq!(&decoded.token, &grant.token);
        prop_assert_eq!(decoded.chain.len(), grant.chain.len());
        // Re-encode matches.
        let scope_a = iam.inspect(&grant.token).unwrap();
        let scope_b = iam.inspect(&decoded.token).unwrap();
        prop_assert_eq!(scope_a, scope_b);
    }

    /// Principal hex parsing round-trips for any 32-byte id.
    #[test]
    fn principal_round_trips(raw in proptest::array::uniform32(any::<u8>())) {
        let p = Principal(raw);
        let back = Principal::parse(&p.hex()).unwrap();
        prop_assert_eq!(p, back);
    }

    /// Multi-link (depth >= 3) attenuation: a 3-deep chain authorizes exactly the leaf's actions,
    /// always a subset of every ancestor's, and never more than the root granted.
    #[test]
    fn deep_chain_never_amplifies(
        root_actions in action_subset(),
        mid_actions in action_subset(),
        leaf_actions in action_subset(),
    ) {
        let iam = iam();
        let org = fresh_identity();
        let alice = fresh_identity();
        let bob = fresh_identity();
        let carol = fresh_identity();

        let g1 = iam.mint(
            &org, Principal(alice.node_id()),
            &simple_policy(root_actions.clone(), ResourceMatch::Any, Conditions::default()), 1,
        ).unwrap();

        // alice -> bob: only succeeds if mid ⊆ root.
        let mid_is_subset = mid_actions.iter().all(|a| root_actions.contains(a));
        let g2 = iam.attenuate(
            &alice, &g1, Principal(bob.node_id()),
            &simple_policy(mid_actions.clone(), ResourceMatch::Any, Conditions::default()), 2,
        );
        if !mid_is_subset {
            prop_assert!(g2.is_err());
            return Ok(());
        }
        let g2 = g2.unwrap();

        // bob -> carol: only succeeds if leaf ⊆ mid.
        let leaf_is_subset = leaf_actions.iter().all(|a| mid_actions.contains(a));
        let g3 = iam.attenuate(
            &bob, &g2, Principal(carol.node_id()),
            &simple_policy(leaf_actions.clone(), ResourceMatch::Any, Conditions::default()), 3,
        );
        if !leaf_is_subset {
            prop_assert!(g3.is_err());
            return Ok(());
        }
        let g3 = g3.unwrap();
        prop_assert_eq!(g3.chain.len(), 3);

        // carol's authority is exactly leaf_actions, and ⊆ root_actions.
        for action in UNIVERSE {
            let allowed = iam
                .verify(&org.node_id(), &[], 0, &Principal(carol.node_id()), action, &g3.token, &never_revoked)
                .is_ok();
            prop_assert_eq!(allowed, leaf_actions.iter().any(|a| a == action));
            if allowed {
                prop_assert!(root_actions.iter().any(|a| a == action),
                    "depth-3 leaf allowed {} the root never granted", action);
            }
        }
    }

    /// DoS bound: a chain deeper than the configured max-depth is rejected as malformed, never
    /// authorized, regardless of how the deep chain was built. We build a long legitimate chain and
    /// verify it under a tight depth limit.
    #[test]
    fn depth_limit_rejects_long_chains(extra in 2usize..8) {
        let limit = 1;
        let iam = iam().with_max_chain_depth(limit);
        let org = fresh_identity();
        let mut holder = fresh_identity();
        let mut grant = iam.mint(
            &org, Principal(holder.node_id()),
            &simple_policy(vec!["a:read".into()], ResourceMatch::Any, Conditions::default()), 1,
        ).unwrap();
        // Build a chain of depth `extra + 1` > limit.
        for n in 0..extra {
            let next = fresh_identity();
            grant = iam.attenuate(
                &holder, &grant, Principal(next.node_id()),
                &simple_policy(vec!["a:read".into()], ResourceMatch::Any, Conditions::default()),
                (n as u64) + 2,
            ).unwrap();
            holder = next;
        }
        let r = iam.verify(&org.node_id(), &[], 0, &Principal(holder.node_id()), "a:read", &grant.token, &never_revoked);
        prop_assert!(matches!(r, Err(ce_iam::IamError::MalformedChain(_))));
    }

    /// DoS bound: an oversized token (longer than max_token_bytes) is rejected before decoding.
    #[test]
    fn oversize_token_rejected(pad in 1usize..4096) {
        let iam = iam().with_max_token_bytes(32);
        let org = fresh_identity();
        let alice = fresh_identity();
        let grant = iam.mint(
            &org, Principal(alice.node_id()),
            &simple_policy(vec!["a:read".into()], ResourceMatch::Any, Conditions::default()), 1,
        ).unwrap();
        // The real token already exceeds 32 bytes; appending more keeps it oversized.
        let big = format!("{}{}", grant.token, "0".repeat(pad));
        let r = iam.verify(&org.node_id(), &[], 0, &Principal(alice.node_id()), "a:read", &big, &never_revoked);
        prop_assert!(matches!(r, Err(ce_iam::IamError::MalformedChain(m)) if m.contains("limit")));
    }
}
