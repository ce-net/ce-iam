//! Integration tests for the managed role/policy catalog over the ce-coord replicated-map model.
//!
//! Three things are proven here, end-to-end against the real [`Iam`] verifier and real CE identities:
//!
//! 1. **Catalog CRUD convergence over ce-coord** — a writer evolves the catalog through an ordered
//!    op-log; a reader that replays that log (exactly what a `ce_coord::RMap` reader does) reaches a
//!    byte-identical catalog, including partial-replay prefixes.
//! 2. **Effective-grant resolution** — the catalog's `effective_grants` report matches what actually
//!    minting from the attached roles produces and verifies.
//! 3. **Catalog changes never broaden an already-issued capability** — a token minted from a role is
//!    an immutable signed capability; widening, replacing, or deleting that role afterwards leaves
//!    the issued token's authority exactly as it was. This is the central safety property.

use ce_iam::{
    Catalog, CatalogLog, CatalogOp, Conditions, Iam, Principal, ResourceMatch, Role,
    ce_cloud_action_universe, simple_policy,
};
use ce_iam::{Identity, NodeId};
use proptest::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn fresh_identity() -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-iam-cat-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn never_revoked(_: &NodeId, _: u64) -> bool {
    false
}

fn iam() -> Iam {
    Iam::new().with_action_universe(ce_cloud_action_universe())
}

fn reader_role(name: &str) -> Role {
    Role::new(
        name,
        simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default()),
    )
}

// ============================ convergence over ce-coord =====================================

#[test]
fn catalog_crud_converges_over_coord_log() {
    // The writer mutates the catalog and logs each op (the ce-coord writer broadcast). A reader is
    // any node that replays that op-log in order; convergence means it reaches the writer's state.
    let actor = Principal(fresh_identity().node_id());
    let alice = Principal(fresh_identity().node_id());

    let mut writer = Catalog::new();
    let mut log = CatalogLog::new();

    let script = vec![
        CatalogOp::PutRole(reader_role("reader")),
        CatalogOp::PutRole(Role::new(
            "writer",
            simple_policy(vec!["storage:write".into()], ResourceMatch::Any, Conditions::default()),
        )),
        CatalogOp::PutPolicy {
            name: "audit-only".into(),
            policy: simple_policy(vec!["db:read".into()], ResourceMatch::Any, Conditions::default()),
        },
        CatalogOp::AttachRole { principal: alice, role: "reader".into() },
        CatalogOp::AttachRole { principal: alice, role: "writer".into() },
        CatalogOp::RemoveRole("writer".into()),
    ];
    for op in &script {
        writer.apply(op.clone(), Some(&actor));
        log.record(op.clone(), Some(&actor));
    }

    // Full replay on a fresh replica reproduces the writer exactly.
    let reader = log.replay();
    assert_eq!(reader, writer);
    assert_eq!(reader.version(), writer.version());

    // Removing "writer" detached it from alice, leaving only "reader".
    assert_eq!(reader.roles_for(&alice), vec!["reader".to_string()]);

    // Every prefix replay is a valid intermediate state (monotone version).
    for upto in 0..=log.len() as u64 {
        let partial = log.replay_through(upto);
        assert_eq!(partial.version(), upto);
    }
}

#[test]
fn two_independent_replicas_of_same_log_are_identical() {
    let mut log = CatalogLog::new();
    log.record(CatalogOp::PutRole(reader_role("a")), None);
    log.record(CatalogOp::PutRole(reader_role("b")), None);
    log.record(CatalogOp::AttachRole { principal: Principal([1u8; 32]), role: "a".into() }, None);

    let r1 = log.replay();
    let r2 = log.replay();
    assert_eq!(r1, r2, "two readers of the same log converge");
    // Serialized form is identical too (deterministic BTreeMap ordering).
    assert_eq!(serde_json::to_string(&r1).unwrap(), serde_json::to_string(&r2).unwrap());
}

// ============================ effective-grant resolution ====================================

#[test]
fn effective_grants_match_minted_capability() {
    let iam = iam();
    let issuer = fresh_identity();
    let alice = Principal(fresh_identity().node_id());

    let mut cat = Catalog::new();
    cat.put_role(reader_role("reader"), None).unwrap();
    cat.put_role(
        Role::new(
            "lister",
            simple_policy(vec!["storage:list".into()], ResourceMatch::Any, Conditions::default()),
        ),
        None,
    )
    .unwrap();
    cat.attach_role(alice, "reader", None).unwrap();
    cat.attach_role(alice, "lister", None).unwrap();

    // The catalog reports one effective grant: {storage:list, storage:read} on Any.
    let eff = cat.effective_grants(&alice).unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].abilities, vec!["storage:list".to_string(), "storage:read".to_string()]);

    // Minting that exact effective grant produces a capability that authorizes precisely those
    // actions and nothing else — the report is faithful to issuance.
    let policy = simple_policy(eff[0].abilities.clone(), eff[0].resource.clone(), eff[0].conditions.clone());
    let grant = iam.mint(&issuer, alice, &policy, 1).unwrap();
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:read", &grant.token, &never_revoked)
        .is_ok());
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:list", &grant.token, &never_revoked)
        .is_ok());
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:write", &grant.token, &never_revoked)
        .is_err());
}

#[test]
fn mint_role_uses_catalog_role() {
    let iam = iam();
    let issuer = fresh_identity();
    let alice = Principal(fresh_identity().node_id());
    let mut cat = Catalog::new();
    cat.put_role(reader_role("reader"), None).unwrap();

    let grant = iam.mint_role(&issuer, alice, &cat, "reader", 5).unwrap();
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:read", &grant.token, &never_revoked)
        .is_ok());

    // Minting from a missing role is a clean error, not a panic.
    assert!(matches!(
        iam.mint_role(&issuer, alice, &cat, "ghost", 6).unwrap_err(),
        ce_iam::IamError::BadPolicy(_)
    ));
}

// ============= catalog changes never broaden an already-issued capability ===================

#[test]
fn widening_a_role_does_not_broaden_an_issued_token() {
    let iam = iam();
    let issuer = fresh_identity();
    let alice = Principal(fresh_identity().node_id());

    let mut cat = Catalog::new();
    cat.put_role(reader_role("role"), None).unwrap(); // storage:read only

    // Issue a token from the narrow role.
    let grant = iam.mint_role(&issuer, alice, &cat, "role", 1).unwrap();
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:read", &grant.token, &never_revoked)
        .is_ok());
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:write", &grant.token, &never_revoked)
        .is_err());

    // Now WIDEN the catalog role to also grant storage:write.
    cat.put_role(
        Role::new(
            "role",
            simple_policy(
                vec!["storage:read".into(), "storage:write".into()],
                ResourceMatch::Any,
                Conditions::default(),
            ),
        ),
        None,
    )
    .unwrap();

    // The ALREADY-ISSUED token is unchanged: it still authorizes only storage:read. A catalog edit
    // cannot retroactively broaden a signed capability in a holder's wallet.
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:read", &grant.token, &never_revoked)
        .is_ok());
    assert!(
        iam.verify(&issuer.node_id(), &[], 0, &alice, "storage:write", &grant.token, &never_revoked)
            .is_err(),
        "widening the catalog role must NOT broaden the issued token"
    );

    // Only a FRESH mint from the widened role carries the new authority (and it is a distinct token).
    let grant2 = iam.mint_role(&issuer, alice, &cat, "role", 2).unwrap();
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:write", &grant2.token, &never_revoked)
        .is_ok());
    assert_ne!(grant.token, grant2.token);
}

#[test]
fn deleting_a_role_does_not_revoke_an_issued_token() {
    // Catalog deletion is not revocation: the token outlives the template it was minted from.
    let iam = iam();
    let issuer = fresh_identity();
    let alice = Principal(fresh_identity().node_id());

    let mut cat = Catalog::new();
    cat.put_role(reader_role("role"), None).unwrap();
    let grant = iam.mint_role(&issuer, alice, &cat, "role", 1).unwrap();

    cat.remove_role("role", None);
    assert!(cat.get_role("role").is_none());
    assert!(cat.effective_grants(&alice).unwrap().is_empty());

    // The issued token still verifies — deletion changed only future issuance, not live tokens.
    assert!(iam
        .verify(&issuer.node_id(), &[], 0, &alice, "storage:read", &grant.token, &never_revoked)
        .is_ok());
}

#[test]
fn issued_token_scope_is_byte_stable_across_catalog_edits() {
    // Stronger statement of the invariant: the inspected scope of an issued token is identical before
    // and after arbitrary catalog churn.
    let iam = iam();
    let issuer = fresh_identity();
    let alice = Principal(fresh_identity().node_id());

    let mut cat = Catalog::new();
    cat.put_role(reader_role("role"), None).unwrap();
    let grant = iam.mint_role(&issuer, alice, &cat, "role", 1).unwrap();
    let scope_before = iam.inspect(&grant.token).unwrap();

    // Churn: widen, attach, detach, delete, re-create with a totally different policy.
    cat.put_role(
        Role::new("role", simple_policy(vec!["*".into()], ResourceMatch::Any, Conditions::default())),
        None,
    )
    .unwrap();
    cat.attach_role(alice, "role", None).unwrap();
    cat.detach_role(alice, "role", None);
    cat.remove_role("role", None);
    cat.put_role(
        Role::new("role", simple_policy(vec!["db:admin".into()], ResourceMatch::Tag("x".into()), Conditions::default())),
        None,
    )
    .unwrap();

    let scope_after = iam.inspect(&grant.token).unwrap();
    assert_eq!(scope_before, scope_after, "the issued token's scope must be immutable");
}

// ============================ property tests ================================================

proptest! {
    /// CRUD convergence: for any sequence of catalog ops, replaying the writer's op-log on a fresh
    /// replica reproduces the writer exactly, and every prefix replay sits at its own version.
    #[test]
    fn prop_op_log_replay_converges(seq in proptest::collection::vec(0u8..6, 0..40)) {
        // A small fixed cast of roles and principals so ops reference real names.
        let p = |b: u8| Principal([b; 32]);
        let role_name = |i: u8| format!("role{}", i % 3);

        let mut writer = Catalog::new();
        let mut log = CatalogLog::new();
        // Ensure the three roles exist up front so attaches can succeed; their churn is exercised by
        // the random ops below.
        for i in 0..3u8 {
            let op = CatalogOp::PutRole(reader_role(&format!("role{i}")));
            writer.apply(op.clone(), None);
            log.record(op, None);
        }

        for (n, code) in seq.iter().enumerate() {
            let i = n as u8;
            let op = match code {
                0 => CatalogOp::PutRole(reader_role(&role_name(i))),
                1 => CatalogOp::RemoveRole(role_name(i)),
                2 => CatalogOp::PutPolicy {
                    name: format!("pol{}", i % 4),
                    policy: simple_policy(vec!["db:read".into()], ResourceMatch::Any, Conditions::default()),
                },
                3 => CatalogOp::RemovePolicy(format!("pol{}", i % 4)),
                4 => CatalogOp::AttachRole { principal: p(i % 5), role: role_name(i) },
                _ => CatalogOp::DetachRole { principal: p(i % 5), role: role_name(i) },
            };
            writer.apply(op.clone(), None);
            log.record(op, None);
        }

        let reader = log.replay();
        prop_assert_eq!(&reader, &writer);
        prop_assert_eq!(reader.version(), log.len() as u64);

        for upto in 0..=log.len() as u64 {
            let partial = log.replay_through(upto);
            prop_assert_eq!(partial.version(), upto);
        }
    }

    /// Effective grants never reference a role that is not present, and abilities are always a sorted
    /// dedup union of the attached roles' actions (no broadening, no duplication).
    #[test]
    fn prop_effective_grants_are_well_formed(attach in proptest::collection::vec(0u8..3, 0..6)) {
        let mut cat = Catalog::new();
        for i in 0..3u8 {
            // role{i} grants exactly one distinct action, all on Resource::Any.
            let action = match i { 0 => "storage:read", 1 => "storage:write", _ => "storage:list" };
            cat.put_role(
                Role::new(format!("role{i}"), simple_policy(vec![action.into()], ResourceMatch::Any, Conditions::default())),
                None,
            ).unwrap();
        }
        let alice = Principal([42u8; 32]);
        let mut expected: Vec<String> = Vec::new();
        for code in &attach {
            cat.attach_role(alice, &format!("role{code}"), None).unwrap();
            let action = match code { 0 => "storage:read", 1 => "storage:write", _ => "storage:list" };
            expected.push(action.to_string());
        }
        expected.sort();
        expected.dedup();

        let eff = cat.effective_grants(&alice).unwrap();
        if expected.is_empty() {
            prop_assert!(eff.is_empty());
        } else {
            // All on one scope (Resource::Any, default conditions) → exactly one effective grant.
            prop_assert_eq!(eff.len(), 1);
            prop_assert_eq!(&eff[0].abilities, &expected);
            // Sorted + deduped invariant.
            let mut sorted = eff[0].abilities.clone();
            sorted.sort();
            sorted.dedup();
            prop_assert_eq!(&eff[0].abilities, &sorted);
        }
    }

    /// The safety invariant under randomization: for any catalog edit applied AFTER a token is
    /// issued, the issued token's verified authority is unchanged.
    #[test]
    fn prop_catalog_edits_never_broaden_issued_token(widen_actions in proptest::collection::vec(0u8..4, 0..4)) {
        let iam = iam();
        let issuer = fresh_identity();
        let alice = Principal(fresh_identity().node_id());

        let mut cat = Catalog::new();
        cat.put_role(reader_role("role"), None).unwrap(); // storage:read only
        let grant = iam.mint_role(&issuer, alice, &cat, "role", 1).unwrap();

        // Apply an arbitrary widening of the catalog role.
        let mut wider: Vec<String> = vec!["storage:read".into()];
        for code in &widen_actions {
            wider.push(match code {
                0 => "storage:write".into(),
                1 => "storage:list".into(),
                2 => "storage:delete".into(),
                _ => "db:read".into(),
            });
        }
        cat.put_role(
            Role::new("role", simple_policy(wider, ResourceMatch::Any, Conditions::default())),
            None,
        ).unwrap();
        // And delete it entirely.
        cat.remove_role("role", None);

        // The issued token still authorizes storage:read and STILL denies everything it never held.
        prop_assert!(iam
            .verify(&issuer.node_id(), &[], 0, &alice, "storage:read", &grant.token, &never_revoked)
            .is_ok());
        for denied in ["storage:write", "storage:list", "storage:delete", "db:read"] {
            prop_assert!(iam
                .verify(&issuer.node_id(), &[], 0, &alice, denied, &grant.token, &never_revoked)
                .is_err(), "issued token must never gain {}", denied);
        }
    }
}
