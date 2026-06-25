//! Integration tests: the IAM service end-to-end, plus failure-injection on the node-backed
//! revocation view (a node that is down / errors must degrade gracefully, never panic).

use ce_iam::{
    Conditions, Iam, Principal, ResourceMatch, RevocationSet, Role, ce_cloud_action_universe,
    simple_policy,
};
use ce_iam::{Identity, NodeId, Policy};
use std::sync::atomic::{AtomicU64, Ordering};

fn fresh_identity() -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-iam-it-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn never_revoked(_: &NodeId, _: u64) -> bool {
    false
}

#[test]
fn role_to_grant_to_verify_flow() {
    // A role (named policy) is attached to a principal by minting its policy.
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let issuer = fresh_identity();
    let alice = fresh_identity();

    let role = Role::new(
        "storage-reader",
        simple_policy(
            vec!["storage:read".into(), "storage:list".into()],
            ResourceMatch::Any,
            Conditions::default(),
        ),
    );
    // Round-trip the role through JSON (as it would be stored).
    let role: Role = Role::from_json(&role.to_json()).unwrap();

    let grant = iam
        .mint(&issuer, Principal(alice.node_id()), &role.policy, 1)
        .unwrap();
    assert!(
        iam.verify(
            &issuer.node_id(),
            &[],
            0,
            &Principal(alice.node_id()),
            "storage:read",
            &grant.token,
            &never_revoked
        )
        .is_ok()
    );
    assert!(
        iam.verify(
            &issuer.node_id(),
            &[],
            0,
            &Principal(alice.node_id()),
            "storage:list",
            &grant.token,
            &never_revoked
        )
        .is_ok()
    );
    assert!(
        iam.verify(
            &issuer.node_id(),
            &[],
            0,
            &Principal(alice.node_id()),
            "storage:write",
            &grant.token,
            &never_revoked
        )
        .is_err()
    );
}

#[test]
fn wildcard_policy_grants_whole_prefix() {
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let issuer = fresh_identity();
    let alice = fresh_identity();
    let policy = Policy::from_json(
        r#"{
            "version":"ce-iam-policy-v1",
            "statements":[{"effect":"Allow","actions":["storage:*"],"resource":"any"}]
        }"#,
    )
    .unwrap();
    let grant = iam
        .mint(&issuer, Principal(alice.node_id()), &policy, 1)
        .unwrap();
    for action in [
        "storage:read",
        "storage:write",
        "storage:list",
        "storage:delete",
    ] {
        assert!(
            iam.verify(
                &issuer.node_id(),
                &[],
                0,
                &Principal(alice.node_id()),
                action,
                &grant.token,
                &never_revoked
            )
            .is_ok(),
            "expected {action} allowed by storage:*"
        );
    }
    // A different prefix is not granted.
    assert!(
        iam.verify(
            &issuer.node_id(),
            &[],
            0,
            &Principal(alice.node_id()),
            "db:read",
            &grant.token,
            &never_revoked
        )
        .is_err()
    );
}

#[test]
fn deny_statement_is_rejected_at_mint() {
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let issuer = fresh_identity();
    let alice = fresh_identity();
    let policy = Policy::from_json(
        r#"{
            "version":"ce-iam-policy-v1",
            "statements":[{"effect":"Deny","actions":["storage:read"],"resource":"any"}]
        }"#,
    )
    .unwrap();
    let err = iam
        .mint(&issuer, Principal(alice.node_id()), &policy, 1)
        .unwrap_err();
    assert!(matches!(err, ce_iam::IamError::DenyUnsupported));
}

#[test]
fn resource_scoping_by_tag_is_enforced() {
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let issuer = fresh_identity();
    let alice = fresh_identity();
    let policy = simple_policy(
        vec!["run:deploy".into()],
        ResourceMatch::Tag("gpu".into()),
        Conditions::default(),
    );
    let grant = iam
        .mint(&issuer, Principal(alice.node_id()), &policy, 1)
        .unwrap();
    // gpu node: allowed.
    assert!(
        iam.verify(
            &issuer.node_id(),
            &["gpu".to_string()],
            0,
            &Principal(alice.node_id()),
            "run:deploy",
            &grant.token,
            &never_revoked
        )
        .is_ok()
    );
    // non-gpu node: denied.
    assert!(
        iam.verify(
            &issuer.node_id(),
            &["cpu".to_string()],
            0,
            &Principal(alice.node_id()),
            "run:deploy",
            &grant.token,
            &never_revoked
        )
        .is_err()
    );
}

#[test]
fn revocation_set_from_node_wire_form_works() {
    // Simulate the (issuer_hex, nonce) wire form returned by GET /capabilities/revoked.
    let issuer = fresh_identity();
    let alice = fresh_identity();
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let policy = simple_policy(
        vec!["storage:read".into()],
        ResourceMatch::Any,
        Conditions::default(),
    );
    let grant = iam
        .mint(&issuer, Principal(alice.node_id()), &policy, 99)
        .unwrap();

    let wire = vec![(issuer.node_id_hex(), 99u64)];
    let revset = RevocationSet::from_hex_pairs(&wire);
    assert!(
        iam.verify(
            &issuer.node_id(),
            &[],
            0,
            &Principal(alice.node_id()),
            "storage:read",
            &grant.token,
            &revset.predicate()
        )
        .is_err()
    );
}

#[tokio::test]
async fn revocation_fetch_against_dead_node_is_graceful_err() {
    // Point at a port nothing is listening on. fetch() must return Err, not panic.
    let client = ce_rs::CeClient::new("http://127.0.0.1:1");
    let result = RevocationSet::fetch(&client).await;
    assert!(
        result.is_err(),
        "fetch against a dead node should error gracefully"
    );
    match result {
        Err(ce_iam::IamError::Node(_)) => {}
        other => panic!("expected IamError::Node, got {other:?}"),
    }
}

#[tokio::test]
async fn submit_revoke_against_dead_node_is_graceful_err() {
    let result = ce_iam::revocation::submit_revoke("http://127.0.0.1:1", Some("tok"), 7).await;
    assert!(
        result.is_err(),
        "revoke against a dead node should error gracefully"
    );
    assert!(matches!(result, Err(ce_iam::IamError::Node(_))));
}

#[test]
fn empty_revocation_set_is_safe_offline_default() {
    // The offline default revokes nothing, so expiries are the liveness mechanism.
    let revset = RevocationSet::empty();
    assert!(revset.is_empty());
    let pred = revset.predicate();
    assert!(!pred(&[0u8; 32], 12345));
}
