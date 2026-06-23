//! Mint → attenuate → verify → revoke, end to end, with no node required.
//!
//! Run with: `cargo run --example delegate`
//!
//! Demonstrates the killer demo from the design stub: issue `storage:read @ tag:gpu` to a friend,
//! have them re-delegate a narrower grant to a third party, verify the multi-link chain offline in
//! microseconds, reject an attempt to widen back, then revoke the root and watch all descendants die.

use ce_iam::{Conditions, Iam, Principal, ResourceMatch, RevocationSet, simple_policy};
use ce_iam::Identity;

fn tmp_identity(tag: &str) -> anyhow::Result<Identity> {
    let dir = std::env::temp_dir().join(format!("ce-iam-example-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(Identity::load_or_generate(&dir)?)
}

fn main() -> anyhow::Result<()> {
    let iam = Iam::new().with_action_universe([
        "storage:read".to_string(),
        "storage:write".to_string(),
    ]);

    let org = tmp_identity("org")?;
    let alice = tmp_identity("alice")?;
    let bob = tmp_identity("bob")?;

    // 1. org → alice: read+write on any gpu node, valid for an hour.
    let root_policy = simple_policy(
        vec!["storage:read".into(), "storage:write".into()],
        ResourceMatch::Tag("gpu".into()),
        Conditions { not_after: Some(now() + 3600), ..Default::default() },
    );
    let g1 = iam.mint(&org, Principal(alice.node_id()), &root_policy, 1).map_err(anyhow_err)?;
    println!("minted root grant for alice ({} bytes token)", g1.token.len());

    // 2. alice → bob: only read, still gpu-only.
    let narrow = simple_policy(
        vec!["storage:read".into()],
        ResourceMatch::Tag("gpu".into()),
        Conditions { not_after: Some(now() + 1800), ..Default::default() },
    );
    let g2 = iam.attenuate(&alice, &g1, Principal(bob.node_id()), &narrow, 2).map_err(anyhow_err)?;
    println!("alice delegated a narrower grant to bob (depth {})", g2.chain.len());

    let gpu = vec!["gpu".to_string()];

    // 3. Verify bob may read on a gpu node (offline, no server).
    let allowed = iam
        .verify(&org.node_id(), &gpu, now(), &Principal(bob.node_id()), "storage:read", &g2.token, &|_, _| false)
        .is_ok();
    println!("bob storage:read on gpu node -> {}", if allowed { "ALLOW" } else { "DENY" });

    // ...but not write (never delegated).
    let write = iam
        .verify(&org.node_id(), &gpu, now(), &Principal(bob.node_id()), "storage:write", &g2.token, &|_, _| false)
        .is_ok();
    println!("bob storage:write -> {}", if write { "ALLOW" } else { "DENY (correct)" });

    // 4. Bob cannot widen back to Any — attenuate refuses before signing.
    let widen = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
    match iam.attenuate(&bob, &g2, Principal(org.node_id()), &widen, 3) {
        Err(e) => println!("widening rejected as expected: {e}"),
        Ok(_) => println!("BUG: widening should have been rejected"),
    }

    // 5. Revoke the root link -> the whole subtree (including bob's grant) dies.
    let revset = RevocationSet::from_pairs([(org.node_id(), 1)]);
    let after_revoke = iam
        .verify(&org.node_id(), &gpu, now(), &Principal(bob.node_id()), "storage:read", &g2.token, &revset.predicate())
        .is_ok();
    println!("bob storage:read after root revoked -> {}", if after_revoke { "ALLOW (BUG)" } else { "DENY (correct)" });

    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn anyhow_err(e: ce_iam::IamError) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}
