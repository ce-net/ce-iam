//! The managed product surface end-to-end: a durable role catalog, a wallet of held grants, and a
//! root-rotation migration — all with no node required.
//!
//! Run with: `cargo run --example managed`

use ce_iam::Identity;
use ce_iam::{
    CatalogOp, CatalogStore, Conditions, Iam, Principal, ResourceMatch, Role, Roots, WalletStore,
    ce_cloud_action_universe, simple_policy,
};

fn tmp_identity(tag: &str) -> anyhow::Result<Identity> {
    let dir = std::env::temp_dir().join(format!("ce-iam-managed-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Identity::load_or_generate(&dir)
}

fn main() -> anyhow::Result<()> {
    let work = std::env::temp_dir().join(format!("ce-iam-managed-data-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;

    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let org = tmp_identity("org")?;
    let alice = Principal(tmp_identity("alice")?.node_id());

    // 1. A durable catalog: define a role, attach it, persist to disk.
    let mut catalog = CatalogStore::open(&work).map_err(anyhow_err)?;
    let reader = Role::new(
        "storage-reader",
        simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Any,
            Conditions::default(),
        ),
    );
    catalog
        .apply(CatalogOp::PutRole(reader), None)
        .map_err(anyhow_err)?;
    catalog
        .apply(
            CatalogOp::AttachRole {
                principal: alice,
                role: "storage-reader".into(),
            },
            None,
        )
        .map_err(anyhow_err)?;
    let eff = catalog
        .catalog()
        .effective_grants(&alice)
        .map_err(anyhow_err)?;
    println!("alice's effective grants: {} group(s)", eff.len());

    // 2. Mint a grant from the catalog role and stash it in a wallet.
    let grant = iam
        .mint_role(&org, alice, catalog.catalog(), "storage-reader", 1)
        .map_err(anyhow_err)?;
    let mut wallet = WalletStore::open(&work).map_err(anyhow_err)?;
    wallet
        .add(
            &iam,
            "from-org",
            &grant.token,
            Some("storage reader".into()),
            0,
        )
        .map_err(anyhow_err)?;
    println!("wallet now holds {} grant(s)", wallet.len());

    // 3. Root rotation: a new org root re-issues alice's grant under its key.
    let new_org = tmp_identity("new-org")?;
    let reissued = iam.reissue_under(&new_org, &grant, 2).map_err(anyhow_err)?;
    let mut roots = Roots::open(&work).map_err(anyhow_err)?;
    roots
        .add(Principal(new_org.node_id()), Some("org-2026".into()), 0, 0)
        .map_err(anyhow_err)?;

    // A node that accepts the new root honors the re-issued grant.
    let node = tmp_identity("node")?;
    let iam_roots = iam.clone().with_accepted_roots(roots.accepted_at(0));
    let ok = iam_roots
        .verify(
            &node.node_id(),
            &[],
            0,
            &alice,
            "storage:read",
            &reissued.token,
            &|_, _| false,
        )
        .is_ok();
    println!(
        "reissued grant verifies under the new root -> {}",
        if ok { "ALLOW" } else { "DENY (bug)" }
    );

    Ok(())
}

fn anyhow_err(e: ce_iam::IamError) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}
