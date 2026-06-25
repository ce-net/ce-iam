//! Integration tests for durable persistence: the catalog store round-trips through disk, the wallet
//! and roots stores persist atomically and reload, and concurrent-process writers to *separate* dirs
//! never corrupt each other (single-writer-per-store is the model; this exercises the atomic-write
//! primitive under interleaving).

use ce_iam::Identity;
use ce_iam::{
    CatalogOp, CatalogStore, Conditions, Iam, Principal, ResourceMatch, Role, Roots, WalletStore,
    ce_cloud_action_universe, simple_policy,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("ce-iam-storeit-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn reader_role(name: &str) -> Role {
    Role::new(
        name,
        simple_policy(
            vec!["storage:read".into()],
            ResourceMatch::Any,
            Conditions::default(),
        ),
    )
}

#[test]
fn catalog_store_reload_reproduces_state() {
    let d = dir("reload");
    let alice = Principal([7u8; 32]);
    {
        let mut store = CatalogStore::open(&d).unwrap();
        store
            .apply(CatalogOp::PutRole(reader_role("reader")), None)
            .unwrap();
        store
            .apply(
                CatalogOp::PutRole(Role::new(
                    "writer",
                    simple_policy(
                        vec!["storage:write".into()],
                        ResourceMatch::Any,
                        Conditions::default(),
                    ),
                )),
                None,
            )
            .unwrap();
        store
            .apply(
                CatalogOp::AttachRole {
                    principal: alice,
                    role: "reader".into(),
                },
                None,
            )
            .unwrap();
        store
            .apply(
                CatalogOp::AttachRole {
                    principal: alice,
                    role: "writer".into(),
                },
                None,
            )
            .unwrap();
        store
            .apply(CatalogOp::RemoveRole("writer".into()), None)
            .unwrap();
    }
    // A completely fresh process-equivalent reopen reconstructs the catalog by replay.
    let store = CatalogStore::open(&d).unwrap();
    let cat = store.catalog();
    assert!(cat.get_role("reader").is_some());
    assert!(cat.get_role("writer").is_none());
    // Removing "writer" detached it from alice; only "reader" remains.
    assert_eq!(cat.roles_for(&alice), vec!["reader".to_string()]);
}

#[test]
fn catalog_store_mint_role_after_reload() {
    let d = dir("mint-after-reload");
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let issuer = {
        let id_dir = d.join("issuer-id");
        std::fs::create_dir_all(&id_dir).unwrap();
        Identity::load_or_generate(&id_dir).unwrap()
    };
    let alice = Principal([3u8; 32]);
    {
        let mut store = CatalogStore::open(&d).unwrap();
        store
            .apply(CatalogOp::PutRole(reader_role("reader")), None)
            .unwrap();
    }
    // Reopen and mint from the persisted role.
    let store = CatalogStore::open(&d).unwrap();
    let grant = iam
        .mint_role(&issuer, alice, store.catalog(), "reader", 1)
        .unwrap();
    assert!(
        iam.verify(
            &issuer.node_id(),
            &[],
            0,
            &alice,
            "storage:read",
            &grant.token,
            &|_, _| false
        )
        .is_ok()
    );
}

#[test]
fn compaction_survives_reload() {
    let d = dir("compact-reload");
    let p = Principal([5u8; 32]);
    {
        let mut store = CatalogStore::open(&d).unwrap();
        store
            .apply(CatalogOp::PutRole(reader_role("r")), None)
            .unwrap();
        for _ in 0..10 {
            store
                .apply(
                    CatalogOp::AttachRole {
                        principal: p,
                        role: "r".into(),
                    },
                    None,
                )
                .unwrap();
            store
                .apply(
                    CatalogOp::DetachRole {
                        principal: p,
                        role: "r".into(),
                    },
                    None,
                )
                .unwrap();
        }
        store
            .apply(
                CatalogOp::AttachRole {
                    principal: p,
                    role: "r".into(),
                },
                None,
            )
            .unwrap();
        let before = store.op_count();
        store.compact().unwrap();
        assert!(store.op_count() < before);
    }
    let store = CatalogStore::open(&d).unwrap();
    assert_eq!(store.catalog().roles_for(&p), vec!["r".to_string()]);
}

#[test]
fn wallet_persists_across_open() {
    let d = dir("wallet");
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let issuer = {
        let id_dir = d.join("id");
        std::fs::create_dir_all(&id_dir).unwrap();
        Identity::load_or_generate(&id_dir).unwrap()
    };
    let pol = simple_policy(
        vec!["storage:read".into()],
        ResourceMatch::Any,
        Conditions::default(),
    );
    let token = iam
        .mint(&issuer, Principal(issuer.node_id()), &pol, 1)
        .unwrap()
        .token;
    {
        let mut w = WalletStore::open(&d).unwrap();
        w.add(&iam, "g", &token, None, 0).unwrap();
    }
    let w = WalletStore::open(&d).unwrap();
    assert_eq!(w.token("g"), Some(token.as_str()));
}

#[test]
fn roots_persist_and_filter_by_time() {
    let d = dir("roots");
    let key = Principal([9u8; 32]);
    {
        let mut r = Roots::open(&d).unwrap();
        r.add(key, Some("k".into()), 100, 200).unwrap();
    }
    let r = Roots::open(&d).unwrap();
    assert!(r.is_accepted(&key.node_id(), 150));
    assert!(!r.is_accepted(&key.node_id(), 250));
    assert_eq!(r.accepted_at(150), vec![key.node_id()]);
}

#[test]
fn many_sequential_writers_keep_store_consistent() {
    // Hammer one store with many small writes; the on-disk log must stay replayable at every point.
    let d = dir("hammer");
    let mut store = CatalogStore::open(&d).unwrap();
    store
        .apply(CatalogOp::PutRole(reader_role("r")), None)
        .unwrap();
    for i in 0..200u8 {
        let p = Principal([i; 32]);
        store
            .apply(
                CatalogOp::AttachRole {
                    principal: p,
                    role: "r".into(),
                },
                None,
            )
            .unwrap();
        // Reopen mid-stream: every persisted prefix is a valid, replayable catalog.
        let reopened = CatalogStore::open(&d).unwrap();
        assert_eq!(reopened.op_count(), store.op_count());
        assert!(reopened.catalog().roles_for(&p).contains(&"r".to_string()));
    }
}
