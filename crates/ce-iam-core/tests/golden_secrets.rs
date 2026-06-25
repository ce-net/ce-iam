//! GOLDEN-VECTOR GATE — the Rust secrets vault must agree byte-for-byte with the canonical JS vault.
//!
//! `fixtures/secrets_vectors.json` is produced by `fixtures/gen_secrets_vectors.mjs`, which drives the
//! REAL `ce-secrets/src/{crypto,vault}.mjs` over a fixed owner device key and a fixed clock. This test
//! reproduces (deterministic ops) or verifies (randomized ops) every vector with the Rust port:
//!
//!   * device id derivation                        — recompute, equal.
//!   * deriveOwnerMaster                            — recompute, equal to `master.hex`.
//!   * the enrollment record's wrappedMaster        — UNWRAP to the same master.
//!   * the enrollment + secret record signatures    — VERIFY; and the signRecord canonical string the
//!                                                     JS hashed equals our `stable_stringify_record`.
//!   * the sealed secret                            — OPEN to the same plaintext; fingerprint matches.
//!   * the signed challenge                         — VERIFY against the enrolled device.
//!   * the issued grant token                       — VERIFY (issuer enrolled, scope, audience).
//!
//! This pins all five interop traps end-to-end through the vault layer (empty-salt HKDF, 12-byte GCM
//! nonce, raw P1363 ECDSA, base64url-no-pad, canonical JSON — plus the signRecord allowlist quirk).

use ce_iam_core::secrets::{DeviceKey, MemStore, Store, Vault};
use ce_secrets_rs::{
    decrypt_secret, derive_owner_master, device_id, fingerprint, stable_stringify_record,
    unwrap_master, verify_record, Jwk, SealedSecret, WrapBlob,
};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/secrets_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("parse secrets_vectors.json")
}

fn owner_key(v: &Value) -> DeviceKey {
    serde_json::from_value(v["owner"].clone()).expect("load owner device key")
}

#[test]
fn device_id_matches_js() {
    let v = vectors();
    let dk = owner_key(&v);
    assert_eq!(dk.id, v["deviceId"].as_str().unwrap());
    // Recompute from the public coordinates independently.
    assert_eq!(
        device_id(&dk.ecdh_pub, &dk.ecdsa_pub).unwrap(),
        v["deviceId"].as_str().unwrap()
    );
}

#[test]
fn derive_owner_master_matches_js() {
    let v = vectors();
    let dk = owner_key(&v);
    let ns = v["ns"].as_str().unwrap();
    let master = derive_owner_master(&dk.ecdh_priv, ns).unwrap();
    assert_eq!(
        ce_secrets_rs::encoding::hex_encode(&master),
        v["master"]["hex"].as_str().unwrap(),
        "deriveOwnerMaster must be byte-identical to the JS vault"
    );
}

#[test]
fn enrollment_wrapped_master_unwraps_to_the_same_master() {
    let v = vectors();
    let dk = owner_key(&v);
    let rec = &v["enrollment"]["record"];
    let wrapped: WrapBlob = serde_json::from_value(rec["wrappedMaster"].clone()).unwrap();
    let master = unwrap_master(&dk.ecdh_priv, &wrapped).unwrap();
    assert_eq!(
        ce_secrets_rs::encoding::hex_encode(&master),
        v["enrollment"]["expectUnwrapMasterHex"].as_str().unwrap()
    );
}

#[test]
fn enrollment_record_canonical_and_signature_match_js() {
    let v = vectors();
    let dk = owner_key(&v);
    let rec = v["enrollment"]["record"].as_object().unwrap();
    // Rebuild the signed body = record minus `sig`.
    let mut body = rec.clone();
    let sig = body.remove("sig").unwrap();
    let body = Value::Object(body);
    // The canonical string we hash must equal the one the JS vault hashed.
    assert_eq!(
        stable_stringify_record(&body).unwrap(),
        v["enrollment"]["signedCanonical"].as_str().unwrap(),
        "signRecord canonicalization must match JS (nested objects collapse to the top-level allowlist)"
    );
    // And the JS-produced signature must verify under our verifier.
    assert!(
        verify_record(&dk.ecdsa_pub, &body, sig.as_str().unwrap()).unwrap(),
        "the JS-signed enrollment record must verify in Rust"
    );
}

#[test]
fn sealed_secret_opens_to_the_same_plaintext() {
    let v = vectors();
    let dk = owner_key(&v);
    let ns = v["ns"].as_str().unwrap();
    let master = derive_owner_master(&dk.ecdh_priv, ns).unwrap();
    let sealed: SealedSecret =
        serde_json::from_value(v["secretSealed"]["sealed"].clone()).unwrap();
    let pt = decrypt_secret(&master, &sealed).unwrap();
    assert_eq!(
        String::from_utf8(pt).unwrap(),
        v["secretSealed"]["expectOpenPlaintext"].as_str().unwrap()
    );
}

#[test]
fn secret_record_canonical_signature_and_fingerprint_match_js() {
    let v = vectors();
    let dk = owner_key(&v);
    let rec = v["secretRecord"]["record"].as_object().unwrap();
    let mut body = rec.clone();
    let sig = body.remove("sig").unwrap();
    let body = Value::Object(body);
    assert_eq!(
        stable_stringify_record(&body).unwrap(),
        v["secretRecord"]["signedCanonical"].as_str().unwrap()
    );
    assert!(verify_record(&dk.ecdsa_pub, &body, sig.as_str().unwrap()).unwrap());
    // Fingerprint of the plaintext.
    let pt = v["secretSealed"]["plaintext"].as_str().unwrap();
    assert_eq!(
        fingerprint(pt.as_bytes()),
        v["secretRecord"]["expectFp"].as_str().unwrap()
    );
}

#[test]
fn challenge_proof_verifies_against_enrolled_device() {
    let v = vectors();
    let proof = &v["challenge"]["proof"];
    let jwk: Jwk = serde_json::from_value(proof["ecdsaPub"].clone()).unwrap();
    // Direct crypto-level verify (the auth primitive).
    assert!(
        ce_secrets_rs::verify_auth(
            &jwk,
            proof["aud"].as_str().unwrap(),
            proof["deviceId"].as_str().unwrap(),
            proof["nonce"].as_str().unwrap(),
            proof["ts"].as_str().unwrap(),
            proof["sig"].as_str().unwrap(),
        )
        .unwrap()
    );
}

#[tokio::test]
async fn vault_verify_auth_accepts_the_js_challenge() {
    // End-to-end through the Vault: seed a store with the JS enrollment record, then verify the
    // JS-signed challenge proof through `Vault::verify_auth`.
    let v = vectors();
    let dk = owner_key(&v);
    let store = MemStore::new();
    store
        .put(
            v["enrollment"]["key"].as_str().unwrap(),
            v["enrollment"]["record"].clone(),
        )
        .await
        .unwrap();
    let vault = Vault::new(store, dk, v["ns"].as_str().unwrap());
    let who = vault
        .verify_auth(
            v["challenge"]["aud"].as_str().unwrap(),
            v["challenge"]["nonce"].as_str().unwrap(),
            &v["challenge"]["proof"],
        )
        .await
        .unwrap();
    assert_eq!(who, v["deviceId"].as_str().unwrap());
}

#[tokio::test]
async fn vault_verify_grant_accepts_the_js_grant_token() {
    // Seed the store with the enrollment record (so the issuer is "enrolled") and the grant record
    // (so it is not "revoked"), then verify the JS-issued grant token through `Vault::verify_grant`.
    let v = vectors();
    let dk = owner_key(&v);
    let store = MemStore::new();
    store
        .put(
            v["enrollment"]["key"].as_str().unwrap(),
            v["enrollment"]["record"].clone(),
        )
        .await
        .unwrap();
    let grant_rec = &v["grant"]["record"];
    let grant_id = grant_rec["id"].as_str().unwrap();
    store
        .put(&format!("g.{grant_id}"), grant_rec.clone())
        .await
        .unwrap();
    let vault = Vault::new(store, dk, v["ns"].as_str().unwrap());
    vault
        .verify_grant(
            v["grant"]["token"].as_str().unwrap(),
            v["grant"]["audience"].as_str().unwrap(),
            v["grant"]["action"].as_str().unwrap(),
            v["grant"]["name"].as_str().unwrap(),
            0, // now_ms = 0; the JS grant has no expiry
        )
        .await
        .expect("the JS-issued grant token must verify in Rust");
}
