# ce-iam security model

ce-iam is the merged identity + access + secrets system: **capabilities** (mint/attenuate/verify over
`ce-cap`), **device enrollment** (the P-256 device ↔ Ed25519 NodeId bridge), and the **secrets vault**
(owner-derived, per-device-wrapped master). This document states the trust model each layer relies on,
what an operator must configure to be safe, and the known boundaries. It is honest about what is
*enforced by the code* versus what depends on operator configuration or is deferred.

## The Phase-5 security checklist (the locked invariants)

| invariant | enforced where | status |
|---|---|---|
| **Attenuation never broadens** — a child cap link's abilities ⊆, resource ⊆, caveats ⊇ the parent. | `ce_cap::authorize`, exercised by `Iam::verify`; property-tested in `tests/prop_attenuation.rs` (depths 2–3, randomized). | **Enforced.** |
| **Master derived-but-wrapped** — the vault master is HKDF-derived from the owner's ECDH scalar (recoverable by the owner alone) AND ECIES-wrapped per enrolled device (readable without re-deriving). | `secrets::Vault::{recover, enroll, load_master}`; golden-vectored against `crypto.mjs`. | **Enforced.** |
| **Default-deny** — no enrollment ⇒ no master ⇒ no read and no grant issuance; an unknown principal/action is `Err`, never a panic. | `Vault::{load_master, get_secret, issue_grant}`; `Iam::verify`. Tested: `unenrolled_device_cannot_read_or_grant`, `verify_malformed_token_exits_nonzero_no_panic`. | **Enforced.** |
| **Records signed by the writer** — every device/secret/grant record carries an ECDSA signature over the canonical body; the signer's enrolled key is checked on verify. | `secrets::Vault` (`sign_record` on write; `verify_record` + enrolled-key match on `verify_grant`/`verify_auth`). Tested: `tampered_record_signature_is_detectable`. | **Enforced for verify paths.** See boundary below: the *store itself* is not write-authenticated. |
| **One durable owner-pinned store** — the vault is generic over an async `Store`; production points it at a single mesh KV (`MeshKvStore` / ce-kv) keyed by the owner namespace, not a mutable hub KV. | `secrets::Store` trait; `ce_iam::MeshKvStore`. | **Mechanism enforced; the operator must point it at the durable backend** (the CLI defaults to the mesh ce-kv node). |
| **Offline verify** — a presented capability or vault grant is checked with no policy server; the token *is* the proof. | `Iam::verify` (offline but for revocation), `Vault::{verify_grant, verify_auth}`. | **Enforced** (revocation freshness is the one online input — see below). |

## What a capability is

## What a capability is

A grant is a signed, attenuating capability chain (`ce-cap`). The token *is* the proof: a verifier
checks it offline, with no policy server. Authority can only ever **narrow** down a delegation chain
— the central invariant, property-tested in `tests/prop_attenuation.rs`.

## The verifier's trust model

`Iam::verify(self_id, accepted_roots, self_tags, now, requester, action, token, is_revoked)` returns
`Ok(())` only if **all** of the following hold (delegated to `ce_cap::authorize`):

1. **Roots.** `chain[0].issuer` is `self_id` *or* a configured accepted root. A node always trusts
   its own key; extra org roots are configured explicitly. **A verifier that accepts the wrong root
   set is the primary way to be unsafe** — only add roots you actually trust to issue authority over
   your resources.
2. **Signatures.** Every link's signature verifies against its issuer.
3. **Temporal + revocation.** Every link is within `[not_before, not_after]` at `now` and not
   revoked (`is_revoked(issuer, nonce)`).
4. **Resource.** Every link's resource matches this node `(self_id, self_tags)`.
5. **Continuity + attenuation.** Each non-root link is issued by its parent's audience, names the
   parent by hash, and is no broader (abilities ⊆, resource ⊆, caveats ⊇).
6. **Leaf.** The leaf is held by `requester` and grants `action`.

A verifier MUST pass a correct `now` (real unix time) and a faithful `is_revoked` predicate. Passing
`now = 0` or an empty revocation set disables those checks.

## Operating revocation freshness

Revocation is on-chain (`RevokeCapability` keyed by `(issuer, nonce)`); revoking any link kills its
subtree. Between fetches, a verifier works from a snapshot. The CLI offers three stances:

- **Default (fetch + fail-open).** `verify` fetches the live set; if the node is unreachable it falls
  back to the last-known-good cached snapshot (`<data_dir>/iam/revocation-cache.json`) and warns.
  Favors availability; rely on **short capability expiries** for safety.
- **`--fail-closed`.** If the live fetch fails and the cached snapshot is **stale** (older than
  `--revocation-ttl`, default 300s), verification is **denied**. Favors safety over availability.
- **`--no-revocation-check`.** Skip revocation entirely; rely only on expiries. Use only when you
  understand the tradeoff.

Recommendation: short expiries everywhere, plus `--fail-closed` with a TTL appropriate to your
tolerance for stale revocation on high-value actions.

## Root rotation

To rotate an org root without flag-day downtime:

1. `root add <new-key> --valid-in 0` (and keep the old root accepted) — both are honored during the
   overlap window.
2. `root reissue <token> --nonce N` for each live root grant — re-signs an equivalent grant under the
   new key. Distribute the reissued tokens.
3. `root retire <old-key>` (sets its `not_after`) once every holder is migrated — old grants stop
   verifying after that time.

Validity windows are enforced by `Roots::accepted_at(now)`; feed it to the verifier (`--use-roots`).

## The secrets vault trust model

The vault (`ce-iam-core::secrets`) is a symmetric secret store, orthogonal to capability authority.
A verifier/operator relies on:

1. **Master secrecy.** The 32-byte vault master encrypts every secret (AES-256-GCM). It is HKDF-derived
   from the OWNER device's ECDH private scalar (salt `ce-vault:<ns>`, info `master-v1`), so the owner
   can re-establish the vault from its key alone after a total store wipe (`recover`, tested by
   `full_roundtrip_enroll_put_recover_read`). It is also ECIES-wrapped to each enrolled device's ECDH
   public key, so other devices read without re-deriving. **An attacker who obtains the owner's ECDH
   private key obtains the master and every secret** — the owner key is the root of this layer; protect
   it exactly as the CE node key.
2. **Enrollment is the gate.** Reading a secret or issuing a grant requires a `d.<id>` enrollment
   record this device can unwrap. A device that never enrolled has no master and is denied (default-
   deny). Pairing is owner-mediated: a new device publishes a request, an *already-enrolled* device
   approves it by wrapping the master to the newcomer's key.
3. **Revocation = de-enrollment.** `revoke_device` deletes the `d.<id>` record; the revoked device can
   no longer load the master (tested by `revoked_device_loses_access`). The vault refuses to revoke the
   device you are using (anti-lockout). **Caveat (honest):** revocation does not re-key the master, so a
   device that already cached the master before revocation retains whatever it copied. Rotate
   high-value secrets after revoking a device; full master rotation is deferred (see boundaries).
4. **Record integrity.** Device, secret, and grant records are ECDSA-signed by the writing device, and
   the signer's key is checked against its enrolled record on `verify_grant`/`verify_auth` (tested by
   `tampered_record_signature_is_detectable`). This makes tampering *detectable on the verify paths*.
5. **Grant scope.** A vault grant (`issue_grant`) authorizes `read:<name>` (or `read:*`) for one
   audience with an optional expiry; `verify_grant` requires the issuer be an enrolled device, the grant
   not deleted (revoked), not expired, audience-matched, and ability-matched. Only an enrolled device
   may issue.

## DoS resistance

A service that calls `verify` on remote-supplied tokens is exposed to malicious input. ce-iam bounds
it: tokens over `max_token_bytes` (default 256 KiB) are rejected before decoding, chains over
`max_chain_depth` (default 64) before per-link work. On-disk stores reject files over 64 MiB and cap
roles/policies/wallet entries/roots; the in-memory audit trail is a bounded ring. Malformed input is
always an `Err`, never a panic (property-tested).

## Boundaries (intentional, documented)

- **No `Deny` / boundary policies / SCPs.** Capabilities are monotone grants; "deny" = not granting.
- **No group/principal-set abstraction.** Roles attach per-principal.
- **Catalog replication is single-node.** The durable op-log is real; mesh broadcast / multi-node
  convergence is deferred (see README). Treat the catalog as authoritative only on its writer node.
- **Condition keys are the closed caveat set.** No source-IP / MFA / arbitrary CEL operators.
- **The vault store is not write-authenticated by the store itself.** Integrity comes from per-record
  signatures verified on the *verify* paths, not from the KV refusing unauthorized writes. A malicious
  store can delete or roll back records (a DoS / availability attack), and on read paths that do not
  re-verify the writer signature (e.g. `get_secret` trusts the sealed body decrypts under the master) it
  relies on the AEAD tag, not a record signature. Point the vault at a store you trust for availability;
  treat record signatures as tamper-*evidence*, not write-prevention.
- **No master re-keying on device revocation.** De-enrollment removes future access; it does not rotate
  the master, so rotate sensitive secrets after revoking a device. Master rotation + re-wrap is deferred.
- **Vault grant revocation is single-store.** `verify_grant` treats a deleted `g.<id>` record as revoked;
  there is no on-chain vault-grant revocation list. Use short grant expiries.
- **The P-256 ↔ NodeId bridge binds at enroll time.** A device with no registered NodeId can authenticate
  (proof of possession) but cannot be minted a capability (no principal). The binding is asserted by the
  enrolling admin, not independently proven; trust your admins.

## Reporting

Email security concerns to ledamecrydenfalk@gmail.com.
