# The merge — one identity + access + secrets system, rooted in ce-iam

Directive (Leif, 2026-06-26): don't create a new system — **merge what we have** into one, clean it up,
document it, test it, lock it. Build its **Rust core + ports + CLI + API + SDKs (Rust + TypeScript)**.

## What we have (mapped, no overlap — they're layers)

| crate | loc | role | verdict |
| --- | --- | --- | --- |
| `ce-identity` | ~150 (rust) | Ed25519 keys; a principal IS a node id | **primitive — stays** (ce-iam wraps it) |
| `ce-cap` | ~840 (rust) | signed, attenuating capability chains; `authorize()` | **primitive — stays** (ce-iam wraps it) |
| `ce-iam` | 5.9k (rust) | mint / attenuate / verify; policy + role catalog; wallet; roots; revocation | **CANONICAL CORE** |
| `ce-auth` | 2.0k (rust) | device enrollment (TOFU→request→approve) + P-256↔NodeId **bridge** + mesh/HTTP daemon | **folds INTO ce-iam** (lib); thin daemon stays |
| `ce-secrets` | 875 (js) | the vault: derive/seal/wrap secrets, multi-device, challenge-response | **the SECRETS layer** (port core to rust; keep JS as a port) |
| `ce-secrets-rs` | 920 (rust) | read-only Rust interop for the JS vault | **the start of the rust vault** (grow it to full) |

Key facts from the audit: `ce-auth` already *depends on* `ce-iam` (calls `Iam::mint`) — folding it in
removes a repo, not functionality. `ce-secrets` is orthogonal to authority (symmetric vault), used BY
`ce-auth` for device keys. `ce-cap`/`ce-identity` are tiny, stable, zero-dep — they must stay primitives.

## The merged shape — TWO crates (small core + big IAM), one workspace

Split into a **small** crate (basic auth, what most apps need) and a **big** crate (full IAM on top).
The ce-iam repo becomes a workspace with both.

```
crates/ce-iam-core/   SMALL / lightweight — "basic auth". Minimal deps, fast compile. Most apps use THIS.
  identity         re-export ce-identity (keys, NodeId, sign/verify)
  cap (verify)     re-export ce-cap (Capability, Caveats, Resource, authorize) — VERIFY only
  device.rs        <- ce-auth/store.rs  (DeviceStore: TOFU/request/approve, admin vs pending)
  secrets/         <- ce-secrets-rs grown to the full vault (derive/seal/wrap/recover), golden-vectored
  -> what you need to: verify a capability, hold/recover secrets, enroll your devices. No policy engine.

crates/ce-iam/        BIG / full IAM. depends on + re-exports ce-iam-core, ADDS the heavy machinery:
  grant.rs         mint / attenuate (issuing authority)
  policy.rs roles  AWS-IAM policies, roles, statements, conditions
  catalog.rs       durable role/policy op-log + audit
  wallet.rs roots.rs revocation.rs   held grants; accepted roots; on-chain revocation
  bridge.rs        <- ce-auth/bridge.rs  (device -> cap MINTING; needs the issuing core, so it lives here)
  bin/ce-iam       the unified CLI: device/secret (from core) + grant/verify/role/wallet/root (from big)

daemon (ce-auth)    thin mesh + HTTP console over the two crates.
ports/
  ce-iam-core-wasm/ wasm-bindgen port of the SMALL crate (secrets + cap verify) — what ce-cast/browsers use
  ce-iam-ts/        TS SDK over the wasm (drop-in for ce-cast's vault; crypto.mjs is the JS reference)
```

Rule: **`device` + `secrets` + cap-VERIFY live in `ce-iam-core`; minting/policy/roles live in `ce-iam`.**
An app that only verifies caps + holds secrets depends on the small crate and never compiles the IAM.

## Unified public API (the surface to preserve)

- **Identity**: `Identity`, `NodeId`, `verify` (from ce-identity).
- **Capabilities**: `Iam::{mint, attenuate, verify, inspect, revoke}`, `Policy/Role/Statement`, `Caveats/Resource/SignedCapability` (ce-cap).
- **Devices**: `DeviceStore`, `Device`, enrollment verbs (claim/request/approve/revoke), `CapBridge` (device→cap).
- **Secrets**: `Vault::{open, recover, put, get, list, grant}` — owner-derived master, ECIES-wrapped per device.
- **Stores**: catalog (roles/policies), wallet (held grants), roots (accepted keys), one durable mesh/ce-coord backend.

## Phases (each compiles + tests green before the next; build on the relay/Debian, NOT the laptop)

1. **Fold `ce-auth` → `ce-iam` lib**: move `bridge.rs` + `store.rs` (DeviceStore) into `ce-iam` as
   `bridge`/`device` modules; re-export; turn the `ce-auth` binary into a thin daemon over `ce-iam`.
   No behavior change; all ce-auth verbs preserved. **(START HERE.)**
2. **Rust vault**: grow `ce-secrets-rs` into the full vault (derive/seal/wrap + recover) as `ce-iam::secrets`,
   golden-vectored byte-for-byte against `ce-secrets/src/crypto.mjs` (the 5 interop traps). CI gate.
3. **Unified CLI**: merge the `ce-iam` + `ce-secrets` + `ce-auth` CLIs into one `ce-iam` binary
   (grant/verify/role/wallet/root + device + secret). Deprecate the separate CLIs.
4. **Ports + SDKs**: `ce-iam-wasm` (browser) + `ce-iam-ts` (TS SDK); ce-cast's `src/vault/*` becomes a
   thin call into `ce-iam-ts`. The Rust SDK is the `ce-iam` crate itself.
5. **Lock**: tests across all verbs + golden vectors + a security checklist (signed records, default-deny,
   derived-but-wrapped master, attenuation-never-broadens); retire ce-auth/ce-secrets-rs once at parity.

## Locked invariants (must hold throughout)

- ce-cap attenuation: a child link NEVER broadens abilities/resource/caveats.
- The vault master is DERIVED from the owner key (recoverable) AND wrapped per device (others work).
- One durable, owner-pinned store (mesh ce-coord); no silent dependence on a mutable hub KV.
- Records signed by the writing device; default-deny; offline-verifiable.
- Rust core ↔ JS reference ↔ wasm port agree byte-for-byte (golden vectors in CI).

## Status

- **Phase 1 (done):** ce-auth's `device.rs` + `bridge.rs` folded into ce-iam; ce-auth is a thin daemon.
- **Phase 2 (done):** ce-iam is now a **workspace** with two members:
  - `crates/ce-iam-core` (SMALL) — `device` (DeviceStore) + cap-VERIFY/identity re-exports + the full
    **secrets vault** (`secrets::Vault<S: Store>`, ported from `vault.mjs` over `ce-secrets-rs`).
  - `crates/ce-iam` (BIG) — grant/policy/principal/catalog/wallet/roots/revocation + the `bridge`
    (minting) + the CLI; re-exports `ce-iam-core` so `ce_iam::{device,secrets,Identity,Caveats,…}`
    are unchanged for consumers (ce-auth builds green).
  - `ce-secrets-rs` grew the WRITE side (derive_owner_master, wrap_master, seal_secret, sign/verify
    record, fingerprint, DeviceKey::generate) — golden-vectored against the JS in
    `crates/ce-iam-core/tests/golden_secrets.rs` (fixtures from `fixtures/gen_secrets_vectors.mjs`).
  - Tests: 160 existing ce-iam tests + ce-iam-core unit + 9 golden-vector tests all green on the relay.
- **Phases 3–5 (pending):** unified CLI verbs for device/secret, wasm + TS ports, lock + retire.
