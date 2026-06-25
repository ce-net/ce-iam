//! # ce-iam-core — the lightweight half of CE IAM ("basic auth")
//!
//! Most apps do not need a policy engine or the authority to MINT capabilities. They need to do three
//! things: **verify** a capability someone presents, **hold/recover secrets**, and **enroll** their own
//! devices. `ce-iam-core` is exactly that surface, with minimal dependencies and a fast compile — no
//! `ce-rs`, no `clap`, no `reqwest`, no policy/role/catalog machinery. The full IAM (mint / attenuate /
//! policy / roles / wallet / roots / revocation / the device->cap bridge / the CLI) lives in the
//! sibling [`ce-iam`](https://docs.rs/ce-iam) crate, which re-exports everything here.
//!
//! ## What lives here
//!
//! | concern        | this crate provides                                                      |
//! |----------------|--------------------------------------------------------------------------|
//! | identity       | re-export of [`ce_identity`] — [`Identity`], [`NodeId`], sign/verify     |
//! | capability VERIFY | re-export of [`ce_cap`] — [`Capability`], [`Caveats`], [`Resource`], [`authorize`] (verify-only; minting is in `ce-iam`) |
//! | device registry | [`device`] — [`DeviceStore`]: TOFU `claim`, `request`/`approve`/`revoke`, the P-256<->NodeId binding |
//! | secrets vault  | [`secrets`] — [`Vault`]: owner-derived master, ECIES-wrapped per device, sealed secrets, grants, challenge-response auth |
//!
//! The vault crypto is the byte-exact JS-interop layer from [`ce_secrets_rs`]; the operations
//! (init / recover / enroll / pair / seal / open / grant) are ported here over a pluggable async
//! [`secrets::Store`] so the same logic runs over an in-memory map (tests) or a mesh KV (production).

pub mod attestation;
pub mod device;
pub mod secrets;

// Real-world identity attestations (BankID/Google/OIDC bind a node to a verified human).
pub use attestation::{max_level, Attestation, AttestationBody, Claim};

// Device enrollment (folded in from the former ce-auth crate's store.rs).
pub use device::{Device, DeviceStore, ROLE_ADMIN, ROLE_PENDING, RevokeOutcome};

// The secrets vault: owner-derived, per-device-wrapped master + sealed secrets + grants + auth.
pub use secrets::{DeviceKey, MemStore, Store, Vault};

// Capability VERIFY + identity — re-exported so a consumer can depend on `ce-iam-core` alone to verify
// a presented capability chain and name principals. (MINTING authority lives in the `ce-iam` crate.)
pub use ce_cap::{Capability, Caveats, Resource, SignedCapability, authorize};
pub use ce_identity::{Identity, NodeId};
