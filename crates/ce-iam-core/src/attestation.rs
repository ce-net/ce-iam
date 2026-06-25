//! Real-world identity attestations (Phase 1 of docs/real-world-identity.md).
//!
//! An [`Attestation`] is a provider-signed, offline-verifiable claim that a CE node (`subject`) is
//! controlled by a real-world identity the provider verified (BankID, Google/OIDC, …). It is leveled
//! (assurance) and *pseudonymous* by default — it carries a per-provider pseudonym, never the raw
//! identity — so it proves "one unique verified human at level N" without doxxing. Verified like a
//! capability: check the signature against the provider's key. Additive to ce-iam-core; depends only
//! on `ce-identity` + serde, no new crates.

use anyhow::{bail, Result};
use ce_identity::{Identity, NodeId};
use serde::{Deserialize, Serialize};

/// Assurance levels — higher = stronger real-world binding (drives the trust gradient).
pub const LEVEL_EMAIL: u8 = 0; // email/SMS OTP
pub const LEVEL_SOCIAL: u8 = 1; // Google/GitHub/OIDC account
pub const LEVEL_VERIFIED: u8 = 2; // verified org / domain / KYC-lite
pub const LEVEL_STRONG_EID: u8 = 3; // BankID and equivalent government eID

/// What the provider verified about the subject.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    /// A unique human (Sybil anchor). Uniqueness is carried by the pseudonym.
    UniqueHuman,
    /// A verified email (value = hex hash of the address; never the address itself).
    EmailVerified(String),
    /// Control of a DNS domain / host.
    DomainControl(String),
    /// Membership of a named org.
    OrgMember(String),
    /// Open extension point.
    Custom(String, String),
}

/// The signed fields. Canonical signing payload = deterministic `serde_json` of this struct
/// (fields serialize in declaration order; no maps), so issue and verify agree byte-for-byte.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AttestationBody {
    pub provider: NodeId,    // [u8;32] — serde-native
    pub subject: NodeId,
    pub claim: Claim,
    pub level: u8,
    pub pseudonym: [u8; 32], // per-provider, per-context; NOT the raw identity
    pub issued: u64,         // unix seconds
    pub expires: u64,        // unix seconds
    pub nonce: u64,          // for on-chain RevokeAttestation{provider,nonce}
}

impl AttestationBody {
    fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("AttestationBody serializes")
    }
}

/// A provider-signed attestation: body + detached Ed25519 signature (hex of [u8;64], since serde has
/// no native 64-byte-array support).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Attestation {
    #[serde(flatten)]
    pub body: AttestationBody,
    pub sig: String,
}

impl Attestation {
    /// Provider issues an attestation about `subject`. The provider signs as itself.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        provider: &Identity,
        subject: NodeId,
        claim: Claim,
        level: u8,
        pseudonym: [u8; 32],
        issued: u64,
        expires: u64,
        nonce: u64,
    ) -> Self {
        let body = AttestationBody {
            provider: provider.node_id(),
            subject,
            claim,
            level,
            pseudonym,
            issued,
            expires,
            nonce,
        };
        let sig = provider.sign(&body.signing_bytes());
        Attestation { body, sig: hex::encode(sig) }
    }

    /// Offline verify: signature is valid for the named provider, and not expired at `now`.
    /// (Revocation — on-chain `RevokeAttestation{provider,nonce}` — is checked by the caller against
    /// the chain, exactly like capability revocation.)
    pub fn verify(&self, now: u64) -> Result<()> {
        if self.body.expires != 0 && now >= self.body.expires {
            bail!("attestation expired");
        }
        let raw = hex::decode(&self.sig).map_err(|_| anyhow::anyhow!("sig not hex"))?;
        let sig: [u8; 64] = raw.try_into().map_err(|_| anyhow::anyhow!("sig wrong length"))?;
        ce_identity::verify(&self.body.provider, &self.body.signing_bytes(), &sig)
    }

    pub fn provider_hex(&self) -> String {
        hex::encode(self.body.provider)
    }
    pub fn subject_hex(&self) -> String {
        hex::encode(self.body.subject)
    }
}

/// Highest assurance level among attestations that verify and aren't expired. A first, policy-free
/// trust read (Phase 5 adds provider weighting / trust policies); 0 = unattested.
pub fn max_level(attestations: &[Attestation], now: u64) -> u8 {
    attestations
        .iter()
        .filter(|a| a.verify(now).is_ok())
        .map(|a| a.body.level)
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Identity {
        Identity::generate()
    }

    #[test]
    fn issue_then_verify_roundtrips() {
        let provider = id();
        let subject = id().node_id();
        let a = Attestation::issue(
            &provider, subject, Claim::UniqueHuman, LEVEL_STRONG_EID, [7u8; 32], 1000, 2000, 1,
        );
        assert!(a.verify(1500).is_ok(), "valid attestation should verify");
        assert_eq!(a.provider_hex(), provider.node_id_hex());
    }

    #[test]
    fn expired_is_rejected() {
        let p = id();
        let a = Attestation::issue(&p, id().node_id(), Claim::UniqueHuman, 3, [0u8; 32], 1000, 2000, 1);
        assert!(a.verify(2001).is_err(), "expired must fail");
        assert!(a.verify(0).is_ok(), "before expiry must pass");
    }

    #[test]
    fn tampered_body_breaks_signature() {
        let p = id();
        let mut a = Attestation::issue(&p, id().node_id(), Claim::UniqueHuman, 1, [0u8; 32], 0, 0, 1);
        a.body.level = 3; // forge a higher assurance level
        assert!(a.verify(1).is_err(), "tampering must invalidate the signature");
    }

    #[test]
    fn wrong_provider_key_fails() {
        let p = id();
        let mut a = Attestation::issue(&p, id().node_id(), Claim::UniqueHuman, 3, [0u8; 32], 0, 0, 1);
        a.body.provider = id().node_id(); // claim a different provider
        assert!(a.verify(1).is_err(), "signature must not verify under a different provider");
    }

    #[test]
    fn max_level_picks_strongest_valid() {
        let p = id();
        let s = id().node_id();
        let weak = Attestation::issue(&p, s, Claim::EmailVerified("h".into()), LEVEL_EMAIL, [0u8; 32], 0, 0, 1);
        let strong = Attestation::issue(&p, s, Claim::UniqueHuman, LEVEL_STRONG_EID, [1u8; 32], 0, 0, 2);
        assert_eq!(max_level(&[weak, strong], 1), LEVEL_STRONG_EID);
    }
}
