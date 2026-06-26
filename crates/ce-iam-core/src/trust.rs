//! Trust model: provider registry + trust policy + scoring (Phases 5 & 6 of
//! docs/real-world-identity.md). Turns a bag of [`Attestation`]s into a number a relying party can
//! gate on — **federated, no central authority**: each verifier supplies its OWN policy (which
//! providers it trusts, at what weight + minimum level), and computes trust locally and offline.
//! Pure logic over Phase 1; no new dependencies.

use crate::attestation::Attestation;
use ce_identity::NodeId;
use serde::{Deserialize, Serialize};

/// A known attestor, as listed in the (ce-hub-hosted) provider registry (Phase 6).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Provider {
    pub key: NodeId,       // the attestor's signing key
    pub name: String,      // human label, e.g. "BankID (SE)"
    pub method: String,    // "bankid" | "google-oidc" | "oidc" | "email" | ...
    pub max_level: u8,     // strongest assurance this provider may attest
    pub operator: String,  // who runs it (for accountability; not trust)
}

/// One line of a [`TrustPolicy`]: trust attestations from `key` at `weight`, but only if they assert
/// at least `min_level`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProviderWeight {
    pub key: NodeId,
    pub weight: f64,
    pub min_level: u8,
}

/// A relying party's local trust policy. There is no global policy — the economy, an app, or a node
/// each pick their own (and can be strict or lenient independently).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TrustPolicy {
    pub providers: Vec<ProviderWeight>,
    /// Aggregate weight required to count as "trusted" for whatever this policy gates.
    pub threshold: f64,
}

impl TrustPolicy {
    pub fn new(threshold: f64) -> Self {
        TrustPolicy { providers: Vec::new(), threshold }
    }
    pub fn trust(mut self, key: NodeId, weight: f64, min_level: u8) -> Self {
        self.providers.push(ProviderWeight { key, weight, min_level });
        self
    }

    /// Trust score for `subject` from its attestations under this policy. Each trusted provider counts
    /// **at most once** (its highest qualifying attestation), so a node can't inflate trust by holding
    /// many attestations from the same provider. Only attestations that cryptographically verify, are
    /// unexpired, name this subject, and meet the provider's `min_level` count.
    pub fn score(&self, subject: &NodeId, attestations: &[Attestation], now: u64) -> f64 {
        let mut total = 0.0;
        for pw in &self.providers {
            let qualifies = attestations.iter().any(|a| {
                a.body.subject == *subject
                    && a.body.provider == pw.key
                    && a.body.level >= pw.min_level
                    && a.verify(now).is_ok()
            });
            if qualifies {
                total += pw.weight;
            }
        }
        total
    }

    pub fn is_trusted(&self, subject: &NodeId, attestations: &[Attestation], now: u64) -> bool {
        self.score(subject, attestations, now) >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{Attestation, Claim, LEVEL_SOCIAL, LEVEL_STRONG_EID};
    use ce_identity::Identity;

    fn id(seed: u8) -> Identity {
        Identity::from_secret_bytes(&[seed; 32])
    }

    #[test]
    fn bankid_attested_node_is_trusted_unattested_is_not() {
        let bankid = id(1);
        let google = id(2);
        let alice = id(10).node_id();
        // economy policy: BankID alone is enough (1.0); Google is partial (0.4); need >= 1.0
        let policy = TrustPolicy::new(1.0)
            .trust(bankid.node_id(), 1.0, LEVEL_STRONG_EID)
            .trust(google.node_id(), 0.4, LEVEL_SOCIAL);

        // unattested -> 0, not trusted
        assert_eq!(policy.score(&alice, &[], 100), 0.0);
        assert!(!policy.is_trusted(&alice, &[], 100));

        // a BankID attestation -> trusted
        let att = Attestation::issue(&bankid, alice, Claim::UniqueHuman, LEVEL_STRONG_EID, [1; 32], 0, 1000, 1);
        assert_eq!(policy.score(&alice, std::slice::from_ref(&att), 100), 1.0);
        assert!(policy.is_trusted(&alice, &[att], 100));
    }

    #[test]
    fn untrusted_provider_and_low_level_dont_count() {
        let real = id(1);
        let rogue = id(3); // not in the policy
        let alice = id(10).node_id();
        let policy = TrustPolicy::new(1.0).trust(real.node_id(), 1.0, LEVEL_STRONG_EID);

        // attestation from a provider not in the policy -> ignored
        let rogue_att = Attestation::issue(&rogue, alice, Claim::UniqueHuman, LEVEL_STRONG_EID, [0; 32], 0, 1000, 1);
        assert_eq!(policy.score(&alice, &[rogue_att], 100), 0.0);

        // attestation from a trusted provider but BELOW its required level -> ignored
        let weak = Attestation::issue(&real, alice, Claim::UniqueHuman, LEVEL_SOCIAL, [0; 32], 0, 1000, 2);
        assert_eq!(policy.score(&alice, &[weak], 100), 0.0);
    }

    #[test]
    fn expired_attestation_loses_trust() {
        let bankid = id(1);
        let alice = id(10).node_id();
        let policy = TrustPolicy::new(1.0).trust(bankid.node_id(), 1.0, LEVEL_STRONG_EID);
        let att = Attestation::issue(&bankid, alice, Claim::UniqueHuman, LEVEL_STRONG_EID, [0; 32], 0, 500, 1);
        assert!(policy.is_trusted(&alice, std::slice::from_ref(&att), 100), "valid before expiry");
        assert!(!policy.is_trusted(&alice, &[att], 600), "trust lapses after expiry");
    }

    #[test]
    fn same_provider_counts_once_no_inflation() {
        let bankid = id(1);
        let alice = id(10).node_id();
        let policy = TrustPolicy::new(2.5).trust(bankid.node_id(), 1.0, LEVEL_STRONG_EID);
        // three attestations from the SAME provider must not sum to 3.0
        let a1 = Attestation::issue(&bankid, alice, Claim::UniqueHuman, LEVEL_STRONG_EID, [1; 32], 0, 1000, 1);
        let a2 = Attestation::issue(&bankid, alice, Claim::UniqueHuman, LEVEL_STRONG_EID, [2; 32], 0, 1000, 2);
        let a3 = Attestation::issue(&bankid, alice, Claim::UniqueHuman, LEVEL_STRONG_EID, [3; 32], 0, 1000, 3);
        assert_eq!(policy.score(&alice, &[a1, a2, a3], 100), 1.0, "one provider counts once");
    }

    #[test]
    fn federation_two_providers_sum() {
        let bankid = id(1);
        let google = id(2);
        let alice = id(10).node_id();
        // need 1.2; neither alone suffices, together they do
        let policy = TrustPolicy::new(1.2)
            .trust(bankid.node_id(), 1.0, LEVEL_STRONG_EID)
            .trust(google.node_id(), 0.4, LEVEL_SOCIAL);
        let b = Attestation::issue(&bankid, alice, Claim::UniqueHuman, LEVEL_STRONG_EID, [0; 32], 0, 1000, 1);
        let g = Attestation::issue(&google, alice, Claim::UniqueHuman, LEVEL_SOCIAL, [0; 32], 0, 1000, 2);
        assert!(!policy.is_trusted(&alice, std::slice::from_ref(&b), 100));
        assert_eq!(policy.score(&alice, &[b, g], 100), 1.4);
    }
}
