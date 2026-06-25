//! Typed IAM errors.
//!
//! Every fallible public function returns these (wrapped in [`anyhow::Result`] at the binary
//! boundary). Having a typed enum lets callers distinguish "the chain was malformed" from "the
//! action was denied" from "the wrong issuer signed it" — and it makes the crate's central promise
//! easy to keep: *malformed input is an `Err`, never a panic*.

use std::fmt;

/// All the ways an IAM operation can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IamError {
    /// A policy document was structurally invalid (bad JSON, bad version, no statements).
    BadPolicy(String),
    /// A resource matcher could not be parsed or compiled.
    BadResource(String),
    /// An action string was empty or a wildcard could not be expanded against the action universe.
    BadAction(String),
    /// A policy used `Effect::Deny`, which a monotone capability cannot express.
    DenyUnsupported,
    /// A grant token / capability chain could not be decoded.
    MalformedChain(String),
    /// A principal (node id) could not be parsed.
    BadPrincipal(String),
    /// Attenuation would have broadened authority (caught before signing).
    WouldAmplify(String),
    /// Verification denied the action. Carries the human-readable reason from the verifier.
    Denied(String),
    /// An identity/key operation failed (load, sign).
    Identity(String),
    /// A network/node call failed (used by the on-chain revocation view).
    Node(String),
}

impl fmt::Display for IamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IamError::BadPolicy(m) => write!(f, "bad policy: {m}"),
            IamError::BadResource(m) => write!(f, "bad resource: {m}"),
            IamError::BadAction(m) => write!(f, "bad action: {m}"),
            IamError::DenyUnsupported => write!(
                f,
                "Effect::Deny is not expressible as a capability; model deny by not granting the action"
            ),
            IamError::MalformedChain(m) => write!(f, "malformed capability chain: {m}"),
            IamError::BadPrincipal(m) => write!(f, "bad principal: {m}"),
            IamError::WouldAmplify(m) => write!(f, "attenuation would amplify authority: {m}"),
            IamError::Denied(m) => write!(f, "denied: {m}"),
            IamError::Identity(m) => write!(f, "identity error: {m}"),
            IamError::Node(m) => write!(f, "node error: {m}"),
        }
    }
}

impl std::error::Error for IamError {}
