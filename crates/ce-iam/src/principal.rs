//! Principals — the "who" of IAM, always a CE node identity.
//!
//! In AWS, a principal is an ARN (`arn:aws:iam::123:user/alice`). In CE there are no accounts
//! and no central directory: a principal **is** an Ed25519 [`NodeId`]. There is nothing to create
//! or register — possession of the key *is* the identity, and every grant names principals by their
//! 64-hex node id. This module is the thin, well-tested boundary that parses and renders that id.

use anyhow::{Result, anyhow};
use ce_identity::NodeId;
use serde::{Deserialize, Serialize};

/// A principal: a CE node identity, addressed by its 32-byte Ed25519 public key.
///
/// Serialized as its lowercase 64-hex string on the wire so policies and grants are human-readable
/// and copy-pasteable into the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Principal(pub NodeId);

impl Principal {
    /// The underlying 32-byte node id.
    pub fn node_id(&self) -> NodeId {
        self.0
    }

    /// Lowercase 64-hex rendering.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from a 64-hex node-id string. Tolerant of surrounding whitespace and case; rejects
    /// any string that is not exactly 32 bytes of hex.
    pub fn parse(s: &str) -> Result<Principal> {
        let s = s.trim();
        let bytes = hex::decode(s).map_err(|_| anyhow!("principal '{s}' is not valid hex"))?;
        let arr: NodeId = bytes
            .try_into()
            .map_err(|_| anyhow!("principal '{s}' is not a 32-byte node id"))?;
        Ok(Principal(arr))
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl From<NodeId> for Principal {
    fn from(n: NodeId) -> Self {
        Principal(n)
    }
}

impl Serialize for Principal {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Principal::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NodeId {
        let mut n = [0u8; 32];
        for (i, b) in n.iter_mut().enumerate() {
            *b = i as u8;
        }
        n
    }

    #[test]
    fn hex_round_trips() {
        let p = Principal(sample());
        let back = Principal::parse(&p.hex()).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn parse_tolerates_whitespace_and_case() {
        let p = Principal(sample());
        let upper = format!("  {}  ", p.hex().to_uppercase());
        assert_eq!(Principal::parse(&upper).unwrap(), p);
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!(Principal::parse("nothex!!").is_err());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(Principal::parse("abcd").is_err());
        // 31 bytes
        assert!(Principal::parse(&"00".repeat(31)).is_err());
        // 33 bytes
        assert!(Principal::parse(&"00".repeat(33)).is_err());
    }

    #[test]
    fn display_is_hex() {
        let p = Principal(sample());
        assert_eq!(format!("{p}"), p.hex());
    }

    #[test]
    fn json_is_a_hex_string() {
        let p = Principal(sample());
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, format!("\"{}\"", p.hex()));
        let back: Principal = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p);
    }
}
