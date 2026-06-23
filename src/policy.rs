//! Policies and roles — IAM templates that compile to a ce-cap grant body.
//!
//! AWS-IAM models access as a JSON **policy document**: a list of statements, each an `Effect`
//! (`Allow`/`Deny`) over `Action`s and `Resource`s, optionally with `Condition`s. CE's underlying
//! [`ce_cap`] primitive is leaner and, crucially, **monotone**: a capability is a pure *grant* of
//! `abilities × Resource × Caveats` that can only ever be narrowed down a delegation chain. There
//! is no `Deny` in capabilities, because a capability you were never handed is already denied — the
//! default is "no authority". That is a feature, not a gap: it is exactly why capabilities are
//! offline-verifiable with no policy server.
//!
//! So this module is the compiler from the familiar IAM shape to the capability shape:
//!
//! * **Action** (e.g. `"storage:read"`) → a ce-cap ability string. Wildcards (`"storage:*"`, `"*"`)
//!   are expanded at *mint* time against a closed action universe, never left as runtime globs —
//!   a capability must enumerate exactly what it grants so attenuation stays a set-subset check.
//! * **ResourceMatch** → a [`ce_cap::Resource`] (which node-set the grant applies to).
//! * **Conditions** (expiry, resource ceilings, port/path scoping) → [`ce_cap::Caveats`].
//! * **Effect::Deny** → rejected at compile time with a clear error, because it cannot be honored
//!   by a monotone capability. Model "deny" by simply *not granting* the action.
//!
//! A [`Policy`] is one such document; a [`Role`] is just a named, reusable policy (a template you
//! attach to many principals). Both are plain serde types so they round-trip through JSON files and
//! the CLI.

use crate::error::IamError;
use ce_cap::{Caveats, Resource};
use serde::{Deserialize, Serialize};

/// Allow or Deny. CE capabilities are pure grants, so only [`Effect::Allow`] can be compiled;
/// [`Effect::Deny`] is accepted by the parser (so AWS-style documents deserialize) but rejected at
/// compile time with [`IamError::DenyUnsupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum Effect {
    #[default]
    Allow,
    Deny,
}

/// Which nodes a statement applies to — the IAM-facing spelling of [`ce_cap::Resource`].
///
/// `"*"` (or the explicit [`ResourceMatch::Any`]) means every node under the issuer's authority;
/// a 64-hex node id pins one node; `tag:<t>` selects nodes advertising self-tag `t`; `all-of:a,b`
/// requires all listed tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMatch {
    /// Every node (`"*"`).
    Any,
    /// One node, by 64-hex id.
    Node(String),
    /// Nodes advertising this self-tag.
    Tag(String),
    /// Nodes advertising all of these self-tags.
    AllOf(Vec<String>),
}

impl ResourceMatch {
    /// Compile to the ce-cap [`Resource`] the verifier understands.
    pub fn to_cap_resource(&self) -> Result<Resource, IamError> {
        Ok(match self {
            ResourceMatch::Any => Resource::Any,
            ResourceMatch::Node(h) => {
                let bytes = hex::decode(h.trim())
                    .map_err(|_| IamError::BadResource(format!("node '{h}' is not hex")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| IamError::BadResource(format!("node '{h}' is not 32 bytes")))?;
                Resource::Node(arr)
            }
            ResourceMatch::Tag(t) => {
                if t.is_empty() {
                    return Err(IamError::BadResource("empty tag".into()));
                }
                Resource::Tag(t.clone())
            }
            ResourceMatch::AllOf(ts) => {
                if ts.is_empty() {
                    return Err(IamError::BadResource("all_of with no tags".into()));
                }
                Resource::AllOf(ts.clone())
            }
        })
    }

    /// Parse the CLI/string spelling: `*`, a 64-hex node id, `tag:<t>`, or `all-of:a,b,c`.
    pub fn parse(s: &str) -> Result<ResourceMatch, IamError> {
        let s = s.trim();
        if s == "*" || s.eq_ignore_ascii_case("any") {
            return Ok(ResourceMatch::Any);
        }
        if let Some(t) = s.strip_prefix("tag:") {
            return Ok(ResourceMatch::Tag(t.trim().to_string()));
        }
        if let Some(rest) = s.strip_prefix("all-of:") {
            let tags: Vec<String> = rest
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
            if tags.is_empty() {
                return Err(IamError::BadResource("all-of: with no tags".into()));
            }
            return Ok(ResourceMatch::AllOf(tags));
        }
        // Otherwise it must be a node id.
        let bytes = hex::decode(s)
            .map_err(|_| IamError::BadResource(format!("resource '{s}' is not a known form")))?;
        if bytes.len() != 32 {
            return Err(IamError::BadResource(format!(
                "resource '{s}' is not a 32-byte node id"
            )));
        }
        Ok(ResourceMatch::Node(s.to_lowercase()))
    }
}

/// Time/quantity conditions on a statement — the IAM-facing spelling of the subset of
/// [`ce_cap::Caveats`] that this product surfaces.
///
/// All fields are optional; an empty [`Conditions`] compiles to default (unconstrained) caveats.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conditions {
    /// Unix seconds before which the grant is not yet valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    /// Unix seconds after which the grant expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<u64>,
    /// Ceiling on CPU cores a deploy under this grant may request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu: Option<u32>,
    /// Ceiling on memory (MB) a deploy under this grant may request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mem_mb: Option<u32>,
    /// Ceiling on credits (whole credits) the audience may spend under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_credits: Option<u64>,
    /// Restrict tunnels under this grant to these remote ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ports: Option<Vec<u16>>,
    /// Confine sync/file writes under this grant to paths beneath this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
}

impl Conditions {
    /// Compile to ce-cap [`Caveats`]. `None` fields become caveat defaults (`0`/`None` = no bound).
    pub fn to_caveats(&self) -> Caveats {
        Caveats {
            not_before: self.not_before.unwrap_or(0),
            not_after: self.not_after.unwrap_or(0),
            max_cpu: self.max_cpu,
            max_mem_mb: self.max_mem_mb,
            max_credits: self.max_credits,
            allowed_ports: self.allowed_ports.clone(),
            path_prefix: self.path_prefix.clone(),
        }
    }

    /// True if no condition is set.
    pub fn is_empty(&self) -> bool {
        *self == Conditions::default()
    }
}

/// One IAM statement: an effect over a set of actions, scoped to a resource, with conditions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    /// Optional human label (AWS `Sid`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Allow or Deny.
    #[serde(default)]
    pub effect: Effect,
    /// Action strings (ce-cap abilities). May include wildcards like `"storage:*"` or `"*"`, which
    /// are expanded at mint time against the action universe.
    pub actions: Vec<String>,
    /// Which nodes this statement applies to.
    pub resource: ResourceMatch,
    /// Conditions (expiry, ceilings, scoping).
    #[serde(default, skip_serializing_if = "Conditions::is_empty")]
    pub conditions: Conditions,
}

/// A full IAM policy document: an ordered list of statements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Schema discriminator. Always `"ce-iam-policy-v1"`.
    #[serde(default = "Policy::version_tag")]
    pub version: String,
    /// The statements.
    pub statements: Vec<Statement>,
}

impl Policy {
    fn version_tag() -> String {
        "ce-iam-policy-v1".to_string()
    }

    /// A single-statement Allow policy — the common `grant <actions> on <resource>` case.
    pub fn allow(actions: Vec<String>, resource: ResourceMatch, conditions: Conditions) -> Policy {
        Policy {
            version: Self::version_tag(),
            statements: vec![Statement {
                sid: None,
                effect: Effect::Allow,
                actions,
                resource,
                conditions,
            }],
        }
    }

    /// Parse a policy document from JSON, validating the schema tag.
    pub fn from_json(s: &str) -> Result<Policy, IamError> {
        let p: Policy = serde_json::from_str(s)
            .map_err(|e| IamError::BadPolicy(format!("policy JSON did not parse: {e}")))?;
        if p.version != Self::version_tag() {
            return Err(IamError::BadPolicy(format!(
                "unsupported policy version '{}' (expected '{}')",
                p.version,
                Self::version_tag()
            )));
        }
        if p.statements.is_empty() {
            return Err(IamError::BadPolicy("policy has no statements".into()));
        }
        Ok(p)
    }

    /// Pretty JSON rendering.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// A named, reusable policy — an IAM **role**. A role is attached to a principal by minting a grant
/// from its policy. Roles are pure templates with no state of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// Role name (e.g. `"storage-reader"`).
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The policy this role embodies.
    pub policy: Policy,
}

impl Role {
    /// Construct a role.
    pub fn new(name: impl Into<String>, policy: Policy) -> Role {
        Role { name: name.into(), description: None, policy }
    }

    /// Parse a role from JSON.
    pub fn from_json(s: &str) -> Result<Role, IamError> {
        let r: Role = serde_json::from_str(s)
            .map_err(|e| IamError::BadPolicy(format!("role JSON did not parse: {e}")))?;
        if r.name.trim().is_empty() {
            return Err(IamError::BadPolicy("role has an empty name".into()));
        }
        Ok(r)
    }

    /// Pretty JSON rendering.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_parse_forms() {
        assert_eq!(ResourceMatch::parse("*").unwrap(), ResourceMatch::Any);
        assert_eq!(ResourceMatch::parse("any").unwrap(), ResourceMatch::Any);
        assert_eq!(
            ResourceMatch::parse("tag:gpu").unwrap(),
            ResourceMatch::Tag("gpu".into())
        );
        assert_eq!(
            ResourceMatch::parse("all-of:gpu, linux").unwrap(),
            ResourceMatch::AllOf(vec!["gpu".into(), "linux".into()])
        );
        let node = "ab".repeat(32);
        assert_eq!(
            ResourceMatch::parse(&node).unwrap(),
            ResourceMatch::Node(node.clone())
        );
    }

    #[test]
    fn resource_parse_rejects_garbage() {
        assert!(ResourceMatch::parse("not-a-resource").is_err());
        assert!(ResourceMatch::parse("all-of:").is_err());
        assert!(ResourceMatch::parse(&"ab".repeat(10)).is_err());
    }

    #[test]
    fn resource_compiles_to_cap_resource() {
        assert_eq!(ResourceMatch::Any.to_cap_resource().unwrap(), Resource::Any);
        assert_eq!(
            ResourceMatch::Tag("gpu".into()).to_cap_resource().unwrap(),
            Resource::Tag("gpu".into())
        );
        let node = "cd".repeat(32);
        match ResourceMatch::Node(node).to_cap_resource().unwrap() {
            Resource::Node(n) => assert_eq!(n, [0xcdu8; 32]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resource_compile_rejects_bad_node_and_empty_tags() {
        assert!(ResourceMatch::Node("zz".into()).to_cap_resource().is_err());
        assert!(ResourceMatch::Tag("".into()).to_cap_resource().is_err());
        assert!(ResourceMatch::AllOf(vec![]).to_cap_resource().is_err());
    }

    #[test]
    fn conditions_compile_to_caveats() {
        let c = Conditions {
            not_after: Some(1000),
            max_cpu: Some(8),
            allowed_ports: Some(vec![22]),
            ..Default::default()
        };
        let cav = c.to_caveats();
        assert_eq!(cav.not_after, 1000);
        assert_eq!(cav.max_cpu, Some(8));
        assert_eq!(cav.allowed_ports, Some(vec![22]));
        assert_eq!(cav.not_before, 0);
    }

    #[test]
    fn empty_conditions_are_default_caveats() {
        assert!(Conditions::default().is_empty());
        assert_eq!(Conditions::default().to_caveats(), Caveats::default());
    }

    #[test]
    fn policy_json_round_trips() {
        let p = Policy::allow(
            vec!["storage:read".into()],
            ResourceMatch::Tag("gpu".into()),
            Conditions { not_after: Some(42), ..Default::default() },
        );
        let json = p.to_json();
        let back = Policy::from_json(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn policy_rejects_bad_version_and_empty() {
        let bad = r#"{"version":"nope","statements":[]}"#;
        assert!(Policy::from_json(bad).is_err());
        let empty = r#"{"version":"ce-iam-policy-v1","statements":[]}"#;
        assert!(Policy::from_json(empty).is_err());
    }

    #[test]
    fn policy_parses_aws_style_deny_but_marks_it() {
        // Deny deserializes fine; the compile step is what rejects it (tested in grant.rs).
        let json = r#"{
            "version":"ce-iam-policy-v1",
            "statements":[{"effect":"Deny","actions":["storage:read"],"resource":"any"}]
        }"#;
        let p = Policy::from_json(json).unwrap();
        assert_eq!(p.statements[0].effect, Effect::Deny);
    }

    #[test]
    fn role_round_trips() {
        let role = Role::new(
            "storage-reader",
            Policy::allow(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default()),
        );
        let json = role.to_json();
        let back = Role::from_json(&json).unwrap();
        assert_eq!(role, back);
    }

    #[test]
    fn role_rejects_empty_name() {
        let json = r#"{"name":"  ","policy":{"version":"ce-iam-policy-v1","statements":[{"effect":"Allow","actions":["x"],"resource":"any"}]}}"#;
        assert!(Role::from_json(json).is_err());
    }
}
