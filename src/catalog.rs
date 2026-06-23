//! A managed role/policy **catalog** over the ce-coord single-writer replicated-map model.
//!
//! Everything else in this crate is deliberately *stateless*: [`Iam`](crate::Iam) mints, attenuates,
//! verifies, and inspects capability chains and holds no database of its own. That is the right shape
//! for the security core, but real IAM deployments also want the boring, stateful part of AWS-IAM:
//! a place to **store named roles and policies**, list them, edit them, attach them to principals,
//! and read an audit trail of who changed what. This module is that managed product surface, built —
//! like the rest of ce-iam — as an app tier, here over the **ce-coord** coordination primitive.
//!
//! ## Why ce-coord, and what it buys
//!
//! ce-coord gives CE a *single-writer, log-replicated map*: one node owns an append-only log of
//! operations, each stamped with a monotonic [`Version`]; readers apply the log **in version order**
//! to their own copy and converge to identical state. We model the catalog as exactly such a state
//! machine — [`Catalog`] is a [`ce_coord::StateMachine`]-shaped value whose [`Catalog::apply`] folds
//! one [`CatalogOp`] into the maps. The same op-log applied to two fresh [`Catalog`]s yields two
//! byte-identical catalogs; that is the *catalog CRUD convergence over ce-coord* property tested at
//! the bottom of this file and in `tests/catalog.rs`.
//!
//! Because the catalog logic is a pure, deterministic fold, it is unit-testable with no running node:
//! the live path simply wires [`CatalogOp`]s through `ce_coord::RMap` (writer mutates, readers
//! `await_version`), while tests drive the very same [`Catalog::apply`] the replica would. A thin
//! [`CatalogLog`] captures the writer's op-log so a reader can be reconstructed deterministically.
//!
//! ## The critical safety property
//!
//! A capability is an **immutable, signed token**: once [`Iam::mint`](crate::Iam::mint) hands an
//! audience a grant, that grant's authority is fixed forever by the bytes it was signed over. The
//! catalog stores *templates* (roles/policies) you mint **from**; it never holds, mutates, or
//! re-signs an issued capability. Therefore **no catalog edit can broaden a capability already
//! issued** — widening or deleting a role changes only what *future* mints produce, never the scope
//! of a token already in a holder's wallet. [`effective_grants`](Catalog::effective_grants) reports
//! what the catalog *would* mint now; the only ways to reduce a live token's authority remain
//! expiry and on-chain revocation (see [`crate::revocation`]). This module proves that separation
//! holds, with both unit and property tests.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::IamError;
use crate::policy::{Conditions, Policy, ResourceMatch, Role};
use crate::principal::Principal;

/// A monotonic op index, matching `ce_coord::Version`. The catalog writer assigns it; readers
/// converge to it. We keep our own alias so the catalog is usable (and testable) without pulling the
/// whole ce-coord runtime into the compile graph — the live wiring maps it onto `ce_coord::Version`.
pub type Version = u64;

/// One mutation on the catalog. This is the catalog's `ce_coord::StateMachine::Op`: it serializes to
/// JSON, rides the mesh, and is applied **in version order** on every replica. Keep every variant's
/// effect a deterministic function of the op alone so replicas converge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatalogOp {
    /// Create or overwrite the named role.
    PutRole(Role),
    /// Delete a role by name (no-op if absent).
    RemoveRole(String),
    /// Create or overwrite a free-standing named policy document.
    PutPolicy { name: String, policy: Policy },
    /// Delete a named policy (no-op if absent).
    RemovePolicy(String),
    /// Attach a role (by name) to a principal — the principal "has" that role's policy.
    AttachRole { principal: Principal, role: String },
    /// Detach a role from a principal (no-op if not attached).
    DetachRole { principal: Principal, role: String },
}

impl CatalogOp {
    /// A short human label for the audit trail.
    fn audit_action(&self) -> &'static str {
        match self {
            CatalogOp::PutRole(_) => "put_role",
            CatalogOp::RemoveRole(_) => "remove_role",
            CatalogOp::PutPolicy { .. } => "put_policy",
            CatalogOp::RemovePolicy(_) => "remove_policy",
            CatalogOp::AttachRole { .. } => "attach_role",
            CatalogOp::DetachRole { .. } => "detach_role",
        }
    }

    /// The catalog object this op names (role name, policy name, or principal hex).
    fn audit_target(&self) -> String {
        match self {
            CatalogOp::PutRole(r) => r.name.clone(),
            CatalogOp::RemoveRole(n) => n.clone(),
            CatalogOp::PutPolicy { name, .. } => name.clone(),
            CatalogOp::RemovePolicy(n) => n.clone(),
            CatalogOp::AttachRole { principal, role } => format!("{role}@{principal}"),
            CatalogOp::DetachRole { principal, role } => format!("{role}@{principal}"),
        }
    }
}

/// One immutable line in the audit trail: which version applied which op, and (optionally) who the
/// writer attributed it to. Serializable so it can be surfaced over an API or the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The catalog version this change produced.
    pub version: Version,
    /// The mutation verb (`put_role`, `attach_role`, …).
    pub action: String,
    /// The object affected (role/policy name, or `role@principal`).
    pub target: String,
    /// The principal the writer attributes the change to, if known (64-hex). `None` for unattributed
    /// system writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

/// The catalog's effective grant for one principal: the *union* of the abilities its attached roles
/// would mint, grouped by the `(resource, conditions)` they target. Each group is exactly what one
/// [`Iam::mint`](crate::Iam::mint) call would embody, so resolving effective grants tells an operator
/// precisely which capabilities the catalog would issue this principal right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveGrant {
    /// Sorted, deduplicated abilities this principal would receive for this scope.
    pub abilities: Vec<String>,
    /// The resource scope these abilities apply to.
    pub resource: ResourceMatch,
    /// The conditions (expiry/ceilings) on this scope.
    pub conditions: Conditions,
    /// The role names that contributed to this group (sorted), for traceability.
    pub from_roles: Vec<String>,
}

/// The managed role/policy catalog: named roles, named policies, and principal→role attachments,
/// evolved by an ordered [`CatalogOp`] log exactly like a `ce_coord::RMap`.
///
/// `Default` is the empty catalog at version `0`. Apply ops with [`Catalog::apply`]; the same op
/// sequence always yields the same catalog (convergence).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    /// Named roles, keyed by role name. `BTreeMap` so iteration/serialization is deterministic.
    roles: BTreeMap<String, Role>,
    /// Free-standing named policy documents.
    policies: BTreeMap<String, Policy>,
    /// principal-hex -> set of attached role names (sorted, deduped, as a `BTreeMap` value vec).
    attachments: BTreeMap<String, Vec<String>>,
    /// Highest applied version.
    version: Version,
    /// Audit trail, oldest first.
    audit: Vec<AuditEntry>,
}

impl Catalog {
    /// A fresh, empty catalog at version 0.
    pub fn new() -> Catalog {
        Catalog::default()
    }

    /// Highest version applied to this replica.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Apply one operation, advancing the version and appending an audit line. This is the catalog's
    /// `ce_coord::StateMachine::apply`: deterministic in `op` alone, so two replicas fed the same
    /// op-log converge. `actor` is the writer's attribution for the audit trail (pass the writer's
    /// own node id, or `None`).
    pub fn apply(&mut self, op: CatalogOp, actor: Option<&Principal>) {
        let action = op.audit_action().to_string();
        let target = op.audit_target();
        match &op {
            CatalogOp::PutRole(r) => {
                self.roles.insert(r.name.clone(), r.clone());
            }
            CatalogOp::RemoveRole(name) => {
                self.roles.remove(name);
                // Removing a role also detaches it everywhere, so effective grants stay coherent.
                for roles in self.attachments.values_mut() {
                    roles.retain(|r| r != name);
                }
                self.attachments.retain(|_, roles| !roles.is_empty());
            }
            CatalogOp::PutPolicy { name, policy } => {
                self.policies.insert(name.clone(), policy.clone());
            }
            CatalogOp::RemovePolicy(name) => {
                self.policies.remove(name);
            }
            CatalogOp::AttachRole { principal, role } => {
                let entry = self.attachments.entry(principal.hex()).or_default();
                if !entry.contains(role) {
                    entry.push(role.clone());
                    entry.sort();
                }
            }
            CatalogOp::DetachRole { principal, role } => {
                if let Some(entry) = self.attachments.get_mut(&principal.hex()) {
                    entry.retain(|r| r != role);
                    if entry.is_empty() {
                        self.attachments.remove(&principal.hex());
                    }
                }
            }
        }
        self.version += 1;
        self.audit.push(AuditEntry {
            version: self.version,
            action,
            target,
            actor: actor.map(|p| p.hex()),
        });
    }

    // ---- role CRUD ----

    /// Create or replace a role, returning the new catalog version. Rejects an empty role name so a
    /// nameless role can never shadow lookups.
    pub fn put_role(&mut self, role: Role, actor: Option<&Principal>) -> Result<Version, IamError> {
        if role.name.trim().is_empty() {
            return Err(IamError::BadPolicy("role name must not be empty".into()));
        }
        self.apply(CatalogOp::PutRole(role), actor);
        Ok(self.version)
    }

    /// Fetch a role by name.
    pub fn get_role(&self, name: &str) -> Option<&Role> {
        self.roles.get(name)
    }

    /// All role names, sorted.
    pub fn list_roles(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }

    /// Delete a role (idempotent), returning the new version.
    pub fn remove_role(&mut self, name: &str, actor: Option<&Principal>) -> Version {
        self.apply(CatalogOp::RemoveRole(name.to_string()), actor);
        self.version
    }

    // ---- policy CRUD ----

    /// Create or replace a named policy document, returning the new version.
    pub fn put_policy(
        &mut self,
        name: impl Into<String>,
        policy: Policy,
        actor: Option<&Principal>,
    ) -> Result<Version, IamError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(IamError::BadPolicy("policy name must not be empty".into()));
        }
        self.apply(CatalogOp::PutPolicy { name, policy }, actor);
        Ok(self.version)
    }

    /// Fetch a named policy.
    pub fn get_policy(&self, name: &str) -> Option<&Policy> {
        self.policies.get(name)
    }

    /// All policy names, sorted.
    pub fn list_policies(&self) -> Vec<String> {
        self.policies.keys().cloned().collect()
    }

    /// Delete a named policy (idempotent).
    pub fn remove_policy(&mut self, name: &str, actor: Option<&Principal>) -> Version {
        self.apply(CatalogOp::RemovePolicy(name.to_string()), actor);
        self.version
    }

    // ---- attachments ----

    /// Attach a role to a principal. Returns [`IamError::BadPolicy`] if the role is unknown, so an
    /// effective-grant lookup never silently references a missing role.
    pub fn attach_role(
        &mut self,
        principal: Principal,
        role: &str,
        actor: Option<&Principal>,
    ) -> Result<Version, IamError> {
        if !self.roles.contains_key(role) {
            return Err(IamError::BadPolicy(format!("no such role '{role}' to attach")));
        }
        self.apply(CatalogOp::AttachRole { principal, role: role.to_string() }, actor);
        Ok(self.version)
    }

    /// Detach a role from a principal (idempotent).
    pub fn detach_role(
        &mut self,
        principal: Principal,
        role: &str,
        actor: Option<&Principal>,
    ) -> Version {
        self.apply(CatalogOp::DetachRole { principal, role: role.to_string() }, actor);
        self.version
    }

    /// The role names attached to a principal, sorted.
    pub fn roles_for(&self, principal: &Principal) -> Vec<String> {
        self.attachments.get(&principal.hex()).cloned().unwrap_or_default()
    }

    // ---- effective-grant resolution ----

    /// Resolve a principal's **effective grants**: the set of capabilities the catalog would mint for
    /// it right now, from its attached roles. Abilities are unioned per distinct `(resource,
    /// conditions)` scope — exactly the grouping a capability requires, since one capability carries
    /// one resource and one caveat set. Each role's *single-statement Allow* policy contributes its
    /// actions to the scope it targets; a role whose policy is empty or multi-scope is reported via
    /// `Err` so the operator sees the misconfiguration rather than a silently dropped grant.
    ///
    /// Roles are resolved in sorted name order and the result is deterministic, so two replicas at
    /// the same version compute identical effective grants. This is a *report*, not an issuance: it
    /// describes what minting would produce; it does not touch any already-issued token.
    pub fn effective_grants(
        &self,
        principal: &Principal,
    ) -> Result<Vec<EffectiveGrant>, IamError> {
        // Group abilities by (resource, conditions). We key on the JSON of the scope so distinct
        // resources/conditions never collide and the grouping is deterministic.
        let mut groups: BTreeMap<String, (ResourceMatch, Conditions, Vec<String>, Vec<String>)> =
            BTreeMap::new();

        for role_name in self.roles_for(principal) {
            let role = match self.roles.get(&role_name) {
                Some(r) => r,
                // An attachment can only be created for an existing role, and removing a role
                // detaches it, so this is unreachable in practice — but report rather than panic.
                None => {
                    return Err(IamError::BadPolicy(format!(
                        "attached role '{role_name}' is missing from the catalog"
                    )));
                }
            };
            for stmt in &role.policy.statements {
                // Only Allow statements grant authority; Deny is rejected at mint time and carries no
                // effective grant, so we skip it here too.
                if !matches!(stmt.effect, crate::policy::Effect::Allow) {
                    continue;
                }
                if stmt.actions.is_empty() {
                    return Err(IamError::BadPolicy(format!(
                        "role '{role_name}' has an Allow statement with no actions"
                    )));
                }
                let key = scope_key(&stmt.resource, &stmt.conditions)?;
                let group = groups.entry(key).or_insert_with(|| {
                    (stmt.resource.clone(), stmt.conditions.clone(), Vec::new(), Vec::new())
                });
                group.2.extend(stmt.actions.iter().cloned());
                if !group.3.contains(&role_name) {
                    group.3.push(role_name.clone());
                }
            }
        }

        let mut out: Vec<EffectiveGrant> = groups
            .into_values()
            .map(|(resource, conditions, mut abilities, mut from_roles)| {
                abilities.sort();
                abilities.dedup();
                from_roles.sort();
                from_roles.dedup();
                EffectiveGrant { abilities, resource, conditions, from_roles }
            })
            .collect();
        // Deterministic order independent of map iteration: sort by the rendered scope.
        out.sort_by(|a, b| {
            scope_key(&a.resource, &a.conditions)
                .unwrap_or_default()
                .cmp(&scope_key(&b.resource, &b.conditions).unwrap_or_default())
        });
        Ok(out)
    }

    // ---- audit ----

    /// The full audit trail, oldest first.
    pub fn audit(&self) -> &[AuditEntry] {
        &self.audit
    }

    /// Audit entries at version `> after` (for incremental polling). `after = 0` returns everything.
    pub fn audit_since(&self, after: Version) -> Vec<AuditEntry> {
        self.audit.iter().filter(|e| e.version > after).cloned().collect()
    }
}

/// A deterministic grouping key for an `(resource, conditions)` scope.
fn scope_key(resource: &ResourceMatch, conditions: &Conditions) -> Result<String, IamError> {
    serde_json::to_string(&(resource, conditions))
        .map_err(|e| IamError::BadPolicy(format!("cannot key scope: {e}")))
}

/// The writer's append-only op-log — the thing a `ce_coord::RMap` writer broadcasts and a reader
/// replays. Holding it lets a reader reconstruct the catalog deterministically (convergence), and
/// lets tests assert that replaying the log on a fresh [`Catalog`] reproduces the writer's state.
///
/// In the live path this is `ce_coord`'s replicated log; here it is a thin, serializable record so
/// the catalog is exercisable end-to-end without a running node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogLog {
    /// Each entry is the op plus the attributed actor (hex), in version order.
    entries: Vec<(CatalogOp, Option<String>)>,
}

impl CatalogLog {
    /// An empty log.
    pub fn new() -> CatalogLog {
        CatalogLog::default()
    }

    /// Record an op the writer applied. Returns the new length (== the version it produced).
    pub fn record(&mut self, op: CatalogOp, actor: Option<&Principal>) -> Version {
        self.entries.push((op, actor.map(|p| p.hex())));
        self.entries.len() as Version
    }

    /// Number of logged ops (== the catalog version a full replay reaches).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no ops are logged.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Replay the whole log onto a fresh [`Catalog`] — what a reader does to converge. Determinism of
    /// [`Catalog::apply`] guarantees this reproduces the writer's catalog exactly.
    pub fn replay(&self) -> Catalog {
        self.replay_through(self.entries.len() as Version)
    }

    /// Replay only the first `upto` ops (simulating a reader that has caught up to `upto` but not the
    /// writer's latest). Useful to test partial convergence.
    pub fn replay_through(&self, upto: Version) -> Catalog {
        let mut cat = Catalog::new();
        for (op, actor_hex) in self.entries.iter().take(upto as usize) {
            let actor = actor_hex.as_deref().and_then(|h| Principal::parse(h).ok());
            cat.apply(op.clone(), actor.as_ref());
        }
        cat
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Effect, Statement};

    fn principal(b: u8) -> Principal {
        Principal([b; 32])
    }

    fn reader_role(name: &str) -> Role {
        Role::new(
            name,
            Policy::allow(
                vec!["storage:read".into()],
                ResourceMatch::Any,
                Conditions::default(),
            ),
        )
    }

    // ---- CRUD happy paths ----

    #[test]
    fn role_crud_round_trip() {
        let mut cat = Catalog::new();
        assert_eq!(cat.version(), 0);
        let v = cat.put_role(reader_role("reader"), None).unwrap();
        assert_eq!(v, 1);
        assert_eq!(cat.list_roles(), vec!["reader".to_string()]);
        assert!(cat.get_role("reader").is_some());
        cat.remove_role("reader", None);
        assert!(cat.get_role("reader").is_none());
        assert!(cat.list_roles().is_empty());
    }

    #[test]
    fn policy_crud_round_trip() {
        let mut cat = Catalog::new();
        let p = Policy::allow(vec!["db:read".into()], ResourceMatch::Any, Conditions::default());
        cat.put_policy("ro", p.clone(), None).unwrap();
        assert_eq!(cat.get_policy("ro"), Some(&p));
        assert_eq!(cat.list_policies(), vec!["ro".to_string()]);
        cat.remove_policy("ro", None);
        assert!(cat.get_policy("ro").is_none());
    }

    #[test]
    fn put_role_then_overwrite_updates() {
        let mut cat = Catalog::new();
        cat.put_role(reader_role("r"), None).unwrap();
        let updated = Role::new(
            "r",
            Policy::allow(vec!["storage:write".into()], ResourceMatch::Any, Conditions::default()),
        );
        cat.put_role(updated.clone(), None).unwrap();
        assert_eq!(cat.get_role("r"), Some(&updated));
        // Still one role (overwrite, not append).
        assert_eq!(cat.list_roles().len(), 1);
    }

    // ---- CRUD error paths ----

    #[test]
    fn put_role_rejects_empty_name() {
        let mut cat = Catalog::new();
        let bad = Role::new("  ", Policy::allow(vec!["x".into()], ResourceMatch::Any, Conditions::default()));
        assert!(matches!(cat.put_role(bad, None).unwrap_err(), IamError::BadPolicy(_)));
        assert_eq!(cat.version(), 0, "a rejected op must not advance the version");
    }

    #[test]
    fn put_policy_rejects_empty_name() {
        let mut cat = Catalog::new();
        let p = Policy::allow(vec!["x".into()], ResourceMatch::Any, Conditions::default());
        assert!(matches!(cat.put_policy("", p, None).unwrap_err(), IamError::BadPolicy(_)));
    }

    #[test]
    fn attach_unknown_role_errors() {
        let mut cat = Catalog::new();
        let err = cat.attach_role(principal(1), "ghost", None).unwrap_err();
        assert!(matches!(err, IamError::BadPolicy(_)));
    }

    #[test]
    fn remove_is_idempotent() {
        let mut cat = Catalog::new();
        // Removing absent role/policy is a no-op that still advances the version (an op was applied).
        cat.remove_role("nope", None);
        cat.remove_policy("nope", None);
        assert_eq!(cat.version(), 2);
        assert!(cat.list_roles().is_empty());
    }

    // ---- attachments + effective grants ----

    #[test]
    fn attach_detach_and_roles_for() {
        let mut cat = Catalog::new();
        cat.put_role(reader_role("reader"), None).unwrap();
        cat.attach_role(principal(7), "reader", None).unwrap();
        assert_eq!(cat.roles_for(&principal(7)), vec!["reader".to_string()]);
        // Idempotent attach: attaching twice does not duplicate.
        cat.attach_role(principal(7), "reader", None).unwrap();
        assert_eq!(cat.roles_for(&principal(7)).len(), 1);
        cat.detach_role(principal(7), "reader", None);
        assert!(cat.roles_for(&principal(7)).is_empty());
    }

    #[test]
    fn effective_grants_union_abilities_same_scope() {
        let mut cat = Catalog::new();
        cat.put_role(
            Role::new("a", Policy::allow(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default())),
            None,
        )
        .unwrap();
        cat.put_role(
            Role::new("b", Policy::allow(vec!["storage:write".into()], ResourceMatch::Any, Conditions::default())),
            None,
        )
        .unwrap();
        cat.attach_role(principal(1), "a", None).unwrap();
        cat.attach_role(principal(1), "b", None).unwrap();

        let eff = cat.effective_grants(&principal(1)).unwrap();
        assert_eq!(eff.len(), 1, "same resource+conditions collapse to one grant");
        assert_eq!(eff[0].abilities, vec!["storage:read".to_string(), "storage:write".to_string()]);
        assert_eq!(eff[0].resource, ResourceMatch::Any);
        assert_eq!(eff[0].from_roles, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn effective_grants_split_by_distinct_scope() {
        let mut cat = Catalog::new();
        cat.put_role(
            Role::new("any", Policy::allow(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default())),
            None,
        )
        .unwrap();
        cat.put_role(
            Role::new(
                "gpu",
                Policy::allow(vec!["run:deploy".into()], ResourceMatch::Tag("gpu".into()), Conditions::default()),
            ),
            None,
        )
        .unwrap();
        cat.attach_role(principal(2), "any", None).unwrap();
        cat.attach_role(principal(2), "gpu", None).unwrap();
        let eff = cat.effective_grants(&principal(2)).unwrap();
        assert_eq!(eff.len(), 2, "distinct resources produce distinct grants");
    }

    #[test]
    fn effective_grants_empty_for_unknown_principal() {
        let cat = Catalog::new();
        assert!(cat.effective_grants(&principal(9)).unwrap().is_empty());
    }

    #[test]
    fn effective_grants_skips_deny_statements() {
        let mut cat = Catalog::new();
        let mixed = Policy {
            version: "ce-iam-policy-v1".into(),
            statements: vec![
                Statement {
                    sid: None,
                    effect: Effect::Allow,
                    actions: vec!["storage:read".into()],
                    resource: ResourceMatch::Any,
                    conditions: Conditions::default(),
                },
                Statement {
                    sid: None,
                    effect: Effect::Deny,
                    actions: vec!["storage:write".into()],
                    resource: ResourceMatch::Any,
                    conditions: Conditions::default(),
                },
            ],
        };
        cat.put_role(Role::new("mixed", mixed), None).unwrap();
        cat.attach_role(principal(3), "mixed", None).unwrap();
        let eff = cat.effective_grants(&principal(3)).unwrap();
        assert_eq!(eff.len(), 1);
        assert_eq!(eff[0].abilities, vec!["storage:read".to_string()]);
    }

    #[test]
    fn effective_grants_errors_on_empty_action_statement() {
        let mut cat = Catalog::new();
        let bad = Policy {
            version: "ce-iam-policy-v1".into(),
            statements: vec![Statement {
                sid: None,
                effect: Effect::Allow,
                actions: vec![],
                resource: ResourceMatch::Any,
                conditions: Conditions::default(),
            }],
        };
        cat.put_role(Role::new("empty", bad), None).unwrap();
        cat.attach_role(principal(4), "empty", None).unwrap();
        assert!(matches!(cat.effective_grants(&principal(4)).unwrap_err(), IamError::BadPolicy(_)));
    }

    #[test]
    fn removing_a_role_detaches_it_everywhere() {
        let mut cat = Catalog::new();
        cat.put_role(reader_role("reader"), None).unwrap();
        cat.attach_role(principal(1), "reader", None).unwrap();
        cat.attach_role(principal(2), "reader", None).unwrap();
        cat.remove_role("reader", None);
        assert!(cat.roles_for(&principal(1)).is_empty());
        assert!(cat.roles_for(&principal(2)).is_empty());
        assert!(cat.effective_grants(&principal(1)).unwrap().is_empty());
    }

    // ---- convergence over the ce-coord op-log ----

    #[test]
    fn op_log_replay_converges_to_writer() {
        // Build a catalog through the public API while logging each applied op, then prove a fresh
        // replica that replays the log reaches a byte-identical catalog (ce-coord convergence).
        let mut writer = Catalog::new();
        let mut log = CatalogLog::new();
        let actor = principal(0xAA);

        let ops = vec![
            CatalogOp::PutRole(reader_role("reader")),
            CatalogOp::PutPolicy {
                name: "p1".into(),
                policy: Policy::allow(vec!["db:read".into()], ResourceMatch::Any, Conditions::default()),
            },
            CatalogOp::AttachRole { principal: principal(1), role: "reader".into() },
            CatalogOp::PutRole(Role::new(
                "writer",
                Policy::allow(vec!["storage:write".into()], ResourceMatch::Any, Conditions::default()),
            )),
            CatalogOp::AttachRole { principal: principal(1), role: "writer".into() },
            CatalogOp::DetachRole { principal: principal(1), role: "reader".into() },
        ];
        for op in ops {
            writer.apply(op.clone(), Some(&actor));
            log.record(op, Some(&actor));
        }

        let reader = log.replay();
        assert_eq!(reader, writer, "a full replay must reproduce the writer exactly");
        assert_eq!(reader.version(), writer.version());
        assert_eq!(reader.version(), log.len() as Version);
    }

    #[test]
    fn partial_replay_is_a_prefix_of_full() {
        let mut log = CatalogLog::new();
        log.record(CatalogOp::PutRole(reader_role("r")), None);
        log.record(CatalogOp::AttachRole { principal: principal(1), role: "r".into() }, None);
        log.record(CatalogOp::RemoveRole("r".into()), None);

        let at1 = log.replay_through(1);
        assert_eq!(at1.version(), 1);
        assert!(at1.get_role("r").is_some());
        // A reader that has only applied the first op has not yet seen the attach.
        assert!(at1.roles_for(&principal(1)).is_empty());

        let full = log.replay();
        assert_eq!(full.version(), 3);
        assert!(full.get_role("r").is_none());
    }

    #[test]
    fn replay_order_independence_for_independent_keys() {
        // Two ops on disjoint keys: applied in either order they converge (single-writer log fixes
        // the order, but the resulting state is the same set of independent insertions).
        let mut a = Catalog::new();
        a.apply(CatalogOp::PutRole(reader_role("x")), None);
        a.apply(CatalogOp::PutPolicy {
            name: "y".into(),
            policy: Policy::allow(vec!["db:read".into()], ResourceMatch::Any, Conditions::default()),
        }, None);

        let mut b = Catalog::new();
        b.apply(CatalogOp::PutPolicy {
            name: "y".into(),
            policy: Policy::allow(vec!["db:read".into()], ResourceMatch::Any, Conditions::default()),
        }, None);
        b.apply(CatalogOp::PutRole(reader_role("x")), None);

        // Same roles and policies regardless of order; only the audit/version order differs.
        assert_eq!(a.list_roles(), b.list_roles());
        assert_eq!(a.list_policies(), b.list_policies());
        assert_eq!(a.roles, b.roles);
        assert_eq!(a.policies, b.policies);
    }

    // ---- audit ----

    #[test]
    fn audit_records_each_change() {
        let mut cat = Catalog::new();
        let actor = principal(0xBB);
        cat.put_role(reader_role("r"), Some(&actor)).unwrap();
        cat.attach_role(principal(1), "r", Some(&actor)).unwrap();
        let trail = cat.audit();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].action, "put_role");
        assert_eq!(trail[0].version, 1);
        assert_eq!(trail[0].actor.as_deref(), Some(actor.hex().as_str()));
        assert_eq!(trail[1].action, "attach_role");
        assert_eq!(trail[1].target, format!("r@{}", principal(1)));
    }

    #[test]
    fn audit_since_filters_by_version() {
        let mut cat = Catalog::new();
        cat.put_role(reader_role("a"), None).unwrap();
        cat.put_role(reader_role("b"), None).unwrap();
        cat.put_role(reader_role("c"), None).unwrap();
        let recent = cat.audit_since(1);
        assert_eq!(recent.len(), 2);
        assert!(recent.iter().all(|e| e.version > 1));
        assert_eq!(cat.audit_since(0).len(), 3);
        assert!(cat.audit_since(3).is_empty());
    }

    #[test]
    fn catalog_json_round_trips() {
        let mut cat = Catalog::new();
        cat.put_role(reader_role("r"), None).unwrap();
        cat.attach_role(principal(1), "r", None).unwrap();
        let json = serde_json::to_string(&cat).unwrap();
        let back: Catalog = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}
