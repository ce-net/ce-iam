# ce-iam security model

ce-iam is authorization over CE capabilities. This document states the trust model a verifier relies
on, what an operator must configure to be safe, and the known boundaries.

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

## Reporting

Email security concerns to ledamecrydenfalk@gmail.com.
