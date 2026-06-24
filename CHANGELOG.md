# Changelog

All notable changes to `ce-iam`. Format loosely follows Keep a Changelog.

## [Unreleased]

### Added

- **Durable catalog store** (`store::CatalogStore`): an on-disk, op-logged role/policy catalog at
  `<data_dir>/iam/catalog.json`. The live catalog is reconstructed by replaying the log on load; this
  is the durable writer half of the ce-coord replicated-map model. Atomic writes (temp-file + fsync +
  rename). `role compact` snapshots state and truncates history.
- **Wallet** (`wallet::WalletStore`) and `ce-iam wallet add|list|show|rm`: labeled, durable storage of
  held grant tokens at `<data_dir>/iam/wallet.json`. `verify --wallet-label` references a stored grant.
- **Accepted-roots store + rotation** (`roots::Roots`) and `ce-iam root add|list|retire|rm|reissue`:
  multi-root trust with optional validity windows, overlap-safe retirement, and
  `Iam::reissue_under` to migrate a root grant under a new key. `verify --use-roots` honors roots
  inside their window.
- **Catalog/role CLI**: `ce-iam role put|get|list|rm`, `attach|detach`, `effective-grants`, `audit`,
  `compact`; `grant --role <name>` mints from a catalog role.
- **`Iam::mint_policy`**: mint the N grants a multi-scope policy implies (one per distinct
  `(resource, conditions)` scope), instead of rejecting multi-scope documents.
- **Full condition surface in the CLI**: `--activates-in` (not_before), `--allowed-port`
  (repeatable), `--path-prefix`, alongside the existing `--expires-in`/`--max-*`.
- **Revocation freshness**: `revocation::CachedRevocationSet` (last-known-good snapshot + TTL),
  `RevocationPolicy::{FailOpen, FailClosed}`, `verify --fail-closed`/`--revocation-ttl`, and a
  `ce-iam revoked` command to list the on-chain revoked set.
- **DoS bounds on verification**: `Iam::with_max_token_bytes` / `with_max_chain_depth` (defaults
  256 KiB / 64) reject oversized or over-deep untrusted tokens before doing work.
- Extensive new tests: `tests/cli.rs` (binary e2e), `tests/store.rs` (persistence integration), new
  unit tests for caveat narrowing, not_before, mint_policy, reissue, and DoS bounds, plus new
  property tests for depth-3 attenuation and DoS limits.
- `SECURITY.md` (verifier trust model + revocation operation) and this `CHANGELOG.md`.

### Fixed

- **Expiry overflow**: `expires_in`/`activates_in`/root windows now use `saturating_add`, so a huge
  CLI value can no longer wrap to a tiny/garbage timestamp.
- **`effective_grants` determinism**: ordering no longer depends on a fallible `to_string` in a sort
  comparator; entries come out in deterministic scope-key order from the grouping map.
- **`submit_revoke` error masking**: a failed response-body read is now reported instead of silently
  discarded.
- **Unbounded growth**: the in-memory audit trail is a bounded ring (`MAX_AUDIT_ENTRIES`); stores
  enforce a max read size and per-store entry caps; the durable op-log has a max-ops guard and
  compaction.

### Changed

- README now discloses that catalog mesh-replication is deferred (the store is single-node durable),
  documents the full condition syntax, the catalog/wallet/roots surfaces, and adds a Google Cloud IAM
  comparison.
- `policy validate` compiles via an in-memory identity (no scratch key written to a predictable temp
  dir) and accepts multi-scope documents through `mint_policy`.
