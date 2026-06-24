# ce-iam

IAM / identity-and-access-management as a managed product over CE's capability primitive
(`ce-cap`). It gives you the familiar **AWS-IAM vocabulary** — principals, roles, policies,
mint / attenuate / verify / revoke — implemented as **signed, attenuating capability chains**.

Nothing here is a new node feature. `ce-iam` is an SDK / app tier that composes existing CE:

- **`ce-cap`** — the authorization primitive (signed attenuating chains, offline verification).
- **`ce-identity`** — Ed25519 keys; a principal *is* a node id.
- **`ce-rs`** — the CE node HTTP client, used to read the on-chain revocation set.

## Why capabilities instead of ACLs

AWS-IAM is a *policy server*: a central service evaluates `(principal, action, resource)` against
stored rules on every request. CE has no such server. A capability is the inverse — a portable,
signed **grant** the holder carries and presents, verified **offline** by the resource owner in
microseconds. That buys three properties ACLs cannot:

1. **Attenuating** — a holder can sub-delegate only a *subset* of what it holds, recursively, and
   the math guarantees a delegation can never broaden authority. This is the central invariant the
   crate property-tests.
2. **Offline-verifiable** — no policy server, no `O(shares)` host-side state; the token *is* the proof.
3. **Uniformly revocable** — short expiries (offline), on-chain `RevokeCapability` keyed by
   `(issuer, nonce)` (revoking any link kills its whole subtree), and root rotation.

## The mapping

| AWS-IAM concept            | ce-iam                                              | ce-cap                       |
|----------------------------|-----------------------------------------------------|------------------------------|
| Principal (user/role)      | `Principal` — a CE node id                          | `NodeId`                     |
| Policy document            | `Policy` / `Statement` / `Effect`                   | —                            |
| Role (named policy)        | `Role`                                              | —                            |
| Action (`s3:GetObject`)    | ability string inside a statement                   | `abilities: Vec<String>`     |
| Resource ARN               | `ResourceMatch` → `Resource`                        | `Resource`                   |
| Condition                  | `Conditions` → `Caveats`                            | `Caveats`                    |
| Attach policy to principal | `Iam::mint`                                          | `SignedCapability::issue`    |
| `sts:AssumeRole` (scoped)  | `Iam::attenuate`                                    | child link in the chain      |
| `IsAuthorized`             | `Iam::verify`                                       | `ce_cap::authorize`          |
| Inspect a token's scope    | `Iam::inspect`                                      | walk the chain               |
| Revoke                     | on-chain `RevokeCapability` + `RevocationSet`        | `is_revoked` predicate       |

### Effect::Deny is intentionally not expressible

A CE capability is a pure, **monotone grant** — there is no `Deny`, because a capability you were
never handed is already denied (the default is "no authority"). `Policy` documents *parse* `Deny`
(so AWS-style documents deserialize), but compiling a `Deny` statement to a grant is a hard error
(`IamError::DenyUnsupported`). Model "deny" by simply not granting the action.

### Wildcards expand at mint time

Capabilities must enumerate their abilities so attenuation stays a pure set-subset test. IAM authors
still get `"storage:*"` and `"*"`: they are expanded at **mint** time against a closed *action
universe* (`Iam::with_action_universe`), so the runtime verifier never sees a glob. A wildcard that
matches nothing in the universe is an error, never a silent empty grant. Literal actions outside the
universe are always allowed, so apps can grant abilities the IAM service was never told about.

## Compared to Google Cloud IAM

ce-iam wears AWS-IAM vocabulary, but it maps cleanly onto Google Cloud IAM concepts too:

| Google Cloud IAM            | ce-iam analog                                                      |
|-----------------------------|-------------------------------------------------------------------|
| Member / principal          | `Principal` (a CE node id) — possession of the key *is* the identity |
| Service account             | a `Principal` whose key a workload holds; no separate account object |
| Role (`roles/storage.objectViewer`) | a `Role` (named policy) in the catalog                    |
| Permission (`storage.objects.get`)  | an ability string (e.g. `storage:read`)                   |
| IAM binding (member → role on a resource) | `role attach <principal> <role>` + the resource scope inside the role's policy |
| IAM Condition (CEL on resource/request) | `Conditions` (expiry, ceilings, ports, path prefix) compiled to `Caveats` |
| `setIamPolicy` / `getIamPolicy`     | `role put` / `effective-grants`                           |
| Policy evaluation service   | **none** — verification is offline and local; the token *is* the proof |

Key divergences: Google IAM is a centrally-evaluated allow-list with CEL conditions; ce-iam is a
capability model — bearer grants verified offline, attenuating-only, with no central policy server
and no `Deny` (a permission you were never granted is already denied). Google IAM conditions support
arbitrary CEL over request attributes (IP, time, resource tags); ce-iam's conditions are the closed,
monotone caveat set above. That closure is what makes offline, server-less verification possible.

## Library

```rust
use ce_iam::{Iam, Principal, ResourceMatch, Conditions, RevocationSet, simple_policy};
use ce_iam::Identity;

let issuer = Identity::load_or_generate(std::path::Path::new("/tmp/iam"))?;
let alice  = Principal::parse(&"ab".repeat(32))?;

let iam = Iam::new()
    .with_action_universe(["storage:read".into(), "storage:write".into()]);

// Mint a root grant: "alice may storage:read on any node".
let policy = simple_policy(vec!["storage:read".into()], ResourceMatch::Any, Conditions::default());
let grant  = iam.mint(&issuer, alice, &policy, /*nonce*/ 1)?;

// Verify offline on the resource owner's node — no policy server, no network.
iam.verify(
    &issuer.node_id(), &[], /*now*/ 0, &alice, "storage:read", &grant.token,
    &RevocationSet::empty().predicate(),
)?;
```

`Iam::attenuate` produces a narrower child link (refused *before signing* if it would broaden), and
`RevocationSet::fetch(&ce_rs::CeClient)` reads the live on-chain revoked set for the `is_revoked`
predicate. See `examples/delegate.rs` for a full mint → attenuate → verify → revoke walkthrough.

## CLI

```
ce-iam whoami                       # this machine's node id (the principal it acts as)

# --- grants ---
ce-iam grant   --to <node> --action storage:read --resource '*' --nonce 1
ce-iam grant   --parent <token> --to <node> --action storage:read --nonce 2   # attenuate (delegate)
ce-iam grant   --to <node> --role storage-reader --nonce 3                     # mint from a catalog role
ce-iam verify  --token <token> --requester <node> --action storage:read       # ALLOW/DENY (exit 0/1)
ce-iam verify  --wallet-label mygrant --requester <node> --action storage:read # verify a stored grant
ce-iam revoke  --nonce 1            # submit on-chain RevokeCapability (via the node API)
ce-iam revoked                      # list the on-chain revoked set

# --- policies ---
ce-iam policy  new   --action 'storage:*' --resource tag:gpu --expires-in 3600 # author a policy doc
ce-iam policy  validate policy.json                                            # validate + compile-check
ce-iam policy  inspect <token>                                                 # decode a grant's scope

# --- the durable role/policy catalog ---
ce-iam role    put reader --policy reader.json     # create/replace a role (or read policy from stdin)
ce-iam role    get reader                          # print a role
ce-iam role    list [--json]                       # list role + policy names
ce-iam role    rm reader                           # delete a role
ce-iam role    attach <principal> reader           # attach a role to a principal
ce-iam role    detach <principal> reader
ce-iam role    effective-grants <principal>        # what the catalog would mint for a principal
ce-iam role    audit [--since <version>]           # the catalog change log
ce-iam role    compact                             # snapshot + truncate the durable op-log

# --- wallet (held grant tokens) ---
ce-iam wallet  add mygrant <token> [--note ...]    # store a grant under a label (token may be stdin)
ce-iam wallet  list [--json]
ce-iam wallet  show mygrant                         # token + decoded scope
ce-iam wallet  rm mygrant

# --- accepted roots + rotation ---
ce-iam root    add <key> [--label org] [--valid-in <s>] [--valid-for <s>]  # accept a root w/ window
ce-iam root    list                                 # configured roots + accepted-now status
ce-iam root    retire <key> [--in-secs <s>]         # overlap-safe retirement (sets not_after)
ce-iam root    rm <key>                             # hard-remove
ce-iam root    reissue <token> --nonce 2            # migrate a root grant under this node's key
```

`grant`, `verify`, `policy *`, `role *`, `wallet *`, `root add|list|retire|rm|reissue`, and `whoami`
are fully offline. `verify` exits non-zero on DENY so scripts can branch on authorization. `verify`
consults the on-chain revocation set by default (`--no-revocation-check` to skip and rely on
expiries only; `--fail-closed` to deny when the revoke set is unfetchable and the cached snapshot is
stale). `revoke` and `revoked` call the node API. `--use-roots` makes `verify` honor the roots
configured via `root add` (filtered to those inside their validity window at the request time).

### Resource and condition syntax

- Resource: `*` / `any`, a 64-hex node id, `tag:<t>`, or `all-of:a,b,c`.
- Conditions:
  - `--expires-in <secs>` (0 = never) → `not_after`
  - `--activates-in <secs>` → `not_before` (future-dated / time-windowed grants)
  - `--max-cpu`, `--max-mem-mb`, `--max-credits` → resource ceilings
  - `--allowed-port <p>` (repeatable) → restrict tunnels to these remote ports
  - `--path-prefix <p>` → confine sync/file writes beneath this prefix

All conditions are enforced by `ce-cap` at verify time and are checked to *narrow only* during
attenuation (a child can never raise a ceiling, widen the port set, escape the path prefix, or
outlive its parent).

## Catalog, wallet, and roots (the managed product)

The security core (mint/attenuate/verify) is stateless. The *managed* surface adds three durable,
single-node stores under `<data_dir>/iam/`, each persisted **atomically** (temp-file + fsync +
rename, so a crash mid-write never corrupts the file):

- **`catalog.json`** — an append-only **op-log** of role/policy/attachment mutations. The live
  catalog is reconstructed by replaying the log on load (`CatalogStore`). This is the durable
  *writer half* of the ce-coord replicated-map model: exactly the local op-log a ce-coord writer
  persists before broadcasting. `role compact` snapshots current state and truncates history.
- **`wallet.json`** — labeled held grant tokens (`WalletStore`). A capability is a bearer token;
  the wallet is where you keep the ones you hold so `verify --wallet-label` can reference them.
- **`roots.json`** — accepted root keys with optional validity windows (`Roots`), for multi-root
  trust and root rotation.
- **`revocation-cache.json`** — the last-known-good revoked-set snapshot with a freshness TTL, used
  by `verify --fail-closed`.

### What is deferred (honest status)

The catalog is the durable, reload-stable, op-logged **writer half** of ce-coord — fully real and
tested. The **mesh-replication half** (broadcasting the op-log to other nodes and `await_version`
convergence across a live cluster) requires a running node and is **not yet wired**: today the
catalog is single-node durable, not multi-node replicated. The code and docs no longer claim
otherwise. Group/principal-set abstractions and richer AWS-style condition operators (source IP,
MFA, string/date/numeric matchers) are also deferred — see `SECURITY.md` and the design notes.

## Testing

```
cargo test
```

The suite is the foundation's validation and is meant to be read as the spec:

- **Unit tests** on every public function (happy + error paths) across `principal`, `policy`,
  `grant`, `catalog`, `store`, `wallet`, `roots`, and `revocation`.
- **Property tests** (`tests/prop_attenuation.rs`) for the security invariants over randomized
  inputs: *attenuation can never amplify* (depths 2 and 3), expiry honored, revocation honored,
  wrong-issuer and wrong-audience rejected, **malformed input is `Err` not panic**, token
  serialization round-trips, and **DoS bounds** (oversized tokens and over-deep chains rejected).
- **Failure injection** (`tests/integration.rs`): a dead / erroring node makes `RevocationSet::fetch`
  and `submit_revoke` return a graceful `IamError::Node`, never a panic; malformed wire rows are
  skipped rather than failing the whole snapshot.
- **Persistence integration** (`tests/store.rs`): the catalog/wallet/roots stores survive a reload,
  compaction is reload-stable, and a long write stream keeps every persisted prefix replayable.
- **CLI end-to-end** (`tests/cli.rs`): the built binary's grant/verify exit codes (0 ALLOW / 1
  DENY), `--json` shapes, `policy validate` from file and stdin, the role catalog and wallet flows,
  and a full root-rotation reissue → verify-under-new-root.

## Design notes

- Money is integer base units, decimal strings on the wire (per CE convention). `Conditions`
  surfaces a whole-credit `max_credits` ceiling that compiles to the `ce-cap` `max_credits` caveat.
- No `unsafe`; no `unwrap()` / `expect()` in non-test paths. Every fallible public fn returns
  `Result` with a typed `IamError`.
- **DoS bounds.** `Iam::verify`/`decode`/`inspect` reject a token over `max_token_bytes`
  (default 256 KiB) before decoding, and a chain over `max_chain_depth` (default 64) before
  per-link verification. Stores enforce a `MAX_STORE_BYTES` (64 MiB) read cap and per-store entry
  limits, and the in-memory audit trail is a bounded ring (`MAX_AUDIT_ENTRIES`).
- **Atomic persistence.** All on-disk state is written temp-file + fsync + rename; a crash mid-write
  leaves the old or new file intact, never a half-written one. A missing file loads as the type's
  default; an oversized one is a clear error, never a panic.
- **Overflow safety.** All time arithmetic (`expires_in`, `activates_in`, root windows) uses
  `saturating_add`, so a huge CLI value can never wrap to a tiny/garbage timestamp.
- Edition 2024.

See `SECURITY.md` for the verifier trust model and how to operate revocation freshness, and
`CHANGELOG.md` for the change history.

## License

MIT.
