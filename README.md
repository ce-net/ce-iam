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
ce-iam grant   --to <node> --action storage:read --resource '*' --nonce 1
ce-iam grant   --parent <token> --to <node> --action storage:read --nonce 2   # attenuate (delegate)
ce-iam verify  --token <token> --requester <node> --action storage:read       # ALLOW/DENY (exit 0/1)
ce-iam revoke  --nonce 1            # submit on-chain RevokeCapability (via the node API)
ce-iam policy  new   --action 'storage:*' --resource tag:gpu --expires-in 3600 # author a policy doc
ce-iam policy  validate policy.json                                            # validate + compile-check
ce-iam policy  inspect <token>                                                 # decode a grant's scope
```

`grant`, `verify`, `policy inspect`, and `whoami` are fully offline. `verify` exits non-zero on
DENY so scripts can branch on authorization. `verify` consults the on-chain revocation set by
default (`--no-revocation-check` to skip and rely on expiries only). `revoke` calls the node's
authenticated `POST /capabilities/revoke` (the one endpoint `ce-rs` does not wrap, so `ce-iam`
issues it directly).

### Resource and condition syntax

- Resource: `*` / `any`, a 64-hex node id, `tag:<t>`, or `all-of:a,b,c`.
- Conditions: `--expires-in <secs>` (0 = never), `--max-cpu`, `--max-mem-mb`, `--max-credits`.

## Testing

```
cargo test
```

The suite is the foundation's validation and is meant to be read as the spec:

- **Unit tests** on every public function (happy + error paths) across `principal`, `policy`,
  `grant`, and `revocation`.
- **Property tests** (`tests/prop_attenuation.rs`) for the security invariants over randomized
  inputs: *attenuation can never amplify*, expiry honored, revocation honored, wrong-issuer and
  wrong-audience rejected, **malformed input is `Err` not panic**, and token serialization
  round-trips.
- **Failure injection** (`tests/integration.rs`): a dead / erroring node makes `RevocationSet::fetch`
  and `submit_revoke` return a graceful `IamError::Node`, never a panic; malformed wire rows are
  skipped rather than failing the whole snapshot.

## Design notes

- Money is integer base units, decimal strings on the wire (per CE convention). `Conditions`
  surfaces a whole-credit `max_credits` ceiling that compiles to the `ce-cap` `max_credits` caveat.
- No `unsafe`; no `unwrap()` / `expect()` in non-test paths. Every fallible public fn returns
  `Result` with a typed `IamError`.
- Edition 2024.

## License

MIT.
