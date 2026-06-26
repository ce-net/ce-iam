# ce-iam adversarial distributed e2e

Real e2e tests that set up **fresh ce nodes** and attack the auth system. The contract: every
take-over attempt must be **rejected**; legit distributed flows must work even under node failure.

- `security-e2e.sh` — the suite: **A. distributed** (issue on one node, verify on another, offline),
  **B. fault tolerance** (kill the issuer — grants still verify; revocation propagates on-chain),
  **C. take-over battery** (escalation, forgery, impersonation, tamper, replay/expiry, attestation
  forgery, Sybil, root takeover) — each PASSES only when the attack FAILS.
- `lib-fleet.sh` — fleet backend: real **Hetzner VMs** (`PROVIDER=hetzner`) or isolated **relay
  containers** (`PROVIDER=relay`, default). Uniform `node N "cmd"` / `node_kill` / `node_revive`.

## Run
```
PROVIDER=relay    bash e2e/security-e2e.sh    # containers on the relay (works today, no VM quota)
PROVIDER=hetzner  bash e2e/security-e2e.sh    # real fresh VMs (needs Hetzner server-quota > 1)
```

## Status / prerequisites (honest)
This is the full security CONTRACT; it goes green phase-by-phase as ce-iam ships:
- Needs a **glibc-correct linux `ceiam` binary** staged for the nodes (build blocker: ce-iam has
  path-deps to sibling repos; build on a linux box that has the workspace, publish as a content-
  addressed blob — see `docs/real-world-identity.md` + the ce-hub binary-distribution plan).
- **Cap take-over tests** (escalation/forgery/impersonation/tamper/expiry/revocation) exercise
  EXISTING commands (`grant`/`verify`/`revoke`) — runnable as soon as the CLI is deployed.
- **Attestation / Sybil / root** tests gate on Phases 2–6. The attestation *cryptographic* take-over
  resistance (forge/tamper/wrong-provider/expiry) is ALREADY covered by Phase-1 unit tests in
  `ce-iam-core/src/attestation.rs`.
- **Hetzner VM** backend blocked while the account server-limit = 1 (raise it; `e2e/vm-e2e.sh` at the
  workspace root is the same provisioner).

A take-over test that "passes" only because its command doesn't exist yet is a FALSE green — the suite
is wired so each attack is a real command once its phase lands.
