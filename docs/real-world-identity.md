# ce-iam: real-world identity, 2FA, and distributed auth providers

Status: design / plan (2026-06-26). Extends ce-iam from "a principal is a key" to "a principal can be
**attested** to a real-world identity by independent providers, building **trust** — the Sybil
foundation for the economy." Goal: production auth that feels like a modern product (Claude-grade
login + 2FA), with BankID/Google/OIDC and a federated, no-central-authority provider model.

## 1. Core object: the Attestation
Today a CE principal = an Ed25519 node id; possession of the key *is* the identity. We add a verifiable
claim that binds that key to something real:

```
Attestation {
  provider:    NodeId,        // the attestor's CE key (e.g. the BankID attestor)
  subject:     NodeId,        // the node being attested
  claim:       Claim,         // what was verified (below)
  level:       u8,            // assurance: 0 email .. 3 strong-eID (BankID)
  pseudonym:   [u8;32],       // per-provider, per-context pseudonym (NOT the raw identity)
  issued, expires, nonce,
  sig:         [u8;64],       // provider signs the above
}
enum Claim { UniqueHuman, EmailVerified(hash), DomainControl(host), OrgMember(org), Custom(k,v) }
```

Key properties:
- **Verifiable offline** like a capability: check `sig` against the provider's known key. No central
  server in the hot path (same philosophy as ce-cap).
- **Privacy-preserving by default:** the attestation carries a *pseudonym* (e.g. HMAC(provider_secret,
  real_subject, context)) + a level, NOT the name/personal-number. It proves "one unique strong-eID
  human" without doxxing. Full-identity claims are opt-in for contexts that need them.
- **Revocable:** short expiry + on-chain `RevokeAttestation{provider,nonce}` (reuse the existing
  revocation set), and provider key rotation.
- Stored in the wallet next to capabilities; an on-chain *hash anchor* makes them discoverable +
  revocable without publishing contents.

## 2. External identity providers (attestor services)
An **attestor** is a CE principal that runs an IdP flow, verifies a human, and issues an Attestation.
Anyone can run one; relying parties choose which to trust (§4).

- **BankID** (Swedish strong eID — the high-trust anchor): attestor is a BankID Relying Party (needs an
  RP cert). Flow: user signs with BankID → attestor verifies the assertion → issues
  `Claim::UniqueHuman, level=3, pseudonym=HMAC(secret, personalnumber, ctx)`. One BankID ⇒ one
  pseudonym per context ⇒ **Sybil-resistant without storing the personal number**.
- **Google / generic OIDC** (`level=1–2`): standard OAuth2/OIDC authorization-code + PKCE → attestor
  verifies the ID token → `EmailVerified` / `UniqueHuman`. Generic OIDC covers Microsoft, Apple,
  GitHub, Okta, etc. with one connector.
- **Lightweight:** email/SMS OTP (level 0), domain-control, org SSO.

Attestor service = an `ce-rs::serve` mesh app: `POST attest/start {method}` → provider-specific
challenge/redirect; `attest/finish` → verify + return a signed Attestation. Mesh-native, capability-
gated, no bespoke HTTP origin.

## 3. 2FA / step-up (the Claude-grade feel)
- **Factor 1:** the node key (possession).
- **Factor 2:** TOTP, **WebAuthn/passkeys**, or **paired-device push-approval** (approve on your phone —
  we already have device pairing + the secrets vault; reuse it).
- **Sessions + step-up:** a session has a TTL; *sensitive* ops (mint a root, revoke, attach a powerful
  role, high-value transfer, link a new provider) require fresh 2FA — exactly like Claude asking again
  for sensitive actions. Encoded as a caveat on the session capability (`requires_2fa_after`).
- **Recovery:** device-set + recovery-key (Shamir across your paired devices / printable codes). No
  central password reset.

## 4. Distributed / federated providers (no central authority)
- A **Provider Registry** (on ce-hub) lists attestors: `provider key → {method, level, operator}`.
- A relying party (a node, an app, the economy) holds a **Trust Policy**: which providers it trusts and
  at what weight (e.g. "BankID=1.0, Google=0.4, email=0.1; require ≥0.6 for paid work").
- A node's **trust** = aggregate of its attestations under the verifier's policy. No single root of
  truth; it's federated + web-of-trust, and each verifier decides. Providers can also cross-attest each
  other.

## 5. Trust → economy & Sybil (why this exists)
- Attestations drive the existing **trust gradient** (`ce/docs/sybil-resistance.md`, trust-and-economy):
  trust gates priced work, governance vote weight, resource access, bond requirements.
- **Sybil resistance:** strong-eID (BankID) makes identities scarce — you can't mint 1000 verified
  humans. Unattested nodes still work but at low trust / higher bond. This is the real-world anchor the
  threat model wants.

## 6. API surface (iterate toward this; clean + uniform)
```
ce-iam login                 # device + 2FA -> a session capability
ce-iam attest <provider>     # run BankID/Google/OIDC -> store an Attestation
ce-iam whoami                # node id, attestations, computed trust level
ce-iam providers             # registry; add/trust a provider with a weight
ce-iam 2fa add <totp|passkey|device>   /   ce-iam step-up
ce-iam verify <attestation>  # offline check against provider key + policy
Iam::attest / verify_attestation / trust_of(node, policy)   # library/SDK + WASM + TS parity
```

## 7. Phases
1. **Attestation model + verify** in `ce-iam-core` (offline-verifiable; wallet storage; on-chain anchor + RevokeAttestation). WASM + TS parity.
2. **OIDC attestor** (Google first) as a mesh `serve` app + `ce-iam attest google`.
3. **BankID attestor** (the strong anchor; pseudonymous claims).
4. **2FA / step-up** (TOTP + WebAuthn/passkeys + device-push) + sessions.
5. **Trust scoring** → wire into the trust gradient / economy / governance.
6. **Provider registry + trust policy** on ce-hub; federation + cross-attestation.

Security review gates each phase (`ce-iam/SECURITY.md`): provider-key compromise blast radius, replay,
pseudonym unlinkability, step-up bypass, revocation latency. Every flow has an e2e test (the new
harness) before it ships.
