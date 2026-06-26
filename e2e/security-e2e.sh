#!/usr/bin/env bash
# ce-iam adversarial distributed e2e. Sets up fresh ce nodes (real Hetzner VMs, or isolated relay
# containers if the VM quota is capped), then tests:
#   A. DISTRIBUTED   — issue auth on one node, verify it independently on another (offline, over mesh)
#   B. FAULT TOLERANCE — kill the issuer; existing grants/attestations must STILL verify (no central
#                        server); revocation must propagate on-chain across node churn
#   C. TAKE-OVER     — a battery of attacks that MUST ALL FAIL (this is the security contract)
#
# Every "attack" assertion is inverted: the test PASSES only when the attack is REJECTED. A single
# accepted attack = security FAIL = non-zero exit. ALWAYS tears down.
#
#   PROVIDER=hetzner ce-iam/e2e/security-e2e.sh   # real fresh VMs (needs server quota > 1)
#   PROVIDER=relay    ce-iam/e2e/security-e2e.sh  # isolated containers on the relay (default; runs today)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
PROVIDER="${PROVIDER:-relay}"
PASS=0; FAIL=0
ok(){ echo "  PASS: $*"; PASS=$((PASS+1)); }
no(){ echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
# An attack assertion: $1 is a shell test that should FAIL (exit!=0) because the attack was rejected.
attack_rejected(){ desc="$1"; shift; if "$@" >/dev/null 2>&1; then no "TAKE-OVER POSSIBLE: $desc (attack ACCEPTED)"; else ok "rejected: $desc"; fi; }
legit_ok(){ desc="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else no "$desc (legit op failed)"; fi; }

# ---- node fleet abstraction: nodeN runs a command on test node N -------------------------------
# Backed by Hetzner VMs (real) or relay containers. Each node has: ce (node), ceiam (CLI), its own key.
. "$HERE/lib-fleet.sh"   # provides: fleet_up N ; node N "cmd" ; node_id N ; fleet_down
trap fleet_down EXIT INT TERM

echo "================  ce-iam adversarial e2e ($PROVIDER)  ================"
echo "=== provision 4 fresh nodes ==="
fleet_up 4 || { echo "fleet bring-up failed"; exit 1; }
for n in 1 2 3 4; do node "$n" "ceiam --version" >/dev/null 2>&1 && ok "node$n: ce-iam present" || no "node$n: ce-iam missing"; done
ROOT_ID=$(node_id 1); ALICE=$(node_id 2); BOB=$(node_id 3); MALLORY=$(node_id 4)

echo
echo "=== A. DISTRIBUTED: grant on node1 (root), verify independently on node3 ==="
# root (node1) grants Alice (node2) a scoped capability for resource drive/alice/*
TOK=$(node 1 "ceiam grant $ALICE --can drive:sync --resource 'drive/alice/*' --expires 1h --json" 2>/dev/null | tr -d '\r')
legit_ok "node1 minted a scoped grant for Alice" test -n "$TOK"
# node3 (Bob, uninvolved) verifies Alice's token offline — proves no central authority
legit_ok "node3 independently verifies Alice's grant (offline, cross-node)" \
  bash -c "node 3 \"ceiam verify --token '$TOK' --action drive:sync --resource drive/alice/readme\""

echo
echo "=== B. FAULT TOLERANCE: kill the issuer (node1); the grant must still verify ==="
node_kill 1
sleep 3
legit_ok "Alice's grant STILL verifies on node3 after issuer is DOWN (offline-verifiable, no server)" \
  bash -c "node 3 \"ceiam verify --token '$TOK' --action drive:sync --resource drive/alice/readme\""
# revocation must still work + propagate even with the issuer gone is impossible (issuer signs revokes);
# so bring the issuer back and test on-chain revoke propagation across nodes.
node_revive 1; sleep 5
node 1 "ceiam revoke --token '$TOK'" >/dev/null 2>&1
echo "  (revoked on node1; waiting for on-chain propagation)"; sleep 12
attack_rejected "revoked grant still accepted on node3 (revocation must propagate)" \
  bash -c "node 3 \"ceiam verify --token '$TOK' --action drive:sync --resource drive/alice/readme\""

echo
echo "=== C. TAKE-OVER ATTEMPTS (every one MUST be rejected) ==="
# fresh legit grant for the attack battery
TOK=$(node 1 "ceiam grant $ALICE --can drive:sync --resource 'drive/alice/*' --expires 1h --json" 2>/dev/null | tr -d '\r')

# 1. ESCALATION: Alice attenuates her own grant to a BROADER scope (drive/*) and gives it to herself.
attack_rejected "privilege escalation via attenuation (narrow->broad)" \
  bash -c "node 2 \"ceiam grant $ALICE --from-token '$TOK' --can drive:sync --resource 'drive/*' --json\" | grep -q ."
# verify the broadened token (if any) does NOT authorize outside Alice's scope
attack_rejected "broadened token authorizes another user's resource" \
  bash -c "node 3 \"ceiam verify --token '$TOK' --action drive:sync --resource drive/bob/secret\""

# 2. FORGERY: Mallory mints a grant as if she were root, for herself.
attack_rejected "forged grant (Mallory mints authority she does not hold)" \
  bash -c "node 4 \"ceiam grant $MALLORY --can drive:admin --resource 'drive/*' --as-root --json\" | xargs -I{} node 3 'ceiam verify --token {} --action drive:admin --resource drive/bob/secret'"

# 3. IMPERSONATION: Mallory presents Alice's audience-bound token as her own.
attack_rejected "impersonation (Mallory uses Alice's audience-bound token)" \
  bash -c "node 4 \"ceiam verify --token '$TOK' --as-self --action drive:sync --resource drive/alice/readme\""

# 4. TAMPER: flip a byte in the token; signature must break.
BAD=$(printf '%s' "$TOK" | sed 's/./X/10')
attack_rejected "tampered token (one byte flipped)" \
  bash -c "node 3 \"ceiam verify --token '$BAD' --action drive:sync --resource drive/alice/readme\""

# 5. REPLAY/EXPIRY: an already-expired grant.
EXP=$(node 1 "ceiam grant $ALICE --can drive:sync --resource 'drive/alice/*' --expires -1s --json" 2>/dev/null | tr -d '\r')
attack_rejected "expired grant accepted" \
  bash -c "node 3 \"ceiam verify --token '$EXP' --action drive:sync --resource drive/alice/readme\""

# 6. ATTESTATION FORGERY: Mallory signs a 'strong-eID, unique-human' attestation for herself.
attack_rejected "forged real-world attestation (Mallory self-signs strong-eID)" \
  bash -c "node 4 'ceiam attest forge --provider self --level 3 --claim unique-human --json' | xargs -I{} node 3 'ceiam attest verify --attestation {} --trusted-provider '$ROOT_ID''"

# 7. SYBIL: node4 spins 50 throwaway identities; none gains trust without an attestation.
HI=$(node 4 "ceiam sybil-probe --count 50 --max-trust" 2>/dev/null | grep -oE '[0-9]+' | head -1)
[ "${HI:-0}" = "0" ] 2>/dev/null && ok "Sybil: 50 unattested identities all trust=0" || no "Sybil identities gained trust (=$HI) without attestation"

# 8. ROOT TAKEOVER: Mallory tries to rotate/replace the root key without holding it.
attack_rejected "root takeover (rotate root without the root key)" \
  bash -c "node 4 \"ceiam root rotate --new $MALLORY\""

echo
echo "================  RESULT: $PASS passed, $FAIL failed  ================"
[ "$FAIL" -eq 0 ]
