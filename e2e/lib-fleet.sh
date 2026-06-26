#!/usr/bin/env bash
# Fleet abstraction for ce-iam e2e: brings up N fresh ce nodes (each with the `ce` node + `ceiam` CLI),
# over either real Hetzner VMs or isolated containers on the relay. Exposes a uniform interface so the
# security tests don't care which backend runs them:
#
#   fleet_up N        # provision N fresh nodes, deploy ce + ceiam, start nodes
#   node N "cmd"      # run a shell command on node N (ceiam/ce live on PATH there)
#   node_id N         # node N's ce node id (hex)
#   node_kill N       # stop node N's ce process (fault injection)
#   node_revive N     # restart it
#   fleet_down        # destroy everything (idempotent)
#
# Binaries: a glibc-correct linux build of `ce` and `ceiam` must be published as content-addressed
# blobs / release assets (see ce-iam/docs/real-world-identity.md + the ce-hub binary-distribution plan).
# CE_URL/CEIAM_URL point at them; nodes fetch + checksum-verify.
set -uo pipefail
: "${PROVIDER:=relay}"
: "${RELAY_HOST:=178.105.145.170}"
: "${RELAY_MA:=/ip4/172.17.0.1/tcp/4001/p2p/12D3KooWC6vyMMrtmdWEdpcMx7JZ4Ze5scUhA6BbMdYqnUDC7nr7}"
: "${IMG:=ubuntu:24.04}"                 # MUST match build glibc (relay = Ubuntu 24.04 / glibc 2.39)
SSHK="${SSHK:-$HOME/.ssh/id_ed25519}"
RSSH="ssh -i $SSHK -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
_relay(){ $RSSH "root@$RELAY_HOST" "$@"; }
FLEET_IDS=""

# --- relay-container backend (runs today; VM quota-independent) ----------------------------------
_c(){ echo "ceiam-e2e-$1"; }   # container name for node N
fleet_up_relay(){
  local n=$1 i
  # deploy ce + ceiam into a shared host dir the containers mount
  _relay 'mkdir -p /root/ceiam-e2e && cp /usr/local/bin/ce /root/ceiam-e2e/ce 2>/dev/null; [ -f /root/ceiam-e2e/ceiam ] || echo NO_CEIAM' | grep -q NO_CEIAM && {
    echo "lib-fleet: ceiam binary not staged on relay (/root/ceiam-e2e/ceiam). Build+publish the linux ceiam first." >&2; return 1; }
  for i in $(seq 1 "$n"); do
    _relay "docker rm -f $(_c "$i") >/dev/null 2>&1; docker run -d --name $(_c "$i") -v /root/ceiam-e2e:/opt/ce:ro $IMG sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null 2>&1; apt-get install -yq libssl3 ca-certificates >/dev/null 2>&1; ln -sf /opt/ce/ce /usr/local/bin/ce; ln -sf /opt/ce/ceiam /usr/local/bin/ceiam; /usr/local/bin/ce start --light --bootstrap $RELAY_MA --relay $RELAY_MA > /var/log/ce.log 2>&1' >/dev/null"
  done
  sleep 8
  for i in $(seq 1 "$n"); do _relay "docker ps --format '{{.Names}}' | grep -q $(_c "$i")" || { echo "node$i failed to start" >&2; return 1; }; done
}
node_relay(){ local n=$1; shift; _relay "docker exec $(_c "$n") sh -lc \"$*\""; }
node_id_relay(){ node_relay "$1" "/usr/local/bin/ce status 2>/dev/null" | grep -oE 'node id *: *[0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | head -1; }
node_kill_relay(){ _relay "docker exec $(_c "$1") pkill -9 -f 'ce start'" 2>/dev/null || true; }
node_revive_relay(){ _relay "docker exec -d $(_c "$1") sh -c '/usr/local/bin/ce start --light --bootstrap $RELAY_MA --relay $RELAY_MA >> /var/log/ce.log 2>&1'"; }
fleet_down_relay(){ for i in 1 2 3 4 5 6 7 8; do _relay "docker rm -f $(_c "$i") >/dev/null 2>&1" || true; done; }

# --- Hetzner VM backend (real fresh VMs; needs server quota > 1) ---------------------------------
# Mirrors e2e/vm-e2e.sh (workspace root). Falls back here when PROVIDER=hetzner.
fleet_up_hetzner(){ echo "lib-fleet: Hetzner backend — see workspace e2e/vm-e2e.sh; blocked while account server-limit=1." >&2; return 1; }

# --- dispatch -----------------------------------------------------------------------------------
fleet_up(){    [ "$PROVIDER" = hetzner ] && fleet_up_hetzner "$@" || fleet_up_relay "$@"; }
node(){        [ "$PROVIDER" = hetzner ] && { echo "hetzner node() TODO"; return 1; } || node_relay "$@"; }
node_id(){     [ "$PROVIDER" = hetzner ] && return 1 || node_id_relay "$@"; }
node_kill(){   node_kill_relay "$@"; }
node_revive(){ node_revive_relay "$@"; }
fleet_down(){  fleet_down_relay; }
