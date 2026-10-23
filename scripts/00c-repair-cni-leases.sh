#!/usr/bin/env bash
# Reclaim an exhausted flannel/host-local IPAM pool.
#
#   ./scripts/00c-repair-cni-leases.sh          # confirm first
#   ./scripts/00c-repair-cni-leases.sh -y       # no prompt
#
# Run this only after 00b-diagnose-pod-network.sh says the pool is exhausted.
#
# WHY IT IS SAFE TO BE BLUNT HERE, AND WHY IT WOULD NOT BE IN PRODUCTION:
# every pod on this node was installed from git by 00/01/02 and holds no
# state. So the correct repair is to stop everything, delete every lease file,
# and start again - which guarantees no lease outlives its container.
#
# Deleting lease files while pods are RUNNING is the dangerous version: the
# file is the only record that an address is taken, so host-local would hand
# the same address to a second pod and you would have two pods with one IP
# and intermittent, direction-dependent connection failures. That is why this
# stops k3s first rather than cleaning live.
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m!!! %s\033[0m\n' "$*" >&2; exit 1; }

LEASE_DIR=/var/lib/cni/networks/cbr0
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

BEFORE="$(sudo ls "$LEASE_DIR" 2>/dev/null | grep -c '^10\.' || echo 0)"
log "Leases currently on disk: $BEFORE of 254"
[ "$BEFORE" -eq 0 ] && { ok "nothing to reclaim"; exit 0; }

if [[ "${1:-}" != "-y" ]]; then
  warn "This stops k3s, kills every container on the node, deletes all"
  warn "$BEFORE lease files, and starts k3s again. Pods are recreated by"
  warn "their controllers; nothing here holds state worth keeping."
  read -r -p "    Proceed? [y/N] " a
  [[ "${a:-}" =~ ^[Yy]$ ]] || die "Stopped."
fi

log "Stopping k3s and every container"
# k3s-killall.sh is the right tool: it stops the service, kills the
# containers, unmounts the pod mounts and tears down the CNI network
# namespaces. `systemctl stop k3s` alone leaves containerd shims running,
# and a lease whose container is still alive is exactly what we must avoid.
sudo /usr/local/bin/k3s-killall.sh >/dev/null 2>&1 || warn "k3s-killall.sh reported an error; continuing"
sleep 3
ok "stopped"

log "Deleting lease files"
sudo rm -rf "$LEASE_DIR"
# last_reserved_ip.0 lives one level up in some layouts; remove the whole
# per-network dir so host-local starts from a clean slate.
sudo rm -f /var/lib/cni/networks/last_reserved_ip.0 2>/dev/null || true
ok "removed $BEFORE leases"

log "Starting k3s"
sudo systemctl start k3s

# Wait for the node to REGISTER before waiting on its condition - `kubectl
# wait --all` exits 1 immediately on an empty set rather than waiting.
for _ in $(seq 1 60); do
  [ "$(kubectl get nodes --no-headers 2>/dev/null | wc -l)" -gt 0 ] && break
  sleep 2
done
kubectl wait --for=condition=Ready node --all --timeout=180s
ok "node Ready"

log "Did the CNI config survive, and is istio-cni still chained?"
CONF="$(sudo grep -rl istio-cni /var/lib/rancher/k3s/agent/etc/cni/net.d 2>/dev/null | head -1 || true)"
if [ -n "$CONF" ]; then
  ok "istio-cni still chained into $(basename "$CONF")"
else
  warn "istio-cni is NOT in the CNI chain right now."
  warn "The istio-cni-node DaemonSet watches for this and re-chains itself"
  warn "once it is Running. Give it a minute, then check:"
  warn "    ./scripts/00a-diagnose-cni.sh"
fi

log "Waiting for the system pods to get addresses"
sleep 20
kubectl get pods -A -o wide --no-headers 2>/dev/null \
  | awk '{printf "    %-14s %-46s %-20s %s\n", $1, $2, $4, $7}' | head -20

AFTER="$(sudo ls "$LEASE_DIR" 2>/dev/null | grep -c '^10\.' || echo 0)"
STUCK="$(kubectl get pods -A --no-headers 2>/dev/null | awk '$4!="Running" && $4!="Completed"' | wc -l)"
log "Result"
ok  "leases: $BEFORE -> $AFTER"
if [ "$STUCK" -eq 0 ]; then
  ok "every pod is Running or Completed"
  ok "Now re-run:  tmux new -s zt   then   ./scripts/01-install-policy-engines.sh"
else
  warn "$STUCK pod(s) still not Running - give it another minute, then:"
  warn "    ./scripts/00b-diagnose-pod-network.sh"
  warn "If the pool is refilling, the CAUSE is still present. Do not just"
  warn "re-run this script; the leak will come back."
fi
