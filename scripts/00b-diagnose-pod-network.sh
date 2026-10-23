#!/usr/bin/env bash
# Why can no new pod get an IP?
#
#   ./scripts/00b-diagnose-pod-network.sh
#
# Read-only. Run this when you see:
#
#   plugin type="flannel" failed (add): failed to allocate for range 0:
#   no IP addresses available in range set: 10.42.0.1-10.42.0.254
#
# THAT MESSAGE IS A SYMPTOM, NOT A CAUSE, and it is actively misleading
# because it names flannel. A single-node k3s cluster gets a /24 - 254 usable
# addresses - and this lab runs about ten pods. Exhausting it means addresses
# were allocated and never released.
#
# host-local (the IPAM plugin flannel delegates to) keeps one file per leased
# address under /var/lib/cni/networks/cbr0/, named for the IP and containing
# the container ID that holds it. The lease is released when the runtime calls
# CNI DEL. A sandbox that fails to come up AFTER its IP is allocated - a later
# plugin in the chain erroring, the runtime giving up, a kill at the wrong
# moment - can leave the file behind with no container.
#
# That leak is self-accelerating: the kubelet retries a failed sandbox every
# few seconds, each retry takes another address, and after ~254 retries every
# pod on the node fails for a reason that has nothing to do with the original
# fault. One transient CNI error becomes a permanent cluster-wide outage, and
# the original error is no longer in the logs anybody reads.
#
# So this script measures the LEAK and then digs for the FIRST failure.
set -uo pipefail

ok()   { printf '\033[1;32m  PASS  %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m  FAIL  %s\033[0m\n' "$*"; }
info() { printf '        %s\n' "$*"; }
log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

LEASE_DIR=/var/lib/cni/networks/cbr0
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

log "1. How many addresses are leased, and how many pods actually exist?"
LEASES="$(sudo ls "$LEASE_DIR" 2>/dev/null | grep -c '^10\.' || echo 0)"
PODS="$(kubectl get pods -A -o wide --no-headers 2>/dev/null \
        | awk '$7 ~ /^10\.42\./ {n++} END{print n+0}')"
info "leases on disk in $LEASE_DIR : $LEASES"
info "pods currently holding a 10.42.x address: $PODS"
LEAK=$(( LEASES - PODS ))
if [ "$LEASES" -ge 250 ]; then
  bad "pool is exhausted or nearly so ($LEASES / 254)"
elif [ "$LEAK" -gt 20 ]; then
  bad "roughly $LEAK leases belong to no pod - leaking"
else
  ok "$LEASES leases, $PODS pods - no significant leak"
fi
info ""
info "oldest and newest lease files:"
sudo ls -lt --time=birth "$LEASE_DIR" 2>/dev/null | tail -3 | sed 's/^/          /'
sudo ls -lt "$LEASE_DIR" 2>/dev/null | sed -n '2,4p' | sed 's/^/          /'

log "2. THE FIRST FAILURE - everything after it may just be the cascade"
# Exclude the exhaustion message to find what went wrong BEFORE the pool
# emptied. If this section is empty, the leak started without a CNI error and
# the cause is upstream of CNI (a crash-looping pod, or a kill mid-sandbox).
# DO NOT TRUNCATE THESE LINES FROM THE LEFT. The first version of this script
# printed `cut -c1-200`, and the informative part of a CNI error sits at the
# END of the line - after the kubelet prefix, the error-wrapper text and a
# 64-character sandbox id. The reason the plugin actually gave was cut off, so
# the script located the trigger and then hid it. Extract the plugin clause.
SINCE="${SINCE:-12 hours ago}"
NONEXH="$(sudo journalctl -u k3s --no-pager --since "$SINCE" 2>/dev/null \
          | grep -F 'failed (add)' | grep -v 'no IP addresses available' || true)"
if [ -n "$NONEXH" ]; then
  bad "a non-exhaustion CNI failure came first:"
  info "first occurrence: $(printf '%s\n' "$NONEXH" | head -1 | awk '{print $1, $2, $3}')"
  info ""
  info "distinct plugin errors, most frequent first:"
  # Keep everything from `plugin type=` to end of line, with sed rather than a
  # quote-aware regex: journald prints these inside err="...", so the inner
  # quotes arrive backslash-escaped as \" and any pattern written against bare
  # quotes matches nothing. Dropping the prefix sidesteps the quoting entirely.
  printf '%s\n' "$NONEXH" | grep -F 'plugin type=' \
    | sed 's/.*plugin type=/plugin type=/; s/[[:space:]]*$//' \
    | sort | uniq -c | sort -rn | head -6 \
    | cut -c1-150 | sed 's/^/          /'
  info ""
  info "the first such line in full, wrapped rather than cut:"
  printf '%s\n' "$NONEXH" | head -1 | fold -w 108 -s | sed 's/^/          /'
else
  info "no non-exhaustion CNI errors in the journal."
  info "The pool emptied through retries, not through a plugin fault."
fi
info ""
info "first exhaustion message, for the timeline:"
sudo journalctl -u k3s --no-pager --since '6 hours ago' 2>/dev/null \
  | grep -F 'no IP addresses available' | head -1 | cut -c1-160 | sed 's/^/          /'

log "3. Is istio-cni in the chain complaining?"
if kubectl -n istio-system get ds/istio-cni-node >/dev/null 2>&1; then
  E="$(kubectl -n istio-system logs ds/istio-cni-node --tail=2000 2>/dev/null \
       | grep -iE 'error|fail|denied' | grep -v 'level=info' | head -8)"
  if [ -n "$E" ]; then
    bad "istio-cni logged errors:"
    echo "$E" | fold -w 108 -s | sed 's/^/          /'
  else
    ok "no errors in the istio-cni-node log buffer"
    # Be precise about what this proves. It reads a bounded tail of a LIVE
    # pod: an error hours old has scrolled off, and a pod restart loses the
    # buffer entirely. A PASS here means "not failing now" and never "did not
    # fail then". Section 2 reads the journal, which is persistent, and is the
    # one to trust about the past.
    info "(bounded tail of a live pod - says nothing about hours ago)"
  fi
else
  info "istio-cni-node not installed"
fi

log "4. The CNI chain and flannel's own view of the subnet"
CONF="$(sudo grep -rl cniVersion /var/lib/rancher/k3s/agent/etc/cni/net.d 2>/dev/null | head -1)"
info "config: ${CONF:-none found}"
[ -n "$CONF" ] && sudo cat "$CONF" | jq -r '.plugins[]?.type' 2>/dev/null | sed 's/^/          - /'
info "flannel subnet.env:"
sudo cat /run/flannel/subnet.env 2>/dev/null | sed 's/^/          /' || info "          (absent)"

log "5. Pods that are not Running - the ones generating the retries"
kubectl get pods -A --no-headers 2>/dev/null \
  | awk '$4 != "Running" && $4 != "Completed" {print "        " $0}' | head -15
C="$(kubectl get pods -A --no-headers 2>/dev/null | awk '$4!="Running" && $4!="Completed"' | wc -l)"
info "$C pod(s) not Running"

log "Verdict"
if [ "$LEASES" -ge 250 ]; then
  bad "IPAM pool exhausted. Reclaim it:  ./scripts/00c-repair-cni-leases.sh"
  info "That script is destructive to running pods and safe for this lab -"
  info "everything on the node was installed from git by 00/01/02."
  info ""
  info "Fix the CAUSE too, or it refills. If section 2 named a plugin"
  info "failure, that is the cause. If it did not, the trigger was a pod"
  info "that could not start for an unrelated reason and then retried itself"
  info "into exhaustion - find it in section 5."
else
  ok "IPAM is not the problem right now"
fi
exit 0
