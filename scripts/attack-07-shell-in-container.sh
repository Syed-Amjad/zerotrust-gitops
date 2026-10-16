#!/usr/bin/env bash
# ATTACK 7 — spawn a shell in a running container. Expect Falco to alert.
#
#   ./scripts/attack-07-shell-in-container.sh
#
# The only attack in the set that SUCCEEDS. That is the point of layer 7.
#
# Layers 1 to 6 are preventive: they refuse things at admission or in the
# network path. None of them has anything to say about a process that is
# already running inside a container that was correctly signed, correctly
# admitted and correctly isolated. If an attacker reaches code execution —
# through a dependency, a deserialisation bug, a leaked credential — every
# preventive control has already been satisfied.
#
# Falco does not prevent. It observes syscalls and says what happened. The
# honest claim is detection, not protection, and conflating the two is how a
# detection layer gets credit for stopping something it merely noticed.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

attack_header 7 "Shell spawned in a running container" \
  "7 — Falco runtime behavioural detection" \
  "The shell SUCCEEDS. Falco alerts, with full Kubernetes context"

POD="$(kubectl -n zt-prod get pod -l app=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
[[ -n "$POD" ]] || { bad "No api pod found. Has ArgoCD synced the workloads?"; exit 1; }

hdr "Timestamp, so the alert can be tied to this action"
SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "$SINCE"

hdr "Executing a shell in $POD, and three things inside it"
note "One exec session, deliberately tripping three independent rules."
rule
kubectl -n zt-prod exec -i "$POD" -c api -- sh -c '
  echo "  [1] shell running as uid $(id -u) in $(hostname)"

  # Rule: Sensitive file read in a governed namespace
  echo "  [2] reading /etc/shadow"
  head -c 60 /etc/shadow 2>&1 | head -1 || echo "      refused"

  # Rule: Write attempt to a system directory. This FAILS with EROFS, which is
  # layer 3 working — and is exactly the case the built-in open_write macro
  # cannot see, because it requires a successful open. The custom rule drops
  # that condition on purpose.
  echo "  [3] attempting to write /usr/bin/evil"
  touch /usr/bin/evil 2>&1 | head -1 || echo "      refused (expected: read-only filesystem)"
' 2>&1 | sed 's/^/      /'
rule
ok "The shell ran. No preventive layer had anything to say about it."

hdr "Waiting for Falco to report"
sleep 12

hdr "Falco alerts since ${SINCE}"
rule
ALERTS="$(kubectl -n falco logs -l app.kubernetes.io/name=falco \
            --since-time="$SINCE" --tail=400 2>/dev/null || true)"

if [[ -z "$ALERTS" ]]; then
  bad "No Falco output at all."
  note "    kubectl -n falco get pods"
  note "    kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=50"
  verdict 1 "layer 7 produced nothing"
  exit 1
fi

# JSON output is set in falco/values.yaml, so jq can pick out the fields that
# matter. Falls back to grep if jq is unavailable or the output is not JSON.
if command -v jq >/dev/null 2>&1; then
  printf '%s\n' "$ALERTS" | while IFS= read -r line; do
    printf '%s' "$line" | jq -r '
      select(.rule != null)
      | "  [\(.priority)] \(.rule)\n      ns=\(.output_fields["k8s.ns.name"] // "<NA>")  pod=\(.output_fields["k8s.pod.name"] // "<NA>")  proc=\(.output_fields["proc.name"] // "?")"
    ' 2>/dev/null
  done | sed 's/^/    /'
else
  printf '%s\n' "$ALERTS" | grep -iE 'shell|sensitive|write attempt' | head -10 | sed 's/^/      /'
fi
rule

# =========================================================================
# THE CHECK THAT MATTERS MORE THAN "DID AN ALERT ARRIVE".
#
# An alert with k8s.ns.name=<NA> means Falco detected the syscall correctly
# and has no idea which pod it happened in — the containerd socket in
# falco/values.yaml is wrong. In that state every rule in
# falco/custom-rules.yaml is scoped to `k8s.ns.name in (zt-prod, ...)`,
# matches nothing, and never fires. What you would be reading above is the
# DEFAULT ruleset firing, which looks like success.
#
# So the test is not "is there an alert". It is "does the alert know where it
# happened".
# =========================================================================
hdr "Does the alert carry Kubernetes context?"
if printf '%s' "$ALERTS" | grep -q 'zt-prod'; then
  ok "Alerts name the namespace (zt-prod) — the containerd socket is correct"
  CUSTOM="$(printf '%s' "$ALERTS" | grep -c 'governed namespace' || true)"
  if [[ "${CUSTOM:-0}" -gt 0 ]]; then
    ok "$CUSTOM alert(s) from the custom rules in falco/custom-rules.yaml"
    verdict 0 "detected, attributed to a pod, by rules written for this cluster"
  else
    warn "Alerts arrived but none from the custom rules."
    note "The default ruleset is firing and the scoped rules are not. Check"
    note "the rules loaded:"
    note "    kubectl -n falco logs -l app.kubernetes.io/name=falco | grep -i 'rules\|error'"
    verdict 1 "the custom rules are not firing"
  fi
else
  bad "No alert mentions zt-prod. k8s.ns.name is almost certainly <NA>."
  note "Falco is detecting syscalls and cannot attribute them to a pod, so"
  note "every namespace-scoped custom rule matches nothing. Fix"
  note "collectors.containerd.socket in falco/values.yaml:"
  note "    sudo ls -l /run/k3s/containerd/containerd.sock"
  note "then  helm upgrade  and re-run."
  verdict 1 "detection has no Kubernetes context - the scoped rules are inert"
fi

hdr "What this layer does and does not claim"
note "It did not stop the shell and it cannot. The sequence was: an attacker"
note "with code execution opened a shell, read a credential file, and tried"
note "to persist a binary. Layer 3 stopped the persistence (read-only root"
note "filesystem). Layer 7 recorded all three."
note
note "In this lab the alert goes to a pod log and falcosidekick. An alert"
note "nobody is paged for is the same class of problem as a policy left in"
note "Audit, and the limitation is recorded in docs/ATTACK-RESULTS.md rather"
note "than implied away."
