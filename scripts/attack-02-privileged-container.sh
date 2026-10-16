#!/usr/bin/env bash
# ATTACK 2 — deploy a privileged container. Expect it refused twice, by two
# different layers, with two different messages.
#
#   ./scripts/attack-02-privileged-container.sh
#
# This attack is really a test of the TEST. Submitting a privileged pod to
# zt-prod proves only that something refused it, and the something is always
# Pod Security Admission — because PSA is a built-in admission plugin and
# Kyverno is a validating webhook, and Kubernetes runs built-in plugins FIRST.
#
# So the Kyverno privileged-container policy would pass this test whether or
# not it existed, and would go on passing it after being deleted. The only way
# to know it works is to remove PSA from the path, which is what the
# zt-psa-off namespace exists for.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_real_digest

IMG="$(signed_image api)"

attack_header 2 "Privileged container" \
  "4 — Pod Security Admission, and 3 — Kyverno, independently" \
  "REJECTED in both namespaces, by a DIFFERENT layer in each"

submit() {  # $1 = namespace, $2 = pod name
  try_apply <<POD
apiVersion: v1
kind: Pod
metadata:
  name: $2
  namespace: $1
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  containers:
    - name: c
      image: $IMG
      command: ["sleep", "60"]
      securityContext:
        # The attack. Shares the host kernel namespaces, can load kernel
        # modules, read every device and mount the host filesystem — which
        # makes the node boundary and every other layer here irrelevant.
        privileged: true
      resources:
        requests: {cpu: 10m, memory: 32Mi}
        limits: {memory: 64Mi}
POD
}

# ---------------------------------------------------------------------------
hdr "Part 1 — zt-prod, where PSA is at restricted"
rule
kubectl -n zt-prod delete pod attack-priv --ignore-not-found >/dev/null 2>&1
OUT1="$(submit zt-prod attack-priv 2>&1)"; RC1=$?
printf '%s\n' "$OUT1"
rule
if [[ $RC1 -ne 0 ]] && printf '%s' "$OUT1" | grep -qi 'PodSecurity'; then
  ok "Refused by PodSecurity — the BUILT-IN plugin, not Kyverno"
  note "Note what is NOT in that message: no mention of Kyverno, and no"
  note "mention of the disallow-privileged policy. Kyverno was never asked."
elif [[ $RC1 -ne 0 ]]; then
  warn "Refused, but not by PodSecurity. Read the message above — if Kyverno"
  warn "spoke here, the PSA labels on zt-prod are missing."
else
  bad "ADMITTED. Neither layer refused a privileged container."
fi

# ---------------------------------------------------------------------------
hdr "Part 2 — zt-psa-off, where PSA is disabled so Kyverno is the only control"
note "That namespace is a test fixture and its purpose annotation says so."
note "Without it, the policy below is untestable and would pass on its own."
rule
kubectl -n zt-psa-off delete pod attack-priv --ignore-not-found >/dev/null 2>&1
OUT2="$(submit zt-psa-off attack-priv 2>&1)"; RC2=$?
printf '%s\n' "$OUT2"
rule

MODE="$(kubectl get clusterpolicy disallow-privileged \
         -o jsonpath='{.spec.validationFailureAction}' 2>/dev/null)"

if [[ $RC2 -ne 0 ]] && printf '%s' "$OUT2" | grep -qi 'kyverno\|disallow-privileged'; then
  ok "Refused by Kyverno — layer 3 works on its own"
  verdict 0 "both layers refuse a privileged container, independently"
  note "Two rejections, two different messages, two different mechanisms."
  note "That is what makes this defence in depth rather than one control"
  note "with a spare written next to it."
elif [[ $RC2 -eq 0 && ! "$MODE" =~ ^[Ee]nforce$ ]]; then
  warn "Admitted, because disallow-privileged is in ${MODE:-Audit}."
  kubectl -n zt-psa-off delete pod attack-priv --ignore-not-found >/dev/null 2>&1
  note "Expected on the first pass. Read the report, then:"
  note "    ./scripts/policy-mode.sh enforce && $0"
  verdict 1 "not yet proven — the Kyverno layer is still in Audit"
else
  bad "A privileged pod was ADMITTED with PSA off and Kyverno in Enforce."
  note "layer 3 is not covering what layer 4 was hiding. Check:"
  note "    kubectl get clusterpolicy disallow-privileged -o yaml"
  note "    kubectl -n kyverno logs -l app.kubernetes.io/component=admission-controller --tail=50"
  kubectl -n zt-psa-off delete pod attack-priv --ignore-not-found >/dev/null 2>&1
  verdict 1 "the Kyverno privileged policy is not enforcing"
fi
