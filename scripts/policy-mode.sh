#!/usr/bin/env bash
# Flip every Kyverno policy between Audit and Enforce.
#
#   ./scripts/policy-mode.sh            # report the current mode
#   ./scripts/policy-mode.sh enforce
#   ./scripts/policy-mode.sh audit
#
# =========================================================================
# "AUDIT BEFORE ENFORCE" IS A DESIGN DECISION, AND THIS SCRIPT IS IT.
#
# Written as a tool rather than a sentence in a README because the sentence
# does not survive contact with a Friday afternoon. Every policy in
# policies/kyverno/ ships with validationFailureAction: Audit, so a fresh
# cluster records violations and blocks nothing. You read the reports, confirm
# the only things failing are things that SHOULD fail, and then switch over.
#
# Skipping that step is how a policy rollout becomes an outage. A signature
# policy switched straight to Enforce rejects every pod that restarts for any
# reason — a node drain, an eviction, an OOM kill — and the resulting outage
# looks like a cluster fault rather than a change somebody made.
#
# It cuts the other way too, and that is the more common failure: a policy set
# left in Audit forever reports beautifully and prevents nothing. This script
# tells you which state you are in, every time it runs, without being asked.
# =========================================================================
set -euo pipefail

ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }
hdr()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# ===========================================================================
# THIS SCRIPT PATCHES THE CLUSTER, AND ARGOCD OWNS THE CLUSTER.
#
# `validationFailureAction` is declared in policies/kyverno/*.yaml as `Audit`.
# The kyverno-policies Application syncs that path with selfHeal: true, so a
# `kubectl patch` flipping a policy to Enforce is drift, and ArgoCD reverts it
# at the next reconciliation - about three minutes, which is shorter than an
# attack run. The switch appears to work, the first attacks are blocked, and
# the later ones are not, for no reason visible in their output.
#
# That is not a bug in ArgoCD. It is attack-06 happening to you: this project
# argues that the cluster must match git, and the policy mode IS cluster
# state, so the honest way to change it is a commit.
#
# This block does not disable anything. It warns, because a tool that silently
# loses its effect three minutes later is worse than one that says so.
# ===========================================================================
warn_if_selfheal() {
  local sh
  sh="$(kubectl -n argocd get app kyverno-policies \
        -o jsonpath='{.spec.syncPolicy.automated.selfHeal}' 2>/dev/null || true)"
  [[ "$sh" != "true" ]] && return 0
  warn ""
  warn "ARGOCD WILL REVERT THIS. kyverno-policies has selfHeal: true, and git"
  warn "declares validationFailureAction: Audit. This patch survives until the"
  warn "next reconciliation (~3 min), which is shorter than an attack run."
  warn ""
  warn "To make it stick, change the declared state instead:"
  warn "    sed -i 's/validationFailureAction: Audit/validationFailureAction: Enforce/' \\"
  warn "        policies/kyverno/*.yaml"
  warn "    git commit -am 'policy: switch Kyverno to Enforce' && git push"
  warn "    kubectl -n argocd patch app kyverno-policies --type merge \\"
  warn "        -p '{\"operation\":{\"sync\":{}}}'          # or just wait 3 min"
  warn ""
  warn "Then confirm with:  ./scripts/policy-mode.sh"
  warn ""
}
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

report() {
  hdr "Current policy modes"
  kubectl get clusterpolicy \
    -o custom-columns='POLICY:.metadata.name,ACTION:.spec.validationFailureAction,BACKGROUND:.spec.background' \
    2>/dev/null | sed 's/^/    /'
  local n_audit
  n_audit="$(kubectl get clusterpolicy \
    -o jsonpath='{range .items[*]}{.spec.validationFailureAction}{"\n"}{end}' 2>/dev/null \
    | grep -ci audit || true)"
  echo
  if [[ "${n_audit:-0}" -gt 0 ]]; then
    warn "${n_audit} policy/policies in Audit: violations are RECORDED, NOT BLOCKED."
    warn "Read the reports first:   kubectl get polr -A"
    warn "Then switch:              $0 enforce"
  else
    ok "Every policy is in Enforce. Violations are refused at admission."
  fi
}

case "${1:-report}" in
  report|"")
    report
    ;;

  enforce|Enforce|ENFORCE)
    warn_if_selfheal
    hdr "Reviewing reports before switching to Enforce"
    # ---------------------------------------------------------------------
    # Printed, not gated on. The failing results are supposed to include the
    # deliberate ones — the unsigned control image, the privileged test pod —
    # so a script that refused to proceed while any violation existed could
    # never be used. Showing them makes the decision informed rather than
    # automatic.
    # ---------------------------------------------------------------------
    FAILS="$(kubectl get polr -A -o json 2>/dev/null \
      | jq -r '.items[].results[]? | select(.result=="fail")
               | "    \(.policy)/\(.rule)  →  \(.resources[0].namespace)/\(.resources[0].name)"' \
      2>/dev/null | sort -u || true)"
    if [[ -n "$FAILS" ]]; then
      warn "These resources currently VIOLATE policy and will be refused on"
      warn "their next admission (i.e. next restart), not immediately:"
      printf '%s\n' "$FAILS"
      echo
      warn "Expected entries: the unsigned control image and any attack"
      warn "fixtures left behind. Anything else is a real workload that is"
      warn "about to stop being able to restart."
    else
      ok "No failing results in any PolicyReport."
    fi

    hdr "Switching all policies to Enforce"
    for p in $(kubectl get clusterpolicy -o name 2>/dev/null); do
      kubectl patch "$p" --type merge \
        -p '{"spec":{"validationFailureAction":"Enforce"}}' >/dev/null
      ok "${p#clusterpolicy.kyverno.io/} → Enforce"
    done
    report
    echo
    warn "IMPORTANT: this takes effect at the next ADMISSION, not now."
    warn "verifyImages runs only at admission (background: false is mandatory"
    warn "for it), so pods already running are never re-evaluated. A"
    warn "non-compliant pod keeps running until something restarts it:"
    warn "    kubectl -n zt-prod rollout restart deploy/api deploy/web"
    ;;

  audit|Audit|AUDIT)
    hdr "Switching all policies back to Audit"
    for p in $(kubectl get clusterpolicy -o name 2>/dev/null); do
      kubectl patch "$p" --type merge \
        -p '{"spec":{"validationFailureAction":"Audit"}}' >/dev/null
      ok "${p#clusterpolicy.kyverno.io/} → Audit"
    done
    report
    warn "Nothing is being blocked now. If this was done to unbreak a"
    warn "deployment, write down why — an 'Audit for now' that nobody"
    warn "revisits is the normal end state of a policy project."
    ;;

  *)
    echo "usage: $0 [report|enforce|audit]" >&2
    exit 2
    ;;
esac
