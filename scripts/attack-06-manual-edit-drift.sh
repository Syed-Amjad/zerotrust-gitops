#!/usr/bin/env bash
# ATTACK 6 — change a live resource by hand. Expect GitOps to revert it.
#
#   ./scripts/attack-06-manual-edit-drift.sh
#
# The weakest-looking attack in the set and the one most likely to be the real
# one. Nothing here is exotic: someone with kubectl access scales a deployment,
# edits an env var, or removes a securityContext field during an incident at
# 2am and never puts it back. Six months later the cluster does not match the
# repository and nobody knows which of the two is wrong.
#
# What makes this a SECURITY control rather than tidiness: every other layer in
# this project is declared in git. A manual edit that silently persists can
# remove a PSA label, widen an AuthorizationPolicy or add a ServiceEntry — and
# reconciliation is what makes those changes temporary instead of permanent.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

attack_header 6 "Manual edit of a live resource" \
  "2 — ArgoCD automated selfHeal" \
  "Reverted to the git-declared state within seconds, with no human action"

DEPLOY=api
NS=zt-prod

DECLARED="$(kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.replicas}' 2>/dev/null)"
[[ -n "$DECLARED" ]] || { bad "Deployment $DEPLOY not found in $NS"; exit 1; }

hdr "Confirming selfHeal is actually on"
# Asked rather than assumed. An Application with automated sync but selfHeal
# false reports Synced and OutOfSync alternately and never corrects anything —
# and the Application list looks healthy at a glance.
SH_ON="$(kubectl -n argocd get app workloads \
          -o jsonpath='{.spec.syncPolicy.automated.selfHeal}' 2>/dev/null)"
if [[ "$SH_ON" == "true" ]]; then
  ok "workloads: syncPolicy.automated.selfHeal = true"
else
  bad "selfHeal is '${SH_ON:-unset}'. The drift below will PERSIST."
  note "That is a finding, not a broken test — record it. Then check"
  note "argocd/applications/04-workloads.yaml."
fi

hdr "State before"
note "declared in git: replicas = $DECLARED"
note "$(kubectl -n "$NS" get deploy "$DEPLOY" -o wide --no-headers 2>/dev/null)"

TAMPER=$((DECLARED + 6))
hdr "Scaling to $TAMPER by hand — exactly as someone would during an incident"
kubectl -n "$NS" scale deploy "$DEPLOY" --replicas="$TAMPER"
START=$(date +%s)
note "$(kubectl -n "$NS" get deploy "$DEPLOY" --no-headers 2>/dev/null)"

hdr "Watching for the revert"
# Polling rather than `argocd app wait`, so the OBSERVED time is measured here
# and does not depend on the CLI being logged in. The number that belongs in
# the results table is a measurement, not a configuration.
REVERTED=0
for i in $(seq 1 60); do
  NOW="$(kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.replicas}' 2>/dev/null)"
  if [[ "$NOW" == "$DECLARED" ]]; then
    ELAPSED=$(( $(date +%s) - START ))
    REVERTED=1
    ok "Reverted to $DECLARED after approximately ${ELAPSED}s"
    break
  fi
  printf '      t+%-3ss  replicas = %s\n' "$i" "${NOW:-?}"
  sleep 1
done

if [[ "$REVERTED" -eq 1 ]]; then
  verdict 0 "the manual change was reverted by reconciliation"
  note "Nobody was paged. Nothing was approved. Git won."
  note
  note "Record the measured seconds, not 'fast'. ArgoCD's default reconcile"
  note "interval is 180s, and selfHeal reacts to the cluster event much"
  note "sooner than that — so the number says which path corrected it, and"
  note "a slow revert is a real window an attacker could work inside."
else
  bad "Still at $(kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.replicas}') after 60s"
  note "    kubectl -n argocd get app workloads -o wide"
  note "    kubectl -n argocd logs statefulset/argocd-application-controller --tail=50"
  verdict 1 "drift persisted"
  kubectl -n "$NS" scale deploy "$DEPLOY" --replicas="$DECLARED"
  note "Scaled back by hand so the next attack starts from a known state."
fi

hdr "The limitation of this control, stated plainly"
note "selfHeal reverts resources ArgoCD MANAGES. It does not notice a resource"
note "nobody declared — a pod created by hand in zt-prod is not drift, it is"
note "simply unmanaged, and reconciliation has no opinion about it."
note
note "orphanedResources.warn is set to true in the AppProject for that reason,"
note "and a warning in a UI is weaker than a rejection. The layer that"
note "actually stops the hand-created pod is admission control, not GitOps."
note "Check for orphans with:"
note "    kubectl -n argocd get app -o json | jq -r '.items[].status.conditions[]?.message' | grep -i orphan"
