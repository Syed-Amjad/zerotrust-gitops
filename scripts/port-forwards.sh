#!/usr/bin/env bash
# Port-forwards for the two UIs. Run ON THE BOX, in its own terminal.
#
#   ./scripts/port-forwards.sh
#
# Then reach them through the SSH tunnel from your workstation:
#   ssh -L 8080:localhost:8080 -L 2802:localhost:2802 ubuntu@<ip>
#
#   8080  ArgoCD            https://localhost:8080  (accept the warning)
#   2802  Falcosidekick UI  http://localhost:2802   (only if FALCO_UI=1)
#
# Two layers of forwarding looks redundant and is not: kubectl port-forward
# binds inside the box, SSH carries it to your laptop, and NO UI PORT IS OPEN
# IN THE SECURITY GROUP. An ArgoCD with a bootstrap password on the public
# internet is found within the hour.
set -uo pipefail

ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# ---------------------------------------------------------------------------
# pkill -f port-forward, NOT pkill -f "kubectl port-forward".
#
# The real command line is `kubectl -n argocd port-forward ...` — the namespace
# flag sits between the two words, so the longer pattern matches nothing and
# silently leaves the old forwards running. The next bind then fails with
# "address already in use" and reads like a port conflict with something else.
# (Project 1, defect 17.)
# ---------------------------------------------------------------------------
pkill -f port-forward 2>/dev/null && warn "stopped existing port-forwards" || true
sleep 1

start() {  # $1 = namespace, $2 = svc, $3 = local:remote, $4 = label
  if kubectl -n "$1" get "svc/$2" >/dev/null 2>&1; then
    kubectl -n "$1" port-forward "svc/$2" "$3" >/dev/null 2>&1 &
    ok "$4 → localhost:${3%%:*}"
  else
    warn "$4 not found (${1}/${2}) - skipping"
  fi
}

start argocd argocd-server 8080:443 "ArgoCD"
start falco  falcosidekick-ui 2802:2802 "Falcosidekick UI"

sleep 2
echo
printf '  %s\n' "Forwards running in the background of THIS shell."
printf '  %s\n' "They stop when it exits. Leave it open."
echo
printf '  %s\n' "ArgoCD password:"
printf '  %s\n' "    kubectl -n argocd get secret argocd-initial-admin-secret \\"
printf '  %s\n' "      -o jsonpath='{.data.password}' | base64 -d; echo"
echo
printf '  %s\n' "If the Falcosidekick UI is missing, it was not enabled. Re-run:"
printf '  %s\n' "    FALCO_UI=1 ./scripts/01-install-policy-engines.sh"
echo
printf '  %s\n' "Falco events without a UI, which is usually enough:"
printf '  %s\n' "    kubectl -n falco logs -l app.kubernetes.io/name=falco -f | jq -c 'select(.rule)'"
echo
wait
