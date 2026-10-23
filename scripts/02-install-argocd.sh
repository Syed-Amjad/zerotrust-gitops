#!/usr/bin/env bash
# ArgoCD — layer 2. Run ON THE BOX after the policy engines.
#
#   ./scripts/02-install-argocd.sh
#
# Installs ArgoCD, enables Helm support in its bundled kustomize, and prints
# the bootstrap password. It does NOT apply the root application — that is a
# separate, deliberate command, because it is the moment the cluster starts
# taking instructions from a git repository.
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../versions.env
source "$HERE/versions.env"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# ---------------------------------------------------------------------------
# DO NOT RUN THIS IN A BARE SSH SESSION.
#
# Everything below produces no output for minutes at a time - the ArgoCD
# server-side apply, then three rollout waits - and an idle session through a
# NAT gateway gets closed. Unlike helm, `kubectl apply` leaves no lock behind,
# so the cost here is only a half-applied install and a confusing re-run
# rather than a stuck release. tmux removes the whole class of problem.
# ---------------------------------------------------------------------------
require_session() {
  [[ -n "${TMUX:-}" || -n "${STY:-}" ]] && { ok "running inside tmux/screen"; return 0; }
  [[ ! -t 0 ]] && return 0        # non-interactive (CI): nothing to prompt
  warn "You are NOT inside tmux or screen."
  warn "This script runs helm installs that take several minutes with no"
  warn "output. If the SSH session drops, helm is killed mid-install and the"
  warn "release is left in 'pending-install', which must be cleared before a"
  warn "retry can work."
  warn ""
  warn "    tmux new -s zt        # then re-run this script"
  warn "    # detach: ctrl-b then d      reattach: tmux attach -t zt"
  warn ""
  read -r -p "    Continue without tmux anyway? [y/N] " _a
  [[ "${_a:-}" =~ ^[Yy]$ ]] || die "Stopped. Start tmux and re-run - it costs 5 seconds."
}

require_session

log "Creating the argocd namespace"
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -

# ---------------------------------------------------------------------------
# NOT labelled for Istio injection, and that is a decision rather than an
# omission.
#
# ArgoCD must reach github.com. The mesh runs with
# outboundTrafficPolicy=REGISTRY_ONLY, so an injected ArgoCD would need a
# ServiceEntry for github.com, and its repo-server would fail to clone with a
# connection error that looks like DNS. The same applies to Kyverno, which
# reaches ghcr.io and rekor.sigstore.dev at admission time.
#
# Keeping the control plane out of the mesh also keeps the mesh out of the
# control plane: a broken Istio config cannot take down the thing you would use
# to fix it.
# ---------------------------------------------------------------------------

log "Installing ArgoCD ${ARGOCD_VERSION}"
# ---------------------------------------------------------------------------
# --server-side --force-conflicts is REQUIRED, not defensive.
#
# Client-side apply stores the entire object in the annotation
# kubectl.kubernetes.io/last-applied-configuration. ArgoCD's CRDs exceed the
# 262144-byte annotation limit and the apply fails with:
#
#   metadata.annotations: Too long: must have at most 262144 bytes
#
# which names an annotation nobody wrote. --force-conflicts additionally lets
# a re-run reconcile fields an earlier client-side apply already claimed.
# (Project 1, defect 9.)
# ---------------------------------------------------------------------------
kubectl apply -n argocd --server-side --force-conflicts -f \
  "https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/install.yaml"

log "Waiting for ArgoCD"
for d in argocd-repo-server argocd-server argocd-applicationset-controller argocd-redis argocd-dex-server; do
  kubectl -n argocd rollout status "deploy/$d" --timeout=300s || warn "$d did not report ready"
done
kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=300s

# ---------------------------------------------------------------------------
# kustomize --enable-helm.
#
# Not needed by any manifest currently in this repository — nothing here uses
# a `helmCharts:` generator, because Kyverno and Falco are installed by script
# and that is on purpose. It is set anyway, because the failure if it is ever
# needed and missing is the most confusing one in the previous project:
# `kustomize build` emits NOTHING for a helmCharts generator and reports no
# error, so ArgoCD syncs "successfully" having deployed nothing. Green
# application, empty namespace.
#
# On kustomize v5.7.1 (bundled with kubectl 1.34) that has changed — it now
# exits 1 and names the generator. ArgoCD bundles its own kustomize, which may
# be older, so the flag stays.
# ---------------------------------------------------------------------------
log "Enabling helm support in ArgoCD's kustomize"
kubectl -n argocd patch cm argocd-cm --type merge \
  -p '{"data":{"kustomize.buildOptions":"--enable-helm"}}'
kubectl -n argocd rollout restart deploy/argocd-repo-server
kubectl -n argocd rollout status deploy/argocd-repo-server --timeout=180s

log "Bootstrap admin password"
PW="$(kubectl -n argocd get secret argocd-initial-admin-secret \
        -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)"
if [[ -n "$PW" ]]; then
  echo
  echo "    username: admin"
  echo "    password: ${PW}"
  echo
  warn "This secret is created once. Change the password and delete it:"
  warn "    argocd account update-password"
  warn "    kubectl -n argocd delete secret argocd-initial-admin-secret"
  warn "If you are screenshotting this terminal, blur this block."
else
  warn "argocd-initial-admin-secret not found - it may already have been"
  warn "deleted, or the password already rotated."
fi

cat <<'MSG'

==> ArgoCD is installed. Nothing is being synced yet.

Hand the cluster over to git with the two commands below, IN THIS ORDER. The
project must exist before an Application can reference it:

  kubectl apply -f argocd/projects/zerotrust.yaml
  kubectl apply -f argocd/root-app.yaml
  watch -n2 'kubectl -n argocd get applications'

Expect five Applications: namespaces, kyverno-policies, network-policies,
istio-security, workloads — in sync waves 0 to 4, in that order.

The workloads will NOT become healthy until CI has written real image digests
into workloads/api.yaml and workloads/web.yaml. Until then the manifests carry
64 zeros as a placeholder digest and the pull fails, which is the intended
behaviour: an un-bumped manifest should fail loudly rather than deploy
whatever a tag points at.

Then, and this step is not optional:

  ./scripts/03-verify-enforcement.sh

MSG
