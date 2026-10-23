#!/usr/bin/env bash
# Kyverno (layer 3) and Falco (layer 7). Run ON THE BOX after the bootstrap.
#
#   ./scripts/01-install-policy-engines.sh
#   FALCO_UI=1 ./scripts/01-install-policy-engines.sh    # + falcosidekick-ui
#
# Both are installed with Helm rather than through ArgoCD, deliberately:
#
#   * Kyverno is the admission controller that validates everything ArgoCD
#     deploys. Deploying it THROUGH ArgoCD makes the thing being policed
#     responsible for installing its own police, and a bad sync could remove
#     the policy engine and then not be refused by it.
#   * Falco is a privileged DaemonSet loading an eBPF program. The AppProject
#     in argocd/projects/zerotrust.yaml deliberately does not permit
#     ClusterRole, ClusterRoleBinding or webhook configurations, which both
#     charts create.
#
# The separation is the point, not a workaround: the controls live outside the
# delivery path they constrain.
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m!!! %s\033[0m\n' "$*" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../versions.env
source "$HERE/versions.env"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# ---------------------------------------------------------------------------
# AN SSH DROP MID-HELM-INSTALL IS NOT A TRANSIENT ERROR.
#
# Helm keeps release state in a Secret in the release namespace. A helm
# process killed partway through - an SSH `Broken pipe` is the usual way,
# because these installs produce no output for minutes and an idle NAT or
# firewall timeout closes the session - leaves that Secret in
# `pending-install`, and NOTHING EVER CLEARS IT. The process that would have
# is gone.
#
# The next run then reports:
#
#   Error: UPGRADE FAILED: another operation (install/upgrade/rollback) is
#   in progress
#
# which reads like a concurrent install and invites waiting. There is nothing
# to wait for. These two functions prevent it and then recover from it.
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

clear_stuck_release() {
  local rel="$1" ns="$2" st
  st="$(helm status "$rel" -n "$ns" -o json 2>/dev/null | jq -r '.info.status' 2>/dev/null || true)"
  case "$st" in
    pending-install)
      warn "helm release $rel/$ns is stuck in 'pending-install' - no process owns it."
      # There is no previous revision to roll back TO on a first install, so
      # `helm rollback` cannot work here; uninstall is the only correct move
      # and it takes the partially-created resources with it.
      helm uninstall "$rel" -n "$ns" --wait --timeout 5m 2>&1 | sed 's/^/      /' || true
      ok "cleared - reinstalling from scratch"
      ;;
    pending-upgrade|pending-rollback)
      warn "helm release $rel/$ns is stuck in '$st' - rolling back."
      helm rollback "$rel" -n "$ns" --wait --timeout 5m 2>&1 | sed 's/^/      /' \
        || { warn "rollback failed; uninstalling instead"
             helm uninstall "$rel" -n "$ns" --wait --timeout 5m 2>&1 | sed 's/^/      /' || true; }
      ok "cleared"
      ;;
    uninstalling)
      warn "helm release $rel/$ns is stuck in 'uninstalling' - forcing removal."
      helm uninstall "$rel" -n "$ns" --no-hooks --timeout 5m 2>&1 | sed 's/^/      /' || true
      ;;
    deployed)  ok "helm release $rel/$ns already deployed - upgrading in place" ;;
    failed)    warn "helm release $rel/$ns is in 'failed' - upgrade will retry over it" ;;
    "")        : ;;   # not installed; normal first run
    *)         warn "helm release $rel/$ns is in unexpected state '$st'" ;;
  esac
}

require_session

# ---------------------------------------------------------------------------
# A pin that does not exist must FAIL, not fall back to latest.
#
# `helm install --version X` on a missing version errors, which is correct. The
# message is terse, so this resolves it first and prints what IS available —
# the previous project spent real time on `helm repo update -q`, an invalid
# flag, producing a failure that looked like a network problem.
# ---------------------------------------------------------------------------
require_chart() {
  local repo="$1" chart="$2" want="$3"
  if ! helm search repo "${repo}/${chart}" --version "${want}" 2>/dev/null \
       | grep -q "${want}"; then
    warn "Chart ${repo}/${chart} version ${want} was not found. Available:"
    helm search repo "${repo}/${chart}" --versions 2>/dev/null | head -12 | sed 's/^/      /'
    die "Set the version explicitly, e.g. ${chart^^}_CHART_VERSION=x.y.z $0"
  fi
  ok "${repo}/${chart} ${want} resolves"
}

log "Adding Helm repositories"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null
# No -q. Helm 3.18 has no such flag for this subcommand and rejects it, which
# reads like a connectivity failure. (Project 1, defect 8.)
helm repo update

require_chart kyverno kyverno "$KYVERNO_CHART_VERSION"
require_chart falcosecurity falco "$FALCO_CHART_VERSION"

# ===========================================================================
log "Installing Kyverno ${KYVERNO_CHART_VERSION}"
clear_stuck_release kyverno kyverno
# ===========================================================================
helm upgrade --install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace \
  --version "$KYVERNO_CHART_VERSION" \
  --set admissionController.replicas=1 \
  --set backgroundController.replicas=1 \
  --set cleanupController.replicas=1 \
  --set reportsController.replicas=1 \
  --wait --timeout 10m

# Single replicas on purpose. The chart defaults to 3 for the admission
# controller, which on an 8 GB single node is 3 copies of the thing most
# likely to be evicted when something else misbehaves. A production cluster
# runs 3 across 3 nodes; one node running 3 copies has the availability of one
# copy and the memory footprint of three.

log "Verifying the Kyverno CRD accepts the policy syntax this repo uses"
# ---------------------------------------------------------------------------
# THE CHECK THAT MAKES THE VERSION PIN MEAN SOMETHING.
#
# policies/kyverno/01-verify-image-signature.yaml is a kyverno.io/v1
# ClusterPolicy with a `verifyImages` rule. Kyverno 1.14 introduced a separate
# ImageValidatingPolicy type and began treating this as the legacy path, so a
# future chart could accept the policy and ignore the rule, or move the field.
#
# Asserting the CRD schema contains the field is the difference between "the
# chart installed" and "the policy I am about to apply will be honoured".
# A policy that is accepted and not enforced is the failure this whole project
# is about.
# ---------------------------------------------------------------------------
kubectl wait --for=condition=Established crd/clusterpolicies.kyverno.io --timeout=120s
if kubectl get crd clusterpolicies.kyverno.io -o json | jq -e '
      .spec.versions[]
      | select(.name == "v1")
      | .schema.openAPIV3Schema.properties.spec.properties.rules.items.properties.verifyImages
   ' >/dev/null 2>&1; then
  ok "kyverno.io/v1 ClusterPolicy supports verifyImages"
else
  warn "The installed Kyverno does NOT expose verifyImages on kyverno.io/v1."
  warn "policies/kyverno/01-verify-image-signature.yaml will not work as"
  warn "written. Either pin KYVERNO_CHART_VERSION to a 3.3.x release, or"
  warn "port policy 01 to policies.kyverno.io/v1alpha1 ImageValidatingPolicy."
  die  "Refusing to continue - layer 3 is the load-bearing layer here."
fi
kubectl -n kyverno get pods

# ===========================================================================
log "Installing Falco ${FALCO_CHART_VERSION}"
clear_stuck_release falco falco
# ===========================================================================

# The kernel prerequisites for the modern_ebpf driver, checked BEFORE the
# install rather than diagnosed after it. A Falco that loads no driver still
# starts, still reports Ready, and reports zero events — which is
# indistinguishable from a quiet cluster.
log "Checking CO-RE prerequisites"
KREL="$(uname -r)"
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  ok "BTF present (/sys/kernel/btf/vmlinux), kernel ${KREL}"
else
  warn "No /sys/kernel/btf/vmlinux on kernel ${KREL}."
  warn "The modern_ebpf driver needs kernel BTF (CONFIG_DEBUG_INFO_BTF) and"
  warn "a kernel of 5.8 or newer. Ubuntu 24.04 ships 6.8 with BTF enabled, so"
  warn "if you are seeing this you are not on the AMI the terraform selects."
  warn "Options: switch falco/values.yaml driver.kind to 'ebpf' and install"
  warn "linux-headers-\$(uname -r), or use the matching Ubuntu AMI."
  die  "Refusing to install a detection layer that would report nothing."
fi

# --set-file passes falco/custom-rules.yaml through as the VALUE of a
# customRules key, so the chart mounts it into /etc/falco/rules.d. Writing the
# rules inline in values.yaml would work and would mean the rules could not be
# linted or diffed as YAML in their own right.
FALCO_ARGS=(
  --namespace falco --create-namespace
  --version "$FALCO_CHART_VERSION"
  -f "$HERE/falco/values.yaml"
  --set-file "customRules.zero-trust-rules\.yaml=$HERE/falco/custom-rules.yaml"
)

if [[ "${FALCO_UI:-0}" == "1" ]]; then
  log "FALCO_UI=1 - enabling falcosidekick-ui (adds a Redis, ~150 MB)"
  FALCO_ARGS+=(
    --set falcosidekick.webui.enabled=true
    --set falcosidekick.webui.redis.storageEnabled=false
  )
fi

helm upgrade --install falco falcosecurity/falco "${FALCO_ARGS[@]}" \
  --wait --timeout 10m

kubectl -n falco rollout status ds/falco --timeout=300s

log "Verifying the Falco driver actually loaded"
# ---------------------------------------------------------------------------
# The same principle as the Kyverno CRD check: a detection layer that failed
# to load reports no events, and no events looks like good news.
#
# Falco logs the driver it opened at startup. Absence of that line, or a
# "failed to open" line, means every rule in falco/custom-rules.yaml is inert.
# ---------------------------------------------------------------------------
sleep 10
FALCO_LOG="$(kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=200 2>/dev/null || true)"
if printf '%s' "$FALCO_LOG" | grep -qiE 'modern.?ebpf|modern_bpf|Starting health webserver|Falco initialized'; then
  ok "Falco initialised and the driver is open"
else
  warn "Could not confirm the driver from the log. Check by hand:"
  warn "    kubectl -n falco logs -l app.kubernetes.io/name=falco | head -40"
  warn "Look for 'modern_bpf' and the absence of 'failed to open'."
fi

log "Verifying Falco can see Kubernetes metadata"
# ---------------------------------------------------------------------------
# THE CHECK FOR THE CONTAINERD SOCKET PATH.
#
# Every custom rule is scoped with `k8s.ns.name in (zt-prod, ...)`. That field
# comes from the container runtime, not the kernel. If the socket path in
# falco/values.yaml is wrong, the field is <NA> on every event, the scope
# matches nothing, and all five custom rules silently never fire.
#
# Checked here by asking whether the socket the chart was pointed at exists at
# all. The functional proof is attack-07, which must produce an alert whose
# k8s.ns.name is populated — if it says <NA>, the rules are not working even
# though an alert arrived.
# ---------------------------------------------------------------------------
if sudo test -S /run/k3s/containerd/containerd.sock; then
  ok "k3s containerd socket present at /run/k3s/containerd/containerd.sock"
else
  warn "Expected socket /run/k3s/containerd/containerd.sock is missing."
  warn "Falco will report events with k8s.ns.name=<NA>, and every custom rule"
  warn "in falco/custom-rules.yaml filters on that field - so they will never"
  warn "fire, and the log will look clean. Find the real path with:"
  warn "    sudo ls -l /run/k3s/containerd/ /run/containerd/ 2>/dev/null"
  warn "then add it to collectors.containerEngine.engines.cri.sockets in"
  warn "falco/values.yaml. NOTE: that key is a LIST in chart 9.x; the old"
  warn "chart 4.x spelling (collectors.containerd.socket) is accepted by"
  warn "Helm and silently ignored, because the chart has no values schema."
fi

kubectl -n falco get pods

cat <<'MSG'

==> Kyverno and Falco installed.

Both are deliberately OUTSIDE ArgoCD. The policy engine is not deployed by the
delivery path it polices, and the detection layer is not removable by a commit.

Next:
  ./scripts/02-install-argocd.sh

MSG
