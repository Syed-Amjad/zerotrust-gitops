#!/usr/bin/env bash
# Cluster and mesh. Run once, ON THE BOX, on a fresh t3.large.
#
#   ./scripts/00-bootstrap-cluster.sh
#
# Installs k3s, then Istio configured for the three things layer 6 needs:
# the CNI plugin (so sidecars work under Pod Security Admission), STRICT-capable
# mTLS, and REGISTRY_ONLY outbound traffic policy.
#
# Three of the settings below are the difference between a mesh that enforces
# and a mesh that looks like it enforces. Each is marked.
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m!!! %s\033[0m\n' "$*" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../versions.env
source "$HERE/versions.env"

log "Base packages"
sudo apt-get update -qq
sudo apt-get install -y -qq curl git jq apt-transport-https

log "Installing k3s ${K3S_CHANNEL:-stable}"
# --disable traefik: Istio's ingress gateway is the entry point, and two
#   ingress controllers contending for :80 is a confusing first afternoon.
#
# NOT --disable-network-policy. k3s embeds a NetworkPolicy controller and it is
#   on by default; layer 5 is entirely dependent on it. Disabling it does not
#   produce an error when you apply a NetworkPolicy — the object is accepted and
#   stored and nothing enforces it, so `kubectl get netpol` looks perfect.
curl -sfL https://get.k3s.io | \
  INSTALL_K3S_EXEC="--disable traefik --write-kubeconfig-mode 644" sh -

mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown "$(id -u):$(id -g)" ~/.kube/config
export KUBECONFIG=~/.kube/config
grep -q 'KUBECONFIG' ~/.bashrc || echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc

log "Waiting for the k3s node to register"
# `kubectl wait --all` does NOT wait for a resource to exist. k3s registers
# its node a few seconds AFTER systemd reports the service started, and in
# that window --all resolves to an empty set, so kubectl exits 1 immediately
# with "error: no matching resources found" instead of waiting. Under
# `set -e` that killed this script here, before Istio was installed - and the
# message names no resource and no timeout, so it reads like a kubeconfig
# problem rather than a race.
for _ in $(seq 1 60); do
  [ "$(kubectl get nodes --no-headers 2>/dev/null | wc -l)" -gt 0 ] && break
  sleep 2
done
[ "$(kubectl get nodes --no-headers 2>/dev/null | wc -l)" -gt 0 ] ||
  die "k3s registered no node in 120s. Check: sudo journalctl -u k3s -n 50"

kubectl wait --for=condition=Ready node --all --timeout=180s
kubectl get nodes -o wide

log "Installing helm"
if ! command -v helm >/dev/null; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

log "Installing istioctl ${ISTIO_VERSION}"
if ! command -v istioctl >/dev/null; then
  curl -sL https://istio.io/downloadIstio | ISTIO_VERSION="${ISTIO_VERSION}" sh -
  sudo mv "istio-${ISTIO_VERSION}/bin/istioctl" /usr/local/bin/
  rm -rf "istio-${ISTIO_VERSION}"
fi
istioctl version --remote=false

log "Installing the argocd CLI"
if ! command -v argocd >/dev/null; then
  curl -sSL -o /tmp/argocd \
    "https://github.com/argoproj/argo-cd/releases/download/${ARGOCD_VERSION}/argocd-linux-amd64"
  chmod +x /tmp/argocd && sudo mv /tmp/argocd /usr/local/bin/argocd
fi

log "Installing cosign ${COSIGN_VERSION}"
if ! command -v cosign >/dev/null; then
  curl -sSL -o /tmp/cosign \
    "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
  chmod +x /tmp/cosign && sudo mv /tmp/cosign /usr/local/bin/cosign
fi
cosign version 2>/dev/null | head -3 || true

# ===========================================================================
# ISTIO. Three settings here carry the entire mesh half of this project.
# ===========================================================================
log "Installing Istio ${ISTIO_VERSION} with CNI and REGISTRY_ONLY egress"

istioctl install -y \
  --set profile=default \
  --set components.cni.enabled=true \
  --set values.cni.cniBinDir=/var/lib/rancher/k3s/data/current/bin \
  --set values.cni.cniConfDir=/var/lib/rancher/k3s/agent/etc/cni/net.d \
  --set meshConfig.outboundTrafficPolicy.mode=REGISTRY_ONLY \
  --set meshConfig.accessLogFile=/dev/stdout

# ---------------------------------------------------------------------------
# SETTING 1 — components.cni.enabled=true
#
# Without the CNI plugin, Istio redirects traffic using an init container
# (istio-init) that runs `iptables` and therefore needs NET_ADMIN and NET_RAW.
# Pod Security Admission at `restricted` forbids added capabilities, so every
# pod in zt-prod is rejected:
#
#   pods "web-xxxx" is forbidden: violates PodSecurity "restricted:latest":
#   non-default capabilities (container "istio-init" must not include
#   "NET_ADMIN", "NET_RAW" in securityContext.capabilities.add)
#
# Layer 4 and layer 6 are mutually exclusive without the CNI plugin. With it,
# the iptables rules are written by a privileged DaemonSet on the node once,
# and the injected pod needs no capabilities at all.
#
# ---------------------------------------------------------------------------
# SETTING 2 — THE K3S CNI PATHS. The most dangerous line in this repository.
#
# Istio's CNI defaults are /opt/cni/bin and /etc/cni/net.d. k3s uses NEITHER:
#
#   binaries  /var/lib/rancher/k3s/data/current/bin
#   config    /var/lib/rancher/k3s/agent/etc/cni/net.d
#
# Leave the defaults and the istio-cni DaemonSet starts, reports Running,
# reports Ready, and writes its configuration into a directory that nothing
# reads. Then:
#
#   * pods are admitted (no init container, so PSA is satisfied)
#   * the sidecar is injected and runs
#   * `istioctl proxy-status` shows it SYNCED
#   * and NO TRAFFIC IS REDIRECTED THROUGH IT
#
# Which means mTLS is not applied, the AuthorizationPolicy is not consulted,
# and REGISTRY_ONLY does not constrain anything — because none of those are
# enforced by the policy objects, they are enforced by an Envoy that traffic
# has to actually pass through. Every manifest in istio/ applies cleanly.
# `kubectl get peerauthentication` looks right. Three of the seven layers are
# decorative and nothing anywhere reports a problem.
#
# This is the worst failure mode in the project: not an outage, a silent
# downgrade to no enforcement, on a cluster whose whole claim is enforcement.
# It is why scripts/03-verify-enforcement.sh tests a plaintext connection from
# outside the mesh instead of reading YAML, and why that script is a required
# step rather than an optional check.
#
# `data/current` is a SYMLINK that k3s repoints on upgrade. It is correct here
# and it is not stable across a k3s version change — re-run the verification
# after upgrading k3s, not just after changing Istio.
#
# ---------------------------------------------------------------------------
# SETTING 3 — meshConfig.outboundTrafficPolicy.mode=REGISTRY_ONLY
#
# The default is ALLOW_ANY: a sidecar forwards traffic to any destination it
# does not recognise. Under that default, istio/03-egress-allowlist.yaml is a
# statement of intent with no effect, and attack-05 passes — the exfiltration
# succeeds — while every manifest involved reads correctly.
#
# REGISTRY_ONLY inverts it: anything not in the mesh registry is refused. The
# cost is that every external dependency must be declared as a ServiceEntry,
# which is the point, and is also the thing that will break the first time
# somebody adds a feature that calls an API.
#
# Only SIDECAR-INJECTED pods are affected. The node itself, the kubelet pulling
# images, ArgoCD reaching github.com and Kyverno reaching rekor.sigstore.dev
# all run outside the mesh and are untouched — which is why those namespaces
# are deliberately not labelled for injection.
# ---------------------------------------------------------------------------

kubectl -n istio-system rollout status deploy/istiod --timeout=300s
kubectl -n istio-system rollout status ds/istio-cni-node --timeout=300s
kubectl -n istio-system get pods

log "Confirming the CNI plugin wrote its config where k3s will read it"
# Asserted rather than assumed. This is the cheap check for setting 2; the
# functional check is 03-verify-enforcement.sh and it is not optional.
CNI_CONF_DIR=/var/lib/rancher/k3s/agent/etc/cni/net.d
CNI_BIN_DIR=/var/lib/rancher/k3s/data/current/bin

# TEST THE CONTENTS, NOT THE FILENAMES.
#
# An earlier version of this check ran `ls "$CNI_CONF_DIR" | grep -q istio`,
# and that is wrong in Istio's DEFAULT configuration. In chained mode
# (cni.chained=true, the default) istio-cni does not write a file of its own:
# it edits the conflist k3s already placed there - on k3s that is
# 10-flannel.conflist - and appends itself to the `plugins` array. A fully
# correct install therefore leaves NO filename containing "istio", and the
# filename check fails on a healthy cluster.
#
# That matters more than a cosmetic bug. This gate exists to catch a silent
# downgrade to no enforcement, and a gate that fires on a healthy cluster is
# one an operator learns to ignore - at which point it protects nothing. So
# the check now asserts the two things that have to be true:
#
#   1. some conflist in the dir NAMES istio-cni in its plugin chain
#   2. the istio-cni binary is in the dir k3s loads plugins from
#
# Both, because either alone is satisfiable without redirection working: a
# chained config pointing at a missing binary fails the pod, and a binary
# nobody chained is never invoked.
CHAINED="$(sudo grep -l istio-cni "$CNI_CONF_DIR"/* 2>/dev/null | head -1 || true)"
BINARY_OK=no
sudo test -f "$CNI_BIN_DIR/istio-cni" && BINARY_OK=yes

if [[ -n "$CHAINED" && "$BINARY_OK" == "yes" ]]; then
  ok "istio-cni chained into $(basename "$CHAINED")"
  ok "istio-cni binary present in $CNI_BIN_DIR"
  sudo ls -l "$CNI_CONF_DIR" | sed 's/^/    /'
  sudo cat "$CHAINED" | jq -r '.plugins[]?.type' 2>/dev/null     | sed 's/^/    plugin: /' || true
else
  [[ -z "$CHAINED"           ]] && warn "No file in $CNI_CONF_DIR names istio-cni"
  [[ "$BINARY_OK" != "yes"   ]] && warn "No istio-cni binary in $CNI_BIN_DIR"
  warn "Sidecars will be injected and traffic will NOT be redirected through"
  warn "them. mTLS, AuthorizationPolicy and REGISTRY_ONLY will all silently"
  warn "do nothing."
  warn ""
  warn "Run the diagnostic - it is read-only and prints the real paths:"
  warn "    ./scripts/00a-diagnose-cni.sh"
  die  "Refusing to continue - every mesh guarantee below depends on this."
fi

log "Verifying REGISTRY_ONLY actually landed in the mesh config"
MODE="$(kubectl -n istio-system get cm istio -o jsonpath='{.data.mesh}' \
         | grep -A2 outboundTrafficPolicy | grep -o 'REGISTRY_ONLY' || true)"
if [[ "$MODE" == "REGISTRY_ONLY" ]]; then
  ok "outboundTrafficPolicy.mode = REGISTRY_ONLY"
else
  warn "outboundTrafficPolicy is NOT REGISTRY_ONLY - the egress allowlist in"
  warn "istio/03-egress-allowlist.yaml will have no effect and attack-05 will"
  warn "report a successful exfiltration."
  die  "Refusing to continue."
fi

cat <<'MSG'

==> Cluster and mesh ready.

Next, in order:
  ./scripts/01-install-policy-engines.sh   # Kyverno + Falco
  ./scripts/02-install-argocd.sh           # ArgoCD, then the root app

Sanity check before continuing:
  kubectl get pods -A
  free -h        # expect ~3.0 GB used before Kyverno, Falco and ArgoCD

MSG
