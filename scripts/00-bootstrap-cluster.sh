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
# tmux is not optional comfort. 01 and 02 run helm installs that print
# nothing for minutes, and an idle SSH session through a NAT gateway gets
# closed - which kills helm mid-install and leaves the release stuck in
# `pending-install`. Both scripts refuse to start outside tmux for that
# reason, so install it here while we are already root.
sudo apt-get install -y -qq curl git jq apt-transport-https tmux

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
# DISCOVER the CNI directories. Do not hardcode them. See SETTING 2 below for
# what hardcoding them cost.
#
# The authority is k3s's own containerd configuration, which is what actually
# resolves plugin names. Probing is the fallback, and it probes for `flannel`
# specifically: flannel is the plugin k3s itself installed and uses, so the
# directory holding it is by definition the directory containerd searches.
# TWO THINGS IN HERE WERE WRONG ON THE FIRST ATTEMPT. Both are marked, because
# both are easy to write again.
detect_cni_dirs() {
  local cdir=/var/lib/rancher/k3s/agent/etc/containerd

  # (1) `grep -r` ON THE DIRECTORY, never `"$cdir"/config.toml*`. A glob is
  # expanded by THIS shell, which is unprivileged, and /var/lib/rancher/k3s is
  # 0700 root - so the glob matches nothing, the literal * reaches grep, and
  # grep fails. Exactly the trap that made the conflist check report a missing
  # istio-cni on a healthy node, written a second time in the fix for it.
  #
  # (2) `|| true` ON EVERY SUBSTITUTION. A miss here is expected, and `head -1`
  # closes the pipe early so grep can take SIGPIPE even on a hit. Under
  # `set -euo pipefail` a failing pipeline inside a command substitution aborts
  # the script - and because the failure is an assignment, bash prints NOTHING.
  # The first version of this function exited the bootstrap silently, right
  # after printing its own log line, with the exit status of a grep nobody saw.
  CNI_BIN_DIR="$(sudo grep -rho 'bin_dir *= *"[^"]*"' "$cdir" 2>/dev/null \
      | head -1 | sed 's/.*= *"//; s/".*//' || true)"
  if [ -z "${CNI_BIN_DIR:-}" ] || ! sudo test -x "$CNI_BIN_DIR/flannel"; then
    CNI_BIN_DIR=""
    for d in /var/lib/rancher/k3s/data/cni \
             /var/lib/rancher/k3s/data/current/bin \
             /opt/cni/bin; do
      if sudo test -x "$d/flannel"; then CNI_BIN_DIR="$d"; break; fi
    done
  fi

  CNI_CONF_DIR="$(sudo grep -rho 'conf_dir *= *"[^"]*"' "$cdir" 2>/dev/null \
      | head -1 | sed 's/.*= *"//; s/".*//' || true)"
  if [ -z "${CNI_CONF_DIR:-}" ] || ! sudo test -d "$CNI_CONF_DIR"; then
    CNI_CONF_DIR=/var/lib/rancher/k3s/agent/etc/cni/net.d
  fi
}

log "Discovering the CNI directories containerd actually uses"
detect_cni_dirs
[ -n "${CNI_BIN_DIR:-}" ] || die "Could not find the directory holding the flannel CNI plugin.
    Look for it:  sudo find /var/lib/rancher /opt/cni -name flannel -type f 2>/dev/null
    Then re-run:  CNI_BIN_DIR=<that dir> $0"
ok "plugin binaries: $CNI_BIN_DIR"
ok "plugin config:   $CNI_CONF_DIR"
sudo ls "$CNI_BIN_DIR" 2>/dev/null | tr '\n' ' ' | fold -w 100 -s | sed 's/^/    /'

log "Installing Istio ${ISTIO_VERSION} with CNI and REGISTRY_ONLY egress"

istioctl install -y \
  --set profile=default \
  --set components.cni.enabled=true \
  --set values.cni.cniBinDir="$CNI_BIN_DIR" \
  --set values.cni.cniConfDir="$CNI_CONF_DIR" \
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
# SETTING 2 — THE K3S CNI PATHS. The most dangerous line in this repository,
# and it was wrong. This entry is the corrected version; read it before
# touching the paths.
#
# Istio's CNI defaults are /opt/cni/bin and /etc/cni/net.d. k3s uses neither,
# and WHICH directory it uses depends on the k3s version:
#
#   k3s 1.36.5   binaries  /var/lib/rancher/k3s/data/cni
#   earlier      binaries  /var/lib/rancher/k3s/data/current/bin
#   both         config    /var/lib/rancher/k3s/agent/etc/cni/net.d
#
# This script used to hardcode `data/current/bin`. On k3s v1.36.5 that
# directory still EXISTS and still contains plugins, so every check that the
# binary had landed passed — while containerd was resolving plugin names
# against /var/lib/rancher/k3s/data/cni, where istio-cni was not. The result
# was far worse than the silent downgrade described below:
#
#   plugin type="istio-cni" failed (add):
#   failed to find plugin "istio-cni" in path [/var/lib/rancher/k3s/data/cni]
#
# istio-cni was correctly CHAINED into 10-flannel.conflist and the binary was
# unreachable, so every CNI ADD on the node failed — not just mesh pods. And
# because flannel allocates the address before the chain reaches istio-cni,
# each of the kubelet's retries leaked one host-local lease. 254 retries later
# the pool was empty and every pod on the node was failing with
# `no IP addresses available`, an error that names flannel and points nowhere
# near the cause. One wrong path took out the whole node 14 minutes later.
#
# So the paths are now DISCOVERED from k3s's containerd config, with a probe
# for the flannel binary as the fallback — flannel is the plugin k3s itself
# uses, so wherever it lives is where containerd looks. Hardcoding a path that
# moves between minor versions was the actual defect; the old comment below
# even predicted it would move and still left the value hardcoded.
#
# The silent-downgrade failure mode described next is still real, and is what
# happens when the CONFIG directory is wrong rather than the binary directory.
# Leave the config path wrong and the istio-cni DaemonSet starts, reports
# Running, reports Ready, and writes its configuration into a directory that
# nothing reads. Then:
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
# Re-detect rather than reuse: istioctl install can take minutes and a check
# that reads back the same variable it wrote only proves the variable, never
# the filesystem.
detect_cni_dirs

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
# grep -r, NOT a glob. `sudo grep -l istio-cni "$CNI_CONF_DIR"/*` expands
# the glob in the CALLING shell, which is unprivileged, and k3s sets
# /var/lib/rancher/k3s to 0700 root. The glob matches nothing, the literal
# * is passed to grep, grep fails into /dev/null, and the gate reports a
# missing config on a cluster where it is present. sudo elevates the
# command; it cannot elevate the shell that built the arguments.
CHAINED="$(sudo grep -rl istio-cni "$CNI_CONF_DIR" 2>/dev/null | head -1 || true)"
BINARY_OK=no
sudo test -f "$CNI_BIN_DIR/istio-cni" && BINARY_OK=yes

if [[ -n "$CHAINED" && "$BINARY_OK" == "yes" ]]; then
  ok "istio-cni chained into $(basename "$CHAINED")"
  ok "istio-cni binary present in $CNI_BIN_DIR"
  sudo ls -l "$CNI_CONF_DIR" | sed 's/^/    /'
  sudo cat "$CHAINED" | jq -r '.plugins[]?.type' 2>/dev/null     | sed 's/^/    plugin: /' || true
else
  [[ -z "$CHAINED" ]] && warn "No file in $CNI_CONF_DIR names istio-cni"
  if [[ "$BINARY_OK" != "yes" ]]; then
    warn "No istio-cni binary in $CNI_BIN_DIR - the directory containerd searches."
    # Name this case explicitly. It is the one that cost a node: the binary is
    # present somewhere plausible, so "did it install?" answers yes, while
    # containerd resolves names against a different directory and fails every
    # ADD on the node - mesh pods and non-mesh pods alike.
    OTHER="$(sudo find /var/lib/rancher /opt/cni -name 'istio-cni' -type f 2>/dev/null \
             | grep -v "^$CNI_BIN_DIR/" | head -3 || true)"
    if [[ -n "$OTHER" ]]; then
      warn ""
      warn "IT IS PRESENT ELSEWHERE, which is worse than absent:"
      echo "$OTHER" | sed 's/^/      /'
      warn "containerd resolves plugin names only under $CNI_BIN_DIR, so every"
      warn "CNI ADD on this node will fail with:"
      warn "    failed to find plugin \"istio-cni\" in path [$CNI_BIN_DIR]"
      warn "and each failed retry leaks one host-local address lease. After"
      warn "~254 retries every pod on the node fails with 'no IP addresses"
      warn "available', which names flannel and points nowhere near this."
    fi
  fi
  warn ""
  warn "Run the diagnostic - it is read-only and prints the real paths:"
  warn "    ./scripts/00a-diagnose-cni.sh"
  die  "Refusing to continue - every mesh guarantee below depends on this."
fi

# ---------------------------------------------------------------------------
# THE FUNCTIONAL CHECK. The two assertions above read the filesystem, and both
# of them passed on the run that took the node down - the binary was where
# they looked, just not where containerd looked. The only check that cannot be
# fooled by a path is starting a pod and seeing whether it gets an address.
# ---------------------------------------------------------------------------
log "Can a brand-new pod actually get an IP through this chain?"
kubectl delete pod cni-canary --ignore-not-found --force --grace-period=0 >/dev/null 2>&1 || true
kubectl run cni-canary --image=registry.k8s.io/pause:3.10 --restart=Never >/dev/null 2>&1 \
  || warn "could not create the canary pod"

CANARY_IP=""
for _ in $(seq 1 30); do
  CANARY_IP="$(kubectl get pod cni-canary -o jsonpath='{.status.podIP}' 2>/dev/null || true)"
  [ -n "$CANARY_IP" ] && break
  sleep 2
done

if [ -n "$CANARY_IP" ]; then
  ok "canary pod got $CANARY_IP - the CNI chain works end to end"
  kubectl delete pod cni-canary --force --grace-period=0 >/dev/null 2>&1 || true
else
  warn "A new pod could NOT get an address in 60s. Events:"
  kubectl describe pod cni-canary 2>/dev/null | sed -n '/Events:/,$p' \
    | fold -w 108 -s | sed 's/^/      /'
  warn ""
  warn "STOP HERE. Do not retry in a loop - every failed sandbox leaks an"
  warn "address lease, and ~254 of them exhausts the node's whole /24."
  kubectl delete pod cni-canary --force --grace-period=0 >/dev/null 2>&1 || true
  warn "    ./scripts/00b-diagnose-pod-network.sh    # names the real cause"
  die  "Refusing to continue - pod networking is broken."
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
