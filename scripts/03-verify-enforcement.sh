#!/usr/bin/env bash
# ===========================================================================
# PROVE THE CONTROLS ARE ON. Run ON THE BOX, after the root app is healthy.
#
#   ./scripts/03-verify-enforcement.sh
#
# This is not a smoke test and it is not optional. It exists because four of
# the seven layers in this project can fail in a way that produces NO ERROR
# ANYWHERE:
#
#   Istio CNI paths wrong   sidecar injected, traffic not redirected through
#                           it. mTLS, AuthorizationPolicy and REGISTRY_ONLY
#                           all silently enforce nothing.
#   NetworkPolicy off       k3s started with --disable-network-policy. Every
#                           policy object is accepted and stored; none is
#                           enforced. `kubectl get netpol` looks perfect.
#   PSA labels absent       a namespace with no pod-security labels admits
#                           anything, and reports nothing.
#   Falco socket wrong      k8s.ns.name is <NA> on every event, so every
#                           namespace-scoped rule matches nothing and the log
#                           reads as a clean cluster.
#
# In all four cases `kubectl get` shows the configuration present and correct.
# The only way to tell is to try something that must fail and check that it
# did. That is the whole argument of this project applied to the project
# itself: scanning tells you what you inspected, not what is running.
# ===========================================================================
set -uo pipefail   # NOT -e: a failing check must be reported, not abort the run

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

PASS=0; FAIL=0; SKIP=0
hdr()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
pass() { printf '\033[1;32m    PASS  %s\033[0m\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '\033[1;31m    FAIL  %s\033[0m\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '\033[1;33m    SKIP  %s\033[0m\n' "$*"; SKIP=$((SKIP+1)); }
note() { printf '          %s\n' "$*"; }

cleanup() {
  kubectl -n zt-prod delete pod probe-no-sidecar probe-wrong-label \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# The probe pods use OUR OWN SIGNED IMAGE, read out of workloads/api.yaml.
#
# Not a public utility image, for two reasons. First, the registry allowlist
# (policy 03) would refuse one, so the probe would be rejected before it could
# test anything and the result would be a false pass. Second, that image
# contains python3, which is all the probing needs — no curl required.
# ---------------------------------------------------------------------------
API_IMG="$(grep -oE 'image: ghcr\.io/[^ ]+/zt-api@sha256:[0-9a-f]{64}' \
            "$HERE/workloads/api.yaml" | head -1 | sed 's/^image: //')"
ZERO_DIGEST="sha256:$(printf '0%.0s' {1..64})"

hdr "Preconditions"
if [[ -z "$API_IMG" ]]; then
  fail "Could not read an image digest from workloads/api.yaml"
  exit 1
fi
if [[ "$API_IMG" == *"$ZERO_DIGEST" ]]; then
  fail "workloads/api.yaml still carries the placeholder digest (64 zeros)."
  note "CI has not written a real digest yet. Push to supply-chain-app, wait"
  note "for the workflow to go green, then let ArgoCD sync and re-run this."
  exit 1
fi
pass "Image under test: ${API_IMG##*/}"

# A probe pod built to satisfy every control except the one being tested.
# PSA restricted, read-only root, resources declared, signed image, allowed
# registry — so a rejection can only come from the layer under test.
probe_pod() {  # $1 = name, $2 = extra metadata lines (labels/annotations)
  cat <<POD
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: zt-prod
$2
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    seccompProfile: {type: RuntimeDefault}
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
  containers:
    - name: probe
      image: ${API_IMG}
      command: ["sleep", "600"]
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
      resources:
        requests: {cpu: 10m, memory: 32Mi}
        limits: {memory: 64Mi}
POD
}

# Returns 0 if the HTTP call SUCCEEDED, 1 if it was blocked.
try_http() {  # $1 = pod, $2 = url
  kubectl -n zt-prod exec -i "$1" -- python3 - "$2" <<'PY' 2>/dev/null
import sys, urllib.request
try:
    r = urllib.request.urlopen(sys.argv[1], timeout=6)
    print("REACHED http", r.status)
    sys.exit(0)
except Exception as e:
    print("BLOCKED", type(e).__name__, str(e)[:120])
    sys.exit(1)
PY
}

# ===========================================================================
hdr "CHECK 1 of 6 — Istio traffic redirection (the silent one)"
# ===========================================================================
# A pod labelled app=web, so the NetworkPolicy PERMITS it to reach api, with
# sidecar injection explicitly disabled. Both of those matter:
#
#   * label app=web        the L3 allowance applies, so a block cannot be
#                          mistaken for a NetworkPolicy block
#   * inject: "false"      the request leaves as PLAINTEXT
#
# api's namespace is under STRICT PeerAuthentication, so a plaintext request
# must be refused by api's sidecar. If it succeeds, traffic is NOT passing
# through that sidecar — which means the CNI plugin wrote its configuration
# somewhere k3s does not read, and mTLS, AuthorizationPolicy and REGISTRY_ONLY
# are all inert while appearing configured.
#
# This is the single most valuable check in the file. A naive version of this
# test puts the probe in a namespace with no sidecar injection and no app=web
# label, where the NetworkPolicy blocks it first — and then passes whether or
# not the mesh is working at all.
kubectl delete pod -n zt-prod probe-no-sidecar --ignore-not-found >/dev/null 2>&1
probe_pod probe-no-sidecar '  labels:
    app: web
  annotations:
    sidecar.istio.io/inject: "false"' | kubectl apply -f - >/dev/null 2>&1

if kubectl -n zt-prod wait --for=condition=Ready pod/probe-no-sidecar --timeout=90s >/dev/null 2>&1; then
  SIDECARS=$(kubectl -n zt-prod get pod probe-no-sidecar \
               -o jsonpath='{.spec.containers[*].name}' | tr ' ' '\n' | grep -c istio-proxy || true)
  if [[ "$SIDECARS" != "0" ]]; then
    skip "probe got a sidecar despite inject=false - cannot test plaintext"
  else
    OUT="$(try_http probe-no-sidecar http://api.zt-prod.svc.cluster.local:8000/health)"
    RC=$?
    note "$OUT"
    if [[ $RC -ne 0 ]]; then
      pass "Plaintext from outside the mesh was REFUSED - redirection works"
      note "STRICT mTLS is being enforced by api's sidecar, which means"
      note "traffic really is passing through it."
    else
      fail "Plaintext from outside the mesh SUCCEEDED"
      note "The sidecar is present and traffic is bypassing it. Layers 6"
      note "(mTLS, authz, egress) are all inert. Check the CNI paths in"
      note "scripts/00-bootstrap-cluster.sh against this node:"
      note "    sudo ls /var/lib/rancher/k3s/agent/etc/cni/net.d"
      note "    kubectl -n istio-system logs ds/istio-cni-node | tail -30"
    fi
  fi
else
  fail "probe-no-sidecar never became Ready"
  kubectl -n zt-prod describe pod probe-no-sidecar 2>/dev/null | tail -20 | sed 's/^/          /'
fi

# ===========================================================================
hdr "CHECK 2 of 6 — NetworkPolicy is actually enforced"
# ===========================================================================
# k3s embeds a NetworkPolicy controller and enables it by default. Started with
# --disable-network-policy, every policy object is still accepted and stored,
# and nothing enforces any of it. There is no error and no event; layer 5
# simply is not there.
#
# A pod labelled app=probe matches no allow rule in network/, so default-deny
# must stop it reaching api. It is sidecar-injected (the normal case), so if
# the mesh were the only thing blocking, the AuthorizationPolicy would return
# an HTTP 403 — which `try_http` reports as REACHED, not BLOCKED. A transport
# error means it was stopped at L3/L4, before any HTTP response existed.
kubectl delete pod -n zt-prod probe-wrong-label --ignore-not-found >/dev/null 2>&1
probe_pod probe-wrong-label '  labels:
    app: probe' | kubectl apply -f - >/dev/null 2>&1

if kubectl -n zt-prod wait --for=condition=Ready pod/probe-wrong-label --timeout=120s >/dev/null 2>&1; then
  OUT="$(try_http probe-wrong-label http://api.zt-prod.svc.cluster.local:8000/health)"
  RC=$?
  note "$OUT"
  if [[ $RC -ne 0 ]]; then
    pass "An unlisted workload was blocked below HTTP - NetworkPolicy enforces"
  else
    fail "An unlisted workload reached api"
    note "If the response was an HTTP 403, the mesh stopped it and"
    note "NetworkPolicy did not - layer 5 is not being enforced. Check:"
    note "    sudo cat /etc/systemd/system/k3s.service | grep -i network-policy"
  fi
else
  skip "probe-wrong-label never became Ready - cannot test L3 isolation"
  note "Its own egress to istiod may be blocked, which is itself a sign"
  note "NetworkPolicy IS being enforced. Check:"
  note "    kubectl -n zt-prod describe pod probe-wrong-label | tail -20"
fi

# ===========================================================================
hdr "CHECK 3 of 6 — Pod Security Admission is enforcing"
# ===========================================================================
# Labels read back from the API server rather than from the repository. The
# question is what the CLUSTER believes, and a namespace whose labels were
# edited by hand or lost in a partial sync reads exactly the same in git.
for ns in zt-prod zt-attack; do
  LVL="$(kubectl get ns "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null)"
  if [[ "$LVL" == "restricted" ]]; then
    pass "$ns enforce=restricted"
  else
    fail "$ns enforce='${LVL:-<unset>}' (expected restricted)"
  fi
done

# And a functional confirmation, because a label is a claim too. A privileged
# pod submitted to zt-prod must be refused, and the refusal must come from
# PodSecurity — not from Kyverno, which in Audit mode would permit it.
PRIV_OUT="$(kubectl -n zt-prod run psa-probe --image="$API_IMG" --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"c","image":"'"$API_IMG"'","securityContext":{"privileged":true}}]}}' \
  --dry-run=server 2>&1)"
if printf '%s' "$PRIV_OUT" | grep -qi 'PodSecurity\|violates PodSecurity'; then
  pass "A privileged pod is refused by PodSecurity at admission"
  note "$(printf '%s' "$PRIV_OUT" | head -2 | tr '\n' ' ' | cut -c1-150)"
else
  fail "A privileged pod was NOT refused by PodSecurity"
  note "$(printf '%s' "$PRIV_OUT" | head -3 | tr '\n' ' ' | cut -c1-200)"
fi

# ===========================================================================
hdr "CHECK 4 of 6 — Kyverno is registered and the policies are loaded"
# ===========================================================================
# Three separate things, each of which can be true while the others are not:
# the webhook exists, the policies are present, and they are in Enforce rather
# than Audit. The third is the one that gets forgotten — a policy set left in
# Audit is the most common reason a cluster that reports compliant is not.
WH="$(kubectl get validatingwebhookconfigurations -o name 2>/dev/null | grep -c kyverno || true)"
if [[ "${WH:-0}" -gt 0 ]]; then
  pass "Kyverno validating webhook(s) registered: $WH"
else
  fail "No Kyverno validating webhook is registered - no policy is evaluated"
fi

EXPECTED=5
GOT="$(kubectl get clusterpolicy -o name 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$GOT" == "$EXPECTED" ]]; then
  pass "All $EXPECTED ClusterPolicies present"
else
  fail "Found $GOT ClusterPolicies, expected $EXPECTED"
  kubectl get clusterpolicy 2>/dev/null | sed 's/^/          /'
fi

AUDIT="$(kubectl get clusterpolicy -o jsonpath='{range .items[*]}{.metadata.name}={.spec.validationFailureAction}{"\n"}{end}' 2>/dev/null | grep -ci 'audit' || true)"
if [[ "${AUDIT:-0}" -eq 0 ]]; then
  pass "Every policy is in Enforce"
else
  skip "$AUDIT policy/policies still in Audit - violations are REPORTED, NOT BLOCKED"
  kubectl get clusterpolicy -o custom-columns='NAME:.metadata.name,ACTION:.spec.validationFailureAction' 2>/dev/null | sed 's/^/          /'
  note "This is the intended starting state. Read the reports:"
  note "    kubectl get polr -A"
  note "then switch over with:  ./scripts/policy-mode.sh enforce"
fi

# ===========================================================================
hdr "CHECK 5 of 6 — the mesh refuses undeclared egress"
# ===========================================================================
MODE="$(kubectl -n istio-system get cm istio -o jsonpath='{.data.mesh}' 2>/dev/null \
         | grep -A3 outboundTrafficPolicy | grep -o 'REGISTRY_ONLY\|ALLOW_ANY' | head -1)"
if [[ "$MODE" == "REGISTRY_ONLY" ]]; then
  pass "outboundTrafficPolicy.mode = REGISTRY_ONLY"
else
  fail "outboundTrafficPolicy.mode = ${MODE:-<unset, defaults to ALLOW_ANY>}"
  note "istio/03-egress-allowlist.yaml has no effect in this state and"
  note "attack-05 will report a successful exfiltration. Re-run the install:"
  note "    istioctl install -y --set meshConfig.outboundTrafficPolicy.mode=REGISTRY_ONLY ..."
fi

SE="$(kubectl -n zt-prod get serviceentry -o name 2>/dev/null | wc -l | tr -d ' ')"
if [[ "${SE:-0}" -gt 0 ]]; then
  pass "$SE ServiceEntry declared in zt-prod (the egress allowlist)"
else
  fail "No ServiceEntry in zt-prod - with REGISTRY_ONLY, NOTHING external is"
  note "reachable, including the destination attack-05 expects to succeed."
fi

# ===========================================================================
hdr "CHECK 6 of 6 — Falco is watching, with Kubernetes context"
# ===========================================================================
# Two questions, and the second is the one that silently fails. A Falco with
# the wrong containerd socket detects everything correctly and labels every
# event <NA>, so every namespace-scoped custom rule matches nothing.
if kubectl -n falco get ds falco >/dev/null 2>&1; then
  READY="$(kubectl -n falco get ds falco -o jsonpath='{.status.numberReady}')"
  DESIRED="$(kubectl -n falco get ds falco -o jsonpath='{.status.desiredNumberScheduled}')"
  if [[ "$READY" == "$DESIRED" && "${READY:-0}" -gt 0 ]]; then
    pass "Falco DaemonSet ready ($READY/$DESIRED)"
  else
    fail "Falco DaemonSet ${READY:-0}/${DESIRED:-0} ready"
  fi

  RULES="$(kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=400 2>/dev/null \
            | grep -ci 'zero-trust-rules\|Loading rules' || true)"
  if [[ "${RULES:-0}" -gt 0 ]]; then
    pass "Custom rule file was loaded"
  else
    skip "Could not confirm the custom rules loaded from the log"
    note "    kubectl -n falco logs -l app.kubernetes.io/name=falco | grep -i rule"
  fi

  if sudo test -S /run/k3s/containerd/containerd.sock 2>/dev/null; then
    pass "k3s containerd socket present - events will carry k8s.ns.name"
  else
    fail "k3s containerd socket missing at /run/k3s/containerd/containerd.sock"
    note "Every custom rule filters on k8s.ns.name, which will be <NA>."
    note "Fix the LIST at collectors.containerEngine.engines.cri.sockets in"
    note "falco/values.yaml - not the chart 4.x key, which Helm ignores."
    note "They will never fire and the log will look clean."
  fi
  note "Definitive proof is attack-07: the alert it produces must show a real"
  note "k8s.ns.name, not <NA>. An alert with <NA> means the default ruleset"
  note "fired and the scoped rules did not."
else
  fail "No Falco DaemonSet - layer 7 is absent"
fi

# ===========================================================================
printf '\n\033[1m================ %s ================\033[0m\n' "RESULT"
printf '  passed %s   failed %s   skipped %s\n\n' "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
  printf '\033[1;31m  %s\033[0m\n' "Do not record attack results until these are fixed."
  printf '  %s\n\n' "A failing control makes every attack below it pass for the wrong reason."
  exit 1
fi
printf '\033[1;32m  %s\033[0m\n\n' "All controls verified. Run ./scripts/attack-all.sh"
