#!/usr/bin/env bash
# ATTACK 4 — call api from a workload that is not permitted to. Expect denial
# at api's sidecar, on IDENTITY rather than on label.
#
#   ./scripts/attack-04-unauthorised-service-call.sh
#
# The attacker pod is labelled app=web ON PURPOSE. That label is what
# network/02-allow-web-to-api.yaml selects on, so layer 5 PERMITS this
# request — a NetworkPolicy cannot tell a pod that is web from a pod that says
# it is web, because any workload author can write any label.
#
# What stops it is the ServiceAccount. The AuthorizationPolicy names
# `cluster.local/ns/zt-prod/sa/web`, an identity that comes from a certificate
# istiod issued for a ServiceAccount, and which cannot be claimed by
# assertion. That gap between a claim and a credential is the reason both
# layers are in the architecture.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_real_digest

IMG="$(signed_image api)"
URL="http://api.zt-prod.svc.cluster.local:8000"

attack_header 4 "Service call from an unauthorised workload" \
  "6 — Istio AuthorizationPolicy on mTLS identity" \
  "DENIED at api's sidecar. With a sidecar: HTTP 403. Without: connection reset"

cleanup() {
  kubectl -n zt-prod delete pod attack-imposter attack-plaintext \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

spawn() {  # $1 = name, $2 = extra metadata
  cat <<POD | kubectl apply -f - >/dev/null 2>&1
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: zt-prod
$2
spec:
  restartPolicy: Never
  # The default ServiceAccount, NOT `web`. This is the entire attack: the pod
  # looks like web to every label selector and is a different principal to
  # the mesh.
  serviceAccountName: default
  securityContext:
    seccompProfile: {type: RuntimeDefault}
    runAsNonRoot: true
    runAsUser: 10001
  containers:
    - name: c
      image: $IMG
      command: ["sleep", "900"]
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
      resources:
        requests: {cpu: 10m, memory: 32Mi}
        limits: {memory: 64Mi}
POD
}

# Reports the HTTP status when one exists, or the transport error when the
# connection never got that far. The DIFFERENCE between those two outcomes is
# the finding in this attack, so the probe has to be able to tell them apart.
probe() {  # $1 = pod, $2 = path
  kubectl -n zt-prod exec -i "$1" -- python3 - "$URL$2" <<'PY' 2>/dev/null
import sys, urllib.error, urllib.request
try:
    r = urllib.request.urlopen(sys.argv[1], timeout=8)
    print(f"HTTP {r.status}  body={r.read()[:120].decode(errors='replace')}")
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}  body={e.read()[:120].decode(errors='replace')}")
except Exception as e:
    print(f"NO HTTP RESPONSE  {type(e).__name__}: {str(e)[:140]}")
PY
}

# ---------------------------------------------------------------------------
hdr "Variant A — imposter WITH a sidecar (presents a real but wrong identity)"
spawn attack-imposter '  labels:
    app: web'
if kubectl -n zt-prod wait --for=condition=Ready pod/attack-imposter --timeout=120s >/dev/null 2>&1; then
  rule
  A="$(probe attack-imposter /data)"
  printf '      %s\n' "$A"
  rule
  if printf '%s' "$A" | grep -q 'HTTP 403'; then
    ok "HTTP 403 — refused by the AuthorizationPolicy"
    note "An HTTP response exists, so the connection WAS established and mTLS"
    note "succeeded: the imposter has a valid certificate. It is just a"
    note "certificate for the wrong ServiceAccount. The mesh authenticated it"
    note "and then declined to authorise it, which are two separate steps."
  elif printf '%s' "$A" | grep -q 'HTTP 200'; then
    bad "HTTP 200 — an unauthorised workload reached api"
    note "Either the AuthorizationPolicy is absent, or the port is not named"
    note "http (so the sidecar cannot see methods and paths), or traffic is"
    note "bypassing the sidecar entirely. Run 03-verify-enforcement.sh."
  else
    warn "No HTTP response. Expected 403 here — check whether the pod's own"
    warn "egress is being blocked by NetworkPolicy before it reaches api."
  fi
else
  warn "attack-imposter never became Ready"
  kubectl -n zt-prod describe pod attack-imposter 2>/dev/null | tail -15 | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
hdr "Variant B — imposter WITHOUT a sidecar (no identity at all)"
note "Same label, same ServiceAccount, injection disabled. The request leaves"
note "as plaintext, so it is refused one layer earlier and differently."
spawn attack-plaintext '  labels:
    app: web
  annotations:
    sidecar.istio.io/inject: "false"'
if kubectl -n zt-prod wait --for=condition=Ready pod/attack-plaintext --timeout=90s >/dev/null 2>&1; then
  rule
  B="$(probe attack-plaintext /data)"
  printf '      %s\n' "$B"
  rule
  if printf '%s' "$B" | grep -q 'NO HTTP RESPONSE'; then
    ok "Connection refused before any HTTP response existed"
    note "This is STRICT PeerAuthentication, not the AuthorizationPolicy. The"
    note "TLS handshake failed, so there was never a request to authorise."
    note
    note "Both variants are 'denied', and recording them as one result would"
    note "lose the useful part: in A the mesh knew who the caller was and said"
    note "no; in B it never found out. A control set that only ever sees B is"
    note "a control set whose authorization rules have never been exercised."
  elif printf '%s' "$B" | grep -q 'HTTP'; then
    bad "A plaintext request got an HTTP response"
    note "STRICT mTLS is not in force, or traffic is bypassing the sidecar."
    note "This is the failure 03-verify-enforcement.sh check 1 exists to catch."
  fi
else
  warn "attack-plaintext never became Ready"
fi

# ---------------------------------------------------------------------------
hdr "The positive control — the REAL web workload, and path granularity"
note "A deny-all that denies everything proves nothing. The legitimate caller"
note "must succeed, and must be refused the paths it was not granted."
WEB_POD="$(kubectl -n zt-prod get pod -l app=web -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
if [[ -n "$WEB_POD" ]]; then
  rule
  printf '      /data   (granted)     %s\n' "$(probe "$WEB_POD" /data)"
  printf '      /whoami (NOT granted) %s\n' "$(probe "$WEB_POD" /whoami)"
  rule
  note "/data succeeds and /whoami is refused, from the SAME pod over the SAME"
  note "connection, by the same policy. That path-level distinction is what"
  note "NetworkPolicy structurally cannot express: at L3/L4 a connection is"
  note "permitted or not, and every URL on the far side rides the same one."
else
  warn "No web pod found. Has ArgoCD synced the workloads?"
fi
