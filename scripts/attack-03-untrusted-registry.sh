#!/usr/bin/env bash
# ATTACK 3 — pull from a registry nobody declared. Expect refusal at admission.
#
#   ./scripts/attack-03-untrusted-registry.sh
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

# docker.io/library/nginx. A real, popular, perfectly well-maintained image —
# chosen precisely because there is nothing wrong with it. The policy is not a
# judgement about nginx; it is a statement that this cluster runs artifacts
# from two places and this is not one of them. A test using something
# obviously malicious would make the control look like malware detection,
# which is not what it is.
BAD_IMG="docker.io/library/nginx:1.27-alpine"
POD=attack-registry

attack_header 3 "Image from an undeclared registry" \
  "3 — Kyverno allowed-registries" \
  "Pod REJECTED at admission, naming /spec/containers/0/image"

kubectl -n zt-prod delete pod "$POD" --ignore-not-found >/dev/null 2>&1

hdr "Submitting a pod that pulls from docker.io"
note "$BAD_IMG"
rule
OUT="$(try_apply <<POD
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: zt-prod
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    seccompProfile: {type: RuntimeDefault}
    runAsNonRoot: true
    runAsUser: 10001
  containers:
    - name: c
      image: $BAD_IMG
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
      resources:
        requests: {cpu: 10m, memory: 32Mi}
        limits: {memory: 64Mi}
POD
)"; RC=$?
printf '%s\n' "$OUT"
rule

MODE="$(kubectl get clusterpolicy allowed-registries \
         -o jsonpath='{.spec.validationFailureAction}' 2>/dev/null)"

if [[ $RC -ne 0 ]]; then
  verdict 0 "the undeclared registry was refused"
  note "Two things worth noticing in that message."
  note
  note "1. It names the PATH, /spec/containers/0/image, not the image. When a"
  note "   legitimate pod is rejected by this policy the path is usually"
  note "   /spec/containers/1/image — container 1 being the Istio sidecar,"
  note "   which is added by a mutating webhook AFTER the pod is submitted."
  note "   That is why docker.io/istio is on the allowlist, and why searching"
  note "   the repository for the offending image finds nothing."
  note
  note "2. This is a NAME check, not an identity check. Anyone who can push"
  note "   to ghcr.io/syed-amjad satisfies it. Closing that gap is what the"
  note "   signature policy in attack 1 is for. Neither is sufficient alone."
elif [[ ! "$MODE" =~ ^[Ee]nforce$ ]]; then
  warn "Admitted, because allowed-registries is in ${MODE:-Audit}."
  kubectl get polr -n zt-prod 2>/dev/null | sed 's/^/      /'
  kubectl -n zt-prod delete pod "$POD" --ignore-not-found >/dev/null 2>&1
  note "Run ./scripts/policy-mode.sh enforce and try again."
  verdict 1 "not yet proven — still in Audit"
else
  bad "Admitted in Enforce mode. Check the glob in policy 03 against the"
  note "image string as the API server sees it:"
  note "    kubectl -n zt-prod get pod $POD -o jsonpath='{.spec.containers[*].image}'"
  kubectl -n zt-prod delete pod "$POD" --ignore-not-found >/dev/null 2>&1
  verdict 1 "the registry allowlist is not enforcing"
fi

hdr "Confirming the allowlist does not block the sidecar it has to permit"
# The negative half of this test. An allowlist that rejects everything is not
# a working allowlist, and the most likely thing for it to break is the
# injected sidecar — which would show up as the whole mesh failing rather than
# as a policy problem.
RUNNING="$(kubectl -n zt-prod get pods -l app=api -o jsonpath='{.items[0].status.phase}' 2>/dev/null)"
if [[ "$RUNNING" == "Running" ]]; then
  ok "api is Running with its sidecar — docker.io/istio is correctly permitted"
  kubectl -n zt-prod get pod -l app=api \
    -o jsonpath='{range .items[0].spec.containers[*]}      {.name}  {.image}{"\n"}{end}' 2>/dev/null
else
  warn "api is not Running (phase: ${RUNNING:-absent})."
  warn "If this policy is in Enforce and api cannot start, the sidecar image"
  warn "is probably being refused. Check the ReplicaSet events:"
  warn "    kubectl -n zt-prod describe rs -l app=api | tail -20"
fi
