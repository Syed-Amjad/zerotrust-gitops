#!/usr/bin/env bash
# ATTACK 1 — deploy an unsigned image. Expect it refused at admission.
#
#   ./scripts/attack-01-unsigned-image.sh
#
# Uses ghcr.io/syed-amjad/zt-unsigned-control, which the CI workflow publishes
# on every run with NO signature and NO id-token permission to produce one.
#
# WHY A PURPOSE-BUILT CONTROL SAMPLE AND NOT `nginx:latest`:
# nginx comes from docker.io, so the registry allowlist (policy 03) would
# refuse it first and the test would pass without the signature policy being
# consulted at all. The control image is in the same registry, under the same
# owner, built from the same Dockerfile by the same pipeline, and matched by
# the same `ghcr.io/syed-amjad/zt-*` glob. The ONLY difference is the
# signature. That is what makes the result mean something.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

UNSIGNED="ghcr.io/syed-amjad/zt-unsigned-control:latest"
POD=attack-unsigned

attack_header 1 "Unsigned image" \
  "3 — Kyverno verifyImages (keyless, Sigstore)" \
  "Pod REJECTED at admission: no matching signatures"

MODE="$(kubectl get clusterpolicy verify-image-signature \
         -o jsonpath='{.spec.validationFailureAction}' 2>/dev/null)"
hdr "Policy mode"
if [[ "$MODE" =~ ^[Ee]nforce$ ]]; then
  ok "verify-image-signature is in Enforce — the pod should be refused"
else
  warn "verify-image-signature is in ${MODE:-unknown} (not Enforce)."
  warn "The pod will be ADMITTED and the violation only reported. That is the"
  warn "intended first observation of this attack: run it in Audit, read the"
  warn "report, then run ./scripts/policy-mode.sh enforce and run it again."
fi

kubectl -n zt-prod delete pod "$POD" --ignore-not-found >/dev/null 2>&1

hdr "Submitting a pod that references the unsigned control image"
note "$UNSIGNED"
rule
# ---------------------------------------------------------------------------
# A POD, not a Deployment, and the difference is visible in the output.
#
# Policy 01 matches Pods only — see the long comment in
# policies/kyverno/01-verify-image-signature.yaml for why (matching the
# controller makes Kyverno rewrite the object ArgoCD manages, and the two then
# fight forever). The consequence is that a Deployment with an unsigned image
# is ACCEPTED and its pods are rejected afterwards, so the rejection would
# appear in ReplicaSet events rather than here.
#
# Submitting a bare Pod puts the admission response on stdout, where it can be
# read and screenshotted. The Deployment path is demonstrated at the end.
# ---------------------------------------------------------------------------
try_apply <<POD
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
      image: $UNSIGNED
      command: ["sleep", "60"]
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
      resources:
        requests: {cpu: 10m, memory: 32Mi}
        limits: {memory: 64Mi}
POD
RC=$?
rule

if [[ $RC -ne 0 ]]; then
  verdict 0 "the unsigned image was refused at admission"
  note "Read the message above: it should name the policy"
  note "(verify-image-signature) and say no matching signatures were found."
  note
  note "A note on that wording: 'no matching signatures' is ALSO what you get"
  note "when a signature exists but its certificate identity does not match"
  note "the subject pinned in the policy. The two are not distinguished in"
  note "the message, so when a legitimate image is rejected, check the"
  note "subject before concluding the signing step failed."
else
  if [[ "$MODE" =~ ^[Ee]nforce$ ]]; then
    verdict 1 "an unsigned image was ADMITTED while the policy was in Enforce"
    note "Check that the image really is unsigned and really does match the"
    note "policy glob 'ghcr.io/syed-amjad/zt-*':"
    note "    cosign verify --certificate-identity-regexp '.*' \\"
    note "      --certificate-oidc-issuer https://token.actions.githubusercontent.com \\"
    note "      $UNSIGNED"
    note "If that command SUCCEEDS, the control image got signed by accident."
  else
    warn "Admitted, as expected in Audit mode. The violation is recorded:"
    kubectl get polr -A -o wide 2>/dev/null | grep -i "$POD" | sed 's/^/      /' || \
      kubectl get polr -n zt-prod 2>/dev/null | sed 's/^/      /'
    note
    note "Now run:  ./scripts/policy-mode.sh enforce"
    note "then this script again. Recording both outcomes is the demonstration."
  fi
  kubectl -n zt-prod delete pod "$POD" --ignore-not-found >/dev/null 2>&1
fi

hdr "The same attack through a Deployment, for contrast"
note "Policy 01 matches Pods, so the Deployment itself is accepted and the"
note "rejection surfaces one level down. This is the shape the failure takes"
note "when it arrives through the GitOps path rather than from kubectl."
kubectl -n zt-prod delete deploy attack-unsigned-deploy --ignore-not-found >/dev/null 2>&1
kubectl -n zt-prod create deployment attack-unsigned-deploy \
  --image="$UNSIGNED" >/dev/null 2>&1 && ok "Deployment ACCEPTED (as predicted)"
sleep 8
note "ReplicaSet events — the real reason, one level down:"
kubectl -n zt-prod describe rs -l app=attack-unsigned-deploy 2>/dev/null \
  | grep -iA3 'Events\|FailedCreate' | head -14 | sed 's/^/      /' \
  || note "(no events yet - re-run: kubectl -n zt-prod describe rs -l app=attack-unsigned-deploy)"
kubectl -n zt-prod delete deploy attack-unsigned-deploy --ignore-not-found >/dev/null 2>&1
