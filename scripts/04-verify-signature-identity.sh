#!/usr/bin/env bash
# Verify the published signature BY HAND, and prove the identity binding is
# what makes it worth anything.
#
#   ./scripts/04-verify-signature-identity.sh
#
# =========================================================================
# THE STRONGEST CLAIM THIS PROJECT MAKES, TESTED DIRECTLY.
#
# The claim on the website is that compromising the registry alone is not
# enough — an attacker would also need the build workflow's identity. Kyverno
# enforces that at admission, but a passing admission check cannot distinguish
# "the signature matched the pinned identity" from "the policy is looser than
# I think it is".
#
# So this runs cosign twice against the same image:
#
#   1. with the CORRECT workflow identity          → must SUCCEED
#   2. with a DIFFERENT, plausible identity        → must FAIL
#
# The second run is the one that matters. Without it, a policy whose subject
# had been loosened to a wildcard would pass test 1 exactly as well.
# =========================================================================
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_real_digest

ISSUER="https://token.actions.githubusercontent.com"
GOOD='^https://github\.com/Syed-Amjad/supply-chain-app/\.github/workflows/build-sign\.yml@refs/heads/main$'

# A WRONG identity that is deliberately plausible rather than absurd: the same
# repository, the same branch, a different workflow file. That is the shape a
# real attack takes — an attacker who can add a workflow to the repository,
# rather than one who signs with a random key.
WRONG='^https://github\.com/Syed-Amjad/supply-chain-app/\.github/workflows/release\.yml@refs/heads/main$'

command -v cosign >/dev/null || { bad "cosign not installed - run 00-bootstrap-cluster.sh"; exit 1; }

for svc in api web; do
  IMG="$(signed_image "$svc")"
  hdr "zt-${svc}  ${IMG##*@}"

  rule
  printf '      1. correct identity (must SUCCEED)\n'
  if cosign verify \
       --certificate-identity-regexp "$GOOD" \
       --certificate-oidc-issuer "$ISSUER" \
       "$IMG" >/tmp/cosign-good.json 2>/tmp/cosign-good.err; then
    ok "verified"
    # The certificate's own fields, which are the evidence. These come from
    # Fulcio and cannot be set by whoever pushed the image.
    jq -r '.[0].optional |
      "      subject : \(.Subject // "?")\n      issuer  : \(.Issuer // "?")\n      logIndex: \(.Bundle.Payload.logIndex // "?")"' \
      /tmp/cosign-good.json 2>/dev/null || head -5 /tmp/cosign-good.json
    note "logIndex is the entry number in the public Rekor transparency log."
    note "It is what makes a backdated signature detectable: an attacker"
    note "cannot insert an entry before one that is already there."
  else
    bad "the correct identity did NOT verify"
    sed 's/^/      /' /tmp/cosign-good.err | head -8
    note "If this says 'no matching signatures', check the subject above"
    note "against the workflow file name and branch. The message is the same"
    note "for a missing signature and a mismatched identity."
  fi

  rule
  printf '      2. wrong identity, same repo and branch (must FAIL)\n'
  if cosign verify \
       --certificate-identity-regexp "$WRONG" \
       --certificate-oidc-issuer "$ISSUER" \
       "$IMG" >/dev/null 2>/tmp/cosign-bad.err; then
    bad "A DIFFERENT workflow identity verified against this image."
    note "The identity binding is not doing anything. Any workflow in the"
    note "repository can sign images this cluster will accept."
  else
    ok "refused, as required"
    sed 's/^/      /' /tmp/cosign-bad.err | head -3
    note "Same registry, same digest, same repository, same branch — and a"
    note "different workflow file. Refused. THAT is the claim: an attacker"
    note "who steals a GHCR token can push any bytes they like and cannot"
    note "produce a Fulcio certificate naming this workflow."
  fi

  rule
  printf '      3. the SBOM attestation\n'
  if cosign verify-attestation --type spdxjson \
       --certificate-identity-regexp "$GOOD" \
       --certificate-oidc-issuer "$ISSUER" \
       "$IMG" >/tmp/att.json 2>/tmp/att.err; then
    ok "SBOM attestation verifies, bound to the same identity and digest"
    PKGS="$(jq -r '.payload' /tmp/att.json 2>/dev/null | base64 -d 2>/dev/null \
            | jq -r '.predicate.packages | length' 2>/dev/null || echo "?")"
    note "packages in the SBOM: ${PKGS}"
    note "An attestation is a SIGNED STATEMENT ABOUT the image, not a"
    note "signature OF it — so the SBOM cannot be swapped for one describing"
    note "a different, cleaner image."
  else
    warn "no verifiable SBOM attestation"
    sed 's/^/      /' /tmp/att.err | head -4
  fi
  echo
done

rm -f /tmp/cosign-good.json /tmp/cosign-good.err /tmp/cosign-bad.err /tmp/att.json /tmp/att.err

hdr "What this does not prove"
note "A verified signature says the artifact came from this pipeline. It says"
note "nothing about whether the pipeline produced something safe — a signed"
note "image containing a vulnerable dependency is signed, correctly."
note
note "That is the scan gate's job, and the reason the CI workflow signs AFTER"
note "scanning rather than before. The order makes the signature mean 'built"
note "here AND passed the gate' instead of just 'built here'."
