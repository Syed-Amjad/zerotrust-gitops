#!/usr/bin/env bash
# Shared helpers for the attack scripts. Sourced, not executed.
#
# Each attack script is standalone and readable on its own; this holds only the
# parts that would otherwise be copied seven times and drift.

# shellcheck disable=SC2034
ZT_LIB=1

hdr()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }
note() { printf '      %s\n' "$*"; }
rule() { printf '\033[2m    %s\033[0m\n' "------------------------------------------------------------"; }

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
ZT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ZT_ROOT

# ---------------------------------------------------------------------------
# The expected-outcome banner every attack prints before it runs.
#
# Stating the prediction first is not presentation. An attack script that only
# prints what happened lets you read any result as the result you wanted —
# which is how a control that is not working gets recorded as working. Writing
# the expectation down first makes a surprise visible as a surprise.
# ---------------------------------------------------------------------------
attack_header() {  # $1 = number, $2 = title, $3 = layer, $4 = expected
  printf '\n\033[1;37m%s\033[0m\n' "============================================================"
  printf '\033[1;37m  ATTACK %s — %s\033[0m\n' "$1" "$2"
  printf '\033[1;37m%s\033[0m\n' "============================================================"
  printf '  layer under test : %s\n' "$3"
  printf '  expected outcome : %s\n' "$4"
}

# PASS means THE ATTACK WAS STOPPED. Worth saying out loud in the output,
# because "attack 3: PASS" is ambiguous on its own and these results get
# pasted into a results table.
verdict() {  # $1 = 0 if the control held, $2 = description
  if [[ "$1" -eq 0 ]]; then
    printf '\n\033[1;32m  >>> CONTROL HELD — %s\033[0m\n\n' "$2"
  else
    printf '\n\033[1;31m  >>> CONTROL FAILED — %s\033[0m\n\n' "$2"
  fi
}

# Read the real, CI-written digest out of the workload manifests. Several
# attacks need a signed image reference, and hardcoding one would go stale on
# the next push.
signed_image() {  # $1 = api|web
  grep -oE "image: ghcr\.io/[^ ]+/zt-$1@sha256:[0-9a-f]{64}" \
    "$ZT_ROOT/workloads/$1.yaml" | head -1 | sed 's/^image: //'
}

# Guard against running the attacks against placeholder digests, which would
# fail at the image pull and look like a policy rejection.
require_real_digest() {
  local img; img="$(signed_image api)"
  if [[ -z "$img" || "$img" == *"sha256:0000000000000000000000000000000000000000000000000000000000000000" ]]; then
    bad "workloads/api.yaml still has the placeholder digest."
    note "CI has not published yet, or ArgoCD has not synced. Every attack"
    note "below would fail at the pull and look like a policy rejection."
    exit 1
  fi
}

# kubectl apply that captures the admission response instead of letting it
# scroll past. The MESSAGE is the evidence in these demonstrations — which
# layer spoke, and what it said.
try_apply() {  # stdin = manifest; prints the response, returns apply's status
  local out rc
  out="$(kubectl apply -f - 2>&1)"; rc=$?
  printf '%s\n' "$out" | sed 's/^/      /'
  return $rc
}
