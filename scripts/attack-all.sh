#!/usr/bin/env bash
# Run all seven attacks in order, and keep a transcript.
#
#   ./scripts/attack-all.sh
#   ./scripts/attack-all.sh --audit-first    # run once in Audit, then Enforce
#
# The transcript is the deliverable. docs/ATTACK-RESULTS.md is filled in from
# it, and a result typed from memory an hour later is a description rather
# than an observation.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STAMP="$(date -u +%Y%m%d-%H%M%SZ)"
OUT="$ROOT/docs/attack-run-${STAMP}.log"

hdr() { printf '\n\033[1;35m%s\033[0m\n' "################ $* ################"; }

# ---------------------------------------------------------------------------
# EVERYTHING from here on goes to the transcript as well as the terminal.
#
# Done once, at the top, rather than per-command. The previous version of
# this script teed only the verification step and let the seven attacks —
# the actual evidence — scroll past into terminal history. A transcript that
# is missing the part you needed is the same problem as no transcript.
#
# `exec > >(tee ...)` replaces this shell's stdout with a tee process, so it
# applies to every child command too. stderr is folded in, because admission
# rejections arrive on stderr and those messages ARE the finding.
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$OUT")"
exec > >(tee -a "$OUT") 2>&1

# ---------------------------------------------------------------------------
# Verification is a PRECONDITION, not a suggestion.
#
# Four of the seven layers can fail silently (see 03-verify-enforcement.sh).
# If any has, the attacks below still produce a tidy column of blocks — each
# one for the wrong reason — and that transcript is worse than no transcript,
# because it looks like evidence.
# ---------------------------------------------------------------------------
hdr "PRECONDITION: verifying the controls are actually on"
if ! "$HERE/03-verify-enforcement.sh"; then
  printf '\n\033[1;31m%s\033[0m\n' "Verification FAILED. Not running the attacks."
  printf '%s\n' "A failing control makes every attack below it pass for the wrong reason."
  printf '%s\n' "Transcript: $OUT"
  exit 1
fi

run_all() {
  for s in \
    attack-01-unsigned-image.sh \
    attack-02-privileged-container.sh \
    attack-03-untrusted-registry.sh \
    attack-04-unauthorised-service-call.sh \
    attack-05-egress-exfiltration.sh \
    attack-06-manual-edit-drift.sh \
    attack-07-shell-in-container.sh
  do
    hdr "$s"
    # Not `set -e`. An attack that errors is itself a result and the remaining
    # attacks still need to run — stopping at the first surprise is how you
    # end up with one row filled in.
    "$HERE/$s" 2>&1 || printf '\033[1;33m    (exited non-zero - see above)\033[0m\n'
  done
}

if [[ "${1:-}" == "--audit-first" ]]; then
  hdr "PASS 1 of 2 — policies in AUDIT (nothing is blocked)"
  "$HERE/policy-mode.sh" audit
  run_all
  hdr "PASS 2 of 2 — policies in ENFORCE"
  "$HERE/policy-mode.sh" enforce
  echo
  printf '%s\n' "Restarting the workloads so Enforce applies to them: verifyImages"
  printf '%s\n' "only evaluates at admission, so running pods are never re-checked."
  kubectl -n zt-prod rollout restart deploy/api deploy/web >/dev/null 2>&1 || true
  kubectl -n zt-prod rollout status deploy/api --timeout=180s >/dev/null 2>&1 || true
  kubectl -n zt-prod rollout status deploy/web --timeout=180s >/dev/null 2>&1 || true
  run_all
else
  "$HERE/policy-mode.sh"
  run_all
fi

hdr "DONE"
cat <<MSG

  Transcript: $OUT

  Now fill in docs/ATTACK-RESULTS.md FROM THIS FILE, while it is in front of
  you. Copy the actual error messages into the table — the message is the
  evidence, because it names which layer spoke. "Rejected" in a results column
  could have come from any of four places.

  Do not tidy out a surprise. On the previous project the defect table became
  the most interesting section of the whole write-up, and a table containing
  only the expected outcomes tells a reader you deleted the interesting rows.

MSG
