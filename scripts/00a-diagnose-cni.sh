#!/usr/bin/env bash
# Is the Istio CNI plugin actually installed where k3s will read it?
#
#   ./scripts/00a-diagnose-cni.sh
#
# Read-only. Changes nothing, costs nothing, safe to run repeatedly.
#
# This exists because the cheap check in 00-bootstrap-cluster.sh originally
# tested FILENAMES, and Istio's default "chained" mode does not create a file:
# it edits the CNI conflist already on the node and appends itself to the
# plugins array. So a correct install can leave no filename containing
# "istio" - and the same `ls | grep` also cannot tell a correct install from
# a plugin that was written but never chained.
#
# What actually has to be true, all three:
#   1. the istio-cni BINARY is in the directory k3s loads plugins from
#   2. some conflist in k3s's CNI config dir NAMES istio-cni in its plugins
#   3. the istio-cni-node pod logged a successful install
set -uo pipefail

ok()   { printf '\033[1;32m  PASS  %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m  FAIL  %s\033[0m\n' "$*"; }
info() { printf '        %s\n' "$*"; }
log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

CONF_DIR=/var/lib/rancher/k3s/agent/etc/cni/net.d
BIN_DIR=/var/lib/rancher/k3s/data/current/bin
fails=0

log "k3s version and the real data dir"
k3s --version 2>/dev/null | head -1
info "data/current -> $(readlink -f /var/lib/rancher/k3s/data/current 2>/dev/null || echo '(no such symlink)')"

log "1. CNI config directory: $CONF_DIR"
if sudo test -d "$CONF_DIR"; then
  sudo ls -l "$CONF_DIR" | sed 's/^/        /'
else
  bad "directory does not exist - the cniConfDir in 00-bootstrap is wrong"
  info "search for the real one:"
  info "  sudo find /var/lib/rancher /etc/cni -name '*.conflist' -o -name '*.conf' 2>/dev/null"
  fails=$((fails+1))
fi

log "2. Does any conflist NAME istio-cni? (this is the test that matters)"
HITS="$(sudo grep -l istio-cni "$CONF_DIR"/* 2>/dev/null || true)"
if [ -n "$HITS" ]; then
  ok "istio-cni is chained into:"
  echo "$HITS" | sed 's/^/        /'
  for f in $HITS; do
    info "plugins in $(basename "$f"):"
    sudo cat "$f" | jq -r '.plugins[]?.type // .type' 2>/dev/null | sed 's/^/          - /' \
      || sudo grep -o '"type"[^,]*' "$f" | sed 's/^/          /'
  done
else
  bad "no file in $CONF_DIR mentions istio-cni"
  fails=$((fails+1))
fi

log "3. Is the istio-cni binary where k3s loads plugins from?"
if sudo test -f "$BIN_DIR/istio-cni"; then
  ok "$BIN_DIR/istio-cni"
  sudo ls -l "$BIN_DIR/istio-cni" | sed 's/^/        /'
else
  bad "$BIN_DIR/istio-cni missing"
  info "what IS in that dir:"
  sudo ls "$BIN_DIR" 2>/dev/null | head -20 | sed 's/^/          /' || info "          (dir unreadable)"
  info "and anywhere on the box:"
  sudo find /var/lib/rancher /opt/cni -name 'istio-cni*' 2>/dev/null | sed 's/^/          /' || true
  fails=$((fails+1))
fi

log "4. What the istio-cni-node pod thinks it did"
POD="$(kubectl -n istio-system get pods -l k8s-app=istio-cni-node -o name 2>/dev/null | head -1)"
[ -z "$POD" ] && POD="$(kubectl -n istio-system get pods -o name 2>/dev/null | grep istio-cni | head -1)"
if [ -n "$POD" ]; then
  info "pod: $POD"
  kubectl -n istio-system logs "$POD" --tail=25 2>/dev/null \
    | grep -iE 'install|cni|conf|error|warn' | tail -15 | sed 's/^/        /'
  info "mounted host paths it was given:"
  kubectl -n istio-system get "$POD" \
    -o jsonpath='{range .spec.volumes[*]}{.name}{" -> "}{.hostPath.path}{"\n"}{end}' 2>/dev/null \
    | grep -v '^.* -> $' | sed 's/^/        /'
else
  bad "no istio-cni pod found"
  fails=$((fails+1))
fi

log "Verdict"
if [ "$fails" -eq 0 ]; then
  ok "CNI looks correctly installed. Re-run ./scripts/00-bootstrap-cluster.sh"
  info "The cheap check is not proof - 03-verify-enforcement.sh is the real test."
else
  bad "$fails of 3 checks failed. Do NOT continue to 01 - paste this output."
fi
exit 0
