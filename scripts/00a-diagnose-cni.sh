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

# DISCOVERED, not hardcoded. An earlier version of this script hardcoded
# BIN_DIR=/var/lib/rancher/k3s/data/current/bin and reported PASS for the
# binary while containerd was resolving plugin names under
# /var/lib/rancher/k3s/data/cni, where istio-cni was absent. Both directories
# exist on k3s v1.36.5 and both contain plugins, so the check was green and
# every CNI ADD on the node was failing. A diagnostic that asserts against a
# path of its own choosing is not diagnosing anything.
#
# k3s's containerd config is the authority. The fallback probes for `flannel`,
# because flannel is the plugin k3s itself installed and uses - wherever it
# resolves from is, by definition, where containerd looks.
CONF_DIR="$(sudo grep -ho 'conf_dir *= *"[^"]*"' \
    /var/lib/rancher/k3s/agent/etc/containerd/config.toml* 2>/dev/null \
    | head -1 | sed 's/.*= *"//; s/".*//')"
[ -n "${CONF_DIR:-}" ] && sudo test -d "$CONF_DIR" \
  || CONF_DIR=/var/lib/rancher/k3s/agent/etc/cni/net.d

BIN_DIR="$(sudo grep -ho 'bin_dir *= *"[^"]*"' \
    /var/lib/rancher/k3s/agent/etc/containerd/config.toml* 2>/dev/null \
    | head -1 | sed 's/.*= *"//; s/".*//')"
if [ -z "${BIN_DIR:-}" ] || ! sudo test -x "$BIN_DIR/flannel"; then
  for d in /var/lib/rancher/k3s/data/cni \
           /var/lib/rancher/k3s/data/current/bin \
           /opt/cni/bin; do
    if sudo test -x "$d/flannel"; then BIN_DIR="$d"; break; fi
  done
fi
BIN_DIR="${BIN_DIR:-/var/lib/rancher/k3s/data/cni}"
fails=0

log "k3s version and the real data dir"
k3s --version 2>/dev/null | head -1
info "data/current -> $(readlink -f /var/lib/rancher/k3s/data/current 2>/dev/null || echo '(no such symlink)')"

log "0. Can the invoking user traverse these paths at all?"
# If any of these is 0700 root, every shell glob an unprivileged user
# writes against a path below it silently matches nothing.
for d in /var/lib/rancher /var/lib/rancher/k3s \n         /var/lib/rancher/k3s/agent "$CONF_DIR"; do
  printf '        %s
' "$(ls -ld "$d" 2>&1)"
done
if [ -r "$CONF_DIR" ]; then info "readable by $(id -un) - globs work"
else info "NOT readable by $(id -un) - globs below this path match nothing"; fi

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
# `sudo grep -l PATTERN "$DIR"/*` DOES NOT WORK HERE. The glob is expanded
# by the calling shell, which is unprivileged, and k3s sets
# /var/lib/rancher/k3s to 0700 root - so the glob matches nothing, bash
# passes the literal * through, and grep fails into /dev/null. sudo only
# elevates the command, never the shell that built its arguments.
# `grep -r DIR` does its own traversal, as root.
HITS="$(sudo grep -rl istio-cni "$CONF_DIR" 2>/dev/null || true)"
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
  bad "$BIN_DIR/istio-cni missing - and that is the dir containerd searches"
  info "what IS in that dir:"
  sudo ls "$BIN_DIR" 2>/dev/null | head -20 | sed 's/^/          /' || info "          (dir unreadable)"
  ELSEWHERE="$(sudo find /var/lib/rancher /opt/cni -name 'istio-cni' -type f 2>/dev/null \
               | grep -v "^$BIN_DIR/" || true)"
  if [ -n "$ELSEWHERE" ]; then
    info ""
    bad "it IS present elsewhere, which is worse than absent:"
    echo "$ELSEWHERE" | sed 's/^/          /'
    info "The binary installed fine; it is just not on the path containerd"
    info "resolves names against. Every CNI ADD on this node fails with"
    info "  failed to find plugin \"istio-cni\" in path [$BIN_DIR]"
    info "and each failed retry leaks one host-local lease, so ~254 retries"
    info "later every pod fails with 'no IP addresses available' instead -"
    info "an error that names flannel and points nowhere near the cause."
    info "Fix: re-run ./scripts/00-bootstrap-cluster.sh, which now DISCOVERS"
    info "this directory instead of hardcoding it."
  fi
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
  bad "$fails check(s) failed. Do NOT continue to 01 - paste this output."
  info "This script is read-only, so it reads paths and files. The check that"
  info "cannot be fooled by a path is starting a pod and seeing whether it"
  info "gets an address - 00-bootstrap-cluster.sh does that at the end."
fi
exit 0
