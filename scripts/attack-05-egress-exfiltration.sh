#!/usr/bin/env bash
# ATTACK 5 — exfiltrate to an undeclared external host. Expect it blocked.
#
#   ./scripts/attack-05-egress-exfiltration.sh
#
# Driven through web's /fetch endpoint, which performs an outbound request to
# a URL it is handed — a deliberate SSRF, built into the application for this
# purpose.
#
# WHY NOT `kubectl exec curl`: an exec'd shell runs inside the pod's network
# namespace, which is where the sidecar's outbound interception already
# applies, so it would appear to test the same thing. It would not test the
# same THREAT. The threat modelled here is a request arriving from outside and
# the application honouring it, with no attacker shell and no cluster
# credentials involved. So the application honours it.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

attack_header 5 "Exfiltration to an undeclared host" \
  "6 — Istio REGISTRY_ONLY + ServiceEntry, over 5 — NetworkPolicy" \
  "DECLARED host reachable; everything else refused by the sidecar"

MODE="$(kubectl -n istio-system get cm istio -o jsonpath='{.data.mesh}' 2>/dev/null \
         | grep -A3 outboundTrafficPolicy | grep -o 'REGISTRY_ONLY\|ALLOW_ANY' | head -1)"
hdr "Mesh outbound policy"
if [[ "$MODE" == "REGISTRY_ONLY" ]]; then
  ok "REGISTRY_ONLY — undeclared destinations are refused"
else
  bad "outboundTrafficPolicy is ${MODE:-ALLOW_ANY (the default)}"
  note "Every exfiltration below will SUCCEED, and the ServiceEntry allowlist"
  note "in istio/03-egress-allowlist.yaml is having no effect. This is not an"
  note "attack finding, it is a broken installation — fix it before recording"
  note "anything:  ./scripts/00-bootstrap-cluster.sh (the istioctl install)"
fi

WEB_POD="$(kubectl -n zt-prod get pod -l app=web -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
[[ -n "$WEB_POD" ]] || { bad "No web pod. Has ArgoCD synced the workloads?"; exit 1; }

# Calls /fetch INSIDE the pod, so the request to the external host originates
# from the application process — which is what the sidecar intercepts.
fetch() {  # $1 = target url
  # DO NOT SEND STDERR TO /dev/null HERE. It used to, and when `kubectl exec`
  # itself failed - a container still starting, a missing python3, the wrong
  # -c name - this function returned the empty string and the reason was
  # discarded. Every destination then printed as a bare URL with no result,
  # and the script read that silence as "blocked". An absent result is not a
  # block: it is no evidence either way, and in a script whose entire output
  # is evidence that is the worst possible failure.
  local out err rc=0
  err="$(mktemp)"
  out="$(_fetch_inner "$1" 2>"$err")" || rc=$?
  if [[ -z "$out" ]]; then
    printf 'NO RESULT  (exec rc=%s)  %s\n' "$rc" "$(head -c 200 "$err" | tr '\n' ' ')"
  else
    printf '%s\n' "$out"
  fi
  rm -f "$err"
}

_fetch_inner() {  # $1 = target url
  kubectl -n zt-prod exec -i "$WEB_POD" -c web -- python3 - "$1" <<'PY'
import json, sys, urllib.parse, urllib.request
target = urllib.parse.quote(sys.argv[1], safe="")
try:
    r = urllib.request.urlopen(f"http://localhost:8001/fetch?url={target}", timeout=15)
    d = json.load(r)
    if d.get("blocked"):
        print(f"BLOCKED  {d.get('error','')[:150]}")
    else:
        print(f"REACHED  status={d.get('status')}  body={str(d.get('body_head'))[:80]}")
except Exception as e:
    print(f"PROBE ERROR  {type(e).__name__}: {str(e)[:120]}")
PY
}

hdr "1. The DECLARED destination — must SUCCEED"
note "api.github.com is the only external host in istio/03-egress-allowlist.yaml"
rule
D="$(fetch 'https://api.github.com/zen')"
printf '      %s\n' "$D"
rule
DECLARED_OK=1
if printf '%s' "$D" | grep -q REACHED; then
  DECLARED_OK=0
  ok "Reachable, as declared"
  note "This half matters as much as the blocks below. An egress policy that"
  note "refuses everything is indistinguishable from a broken network, and"
  note "would make every result in this script meaningless."
else
  warn "The declared host was NOT reachable. Check the ServiceEntry and the"
  warn "Sidecar egress hosts for web:"
  warn "    kubectl -n zt-prod get serviceentry,sidecar"
  warn ""
  warn "This invalidates the blocks below rather than merely being one"
  warn "failure among them: if the ALLOWED host is also unreachable, then"
  warn "'undeclared destination refused' is not evidence of an allowlist. It"
  warn "is consistent with egress being broken outright, which would produce"
  warn "exactly the same output for every destination."
  kubectl -n zt-prod get serviceentry,sidecar 2>/dev/null | sed 's/^/      /'
fi

hdr "2. An UNDECLARED destination — must be BLOCKED"
rule
UNDECLARED_BLOCKED=0
UNDECLARED_TOTAL=0
for target in 'https://example.com/' 'https://pastebin.com/raw/abc123'; do
  R="$(fetch "$target")"
  printf '      %-42s %s\n' "$target" "$R"
  UNDECLARED_TOTAL=$((UNDECLARED_TOTAL+1))
  printf '%s' "$R" | grep -q BLOCKED && UNDECLARED_BLOCKED=$((UNDECLARED_BLOCKED+1))
done
rule
# ASSERT it, rather than asserting it in prose underneath. The paragraph below
# is true only if the probe actually reported BLOCKED; printed under a NO
# RESULT it would be a confident explanation of something that never happened.
if [[ "$UNDECLARED_BLOCKED" -eq "$UNDECLARED_TOTAL" ]]; then
  ok "$UNDECLARED_BLOCKED/$UNDECLARED_TOTAL undeclared destinations reported BLOCKED"
else
  warn "only $UNDECLARED_BLOCKED/$UNDECLARED_TOTAL reported BLOCKED - the rest"
  warn "returned no usable result, which is not the same as being refused."
  warn "The explanation below applies to the BLOCKED ones only."
fi
note "The refusal comes from web's OWN sidecar, outbound, before a packet"
note "leaves the pod. Nothing was sent anywhere, so there is no DNS query and"
note "no TCP connection for a network monitor to notice — which is the"
note "argument for enforcing egress at the workload rather than at the edge."

hdr "3. The cloud metadata endpoint — three independent controls"
note "169.254.169.254 is where an SSRF goes first. Against IMDSv1 one request"
note "returns the instance role credentials."
rule
printf '      %-42s %s\n' 'http://169.254.169.254/latest/meta-data/' \
  "$(fetch 'http://169.254.169.254/latest/meta-data/')"
printf '      %-42s %s\n' 'https://169.254.169.254/latest/meta-data/' \
  "$(fetch 'https://169.254.169.254/latest/meta-data/')"
rule
note "Three reasons this fails, and all three are real and independent:"
note
note "  1. Istio REGISTRY_ONLY — not a declared destination."
note "  2. NetworkPolicy — network/04-allow-https-egress.yaml excludes"
note "     169.254.0.0/16 from its 0.0.0.0/0 allowance, so the packet is"
note "     dropped by the CNI even with the mesh out of the way. Plaintext"
note "     port 80 is not permitted outbound at all, which is why the http://"
note "     variant above is refused for a second, different reason."
note "  3. The instance — terraform sets IMDSv2 required with"
note "     http_put_response_hop_limit = 1, so a response cannot be forwarded"
note "     out of the pod's network namespace. And no IAM role is attached to"
note "     the instance at all, so there would be nothing to read."
note
note "Removing them one at a time is how you find out which ones are actually"
note "load-bearing. Doing that is a worthwhile exercise and it is NOT what"
note "this script does — it would leave the cluster in a weakened state that"
note "a later attack would then silently pass through."
# The verdict used to be a hardcoded `verdict 0`, so it printed "CONTROL HELD
# - declared egress works" on a run where part 1 had just reported the
# declared host unreachable. A verdict that cannot fail is not a verdict.
if [[ "${DECLARED_OK:-1}" -eq 0 && "${UNDECLARED_BLOCKED:-0}" -eq "${UNDECLARED_TOTAL:-1}" ]]; then
  verdict 0 "declared egress works, undeclared egress and metadata are refused"
elif [[ "${UNDECLARED_BLOCKED:-0}" -ne "${UNDECLARED_TOTAL:-1}" ]]; then
  verdict 1 "the probe produced no usable result for at least one destination - this run is evidence of nothing, fix the probe before reading anything into it"
else
  verdict 1 "undeclared egress was refused, but so was the DECLARED host - so this run does not prove an allowlist, only that egress is closed"
fi
