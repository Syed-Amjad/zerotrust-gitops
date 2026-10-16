#!/usr/bin/env bash
# Provision the box and print how to reach it. Run from your WORKSTATION.
#
#   ./scripts/lab-up.sh
#
# Stops deliberately at a provisioned, reachable machine. The cluster is built
# by 00-bootstrap-cluster.sh and friends, over SSH. Wiring those into one
# command would hide the steps where things actually go wrong, and on this
# project three of those steps are the ones worth watching.
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$HERE/terraform"
export AWS_PAGER=""

cd "$TF_DIR"

log "Which AWS account are we about to bill?"
# ---------------------------------------------------------------------------
# Printed before anything is created, because this project runs in a DIFFERENT
# account from the GitOps platform. A stale AWS_PROFILE is the easy mistake,
# and discovering it after `apply` means resources in the wrong account and a
# destroy you have to go and find.
# ---------------------------------------------------------------------------
aws sts get-caller-identity --output table 2>/dev/null || {
  warn "aws sts get-caller-identity failed. Check your credentials/profile:"
  warn "    aws configure list"
  exit 1
}
read -r -p "    Is that the right account for this project? [y/N] " acct
[[ "$acct" =~ ^[Yy]$ ]] || { warn "Aborted. Set AWS_PROFILE and try again."; exit 0; }

log "terraform init"
terraform init -input=false

# A home connection's public IP changes without warning. The security group
# opens :22 to one auto-detected /32, so a box that was reachable yesterday
# can refuse you today — and the symptom is an SSH timeout that looks like a
# dead instance rather than a firewall rule. Re-running apply re-detects and
# updates the rule in place.
MYIP="$(curl -s https://checkip.amazonaws.com | tr -d '[:space:]')"
log "Your current public address is ${MYIP} - SSH will be opened to this /32"

log "terraform apply"
terraform apply -auto-approve

IP="$(terraform output -raw public_ip)"

log "Waiting for SSH on ${IP}"
for i in $(seq 1 36); do
  if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o BatchMode=yes \
         "ubuntu@${IP}" true 2>/dev/null; then
    ok "SSH is up after $((i*5))s"
    break
  fi
  printf '    still waiting (%ss)\n' "$((i*5))"
  sleep 5
done

cat <<EOF

$(terraform output -raw hourly_cost_reminder)

==> Box is up at ${IP}

Open a SECOND terminal and keep it running. Every UI is reached through this
tunnel, because no UI port is open in the security group:

  $(terraform output -raw tunnel_command)

Then, in that SSH session:

  sudo apt-get update && sudo apt-get install -y git
  git clone https://github.com/Syed-Amjad/zerotrust-gitops.git
  cd zerotrust-gitops

  ./scripts/00-bootstrap-cluster.sh        # k3s + Istio (CNI, REGISTRY_ONLY)
  ./scripts/01-install-policy-engines.sh   # Kyverno + Falco
  ./scripts/02-install-argocd.sh           # ArgoCD

  kubectl apply -f argocd/projects/zerotrust.yaml
  kubectl apply -f argocd/root-app.yaml
  watch -n2 'kubectl -n argocd get applications'

  ./scripts/03-verify-enforcement.sh       # NOT optional - see its header
  ./scripts/attack-all.sh --audit-first

When you stop for the day:

  ./scripts/lab-down.sh

EOF
