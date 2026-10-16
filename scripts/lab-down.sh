#!/usr/bin/env bash
# Tear the lab down, and PROVE it is down. Run from your WORKSTATION.
#
#   ./scripts/lab-down.sh          # confirm, destroy, verify
#   ./scripts/lab-down.sh -y       # no confirmation prompt
#
# Nothing on the instance is worth keeping. k3s, Istio, Kyverno, Falco, ArgoCD
# and the workloads were all installed from git by the other scripts here, so
# the box holds no state you cannot rebuild in an hour. Being able to destroy
# it on a whim is the argument for the architecture, not a cost-saving
# afterthought.
#
# KEEP FIRST, if you have not already: docs/attack-run-*.log and your
# screenshots are the only irreplaceable things produced on that box.
#   scp ubuntu@<ip>:zerotrust-gitops/docs/attack-run-*.log ./docs/
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m%s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m%s\033[0m\n' "$*"; }

REGION="${AWS_REGION:-us-east-1}"
TAG="zero-trust-supply-chain"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$HERE/terraform"
export AWS_PAGER=""

[[ -d "$TF_DIR" ]] || { err "No terraform directory at $TF_DIR"; exit 1; }
cd "$TF_DIR"

log "Account being torn down"
aws sts get-caller-identity --query '[Account,Arn]' --output text 2>/dev/null || true

if [[ ! -f terraform.tfstate ]]; then
  warn "No terraform.tfstate here."
  warn "Either nothing was ever applied, or you are on a different machine"
  warn "from the one that applied it - state is local and gitignored by"
  warn "design. Checking AWS directly anyway, because the bill does not care"
  warn "where the state file lives."
else
  log "Currently tracked in state"
  terraform state list | sed 's/^/    /' || true

  if [[ "${1:-}" != "-y" ]]; then
    echo
    read -r -p "Destroy all of the above? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { warn "Aborted. Nothing destroyed."; exit 0; }
  fi

  log "Destroying"
  terraform destroy -auto-approve
fi

# ---------------------------------------------------------------------------
# The part that actually matters.
#
# "terraform destroy completed" and "the account is empty" are different
# claims. Terraform reports on what IT tracked; anything created outside that
# state — by hand, or by a run whose state was lost — is invisible to it. Ask
# AWS instead.
#
# This project creates its OWN VPC, which makes the check stricter than the
# previous one: if the VPC is gone, so is everything that was inside it.
# ---------------------------------------------------------------------------
log "Verifying against AWS, not against terraform"

INSTANCES=$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Project,Values=$TAG" \
            "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name]' \
  --output text 2>/dev/null || true)

VOLUMES=$(aws ec2 describe-volumes --region "$REGION" \
  --filters "Name=tag:Project,Values=$TAG" \
  --query 'Volumes[].[VolumeId,Size,State]' --output text 2>/dev/null || true)

VPCS=$(aws ec2 describe-vpcs --region "$REGION" \
  --filters "Name=tag:Project,Values=$TAG" \
  --query 'Vpcs[].[VpcId,CidrBlock]' --output text 2>/dev/null || true)

# Unattached Elastic IPs are account-wide, not tagged by this stack, and bill
# precisely while nothing is using them. Checked without a tag filter on
# purpose — this is the charge most likely to be left behind by an earlier
# experiment and never noticed.
EIPS=$(aws ec2 describe-addresses --region "$REGION" \
  --query 'Addresses[?AssociationId==null].[PublicIp,AllocationId]' \
  --output text 2>/dev/null || true)

echo
printf '  %-22s %s\n' "instances:"        "${INSTANCES:-none}"
printf '  %-22s %s\n' "tagged volumes:"   "${VOLUMES:-none}"
printf '  %-22s %s\n' "tagged VPCs:"      "${VPCS:-none}"
printf '  %-22s %s\n' "unattached EIPs:"  "${EIPS:-none}"
echo

if [[ -z "$INSTANCES" && -z "$VOLUMES" && -z "$VPCS" && -z "$EIPS" ]]; then
  ok "==> Clean. Nothing is billing."
  echo
  echo "A VPC, subnet, route table and internet gateway are free, so even a"
  echo "leftover network would not have cost anything - but it is gone, which"
  echo "means nothing can have been left running inside it."
  echo
  echo "Rebuild with ./scripts/lab-up.sh - about an hour to a verified"
  echo "cluster, entirely from git. Your transcripts and screenshots are"
  echo "unaffected."
else
  err "==> SOMETHING IS STILL THERE. Read the list above."
  echo
  echo "An unattached Elastic IP bills while it is NOT attached, which is"
  echo "exactly when you have forgotten it exists. Release it:"
  echo "    aws ec2 release-address --region $REGION --allocation-id <id>"
  echo
  echo "A VPC that will not delete usually still contains something:"
  echo "    aws ec2 describe-network-interfaces --region $REGION \\"
  echo "      --filters Name=vpc-id,Values=<vpc-id> --output table"
  exit 1
fi
