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

# ===========================================================================
# WHICH ACCOUNT ARE WE ABOUT TO DESTROY IN? ASSERT IT. DO NOT JUST PRINT IT.
#
# This used to run `aws sts get-caller-identity` and carry on regardless. On a
# machine with two profiles that is a caption, not a check - and the failure
# it misses is bad in a specific, quiet way:
#
#   `terraform destroy` against the WRONG account DOES NOT ERROR. It calls the
#   API, is told the instance and the VPC do not exist, concludes they were
#   already deleted, and REMOVES THEM FROM STATE. This script then verifies
#   "against AWS" in that same wrong account, finds nothing, and prints
#   "Clean. Nothing is billing."
#
#   The real instance keeps running. The state file that could have destroyed
#   it is now empty. Both halves of the safety net fail in the same direction,
#   and the output is indistinguishable from success.
#
# AWS_PROFILE is not sticky: it lives in the shell that exported it. A new
# terminal, a reboot, or a tmux pane started before the export all land on the
# default profile. So the account is read out of STATE - whichever account
# owns the resources terraform is tracking - and compared to the caller.
# ===========================================================================
log "Account check"
CALLER_ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || true)"

# Every ARN in state carries the owning account as its 5th field. Prefer
# `terraform show -json`; fall back to the raw state file, because show needs
# the provider plugins and this script must work when they are unusable.
STATE_ACCT=""
if [[ -f terraform.tfstate ]]; then
  STATE_ACCT="$(terraform show -json 2>/dev/null \
    | grep -oE 'arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}' \
    | grep -oE '[0-9]{12}' | sort -u | head -1 || true)"
  if [[ -z "$STATE_ACCT" ]]; then
    STATE_ACCT="$(grep -oE 'arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}' \
      terraform.tfstate 2>/dev/null \
      | grep -oE '[0-9]{12}' | sort -u | head -1 || true)"
  fi
fi

printf '    AWS_PROFILE                 %s\n' "${AWS_PROFILE:-<unset - using [default]>}"
printf '    caller account              %s\n' "${CALLER_ACCT:-<unreadable>}"
printf '    caller identity             %s\n' "${CALLER_ARN:-<unreadable>}"
printf '    account owning the state    %s\n' "${STATE_ACCT:-<no ARNs in state>}"

if [[ -z "$CALLER_ACCT" ]]; then
  err "Cannot read the caller identity. Refusing to destroy blind."
  err "    aws sts get-caller-identity --profile zerotrust"
  exit 1
fi

if [[ -n "$STATE_ACCT" && "$STATE_ACCT" != "$CALLER_ACCT" ]]; then
  err "ACCOUNT MISMATCH - refusing to touch anything."
  err ""
  err "  terraform is tracking resources in $STATE_ACCT"
  err "  your credentials are for          $CALLER_ACCT"
  err ""
  err "A destroy from here would find nothing in $CALLER_ACCT, decide the"
  err "resources were already gone, drop them from state, and then report a"
  err "clean account - while $STATE_ACCT keeps billing."
  err ""
  err "Fix the profile, in THIS shell, and run again:"
  err "    export AWS_PROFILE=zerotrust"
  err "    aws sts get-caller-identity          # must print $STATE_ACCT"
  err "    ./scripts/lab-down.sh"
  exit 1
fi

if [[ -n "$STATE_ACCT" ]]; then
  ok "caller and state agree on account $CALLER_ACCT"
else
  warn "No ARNs in state, so there is nothing to cross-check against."
  warn "The sweep below will search account $CALLER_ACCT only. If the lab was"
  warn "built in a different account, nothing found here means nothing."
fi

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
# Name the account in the output. "Clean" is a claim about one account in one
# region, and a reader three weeks later cannot tell which.
printf '    account %s, region %s, tag Project=%s\n' "$CALLER_ACCT" "$REGION" "$TAG"

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
  ok "==> Clean. Nothing is billing in account $CALLER_ACCT, region $REGION."
  echo
  echo "That sentence is scoped on purpose. It is a claim about ONE account"
  echo "and ONE region. If you have more than one AWS account, confirm the"
  echo "other one too - the console's region selector and the profile you"
  echo "last exported are independent of each other:"
  echo "    AWS_PROFILE=<other> aws ec2 describe-instances \\"
  echo "      --query 'Reservations[].Instances[?State.Name==\`running\`].InstanceId' \\"
  echo "      --output text"
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
