#!/usr/bin/env bash
# Destroy the lab BY TAG, through the AWS API, when terraform state cannot.
#
#   ./scripts/lab-nuke.sh            # list, confirm, delete
#   ./scripts/lab-nuke.sh -y         # no confirmation
#   AWS_REGION=eu-west-1 ./scripts/lab-nuke.sh
#
# ===========================================================================
# WHY THIS EXISTS. It is the recovery path for a specific, quiet failure.
#
# `terraform destroy` run against the WRONG AWS account does not error. It
# calls the API, is told the instance and the VPC do not exist, concludes they
# were already deleted, and REMOVES THEM FROM STATE. The result is a state
# file of about 180 bytes, a real instance still running in the other
# account, and nothing left that terraform can use to destroy it.
#
# lab-down.sh now refuses on an account mismatch, so this should not happen
# again. This script cleans up after the time it did.
#
# It works from TAGS, not from state: the provider in versions.tf sets
# default_tags Project=zero-trust-supply-chain on every resource, so the API
# can find them all without terraform knowing anything.
#
# ORDER MATTERS and is not negotiable. AWS refuses to delete a VPC while
# anything is attached to it, and the error it gives
# ("DependencyViolation") does not say what. Instance, then security groups,
# then IGW, then subnets, then route tables, then the VPC.
# ===========================================================================
set -uo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m!!! %s\033[0m\n' "$*" >&2; }

REGION="${AWS_REGION:-us-east-1}"
TAG="${LAB_TAG:-zero-trust-supply-chain}"
NAME="${LAB_NAME:-zerotrust-platform}"
export AWS_PAGER=""

q() { aws ec2 "$@" --region "$REGION" --output text 2>/dev/null || true; }

log "Identity"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
ARN="$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || true)"
if [[ -z "$ACCT" ]]; then
  err "Cannot read the caller identity. Nothing done."
  err "    export AWS_PROFILE=zerotrust && aws sts get-caller-identity"
  exit 1
fi
printf '    AWS_PROFILE  %s\n' "${AWS_PROFILE:-<unset - using [default]>}"
printf '    account      %s\n' "$ACCT"
printf '    identity     %s\n' "$ARN"
printf '    region       %s\n' "$REGION"
printf '    tag          Project=%s\n' "$TAG"

# ---------------------------------------------------------------------------
log "What is actually there"
INST="$(q describe-instances \
  --filters "Name=tag:Project,Values=$TAG" \
            "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId')"
VPCS="$(q describe-vpcs --filters "Name=tag:Project,Values=$TAG" --query 'Vpcs[].VpcId')"
SUBS="$(q describe-subnets --filters "Name=tag:Project,Values=$TAG" --query 'Subnets[].SubnetId')"
IGWS="$(q describe-internet-gateways --filters "Name=tag:Project,Values=$TAG" \
  --query 'InternetGateways[].InternetGatewayId')"
RTBS="$(q describe-route-tables --filters "Name=tag:Project,Values=$TAG" \
  --query 'RouteTables[].RouteTableId')"
# The backticks below are JMESPath string-literal syntax, not shell command
# substitution. They are inside SINGLE quotes, so bash leaves them alone and
# must NOT be backslash-escaped - an escaped backtick reaches JMESPath as
# \`default\` and the query fails to parse, which `q` then swallows, leaving
# SGS empty and the security group undeleted.
SGS="$(q describe-security-groups --filters "Name=tag:Project,Values=$TAG" \
  --query 'SecurityGroups[?GroupName!=`default`].GroupId')"
EIPS="$(q describe-addresses --filters "Name=tag:Project,Values=$TAG" \
  --query 'Addresses[].AllocationId')"
VOLS="$(q describe-volumes --filters "Name=tag:Project,Values=$TAG" --query 'Volumes[].VolumeId')"
KEYS="$(q describe-key-pairs --filters "Name=tag:Project,Values=$TAG" --query 'KeyPairs[].KeyName')"

show() { printf '    %-18s %s\n' "$1" "${2:-(none)}"; }
show instances       "$INST"
show volumes         "$VOLS"
show vpcs            "$VPCS"
show subnets         "$SUBS"
show "internet gws"  "$IGWS"
show "route tables"  "$RTBS"
show "security grps" "$SGS"
show "elastic ips"   "$EIPS"
show "key pairs"     "$KEYS"

if [[ -z "$INST$VPCS$SUBS$IGWS$RTBS$SGS$EIPS$VOLS$KEYS" ]]; then
  ok "Nothing tagged Project=$TAG in account $ACCT, region $REGION."
  warn "If you can see a running instance in the console, you are looking at"
  warn "a different account or a different region. Check the console's"
  warn "account menu and its region selector - they are independent."
  exit 0
fi

if [[ "${1:-}" != "-y" ]]; then
  echo
  warn "Everything listed above will be DELETED from account $ACCT."
  read -r -p "    Proceed? [y/N] " a
  [[ "${a:-}" =~ ^[Yy]$ ]] || { warn "Aborted. Nothing deleted."; exit 0; }
fi

# ---------------------------------------------------------------------------
# The instance first, and WAIT. Everything else fails while it exists, and the
# root volume has delete_on_termination so it goes with it. This is also the
# only line here that stops money being spent - a VPC, subnet, route table,
# IGW and security group are all free.
if [[ -n "$INST" ]]; then
  log "Terminating instances (this is the part that stops the billing)"
  # shellcheck disable=SC2086
  q terminate-instances --instance-ids $INST \
    --query 'TerminatingInstances[].[InstanceId,CurrentState.Name]' | sed 's/^/    /'
  ok "waiting for termination - up to a couple of minutes"
  # shellcheck disable=SC2086
  aws ec2 wait instance-terminated --region "$REGION" --instance-ids $INST 2>/dev/null \
    && ok "terminated" || warn "wait timed out; continuing (deletes below may need a re-run)"
fi

# Any volume not attached to the instance, e.g. a leftover from an earlier run.
if [[ -n "$VOLS" ]]; then
  log "Deleting volumes"
  for v in $VOLS; do
    st="$(q describe-volumes --volume-ids "$v" --query 'Volumes[].State')"
    if [[ "$st" == "available" ]]; then
      q delete-volume --volume-id "$v" >/dev/null && ok "deleted $v"
    else
      warn "$v is '$st' - skipped (it goes with its instance)"
    fi
  done
fi

# Security groups before the IGW, because an SG referencing another SG blocks
# both. The VPC's default SG cannot be deleted and does not need to be.
if [[ -n "$SGS" ]]; then
  log "Deleting security groups"
  for g in $SGS; do
    if q delete-security-group --group-id "$g" >/dev/null 2>&1; then ok "deleted $g"
    else warn "$g would not delete yet - retried after the subnets below"; fi
  done
fi

if [[ -n "$IGWS" ]]; then
  log "Detaching and deleting internet gateways"
  for i in $IGWS; do
    for v in $VPCS; do q detach-internet-gateway --internet-gateway-id "$i" --vpc-id "$v" >/dev/null 2>&1; done
    q delete-internet-gateway --internet-gateway-id "$i" >/dev/null 2>&1 \
      && ok "deleted $i" || warn "$i would not delete"
  done
fi

# Subnets before route tables: deleting a subnet removes its route-table
# association, and a route table with an association refuses to delete.
if [[ -n "$SUBS" ]]; then
  log "Deleting subnets"
  for s in $SUBS; do
    q delete-subnet --subnet-id "$s" >/dev/null 2>&1 && ok "deleted $s" || warn "$s would not delete"
  done
fi

if [[ -n "$RTBS" ]]; then
  log "Deleting route tables"
  for r in $RTBS; do
    # The main route table of a VPC cannot be deleted on its own; it is
    # removed with the VPC. Skipping it is correct, not a failure.
    if q delete-route-table --route-table-id "$r" >/dev/null 2>&1; then ok "deleted $r"
    else warn "$r not deleted (likely the VPC's main table - goes with the VPC)"; fi
  done
fi

# Retry the security groups now that the subnets are gone.
if [[ -n "$SGS" ]]; then
  for g in $SGS; do
    q delete-security-group --group-id "$g" >/dev/null 2>&1 && ok "deleted $g (retry)"
  done
fi

# An unattached Elastic IP bills while it is NOT attached, which is exactly
# when you have forgotten it exists.
if [[ -n "$EIPS" ]]; then
  log "Releasing Elastic IPs"
  for e in $EIPS; do
    q release-address --allocation-id "$e" >/dev/null 2>&1 && ok "released $e" || warn "$e would not release"
  done
fi

if [[ -n "$VPCS" ]]; then
  log "Deleting VPCs"
  for v in $VPCS; do
    if q delete-vpc --vpc-id "$v" >/dev/null 2>&1; then ok "deleted $v"
    else
      warn "$v would not delete - something is still attached. Find it:"
      warn "    aws ec2 describe-network-interfaces --region $REGION \\"
      warn "        --filters Name=vpc-id,Values=$v --output table"
    fi
  done
fi

if [[ -n "$KEYS" ]]; then
  log "Deleting key pairs"
  for k in $KEYS; do
    q delete-key-pair --key-name "$k" >/dev/null 2>&1 && ok "deleted $k"
  done
fi

# ---------------------------------------------------------------------------
log "Re-checking against the API"
L_INST="$(q describe-instances --filters "Name=tag:Project,Values=$TAG" \
  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId')"
L_VPCS="$(q describe-vpcs --filters "Name=tag:Project,Values=$TAG" --query 'Vpcs[].VpcId')"
L_VOLS="$(q describe-volumes --filters "Name=tag:Project,Values=$TAG" --query 'Volumes[].VolumeId')"
L_EIPS="$(q describe-addresses --filters "Name=tag:Project,Values=$TAG" --query 'Addresses[].AllocationId')"
show instances "$L_INST"
show volumes   "$L_VOLS"
show vpcs      "$L_VPCS"
show "elastic ips" "$L_EIPS"

echo
if [[ -z "$L_INST$L_VPCS$L_VOLS$L_EIPS" ]]; then
  ok "Clean. Nothing is billing in account $ACCT, region $REGION."
  echo
  echo "    Scoped on purpose: one account, one region. Terraform state is"
  echo "    empty either way, so rebuild with ./scripts/lab-up.sh rather"
  echo "    than expecting terraform to know about any of this."
else
  err "Something is still there. Re-run this script - several of the deletes"
  err "above only succeed once the instance has finished terminating."
  exit 1
fi
