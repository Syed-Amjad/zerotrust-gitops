# terraform

One EC2 instance, in its own VPC. Nine resources, no modules, no remote state.

```bash
terraform init
terraform apply                      # or ../scripts/lab-up.sh, which also
                                     # prints the AWS account and asks first
terraform output tunnel_command
```

## Why a dedicated VPC, and not the default one

The GitOps platform's terraform reused the default VPC and declared only the
pieces that were missing. That worked there for an accidental reason: that
account's default VPC had been stripped — every subnet deleted, the internet
gateway deleted, and the main route table still pointing `0.0.0.0/0` at the
dead gateway in state `blackhole`. Declaring an IGW succeeded because there was
no longer one to collide with.

**This project runs in a different, fresh AWS account, where the default VPC is
intact** — and an intact default VPC already has an internet gateway. AWS
permits exactly one per VPC, so the same code fails:

```
Error: creating EC2 Internet Gateway Attachment: Resource.AlreadyAssociated:
resource igw-0abc... is already attached to network vpc-0def...
```

The deeper point: *"reuse the default VPC"* is not one behaviour. It depends on
what previous occupants of the account did to it, which is state nobody is
maintaining and nobody documented.

A dedicated VPC costs six small resources and buys two things worth more than
that: **the plan is identical in any account**, and `terraform destroy` removes
every byte of it, so nothing is left behind to bill or to puzzle over later.

A VPC, subnet, route table, internet gateway and their associations are all
**free**. The only thing here that would cost money is a NAT gateway, and there
is deliberately none — the node sits in a public subnet with a public IP. A NAT
gateway bills about $32/month and would buy nothing.

## What it creates

| Resource | Note |
|---|---|
| `aws_vpc` | `10.80.0.0/16`, DNS support and hostnames both on |
| `aws_internet_gateway` | |
| `aws_subnet` | `10.80.1.0/24`, public IP on launch |
| `aws_route_table` + association | `0.0.0.0/0` to the IGW |
| `aws_default_security_group` | **Emptied.** A new VPC's default SG allows all traffic between its own members |
| `aws_security_group` + 2 rules | SSH from one `/32`; egress open |
| `aws_key_pair` | Public half only |
| `aws_instance` | `t3.large`, 40 GB gp3 encrypted, IMDSv2 required, **no IAM role** |

## Three decisions worth defending

**`10.80.0.0/16`, not `172.31` or `10.42`.** `172.31.0.0/16` is every AWS
default VPC, and k3s uses `10.42.0.0/16` for pods and `10.43.0.0/16` for
services. A VPC range overlapping the pod range breaks cluster routing in ways
that look like application bugs — and it would make the `except` list in
`network/04-allow-https-egress.yaml` impossible to write correctly.

**IMDSv2 required, `http_put_response_hop_limit = 1`.** Part of the thesis
rather than a checkbox. `web` has a `/fetch` endpoint that performs an outbound
request to a URL it is handed — a deliberate SSRF, for attack 5. Against IMDSv1
that reads the instance role credentials in a single request. The hop limit is
the part most often left at 2: a response with TTL 1 cannot be forwarded out of
the host network namespace, so a container cannot reach IMDS at all, token or
no token.

**No IAM instance profile.** Nothing on the box needs the AWS API — the cluster
is self-contained, and the only AWS calls in the project are terraform's, from
your workstation. No role means there are no credentials for attack 5 to reach
even if the other two controls were bypassed.

## One ingress rule

SSH, from one auto-detected `/32`. Every UI is reached over an SSH tunnel:

```bash
eval "$(terraform output -raw tunnel_command)"
```

A home connection's public IP changes without warning, so a box that was
reachable yesterday may refuse you today — and the symptom is an SSH timeout
that looks like a dead instance rather than a firewall rule. Re-running `apply`
re-detects and updates the rule in place.

**A trap from the previous project:** AWS restricts security-group rule
descriptions to `a-zA-Z0-9. _-:/()#,@[]+=&;{}!$*` and rejects anything else
with `InvalidParameterValue`. A description reading *"the operator's address"*
failed the rule **after** the instance had been created, leaving a running,
billing box with no way to SSH into it. There are no apostrophes in this stack.

Egress stays open at the security group, which is deliberate even in the
egress-filtering project. The node must reach package mirrors, `get.k3s.io`,
the Helm repositories, `ghcr.io`, and — the one people forget —
`rekor.sigstore.dev` and `fulcio.sigstore.dev`, because Kyverno resolves the
transparency log at admission time. A security-group allowlist that omits
Sigstore turns every deployment into a verification timeout. A CIDR allowlist
here would be theatre anyway: the addresses behind `ghcr.io` are a CDN. The
real egress control is one layer up and two layers more precise — see
`istio/03-egress-allowlist.yaml`.

## State

Local, and gitignored. It contains every attribute of every resource, and for
some resource types that includes secrets. A `terraform.tfstate` committed to a
public repository is the worst single thing that could happen to this project,
which is why it appears in two `.gitignore` files.

There is no `tls_private_key` resource: that would write a private key into
state in plaintext. Terraform uploads the public half of a key you already
hold.

## Teardown

```bash
../scripts/lab-down.sh
```

Destroys, then **verifies against the AWS API rather than terraform state** —
because "destroy completed" and "the account is empty" are different claims.
Terraform reports on what it tracked; anything created outside that state, by
hand or by a run whose state was lost, is invisible to it. The script checks
instances, volumes, the VPC and unattached Elastic IPs, which bill precisely
while nothing is using them.
