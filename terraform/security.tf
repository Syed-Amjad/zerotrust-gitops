# One ingress rule, and it is not an accident that there is only one.
#
# ArgoCD, the Falco event UI and anything else with a web interface run on this
# box and none of them is exposed. They are reached over an SSH tunnel:
#
#   ssh -L 8080:localhost:8080 -L 2802:localhost:2802 ubuntu@<ip>
#
# That is why no 8080 rule appears below.

resource "aws_security_group" "node" {
  name        = "${var.name}-sg"
  description = "SSH from one address; all UIs reached via SSH tunnel"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.name}-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.node.id

  # No apostrophe. AWS restricts rule descriptions to
  #   a-zA-Z0-9. _-:/()#,@[]+=&;{}!$*
  # and rejects anything else with InvalidParameterValue. In project 1 this
  # read "the operator's address" and the apply failed AFTER the instance had
  # been created, leaving a running, billing box with no way to SSH into it.
  description = "SSH from the operator address only"

  cidr_ipv4   = local.ssh_cidr
  ip_protocol = "tcp"
  from_port   = 22
  to_port     = 22
}

# ---------------------------------------------------------------------------
# Egress stays open AT THE SECURITY GROUP, and that is the right answer here
# even though this is the egress-filtering project.
#
# The node itself must reach: Ubuntu package mirrors, get.k3s.io, the Helm
# chart repositories, ghcr.io for images, and — the one people forget —
# rekor.sigstore.dev and fulcio.sigstore.dev, because Kyverno's keyless
# signature verification resolves the transparency log at admission time. A
# security group allowlist that omits Sigstore turns every deployment into a
# verification timeout.
#
# The egress control this project actually demonstrates is one layer up and two
# layers more precise: Istio's REGISTRY_ONLY outbound policy plus ServiceEntry,
# which filters per-workload at L7 on a verified identity rather than
# per-instance at L3 on an IP. Attack 5 proves it. Writing a CIDR list here as
# well would be security theatre: the addresses behind ghcr.io are a CDN and
# change without notice.
# ---------------------------------------------------------------------------
resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.node.id
  description       = "Outbound for package, chart, image and Sigstore fetches"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
