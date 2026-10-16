# A dedicated VPC. Six resources, no dependency on account state.
#
# ---------------------------------------------------------------------------
# WHY THIS DOES NOT REUSE THE DEFAULT VPC — the lesson from project 1.
#
# The GitOps platform's terraform reused the default VPC and declared only the
# pieces that were missing. That worked there for an accidental reason: that
# account's default VPC had been stripped — subnets deleted, internet gateway
# deleted, and the main route table still pointing 0.0.0.0/0 at the dead
# gateway in state `blackhole`. Declaring an IGW succeeded because there was
# no longer one to collide with.
#
# This project runs in a DIFFERENT, FRESH AWS account, where the default VPC is
# intact. An intact default VPC already has an internet gateway, and AWS permits
# exactly one per VPC, so the same code fails on apply:
#
#   Error: creating EC2 Internet Gateway Attachment: Resource.AlreadyAssociated:
#   resource igw-0abc... is already attached to network vpc-0def...
#
# The deeper point is that "reuse the default VPC" is not one behaviour. It
# depends on what previous occupants of the account did to it, which is state
# nobody is maintaining and nobody documented. A dedicated VPC costs six small
# resources and buys two things worth more than that: the plan is identical in
# any account, and `terraform destroy` removes every byte of it, so there is
# nothing left behind to bill or to puzzle over later.
#
# A VPC, subnets, route tables, internet gateways and their associations are all
# free. The only thing in this file that would ever cost money is a NAT gateway,
# and there is deliberately none — the node sits in a public subnet with a public
# IP. A NAT gateway bills about $32/month and would buy nothing here.
# ---------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  # Both required for the node to resolve anything by name, including the
  # package mirrors, ghcr.io and rekor.sigstore.dev that the signature
  # verification path depends on.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.name}-igw"
  }
}

resource "aws_subnet" "node" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.subnet_cidr
  availability_zone = local.az

  # The node needs a routable address: SSH in, and image pulls out.
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name}-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.name}-rt"
  }
}

resource "aws_route_table_association" "node" {
  subnet_id      = aws_subnet.node.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# The default security group of a VPC this stack owns.
#
# A new VPC's default security group allows all traffic between members of
# itself. Nothing in this project is placed in it, but leaving it permissive is
# the kind of thing a reviewer of a zero-trust project will notice, so it is
# emptied. Both argument lists present and empty means "no rules", which is
# different from omitting them (which means "do not manage them").
# ---------------------------------------------------------------------------
resource "aws_default_security_group" "locked" {
  vpc_id = aws_vpc.main.id

  ingress = []
  egress  = []

  tags = {
    Name = "${var.name}-default-sg-emptied"
  }
}
