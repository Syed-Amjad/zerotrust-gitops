# Lookups and locals. Nothing here creates anything — see network.tf.

data "aws_availability_zones" "available" {
  state = "available"
}

# Canonical's account id. Resolved at plan time rather than hardcoded, because a
# hardcoded AMI id is region-locked and goes stale the moment Ubuntu republishes.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Auto-detects the caller's public address so the security group can be a /32.
# Overridden by var.allowed_ssh_cidr when set — on a changing home connection,
# re-running apply is enough to correct the rule.
data "http" "my_ip" {
  count = var.allowed_ssh_cidr == null ? 1 : 0
  url   = "https://checkip.amazonaws.com"
}

locals {
  ssh_cidr = var.allowed_ssh_cidr != null ? var.allowed_ssh_cidr : "${chomp(data.http.my_ip[0].response_body)}/32"
  az       = var.availability_zone != null ? var.availability_zone : data.aws_availability_zones.available.names[0]
}
