resource "aws_key_pair" "node" {
  key_name   = "${var.name}-key"
  public_key = file(pathexpand(var.public_key_path))

  tags = {
    Name = "${var.name}-key"
  }
}

resource "aws_instance" "node" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.node.id
  vpc_security_group_ids      = [aws_security_group.node.id]
  key_name                    = aws_key_pair.node.key_name
  associate_public_ip_address = true

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = "gp3"
    encrypted   = true

    # The volume goes when the instance goes. This is a rebuildable lab box and
    # an orphaned 40 GB volume bills at ~$3.20/month for nothing — exactly the
    # kind of leak `terraform destroy` exists to prevent.
    delete_on_termination = true
  }

  # ---------------------------------------------------------------------------
  # IMDSv2 required, and in THIS project it is part of the thesis rather than a
  # checkbox.
  #
  # The v1 endpoint answers an unauthenticated GET from anything that can make
  # an HTTP request from inside a pod. The web service in this build has a
  # /fetch endpoint that performs an outbound request to a URL it is given — a
  # deliberate, self-inflicted SSRF, there to drive the egress-filtering
  # demonstration. Against IMDSv1 that endpoint reads the instance role
  # credentials in a single request. Against IMDSv2 the same request gets a 401,
  # because it carries no PUT-obtained token.
  #
  # hop_limit = 1 is the part that matters most and is most often left at 2: a
  # response with TTL 1 cannot be forwarded out of the host network namespace,
  # so a container cannot reach IMDS at all, token or no token.
  # ---------------------------------------------------------------------------
  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  # No instance profile is attached, deliberately. Nothing on this box needs to
  # call the AWS API — the cluster is self-contained, and the only AWS calls in
  # the project are terraform's, from your workstation. No role means there are
  # no credentials on the instance for the SSRF demonstration to reach even if
  # IMDSv2 were bypassed.

  # No Elastic IP on purpose. An EIP bills while it is NOT attached, which is
  # precisely when you have forgotten about it.

  tags = {
    Name = var.name
  }

  # Terraform would otherwise be free to build the instance in parallel with the
  # route table association. The instance would come up, cloud-init would run
  # apt against a subnet with no egress yet, and the boot would fail in a way
  # that looks nothing like a race.
  depends_on = [aws_route_table_association.node]

  lifecycle {
    # The AMI data source resolves "most recent", so Ubuntu republishing would
    # otherwise show up as a plan that destroys the cluster you spent a day
    # building. Changing instance type or disk size still works; only AMI drift
    # is ignored.
    ignore_changes = [ami]
  }
}
