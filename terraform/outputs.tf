output "public_ip" {
  description = "Current public address of the node."
  value       = aws_instance.node.public_ip
}

output "instance_id" {
  description = "Instance id, for the teardown check."
  value       = aws_instance.node.id
}

output "vpc_id" {
  description = "The VPC this stack created. Nothing else lives in it."
  value       = aws_vpc.main.id
}

output "ssh_command" {
  description = "Plain SSH."
  value       = "ssh ubuntu@${aws_instance.node.public_ip}"
}

output "tunnel_command" {
  description = <<-EOT
    SSH with the two UIs forwarded. No UI port is open in the security group.
      8080 ArgoCD · 2802 Falcosidekick UI (only if FALCO_UI=1 at install time)
  EOT
  value = join(" ", [
    "ssh",
    # Keepalives, not decoration. These installs print nothing for minutes and
    # an idle session through a NAT gateway is closed - which kills helm
    # mid-install and strands the release in `pending-install`.
    "-o ServerAliveInterval=30",
    "-o ServerAliveCountMax=6",
    "-L 8080:localhost:8080",
    "-L 2802:localhost:2802",
    "ubuntu@${aws_instance.node.public_ip}",
  ])
}

output "allowed_ssh_cidr" {
  description = "The address :22 was opened to. Confirm this is yours."
  value       = local.ssh_cidr
}

output "hourly_cost_reminder" {
  description = "Read this at the end of every session."
  value       = "${var.instance_type} bills ~$0.083/hour while running. Run ./scripts/lab-down.sh when you stop for the day."
}
