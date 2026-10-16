variable "region" {
  description = "AWS region. us-east-1 keeps it consistent with the other projects."
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = <<-EOT
    8 GB is enough for THIS project, and that is a deliberate difference from
    the GitOps platform, which needed 16 GB.

    The reason is that this build does not run kube-prometheus-stack. The seven
    enforcement layers cost roughly:

      k3s control plane + kubelet          ~700 MB
      Istio (istiod, ingress, CNI agent)   ~1.3 GB
      ArgoCD                               ~1.0 GB
      Kyverno (4 controllers)              ~800 MB
      Falco (modern_ebpf) + sidekick       ~400 MB
      Workloads + sidecars                 ~400 MB
      OS                                   ~500 MB
                                           --------
                                           ~5.1 GB

    That leaves about 3 GB of headroom on a t3.large at roughly half the hourly
    cost of a t3.xlarge. If you want Prometheus, Grafana and Loki back on this
    box as well — which the website write-up does not claim — set this to
    t3.xlarge, because 5.1 + 2.7 does not fit in 8.
  EOT
  type        = string
  default     = "t3.large"
}

variable "root_volume_size" {
  description = <<-EOT
    GB. Larger than it looks like it needs to be, on purpose.

    Container images are the bulk of it, and this project pulls more of them
    than the last one: Istio, ArgoCD, four Kyverno controllers, Falco. Falco's
    modern_ebpf driver is compiled in at build time so there is no toolchain to
    install, but Trivy's vulnerability database is about 1 GB on its own if you
    ever run a scan on the box rather than in CI.
  EOT
  type        = number
  default     = 40
}

variable "public_key_path" {
  description = <<-EOT
    Path to an EXISTING SSH public key. Terraform uploads the public half only.

    Deliberately not tls_private_key: that resource would write the private key
    into terraform.tfstate in plaintext, and state is the one file in an IaC repo
    you cannot afford to leak. Reusing a key you already hold keeps the private
    half out of this project entirely.
  EOT
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "allowed_ssh_cidr" {
  description = <<-EOT
    CIDR permitted to reach :22. Leave null to auto-detect this machine's public
    address as a /32.

    Every UI in this project is reached through an SSH tunnel rather than an open
    port, so this is the only ingress rule the box needs. A zero-trust project
    whose own management plane is on 0.0.0.0/0 answers its own thesis.
  EOT
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = <<-EOT
    CIDR for the VPC this stack creates.

    10.80.0.0/16 is chosen to avoid the two ranges that collide in practice:
    172.31.0.0/16, which is every AWS default VPC, and 10.42/10.43, which k3s
    uses for pods and services. A VPC range that overlaps the pod range produces
    routing failures inside the cluster that look like application bugs.
  EOT
  type        = string
  default     = "10.80.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR for the single public subnet. Must sit inside var.vpc_cidr."
  type        = string
  default     = "10.80.1.0/24"
}

variable "availability_zone" {
  description = "AZ for the subnet. Leave null to take the first available in the region."
  type        = string
  default     = null
}

variable "name" {
  description = "Name tag and prefix for the VPC, instance, key pair and security group."
  type        = string
  default     = "zerotrust-platform"
}
