# Provider pinning.
#
# Pinned to a major version rather than left open. An unpinned AWS provider is
# the reason a stack that applied cleanly in March fails to plan in September,
# and the diff that explains it lives in someone else's changelog.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "zero-trust-supply-chain"
      ManagedBy = "terraform"
      Owner     = "Syed-Amjad"
    }
  }
}
