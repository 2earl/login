terraform {
  required_version = ">= 1.10.0"

  # State and runs live in HCP Terraform. The workspace is VCS-driven from this repo
  # (working directory "infra", manual apply). This block also lets an authorised operator run
  # remote plans from a laptop with `terraform login`.
  cloud {
    organization = "2earl"
    workspaces {
      name = "2earl-login-prod"
    }
  }

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.28"
    }
  }
}
