terraform {
  required_version = ">= 1.10.0"

  # State lives in HCP Terraform (workspace in local execution mode); plans and applies run in
  # .github/workflows/infra.yml. An authorised operator can also plan from a laptop after
  # `terraform login`.
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
