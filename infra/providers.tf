# Credentials come from the CLOUDFLARE_API_TOKEN environment variable, set as a sensitive
# variable in the HCP Terraform workspace. Never put a token in this repository.
provider "cloudflare" {}
