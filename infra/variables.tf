variable "account_id" {
  description = "Cloudflare account that owns the 2earl.com zone and the login Worker."
  type        = string
  # Cloudflare account IDs are identifiers, not credentials.
  default = "304c2b77d734c688c8309d5a535f561a"
}

variable "zone_name" {
  description = "DNS zone the service runs in. The zone already exists and is not managed here."
  type        = string
  default     = "2earl.com"
}

variable "login_hostname" {
  description = "Public hostname of the identity service."
  type        = string
  default     = "login.2earl.com"
}

variable "worker_name" {
  description = "Name of the Worker deployed by .github/workflows/deploy.yml (wrangler.jsonc \"name\")."
  type        = string
  default     = "login"
}
