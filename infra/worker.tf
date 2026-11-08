# Attaches login.2earl.com to the Worker. Cloudflare creates the DNS record and certificate
# itself; no separate DNS resource is needed. The Worker script must already exist: it is
# created by the deploy workflow, not by Terraform (docs/DESIGN.md §9.1).
resource "cloudflare_workers_custom_domain" "login" {
  account_id = var.account_id
  zone_id    = local.zone_id
  hostname   = var.login_hostname
  service    = var.worker_name
}
