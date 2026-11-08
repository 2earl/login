# The 2earl.com zone already exists. It is read, never created or destroyed, by this
# configuration, so a mistake here cannot delete the domain.
data "cloudflare_zone" "this" {
  filter = {
    name    = var.zone_name
    account = { id = var.account_id }
  }
}

locals {
  zone_id = data.cloudflare_zone.this.id

  # Zone-wide settings (docs/DESIGN.md §9.1). These apply to every hostname in 2earl.com.
  zone_settings = {
    ssl                      = "strict"
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    always_use_https         = "on"
    automatic_https_rewrites = "on"
    # 0-RTT lets a network attacker replay the first request of a resumed TLS session.
    # The service accepts POSTs (token endpoint, consent), so it stays off.
    "0rtt"        = "off"
    browser_check = "on"
    http3         = "on"
  }
}

resource "cloudflare_zone_setting" "this" {
  for_each = local.zone_settings

  zone_id    = local.zone_id
  setting_id = each.key
  value      = each.value
}

# HSTS for the whole zone. include_subdomains commits every *.2earl.com hostname to HTTPS for a
# year in browsers that have seen it. Preload is left off at zone level (the Worker sends its own
# header); submitting the domain to the browser preload list is a separate, deliberate step.
resource "cloudflare_zone_setting" "security_header" {
  zone_id    = local.zone_id
  setting_id = "security_header"
  value = {
    strict_transport_security = {
      enabled            = true
      max_age            = 31536000
      include_subdomains = true
      preload            = false
      nosniff            = true
    }
  }
}

# DNSSEC. Cloudflare signs the zone; the DS record (output `dnssec_ds`) must be present at the
# registrar for validation to start. With Cloudflare Registrar this happens automatically.
resource "cloudflare_zone_dnssec" "this" {
  zone_id = local.zone_id
  status  = "active"
}
