# Edge rules for the zone (docs/DESIGN.md §8). Written to work on the Cloudflare Free plan:
# no regex operators, and the rate-limiting limits that plan allows. Fine-grained limits (per
# client, per endpoint) live in the Worker's Rate Limiting binding in phase 4.
#
# A zone has one entry-point ruleset per phase. If a rule was created in the dashboard before
# this runs, apply fails with a conflict: import that ruleset instead of creating a second one.

resource "cloudflare_ruleset" "custom_firewall" {
  zone_id     = local.zone_id
  name        = "login custom rules"
  description = "Managed by Terraform in 2earl/login (infra/firewall.tf)"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "login_block_unexpected_methods"
      description = "login: only GET, HEAD, POST and OPTIONS are used"
      expression  = "(http.host eq \"${var.login_hostname}\" and not http.request.method in {\"GET\" \"HEAD\" \"POST\" \"OPTIONS\"})"
      action      = "block"
      enabled     = true
    },
  ]
}

resource "cloudflare_ruleset" "rate_limit" {
  zone_id     = local.zone_id
  name        = "login rate limits"
  description = "Managed by Terraform in 2earl/login (infra/firewall.tf)"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "login_auth_endpoints"
      description = "login: coarse per-IP limit on sign-in and token endpoints"
      expression  = "(http.request.uri.path in {\"/authorize\" \"/oauth/token\" \"/callback/google\" \"/login\"})"
      action      = "block"
      enabled     = true
      ratelimit = {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = 10
        requests_per_period = 30
        mitigation_timeout  = 10
      }
    },
  ]
}
