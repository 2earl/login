# Data stores for the login Worker (docs/DESIGN.md §6). Both are restricted to the EU
# jurisdiction, which can only be chosen at creation and never changed afterwards.
#
# prevent_destroy: replacing either resource deletes all users, sessions and grants. If a plan
# ever wants to replace one, stop and investigate instead of removing this guard.

resource "cloudflare_d1_database" "login" {
  account_id   = var.account_id
  name         = "login"
  jurisdiction = "eu"

  # Read replicas outside the EU would defeat the jurisdiction choice.
  read_replication = {
    mode = "disabled"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Owned by @cloudflare/workers-oauth-provider: clients, grants, codes and tokens (hashed),
# encrypted props.
resource "cloudflare_workers_kv_namespace" "oauth" {
  account_id   = var.account_id
  title        = "login-oauth"
  jurisdiction = "eu"

  lifecycle {
    prevent_destroy = true
  }
}
