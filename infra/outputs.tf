# IDs the Worker needs in wrangler.jsonc (phase 4). None of these are secrets.

output "zone_id" {
  value = local.zone_id
}

output "d1_database_id" {
  description = "wrangler.jsonc → d1_databases[].database_id"
  value       = cloudflare_d1_database.login.id
}

output "kv_namespace_id" {
  description = "wrangler.jsonc → kv_namespaces[].id (binding OAUTH_KV)"
  value       = cloudflare_workers_kv_namespace.oauth.id
}

output "dnssec_ds" {
  description = "DS record to add at the registrar if it is not Cloudflare Registrar"
  value       = cloudflare_zone_dnssec.this.ds
}
