# infra

Terraform for the Cloudflare resources around the `login` Worker. Ownership split and rationale:
[docs/DESIGN.md §9](../docs/DESIGN.md).

| File | Manages |
|---|---|
| `zone.tf` | Zone settings for 2earl.com (TLS, HTTPS, HSTS, 0-RTT off), DNSSEC. The zone itself is read, not managed. |
| `storage.tf` | D1 database `login` and KV namespace `login-oauth`, both in the EU jurisdiction, protected from destroy |
| `worker.tf` | Custom domain `login.2earl.com` → Worker `login` |
| `firewall.tf` | WAF custom rule and rate-limiting rule |

## How changes are applied

HCP Terraform (workspace `2earl-login-prod`) keeps the state only; Terraform runs in GitHub Actions
(`.github/workflows/infra.yml`), so a run never depends on HCP fetching the repository.

1. Open a PR that changes files here. The `check` job runs `terraform fmt`, `init` and
   `validate`, without secrets.
2. Merge. On `main`, the `plan` job waits for the owner's approval (environment `production`),
   then writes the plan to the run's summary.
3. If there are changes, the `apply` job waits for a second approval and applies only if a fresh
   plan is identical to the one reviewed. Apply is never automatic.

Credentials, in the repository's `production` environment: `TF_API_TOKEN` (an HCP Terraform team
token) and `CLOUDFLARE_INFRA_API_TOKEN`. Nothing in this directory may contain a secret.

## Not managed here

- Worker code, Worker secrets, D1 migrations: Wrangler, through `.github/workflows/deploy.yml`.
- The 2earl.com zone and its other DNS records.
