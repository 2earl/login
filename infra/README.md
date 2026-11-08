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

1. Open a PR that changes files here. HCP Terraform (workspace `2earl-login-prod`) posts a
   speculative plan on the PR. HCP does not plan PRs from forks.
2. Merge. HCP queues a run on `main`.
3. The owner reviews the plan in HCP and confirms the apply. Apply is never automatic.

Credentials: `CLOUDFLARE_API_TOKEN` is a sensitive environment variable in the workspace. Nothing
in this directory may contain a secret.

## Not managed here

- Worker code, Worker secrets, D1 migrations: Wrangler, through `.github/workflows/deploy.yml`.
- The 2earl.com zone and its other DNS records.
