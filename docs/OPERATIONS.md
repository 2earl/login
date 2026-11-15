# Operations

How login.2earl.com is run: incidents and breaches, the switches that contain them, backups,
staging, access, and the routine that keeps it healthy. Written for the operator. Customers see
the public summary at <https://2earl.com/security> and the commitments at
<https://2earl.com/dpa>.

Status as of 13 November 2026. **[owner]** marks a step only the owner can take.

## 1. Severity

| Level | Examples | First response |
|---|---|---|
| **S1** | Accounts taken over; tokens or session secrets leaked; personal data exposed; sign-in down for everyone | At once, whatever the hour |
| **S2** | A flaw that could lead to S1 but isn't being exploited; one organization's SSO or directory sync broken by us; sign-in degraded | Same day |
| **S3** | A bug with a workaround; a vulnerability report that needs analysis | Within 3 working days |

One person runs the service. Until a second person can act (§5), every S1 starts with the
containment switches in §3: they work from a phone.

## 2. Incident and breach procedure

1. **Record.** Start a private note: when it was noticed, by whom, what is known. Keep adding
   times and actions; it becomes the record Art. 33(5) GDPR requires. Don't put personal data in
   GitHub issues.
2. **Contain** (§3). Prefer the narrowest switch that stops the harm.
3. **Assess within 24 hours.**
   - What happened, since when, which data, how many people and organizations.
   - The security log (`/admin/log`, 90 days) and Cloudflare's Worker logs show sign-ins, changes
     and requests.
   - Is it a personal data breach (Art. 4(12))? If unsure, treat it as one.
4. **Notify.**
   - **Organizations** whose managed accounts are affected: their owners by email **within 48
     hours** of becoming aware (2earl.com/dpa §7). Say what happened, which data and how many
     people as far as known, what was done, and a contact; follow up as more is learned.
   - **Supervisory authority**, Berlin Commissioner for Data Protection and Freedom of
     Information: **within 72 hours** unless the breach is unlikely to result in a risk (Art. 33),
     through its online form. A late report says why it is late.
   - **People affected**, when the risk to them is high (Art. 34): by email, in plain words, with
     what they should do (for example: check connected apps, add a second factor).
   - For managed accounts, the organization is the controller: it decides on the Art. 33 and 34
     notifications; we give it what it needs.
5. **Fix and recover.** Fix the cause in a pull request; deploy as usual (owner approval).
   Restore data only if needed (§4).
6. **Review within 2 weeks.** What happened, why, what changes. Update THREAT_MODEL.md; publish a
   short post-incident note if customers were affected.

A vulnerability report (SECURITY.md) is answered within 3 working days, then handled as above at
the level it deserves.

## 3. Containment switches

| Situation | Switch | Effect |
|---|---|---|
| Sign-up abuse | `/admin/invitations` → sign-up **invite only** | New accounts only by invitation; existing ones unaffected |
| One account misused | `/admin/users` → **Suspend** | Sessions end, every app grant revoked, no sign-in. 2earl's suspension can't be lifted by an organization |
| One organization misused | `/admin/orgs` → **Suspend** | Its SCIM tokens stop, services stop seeing it, members can't change it |
| An organization's SSO or directory compromised | Ask its owner to turn SSO off or revoke the token; or suspend the organization | SSO off also lifts required SSO; revoked tokens stop at once |
| One app misbehaving | `/admin/apps` → untrust or delete the client | Its consent screen changes, or it can't sign anyone in |
| All sessions suspect | Rotate `SESSION_PEPPER` **[owner]** | Every session cookie stops matching: everyone is signed out |
| Remembered consent suspect | Rotate `CONSENT_REMEMBER_SECRET` **[owner]** | Everyone is asked for consent again |
| ID-token key leaked | Rotate `OIDC_SIGNING_KEY` (DESIGN §4.11) **[owner]** | Old ID tokens stop verifying |
| Google client secret leaked | New secret in Google Cloud, then `GOOGLE_CLIENT_SECRET` **[owner]** | Google sign-in keeps working after the deploy |
| Authenticator-app key leaked | Rotate `MFA_ENCRYPTION_KEY` after a migration that re-encrypts (not built; S1 plan: reset second factors of affected users in `/admin`) | — |
| Cloudflare or GitHub credentials leaked | Revoke them in Cloudflare and GitHub; issue new ones scoped as before **[owner]** | — |
| Whole service must stop | Cloudflare dashboard → Workers → `login` → disable the route, or deploy a maintenance build **[owner]** | Everything stops, including the gateway's token checks |

Secrets are set in the GitHub `production` environment and pushed with the next deploy
(`wrangler secret bulk`); a deploy needs the owner's approval.

## 4. Backups and restore

**What exists.**
- **D1** (`login`, EU): Cloudflare's point-in-time recovery (Time Travel), up to 30 days back.
- **KV** (`OAUTH_KV`): grants and tokens. No backups; losing it means everyone connects their apps
  again, which is acceptable.
- Code and infrastructure: GitHub and HCP Terraform.

**Restoring D1** **[owner]**:
1. Export the current state first, so the restore can be undone:
   `wrangler d1 export login --remote --output=before-restore.sql` (store it encrypted, delete it
   within 30 days).
2. Find the point: `wrangler d1 time-travel info login --timestamp=<RFC 3339>`.
3. Restore: `wrangler d1 time-travel restore login --timestamp=<RFC 3339>`.
4. Accounts deleted after that point come back. Delete them again: the security log has their
   `user.deleted` events (re-keyed), and the deletion notices tell which services to notify.
   Grants in KV may refer to accounts that the restore removed; they fail safe (the account check
   on every token use).

**Drill, every 3 months** **[owner]**: export the database, import it into a scratch database
(`wrangler d1 create login-drill --jurisdiction eu`, then `wrangler d1 execute login-drill
--remote --file=…`), count users and organizations, delete the scratch database and the export.
Record the date and how long it took.

## 5. Access and continuity

| What | Who today | Plan |
|---|---|---|
| Cloudflare account | The owner | **[owner]** A second member with emergency access, a hardware key, used only when the owner can't act |
| GitHub organization `2earl` | The owner and a second owner | Write down when the second owner may act (S1 while the owner is unreachable) |
| HCP Terraform | The owner | Add the second person read-only |
| `/admin` on login | The owner's Google account (`OWNER_GOOGLE_SUB`), always with a second factor | A second admin needs a code change (one owner is a design decision, D11); not planned |
| Recovery codes, domain registrar, Google Cloud project | The owner | **[owner]** Keep recovery codes offline; write down where each lives |

Customers ask about a single operator; 2earl.com/security says so plainly. The plan above is what
to show them.

## 6. Staging

Production-only was the owner's decision for the start. Enterprise customers expect changes to
be tried before production, so this is the plan when the owner decides on it:
- A second Worker `login-staging` at `login-staging.2earl.com`, with its own D1 and KV (both EU),
  its own secrets and its own Google OAuth client (test users only).
- `deploy.yml`: on push to `main`, deploy to staging first, run the Playwright journey against it,
  then wait for the owner's approval for production.
- Terraform: a second HCP workspace `2earl-login-staging` from the same `infra/`, with the
  hostname and names as variables.
- Services (gateway, Prompt share) get staging bindings the same way when they need one.
- Cost on Workers Paid: small (a second D1 and KV within the included limits) **[verify]**.

## 7. Routine

| How often | What |
|---|---|
| Every deploy | Read the diff; approve; check `/healthz` and a sign-in |
| Weekly | Dependabot PRs; CodeQL alerts; `/admin/log` for denied and failed events |
| Monthly | Deletion notices still pending (`/admin`); SCIM tokens and SAML certificates close to expiry; `pnpm audit` |
| Every 3 months | Restore drill (§4); review who has access (§5) |
| Yearly | Rotate `SESSION_PEPPER`, `CONSENT_REMEMBER_SECRET`, the Google client secret and infrastructure tokens; review DATA_PROTECTION.md, THREAT_MODEL.md and 2earl.com/security |
| Before the first enterprise customer | An outside penetration test of login and the gateway; fix findings; keep the summary to share |

## 8. Private repositories: what the GitHub plan decides

Since 2026-11-14 the code is proprietary (LICENSE) and the repositories are to be private. What
GitHub enforces on a **private** repository depends on the organization's plan; on a public one
it was free. Check this **before** switching visibility, or the protections below stop silently.

| Protection | Free | Team | Enterprise Cloud |
|---|---|---|---|
| Rulesets `protect-main`, `protect-release-tags` (PRs, checks, linear history, tags) | **Not enforced** | Enforced | Enforced |
| Environment `production` and its secrets, deploys from `main` only | **Not available**: the deploy job loses its secrets | Available | Available |
| Required reviewer on `production` (the owner approves each deploy) | **Not available** | **Not available** | Available |
| CodeQL code scanning (default setup) | Needs the Code Security add-on | Needs the add-on | Needs the add-on |
| Secret scanning push protection | Needs the Secret Protection add-on | Needs the add-on | Needs the add-on |
| Dependabot alerts and updates | Yes | Yes | Yes |
| Actions minutes for private repositories | 2,000 a month | 3,000 a month | 50,000 a month |

Today's use is a few hundred minutes a month across the repositories, without CodeQL's runs.

**Without Enterprise, the deploy approval needs a replacement.** On Team, keep the environment
(secrets, `main` only) and start deploys by hand: `workflow_dispatch` only, the job refusing any
actor but the owner (a repository variable `DEPLOY_APPROVERS`). Merging stays the review; the
dispatch is the approval.

**Without the add-ons**, CI's `pnpm audit` (all services) and Dependabot stay; CodeQL's licence
allows it only on open-source code, so it can't simply run in a workflow instead.

**The order:**
1. Merge the licence and wording changes (all five repositories), so nothing public promises
   open source or links to a private repository.
2. Choose the plan; on Team, merge the deploy change above first.
3. Switch each repository to private (Settings → General → Danger zone). Pull request links from
   outside, and `npx github:2earl/cli`, stop working for people without access.
4. Check: a pull request's checks still required, a deploy still needs the owner, the
   `production` environment's secrets still there.

## 9. What enterprise buyers check, and where it stands

| Item | Status |
|---|---|
| Accounts the company manages, required SSO, deprovisioning | Built (DESIGN §4.18) |
| SAML SSO, SCIM, MFA, passkeys | Built |
| Data processing terms, subprocessor list, security measures | Published (2earl.com/dpa, /security) |
| Breach procedure | This document, §2 |
| Restore tested | **Open**: first drill (§4) |
| Staging | **Open**: owner's decision (§6) |
| Second person with emergency access | **Open** (§5) |
| Outside penetration test | **Open** (§7) |
| Uptime commitment, status page | **Open**: no SLA offered yet |
| SOC 2 or ISO 27001 | **Not started**: months of work; a compliance tool (Vanta, Drata) shortens it |
