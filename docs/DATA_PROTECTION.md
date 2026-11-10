# login.2earl.com — Data Protection Notes

Status: **Draft for review** · Owner: @FerhatDundar · Last updated: 2026-11-08

> These are engineering notes on how the service handles personal data. They are **not legal
> advice**. The legal pages (`https://2earl.com/privacy`, `/terms`, `/imprint`, in the `2earl/website`
> repo) must be reviewed by someone qualified before
> sign-up is opened (phase 5). Items marked **[verify]** need that review.

The service is operated from Germany and will have users in the EU, so the GDPR applies, along
with German law on telemedia: TDDDG for cookies, DDG for the imprint **[verify]**.

---

## 1. Principles applied in the design

- **Minimisation.** We ask Google only for `openid email profile`. We keep:
  - the Google `sub`, email, `email_verified` and display name;
  - not the profile picture, locale or Google tokens.
- **Pseudonymisation.** Data stored in KV holds only our internal user ID.
- **Location.** The D1 database and the KV namespace are both created with jurisdiction `eu`
  (`infra/storage.tf`). This cannot be added later. D1 read replication is disabled so no copies
  run outside the EU.
- **No tracking.** No analytics, no third-party scripts, no advertising cookies.
- **Short retention by default** (§4).

## 2. Data inventory

| Data | Where | Source | Purpose |
|---|---|---|---|
| Google subject ID (`sub`) | D1 `identities` | Google ID token | Identify the account |
| Email, `email_verified` | D1 `identities`, `users.primary_email` | Google | Show the account; contact on security issues; let Prompt share find the account when someone shares a prompt with that address (only the user ID is returned) |
| Display name | D1 `users` | Google, or the user (`/welcome`, `/account/name`) | Show the account |
| Email address of an email sign-in method | D1 `identities` (provider `email`), `users.primary_email` | User, verified with a code | Sign in; security notices |
| Email codes in progress (address, HMACs of code, link and cookie, purpose, tries, IP prefix, times) | D1 `email_codes` | System | Verify the address; enforce send limits. Deleted 2 days after creation, and with the account |
| Security notices sent by email (sign-in method or second factor changed, new recovery codes, first approval of an app, account deleted) | Cloudflare Email Service (not stored by us) | System | Tell the user about changes to their account (Art. 6(1)(b), (f)) |
| Session records (hashed ID, timestamps, IP prefix, user-agent hash) | D1 `sessions` | Request | Keep the user signed in; detect abuse |
| Login transaction (`state`, `nonce`, PKCE verifier) | D1 `login_tx` | Generated | Secure the sign-in, ≤ 10 min |
| OAuth grants and tokens (hashed, encrypted props `{uid, authTime}`) | KV | Generated | Authorise apps the user approved |
| Consent decisions | Signed cookie + grants | User | Remember approvals |
| Audit events (event, time, IP prefix, client ID, user ID) | D1 `audit_events` | Generated | Security and accountability |
| Second-factor data (passkey public keys, IDs, names and counters; encrypted TOTP secret; hashed recovery codes; wrong-attempt counter and lock time) | D1 `mfa_factors`, `recovery_codes`, `users` | User (enrolment) | Protect the account. Deleted with the factor or the account; included in the export without secrets |
| Second-factor steps in progress (passkey challenge, TOTP secret being set up, new recovery codes before they are shown) | D1 `mfa_pending` | System | ≤ 10 minutes, deleted with the session |
| Request logs | Cloudflare (Workers logs, if enabled) | Request | Operations; configured without tokens or full query strings |

IP addresses are stored only truncated (/24 IPv4, /48 IPv6).

## 3. Legal basis **[verify]**

| Processing | Basis |
|---|---|
| Account, sign-in, sessions, grants, consent | Art. 6(1)(b) GDPR: necessary to provide the service the user signs up for |
| Security logging, rate limiting, audit | Art. 6(1)(f) GDPR: legitimate interest in securing the service. Minimised; short retention |
| Strictly necessary cookies | § 25(2) No. 2 TDDDG: no consent banner needed for `__Host-session`, `__Host-login_tx` and the consent-remember cookie |

## 4. Retention

| Data | Retention |
|---|---|
| Login transactions | 10 minutes, then deleted |
| Email codes | Usable 10 minutes; the row is deleted 2 days after creation (send limits count it), or with the account |
| Sessions | 12 h idle / 7 days absolute |
| OAuth grants | 7 days idle / 90 days absolute, or until revoked |
| Audit events | 90 days, then deleted (daily cron) |
| Account data | Until the user deletes the account or the owner deletes it |
| Invitations (allowlist) | Until the invitation is withdrawn or the invited user deletes their account |
| Deletion notices (`deletion_notices`: a deleted account's internal ID, per service) | Until that service confirms it deleted the user's data; then nothing about the account is kept |
| After account deletion | Deleted immediately from D1 and KV. D1 point-in-time recovery may hold copies for up to 30 days **[verify the Time Travel window]**; not restored except for disaster recovery |

## 5. Recipients and processors

| Party | Role | Notes |
|---|---|---|
| Cloudflare, Inc. | Processor (hosting, Workers, D1, KV, network) | Cloudflare's DPA applies through its terms **[verify that the account has accepted it]**. US company: transfers rely on the EU-US Data Privacy Framework and/or SCCs **[verify current status]**. D1 and KV data stay in the EU jurisdiction; request processing at the edge is global |
| Cloudflare Email Service | Processor (part of Cloudflare, above) | Delivers sign-in codes and security notices from `noreply@2earl.com`. Receives the recipient address and the message |
| Google | Independent controller for the user's Google account | We receive identity claims when the user chooses "Sign in with Google". Google's privacy terms apply to the user's Google account |
| GitHub, HashiCorp | Not recipients of user data | Hold code, infrastructure state and secrets only. **Terraform state must not contain user data** |
| OAuth clients (MCP apps) | Separate controllers | Receive only what the user approves. In v1 the gateway receives the internal user ID and scopes, not email or name |

## 6. Data subject rights — how the system supports them

| Right | Implementation |
|---|---|
| Access (Art. 15) | `/account` shows the data; `/account/export` downloads JSON: account, sign-in methods, sessions (shortened IP, user-agent hash), connected apps, invitation, the user's security log, what each other 2earl service holds (asked of that service, e.g. the MCP gateway's security log), and notes on what is not included (hashes of cookies and tokens) |
| Rectification (Art. 16) | Name: `/account/name`. Email: add the right address as a sign-in method, then remove the old one. A Google method's address follows Google |
| Erasure (Art. 17) | `/account/delete`, confirmed through Google or a code to the account's address: revokes grants, deletes the account, sign-in link, sessions and invitation; the security log is re-keyed to a random ID and expires after 90 days (DESIGN §6.3) |
| Restriction / objection | Owner can suspend an account on request |
| Portability (Art. 20) | Same JSON export |
| Withdraw approvals for apps | `/account` → Connected apps → Disconnect |

Requests can also be sent to the contact address on `https://2earl.com/privacy`.

## 7. Security measures (Art. 32)

The measures are in [THREAT_MODEL.md](THREAT_MODEL.md):
- TLS-only, HSTS;
- hashed tokens and sessions, encrypted grant properties;
- least-privilege CI;
- owner-approved production deploys;
- audit logging;
- rate limiting.

**Breach procedure (to write in phase 5).** Assess within 24 h. Notify the supervisory authority
within 72 h where required (Art. 33). Notify users where there is high risk (Art. 34).

## 8. Owner to-dos before opening sign-up

1. Controller identity: done. Name, postal address and contact email are published on
   `https://2earl.com/imprint` and `/privacy` (`2earl/website`). Consider a role address on the
   domain (for example `privacy@2earl.com` via Cloudflare Email Routing) instead of a personal
   mailbox.
2. Confirm the Cloudflare DPA is in place for the account.
3. Have the privacy policy and imprint reviewed **[verify]**.
4. Create a record of processing activities (Art. 30) — this document is a starting point.
5. Google consent screen: privacy and terms links are set to `https://2earl.com/privacy` and
   `https://2earl.com/terms`. Publish the consent screen ("In production") only when sign-up opens;
   until then it stays in Testing with the owner as test user. **Sign-up opens with phase 7
   (2026-11-10): publish it now, or new Google sign-ups fail while email sign-up works.**
6. Roll the credentials shared during setup (THREAT_MODEL R5b) before the phase 7 deploy.
