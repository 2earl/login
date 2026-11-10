# login.2earl.com — Threat Model

Status: **Draft for review** · Owner: @FerhatDundar · Last updated: 2026-11-08
Scope: v1 as described in [DESIGN.md](DESIGN.md). Method: assets → trust boundaries → threats per
boundary → mitigations → residual risks. Re-review whenever a phase changes the attack surface.

---

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Access and refresh tokens | Act as the user on the MCP gateway |
| A2 | Authorization codes | One step from A1 |
| A3 | User sessions (`__Host-session`) | Approve consent as the user |
| A4 | Owner/admin session | Full control of users, allowlist and trusted clients |
| A5 | Google client secret | Impersonate login.2earl.com to Google |
| A6 | Cloudflare API token | Change DNS, WAF, Workers and data for 2earl.com |
| A7 | HCP Terraform workspace and state | State can contain resource IDs and secrets |
| A8 | GitHub repo `main` and `production` environment | Ship arbitrary code to the login service |
| A9 | User personal data (D1) | GDPR exposure |
| A10 | Integrity of consent decisions | The user agreed to *this* client, *this* resource, *these* scopes |

## 2. Actors

- **Anonymous Internet** — anyone, including automated scanners.
- **Malicious OAuth client** — a CIMD URL anyone can host; it can show any `client_name`.
- **Malicious web page** visited by a signed-in user (CSRF, clickjacking, login CSRF).
- **Network attacker on loopback/native client** (intercepted redirect).
- **Compromised dependency or GitHub Action** (supply chain).
- **Outside contributor** opening pull requests to the public repo.
- **Privileged insider** — any GitHub org owner, any installed GitHub App with org-wide access,
  any Cloudflare or HCP account member.
- **Upstream compromise** — a user's Google account, or Google itself.

## 3. Trust boundaries

1. Browser ↔ login.2earl.com
2. MCP client ↔ login.2earl.com (authorize, token endpoints)
3. login.2earl.com → Google (OIDC client)
4. login.2earl.com → arbitrary CIMD URLs (outbound fetch)
5. Gateway ↔ login (Service Binding)
6. GitHub → Cloudflare (deploy), GitHub → HCP → Cloudflare (Terraform)
7. Worker ↔ D1 / KV

---

## 4. Threats and mitigations

### B1/B2 — OAuth protocol

| Threat | Mitigation | Verified by |
|---|---|---|
| Authorization code interception (native/loopback) | PKCE **S256 required**; `plain` rejected in our `/authorize` handler, since the library's types accept it | Protocol test |
| Redirect URI manipulation / open redirect | Exact match against registered or CIMD-listed URIs; loopback port flexibility only for loopback; `javascript:`, fragments, userinfo refused (library) | Protocol test |
| Mix-up attack (client talking to several authorization servers) | RFC 9207 `iss` on every authorization response (library, always on); exact issuer in metadata | Protocol test |
| Token used at a different resource (confused deputy, token passthrough) | RFC 8707 `resource` required; tokens bound to one audience; gateway checks audience; gateway **never forwards** user tokens upstream | Protocol test + gateway contract |
| Code replay | Single-use codes; reuse must invalidate the grant | Protocol test (if the library does not revoke on reuse, add it in `tokenExchangeCallback`) |
| Refresh token theft | Rotation on use; 7-day idle and 90-day absolute cap; revocation endpoint; grant revoke from `/account` | Protocol test |
| Long-lived access token after client deletion | Library revokes asynchronously; **access TTL 15 min** bounds the gap | Config review |
| Scope escalation | Consent lists each scope; user may reduce; `admin` never grantable to OAuth clients; new scope re-prompts | Unit test |
| Scope escalation through an altered consent form (the library grants any supported scope the form submits) | The page carries its offered scopes, HMAC-signed and bound to the consent handle; only offered and ticked scopes of the requested service are granted | `test/services.test.ts` |
| A service keeps a deleted user's data | Deletion notices to every service, written with the deletion, retried until confirmed, visible in `/admin` (DESIGN §4.8) | `test/services.test.ts` |
| DCR abuse (mass client registration) | DCR disabled | Metadata test |

### B2/B4 — Client ID Metadata Documents

| Threat | Mitigation |
|---|---|
| SSRF via `client_id` URL (internal hosts, Cloudflare same-zone routing) | `global_fetch_strictly_public` compatibility flag (required by the library before it advertises CIMD); HTTPS only; no private addresses |
| Resource exhaustion via slow or large documents | Library limits: 5 KB, 10 s, cached |
| Phishing via a lookalike `client_name` ("2earl Official") | Consent page shows the **client_id host** and redirect host prominently; "not verified by 2earl" badge unless owner-trusted; logos not rendered |
| Secret material in documents | Library rejects embedded secrets and private/symmetric JWKs |

### B1 — Browser-facing

| Threat | Mitigation |
|---|---|
| Consent clickjacking | `frame-ancestors 'none'` (CSP) on all pages; library consent headers forbid framing |
| CSRF on consent | Library-bound, single-use consent handle tied to this browser |
| CSRF on account/admin actions | Synchronizer token per session + `Origin` check; SameSite=Lax |
| Login CSRF (victim signed in as attacker) | Google `state` bound to a server-side transaction and cookie; one-time use |
| Session fixation | New session ID issued on every sign-in; old cookie discarded |
| XSS | No user-authored HTML; all client strings escaped; strict CSP (`default-src 'none'`, no inline script) |
| Code/token leakage via Referer, logs or caches | `Referrer-Policy: same-origin` (nothing sent to other sites); `Cache-Control: no-store`; logging rules (DESIGN §7) |
| Cookie theft by a sibling subdomain | `__Host-` prefix (no `Domain`, Path=/, Secure). Other `*.2earl.com` apps cannot set or read it |

### B3 — Google sign-in

| Threat | Mitigation |
|---|---|
| Account takeover by email collision (attacker controls a different identity with the same email) | Users keyed on Google `sub`; **no automatic linking by email**; `email_verified` required |
| Allowlist by email admits a different Google account with the same address (e.g. a reassigned Workspace address) | Email entries are replaced by the `sub` on first successful sign-in; tested |
| Forged or replayed ID token | `jose` verification against Google JWKS; `iss`, `aud`, `exp`, `nonce` checks |
| Google account compromise | Out of our control. Mitigation: user can revoke all grants; owner can suspend the user. Owner account must use Google 2-step verification / passkey |
| Google client secret leak (A5) | Stored only as GitHub environment secret and Worker secret. Leak alone does not bypass redirect-URI matching. **Rotate** — it was shared in plain text during setup (R5) |

### B3 — Sign-in with an email code (DESIGN §4.9, phase 7)

| Threat | Mitigation |
|---|---|
| Guessing a code | 6 digits, 5 tries per code, then it stops; codes need the cookie of the browser that asked, so an attacker can't try codes for someone else's request. Per-address and per-network send limits bound how many codes exist |
| Login CSRF: a victim is signed in to the attacker's account by opening the attacker's link | The link works only with the `__Host-email_code` cookie of the browser that asked |
| Mail scanners "clicking" the link, signing in or burning it | Opening the link shows a button; only the POST uses the code |
| Code leaked from the database | Only HMACs (`SESSION_PEPPER`) of the code, the link token and the cookie are stored |
| Account enumeration through the form | The same answer for addresses with and without an account; a code is sent either way |
| Using the form to flood someone's inbox, or our sender's reputation | 5 codes per address per hour (10 a day), 20 per network per hour, 2,000 a day overall; `AUTH_RATE_LIMITER`; zone rate rule on the paths |
| Takeover of a Google user's account by someone with access to the same inbox | No joining by address: an email sign-in never reaches an account that signs in with Google, and vice versa. Methods are added only while signed in, after a recent proof |
| Compromised inbox | Equals account access for accounts that sign in by email (as for any passwordless email sign-in). Mitigations: security notices on every change, second factor offered at sign-up and enforced once enrolled |
| Stolen session adds the attacker's method | Adding or removing a method needs a recent second factor or sign-in (`changeCheck`), and the account's address gets a notice |
| Owner locked out of `/admin` by removing their Google account | The owner's Google method can't be removed |

### B1/B3 — Second factor (DESIGN §4.7, phase 5)

| Threat | Mitigation |
|---|---|
| Google account takeover gives full access | Second factor in our service. Optional by default; enforced when `MFA_REQUIRED=true`; always required for enrolled users |
| Downgrade: turning the flag off weakens enrolled accounts | Enrolled users are challenged regardless of the flag |
| TOTP phishing / relay | Passkeys are the primary factor (origin-bound); TOTP is a fallback |
| TOTP code reuse | Last accepted time step stored; same or older step rejected |
| TOTP secret theft from D1 | Encrypted with `MFA_ENCRYPTION_KEY` (AES-GCM); key only in Worker secrets |
| Recovery-code guessing | 10 random 50-bit codes, stored as keyed hashes, single use; per-network rate limit and a per-user lockout (5 wrong answers → 15 minutes) |
| TOTP code guessing | Same lockout: at most 480 attempts a day per user, about a 1 in 700 chance per day |
| Admin area abused by a stolen owner session | `/admin` needs the owner's Google account, a second factor and `aal2`; every change needs the second factor from the last 15 minutes; same-origin check; all changes audited |
| Owner locks themself out from `/admin` | The owner's own account and invitation can't be changed from `/admin` |
| `/admin` probing by other users | Same 404 as an unknown page |
| Stolen session adds the first factor (user had none) | First factor needs a Google sign-in from the last 10 minutes; otherwise `/login?reauth=1` |
| Script injection on the passkey pages | The only script is a static file from this origin (`MFA_CSP`); no inline script, `connect-src 'self'` |
| Attacker with a stolen session adds their own factor | Factor changes need a challenge ≤ 5 minutes old |
| Owner's Google account taken over → full admin | `/admin` always requires the second factor, whatever `MFA_REQUIRED` says (D11) |
| Admin MFA reset abused | Owner-only, audited; the user is notified by email (when email sending exists) |

### B5 — Gateway integration

| Threat | Mitigation |
|---|---|
| Gateway validating tokens by reading KV directly (skips audience checks) | Gateway has **no** KV binding; only the Service Binding RPC |
| Public token validation endpoint abused | Validation is RPC-only over the Service Binding; no public introspection endpoint in v1 |

### B6 — Supply chain and CI

| Threat | Mitigation |
|---|---|
| Malicious PR from a fork reads secrets | Secrets exist only in the `production` environment, deployable only from `main` with owner approval. Fork PRs need approval to run. No `pull_request_target`. HCP does not plan fork PRs |
| Compromised GitHub Action | SHA pinning enforced; allow-list of actions; read-only default token |
| Compromised npm dependency | Minimal dependencies; frozen lockfile; Dependabot alerts and updates; `pnpm audit` in CI; review of lockfile diffs |
| Malicious Terraform in an internal branch exfiltrates the Cloudflare token during plan | Only owner-level actors can push branches; manual apply; residual risk R2 |
| `main` tampering | Ruleset: PR required, no force-push or deletion, no bypass actors; required CI check from phase 2 |

### B7 — Data at rest

| Threat | Mitigation |
|---|---|
| KV dump exposes tokens | Library stores only hashes; `props` encrypted with token-holder key; `props` minimal (`uid`, `authTime`) |
| D1 dump exposes sessions | Only HMAC-SHA-256 hashes of session and transaction IDs are stored (`SESSION_PEPPER`) |
| Personal data outside the EU | D1 and KV both in jurisdiction `eu`; D1 read replication disabled; KV holds pseudonymous IDs only |
| Accidental destruction of D1/KV (all users and grants lost) | `prevent_destroy` on both in Terraform; manual apply in HCP |

### Availability

| Threat | Mitigation |
|---|---|
| Credential stuffing / brute force | No passwords exist; rate limits on all entry points |
| Request floods | Cloudflare network DDoS protection; Rate Limiting binding; WAF rules |
| KV/D1 outage | Fail closed (deny), never fail open |

---

## 5. Residual risks (accepted or open)

| ID | Risk | Status | Owner action |
|---|---|---|---|
| R1 | **GitHub org owner `TayfunCesur`** has admin on this repo and can change rulesets, environments and secrets. Installed apps `claude` and `azure-pipelines` have write access to all org repos, including workflows (`claude`). | **Accepted** by owner (2026-11-08: trusted person) | Re-review if org membership changes |
| R2 | One Cloudflare token (D8) is held by both HCP (Terraform) and GitHub (deploy). Compromise of either path gives zone + DNS + Workers control. | **Accepted** by owner | Revisit when staging is added |
| R3 | `terraform-cloud` GitHub App can read all org repos, not just this one. | **Accepted** by owner (org token revoked) | — |
| R4 | GitHub org members without 2FA. Not the same as MFA in this service (DESIGN §4.7). | **Resolved** 2026-11-08 (org requires 2FA, verified via API) | — |
| R5a | Cloudflare Global API Key (`cfk_…`) was pasted into chat. It has full control of the Cloudflare account and cannot be scoped. | **Accepted** by owner, against recommendation | Roll it in the Cloudflare dashboard if it is ever needed again or exposure is suspected |
| R5b | Cloudflare account token and Google client secret were pasted into chat. | **Deferred** by owner (2026-11-08); must be done before sign-up opens | Roll the Cloudflare token (same permissions) and update it in both GitHub `production` and HCP; add a new Google client secret, update GitHub, disable the old one. HCP team token: revoked 2026-11-08 |
| R6 | No staging: first exposure of new code is production. | **Accepted**, mitigated by locked launch (D9) until 2026-11-10; since sign-up opened, by the sign-up switch on `/admin/invitations` (close it without a deploy) | — |
| R7 | Library keeps the previous refresh token valid until the rotated one is used (retry safety). A stolen-and-raced refresh token may work once. | Accepted (library design) | Monitor via audit; consider DPoP later |
| R8 | Old org-level secrets (`CLOUDFLARE_API_KEY`, Google pair) readable by every org repo. | **Resolved** 2026-11-08 (deleted) | — |
| R9 | Account deletion is confirmed through Google (or, for accounts that sign in by email, a code to that address), but neither forces a password re-entry. Someone at an unlocked computer that is signed in to both 2earl and Google can delete the account. A stolen 2earl session cookie alone cannot. | **Mitigated** 2026-11-09 for users with a second factor: deletion also needs it, used in the last 5 minutes. **Accepted** for users without one | Users who want this protection add a passkey |

## 6. Security review triggers

Re-run this threat model when any of these are introduced:
- a new identity provider or password login;
- OIDC / JWT issuance;
- a new resource server;
- DCR;
- native-app private-use redirect schemes;
- a staging environment;
- a new person with write access.
