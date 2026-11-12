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

### B1/B3 — Sign-in with a passkey, and signed-in devices (DESIGN §4.10, phase 8a)

| Threat | Mitigation |
|---|---|
| Phishing site relays the passkey sign-in | WebAuthn binds the assertion to the origin and RP ID `login.2earl.com`; a relayed answer fails verification (tested) |
| A stolen or unlocked device signs in with a tap | `userVerification: required`: biometric or device PIN on every sign-in; an assertion without the UV flag is refused (tested) |
| Replayed assertion | The challenge is single use (deleted when read), 5 minutes, bound to the browser by `__Host-passkey_tx`; the signature counter is checked |
| Credential enumeration | Unknown credential IDs get the same refusal and an audit entry; the options endpoint reveals nothing about accounts (no `allowCredentials` outside reauth) |
| Reauth with someone else's passkey | The reauth challenge names the signed-in account; only its passkeys are accepted (tested) |
| Suspended account signs in with a passkey | Refused like every other method (tested) |
| Flood of challenge rows | Per-network rate limit (`passkey`), expired rows deleted on each request and by the daily clean-up; the zone rate limit covers `/login/passkey` and `/login/passkey/options` (`infra/firewall.tf`) |
| Script on the sign-in page widens XSS impact | The sign-in page now runs `/passkey.js` under `MFA_CSP` (`script-src 'self'`, no inline script, `connect-src 'self'`); every value is escaped server-side |
| Stolen session stays signed in unnoticed | Signed-in devices list with coarse device names and last activity; sign out one or all others (audited); security notices for method and factor changes |
| Signing out a device used to end someone else's session | The form names a session by an HMAC reference, matched only among the signed-in account's own sessions; same-origin check (tested) |

### B1/B2 — OpenID Connect provider (DESIGN §4.11, phase 8b)

| Threat | Mitigation |
|---|---|
| ID token forged | ES256 with a key only in the Worker secret; relying parties verify against `/.well-known/jwks.json` (tested with a standard JOSE library) |
| Signing key leak | Rotation without downtime (announce the next key, then swap); ID tokens last 10 minutes; the key never leaves Worker secrets and the JWKS never contains `d` (tested) |
| Replay of an ID token into another app's login | `aud`/`azp` name the client; `nonce` from the request, bound to the consent handle by HMAC so the form can't change it (tested) |
| Sites link one person across each other | Pairwise `sub` per sector, random and stored, not derived (tested: different sites get different IDs, the same site the same one) |
| Access token for a 2earl service read at UserInfo, or the reverse | Every token is bound to one audience (RFC 8707); UserInfo accepts only its own; `openid` can't be combined with service scopes (tested) |
| Silent sign-in (`prompt=none`) used to probe | Answers only `login_required`/`consent_required`/`interaction_required` to the client's registered redirect URI, which the library validated first |
| Stale sign-in used for a sensitive app | `max_age` and `prompt=login` force a fresh sign-in; `auth_time` and `acr`/`amr` tell the app how and when the person signed in |
| Logout CSRF (a link signs people out) | `/oidc/logout` asks first; the POST is same-origin only (tested) |
| Open redirect through logout | Only a redirect URI the app registered, for the app named by `client_id` or a valid `id_token_hint`; anything else gets the signed-out page (tested) |
| Name or address leaked to an app that wasn't allowed them | Claims follow the granted scopes; `profile` and `email` can be unticked on the consent page; UserInfo reads the account now |
| UserInfo abuse | Bearer only, no cookies (CORS `*` is safe); limited per address like the token endpoint |

### B2 — Token introspection (DESIGN §4.12, phase 8c)

| Threat | Mitigation |
|---|---|
| A resource server reads other services' tokens | Each credential is bound to one resource; a token for any other resource answers `{"active": false}`, identical to an unknown token (tested) |
| Introspection used as a token oracle | Requires credentials; limited per address; no answer distinguishes "revoked", "expired", "other resource" or "never existed" |
| Credential theft from the database | Only the SHA-256 of a 256-bit random secret is stored; the secret is shown once (tested) |
| Credential brute force | 256-bit secrets; constant-time comparison; the hash is computed for unknown IDs too |
| Stale credentials keep working | Revoking deletes the row at once; `last_used_at` shows unused credentials in /admin |
| Refresh tokens exposed through introspection | Never introspected: always inactive (tested) |

### B2 — Device authorization grant (DESIGN §4.13, phase 8d)

| Threat | Mitigation |
|---|---|
| Device-code phishing: an attacker starts a request and sends the victim the link | A link only fills in the code; the person must sign in, press Continue and approve on the ordinary consent page that names the app; `/device` warns to continue only for a request they started; codes expire in 10 minutes |
| User code guessing | ~34.6 bits per code, valid 10 minutes, only while pending; per-address limit on `/device` plus the zone rate limit |
| Device code theft from the database | Only its HMAC is stored; the authorization code it waits for can't be exchanged without the PKCE verifier, which needs the device code and `SESSION_PEPPER` |
| Polling floods | `slow_down` adds 5 seconds per early poll; the token endpoint's per-address limit |
| A web app abuses the device grant | Only clients that registered `/device/callback` may start one (tested); polls by any other client get `invalid_grant` (tested) |
| Code collected twice | Atomic delete-and-return; a second poll gets `invalid_grant` (tested) |
| Tokens minted outside the library's checks | login never mints tokens: approval goes through `/authorize` (second factor, step-up, consent) and tokens come from the library's own code exchange |

### O — Organizations (DESIGN §4.14, phase 9a)

| # | Threat | Mitigation |
|---|---|---|
| O1 | A forwarded or leaked invitation link lets someone else join | Accepting (and declining) needs an account that signs in with the invited address (tested); the token is stored only as an HMAC; 7 days; single use |
| O2 | Invitation emails as a phishing or spam channel: attacker-chosen organization names and many recipients | Names are plain words (no links, `www.`, domain-like endings, control or bidi characters); the email names the inviter's address and has only our link; 50 invitations per account per day, 100 open per organization; the owner can suspend or delete an organization |
| O3 | An admin takes over the organization | Only owners make or remove owners, rename or delete (tested); making an owner and deleting need a recent proof it's them (`changeCheck`, tested) |
| O4 | The organization loses its last owner (race, account deletion) | The owner count is checked inside the same SQL statement as the change (tested); account deletion passes ownership to the next admin or member, or deletes an empty organization (tested) |
| O5 | Enumeration of organizations or members | Every organization route answers 404 to non-members (tested); IDs are random (96 bits) |
| O6 | Stale memberships in services | Services read memberships live (`OrganizationDirectory`); tokens carry none. The `orgs` OIDC claim is read when the token is issued, so a removed member's next token drops it |
| O7 | Cross-site changes (CSRF) | Every change checks `Origin`/`Sec-Fetch-Site` (tested), as everywhere else (§7) |
| O8 | Sites link people through organization IDs | Only with the `organizations` scope, which the consent page names; IDs are the same for every site by design |

### S — Verified domains and SCIM (DESIGN §4.16, phase 9b)

| # | Threat | Mitigation |
|---|---|---|
| S1 | An organization provisions people it has no authority over (adds a stranger's account, learns whether an address has an account) | Only addresses at domains it proved with DNS (tested); accounts are never created; a domain is verified by one organization at a time (tested) |
| S2 | Account squatting: a directory claims an address before its owner signs up | Provisioning creates no account; the person links on their own sign-in |
| S3 | A stolen SCIM token | 256 bits, stored as SHA-256, scoped to one organization (tested), revocable at once; creating one needs an owner's recent proof; it can only add or remove members (role `member`), never owners or roles |
| S4 | A directory removes the last owner | Refused with `409` (tested); the owner count is checked in the same SQL statement |
| S5 | DNS spoofing during verification | DNS over HTTPS to Cloudflare's resolver over TLS; the record must hold a random value login issued |
| S6 | New HTTP methods widen the edge surface | PUT, PATCH and DELETE are allowed by the zone firewall on `/scim/v2/` only; everything else keeps GET, HEAD, POST, OPTIONS |
| S7 | Oversized or abusive requests | 64 KB bodies, 100 results a page, 50 operations per PATCH, the per-address limit |

### D — DPoP and pushed authorization requests (DESIGN §4.15, phase 9d)

| # | Threat | Mitigation |
|---|---|---|
| D1 | A stolen access token or refresh token is used elsewhere | Tokens from a request with a DPoP proof are bound to the key: a bound access token needs a fresh proof with `ath`, and a bound refresh token a proof from the same key. Presenting a refresh token without the key ends the grant (tested) |
| D2 | A captured proof is replayed | `jti` remembered for 2 minutes and accepted once; `iat` window of 60 s; `htm`/`htu` and, at resources, `ath` bind it to one request and one token (tested) |
| D3 | Weak or forged proofs | Asymmetric algorithms only (HMAC refused, tested); the key in the header must be public; `typ` must be `dpop+jwt` |
| D4 | A bound token used as a bearer token at a resource that doesn't check proofs | Access tokens are bound only for resources that check proofs; `validateToken` (the bearer path) refuses bound tokens (tested) |
| D5 | A pushed request is used by another client or tampered with in the browser | The reference is a 256-bit random value stored as an HMAC, tied to its client ID; every parameter comes from what was pushed and nothing from the URL (tested); unknown or expired references show an error page instead of redirecting |
| D6 | Pushed requests fill the database | The token endpoint's per-address limit, 8 KB per request, 10-minute expiry, daily clean-up |

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
| R7 | Library keeps the previous refresh token valid until the rotated one is used (retry safety). A stolen-and-raced refresh token may work once. | Accepted (library design); **mitigated** for clients that use DPoP (phase 9d): their refresh tokens need the key | Monitor via audit |
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
