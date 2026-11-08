# login.2earl.com — Design

Status: **Draft for review** · Owner: @FerhatDundar · Last updated: 2026-11-08

This document describes v1 of the 2earl identity service: an OAuth 2.1 authorization server at
`https://login.2earl.com` whose first protected resource is the 2earl MCP gateway. It is written
to be reviewed before any authentication code exists.

Companion documents: [THREAT_MODEL.md](THREAT_MODEL.md) · [DATA_PROTECTION.md](DATA_PROTECTION.md)

---

## 1. Scope

### In scope for v1

- OAuth 2.1 authorization server for 2earl-owned resources (first: the MCP gateway).
- Sign-in with Google as the only identity source.
- Users, linked identities, consent, grant revocation, account deletion.
- A minimal owner-only admin area.
- Compliance with the MCP authorization specification, revision **2026-07-28**.

### Explicitly out of scope for v1

| Not in v1 | Why | When |
|---|---|---|
| OpenID Connect provider (ID tokens, `userinfo`, JWKS, OIDC discovery) | The library does not provide it; building token signing ourselves adds risk before the core is hardened. "Sign in with 2earl" for third-party apps is not needed by the gateway. | Later phase, separate design |
| JWT access tokens | Opaque tokens validated over a Service Binding allow immediate revocation; there is no external resource server that needs offline validation. | Revisit with OIDC |
| Email/password, email or phone verification, other social logins | Not required now. The data model (§6) supports them without migration. | Later |
| Dynamic Client Registration (RFC 7591) | Deprecated by MCP 2026-07-28 in favour of Client ID Metadata Documents. | Only if a required client lacks CIMD |
| DPoP / sender-constrained tokens | Hardening step, not needed for launch. | Phase 5+ |

---

## 2. Decisions so far

| # | Decision | Source |
|---|---|---|
| D1 | Public repo `2earl/login`, AGPL-3.0 | Owner |
| D2 | Cloudflare Workers + D1 + KV; domain `2earl.com` already on Cloudflare | Owner |
| D3 | Build on `@cloudflare/workers-oauth-provider` **1.2.x** (`OAuthAuthorizationServer` / `OAuthResourceServer`), not a hand-written OAuth implementation | Agreed |
| D4 | Google is the only login method in v1 | Owner |
| D5 | No OIDC in v1; opaque access tokens | Owner, 2026-11-08 |
| D6 | Production only for now; no staging environment | Owner |
| D7 | Terraform state and runs in HCP Terraform, workspace `2earl-login-prod`, VCS-driven, manual apply | Owner |
| D8 | One Cloudflare account API token used by both Terraform (HCP) and deploys (GitHub) | Owner (accepted risk, see THREAT_MODEL R2) |
| D9 | Launch **locked**: only allowlisted Google accounts may sign in until phase 5 is complete | Confirmed (PR #1 merged) |
| D10 | Second factor in our own service, controlled by a feature flag: optional when off, enforced when on (§4.7) | Owner, 2026-11-08 |
| D11 | `/admin` always requires a second factor, regardless of the flag | Owner, 2026-11-08 |
| D12 | KV namespace in the EU jurisdiction too (supported by the Cloudflare provider, verified in phase 3) | Phase 3 |

---

## 3. Architecture

```
                         ┌──────────────────────────── Cloudflare ─────────────────────────────┐
                         │                                                                      │
 Browser / MCP client ──►│  login.2earl.com  ── Worker "login" (this repo)                      │
                         │     OAuthAuthorizationServer  (metadata, /authorize, /oauth/token,   │
                         │                                revocation, CIMD fetch)               │
                         │     App routes (login UI, Google callback, consent, account, admin)  │
                         │        │            │                     ▲                          │
                         │        ▼            ▼                     │ Service Binding (RPC)    │
                         │   D1 "login" (EU)  KV "OAUTH_KV" (EU)     │ validateToken()          │
                         │   users, identities, grants/tokens/       │                          │
                         │   sessions, audit  codes (hashed)         │                          │
                         │                                           │                          │
 MCP client ────────────►│  mcp.2earl.com  ── Worker "gateway" (separate repo, later)          │
                         │     OAuthResourceServer  (RFC 9728 metadata, 401/403 challenges)     │
                         └──────────────────────────────────────────────────────────────────────┘
                                    │ OIDC (we are the client)
                                    ▼
                           accounts.google.com
```

- **One Worker, `login`**, serves `login.2earl.com`. It is the authorization server and hosts the
  human-facing pages.
- **The gateway is a separate Worker** (other session). It validates tokens by calling the
  `login` Worker over a **Service Binding**, never over the public Internet and never by reading
  KV directly.
- **Google** is an upstream OpenID Provider. We are an OIDC *client* of Google; we do not expose
  OIDC ourselves.
- Hostname `mcp.2earl.com` for the gateway is an assumption; the resource registry (§5.3) is the
  single place to change it.

### Technology

- TypeScript (strict), pnpm, Wrangler, `@cloudflare/vitest-pool-workers` for tests on the
  Workers runtime.
- Routing: a small router (Hono) in front of `authorizationServer.fetch()`.
- Google ID-token verification: `jose` (JWKS fetch + `jwtVerify`).
- Server-rendered HTML with no client-side framework; no inline scripts.
- Dependencies kept minimal and pinned via the lockfile.

---

## 4. Flows

### 4.1 OAuth authorization (MCP client → login.2earl.com)

1. Client discovers us via the gateway's protected resource metadata (RFC 9728), then fetches
   `/.well-known/oauth-authorization-server` (RFC 8414).
2. Client identifies itself with a **Client ID Metadata Document** URL as `client_id`
   (or a pre-registered client ID).
3. Client sends `GET /authorize` with `response_type=code`, `code_challenge` (**S256 only**),
   `redirect_uri`, `state`, `scope`, and `resource` (RFC 8707, required).
4. `/authorize` handler:
   1. `parseAuthRequest()`; reject anything but `code_challenge_method=S256`.
   2. Reject a `resource` not in the registry.
   3. No valid session → store the parsed request in a short-lived login transaction and send
      the user through Google sign-in (§4.2), then resume.
   4. Signed in but not allowlisted (while locked) → access-denied page; nothing is sent to the
      client beyond `error=access_denied`.
   5. Consent needed → consent page (§4.3). Consent already remembered for this
      user + client + resource + scopes → skip.
5. `completeAuthorization()` issues the code; the redirect carries `code`, `state` and `iss`
   (RFC 9207, always on in the library).
6. Client exchanges the code at `POST /oauth/token` with the PKCE verifier and `resource`.
   It receives an opaque access token bound to that resource, plus a refresh token if allowed.

### 4.2 Google sign-in (login.2earl.com → Google)

1. Create a login transaction: random `state`, `nonce` and PKCE verifier. Store server-side in
   D1, keyed by a random ID in a `__Host-login_tx` cookie (HttpOnly, Secure, SameSite=Lax,
   10-minute lifetime).
2. Redirect to Google with `scope=openid email profile`, `response_type=code`, `state`, `nonce`,
   `code_challenge` (S256), and `prompt=select_account`.
3. `GET /callback/google`:
   1. Match `state` to the transaction (one-time use); exchange the code with the client secret
      and PKCE verifier.
   2. Verify the ID token with Google's JWKS:
      - `iss` ∈ {`https://accounts.google.com`, `accounts.google.com`}
      - `aud` = our client ID
      - `exp`/`iat` within 60 s skew
      - `nonce` matches
      - `email_verified` = true
4. Find the user **by `(provider='google', subject=sub)`**, never by email. If none exists:
   - Locked mode: allow only if `sub` or email is on the allowlist.
   - Open mode: create user + identity.
5. **Rotate the session**: delete any pre-existing session cookie, create a new session, set
   `__Host-session`.
6. Discard Google's access token immediately; we do not call Google APIs in v1. Store no Google
   refresh token.

### 4.3 Consent

- Uses the library's `beginConsent()` / `approveConsent()`. These bind the form handle to this
  browser via a cookie, make it single-use, and set anti-framing headers.
- The page shows:
  - the client's `client_name`;
  - the **host of its `client_id` URL** (for CIMD clients) and the host of the redirect URI;
  - the target resource;
  - each requested scope in plain language.
- CIMD clients are labelled "not verified by 2earl" unless the owner has marked them trusted.
- The user may approve fewer scopes than requested.
- "Remember" stores the approval in the library's signed cookie, scoped to user + client.
- Any new scope re-prompts.

### 4.4 Token validation (gateway → login, via Service Binding)

- The gateway's `OAuthResourceServer.validateToken` calls the `login` Worker's RPC entrypoint.
- That entrypoint returns `{ props: { uid }, audience, scope, expiresAt }`.
- The gateway enforces `audience === its resource URL` and per-tool scopes. It returns
  `insufficientScope()` for step-up.

### 4.5 Account page

`/account` provides:
- Connected apps: grants listed per client, with revoke.
- Delete account: re-authentication with Google required, then a hard delete (§6.3).
- Export my data: JSON download.

### 4.6 Admin

- `/admin` is available only to the user whose Google `sub` equals `OWNER_GOOGLE_SUB` (secret).
- It provides:
  - allowlist management;
  - user list, with suspend and delete;
  - pre-registered clients;
  - marking CIMD clients as trusted;
  - audit log view.
- Every admin action is audited.

### 4.7 Second factor (MFA), behind a feature flag

Google sign-in proves the Google account. A second factor proves the person at login.2earl.com
too, independent of how the Google account is protected. Google's ID token does not reliably say
whether the user passed 2-step verification, so we cannot rely on Google for this.

- **Factors:**
  - **Passkeys / security keys (WebAuthn)**: primary, phishing-resistant.
  - **TOTP** (authenticator app): fallback.
  - **Recovery codes**: 10 single-use codes, shown once, stored hashed.
- **Feature flag `MFA_REQUIRED`** (Worker variable, default `false`):

  | Flag | User has no factor | User has a factor |
  |---|---|---|
  | `false` | Signs in with Google only; may enrol in `/account/security` | Challenged after Google on every new session |
  | `true` | Must enrol before the session is usable: no consent, no account changes | Challenged after Google on every new session |

  - A user who has enrolled is **always** challenged, whatever the flag. Turning the flag off
    never downgrades an enrolled account.
  - **Admin (D11):** `/admin` always requires a second factor, independent of the flag. The owner
    must enrol before `/admin` opens; an owner session at `aal1` is treated as a normal user
    session. `MFA_REQUIRED` only governs ordinary users.
- **Where the challenge sits:** after the Google callback and before the session is marked
  `aal2`. Consent, account changes and admin actions require `aal2` when MFA applies to that user.
- **Changing factors:** adding or removing a factor requires a fresh second-factor challenge
  (≤ 5 min old). Removing the last factor is refused while the flag is on.
- **Lost factors:** recovery code; otherwise the owner resets MFA for the user from `/admin`,
  audited.
- **Phase:** built after the MVP, in phase 5 (§12). The flag ships `false`.

---

## 5. Protocol surface

### 5.1 Endpoints

| Path | Owner | Purpose |
|---|---|---|
| `/.well-known/oauth-authorization-server` | library | RFC 8414 metadata |
| `/authorize` | app + library | Authorization endpoint (GET) |
| `/oauth/token` | library | Token endpoint: `authorization_code`, `refresh_token` |
| revocation endpoint (as advertised) | library | RFC 7009 |
| `/login`, `/callback/google`, `/logout` | app | Google sign-in, session |
| `/consent` | app + library | Consent form POST |
| `/account`, `/account/apps`, `/account/delete`, `/account/export` | app | Self-service |
| `/account/security`, `/mfa/challenge` | app | Second factor enrolment and challenge (§4.7) |
| `/admin/*` | app | Owner-only |
| `/privacy`, `/imprint`, `/terms` | app | Legal pages (DATA_PROTECTION.md) |

There is **no registration endpoint** (`clientRegistrationEndpoint` unset).

### 5.2 Library configuration (v1)

| Option | Value | Reason |
|---|---|---|
| `issuer` | `https://login.2earl.com` | Canonical; exact match by clients |
| `resources` | registry (§5.3) | Audience binding (RFC 8707) |
| `clientIdMetadataDocumentEnabled` | `true` | MCP 2026-07-28 default registration |
| compatibility flag | `global_fetch_strictly_public` | Required for CIMD; SSRF protection on metadata fetches |
| `clientRegistrationEndpoint` | unset | DCR off |
| `accessTokenTTL` | **900 s** | Bounds a stolen token and the gap in client-deletion revocation |
| `refreshTokenTTL` | 30 days | Grant lifetime at issue |
| `refreshTokenIdleTTL` | 7 days | Unused grants expire |
| absolute grant cap | 90 days | Enforced in `tokenExchangeCallback`: `authTime` stored in props |
| `scopesSupported` | §5.4 | |
| `allowPrivateUseRedirectUris` | `false` | Enable per client later if native apps need it |

### 5.3 Resource registry

| Resource (audience) | Server | Required scopes |
|---|---|---|
| `https://mcp.2earl.com/mcp` | MCP gateway | `mcp:tools.read` |

### 5.4 Scopes (draft, finalised in the gateway session)

| Scope | Meaning | Grantable to |
|---|---|---|
| `mcp:tools.read` | List tools and resources on the gateway | any client |
| `mcp:tools.invoke` | Call tools | any client |
| `admin` | Administer the identity service | owner's first-party sessions only; never to OAuth clients |

Scopes are opaque strings to `login`; their enforcement lives in the resource server.

---

## 6. Data model

### 6.1 D1 (jurisdiction `eu`, fixed at creation)

```
users            id (ulid PK), status (active|suspended), created_at, updated_at,
                 display_name, primary_email, deleted_at NULL
identities       id PK, user_id FK, provider ('google'), subject (provider's stable ID),
                 email, email_verified, created_at, last_login_at
                 UNIQUE(provider, subject)
sessions         id_hash PK (HMAC-SHA-256 of cookie value, SESSION_PEPPER), user_id FK,
                 aal ('aal1'|'aal2'), aal2_at NULL, created_at, last_seen_at, expires_at,
                 ip_prefix, user_agent_hash
login_tx         id_hash PK, state, nonce, pkce_verifier, auth_request (JSON), expires_at
mfa_factors      id PK, user_id FK, kind ('webauthn'|'totp'), label, created_at, last_used_at,
                 webauthn_credential_id UNIQUE NULL, webauthn_public_key NULL,
                 webauthn_sign_count NULL, totp_secret_enc NULL (AES-GCM, MFA_ENCRYPTION_KEY),
                 totp_last_step NULL (blocks code reuse)
recovery_codes   id PK, user_id FK, code_hash, used_at NULL
allowlist        id PK, kind ('google_sub'|'email'), value, added_by, created_at
trusted_clients  client_id PK, note, created_at
audit_events     id PK, at, actor_user_id NULL, event, client_id NULL, ip_prefix, detail (JSON)
```

- `identities` is what allows email/phone and other social logins to be added later. Each is
  another provider row.
- **No automatic account linking by email.** Linking a second identity requires being signed in to
  both.
- IP addresses are stored only as a truncated prefix (/24 IPv4, /48 IPv6).

### 6.2 KV `OAUTH_KV` (library-owned)

- Holds clients, grants, codes and tokens in the library's schema. Tokens, codes and secrets are
  stored **only as hashes**, and `props` are **encrypted with a key only the token holder can
  unwrap** (library documentation).
- The namespace is created in the **EU jurisdiction** (D12). `props` still contain only
  `{ uid, authTime }`: no email, no name. Minimal props limit what any single store holds.

### 6.3 Deletion

Account deletion does all of the following in one operation:
- revokes all of the user's grants (`listUserGrants` → `revokeGrant`);
- deletes sessions, identities and the user row;
- writes an audit event without personal data (`user.deleted`, with a random correlation ID).

Library maintenance (`purgeExpiredData()`) runs on a daily Cron Trigger.

---

## 7. Sessions and web security

- **Session cookie:** `__Host-session`
  - random 256-bit value; HttpOnly, Secure, SameSite=Lax, Path=/
  - 12 h idle, 7 days absolute
  - only the hash is stored
  - logout and account deletion revoke it server-side
- **CSRF**
  - Consent: the library's bound single-use handle.
  - Other POSTs (account, admin): a per-session synchronizer token, plus `Origin` header check.
- **Response headers on every response:**
  - `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`
    - Exception: the **consent page** omits `form-action`. Some browsers apply `form-action` to
      the redirect that follows a form submission, and approving consent redirects to the
      client's (arbitrary) redirect URI. That redirect target is already restricted by exact
      redirect-URI matching.
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
  - `Referrer-Policy: no-referrer` (codes and state never leak via Referer)
  - `X-Content-Type-Options: nosniff`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cache-Control: no-store` on all authenticated and OAuth responses
- **Output encoding:** all client-supplied strings (`client_name`, URIs) are HTML-escaped. Logos
  from CIMD documents are **not** rendered in v1.
- **Logging:** never log tokens, codes, cookies, `Authorization` headers or full query strings
  of `/authorize` and `/callback/*`.

---

## 8. Abuse controls

- Workers Rate Limiting binding, keyed by IP prefix:
  - `/authorize`, `/callback/google` — 30/min
  - `/oauth/token` — 60/min per client_id + IP prefix
  - `/admin` — 30/min
- Cloudflare WAF custom rules (Terraform):
  - block non-HTTPS;
  - restrict methods per path;
  - challenge on high-risk bot score for `/login` only (never on `/oauth/token`, which machines
    call).
- CIMD fetch limits come from the library: 5 KB, 10 s, HTTPS-only, no private addresses.

---

## 9. Infrastructure

### 9.1 Ownership split

| Managed by | Resources |
|---|---|
| **Terraform** (`infra/`, HCP workspace `2earl-login-prod`) | Zone settings (TLS ≥ 1.2, TLS 1.3, strict SSL, always HTTPS, 0-RTT off, HSTS), DNSSEC, D1 database and KV namespace (both jurisdiction `eu`, `prevent_destroy`), WAF custom rule, rate-limit rule, Worker custom domain |
| **Wrangler** (GitHub deploy) | Worker script, Worker secrets, D1 migrations, Cron Trigger |

No resource is managed by both. The zone itself is **read** through a data source, never
managed, so no Terraform change can delete it. The custom domain creates the `login` DNS record
and certificate, so there is no separate DNS resource. The Worker script must exist before the
custom domain is applied; the first deploy created it.

Zone-wide effects to be aware of: HSTS with `includeSubDomains` (1 year) and strict SSL apply to
every hostname in 2earl.com, not only `login`. The edge rules are written for the Free plan; the
fine-grained limits are in the Worker (§8).

### 9.2 HCP Terraform

- VCS-driven from this repo; working directory `infra`; trigger pattern `infra/**`.
- Execution mode Remote; **manual apply**.
- Speculative plans run only for PRs from branches in this repo. HCP does not run them for forks.
- `CLOUDFLARE_API_TOKEN` is a sensitive environment variable in the workspace.

### 9.3 Worker secrets and variables

| Name | Kind | Set by |
|---|---|---|
| `GOOGLE_CLIENT_ID` | var | deploy (from GitHub env variable) |
| `GOOGLE_CLIENT_SECRET` | secret | deploy (from GitHub env secret) |
| `OWNER_GOOGLE_SUB` | secret | owner, once |
| `CONSENT_REMEMBER_SECRET` | secret | owner, generated locally |
| `SESSION_PEPPER` | secret | owner, generated locally (HMAC for session/tx ID hashing) |
| `MFA_ENCRYPTION_KEY` | secret | owner, generated locally (encrypts TOTP secrets; phase 5) |
| `MFA_REQUIRED` | var | `wrangler.jsonc`, default `"false"` (§4.7) |
| `LEGAL_CONTROLLER_NAME`, `LEGAL_CONTACT_EMAIL`, `LEGAL_POSTAL_ADDRESS` | var | deploy (from GitHub env variables); rendered on `/imprint` and `/privacy`, kept out of the repo |

---

## 10. CI/CD

| Workflow | Trigger | Does |
|---|---|---|
| `ci.yml` | PR, push to `main` | job `verify`: install (frozen lockfile), typecheck (including `wrangler types --check`), lint + format, tests on the Workers runtime, bundle (dry-run deploy), `pnpm audit`. **Required check** on `main`. |
| CodeQL | PR, push, weekly | GitHub default setup (no workflow file) |
| `deploy.yml` | push to `main` (except `docs/`, `infra/`, Markdown), manual | environment `production` (**owner approval**) → tests → `wrangler d1 migrations apply DB --remote` → `wrangler deploy` → smoke test of `/healthz` (the metadata endpoint once it exists). Migrations must stay compatible with the code already live. |
| Dependabot | weekly | npm and GitHub Actions updates, grouped, 1-day cooldown (matches pnpm `minimumReleaseAge`) |

- Default `GITHUB_TOKEN` permissions are read-only; jobs request only what they need.
- All actions are pinned by SHA (enforced by repo setting) and limited to the allow-list.
- No `pull_request_target`; outside contributors' workflows need approval.
- Checkout never persists credentials.
- pnpm runs install scripts only for `esbuild` and `workerd`, and never installs a version
  published less than 24 hours ago (`minimumReleaseAge`).
- Terraform is not run from GitHub Actions (HCP is VCS-driven). `TF_API_TOKEN` was removed from
  GitHub on 2026-11-08.

### Protocol tests (must pass before unlock)

- PKCE: missing, `plain` or wrong verifier → rejected.
- Redirect URI: exact match; extra path, query or port → rejected. Loopback port flexibility
  only for loopback.
- `resource` missing, unknown, or different at the token endpoint → rejected. Token audience =
  requested resource.
- `iss` present on success and error redirects; metadata `issuer` exact.
- Authorization code single use; reuse revokes the grant.
- Refresh rotation; revoked grant → refresh and access both fail.
- CIMD: `client_id` mismatch, oversize, non-HTTPS, private IP, `javascript:` redirect → rejected.
- Consent handle: replay, cross-browser, missing → rejected; page not frameable.
- Google callback: bad `state`, bad `nonce`, wrong `aud`, `email_verified=false` → rejected.
- Locked mode: non-allowlisted user cannot obtain a code.
- MFA (phase 5): enrolled user is challenged with the flag off; unenrolled user cannot consent with
  the flag on; TOTP code reuse and recovery-code reuse rejected; WebAuthn origin and RP ID checked.

---

## 11. Open questions

1. **Sign-up policy after unlock.** Proposal: any Google account may create an account; no
   privileged scopes; owner-only `admin`. The allowlist stays as a kill switch.
2. **Gateway hostname** — `mcp.2earl.com`?
3. **Legal pages** — postal address still to come (DATA_PROTECTION.md §8). Name and contact email
   are set as environment variables, not in the repo.

Resolved:
- Cloudflare account ID is set as the `production` environment variable `CLOUDFLARE_ACCOUNT_ID`.
- Admin second factor is mandatory (D11).

---

## 12. Phases

| Phase | Deliverable |
|---|---|
| 1 | Design, threat model, data protection (PR #1, merged) |
| 2 | Scaffold, `ci.yml`, `deploy.yml`, Dependabot, CodeQL; required checks; rotate credentials exposed during setup |
| 3 | `infra/`: zone settings, DNSSEC, D1 (EU), KV (EU), custom domain, WAF, rate limits |
| 4 | MVP deployed **locked**: Google sign-in, authorization, token, CIMD, consent, revocation, account deletion, legal pages |
| 5 | Protocol test suite complete, audit log, purge cron, **second factor behind `MFA_REQUIRED`** (§4.7); optional OpenID conformance tests for the Google client side → **unlock** |
| 6 | `GATEWAY_INTEGRATION.md`: handoff to the gateway session |

## References

- MCP Authorization, revision 2026-07-28
- OAuth 2.1 (draft-ietf-oauth-v2-1), RFC 9700 (OAuth 2.0 Security BCP)
- RFC 8414, RFC 8707, RFC 9207, RFC 9728, RFC 7009, RFC 7636, RFC 8252
- draft-ietf-oauth-client-id-metadata-document-00
- `@cloudflare/workers-oauth-provider` 1.2.4 documentation
