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
| D4 | Google is the only login method in v1. **Superseded** 2026-11-10: Google or a one-time code by email (§4.9) | Owner |
| D5 | No OIDC in v1; opaque access tokens | Owner, 2026-11-08 |
| D6 | Production only for now; no staging environment | Owner |
| D7 | Terraform state and runs in HCP Terraform, workspace `2earl-login-prod`, VCS-driven, manual apply | Owner |
| D8 | One Cloudflare account API token used by both Terraform (HCP) and deploys (GitHub) | Owner (accepted risk, see THREAT_MODEL R2) |
| D9 | Launch **locked**: only allowlisted Google accounts may sign in until phase 5 is complete. **Opened** 2026-11-10 (§4.9): sign-up is open by default; the owner can close it on `/admin/invitations` without a deploy | Confirmed (PR #1 merged); owner, 2026-11-10 |
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
   - Locked mode (`LOGIN_LOCKED`, default `"true"`): allow only if the `sub` or the email is on
     the allowlist, checked **before** any account is created. An email entry is replaced by a
     `google_sub` entry on the first successful sign-in, so a different Google account that later
     gets the same address is not admitted.
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

- The `login` Worker's default export is a `WorkerEntrypoint` (`src/index.ts`) with an RPC
  method `validateToken(resource, token)`. It is reachable only through a Service Binding, never
  over HTTP.
- The gateway binds it and hands it to `OAuthResourceServer`:

  ```jsonc
  // gateway wrangler.jsonc
  { "services": [{ "binding": "AUTH_SERVER", "service": "login" }] }
  ```

  ```ts
  validateToken: (env) => env.AUTH_SERVER.validateToken,
  ```

- It returns `{ props: { uid, authTime }, audience, expiresAt, scope, userId, clientId }` or
  `null`. A resource other than `MCP_RESOURCE` is rejected.
- The gateway enforces per-tool scopes and returns `insufficientScope()` for step-up. It never
  forwards the token upstream.
- Revocation takes effect at once where it was made and within about a minute elsewhere: grants
  and tokens live in Workers KV, which is eventually consistent ("up to 60 seconds or more").
  Access tokens expire after 15 minutes regardless.
- A resource login doesn't serve makes `validateToken` throw (the gateway answers `503`), not
  return `null`. The full contract, constraints and open decisions for the gateway:
  [GATEWAY_INTEGRATION.md](GATEWAY_INTEGRATION.md).

### 4.5 Account page

`/account` provides:
- Connected apps: grants listed per client, with revoke.
- Export my data (`/account/export`): a JSON download of the account, sign-in methods, sessions,
  connected apps, invitation and the user's security log. Hashes of cookies and tokens are not
  included.
- Delete account (`/account/delete`): a confirmation page that lists what is deleted and what is
  kept, a required checkbox, then a round trip to Google (`prompt=select_account`, `login_hint`)
  with its own sign-in transaction (`purpose = 'delete_account'`, bound to the user). The callback
  deletes only if the browser still holds that user's session **and** Google returns the subject
  linked to the account; it never creates a session. Then a hard delete (§6.3).
  - **Limit:** Google does not support forced re-authentication ("Google does not support Google
    Account reauth requests"), and `auth_time` is only returned to published, verified apps with
    the security bundle enabled. The round trip therefore proves the browser holds the linked Google
    session, not that the person re-entered a password. It stops a stolen `login.2earl.com` session
    cookie on its own; it does not stop someone at an unlocked computer. Phase 5 adds: if the user
    has a second factor, deletion requires it (THREAT_MODEL R9).

### 4.6 Admin

- `/admin` is available only to the user whose Google `sub` equals `OWNER_GOOGLE_SUB` (secret).
- It provides:
  - allowlist management;
  - user list, with suspend and delete;
  - pre-registered clients;
  - marking CIMD clients as trusted;
  - audit log view.
- Every admin action is audited.

**Implementation (phase 5b, `src/admin.ts`):**
- Access: signed in, Google `sub` = `OWNER_GOOGLE_SUB`, a second factor enrolled and the session at
  `aal2`. Anyone else gets the ordinary 404 page, so `/admin` doesn't reveal that it exists.
- Changes (all POST): same-origin check, the `admin` rate-limit key, and a second-factor proof from
  the last 15 minutes (otherwise `/mfa?step_up=1`).
- Users: suspend (status `suspended`, sessions deleted, grants revoked; sign-in is refused
  while suspended), reactivate, reset second factor (factors, recovery codes and lockout cleared,
  sessions ended), delete (same path as self-deletion, §6.3; needs a confirmation box). The owner's
  own account can't be changed here.
- Invitations: add by email (stored in lower case; matching is case-insensitive), withdraw. The
  owner's own invitation can't be withdrawn.
- Apps: mark a client ID as verified (it must resolve: registered, or a fetchable CIMD document);
  register a public client (PKCE, no secret; redirect URIs https or http on loopback, 1–10);
  delete a registered client.
- Security log: latest 200 events, filtered by a fixed list of event prefixes.

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
- **Phase:** built in phase 5 (§12). The flag ships `false`.

**Implementation (phase 5a):**
- Passkeys: `@simplewebauthn/server`, RP ID `login.2earl.com`, attestation `none`, user
  verification preferred (a security key without a PIN still counts: it is the *second* factor).
  The browser side is `public/passkey.js`, the only script in the service, loaded only on
  `/account/security` and `/mfa` under `MFA_CSP` (`script-src 'self'; connect-src 'self'`).
- Authenticator app: RFC 6238 (SHA-1, 6 digits, 30 s, ±1 step), `src/totp.ts`. The secret is
  encrypted with AES-256-GCM under a key derived from `MFA_ENCRYPTION_KEY`, bound to the user ID.
  The last accepted step is stored and the update is conditional, so a code works once even under
  concurrent requests.
- Recovery codes: 10 × 50-bit codes (`xxxxx-xxxxx`, Crockford base32), stored as
  HMAC-SHA-256 under `MFA_ENCRYPTION_KEY`, bound to the user. Shown once: the plaintext lives
  encrypted in `mfa_pending` until the page that shows it is opened.
- Gate: a middleware sends a session that must pass the challenge to `/mfa`, and one that must
  enrol (flag on, no factor) to `/account/security`; other non-GET requests get 403. Export and
  deletion stay reachable without a factor (GDPR).
- Changes: with a factor, adding, removing or regenerating needs `aal2` from the last 5 minutes;
  the first factor needs a Google sign-in from the last 10 minutes (`/login?reauth=1` otherwise),
  so a stolen session cookie can't attach the thief's factor later. Deletion needs a fresh
  second factor too, when the user has one (THREAT_MODEL R9).
- Lockout: 5 wrong answers in a row lock the user's second-factor step for 15 minutes
  (`users.mfa_failed_attempts`, `mfa_locked_until`), on top of the per-network rate limit. This
  caps guessing a 6-digit code at 480 attempts a day (about 1 in 700 per day, with 3 valid codes
  per attempt).

---

### 4.8 Services: per-service permissions and account deletion

Decided by the owner on 2026-11-09:
- each service has its own permission set;
- deleting an account must delete the user's data in every 2earl service.

- **Registry (`src/services.ts`):** each service that accepts tokens declares:
  - `id`, which is also its scope prefix;
  - a display name;
  - its canonical resource URL;
  - its scopes with consent wording;
  - the Service Binding that receives deletion notices.

  The authorization server registers every service's resource. `validateToken` accepts only those.
- **Per-service permissions:** `/authorize` resolves the service from `resource` and offers only
  that service's scopes. The consent page carries the offered scopes, HMAC-signed and bound to the
  single-use consent handle. `POST /authorize` grants only scopes that were offered **and** ticked.
  This is needed because the library accepts any supported scope from the form.
- **Deletion notices (`deletion_notices`, migration 0005):** `deleteAccount` writes one row per
  service in the same D1 batch as the deletion (an outbox). `deliverDeletionNotices` calls each
  service's `AccountEvents.deleteUser(userId)` over its binding and deletes the row when the call
  returns. It runs:
  - right after a deletion (`waitUntil`);
  - every 15 minutes (cron).

  Failures are retried, counted and shown in `/admin`. A service without a binding yet keeps its
  notices until it has one. `user.deletion_delivered` is audited, naming the service only.
- **Adding a service:** a registry entry, then (once deployed) its binding in `wrangler.jsonc`
  (docs/GATEWAY_INTEGRATION.md §5).
- **Looking an account up by email (Prompt share only).** Decided by the owner on 2026-11-09, so
  a prompt can be shared with someone by their address (Prompt share DESIGN §4.1). The named
  entrypoint `PromptshareDirectory` (`src/directory.ts`) has one method, `uidForEmail(email)`:
  - it returns the user ID of the one **active** account with that **Google-verified** address;
  - it returns nothing for an unknown, unverified, suspended or ambiguous address;
  - it never returns the address itself, a name or anything else.

  Only Prompt share's `wrangler.jsonc` binds it. Prompt share limits how often an author may
  try addresses that have no account, because the answer shows whether an address has one.

### 4.9 Open sign-up and sign-in with an email code (phase 7)

Decided by the owner on 2026-11-10: sign-up opens, with email verification, now that Cloudflare
Email Service sends from `2earl.com` (Workers Paid).

**Sign-in page (`/login`).** "Continue with Google" (`/login/google`) or an email address. The same
page signs in and signs up. With `reauth=1` a signed-in user confirms it's them with the methods
their account has.

**Email code (`src/email-codes.ts`, `src/email-routes.ts`).**
1. `POST /login/email`: the address is normalised (trimmed, lower case). The answer is the same
   whether or not it has an account: a code is sent either way.
2. A 6-digit code (uniform, rejection sampling) and a 32-byte link token are created. Only HMACs
   are stored (`email_codes`, keyed by the HMAC of the `__Host-email_code` cookie, which binds the
   code to this browser). 10 minutes, 5 wrong tries, single use (`used_at` set in one statement).
3. The email (`src/mail.ts`, plain text plus the same lines as minimal HTML with no images or remote
   content, from `noreply@2earl.com`, replies to `legal@2earl.com`) has the code and a link. The
   link opens a page with a button: mail scanners open links, and only the POST signs in. The link
   works only in the browser that asked; elsewhere the page says to type the code instead.
4. On success: the account with this email method, or a new one. A new one needs sign-up to be
   open, or an invitation naming the address (`allowlist` kind `email`). New accounts go to
   `/welcome` (a name; a nudge to add a second factor) before `return_to`.
5. **Send limits** (counted in `email_codes`, kept 2 days): 5 per address per hour and 10 a day, 20
   per network (/24, /48) per hour, 2,000 a day for the service. Plus `AUTH_RATE_LIMITER` and the
   zone rule on the paths.

**One account per address.** Accounts are never joined by address (THREAT_MODEL B3). An email
sign-in with an address that a Google account already uses is refused and pointed to Google; a new
Google sign-in with an address that already signs in by email is refused and pointed to email.
Joining happens only while signed in to both:

**Sign-in methods on `/account`.** "Add Google" (a trip to Google with `login_tx.purpose =
'link_google'`, bound to the session) and "Add an email address" (a code with purpose
`link_email`). Whether another account has the address is told only after the code proves it's
the user's. A method can be removed if another remains; the owner's Google account (`OWNER_GOOGLE_SUB`)
can't be. Adding or removing needs a recent proof, as for second factors (`changeCheck`: a second
factor in the last 5 minutes, or a sign-in in the last 10). Removing the method that carried the
account's address moves it to a remaining one.

**Deletion and re-authentication.** An account that signs in by email confirms deletion with a code
sent to that address (purpose `delete_account`, bound to the session and the account), instead of
Google. Accounts with both choose.

**Profile.** The name is the user's (`/account/name`, `/welcome`); Google's name fills in only a
missing one. The account's address follows Google only when the account has no email method.

**Security notices by email** (`notify`, sent after the response): a sign-in method or second
factor added or removed, new recovery codes, the first approval of an app, and the account's
deletion (to the address it had). Nothing marketing; nothing else.

**Sign-up switch.** `settings.signup` (`open` | `invite`) on `/admin/invitations`, audited as
`admin.signup_changed`. Without a saved setting, `LOGIN_LOCKED` decides (`"false"` = open, the
default from this phase). Closing sign-up stops new accounts only; existing ones keep working.

### 4.10 Sign in with a passkey, and signed-in devices (phase 8a)

**Passkey sign-in.** A passkey added under Security is also a way to sign in on its own:

1. The sign-in page asks `/login/passkey/options` for a challenge.
   - `userVerification: required`.
   - No `allowCredentials`, so the browser offers the passkeys it has for `login.2earl.com`.
   - The challenge is kept 5 minutes, keyed by the HMAC of the `__Host-passkey_tx` cookie, which
     binds it to this browser.
2. The person picks one of two ways:
   - **Autofill:** the email field has `autocomplete="email webauthn"`, so the browser lists
     passkeys among its suggestions (WebAuthn conditional mediation).
   - **Button:** "Sign in with a passkey".
3. `/login/passkey` checks the assertion against the stored public key:
   - origin and RP ID must match;
   - user verification is required;
   - the signature counter is checked;
   - the challenge is used once.

   The account is the one that owns the credential. A credential no account has is refused, with a
   pointer to sign in another way and add it.
4. The session starts at **`aal2`**. A passkey with user verification is phishing-resistant and
   two factors in one gesture (possession, plus biometric or PIN), so no second step follows.
   `method = 'passkey'`.
5. **Confirming it's you** (`/login?reauth=1`) offers the passkey too. The challenge then names the
   signed-in account (`user_id`), and only that account's passkeys are accepted.

There is no new credential type. A passkey is still one `mfa_factors` row, used both for the
second step (§4.7) and for signing in. Passkeys created before this phase used
`residentKey: preferred`; the ones the authenticator stored as discoverable work for sign-in, the
others stay second-factor-only, which the browser handles by not offering them.

**Signed-in devices** (`/account/sessions`):
- Every active session of the account, with:
  - a coarse device name (`src/devices.ts`, e.g. "Safari on iPhone", never the user agent);
  - when it was last active and when and how it signed in.
- Signing out works on one device or on all others; this browser stays signed in. Both actions
  are audited (`session.ended`).
- Sessions are named in the form by an HMAC reference, never by their key.
- Signing a device out doesn't disconnect apps: grants are separate (§4.3), and the page says so.

### 4.11 OpenID Connect provider: "Sign in with 2earl" (phase 8b)

Any site or app can sign people in with their 2earl account, with the standard OpenID Connect
authorization code flow (with PKCE). Discovery is at `/.well-known/openid-configuration`.

**Request.**
- `scope=openid`, optionally `profile` (the name) and `email` (the address, always verified).
- `openid` can't be combined with a 2earl service's scopes. The token is for the account's
  UserInfo endpoint (`${ISSUER}/userinfo`), which is the library's `defaultResource`, so an
  OpenID Connect client may leave out `resource`. Every other request must still name its
  resource (RFC 8707, MCP).
- `nonce` (1–255 characters) is carried through the consent form, bound to the single-use consent
  handle by an HMAC, like the offered scopes.
- `prompt`:
  - `none` answers `login_required`, `consent_required` or `interaction_required` instead of
    showing a page;
  - `login` signs the person in again first;
  - `consent` shows the consent page even when consent is remembered.
- `max_age`: a sign-in older than this is redone. The request then comes back without `login`
  and `max_age`, so it doesn't ask twice.
- `acr_values=urn:2earl:aal2` works as before (§4.7).

**Consent.** `openid` is shown ticked and can't be unticked: signing in is what the app is for.
The name and the address can be refused.

**ID token** (`id_token` beside the access token, from the code exchange and from each refresh):
- ES256, signed with the Worker secret `OIDC_SIGNING_KEY`, a private P-256 JWK made by
  `pnpm oidc:key`.
- `kid` is the key's RFC 7638 thumbprint.
- Lifetime 10 minutes.
- Claims:

| Claim | Value |
|---|---|
| `iss`, `aud`, `azp` | The issuer; the client |
| `sub` | **Pairwise**: a random ID per account and sector, stored in `oidc_subjects`, never derived from a secret, so no key rotation can change it |
| `auth_time` | When the approving session signed in |
| `acr` | `urn:2earl:aal2` if a second factor or passkey was verified, else `urn:2earl:aal1` |
| `amr` (RFC 8176) | `fed` for Google, `otp` for an email code, `pop user` for a passkey, plus `mfa` at aal2 |
| `at_hash` | Of the access token it came with |
| `nonce` | Only in the ID token from the code exchange |
| `name`, `updated_at` | With `profile` |
| `email`, `email_verified` | With `email` |

The sector is the host of the redirect URI. Apps on the person's own device (loopback redirects)
are each their own sector, by client ID.

**UserInfo** (`GET`/`POST /userinfo`):
- Bearer token bound to the UserInfo resource, with `openid`; tokens for any other resource are
  refused.
- Answers `sub` and the claims of the granted scopes, read now (a changed name shows at once).
- CORS for bearer requests, no cookies; limited like the token endpoint.

**Keys** (`/.well-known/jwks.json`): the current public key, plus `OIDC_NEXT_PUBLIC_KEY` when a
rotation is announced. To rotate:
1. Make a new key.
2. Publish its public half as `OIDC_NEXT_PUBLIC_KEY` (`pnpm oidc:key --public < key.json`).
3. Wait at least a day, so relying parties' caches pick it up.
4. Swap `OIDC_SIGNING_KEY` and clear `OIDC_NEXT_PUBLIC_KEY`.

ID tokens signed with the old key expire within 10 minutes.

**RP-Initiated Logout 1.0** (`/oidc/logout`):
1. The app names itself by `client_id` or by an `id_token_hint` signed by us. Expired hints are
   accepted, as the spec allows.
2. The person confirms "Sign out of 2earl?". Without that step, a link on any site could sign
   people out.
3. The browser returns to `post_logout_redirect_uri` with `state`, but only to an address the app
   registered as a redirect URI. login keeps no separate list of logout addresses, and
   client metadata documents have no field for one. Any other address gets the signed-out page.

**Not included:**
- implicit and hybrid flows (`response_type` other than `code`);
- the `claims` request parameter and request objects;
- front- and back-channel logout;
- dynamic registration.

Apps register through a client metadata document or `/admin/apps`.

### 4.12 Token introspection and step-up (phase 8c)

**Introspection** (RFC 7662, `POST /oauth/introspect`) is for a resource server that can't use a
Service Binding: a 2earl service outside Cloudflare, or a partner. The gateway keeps the binding.

**Credentials.**
- The owner creates them in `/admin/apps → Resource servers`: a name, and the one resource
  (from `allResources`) the server may check tokens for.
- The secret is 256 random bits, shown once. Only its SHA-256 is stored (`resource_servers`).
- Revoking deletes the row.

**Request.**
- HTTP Basic (`client_secret_basic`), form parameter `token`.
- Limited per address like the token endpoint.

**Answer** (`Cache-Control: no-store`):
- An access token for the server's own resource:

  | Field | Value |
  |---|---|
  | `active` | `true` |
  | `token_type` | `Bearer` |
  | `scope`, `client_id`, `aud`, `iss`, `exp` | From the grant and token |
  | `sub` | The internal account ID, as the gateway gets it |
  | `auth_time`, `acr`, `amr` | When and how the person signed in (RFC 9470, RFC 8176) |

- Everything else is `{"active": false}`: a token for another resource, a refresh token, a revoked
  or unknown token. A resource server can't learn about tokens that aren't its own, not even
  whether they exist.
- Wrong credentials: `401` with a Basic challenge.

**Step-up** (RFC 9470). Resource servers decide when a token isn't enough, and say so with:

```
WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="…", max_age=N
```

(GATEWAY_INTEGRATION.md has the gateway's version.) login's side:
- `acr_values=urn:2earl:aal2` and `max_age` work for every authorization request, not only
  OpenID Connect: a sign-in older than `max_age` is redone first (§4.11).
- Every grant records `signedInAt` and `method` beside `aal2At`. Introspection and ID tokens turn
  them into `auth_time`, `acr` and `amr`. Grants approved before 8c fall back to the approval
  time.

### 4.13 Device authorization grant (phase 8d)

RFC 8628, for devices without a browser, first the 2earl CLI. The library has no device grant, so
login builds it around the ordinary code flow and never mints tokens itself.

**Which apps.** Only a client that registered `https://login.2earl.com/device/callback` as a
redirect URI may use the device grant. That is its explicit opt-in.

**Steps:**

1. **The device asks.** It calls `POST /oauth/device_authorization` with `client_id`, `scope` and
   `resource` (or `openid` without a resource, as in §4.11). Scopes and resource are checked like
   `/authorize`. login stores the request in `device_codes`:
   - the HMAC of a 256-bit `device_code`, never the code itself;
   - an 8-letter `user_code` (`BCDF-GHJK`: 20 consonants, so it spells no words, about 34.6 bits);
   - a random `state`.

   It answers with both codes, `verification_uri` (`/device`), `verification_uri_complete`,
   `expires_in` 600 and `interval` 5.
2. **The person approves** at `/device`:
   - They sign in, enter the code (any case, with or without the dash) and press Continue. A
     prefilled `?user_code=` only fills the field; a link alone never approves anything.
   - The page warns: only continue if you started this yourself.
   - login then sends the browser through the ordinary `/authorize`: second factor, step-up,
     consent with the app's name and verified badge, everything as in §4.3. The redirect URI is
     `/device/callback`, and the PKCE challenge comes from a verifier derived as
     `HMAC(SESSION_PEPPER, device_code hash)`, never stored.
   - The callback finds the request by `state` and stores the authorization code, or marks the
     request denied.
3. **The device polls** `POST /oauth/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code` and `client_id`:

   | Request state | Answer |
   |---|---|
   | Pending | `authorization_pending`; polling faster than `interval` gets `slow_down` and 5 more seconds |
   | Denied | `access_denied` |
   | Expired | `expired_token` |
   | Approved | login takes the code once (atomic delete) and exchanges it with the library, using the derived verifier; the answer is the library's token response, with an ID token for `openid` (§4.11) |
   | Unknown code, or another client | `invalid_grant` |

**What an attacker gets.** Someone with read access to D1 sees, at most, an authorization code
for up to 10 minutes. Exchanging it also needs the verifier, which needs the device code (not
stored) and `SESSION_PEPPER` (not in D1).

**Limits.**
- `/oauth/device_authorization` and polling use the token endpoint's per-address limit.
- Code entry at `/device` has its own (`device`).
- The zone rate limit covers `/device` and `/oauth/device_authorization`.
- Expired requests are deleted daily.

## 5. Protocol surface

### 5.1 Endpoints

| Path | Owner | Purpose |
|---|---|---|
| `/.well-known/oauth-authorization-server` | library | RFC 8414 metadata |
| `/authorize` | app + library | Authorization endpoint (GET) |
| `/oauth/token` | library | Token endpoint: `authorization_code`, `refresh_token` |
| `/oauth/token` (revocation, as advertised) | library | RFC 7009 |
| `/.well-known/oauth-authorization-server` | library | RFC 8414 metadata |
| `/account/apps/disconnect` | app | Revoke one app's grant (same-origin POST) |
| `/login`, `/callback/google`, `/logout` | app | Google sign-in, session |
| `/consent` | app + library | Consent form POST |
| `/account`, `/account/apps`, `/account/delete`, `/account/export` | app | Self-service |
| `/account/security`, `/mfa/challenge` | app | Second factor enrolment and challenge (§4.7) |
| `/admin/*` | app | Owner-only |
| `https://2earl.com/privacy`, `/terms`, `/imprint` | `2earl/website` | Legal pages for all 2earl services; login pages link to them |

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

### 5.4 Scopes (the current set is `src/services.ts`)

| Scope | Meaning | Grantable to |
|---|---|---|
| `mcp:tools.read` | List tools and resources on the gateway | any client |
| `mcp:<service>.<permission>` | Use one service behind the gateway, e.g. `mcp:promptshare.read`, `.write`, `.state` | any client |
| `promptshare:account` | Sign in to Prompt share's website (its own resource, `https://promptshare.cc`) | Prompt share's website |
| `admin` | Administer the identity service | owner's first-party sessions only; never to OAuth clients |

Scopes are opaque strings to `login`; their enforcement lives in the resource server.

---

## 6. Data model

### 6.1 D1 (jurisdiction `eu`, fixed at creation)

```
users            id (random UUID PK), status (active|suspended), created_at, updated_at,
                 display_name, primary_email          (hard delete: no deleted_at)
identities       id PK, user_id FK, provider ('google'|'email'), subject (Google's stable ID, or
                 the address in lower case for 'email'),
                 email, email_verified, created_at, last_login_at
                 UNIQUE(provider, subject)
sessions         id_hash PK (HMAC-SHA-256 of cookie value, SESSION_PEPPER), user_id FK,
                 aal ('aal1'|'aal2'), aal2_at NULL, created_at, last_seen_at, expires_at,
                 ip_prefix, user_agent_hash,
                 device NULL ("Firefox on Windows"), method NULL ('google'|'email'|'passkey')
passkey_challenges id_hash PK (HMAC of __Host-passkey_tx), challenge, user_id NULL (reauth
                 only), expires_at                                   (§4.10; ≤ 5 minutes)
oidc_subjects    sub PK (random), user_id FK, sector, created_at, UNIQUE(user_id, sector)
                                                                     (§4.11; with the account)
resource_servers id PK ('rs_…'), name, resource, secret_hash (SHA-256), created_at,
                 last_used_at                                        (§4.12; no personal data)
device_codes     id_hash PK (HMAC of device_code), user_code UNIQUE, state UNIQUE, client_id,
                 scope, resource NULL, status, code NULL, interval, last_polled_at,
                 created_at, expires_at                              (§4.13; ≤ 10 minutes)
login_tx         id_hash PK, state, nonce, pkce_verifier, return_to, created_at, expires_at,
                 purpose ('sign_in'|'delete_account'), user_id NULL (deletion only)
mfa_factors      id PK, user_id FK, kind ('webauthn'|'totp'), label, created_at, last_used_at,
                 webauthn_credential_id UNIQUE NULL, webauthn_public_key NULL,
                 webauthn_sign_count NULL, webauthn_transports NULL (JSON),
                 totp_secret_enc NULL (AES-GCM, MFA_ENCRYPTION_KEY),
                 totp_last_step NULL (blocks code reuse)
recovery_codes   id PK, user_id FK, code_hash, used_at NULL
mfa_pending      (session_hash FK sessions, purpose) PK, value, expires_at
                 purpose: webauthn_register | webauthn_authenticate | totp_enrol | recovery_codes
users            + mfa_failed_attempts, mfa_locked_until (migration 0004)
allowlist        id PK, kind ('google_sub'|'email'), value, added_by, created_at
trusted_clients  client_id PK, note, created_at
email_codes      id_hash PK (HMAC of the cookie), email, code_hash, link_hash, purpose
                 ('sign_in'|'delete_account'|'link_email'), user_id NULL, return_to, attempts,
                 ip_prefix, created_at, expires_at, used_at          (§4.9; kept 2 days)
settings         key PK, value, updated_at                           ('signup': open|invite)
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

Account deletion (`src/account.ts`):
1. revokes all of the user's grants with their tokens (`listUserGrants` → `revokeGrant`), first, so
   no app keeps access if a later step fails;
2. in one D1 batch (a transaction): re-keys the user's audit events to a random correlation ID
   (`deleted:<uuid>`), deletes pending sign-in transactions, the invitation (allowlist entry),
   sessions, identities and the user row, and writes `user.deleted` (detail: number of grants);
3. sweeps grants again, for one created while step 2 ran (a consent submitted in another tab);
4. clears the session cookie and the library's `__Host-oauth-approvals` cookie.

Audit events about the deleted account stay linkable to each other, not to a person, and expire
with the 90-day retention.

**Backstop:** `tokenExchangeCallback` checks on every code exchange and refresh that the user
exists and is `active`. If not, it revokes the grant, writes `grant.refused` and returns
`invalid_grant`. This also cuts off a suspended user's apps within one access-token lifetime
(15 min).

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
  - Other POSTs (account, admin): a per-session synchronizer token, plus `Origin` header check;
    a `Sec-Fetch-Site` other than `same-origin` is rejected.
- **Response headers on every response:**
  - `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`
  - Stylesheet, font (Readex Pro, OFL, Latin subset, self-hosted) and the 2earl mark (icon) are
    Workers static assets in `public/`, referenced with content fingerprints (`?v=`), with their own headers in `public/_headers`. No third-party
    requests. The only JavaScript is `/passkey.js` (WebAuthn needs the browser API), served from
    this origin and allowed only on the sign-in page and the second-factor pages (`MFA_CSP`:
    `script-src 'self'; connect-src 'self'`).
    - Exception: the **consent page** omits `form-action`. Some browsers apply `form-action` to
      the redirect that follows a form submission, and approving consent redirects to the
      client's (arbitrary) redirect URI. That redirect target is already restricted by exact
      redirect-URI matching.
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
  - `Referrer-Policy: same-origin` (codes and state never leak via Referer to other sites).
    Not `no-referrer`: under that policy browsers send `Origin: null` on same-site form posts,
    which breaks the Origin check below.
  - `X-Content-Type-Options: nosniff`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cache-Control: no-store` on all authenticated and OAuth responses
- **Output encoding:** all client-supplied strings (`client_name`, URIs) are HTML-escaped. Logos
  from CIMD documents are **not** rendered in v1.
- **Logging:** never log tokens, codes, cookies, `Authorization` headers or full query strings
  of `/authorize` and `/callback/*`.

---

## 8. Abuse controls

- Workers Rate Limiting bindings, keyed by IP prefix:
  - `AUTH_RATE_LIMITER` (20/min): `/login`, `/callback/google`, account deletion, second factor,
    `/admin`;
  - `TOKEN_RATE_LIMITER` (1,000/min): `POST /oauth/token`. High on purpose: an AI assistant's
    servers (Claude: Anthropic's `160.79.104.0/21`) refresh for all their users from a few
    addresses, every 15 minutes per user. Guessing isn't possible there (codes need their PKCE
    verifier; refresh tokens are long and random), so the limit only bounds load.
- Zone rate-limit rule (Free plan, one rule, per address): `/authorize`, `/callback/google`,
  `/login`; 30 per 10 s. Not `/oauth/token`, for the reason above.
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
| `GOOGLE_CLIENT_ID` | var | `wrangler.jsonc` (public by design: it appears in every sign-in URL) |
| `LOGIN_LOCKED` | var | `wrangler.jsonc`, `"true"` until phase 5 |
| `GOOGLE_CLIENT_SECRET` | secret | deploy (`wrangler secret bulk` from the GitHub `production` environment); listed in `secrets.required`, so a deploy without it fails |
| `OWNER_GOOGLE_SUB` | secret | owner, once |
| `CONSENT_REMEMBER_SECRET` | secret | owner, generated locally |
| `SESSION_PEPPER` | secret | owner, generated locally (HMAC for session/tx ID hashing); deployed like `GOOGLE_CLIENT_SECRET` |
| `MFA_ENCRYPTION_KEY` | secret | owner, generated locally (encrypts TOTP secrets; phase 5) |
| `MFA_REQUIRED` | var | `wrangler.jsonc`, default `"false"` (§4.7) |

---

## 10. CI/CD

| Workflow | Trigger | Does |
|---|---|---|
| `ci.yml` | PR, push to `main` | job `verify`: install (frozen lockfile), typecheck (including `wrangler types --check`), lint + format, tests on the Workers runtime, browser tests (Playwright Chromium against `wrangler dev` with `e2e/worker/index.ts`: the real app with Google's token endpoint and keys replaced; the whole owner journey including a virtual passkey), bundle (dry-run deploy), `pnpm audit`. **Required check** on `main`. |
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

1. ~~Sign-up policy after unlock.~~ Resolved 2026-11-10 (§4.9): anyone may create an account with
   Google or an email code; no privileged scopes; owner-only `admin`. The sign-up switch and the
   allowlist stay as the kill switch.
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
| 7 | **Open sign-up** (§4.9): email codes, sign-in methods, welcome page, security notices by email, sign-up switch |
| 8a | **Passkey sign-in and signed-in devices** (§4.10) |
| 8b | **OpenID Connect provider** (§4.11) |
| 8c | **Introspection and step-up** (§4.12) |
| 8d | **Device authorization grant** (§4.13) and the **2earl CLI** (`2earl/cli`) |
| 8e | **More social sign-in**: Microsoft, GitHub, Apple (§13) |
| 9a | **Organizations and roles** (§13) |
| 9b | **SCIM 2.0** provisioning into organizations (§13) |
| 9c | **SAML 2.0**: organizations sign in through their own identity provider (§13) |
| 9d | **DPoP and PAR** (§13) |

## 13. Standards roadmap: what login implements, and what it deliberately doesn't

login is the identity service and authorization server for 2earl. Every protocol endpoint is
permanent attack surface on the one service that guards every account, and one person runs it. A
standard is added when something uses it, not to tick a list.

**In place** (phases 4–8d):

| Standard | What it does here |
|---|---|
| OAuth 2.1 (draft), RFC 9700 (Security BCP) | Authorization code + PKCE (S256 only), no implicit or password grant |
| RFC 7636 | PKCE |
| RFC 8414 | Authorization server metadata |
| RFC 7009 | Token revocation |
| RFC 8707, RFC 9728 | Resource indicators: tokens bound to one audience; protected-resource metadata |
| RFC 9207 | `iss` in the authorization response (mix-up defence) |
| draft-ietf-oauth-client-id-metadata-document | Client registration by URL (MCP 2026-07-28) |
| Rotating refresh tokens, 90-day grant cap | RFC 9700 §4.14 |
| WebAuthn Level 3, passkeys | Second factor; sign-in on its own with user verification (§4.10); autofill (conditional mediation) |
| RFC 6238 (TOTP) | Second-factor fallback |
| NIST SP 800-63B AAL | `aal1`/`aal2` sessions; `acr_values=urn:2earl:aal2` for apps that need a recent second factor |
| OpenID Connect (as a client of Google) | Google sign-in: PKCE, nonce, `iss`/`aud` checks |
| OpenID Connect Core 1.0 and Discovery 1.0, as a provider | "Sign in with 2earl" (§4.11): ES256 ID tokens, `nonce`, `auth_time`, `acr`/`amr`, `at_hash`, `/userinfo`, `prompt` and `max_age` |
| OIDC Core §8.1 pairwise subjects | Each site gets its own random ID for a person |
| OIDC RP-Initiated Logout 1.0 | An app can ask to end the 2earl session too; the person confirms |
| RFC 7662 Token introspection | Resource servers without a Service Binding check tokens with their own credentials, only for their own resource (§4.12) |
| RFC 9470 Step-up authentication challenge | `acr_values` and `max_age` for every request; tokens record `auth_time`, `acr`, `amr` (§4.12) |
| RFC 8628 Device authorization grant | Sign in on a device without a browser by approving a short code elsewhere (§4.13) |

**Next** (the owner decided on 2026-11-12 to plan all of these; the order puts each one after
what it depends on):

| Phase | Standard | Why | Depends on |
|---|---|---|---|
| 8d | **2earl CLI** (`2earl/cli`, public repo) | `2earl login` with the device grant; then Prompt share from the terminal through the gateway | Device grant (done) |
| 8e | **Microsoft, GitHub, Apple sign-in** | More ways in for people without Google | The owner registers an app with each provider (client ID and secret); each one is a sign-in method like Google, never joined by address (B3) |
| 9a | **Organizations and roles** | A team owns resources together; members have roles (owner, admin, member) that services can read from the token | A product that teams use |
| 9b | **SCIM 2.0** (RFC 7643, 7644) | An organization's own directory adds and removes its members | Organizations |
| 9c | **SAML 2.0** | An organization's members sign in through the organization's own identity provider (login is the SAML service provider; their IdP proves who they are) | Organizations; an XML signature library reviewed for signature-wrapping attacks |
| 9d | **RFC 9449 DPoP** | Tokens bound to the client's key, so a stolen token is useless elsewhere | Support in `@cloudflare/workers-oauth-provider`, or our own token-endpoint and resource-server wrapping; clients that send DPoP proofs |
| 9d | **RFC 9126 PAR** | The authorization request goes to the server first, not through the browser | — |

**Advisor's note (2026-11-12).** Every row above adds permanent attack surface to the service that
guards every account, and none of them has a user yet. The order above is chosen so each phase
lands only when the thing it depends on exists. 9c (SAML) carries the most risk: XML signature
handling has a long record of signature-wrapping bypasses.

**Deliberately not implemented** (revisit when the listed condition is true):

| Standard | Why not now | Revisit when |
|---|---|---|
| Passwords | Phishable, reused, and the biggest source of account takeover; email codes and passkeys cover everyone | Never planned |
| SMS codes | SIM swap; NIST SP 800-63B restricts them | Never planned |
| Implicit and password grants | Removed in OAuth 2.1 | Never |
| RFC 9396 Rich Authorization Requests | Scopes per service already cover the permissions in use | A service needs per-object consent (e.g. "this one session") |
| RFC 7591 Dynamic client registration | Replaced by client metadata documents, which can't be abused to fill the database | Never, unless MCP requires it again |
| Client credentials grant | No machine-to-machine client; services talk over Service Bindings | A third-party backend needs its own access |
| RFC 9101 JAR | Signed request objects; PAR (9d) already keeps the request off the browser | A FAPI-grade client |
| FedCM | Browser-mediated sign-in for third-party sites; only useful once sites embed "Sign in with 2earl" | A site asks for it |
| Shared Signals (CAEP, RISC) | Pushes session and credential events to relying parties; there is one relying party, our own gateway, which already checks every token | Several independent relying parties |

## References

- MCP Authorization, revision 2026-07-28
- OAuth 2.1 (draft-ietf-oauth-v2-1), RFC 9700 (OAuth 2.0 Security BCP)
- OpenID Connect Core 1.0, Discovery 1.0, RP-Initiated Logout 1.0; RFC 8176 (`amr` values)
- RFC 8414, RFC 8707, RFC 9207, RFC 9728, RFC 7009, RFC 7636, RFC 8252
- draft-ietf-oauth-client-id-metadata-document-00
- `@cloudflare/workers-oauth-provider` 1.2.4 documentation
