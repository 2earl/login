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

**The signed-in app.** Every page under `/account`, `/orgs` and `/admin` shares one frame
(`src/shell.ts`, `page()` in `src/pages.ts`):
- a top bar with the account menu, a `<details>` holding who is signed in and Sign out;
- navigation on the left: Overview, Sign-in & security, Devices, Connected apps, Organizations,
  Your data, and Admin for the owner. On phones it becomes one menu, named after the current page,
  under the top bar.

Who is signed in reaches `page()` through an `AsyncLocalStorage` set once per request by a
middleware, so page functions don't pass it along. Every page still works without JavaScript and
keeps the strict CSP. The sign-in, consent and second-factor pages stay outside the frame, so the
one thing to do there has all the attention.

| Page | What it holds |
|---|---|
| `/account` | Overview: who you are, and the account at a glance (second factor, sign-in methods, connected apps, organizations), each with where to change it |
| `/account/security` | How you sign in (add or remove methods), passkeys, authenticator app, recovery codes, and recent activity: the account's security events of the last 30 days with the network they came from, so a person can spot what they didn't do |
| `/account/sessions` | Signed-in devices |
| `/account/apps` | Connected apps |
| `/account/orgs` | Organizations; each has the tabs Members, Activity, Domains & SSO and Settings (§4.14) |
| `/account/data` | Download a copy; delete the account |

`/account` used to provide all of these on one page:
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
3. The email (`src/mail.ts`, from `noreply@2earl.com`, replies to `legal@2earl.com`) has the code
   and a link: a button, with the address under it for clients that block buttons. The
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
- **What each says:** what changed, and when, from which device and from which network (`/24`, as
  the audit log keeps it). These are the facts that tell a person whether it was them.
- **The button** leads to the page where it can be undone: Sign-in & security, or Connected apps.
- **An organization's new owner** is told only when it happened, never the previous owner's device
  or network.

**How emails look** (`src/mail.ts`). Each message is written once, as a `Mail`, and rendered
twice:
- **Plain text.** The code is on an indented line of its own, and each link is labelled.
- **HTML that matches the web pages:**
  - the 2earl wordmark, and the mark's four-colour band across the top of a white card;
  - one vermilion button;
  - the code set large;
  - a small table for when, device and network;
  - the web pages' dark colours where the client supports `prefers-color-scheme`;
  - a hidden preview line for inboxes.

  It is built from tables with inline styles, so it works in Gmail and Outlook.
- **Kept out:** no images, no remote fonts or styles, no tracking. Only our own addresses become
  links, and a button never leads anywhere else (tested).
- **Footer.** It says why the email came, and that 2earl never asks for a password or code by
  email or phone. It links Privacy and Imprint, and the account unless the account was deleted.

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

### 4.14 Organizations and roles (phase 9a)

A team of 2earl accounts. Everyone keeps their own account; the organization records who belongs
to it, with which role, so 2earl services and "Sign in with 2earl" sites can give a team shared
access. login doesn't hold anything *for* an organization beyond its name.

**Roles** (`src/orgs.ts`, `can*` functions; the routes only ask them):

| | Member | Admin | Owner |
|---|---|---|---|
| See members (name, email, role) | ✓ | ✓ | ✓ |
| Invite, withdraw invitations | | ✓ (as member or admin) | ✓ |
| Change roles between member and admin; remove members and admins | | ✓ | ✓ |
| Make or unmake owners; remove owners | | | ✓, with a recent proof it's them (`changeCheck`) |
| Rename; delete (type the name, recent proof) | | | ✓ |
| Leave | ✓ | ✓ | ✓, unless the last owner |

Nobody changes their own role on the page; to step down, an owner makes someone else owner, then
leaves or is changed by them. **An organization always keeps an owner**: every statement that could
remove the last one checks the owner count in the same SQL statement, so two requests at once
can't both succeed.

**Invitations.** By email address, as member or admin. Owners are made from members once they've
joined, so an emailed link never grants full control.
- The link holds a 256-bit token; D1 holds only `HMAC(SESSION_PEPPER, token)`. It works 7 days.
- Accepting needs the signed-in account to sign in with the invited address (a verified address
  of one of its methods). A forwarded link is useless to anyone else, who can't decline it
  either. Someone without an account signs up first, under the sign-up switch (§4.9): an
  organization invitation never opens sign-up.
- The email names the inviter (name and address), the organization and the role, and its only
  link is ours. Organization names are plain words: 1–60 characters, no control or bidi
  characters, no `://`, `www.` or domain-like endings, so a name can't carry a link
  (THREAT_MODEL O2).
- Limits: 50 invitation emails per account per day (counted from the audit log), 100 open
  invitations and 1,000 members plus invitations per organization, 50 organizations per account.

**Deleting.** An owner deletes the organization after typing its name. Members and invitations
go with it (`ON DELETE CASCADE`). Services with `organizationEvents: true` in `src/services.ts`
get a notice in `org_deletion_notices`, delivered to `AccountEvents.deleteOrganization(orgId)`
with the account-deletion notices (§4.8). None opts in yet.

**When an owner deletes their account** (§6.3): where they are the only owner, the
longest-standing admin becomes owner, else the longest-standing member, and that person gets an
email. An organization with nobody else is deleted. The deletion page lists both beforehand.

**Activity** (`/orgs/:id/activity`, owners and admins): the organization's events from the audit
log, newest first:
- who joined, left or was removed;
- role changes and invitations;
- domain, directory sync and single sign-on changes;
- what the directory did.

Each entry names the people by their names in 2earl. It shows no addresses of invitees, and no IP
addresses. Events are kept 90 days, like the rest of the audit log. An index on the `org` that
the events carry keeps the page fast (`0016`).

**Suspension** (`/admin/orgs`): the 2earl owner can suspend, reactivate or delete an
organization. A suspended one can't be changed and services don't see it; members can still
leave.

**For services.** A named entrypoint, `OrganizationDirectory`, for Service Bindings only:
- `membershipsOf(userId)`;
- `roleOf(orgId, userId)`;
- `members(orgId)`, which returns account IDs and roles, nothing else.

It reads live on every call, so a removed member loses access at once. It leaves out suspended
organizations and suspended accounts. Access tokens don't carry memberships, because they would go
stale for 15 minutes.

**For "Sign in with 2earl" sites** (§4.11): the `organizations` scope releases an `orgs` claim in
the ID token and at `/userinfo`:
- the shape is `[{ id, name, role }]`;
- only active organizations are included;
- it is read when the token is issued.

Organization IDs are the same for every site: two sites can learn that their users share an
organization. That is the point of the scope, and the consent page names it.

**Routes:**
- `/orgs/new` and `POST /orgs`;
- `/orgs/:id`, plus `POST` to `/name`, `/invitations`, `/invitations/revoke`, `/members/role`,
  `/members/remove`, `/leave` and `/delete`;
- `/invite/:token`.

Every change is same-origin and rate-limited (`orgs`). To anyone who isn't a member, an
organization is a 404.

### 4.15 DPoP and pushed authorization requests (phase 9d)

**DPoP (RFC 9449).** A client that sends a `DPoP` proof to the token endpoint gets tokens bound to
its key: a stolen token is useless without the private key. The library has no DPoP, so login
checks the proof itself (`src/dpop.ts`) and binds through the library's `tokenExchangeCallback`
(`src/oauth.ts`). The token endpoint passes the proof's key to the callback in a per-request `env`.

- **The proof** is a JWT. login checks:
  - `typ: dpop+jwt`, with an asymmetric `alg` (`ES256`, `EdDSA`, `RS256` or `PS256`) and a public
    `jwk` in its header;
  - `htm` and `htu` match the request; the query and fragment are ignored;
  - `iat` is no more than 60 seconds old and no more than 10 seconds ahead;
  - `jti` is new: proofs are remembered for 2 minutes in `dpop_proofs`, by a hash of the key's
    thumbprint and the `jti`, so each proof works once;
  - at a resource, `ath` matches the access token.

  A bad proof gets `invalid_dpop_proof`.
- **The grant** (its refresh tokens) is bound to the key of the first proof (`props.dpopJkt`). Any
  later refresh needs a proof from that key. A refresh without one is treated as a stolen token:
  the callback refuses it, and the library then ends the grant (tested). This protects public
  clients, for which RFC 9449 §5 requires bound refresh tokens.
- **The access token** carries `cnf.jkt` only for a resource that checks proofs (`dpop: true` in
  `src/services.ts`), and the response then says `token_type: DPoP`. For any other resource the
  client gets a bearer token (`token_type: bearer`, which RFC 9449 §5 allows), so a DPoP-capable
  client keeps working with a resource that doesn't check proofs yet. Today only UserInfo checks
  them. The MCP gateway can opt in once it uses `validateRequest`.
- **Resources** (`src/token-check.ts`): a bound token is accepted only with the `DPoP` scheme and a
  valid proof; an unbound token only with `Bearer`.
  - `/userinfo` does this, and answers with `WWW-Authenticate` challenges for both schemes.
  - Introspection reports `token_type: DPoP` and `cnf.jkt`.
  - The Worker's RPC `validateRequest(resource, { authorization, dpop, method, url })` does the
    whole check for a Service Binding caller and returns the `WWW-Authenticate` value to send.
    `validateToken` stays for bearer tokens and refuses bound ones.
- **Not implemented:** server-provided nonces (RFC 9449 §8), and binding the authorization code
  with `dpop_jkt`. PKCE already binds the code to the client that started the request.

**Pushed authorization requests (RFC 9126, `src/par.ts`).**
- **Pushing.** A client posts the authorization request to `POST /oauth/par`. login checks what
  the authorization endpoint's first step checks:
  - a known public client;
  - a registered redirect URI;
  - PKCE with S256;
  - no `request` object (`request_not_supported`).

  It stores the parameters in `pushed_requests` under an HMAC of a 256-bit random value, and
  answers `201` with `request_uri: urn:ietf:params:oauth:request_uri:<random>` and `expires_in`
  600.
- **Using it.** The browser then goes to `/authorize?client_id=…&request_uri=…`. login takes every
  parameter from what was pushed; anything else in the URL is ignored. An unknown or expired
  reference, or another client's, shows an error page; nothing is sent to an unchecked redirect
  URI.
- **Reuse.** A reference works until it expires, so a sign-in on the way comes back to the same
  short URL. The code it leads to still needs the PKCE verifier. When `prompt=login` or `max_age`
  sends the person to sign in again, the request comes back as a plain URL, because its prompt has
  to change.
- **Not required.** Clients may still send requests the plain way
  (`require_pushed_authorization_requests: false`).

Both are announced in the server metadata: `dpop_signing_alg_values_supported`,
`pushed_authorization_request_endpoint`. `/oauth/par` uses the token endpoint's per-address limit.
Expired pushed requests and proofs seen are deleted daily.

### 4.16 Verified domains and SCIM provisioning (phase 9b)

An organization's own directory (Okta, Microsoft Entra ID, Google Workspace via a connector, any
SCIM 2.0 client) adds and removes its members. login is the SCIM service provider for Users.

**Verified domains** (`src/org-domains.ts`).
- An owner adds a domain on `/orgs/:id/directory`. login gives a TXT record to publish at
  `_2earl-challenge.<domain>`, with the value `2earl-verification=<random>`.
- "Check DNS" looks the record up over DNS over HTTPS (`cloudflare-dns.com`, through
  `deps.fetch`). If it's there, the domain is verified.
- A domain is verified by one organization at a time: a unique index on verified rows. An
  organization can have up to 10 domains.
- Host names are normalised to lower-case ASCII (punycode). IP addresses and single labels are
  refused.

**Credentials.**
- A directory authenticates with a bearer token (`scim_…`, 256 bits), stored as SHA-256 and shown
  once.
- Only an owner can create one, after a recent proof it's them, and only once a domain is
  verified.
- An organization can hold two tokens, so it can rotate them. Revoking a token is immediate.
- A suspended organization's tokens stop working.

**What provisioning does** (`src/scim.ts`):
- **Addresses.** A SCIM User is an address (`userName`, normalised like an email) at one of the
  organization's verified domains. Anything else is refused (`invalidValue`), so an organization
  can't touch anyone it has no authority over.
- **No new accounts.** Provisioning **never creates a 2earl account**. The account that signs in
  with the address (one active account with it as a verified address) is linked. With none yet,
  the record waits, and the person is linked at their first sign-in with that address
  (`claimProvisioned` in `openSession`). The sign-up switch still applies (§4.9).
- **Active means member.** While a record is active, its account is a member (role `member`,
  within the 50-organization cap). Deactivating it (`active: false`, or `"False"` as Entra sends
  it) or deleting it removes the membership.
- **The last owner stays.** That change is refused with `409 mutability`; an owner hands over
  first.
- **Roles.** They stay in 2earl: SCIM adds members, and an owner promotes them.
- **Changing `userName`** moves the membership to the account with the new address.

**API** (`src/scim-routes.ts`, RFC 7644):
- `GET /scim/v2/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`.
- `GET|POST /scim/v2/Users`; `GET|PUT|PATCH|DELETE /scim/v2/Users/:id`.
- Filters: `userName eq` and `externalId eq` (what directories use). Paging with `startIndex` and
  `count` (at most 100).
- PATCH: `add`, `replace` and `remove`, with or without a path. Attributes login doesn't keep are
  accepted and ignored.
- Bulk, sort and ETags are not supported (`501`). Groups: §4.21.
- Bodies are limited to 64 KB. Limit: 1,000 requests a minute per address (the token
  endpoint's).
- The zone firewall allows PUT, PATCH and DELETE on `/scim/v2/` only (`infra/firewall.tf`).

**Data.** Kept per provisioned user: the address, the directory's `externalId`, given, family and
display name, active, and the linked account. It is deleted when the directory deletes the user or
the organization is deleted. When the account is deleted, the link is cleared. The person's export
lists every record linked to them (`directoryRecords`).

### 4.17 Single sign-on with SAML 2.0 (phase 9c)

An organization's members sign in through its own identity provider (Okta, Microsoft Entra ID,
Google Workspace, ADFS…). login is the SAML **service provider**.

**Setup** (an owner, on `/orgs/:id/directory`, after a recent proof it's them and once a domain
is verified):
- **Owner enters:** the IdP's entity ID, its sign-in URL (https, HTTP-Redirect binding) and its
  signing certificate, as PEM or bare base64.
- **login gives:** its entity ID `https://login.2earl.com/saml/<org>`, the ACS URL `…/acs`
  (HTTP-POST), and metadata at `…/metadata`.
- **Name ID:** the work email address.

**Sign-in, started by login only.** IdP-initiated responses are refused: without login's own
request there is nothing to check them against.
1. The person chooses "Sign in with your organization (SSO)" on `/login` and enters their work
   address. login finds the active organization that verified that domain (§4.16) and has single
   sign-on on.
2. login stores a state, keyed by an HMAC of a 256-bit RelayState, bound to the browser by
   `__Host-saml_tx` (HMAC stored). It then redirects to the IdP with a deflated AuthnRequest.
3. **The IdP's cross-site POST** to the ACS carries no SameSite=Lax cookie. The response is parked
   in that state, and the browser is sent `303` to `GET …/acs?rs=<RelayState>`. That same-site
   GET carries the cookie; only the browser that started can finish.
4. **Checking the response.** node-saml with xml-crypto does it; login has no XML-signature code
   of its own. It requires:
   - a **signed assertion** (RSA-SHA256), not just a signed envelope;
   - the configured IdP issuer;
   - the audience equal to login's entity ID for this organization;
   - the recipient equal to the ACS URL;
   - `InResponseTo` naming the request of **this** sign-in. The cache is scoped to the state,
     and every ID is used once (`consumeAsync`);
   - assertion IDs never seen before (`rejectReplayedAssertions`);
   - validity times within 60 seconds of clock skew, and the assertion at most 10 minutes old.
5. **The address.** It comes from an email attribute or an email-format NameID, and must be at one
   of the organization's verified domains. Anything else is refused.
6. **The account.** The account that signs in with that address is signed in (`method: saml`,
   `amr: fed`). With none, an account is created like an email sign-up: provider `email`, under
   the sign-up switch (§4.9).
   - **Why the address alone is enough here.** An organization that proved control of a domain
     controls its mailboxes, so it could already sign in with an email code. SAML gives it no
     power it didn't have; it gives its members their company's sign-in.
   - **Second factor.** One set up on 2earl is still asked for.

**Runtime.** node-saml needs the Workers `nodejs_compat` flag (`wrangler.jsonc`), for `crypto` and
`zlib`. The bundle is about 510 KB gzipped.

**Not implemented:**
- single logout;
- encrypted assertions (TLS already protects the POST);
- signed AuthnRequests;
- "require SSO" for personal accounts: other ways to sign in keep working for them. For accounts
  the organization manages, it can require SSO (§4.18).

### 4.18 Accounts an organization manages (phase 10a)

A company expects to own its employees' accounts at its domains: to create them, decide how they
sign in, and close them when someone leaves. Until phase 10a every 2earl account was its person's
own, and an organization could only add or remove members. Now an owner can **manage the accounts
at a verified domain** (§4.16).

**Why this is fair.** An organization that verified a domain controls its mailboxes, so it could
already sign in to any account at that domain with an email code. Managing makes that authority
explicit, puts it in the person's view, and lets them keep an account personal by taking the
address off it.

**Turning it on** (`/orgs/:id/directory`, an owner, after a recent proof it's them): per verified
domain, "Manage accounts at example.com". Turning it off releases the accounts it managed
(below). Removing or losing the domain does the same.

**Which accounts are managed** (`users.managed_by`, `src/managed.ts`):
- **New accounts at a managed domain** are managed from the start, however they are made: by the
  organization's directory (SCIM `POST` or `PUT` of an active user with no account yet: provisioning
  now creates the account), at the first single sign-on, or by signing up with an email code or a
  Google account at that domain. The organization vouches for its own addresses, so SCIM and SSO
  don't depend on the sign-up switch (§4.9); signing up yourself still does.
- **Existing accounts** with a verified address at the domain are not taken over. Their owners get
  an email, and at their next request after signing in they must choose
  (`/account/managed`):
  - **Make it a managed account.** The account joins the organization (as a member, if it wasn't
    one) and is managed from then on.
  - **Keep it personal.** The sign-in methods with addresses at the organization's managed domains
    are removed. That needs another way in first (another address, or a Google account elsewhere);
    the page says so and links to it.
  Until they choose, the session can only reach that page, sign-in methods, the second factor,
  export, deletion and sign-out, and no app can be authorized.
- An account can be managed by one organization. With addresses at domains of two organizations,
  the second one can only be taken off.

**What the organization can do** (owners and admins; admins not on owners, as in §4.14):
- **See** which members are managed.
- **Deactivate** an account: it can't sign in, its sessions end and every app's access is revoked
  at once; the account and its data stay. **Reactivate** it.
- **Delete** it (owners only, recent proof): the account and its data in every 2earl service, as
  if the person had deleted it (§4.8). The person gets the deletion email.
- **Require single sign-on** (owners, recent proof, with SSO on): managed accounts sign in only
  through the organization's IdP. Sessions they started another way end at their next request.
  **Owners are exempt**, so a broken IdP can't lock the organization out; the owner turning it on
  must have a second factor. The rule applies only while SSO is on.
- **The directory** does the same: `active: false` deactivates, `active: true` reactivates, and
  `DELETE` deactivates at once and deletes the account **30 days later** unless the directory or an
  owner reactivates it first (a stolen SCIM token can't destroy data at once; Entra ID deletes the
  same way). For accounts that aren't managed, SCIM keeps its §4.16 behaviour.

**What the person can't do with a managed account:** take an address at the organization's
managed domains off it, leave the organization, or delete the account (they ask the
organization). They can still export their data, change their name, and add passkeys and a
second factor. Being removed from the organization is replaced by deactivation.

**Deactivation and 2earl's own suspension** both set `users.status = 'suspended'`;
`users.deactivated_at` marks the organization's. Reactivating by the organization lifts only its own
deactivation; the 2earl owner's reactivation (`/admin`) lifts either.

**Releasing.** When an organization stops managing a domain (or deletes itself), the accounts it
managed through that domain become their people's own again: no longer managed, still members,
deactivated ones still deactivated (the 2earl owner can reactivate them on request), pending
deletions cancelled.

**Privacy.** For managed accounts the organization decides what happens to them, so it is the
controller and 2earl processes the account for it; the privacy policy says so, and organizations
accept 2earl's data processing terms when they turn managing on. Until someone chooses, the
organization learns nothing about accounts at its domain: no names, no count.

### 4.19 Security rules for managed accounts (phase 10b)

An organization sets rules for the accounts it manages (§4.18) on Domains & SSO
(`/orgs/:id/directory`; owners, with a recent proof). `org_policies`, `src/org-policy.ts`.

| Rule | Effect | Owners |
|---|---|---|
| **Require a second factor** | An account without one adds one before going on (the `enrol` gate, as with `MFA_REQUIRED`) | Apply |
| **Require a passkey** | An account without a passkey passes the challenge with what it has, then adds a passkey. Once it has one, authenticator-app codes are refused; recovery codes still work. The last passkey can't be removed | Apply |
| **Session length** (1, 8, 12, 24 or 72 hours) | Sessions end that long after sign-in. The 12-hour idle limit and the 7-day maximum stay | Apply |
| **Ways to sign in** (Google, email code, passkey) | Sign-in another way is refused with the organization's name; sessions started another way end. SSO is always allowed while it's on; at least one way, or SSO, must stay | Exempt |
| **Allowed networks** (up to 50 IPv4 or IPv6 ranges, nothing wider than /8 or /16) | Sign-in from elsewhere is refused; a session used from elsewhere ends. The address is compared and not stored | Exempt |

**Owners are exempt from the ways in and the networks** for the same reason as from required SSO
(§4.18): a broken identity provider, a removed sign-in method or a new office network must not
lock the organization out. The factor rules and the session length make an owner's own access
stronger, so they apply to owners too.

**Where they're checked.** At every sign-in (`signInRefusal`), and on every request: the session
lookup reads the rules with the session, ends sessions that are too old or started a way no longer
allowed, and the session middleware ends sessions used from another network. Rules apply from each
person's next request; nothing is sent.

**Not covered.** Access tokens that apps already hold are used from wherever those apps run, so
networks don't apply to them; their lifetimes (§4.4) and deactivation (§4.18) do. Accounts the
organization doesn't manage never get its rules.

### 4.20 Single sign-on with OpenID Connect (phase 10c)

Many companies prefer OpenID Connect to SAML: Microsoft Entra ID, Google Workspace and Okta all
offer it. An organization's owner connects its provider on Domains & SSO, next to SAML (§4.17);
**one way of single sign-on is on at a time**, and turning one on turns the other off.
`org_oidc`, `src/sso-oidc.ts`.

**Setup** (an owner, recent proof, a verified domain): the issuer URL, a client ID and a client
secret. login reads the provider's discovery document before saving: it must name exactly that
issuer, over https, with authorization, token and key endpoints; otherwise saving is refused.
Microsoft's multi-tenant issuers (`common`, `organizations`, `consumers`) are refused: only the
organization's own tenant will do. The secret is encrypted with `MFA_ENCRYPTION_KEY`, bound to
the organization, and never shown again; a blank field keeps it.

**Signing in.** `/login/sso` finds the organization by the address's verified domain, as for
SAML, and sends the person to the provider with the authorization code flow: `state`, a `nonce`,
PKCE (S256), `login_hint`, scopes `openid email profile`. The way back
(`GET /sso/:org/oidc`) must carry the state, from the same browser (a `__Host-` cookie, Lax, ten
minutes), once. login exchanges the code with the client secret (HTTP Basic) and the PKCE
verifier, and verifies the ID token with the provider's published keys: signature (RS/PS/ES
algorithms only), issuer, audience, the nonce, issued in the last ten minutes. The asserted
address is `email` (refused if `email_verified` is false), or Entra ID's `preferred_username`
when there's no `email` claim; for Google, the hosted domain `hd` must be the address's domain, so
personal Google accounts made with a work address don't count. From there it is the same as SAML:
the address must be at one of the organization's verified domains (THREAT_MODEL L1), then the
account that signs in with it, or a new one (managed if the domain is, §4.18), the organization's
rules (§4.19) and the second factor. Sessions record `oidc`; required SSO counts both ways.

**Not done:** several connections per organization, provider-initiated sign-in, back-channel or
front-channel logout, client authentication with a private key. Revisit when an organization
needs one.

### 4.21 Groups from the directory, and roles (phase 10d)

The organization's directory sends groups as well as users (SCIM 2.0 `/Groups`, RFC 7643 §4.2):
create, list, filter (`displayName eq`, `externalId eq`), read (with
`excludedAttributes=members`), replace, patch and delete. Patches cover what Microsoft Entra ID
and Okta send: members added, removed by path filter (`members[value eq "…"]`) or by value, all
removed, replaced; `displayName` and `externalId` replaced, with or without a path; operation
names in any case. Members are users this organization's directory provisioned; others are
skipped. At most 500 groups per organization and 5,000 members per group; names are unique per
organization, ignoring case. `scim_groups`, `scim_group_members`, `src/scim-groups.ts`.

**Roles.** An owner marks a group "admin" on Domains & SSO (recent proof). From then on **the
directory decides admin or member** for every account it provisioned: admin while the person is
active and in a group marked admin, member otherwise. Roles follow every change: a user saved or
deleted, a group changed, a mark set or removed. In 2earl, those people's roles can't be changed
by hand any more, except to make one an owner. The directory never makes owners and never
changes owners, so a directory can't take an organization over or lock its owners out. Removing
the last mark leaves roles as they are. Accounts the directory didn't provision keep the roles
set in 2earl.

App access by group: §4.22.

### 4.22 Which apps managed accounts may use (phase 10e)

By default the accounts an organization manages may connect any app, as everyone can. An owner
can turn on **"Only allow the apps below"** (Domains & SSO → Apps, recent proof): from then on
they may use only the apps it allows, **for everyone it manages or for the members of a directory
group** (§4.21). It applies to owners' managed accounts too: login's own pages aren't an app, so
nobody is locked out of changing it. `org_app_access`, `organizations.restrict_apps`,
`src/app-access.ts`.

- **Allowing an app:** from "In use by your people" (apps managed accounts connected in the last 90
  days, from the security log), or by client ID or client metadata URL. Only apps registered with
  login can be allowed, so a typo can't look like it worked. Up to 200 entries.
- **Checked twice:** when an app is authorized (a page names the organization; `prompt=none` gets
  `access_denied`), and at **every code exchange and refresh** (`tokenExchangeCallback`), which
  also covers the device flow and pushed requests. A refused grant is revoked. An app that's no
  longer allowed, or a person who left the group, loses access when its access token expires:
  within 15 minutes.
- Accounts the organization doesn't manage are never restricted by it.

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
                 managed_by NULL (organization, §4.18), managed_since NULL,
                 deactivated_at NULL (by the organization), delete_after NULL (SCIM DELETE)
identities       id PK, user_id FK, provider ('google'|'email'), subject (Google's stable ID, or
                 the address in lower case for 'email'),
                 email, email_verified, created_at, last_login_at
                 UNIQUE(provider, subject)
sessions         id_hash PK (HMAC-SHA-256 of cookie value, SESSION_PEPPER), user_id FK,
                 aal ('aal1'|'aal2'), aal2_at NULL, created_at, last_seen_at, expires_at,
                 ip_prefix, user_agent_hash,
                 device NULL ("Firefox on Windows"), method NULL ('google'|'email'|'passkey'|'saml')
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
organizations    id PK ('org_…'), name, status (active|suspended), created_at, updated_at  (§4.14)
org_members      (org_id FK, user_id FK) PK, role (owner|admin|member), joined_at
org_invitations  id PK ('inv_…'), token_hash UNIQUE (HMAC), org_id FK, email, role
                 (admin|member), invited_by FK NULL, created_at, expires_at  (≤ 7 days)
org_deletion_notices (service, org_id) PK, created_at, attempts, last_attempt_at, last_error
org_domains      (org_id FK, domain) PK, challenge, verified_at NULL, created_at,
                 managed_at NULL (§4.18); UNIQUE(domain) WHERE verified (§4.16)
org_policies     org_id PK FK, require_factor, passkeys_only, session_hours NULL, methods,
                 ip_ranges, updated_at                               (§4.19)
scim_tokens      id PK ('st_…'), org_id FK, token_hash UNIQUE (SHA-256), created_at, last_used_at
scim_users       id PK ('scu_…'), org_id FK, user_name, external_id, display_name, given_name,
                 family_name, active, user_id FK NULL (SET NULL), created_at, updated_at,
                 UNIQUE(org_id, user_name)
scim_groups      id PK ('scg_…'), org_id FK, display_name (UNIQUE per org, NOCASE), external_id,
                 role NULL|'admin', created_at, updated_at           (§4.21)
scim_group_members (group_id FK, scim_user_id FK) PK
org_app_access   (org_id FK, client_id, group_id ('' = everyone)) PK, created_at  (§4.22)
org_saml         org_id PK FK, idp_entity_id, sso_url, certificate (public), enabled,
                 created_at, updated_at                              (§4.17)
org_oidc         org_id PK FK, issuer, client_id, client_secret_enc (AES-GCM), enabled,
                 created_at, updated_at                              (§4.20)
oidc_states      state_hash PK (HMAC of state), org_id FK, browser_hash, nonce, verifier
                 (PKCE), return_to, expires_at                       (≤ 10 minutes)
saml_states      state_hash PK (HMAC of RelayState), org_id FK, browser_hash (HMAC of cookie),
                 return_to, response NULL, expires_at                (≤ 10 minutes)
saml_cache       key PK (org, sign-in, request or assertion ID), value, expires_at
pushed_requests  id_hash PK (HMAC of the request_uri's random part), client_id, params,
                 created_at, expires_at                              (§4.15; ≤ 10 minutes)
dpop_proofs      id_hash PK (SHA-256 of key thumbprint and jti), expires_at  (§4.15; 2 minutes)
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
   Organizations it alone owns pass to the next person in line or, with nobody else in them, are
   deleted, in the same batch (§4.14);
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
| 9a | **Organizations and roles** (§4.14) |
| 9b | **SCIM 2.0** provisioning into organizations, with verified domains (§4.16) |
| 9c | **SAML 2.0**: organizations sign in through their own identity provider (§4.17) |
| 9d | **DPoP and PAR** (§4.15) |
| 10a | **Accounts an organization manages** (§4.18): managed domains, deactivation, required SSO |
| 10b | **Security rules for managed accounts** (§4.19): second factor, passkeys, session length, ways in, networks |
| 10c | **Single sign-on with OpenID Connect** (§4.20): Entra ID, Google Workspace, Okta |
| 10d | **Groups from the directory, and roles** (§4.21) |
| 10e | **Which apps managed accounts may use** (§4.22) |

## 13. Standards roadmap: what login implements, and what it deliberately doesn't

login is the identity service and authorization server for 2earl. Every protocol endpoint is
permanent attack surface on the one service that guards every account, and one person runs it. A
standard is added when something uses it, not to tick a list.

**In place** (phases 4–9d):

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
| RFC 8628 Device authorization grant | Sign in on a device without a browser by approving a short code elsewhere (§4.13); the 2earl CLI (`2earl/cli`) uses it |
| Organizations and roles | Teams of accounts with owner, admin and member roles; services read them live over a Service Binding, sites through the `organizations` scope (§4.14) |
| SCIM 2.0 (RFC 7643, 7644) | An organization's directory adds and removes members at its verified domains; never creates accounts (§4.16) |
| SAML 2.0 Web Browser SSO (as service provider) | An organization's members sign in through its IdP, for addresses at its verified domains; SP-initiated only; signed assertions checked by node-saml (§4.17) |
| RFC 9449 DPoP | Refresh tokens bound to the client's key whenever it sends a proof; access tokens bound for resources that check proofs (UserInfo now; the gateway when it opts in) (§4.15) |
| RFC 9126 PAR | The authorization request goes to login first; the browser carries only a reference (§4.15) |

**Advisor's note (2026-11-12).** Everything the owner planned on 2026-11-12 is in place. Each of
these adds permanent attack surface to the service that guards every account, before any of them
has a user. SAML (§4.17) carries the most risk: XML signature handling has a long record of
signature-wrapping bypasses. It is delegated to node-saml and xml-crypto, which need prompt
updates (Dependabot), and it is on only for organizations that turn it on.

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
| Microsoft, GitHub, Apple and other social sign-in | The owner decided on 2026-11-12: Google, email codes and passkeys are the ways in | The owner decides otherwise |
| SAML single logout, encrypted assertions, signed AuthnRequests, IdP-initiated sign-in | TLS protects the POST; IdP-initiated responses can't be tied to a request login made. "Require SSO" now exists for managed accounts (§4.18) | An organization needs one of them |
| SCIM bulk operations | Directories send one change at a time anyway | A directory needs bulk |
| DPoP server nonces (RFC 9449 §8) and `dpop_jkt` | Proofs already expire in 60 seconds and work once; PKCE binds the code | A client or resource needs them |
| FedCM | Browser-mediated sign-in for third-party sites; only useful once sites embed "Sign in with 2earl" | A site asks for it |
| Shared Signals (CAEP, RISC) | Pushes session and credential events to relying parties; there is one relying party, our own gateway, which already checks every token | Several independent relying parties |

## References

- MCP Authorization, revision 2026-07-28
- OAuth 2.1 (draft-ietf-oauth-v2-1), RFC 9700 (OAuth 2.0 Security BCP)
- OpenID Connect Core 1.0, Discovery 1.0, RP-Initiated Logout 1.0; RFC 8176 (`amr` values)
- RFC 8414, RFC 8707, RFC 9207, RFC 9728, RFC 7009, RFC 7636, RFC 8252
- draft-ietf-oauth-client-id-metadata-document-00
- `@cloudflare/workers-oauth-provider` 1.2.4 documentation
