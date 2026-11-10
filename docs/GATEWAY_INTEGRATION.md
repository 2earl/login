# MCP gateway integration

Handoff from `2earl/login` (the authorization server, **AS**) to the session that builds the 2earl
MCP gateway (the protected resource, **RS**). Everything here describes what is deployed at
`login.2earl.com` today (phases 1–5) unless it is marked **open**.

Read with: [DESIGN.md](DESIGN.md) §4–§6 (flows, protocol surface, data), [THREAT_MODEL.md](THREAT_MODEL.md).
Specification: [MCP Authorization, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

## 1. At a glance

| | |
|---|---|
| Issuer | `https://login.2earl.com` |
| AS metadata (RFC 8414) | `https://login.2earl.com/.well-known/oauth-authorization-server` |
| The gateway's canonical resource | `https://mcp.2earl.com/mcp` (login's `MCP_RESOURCE`; the only audience tokens are issued for) |
| Scopes | The gateway's set (`src/services.ts`): `mcp:tools.read` ("See which tools are available to you"), plus each service's behind it, `mcp:<service>.<permission>` (2earl/mcp docs/DESIGN.md §4). Each 2earl service has its own; a token for one never carries another's |
| Access tokens | **Opaque**, not JWTs. 15 minutes. Validated only through the Service Binding (§3) |
| Refresh tokens | 30 days, lapse after 7 days unused, and every grant ends 90 days after the user approved it |
| Client registration | Client ID Metadata Documents (an `https://` `client_id`), or public clients pre-registered by the owner in `/admin`. **No Dynamic Client Registration** |
| Required of clients | PKCE `S256`, an explicit `resource` on `/authorize` and `/oauth/token`, `iss` checked (RFC 9207, `authorization_response_iss_parameter_supported: true`) |
| Users | Google sign-in or a one-time code by email; a second factor when the user has one (always for the owner); sign-up open, switchable to invitation-only on `/admin/invitations` |

## 2. Architecture

```
MCP client ──(1) /mcp without token──────────────▶ Gateway  mcp.2earl.com   (RS)
   ◀── 401 WWW-Authenticate: resource_metadata, scope
   ──(2) RFC 9728 metadata ─────────────────────▶ Gateway
   ──(3) /authorize, consent, /oauth/token ──────▶ login.2earl.com            (AS)
   ──(4) /mcp, Authorization: Bearer <token> ───▶ Gateway
                                                     │ validateToken(resource, token)
                                                     ▼   Service Binding (RPC, never HTTP)
                                                   login Worker  ──▶ OAUTH_KV
```

The gateway never sees passwords, Google tokens or sessions. It learns, per request, which
internal user and which client the token belongs to and which scopes the user approved.

## 3. What the gateway must do

### 3.1 Bind the login Worker

Same Cloudflare account (`304c2b77d734c688c8309d5a535f561a`); Service Bindings don't cross
accounts. The login Worker's default export is a `WorkerEntrypoint`, so no `entrypoint` is needed.

```jsonc
// gateway wrangler.jsonc
"services": [{ "binding": "AUTH_SERVER", "service": "login" }]
```

```ts
import type { AuthorizationServerBinding } from '@cloudflare/workers-oauth-provider';

/** What login stores with each grant (src/oauth.ts GrantProps). */
export interface GrantProps {
  uid: string;      // login's internal user ID
  authTime: number; // Unix seconds: when the user approved this grant
}

interface Env {
  AUTH_SERVER: AuthorizationServerBinding<GrantProps>;
}
```

### 3.2 Serve the resource with `OAuthResourceServer`

Use the same library and major version as login (`@cloudflare/workers-oauth-provider` 1.2.x). It
publishes the RFC 9728 metadata at the location derived from the resource, answers `401` with the
`WWW-Authenticate` challenge, checks the audience and expiry of what the validator returns, and
routes only the canonical resource and its sub-paths to the handler.

```ts
import { OAuthResourceServer, insufficientScope } from '@cloudflare/workers-oauth-provider';

export default new OAuthResourceServer<Env, GrantProps>({
  resourceMetadata: {
    resource: 'https://mcp.2earl.com/mcp',          // must equal login's MCP_RESOURCE exactly
    authorization_servers: ['https://login.2earl.com'],
    bearer_methods_supported: ['header'],
    resource_name: '2earl MCP gateway',
  },
  requiredScopes: ['mcp:tools.read'],               // the minimum; invoke is asked for on demand
  validateToken: (env) => env.AUTH_SERVER.validateToken,
  handler: { fetch: handleMcp },
});
```

### 3.3 Enforce scopes per operation

| MCP operation | Needs |
|---|---|
| `initialize`, `tools/list` | `mcp:tools.read`, or any service scope |
| `tools/call` | the tool's service scope: `read` for read-only tools, `write` otherwise, or a scope the tool names |

- **Scope hierarchy:** a service's `write` implies its `read`; any service scope implies
  `mcp:tools.read`. The consent page lets a user approve each one; MCP requires servers to honour
  hierarchies.
- When a token lacks a scope, answer `insufficientScope(ctx.auth, [...all scopes the operation
  needs])`: a `403` with `error="insufficient_scope"`, in one challenge, never one scope at a time.
- `ctx.auth.scope` holds the approved scopes; `ctx.props` holds `GrantProps`.

### 3.4 Never do this

- Forward the user's access token to an upstream tool or API. MCP: servers "MUST NOT accept or
  transit any other tokens". Upstream credentials are the gateway's own, stored and scoped
  separately.
- Accept tokens from the query string or a cookie. Header only.
- Log the `Authorization` header, the token, or full request bodies of auth-related requests.
- Decode the token or cache validation results longer than the token's `expiresAt`.

## 4. The `validateToken` contract

`AUTH_SERVER.validateToken(resource, token)`, tested in `test/gateway-contract.test.ts` through the
Worker's real entry point:

| Situation | Result |
|---|---|
| Valid token for this resource | `{ props: { uid, authTime, aal2At }, audience, expiresAt, scope, userId, clientId }`. `userId === props.uid`. `aal2At`: when the approving session last verified a second factor, or `null` |
| Unknown, malformed, expired or revoked token | `null`, and the library answers `401` |
| A `resource` login doesn't serve (typo, trailing slash, other host) | **Throws** `resource must name one registered protected resource`, and the library answers `503` on every request. If the gateway returns 503 for everything, compare its resource with login's `MCP_RESOURCE` first |
| KV unavailable | Throws, so `503` (fails closed) |

- An `OAuthError` thrown inside login arrives over RPC as a plain `Error`. If the gateway needs a
  specific OAuth answer, throw it in the gateway's own validator wrapper.
- **Revocation is not instant everywhere.** Tokens live in Workers KV, which is eventually
  consistent: Cloudflare says changes "may take up to 60 seconds or more to be visible in other
  global network locations". After a user disconnects an app, or the owner suspends or deletes a
  user, the token stops working at once where the change was made, and within about a minute
  elsewhere. Access tokens expire after 15 minutes regardless.
- **Users:** suspending or deleting a user revokes all their grants; every refresh and code
  exchange also checks that the user exists and is active. The gateway doesn't need its own
  user-status check.
- **Privacy:** `props` carries no email or name, on purpose (DATA_PROTECTION.md). If the gateway
  needs them, that's a change to login and to the privacy policy (§7).


### 4.1 Requiring a recent second factor

An app's admin area can ask login to verify the user's second factor before it approves: add
`acr_values=urn:2earl:aal2` to `/authorize`.
- A user with a second factor is asked for it unless it was verified in the last 5 minutes.
- A user without one is sent to set one up first.

login then continues to consent as usual. The app must still check `props.aal2At` itself, for
example that it is within the last 15 minutes: the parameter is a request from the app, not a
guarantee to it.

## 5. Users and their data in the gateway

- Key everything per user by `props.uid`. It is stable for the life of the account. An account that
  is deleted and created again gets a new `uid`.
- Key per-app state by `uid` + `clientId`.
- **Required: account deletion.** Decided by the owner: when a user deletes their 2earl account,
  every service deletes that user's data. login records a notice for the gateway in the same
  transaction as the deletion and delivers it until the gateway confirms (DESIGN §4.8). The gateway
  must expose a named entrypoint:

  ```ts
  import { WorkerEntrypoint } from 'cloudflare:workers';

  /** Called by login only, over a Service Binding, when a 2earl account is deleted. */
  export class AccountEvents extends WorkerEntrypoint<Env> {
    async deleteUser(userId: string): Promise<void> {
      // Delete everything stored under userId: KV, D1, R2, Durable Objects, caches, upstream
      // credentials. Resolve only when it is gone. Must be idempotent: login may call it again
      // for the same user after a timeout or retry, and for users the gateway never saw.
    }
  }
  ```

  - **Throw** if deletion did not finish; login retries every 15 minutes and shows failures in
    `/admin`. Don't swallow errors.
  - **Required: export.** The same entrypoint has `exportUser(userId): Promise<unknown>`, returning
    what the gateway holds about the user. "Download your data" includes it under
    `services.mcp`; if it fails or takes over 10 s, the file says so and the rest is still
    downloaded (`src/service-exports.ts`).
  - **Binding** (done once the gateway was deployed). Notices for deletions made before it existed
    were delivered on the next run.

    ```jsonc
    // login wrangler.jsonc
    { "binding": "MCP_GATEWAY_EVENTS", "service": "mcp", "entrypoint": "AccountEvents" }
    ```

## 6. Infrastructure constraints

- **Zone:** `2earl.com` is managed in `2earl/login` `infra/` (HCP workspace `2earl-login-prod`):
  zone settings, HSTS with `includeSubDomains` (HTTPS only for every subdomain), DNSSEC. The gateway
  must not manage zone-wide settings. Attach `mcp.2earl.com` as a Workers custom domain from the
  gateway's own Terraform workspace, referencing the zone with a data source.
- **Free plan rate limiting:** the zone allows **one** rate-limiting rule, matching on **path
  only**, and login uses it: 30 requests per 10 seconds per IP on `/authorize`, `/oauth/token`,
  `/callback/google` and `/login`, on **every host** in the zone. So the gateway:
  - must not serve those four paths on `mcp.2earl.com`;
  - can't add a zone rate-limiting rule. Use the Workers Rate Limiting binding with its own
    `namespace_id` (login uses `1001`).
- **WAF custom rules** can match on host on the Free plan. login has one, scoped to
  `login.2earl.com`. The gateway may add its own, scoped to `mcp.2earl.com`.
- `global_fetch_strictly_public` is recommended if the gateway fetches arbitrary URLs.

## 7. Changes that need a login PR

| Change | Where in login | Effect |
|---|---|---|
| New or finer scopes | the gateway's entry in `src/services.ts` (scopes start with `mcp:`, with consent wording) | Existing grants keep their old scopes; clients step up |
| Different gateway URL | `MCP_RESOURCE` in `wrangler.jsonc` | **Every existing grant becomes useless**: tokens are bound to the old resource. Users reconnect their apps |
| Another service (any app that accepts 2earl tokens) | a new entry in `src/services.ts`: its own resource, scopes and deletion binding | Each service validates with its own resource and has its own permissions |
| Email or profile for the gateway | `GrantProps`, `completeAuthorization`, privacy policy | Personal data crosses to the gateway; needs a privacy-policy change |
| Another service's deletion and export | its `AccountEvents` binding in `services` in `wrangler.jsonc` (§5) | Deletions reach it; "Download your data" includes it |

## 8. Developing and testing the gateway

- **Unit tests:** stub the binding. In `@cloudflare/vitest-plugin`, pass a `serviceBindings`
  entry for `AUTH_SERVER` returning fixed `ValidatedAccessToken`s, `null`, or throwing, to cover the
  rows of §4.
- **Against the real AS:** login's browser-test Worker (`e2e/`) runs the real AS under
  `wrangler dev`, with Google's token endpoint replaced, as service `login-e2e` on
  `http://localhost:8788`. Run it next to the gateway with `wrangler dev -c gateway.jsonc -c
  ../login/e2e/wrangler.jsonc`, and bind `{ "binding": "AUTH_SERVER", "service": "login-e2e" }` in
  the gateway's development config. The resource must then be the e2e value of `MCP_RESOURCE`.
- **Repository conventions:** see login's README and DESIGN §9–§10:
  - a public repo in `2earl`, AGPL-3.0;
  - a ruleset with a required check;
  - a `production` environment with owner approval;
  - SHA-pinned actions;
  - pnpm `minimumReleaseAge`, Dependabot with a 1-day cooldown, CodeQL;
  - no secrets in the repo.

## 9. Launch checklist for the gateway

1. `GET https://mcp.2earl.com/.well-known/oauth-protected-resource/mcp` lists
   `"authorization_servers": ["https://login.2earl.com"]` and `"resource": "https://mcp.2earl.com/mcp"`.
2. `POST /mcp` without a token gives `401` with `WWW-Authenticate` naming `resource_metadata` and
   `scope="mcp:tools.read"`.
3. A token issued for another resource gives `401`, and a `tools/call` for a service's write
   tool with only its read scope gives `403 insufficient_scope` naming that service's write scope
   (gateway permissions: 2earl/mcp docs/DESIGN.md §4).
4. After **Disconnect** on `login.2earl.com/account`, the app's next calls fail within about a
   minute.
5. A real client (Claude, MCP Inspector) connects end to end: discovery, consent, tools.
6. The app's metadata URL is marked as verified in `/admin` → Apps, if the owner has checked
   the publisher.
7. login's `MCP_GATEWAY_EVENTS` binding is merged and deployed; `/admin` → Users shows no
   deletion notices waiting for the gateway.
8. The privacy policy describes the gateway's data and how long it keeps it.

## 10. Decisions (owner, 2026-11-09)

1. The gateway URL is `https://mcp.2earl.com/mcp`.
2. Deleting an account deletes the user's data in every service (§5).
3. Each service has its own permission set. The gateway starts with the two scopes above; finer
   ones are added to its registry entry when tools need them (§7).
