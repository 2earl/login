# Asking login what someone may do

For the 2earl apps that keep data people share (Emanet, KYC): how to use login's authorization
API instead of keeping roles of your own. Why it works this way: [DESIGN.md §4.32–§4.34](DESIGN.md#432-permissions-roles-and-assignments-phase-13).

## 1. Declare your permissions in login

Your service's entry in login's `src/services.ts` gets an `authz` manifest:

| Field | What |
|---|---|
| `permissions` | `<service>:<object>.<action>` → what it lets someone do, in plain words (and the Turkish in `src/locales/tr.ts`) |
| `roles` | System roles, `<service>:<name>` → `{ name, permissions, assignable: 'org' \| 'platform', privileged? }` |
| `orgDefaults` | Which of your roles each organization base role (owner, admin, auditor, member) implies |
| `staffDefaults` | Which of your platform roles each 2earl staff role (owner, admin, support) implies |
| `exclusive` | Pairs of roles nobody may hold together in one scope |
| `scopeGrants` | Which permissions each of your OAuth scopes can carry. A scope not listed carries none |

`test/authz-manifest.test.ts` checks it. Deploy login before the app that asks about a new
permission: an unknown permission throws.

## 2. Bind the entrypoint

Same Cloudflare account. Your service ID goes in `props`; login answers only about your own
permissions.

```jsonc
// your wrangler.jsonc
"services": [
  { "binding": "AUTHZ", "service": "login", "entrypoint": "Authorization",
    "props": { "service": "emanet" } }
]
```

```ts
interface Subject { type: 'user' | 'service_account'; id: string }
interface Resource { type: string; id: string }
interface Context { scopes?: string[] }   // the access token's scopes

interface Authorization {
  check(q: { subject: Subject; action: string; orgId?: string; resource?: Resource; context?: Context }):
    Promise<{ decision: boolean }>;
  checkMany(q: { subject: Subject; orgId?: string; evaluations: { action: string; resource?: Resource }[];
    context?: Context }): Promise<{ decision: boolean }[]>;          // at most 50
  permissionsOf(q: { subject: Subject; orgId?: string; context?: Context }): Promise<{
    permissions: string[]; scoped: Record<string, string[]>; roles: string[]; baseRole: string | null }>;
  subjectsWith(q: { action: string; orgId: string }): Promise<Subject[]>;   // up to 1,000
}
```

- `orgId` asks about one organization; leave it out for 2earl-wide (staff) permissions. The two
  never mix: staff hold nothing inside an organization because they are staff.
- `subject.id` is the `uid` from `validateToken` (`props.uid`, the same as `userId`).

## 3. Ask on every request

```ts
const { permissions } = await env.AUTHZ.permissionsOf({
  subject: { type: 'user', id: session.uid },
  orgId,
  context: { scopes: validated.scope },   // when the request came with a token
});
if (!permissions.includes('emanet:cases.write')) return forbidden();
```

- **One `permissionsOf` per request** is the usual pattern: it tells a page what to draw and every
  handler what to allow. Use `check` for a single action, `checkMany` for a list.
- **Don't cache a decision** longer than the request it was made for. Answers are live: a person
  removed from a role loses it at the next call.
- **Pass the token's scopes** when the request came with one. Then the answer is already limited
  to what the person let the app do. Without them, you get the person's full permissions: right
  for your own signed-in pages, wrong for an API call made by a third-party app.
- **Fail closed.** If the call throws (login unavailable, a wrong question), answer 503 and do
  nothing. Throws are deliberate: an unknown permission, another service's permission, an `orgId`
  that isn't `org_…`, a binding without `props`.
- Keep your membership gate (`OrganizationDirectory.roleOf`) where you already have it; a
  non-member simply gets no permissions here.

## 4. Requests from service accounts

An organization's own servers call your API with a token from a **service account** (DESIGN
§4.33): `validateToken` gives `userId` = `sa_…`, `props.kind === 'service_account'` and
`props.org`, the organization it acts for. Treat `props.org` as the tenant; don't look the
organization up from the client ID. Ask `permissionsOf({ subject: { type: 'service_account', id },
orgId: props.org, context: { scopes } })` if you give accounts roles; or check the token's scopes
alone if your API is scope-based.

### An organization on a person's token

An app that works for one organization at a time can send `organization=org_…` on `/authorize`.
login lets only members through, shows the organization on the consent page, and puts it in
`props.org`; the grant ends when the person leaves. Use `props.org` as the `orgId` of your
`permissionsOf` calls for such tokens.

## 5. Testing

Stub the binding in `@cloudflare/vitest-plugin` with an `Authorization` entrypoint that returns
fixed answers, as login's own `vitest.config.ts` does for `AccountEvents`. To run against the real
thing, bind `login-e2e` (GATEWAY_INTEGRATION §8) with the same `entrypoint` and `props`.

## 6. What's next

Custom roles and assignments in the organization's pages and API (phase 13b), conditions, time-bound access and AuthZEN over HTTP (13e).
