# The organization API

This page is published at <https://login.2earl.com/docs/api>, generated from `docs/API.md`.

For an organization's own scripts: HR syncs, offboarding tools, log collectors. Owners create keys
on the organization's **Settings** page. A key is shown once; 2earl keeps only its SHA-256.

- **Base URL:** `https://login.2earl.com/api/v1`
- **Authentication:** `Authorization: Bearer 2earl_…`
- **Access:** a *read* key reads; a *read and write* key also changes members.
- **Format:** JSON. Lists are `{ "data": [...] }`. Errors are `{ "error": "code", "message": "…" }`
  with a 4xx status.
- **Limits:** up to 5 keys per organization; requests are rate-limited per network address
  (`429`).
- **Owners:** the API never acts on them. Change owners in 2earl.
- **Changes are pushed** by the audit stream (Activity → Stream), not by polling.

## Read

### `GET /members`

```json
{
  "data": [
    {
      "id": "6b1c…",
      "email": "ada@example.com",
      "name": "Ada Lovelace",
      "role": "owner",
      "managed": true,
      "deactivated": false,
      "role_from_directory": false,
      "joined_at": "2026-11-14T08:10:00.000Z"
    }
  ]
}
```

### `GET /domains`

```json
{ "data": [{ "domain": "example.com", "verified": true, "managed": true }] }
```

### `GET /audit`

The organization's audit log, **oldest first**, from the last 90 days: everything that names the
organization, and everything the accounts it manages did.

| Query | Meaning |
|---|---|
| `since` | ISO 8601 time: events at or after it |
| `cursor` | `next_cursor` from the previous page: events after it |
| `limit` | 1 to 100 (default 100) |

```json
{
  "data": [
    {
      "id": "…",
      "time": "2026-11-14T08:12:31.000Z",
      "event": "login.succeeded",
      "actor": { "id": "6b1c…", "email": "ada@example.com" },
      "target": null,
      "client_id": null,
      "ip_prefix": "203.0.113.0/24",
      "detail": { "method": "oidc" }
    }
  ],
  "next_cursor": "1794643951.Zx8…"
}
```

To follow the log, store `next_cursor` and ask again with it; with no new events the same cursor
comes back. Events of the last few seconds appear on the next call.

## Write (read-and-write keys)

| Request | Body | Does |
|---|---|---|
| `POST /members/{id}/role` | `{ "role": "admin" }`, `"auditor"` or `"member"` | Changes the role. `409 directory` when the directory decides it (a group marked admin or auditor) |
| `POST /members/{id}/deactivate` | none | A managed account can't sign in; sessions and app access end. `409 not_managed` otherwise |
| `POST /members/{id}/reactivate` | none | Lifts the organization's deactivation |
| `POST /members/{id}/sign-out` | none | Signs a managed account out everywhere: sessions and app access end, the account stays active. `409 not_managed` otherwise |
| `POST /members/{id}/remove` | none | Removes a member the organization doesn't manage. `409 managed` for managed accounts: deactivate them |

Every change is in the organization's activity, with `"via": "api"` and the key's ID.

## Roles in 2earl's apps

What people may do in Emanet and other 2earl apps beyond their organization role (the
**Roles in apps** page). A key gives and takes roles, but never privileged ones and never
login's own (owners, admins); it doesn't create roles: owners do that on the page.

### `GET /roles`

Each app's built-in roles and the organization's own.

```json
{
  "data": [
    {
      "id": "emanet:viewer",
      "service": "emanet",
      "name": "Viewer",
      "kind": "built_in",
      "privileged": false,
      "permissions": ["emanet:cases.read"]
    }
  ]
}
```

### `GET /assignments`

Roles given, and to whom: `{ "data": [{ "id", "service", "role", "principal": { "type", "id" },
"expires_at", "granted_at", "reason" }] }`. `type` is `user`, `group` (a directory group) or
`service_account`.

### `POST /assignments` (read-and-write keys)

```json
{ "role": "emanet:viewer", "principal": { "type": "user", "id": "6b1c…" }, "days": 30, "reason": "Pilot" }
```

`days` (1 to 365) and `reason` are optional. Answers `201` with the assignment; `409 duplicate`
if they already have it; `403 forbidden` for a role a key can't give; `400 unknown_principal`
for someone who isn't a member, a group or a service account of the organization.

### `POST /assignments/{id}/revoke` (read-and-write keys)

Takes the role back; it ends at the person's next request.

## Directory sync (SCIM 2.0)

Microsoft Entra ID, Okta and other directories provision people and groups into the organization.
Owners create a token on **Domains & SSO**, after verifying a domain.

- **Base URL:** `https://login.2earl.com/scim/v2`
- **Authentication:** `Authorization: Bearer scim_…`
- **Resources:** `Users` and `Groups`: create, read, list, replace, patch, delete. `PATCH` takes
  the shapes Entra ID and Okta send, operation names in any case.
- **Filters:** `userName eq`, `externalId eq` (users); `displayName eq`, `externalId eq`
  (groups). `excludedAttributes=members` on groups.
- **Discovery:** `ServiceProviderConfig`, `ResourceTypes`, `Schemas`.
- **Not supported:** bulk, sorting, ETags, soft delete.

At a domain the organization manages, provisioning creates the 2earl account; `active: false`
deactivates it; `DELETE` deactivates it at once and deletes it 30 days later unless it is
reactivated first. Groups can be marked admins or auditors on **Domains & SSO**: their members get that role.
