# The organization API

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

The organization's audit log (DESIGN §4.23), **oldest first**, from the last 90 days.

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
| `POST /members/{id}/role` | `{ "role": "admin" }` or `"member"` | Changes the role. `409 directory` when the directory decides it (DESIGN §4.21) |
| `POST /members/{id}/deactivate` | none | A managed account can't sign in; sessions and app access end. `409 not_managed` otherwise |
| `POST /members/{id}/reactivate` | none | Lifts the organization's deactivation |
| `POST /members/{id}/remove` | none | Removes a member the organization doesn't manage. `409 managed` for managed accounts: deactivate them |

Every change is in the organization's activity, with `"via": "api"` and the key's ID.
