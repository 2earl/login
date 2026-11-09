# login

Identity service and OAuth 2.1 authorization server for 2earl.com, served at
`https://login.2earl.com`. Runs on Cloudflare Workers.

**Status:** phase 5. Google sign-in, a second factor (passkeys, authenticator app, recovery
codes), the account page (connected apps, data export, account deletion), an owner-only admin
area and the OAuth 2.1 authorization server for apps (MCP clients) are live, locked to
allowlisted accounts.

## Development

Requires Node.js 24 and pnpm (version pinned in `package.json`).

```sh
pnpm install
pnpm dev         # local Worker on http://localhost:8787
pnpm test        # tests run inside the Workers runtime
pnpm test:e2e    # browser tests: Chromium against `wrangler dev` (see e2e/)
pnpm typecheck   # also checks that worker-configuration.d.ts matches wrangler.jsonc
pnpm lint
```

After changing `wrangler.jsonc`, run `pnpm cf-typegen` and commit `worker-configuration.d.ts`.
Production deploys run only from `main`, through the `deploy` workflow, after owner approval.

## Documents

- [Design](docs/DESIGN.md): scope, architecture, flows, protocol surface, data model,
  infrastructure, CI/CD
- [Threat model](docs/THREAT_MODEL.md): assets, trust boundaries, threats, mitigations, residual
  risks
- [Data protection](docs/DATA_PROTECTION.md): GDPR notes: data inventory, retention, rights
- [Gateway integration](docs/GATEWAY_INTEGRATION.md): what the MCP gateway needs from this service:
  token validation over a Service Binding, scopes, constraints, open decisions

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE)
