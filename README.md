# login

Identity service and OAuth 2.1 authorization server for 2earl.com, served at
`https://login.2earl.com`. Runs on Cloudflare Workers.

**Status:** design phase. No authentication code yet.

## Documents

- [Design](docs/DESIGN.md): scope, architecture, flows, protocol surface, data model,
  infrastructure, CI/CD
- [Threat model](docs/THREAT_MODEL.md): assets, trust boundaries, threats, mitigations, residual
  risks
- [Data protection](docs/DATA_PROTECTION.md): GDPR notes: data inventory, retention, rights

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE)
