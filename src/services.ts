/**
 * The 2earl services that accept tokens from this server (DESIGN §4.8). Each declares its own
 * resource URL, its own permissions and where it receives account-deletion notices.
 *
 * Adding a service:
 * 1. an entry here (scopes prefixed with its `id`, worded for the consent page);
 * 2. once the service is deployed: a Service Binding named `deletionBinding` in wrangler.jsonc to
 *    its `AccountEvents` entrypoint (docs/GATEWAY_INTEGRATION.md §5). Notices for deletions made
 *    before the binding exists wait in `deletion_notices` and are delivered then.
 */

export interface Service {
  /** Short, stable identifier. Every scope of the service starts with `${id}:`. */
  id: string;
  /** How the service reads on the consent page and in /admin. */
  name: string;
  /** Canonical resource URL (RFC 8707): the only audience its tokens are issued for. */
  resource(env: Env): string;
  /** Scope → what the user is agreeing to, in their words. */
  scopes: Readonly<Record<string, string>>;
  /**
   * Service Binding to the service's `AccountEvents` entrypoint: `deleteUser(userId)` when an
   * account is deleted, `exportUser(userId)` for "Download your data".
   */
  deletionBinding: string;
  /**
   * Narrower addresses of the same service, each its own resource with a subset of its scopes.
   * The MCP gateway serves every 2earl service at `/mcp` and each one alone at `/<service>`
   * (2earl/mcp docs/DESIGN.md §3): a token for one address is useless at another.
   */
  endpoints?: readonly { name: string; resource(env: Env): string; scopes: readonly string[] }[];
}

export const SERVICES: readonly Service[] = [
  {
    id: 'mcp',
    name: '2earl MCP gateway',
    resource: (env) => env.MCP_RESOURCE,
    // The gateway's own scope, and one set per service behind it, prefixed `mcp:<service>.`
    // (2earl/mcp docs/DESIGN.md §4). Write implies read; the gateway enforces the hierarchy.
    scopes: {
      'mcp:tools.read': 'See which tools are available to you',
      'mcp:promptshare.read': 'Read your prompts and public prompts in Prompt share',
      'mcp:promptshare.write': 'Create, change and delete your prompts in Prompt share',
      'mcp:promptshare.state':
        'Save to and read your shared sessions in Prompt share, including ones other people can see',
    },
    deletionBinding: 'MCP_GATEWAY_EVENTS',
    endpoints: [
      {
        // Prompt share's own MCP address, the one its directory listing uses.
        name: 'Prompt share',
        resource: (env) => `${new URL(env.MCP_RESOURCE).origin}/promptshare`,
        scopes: ['mcp:promptshare.read', 'mcp:promptshare.write', 'mcp:promptshare.state'],
      },
    ],
  },
  {
    // Prompt share (2earl/promptshare). Its own data, so its own deletion and export. The scope
    // is for its website's sign-in (phase P2); assistants use the `mcp:promptshare.*` scopes.
    id: 'promptshare',
    name: 'Prompt share',
    resource: (env) => env.PROMPTSHARE_RESOURCE,
    scopes: {
      'promptshare:account': 'Sign in to Prompt share',
    },
    deletionBinding: 'PROMPTSHARE_EVENTS',
  },
];

/**
 * login itself, as an OpenID Connect provider (DESIGN §4.11): "Sign in with 2earl" for any site
 * or app. Not a 2earl service: no data of its own to delete or export, so it is not in
 * SERVICES. Its resource is the UserInfo endpoint, the one place its tokens are accepted, and it
 * is the default audience when an OpenID Connect client sends no `resource`.
 */
export const IDENTITY: Service = {
  id: 'login',
  name: 'Your 2earl account',
  resource: (env) => `${env.ISSUER}/userinfo`,
  scopes: {
    openid: 'Sign you in with your 2earl account, with an ID only this app gets',
    profile: 'See your name',
    email: 'See your email address',
  },
  deletionBinding: '',
};

/** Every scope of every service, with its consent wording. */
export const ALL_SCOPES: Readonly<Record<string, string>> = Object.assign(
  {},
  IDENTITY.scopes,
  ...SERVICES.map((service) => service.scopes),
) as Record<string, string>;

/**
 * The service a resource belongs to. For one of its narrower endpoints: the same service, named
 * and scoped as that endpoint, so consent offers and tokens carry only the endpoint's scopes.
 */
export function serviceForResource(env: Env, resource: string | undefined): Service | undefined {
  if (resource === undefined) return undefined;
  if (resource === IDENTITY.resource(env)) return IDENTITY;
  for (const service of SERVICES) {
    if (service.resource(env) === resource) return service;
    const endpoint = service.endpoints?.find((e) => e.resource(env) === resource);
    if (endpoint) {
      return {
        id: service.id,
        name: endpoint.name,
        resource: (e: Env) => endpoint.resource(e),
        scopes: Object.fromEntries(
          endpoint.scopes.map((scope) => [scope, service.scopes[scope] ?? scope]),
        ),
        deletionBinding: service.deletionBinding,
      };
    }
  }
  return undefined;
}

/** Every resource tokens may be issued for: each service's, and each of its endpoints'. */
export function allResources(env: Env): string[] {
  return [
    ...SERVICES.flatMap((s) => [
      s.resource(env),
      ...(s.endpoints ?? []).map((e) => e.resource(env)),
    ]),
    IDENTITY.resource(env),
  ];
}

export function serviceById(id: string): Service | undefined {
  return SERVICES.find((s) => s.id === id);
}

/** Plain-language label for a scope; unknown scopes are shown as they are. */
export function scopeLabel(scope: string): string {
  return ALL_SCOPES[scope] ?? scope;
}

/** Only the scopes that belong to `service`: a token for one service never carries another's. */
export function scopesFor(service: Service, scopes: readonly string[]): string[] {
  return scopes.filter((scope) => Object.hasOwn(service.scopes, scope));
}
