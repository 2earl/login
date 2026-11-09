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

/** Every scope of every service, with its consent wording. */
export const ALL_SCOPES: Readonly<Record<string, string>> = Object.assign(
  {},
  ...SERVICES.map((service) => service.scopes),
) as Record<string, string>;

export function serviceForResource(env: Env, resource: string | undefined): Service | undefined {
  return resource === undefined ? undefined : SERVICES.find((s) => s.resource(env) === resource);
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
