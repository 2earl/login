import { LOGIN_AUTHZ } from './authz/login-manifest';
import type { ServiceAuthz, SystemRole } from './authz/types';

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
   * Whether the service keeps data for organizations (DESIGN §4.14). If so, deleting an
   * organization reaches its `AccountEvents.deleteOrganization(orgId)` too, like account deletion.
   */
  organizationEvents?: boolean;
  /**
   * Whether the resource checks DPoP proofs (DESIGN §4.15). Only then are its access tokens bound
   * to the client's key; for any other resource a client with a proof gets a bearer token
   * (`token_type: bearer`, RFC 9449 §5), and its refresh token is bound all the same.
   */
  dpop?: boolean;
  /**
   * Narrower addresses of the same service, each its own resource with a subset of its scopes.
   * The MCP gateway serves every 2earl service at `/mcp` and each one alone at `/<service>`
   * (2earl/mcp docs/DESIGN.md §3): a token for one address is useless at another.
   */
  endpoints?: readonly { name: string; resource(env: Env): string; scopes: readonly string[] }[];
  /**
   * The service's permissions and system roles (DESIGN §4.32), for services whose data people
   * share and that ask login what someone may do. Services without one aren't in the
   * authorization API.
   */
  authz?: ServiceAuthz;
  /**
   * Scopes only some clients may ask for (DESIGN §4.32, phase 13c): an app's own sign-in scope is
   * for that app, not for any app that knows its name. Scope → the client IDs allowed. Scopes
   * not listed: any client, after the person's consent.
   */
  firstPartyClients?: Readonly<Record<string, (env: Env) => readonly string[]>>;
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
    firstPartyClients: {
      'promptshare:account': (env) => [`${env.PROMPTSHARE_RESOURCE}/oauth/client.json`],
    },
  },
  {
    // Emanet (2earl/emanet-core and its apps). One core keeps the data, so one deletion and one
    // export; each app is its own resource with its own scope, so a token for one app is useless
    // at another. Creditors are organizations, so deleting one reaches Emanet too.
    id: 'emanet',
    name: 'Emanet Kurumsal',
    resource: (env) => env.EMANET_KURUMSAL_RESOURCE,
    scopes: {
      'emanet:partner': 'Sign in to Emanet Kurumsal for your organization',
      'emanet:field': 'Sign in to Emanet Saha as a field agent',
      'emanet:control': 'Sign in to Emanet Merkez as 2earl staff',
    },
    deletionBinding: 'EMANET_EVENTS',
    organizationEvents: true,
    // Each app signs in with its own metadata document (2earl/emanet-* src/auth.ts).
    firstPartyClients: {
      'emanet:partner': (env) => [`${env.EMANET_KURUMSAL_RESOURCE}/oauth/client.json`],
      'emanet:field': (env) => [`${env.EMANET_SAHA_RESOURCE}/oauth/client.json`],
      'emanet:control': (env) => [`${env.EMANET_MERKEZ_RESOURCE}/oauth/client.json`],
    },
    // What the two apps' `can` maps decided before phase 13 (emanet-kurumsal and emanet-merkez
    // src/core.ts): with no assignments, the defaults give exactly that.
    authz: {
      permissions: {
        'emanet:cases.read': 'See the organization’s cases',
        'emanet:cases.write': 'Add, change, confirm and withdraw cases, and upload files of cases',
        'emanet:integrations.manage':
          'Manage API keys and webhooks, which act for the organization',
        'emanet:control.review': 'Open Emanet Merkez and settle identity reviews',
        'emanet:control.change':
          'Change partners, agents and settings, confirm deliveries and move money in Emanet Merkez',
      },
      roles: {
        'emanet:partner_admin': {
          name: 'Partner admin',
          assignable: 'org',
          permissions: ['emanet:cases.read', 'emanet:cases.write', 'emanet:integrations.manage'],
        },
        'emanet:case_manager': {
          name: 'Case manager',
          assignable: 'org',
          permissions: ['emanet:cases.read', 'emanet:cases.write'],
        },
        'emanet:viewer': {
          name: 'Viewer',
          assignable: 'org',
          permissions: ['emanet:cases.read'],
        },
        'emanet:staff_admin': {
          name: 'Merkez admin',
          assignable: 'platform',
          privileged: true,
          permissions: ['emanet:control.review', 'emanet:control.change'],
        },
        'emanet:staff_reviewer': {
          name: 'Merkez reviewer',
          assignable: 'platform',
          permissions: ['emanet:control.review'],
        },
      },
      orgDefaults: {
        owner: 'emanet:partner_admin',
        admin: 'emanet:partner_admin',
        member: 'emanet:case_manager',
        auditor: 'emanet:viewer',
      },
      staffDefaults: {
        owner: 'emanet:staff_admin',
        admin: 'emanet:staff_admin',
        support: 'emanet:staff_reviewer',
      },
      scopeGrants: {
        'emanet:partner': ['emanet:cases.read', 'emanet:cases.write', 'emanet:integrations.manage'],
        'emanet:control': ['emanet:control.review', 'emanet:control.change'],
        // Field agents' rights are their status in emanet-core, not roles.
        'emanet:field': [],
      },
    },
    endpoints: [
      {
        name: 'Emanet Saha',
        resource: (env) => env.EMANET_SAHA_RESOURCE,
        scopes: ['emanet:field'],
      },
      {
        name: 'Emanet Merkez',
        resource: (env) => env.EMANET_MERKEZ_RESOURCE,
        scopes: ['emanet:control'],
      },
    ],
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
    organizations: 'See which organizations you belong to, and your role in each',
  },
  deletionBinding: '',
  // /userinfo checks proofs (src/token-check.ts).
  dpop: true,
  // login's own rules for organizations and staff (DESIGN §4.32).
  authz: LOGIN_AUTHZ,
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
        ...(service.dpop ? { dpop: true } : {}),
        ...(service.authz ? { authz: service.authz } : {}),
        ...(service.firstPartyClients ? { firstPartyClients: service.firstPartyClients } : {}),
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

// ---- Authorization (DESIGN §4.32) ---------------------------------------------------------------

/** The services in the authorization API: login itself, and every service with a manifest. */
export const AUTHZ_SERVICES: readonly (Service & { authz: ServiceAuthz })[] = [
  IDENTITY,
  ...SERVICES,
].filter((s): s is Service & { authz: ServiceAuthz } => s.authz !== undefined);

/** A service's manifest by its ID, or undefined if it has none. */
export function authzOf(serviceId: string): ServiceAuthz | undefined {
  return AUTHZ_SERVICES.find((s) => s.id === serviceId)?.authz;
}

/** A system role by its full ID (`<service>:<name>`). */
export function systemRole(roleId: string): SystemRole | undefined {
  const service = roleId.slice(0, Math.max(0, roleId.indexOf(':')));
  return authzOf(service)?.roles[roleId];
}

/** Whether a service declares this permission. */
export function permissionExists(permission: string): boolean {
  const service = permission.slice(0, Math.max(0, permission.indexOf(':')));
  return Object.hasOwn(authzOf(service)?.permissions ?? {}, permission);
}
