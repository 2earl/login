import {
  GrantType,
  OAuthAuthorizationServer,
  OAuthError,
} from '@cloudflare/workers-oauth-provider';
import { audit } from './audit';
import { dpopOf } from './dpop';
import type { SignInMethod } from './sessions';
import { ALL_SCOPES, IDENTITY, allResources, scopeLabel, serviceForResource } from './services';
import { isUserActive } from './users';

/**
 * The OAuth 2.1 authorization server for apps (MCP clients). Built on
 * @cloudflare/workers-oauth-provider in its split authorization-server role
 * (docs/DESIGN.md §5). The library owns metadata, the token endpoint and revocation; this
 * Worker owns /authorize, sign-in and consent.
 */

/** Every scope this server can grant, from the service registry (src/services.ts). */
export const SCOPES = ALL_SCOPES;
export { scopeLabel };

/** DESIGN §5.2 */
export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
export const REFRESH_TOKEN_IDLE_TTL_SECONDS = 7 * 24 * 60 * 60;
export const GRANT_MAX_AGE_SECONDS = 90 * 24 * 60 * 60;

/**
 * Stored encrypted with each grant. Kept to an internal user ID and the time of authorization:
 * no email or name (DESIGN §6.2).
 */
export interface GrantProps {
  uid: string;
  authTime: number;
  /**
   * When the user last verified a second factor in the session that approved this grant, or
   * null. Apps that need a recent second factor (`acr_values=urn:2earl:aal2`) check it.
   */
  aal2At: number | null;
  /**
   * When the person signed in to the session that approved this grant, and how (RFC 9470 and
   * OIDC `auth_time`/`amr`). Grants from before phase 8c don't have them.
   */
  signedInAt?: number;
  method?: SignInMethod | null;
  /** The key this grant's refresh tokens are bound to (DPoP, DESIGN §4.15). */
  dpopJkt?: string;
  /** Access tokens only: the key the token is bound to (RFC 9449 §6.1). */
  cnf?: { jkt: string };
  /** OpenID Connect grants only (DESIGN §4.11). */
  oidc?: {
    /** The pairwise subject this app knows the user by (`oidc_subjects`). */
    sub: string;
    /** The app's `nonce`, returned once, in the ID token of the code exchange. */
    nonce: string | null;
    /** Phase 8b grants carried these here; newer grants have them at the top level. */
    signedInAt?: number;
    method?: SignInMethod | null;
  };
}

/**
 * DPoP at the token endpoint (DESIGN §4.15, RFC 9449 §5). The token endpoint checked the proof and
 * put its key in `env` (src/dpop.ts); here the grant and the token are bound to it.
 * - A grant bound to a key (`dpopJkt`) is refreshed only with a proof from that key.
 * - The first proof binds the grant, so its refresh tokens are useless without the key.
 * - The access token is bound (`cnf.jkt`) only for a resource that checks proofs; otherwise the
 *   client gets a bearer token, as RFC 9449 allows.
 */
function dpopBinding(
  env: Env,
  props: GrantProps,
  resource: string,
): { newProps?: GrantProps; accessTokenProps?: GrantProps } | undefined {
  const dpop = dpopOf(env);
  const bound = props.dpopJkt ?? null;
  if (bound && dpop?.jkt !== bound) {
    throw new OAuthError('invalid_grant', {
      description: 'This grant is bound to a key: send a DPoP proof made with it.',
    });
  }
  if (!dpop) return undefined;
  const result: { newProps?: GrantProps; accessTokenProps?: GrantProps } = {};
  const grantProps = bound ? props : { ...props, dpopJkt: dpop.jkt };
  if (!bound) result.newProps = grantProps;
  if (serviceForResource(env, resource)?.dpop) {
    result.accessTokenProps = { ...grantProps, cnf: { jkt: dpop.jkt } };
    dpop.accessTokenBound = true;
  }
  return result;
}

/** `acr_values` an app sends to require a recent second factor before login approves. */
export const ACR_AAL2 = 'urn:2earl:aal2';

/** Unix seconds. The same clock stamps `authTime` (app.ts) and checks it here. */
let clock = (): number => Math.floor(Date.now() / 1000);

/** Tests only: run the authorization server on the app's injected clock. */
export function setOAuthClock(now: () => number): void {
  clock = now;
}

const servers = new Map<string, OAuthAuthorizationServer<Env>>();

/** One server per issuer/resource configuration; built once per isolate. */
export function authorizationServer(env: Env): OAuthAuthorizationServer<Env> {
  const resources = allResources(env);
  const key = `${env.ISSUER}|${resources.join(' ')}`;
  let server = servers.get(key);
  if (!server) {
    server = new OAuthAuthorizationServer<Env>({
      issuer: env.ISSUER,
      resources,
      // An OpenID Connect client that sends no `resource` gets a token for the UserInfo
      // endpoint; every other client must name its resource (app.ts checks that).
      defaultResource: IDENTITY.resource(env),
      scopesSupported: Object.keys(SCOPES),
      // MCP 2026-07-28 client registration. Needs the global_fetch_strictly_public flag
      // (wrangler.jsonc), which keeps metadata fetches off private and same-zone addresses.
      clientIdMetadataDocumentEnabled: true,
      accessTokenTTL: ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenTTL: REFRESH_TOKEN_TTL_SECONDS,
      refreshTokenIdleTTL: REFRESH_TOKEN_IDLE_TTL_SECONDS,
      tokenExchangeCallback: async ({ grantType, props, userId, grantId, env, resource }) => {
        // Every code exchange and refresh checks that the account still exists and is active.
        // Deletion and suspension revoke grants, but a grant created while that was running (a
        // consent submitted in another tab) is caught here, at the latest 15 minutes later.
        if (!(await isUserActive(env.DB, userId))) {
          await authorizationServer(env).getOAuthApi(env).revokeGrant(grantId, userId);
          await audit(env.DB, clock(), 'grant.refused', { detail: { reason: 'user_inactive' } });
          throw new OAuthError('invalid_grant', {
            description: 'This account is no longer active.',
          });
        }
        const binding = dpopBinding(env, props as GrantProps, resource);
        if (grantType !== GrantType.REFRESH_TOKEN) return binding;
        // Absolute grant lifetime: however often a grant is refreshed, it ends 90 days after
        // the user approved it, and the user signs in again.
        const { authTime } = props as GrantProps;
        const remaining = authTime + GRANT_MAX_AGE_SECONDS - clock();
        if (remaining < 60) {
          throw new OAuthError('invalid_grant', {
            description: 'This authorization has expired. Sign in again.',
          });
        }
        return {
          ...binding,
          refreshTokenIdleTTL: Math.min(REFRESH_TOKEN_IDLE_TTL_SECONDS, remaining),
        };
      },
      onError: ({ code, status, internal }) => {
        // Stable reason codes only; never request data or credentials.
        console.warn('oauth_error', code, status, internal.category, internal.reason);
      },
    });
    servers.set(key, server);
  }
  return server;
}
