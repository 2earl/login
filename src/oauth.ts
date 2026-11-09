import {
  GrantType,
  OAuthAuthorizationServer,
  OAuthError,
} from '@cloudflare/workers-oauth-provider';
import { audit } from './audit';
import { ALL_SCOPES, SERVICES, scopeLabel } from './services';
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
}

/** Unix seconds. The same clock stamps `authTime` (app.ts) and checks it here. */
let clock = (): number => Math.floor(Date.now() / 1000);

/** Tests only: run the authorization server on the app's injected clock. */
export function setOAuthClock(now: () => number): void {
  clock = now;
}

const servers = new Map<string, OAuthAuthorizationServer<Env>>();

/** One server per issuer/resource configuration; built once per isolate. */
export function authorizationServer(env: Env): OAuthAuthorizationServer<Env> {
  const resources = SERVICES.map((service) => service.resource(env));
  const key = `${env.ISSUER}|${resources.join(' ')}`;
  let server = servers.get(key);
  if (!server) {
    server = new OAuthAuthorizationServer<Env>({
      issuer: env.ISSUER,
      resources,
      scopesSupported: Object.keys(SCOPES),
      // MCP 2026-07-28 client registration. Needs the global_fetch_strictly_public flag
      // (wrangler.jsonc), which keeps metadata fetches off private and same-zone addresses.
      clientIdMetadataDocumentEnabled: true,
      accessTokenTTL: ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenTTL: REFRESH_TOKEN_TTL_SECONDS,
      refreshTokenIdleTTL: REFRESH_TOKEN_IDLE_TTL_SECONDS,
      tokenExchangeCallback: async ({ grantType, props, userId, grantId, env }) => {
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
        if (grantType !== GrantType.REFRESH_TOKEN) return;
        // Absolute grant lifetime: however often a grant is refreshed, it ends 90 days after
        // the user approved it, and the user signs in again.
        const { authTime } = props as GrantProps;
        const remaining = authTime + GRANT_MAX_AGE_SECONDS - clock();
        if (remaining < 60) {
          throw new OAuthError('invalid_grant', {
            description: 'This authorization has expired. Sign in again.',
          });
        }
        return { refreshTokenIdleTTL: Math.min(REFRESH_TOKEN_IDLE_TTL_SECONDS, remaining) };
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
