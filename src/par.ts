import type { Hono } from 'hono';
import type { Deps } from './app';
import { hmacHex, randomToken } from './crypto';
import { clientIp, type AppContext, type AppEnv } from './http';
import { authorizationServer } from './oauth';

/**
 * Pushed authorization requests, RFC 9126 (DESIGN §4.15). A client posts its authorization
 * request to login directly and gets a `request_uri`; the browser then carries only that and the
 * client ID, so nothing in the request can be read or changed on the way.
 */

export const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:';
/** Long enough to sign in with an email code on the way; the code still needs its PKCE verifier. */
export const PUSHED_REQUEST_TTL_SECONDS = 10 * 60;
const MAX_PARAMS_LENGTH = 8192;
const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

const idHash = (env: Env, id: string) => hmacHex(env.SESSION_PEPPER, `par:${id}`);

function parError(c: AppContext, error: string, description: string, status: 400 | 401 = 400) {
  return c.json({ error, error_description: description }, status, NO_STORE);
}

export function registerParRoute(app: Hono<AppEnv>, deps: Deps): void {
  app.post('/oauth/par', async (c) => {
    // Clients post from their servers or apps: the token endpoint's per-address limit.
    const { success } = await c.env.TOKEN_RATE_LIMITER.limit({ key: clientIp(c) ?? 'unknown' });
    if (!success) return c.json({ error: 'temporarily_unavailable' }, 429, NO_STORE);
    const form = await c.req.raw.formData().catch(() => null);
    if (!form) return parError(c, 'invalid_request', 'Send the request as a form');
    const params = new URLSearchParams();
    for (const [key, value] of form) {
      if (typeof value !== 'string') return parError(c, 'invalid_request', 'Text fields only');
      params.append(key, value);
    }
    if (params.has('request_uri')) {
      return parError(c, 'invalid_request', 'request_uri can’t be pushed');
    }
    if (params.has('request')) {
      return parError(c, 'request_not_supported', 'Request objects are not supported');
    }
    if (params.toString().length > MAX_PARAMS_LENGTH) {
      return parError(c, 'invalid_request', 'The request is too long');
    }
    const clientId = params.get('client_id');
    if (!clientId) return parError(c, 'invalid_request', 'client_id is required');

    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    let client;
    try {
      client = await oauth.lookupClient(clientId);
    } catch {
      client = null;
    }
    if (!client) return parError(c, 'invalid_client', 'Unknown client', 401);
    // Every client of login is public (DESIGN §4.1): no client secret to check.
    if (client.clientSecret) {
      return parError(c, 'invalid_client', 'Only public clients can push requests', 401);
    }
    // The same checks as the authorization endpoint's first step: client, redirect URI, PKCE.
    try {
      const request = await oauth.parseAuthRequest(
        new Request(`${c.env.ISSUER}/authorize?${params.toString()}`),
      );
      if (!request.codeChallenge || request.codeChallengeMethod !== 'S256') {
        return parError(c, 'invalid_request', 'PKCE with S256 is required');
      }
    } catch (error) {
      const description = error instanceof Error ? error.message : 'Invalid authorization request';
      return parError(c, 'invalid_request', description.slice(0, 200));
    }

    const now = deps.now();
    const id = randomToken(32);
    await c.env.DB.prepare(
      `INSERT INTO pushed_requests (id_hash, client_id, params, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind(
        await idHash(c.env, id),
        clientId,
        params.toString(),
        now,
        now + PUSHED_REQUEST_TTL_SECONDS,
      )
      .run();
    return c.json(
      { request_uri: `${REQUEST_URI_PREFIX}${id}`, expires_in: PUSHED_REQUEST_TTL_SECONDS },
      201,
      NO_STORE,
    );
  });
}

/**
 * For `/authorize?client_id=…&request_uri=…`: the pushed request's URL, with only what was pushed
 * (RFC 9126 §4: every other parameter in the browser's URL is ignored). Null when the request
 * doesn't use a `request_uri`; `'invalid'` when it names one that is unknown, expired or another
 * client's. A request URI works until it expires, so signing in on the way can come back to it.
 */
export async function pushedRequestUrl(
  env: Env,
  now: number,
  url: URL,
): Promise<URL | 'invalid' | null> {
  const requestUri = url.searchParams.get('request_uri');
  if (requestUri === null) return null;
  const clientId = url.searchParams.get('client_id');
  if (!requestUri.startsWith(REQUEST_URI_PREFIX) || !clientId) return 'invalid';
  const row = await env.DB.prepare(
    'SELECT client_id, params FROM pushed_requests WHERE id_hash = ? AND expires_at > ?',
  )
    .bind(await idHash(env, requestUri.slice(REQUEST_URI_PREFIX.length)), now)
    .first<{ client_id: string; params: string }>();
  if (!row || row.client_id !== clientId) return 'invalid';
  return new URL(`${env.ISSUER}/authorize?${row.params}`);
}
