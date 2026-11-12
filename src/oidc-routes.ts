import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import {
  SESSION_COOKIE,
  clearCookie,
  clientIp,
  isSameOrigin,
  workerCtx,
  type AppContext,
  type AppEnv,
} from './http';
import { ACR_AAL2, authorizationServer, type GrantProps } from './oauth';
import {
  ACR_AAL1,
  issueIdToken,
  publicKeys,
  readIdTokenHint,
  userClaims,
  userInfoResource,
} from './oidc';
import { DEVICE_GRANT } from './device';
import { signedOutPage, signOutPage } from './pages';
import { deleteSession } from './sessions';
import { ALL_SCOPES } from './services';

/**
 * OpenID Connect endpoints (DESIGN §4.11): discovery, keys, UserInfo, and RP-Initiated Logout.
 * The ID token itself is added to the library's token response in app.ts (`withIdToken`).
 */

/** Public, cacheable, readable from any site's script: metadata and keys hold no secrets. */
const PUBLIC_JSON = {
  'Access-Control-Allow-Origin': '*',
  'Cache-Control': 'public, max-age=3600',
};

/** UserInfo answers bearer requests from browsers too; no cookies are involved. */
const CORS_BEARER = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization',
  'Access-Control-Allow-Methods': 'GET, POST',
};

export const CLAIMS_SUPPORTED = [
  'sub',
  'iss',
  'aud',
  'exp',
  'iat',
  'auth_time',
  'nonce',
  'acr',
  'amr',
  'azp',
  'at_hash',
  'name',
  'email',
  'email_verified',
  'updated_at',
];

/**
 * Adds the ID token to a successful token response whose grant includes `openid`. Everything
 * else in the response is the library's, unchanged.
 */
export async function withIdToken(
  env: Env,
  now: number,
  grantType: string | null,
  response: Response,
): Promise<Response> {
  if (response.status !== 200) return response;
  const body = await response
    .clone()
    .json<Record<string, unknown>>()
    .catch(() => null);
  const accessToken = typeof body?.access_token === 'string' ? body.access_token : null;
  const scope = typeof body?.scope === 'string' ? body.scope.split(' ') : [];
  if (!body || !accessToken || !scope.includes('openid')) return response;

  const summary = await authorizationServer(env)
    .getOAuthApi(env)
    .unwrapToken<GrantProps>(accessToken);
  if (!summary) return response;
  const idToken = await issueIdToken(env, env.DB, {
    now,
    clientId: summary.grant.clientId,
    props: summary.grant.props,
    scope: summary.grant.scope,
    accessToken,
    // The nonce belongs to the authorization request: only the code exchange returns it.
    includeNonce: grantType === 'authorization_code',
  });
  if (!idToken) return response;

  const headers = new Headers(response.headers);
  headers.delete('Content-Length');
  return new Response(JSON.stringify({ ...body, id_token: idToken }), { status: 200, headers });
}

function bearerToken(c: AppContext): string | null {
  const header = c.req.header('Authorization') ?? '';
  // The library's tokens contain `:`, outside RFC 6750's b64token; any non-space value is read.
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match?.[1] ?? null;
}

function bearerError(
  c: AppContext,
  error: 'invalid_token' | 'insufficient_scope',
  status: 401 | 403,
) {
  return c.json({ error }, status, {
    ...CORS_BEARER,
    'WWW-Authenticate': `Bearer error="${error}"`,
  });
}

/**
 * The authorization server metadata (RFC 8414): the library's, plus what login adds around it
 * (introspection, DESIGN §4.12).
 */
async function serverMetadata(c: AppContext): Promise<Record<string, unknown>> {
  const meta = await authorizationServer(c.env)
    .fetch(
      new Request(`${c.env.ISSUER}/.well-known/oauth-authorization-server`),
      c.env,
      workerCtx(c),
    )
    .then((r) => r.json<Record<string, unknown>>());
  return {
    ...meta,
    introspection_endpoint: `${c.env.ISSUER}/oauth/introspect`,
    introspection_endpoint_auth_methods_supported: ['client_secret_basic'],
    device_authorization_endpoint: `${c.env.ISSUER}/oauth/device_authorization`,
    grant_types_supported: [
      ...(Array.isArray(meta.grant_types_supported)
        ? (meta.grant_types_supported as string[])
        : ['authorization_code', 'refresh_token']),
      DEVICE_GRANT,
    ],
  };
}

export function registerOidcRoutes(app: Hono<AppEnv>, deps: Deps): void {
  app.get('/.well-known/oauth-authorization-server', async (c) =>
    c.json(await serverMetadata(c), 200, PUBLIC_JSON),
  );

  app.get('/.well-known/openid-configuration', async (c) => {
    // OpenID Connect Discovery adds to the OAuth metadata (RFC 8414).
    const oauthMeta = await serverMetadata(c);
    return c.json(
      {
        ...oauthMeta,
        userinfo_endpoint: `${c.env.ISSUER}/userinfo`,
        jwks_uri: `${c.env.ISSUER}/.well-known/jwks.json`,
        end_session_endpoint: `${c.env.ISSUER}/oidc/logout`,
        scopes_supported: Object.keys(ALL_SCOPES),
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        subject_types_supported: ['pairwise'],
        id_token_signing_alg_values_supported: ['ES256'],
        acr_values_supported: [ACR_AAL1, ACR_AAL2],
        claims_supported: CLAIMS_SUPPORTED,
        claims_parameter_supported: false,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        prompt_values_supported: ['none', 'login', 'consent'],
        code_challenge_methods_supported: ['S256'],
      },
      200,
      PUBLIC_JSON,
    );
  });

  app.get('/.well-known/jwks.json', async (c) =>
    c.json({ keys: await publicKeys(c.env) }, 200, PUBLIC_JSON),
  );

  // ---- UserInfo (OIDC Core §5.3) -----------------------------------------------------------------

  app.options('/userinfo', (c) => c.body(null, 204, CORS_BEARER));

  const userinfo = async (c: AppContext) => {
    // Called by sites' servers, many users behind one address: the token endpoint's limit.
    const { success } = await c.env.TOKEN_RATE_LIMITER.limit({ key: clientIp(c) ?? 'unknown' });
    if (!success) return c.json({ error: 'temporarily_unavailable' }, 429, CORS_BEARER);
    const token = bearerToken(c);
    if (!token) return bearerError(c, 'invalid_token', 401);
    const validated = await authorizationServer(c.env).validateToken(
      userInfoResource(c.env),
      token,
      c.env,
    );
    const props = validated?.props as GrantProps | undefined;
    if (!validated || !props?.oidc) return bearerError(c, 'invalid_token', 401);
    const scope = validated.scope;
    if (!scope.includes('openid')) return bearerError(c, 'insufficient_scope', 403);
    const claims = await userClaims(c.env.DB, props.uid, scope);
    if (!claims) return bearerError(c, 'invalid_token', 401);
    return c.json({ sub: props.oidc.sub, ...claims }, 200, {
      ...CORS_BEARER,
      'Cache-Control': 'no-store',
    });
  };
  app.get('/userinfo', userinfo);
  app.post('/userinfo', userinfo);

  // ---- RP-Initiated Logout 1.0 ---------------------------------------------------------------

  /**
   * Where to send the browser afterwards: only an address the app registered as a redirect URI
   * (login has no separate list of logout addresses), for the app named by `client_id` or by an
   * ID token we issued. Anything else: no redirect, the signed-out page.
   */
  async function logoutTarget(
    c: AppContext,
    params: URLSearchParams,
  ): Promise<{ uri: string; state: string | null; appName: string | null } | null> {
    const uri = params.get('post_logout_redirect_uri');
    const hint = params.get('id_token_hint');
    const fromHint = hint ? await readIdTokenHint(c.env, hint) : null;
    const clientId = params.get('client_id') ?? fromHint?.clientId ?? null;
    if (!clientId || (fromHint && fromHint.clientId !== clientId)) return null;
    let client;
    try {
      client = await authorizationServer(c.env).getOAuthApi(c.env).lookupClient(clientId);
    } catch {
      return null;
    }
    if (!client) return null;
    if (!uri) return { uri: '', state: null, appName: client.clientName ?? null };
    if (!client.redirectUris.includes(uri)) return null;
    return { uri, state: params.get('state'), appName: client.clientName ?? null };
  }

  app.get('/oidc/logout', async (c) => {
    const params = new URL(c.req.url).searchParams;
    const target = await logoutTarget(c, params);
    if (!c.get('session')) {
      // Already signed out: go straight back, as the spec allows.
      return target?.uri
        ? c.redirect(withState(target.uri, target.state), 303)
        : c.html(signedOutPage());
    }
    // Ask first: a link on any site could otherwise sign people out (logout CSRF).
    return c.html(
      signOutPage({
        appName: target?.appName ?? null,
        query: params.toString(),
      }),
    );
  });

  app.post('/oidc/logout', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const form = await c.req.raw.formData();
    const query = form.get('query');
    const params = new URLSearchParams(typeof query === 'string' ? query : '');
    const session = c.get('session');
    if (session && form.get('decision') === 'sign_out') {
      await deleteSession(c.env.DB, session.idHash);
      await audit(c.env.DB, deps.now(), 'logout', {
        actorUserId: session.user.id,
        ipPrefix: clientIp(c),
        detail: { via: 'oidc' },
      });
      clearCookie(c, SESSION_COOKIE);
    } else if (session) {
      return c.redirect('/account', 303);
    }
    const target = await logoutTarget(c, params);
    return target?.uri
      ? c.redirect(withState(target.uri, target.state), 303)
      : c.html(signedOutPage());
  });
}

function withState(uri: string, state: string | null): string {
  if (!state) return uri;
  const url = new URL(uri);
  url.searchParams.set('state', state);
  return url.toString();
}
