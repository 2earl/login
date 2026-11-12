import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken } from '../src/crypto';
import { createResourceServer } from '../src/introspection';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  consentBody,
  makeApp,
  parseConsent,
  resetDatabase,
  setCookies,
  signIn,
} from './helpers';

/** Phase 8c (DESIGN §4.12): token introspection (RFC 7662) and step-up (RFC 9470). */

const REDIRECT_URI = 'https://app.example/callback';
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };

let app: ReturnType<typeof makeApp>;
let google: FakeGoogle;
let session: string;
let clientId: string;
let now: number;

async function accessToken(resource: string = env.MCP_RESOURCE, scope = 'mcp:tools.read') {
  const verifier = randomToken(48);
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope,
    state: 's',
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    resource,
  });
  const page = await call(app, `/authorize?${query.toString()}`, {
    cookies: { '__Host-session': session },
  });
  const handle = parseConsent(await page.text());
  const approved = await call(app, '/authorize', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body: consentBody(handle, { decision: 'approve', scope }),
    cookies: { '__Host-session': session, ...setCookies(page) },
  });
  const code = new URL(approved.headers.get('Location') ?? 'about:blank').searchParams.get('code');
  const response = await call(app, '/oauth/token', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code ?? '',
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
      resource,
    }),
  });
  return response.json<{ access_token: string; refresh_token: string }>();
}

function introspect(token: string, credentials: string | null) {
  return call(app, '/oauth/introspect', {
    method: 'POST',
    headers: {
      ...FORM,
      ...(credentials ? { Authorization: `Basic ${btoa(credentials)}` } : {}),
    },
    body: new URLSearchParams({ token }),
  });
}

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  await env.DB.prepare('DELETE FROM resource_servers').run();
  google = new FakeGoogle();
  app = makeApp(google, () => now);
  session = (await signIn(app, google)).session ?? '';
  clientId = (
    await authorizationServer(env)
      .getOAuthApi(env)
      .createClient({
        redirectUris: [REDIRECT_URI],
        clientName: 'App',
        tokenEndpointAuthMethod: 'none',
      })
  ).clientId;
});

describe('token introspection (RFC 7662)', () => {
  it('is announced in the server metadata', async () => {
    for (const path of [
      '/.well-known/oauth-authorization-server',
      '/.well-known/openid-configuration',
    ]) {
      const meta = await (await call(app, path)).json<Record<string, unknown>>();
      expect(meta.introspection_endpoint, path).toBe(`${ORIGIN}/oauth/introspect`);
      expect(meta.introspection_endpoint_auth_methods_supported, path).toEqual([
        'client_secret_basic',
      ]);
    }
  });

  it('describes an active token for the server’s own resource, with when and how the person signed in', async () => {
    const rs = await createResourceServer(env.DB, now, 'Gateway mirror', env.MCP_RESOURCE);
    const { access_token } = await accessToken();
    const response = await introspect(access_token, `${rs.id}:${rs.secret}`);
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    const body = await response.json<Record<string, unknown>>();
    const user = await env.DB.prepare('SELECT id FROM users').first<{ id: string }>();
    expect(body).toMatchObject({
      active: true,
      token_type: 'Bearer',
      scope: 'mcp:tools.read',
      client_id: clientId,
      sub: user?.id,
      aud: env.MCP_RESOURCE,
      iss: ORIGIN,
      acr: 'urn:2earl:aal1',
      amr: ['fed'],
    });
    expect(typeof body.exp).toBe('number');
    expect(typeof body.auth_time).toBe('number');
  });

  it('reports a token for another resource, a refresh token or garbage as simply inactive', async () => {
    const rs = await createResourceServer(env.DB, now, 'Gateway mirror', env.MCP_RESOURCE);
    const credentials = `${rs.id}:${rs.secret}`;
    const oidc = await accessToken(`${ORIGIN}/userinfo`, 'openid');
    for (const token of [oidc.access_token, oidc.refresh_token, 'not-a-token']) {
      const response = await introspect(token, credentials);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ active: false });
    }
  });

  it('reports a revoked token as inactive', async () => {
    const rs = await createResourceServer(env.DB, now, 'Gateway mirror', env.MCP_RESOURCE);
    const { access_token } = await accessToken();
    const oauth = authorizationServer(env).getOAuthApi(env);
    const user = await env.DB.prepare('SELECT id FROM users').first<{ id: string }>();
    const grants = await oauth.listUserGrants(user?.id ?? '');
    await oauth.revokeGrant(grants.items[0]?.id ?? '', user?.id ?? '');
    expect(await (await introspect(access_token, `${rs.id}:${rs.secret}`)).json()).toEqual({
      active: false,
    });
  });

  it('needs the resource server’s own credentials', async () => {
    const rs = await createResourceServer(env.DB, now, 'Gateway mirror', env.MCP_RESOURCE);
    const { access_token } = await accessToken();
    for (const credentials of [null, `${rs.id}:wrong`, `rs_unknown:${rs.secret}`, 'garbage']) {
      const response = await introspect(access_token, credentials);
      expect(response.status, String(credentials)).toBe(401);
      expect(response.headers.get('WWW-Authenticate')).toContain('Basic');
    }
    const noToken = await call(app, '/oauth/introspect', {
      method: 'POST',
      headers: { ...FORM, Authorization: `Basic ${btoa(`${rs.id}:${rs.secret}`)}` },
      body: '',
    });
    expect(noToken.status).toBe(400);
  });
});

describe('step-up (RFC 9470)', () => {
  it('honours max_age for any app: an old sign-in is redone before consent', async () => {
    now += 3600;
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      scope: 'mcp:tools.read',
      code_challenge: await pkceChallenge(randomToken(48)),
      code_challenge_method: 'S256',
      resource: env.MCP_RESOURCE,
      max_age: '300',
    });
    const response = await call(app, `/authorize?${query.toString()}`, {
      cookies: { '__Host-session': session },
    });
    const location = new URL(response.headers.get('Location') ?? 'about:blank', ORIGIN);
    expect(location.pathname).toBe('/login');
    expect(location.searchParams.get('reauth')).toBe('1');
    expect(location.searchParams.get('return_to')).not.toContain('max_age');
  });
});
