import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken } from '../src/crypto';
import {
  ACCESS_TOKEN_TTL_SECONDS,
  GRANT_MAX_AGE_SECONDS,
  authorizationServer,
  setOAuthClock,
} from '../src/oauth';
import { CONSENT_CSP } from '../src/security-headers';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  count,
  makeApp,
  resetDatabase,
  setCookies,
  signIn,
  consentBody,
  parseConsent,
} from './helpers';

const REDIRECT_URI = 'https://client.example/callback';
const RESOURCE = env.MCP_RESOURCE;
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };

let google: FakeGoogle;
let app: ReturnType<typeof makeApp>;
let session: string;
let clientId: string;

function oauth() {
  return authorizationServer(env).getOAuthApi(env);
}

async function authorizeUrl(overrides: Record<string, string | null> = {}) {
  const verifier = randomToken(48);
  const params: Record<string, string | null> = {
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'mcp:tools.read mcp:tools.invoke',
    state: 'client-state-123',
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    resource: RESOURCE,
    ...overrides,
  };
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== null) query.set(key, value);
  return { path: `/authorize?${query.toString()}`, verifier };
}

/** Opens the consent page and returns the form handle and the cookies the browser now holds. */
async function openConsent(path: string, cookies: Record<string, string> = {}) {
  const response = await call(app, path, { cookies: { '__Host-session': session, ...cookies } });
  const html = await response.text();
  const handle = parseConsent(html);
  return { response, html, handle, cookies: { ...cookies, ...setCookies(response) } };
}

async function submitConsent(
  handle: string,
  cookies: Record<string, string>,
  fields: Record<string, string | string[]> = {},
  headers: Record<string, string> = SAME_ORIGIN,
) {
  const body = consentBody(handle);
  const all = { decision: 'approve', scope: ['mcp:tools.read', 'mcp:tools.invoke'], ...fields };
  for (const [key, value] of Object.entries(all)) {
    for (const v of Array.isArray(value) ? value : [value]) body.append(key, v);
  }
  return call(app, '/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
    body,
    cookies: { '__Host-session': session, ...cookies },
  });
}

async function exchangeCode(code: string, verifier: string, extra: Record<string, string> = {}) {
  const response = await call(app, '/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
      resource: RESOURCE,
      ...extra,
    }),
  });
  return { response, body: await response.json<Record<string, unknown>>() };
}

/** Runs authorize → consent → token and returns the token response. */
async function authorizeAndExchange() {
  const { path, verifier } = await authorizeUrl();
  const consent = await openConsent(path);
  const approved = await submitConsent(consent.handle, consent.cookies);
  const location = new URL(approved.headers.get('Location') ?? 'about:blank');
  const code = location.searchParams.get('code') ?? '';
  return { ...(await exchangeCode(code, verifier)), consent, approved, location };
}

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  google = new FakeGoogle();
  app = makeApp(google);
  session = (await signIn(app, google)).session ?? '';
  const client = await oauth().createClient({
    redirectUris: [REDIRECT_URI],
    clientName: 'Test MCP Client',
    tokenEndpointAuthMethod: 'none',
  });
  clientId = client.clientId;
});

describe('authorization server metadata', () => {
  it('advertises the endpoints, PKCE S256, RFC 9207 and CIMD, and no registration', async () => {
    const response = await call(app, '/.well-known/oauth-authorization-server');
    expect(response.status).toBe(200);
    const meta = await response.json<Record<string, unknown>>();
    expect(meta.issuer).toBe(ORIGIN);
    expect(meta.authorization_endpoint).toBe(`${ORIGIN}/authorize`);
    expect(meta.token_endpoint).toBe(`${ORIGIN}/oauth/token`);
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
    expect(meta.authorization_response_iss_parameter_supported).toBe(true);
    expect(meta.client_id_metadata_document_supported).toBe(true);
    expect(meta.registration_endpoint).toBeUndefined();
    expect(meta.scopes_supported).toEqual(['mcp:tools.read', 'mcp:tools.invoke']);
    expect(meta.protected_resources).toEqual([RESOURCE]);
  });
});

describe('authorization code flow', () => {
  it('issues a resource-bound token after consent', async () => {
    const { response, body, location } = await authorizeAndExchange();

    expect(location.origin + location.pathname).toBe(REDIRECT_URI);
    expect(location.searchParams.get('state')).toBe('client-state-123');
    expect(location.searchParams.get('iss')).toBe(ORIGIN);

    expect(response.status).toBe(200);
    expect(body.token_type).toMatch(/^bearer$/i);
    expect(body.expires_in).toBe(ACCESS_TOKEN_TTL_SECONDS);
    expect(typeof body.refresh_token).toBe('string');

    const validated = await authorizationServer(env).validateToken(
      RESOURCE,
      String(body.access_token),
      env,
    );
    expect(validated?.audience).toBe(RESOURCE);
    expect(validated?.clientId).toBe(clientId);
    expect(validated?.scope).toEqual(['mcp:tools.read', 'mcp:tools.invoke']);
    const user = await env.DB.prepare('SELECT id FROM users').first<{ id: string }>();
    expect(validated?.props).toMatchObject({ uid: user?.id });
    expect(JSON.stringify(validated?.props)).not.toContain('@');
  });

  it('only grants the scopes the user left ticked', async () => {
    const { path, verifier } = await authorizeUrl();
    const consent = await openConsent(path);
    const approved = await submitConsent(consent.handle, consent.cookies, {
      scope: ['mcp:tools.read'],
    });
    const code = new URL(approved.headers.get('Location') ?? '').searchParams.get('code') ?? '';
    const { body } = await exchangeCode(code, verifier);
    expect(String(body.scope)).toBe('mcp:tools.read');
  });

  it('rejects the token for any other resource', async () => {
    const { body } = await authorizeAndExchange();
    await expect(
      authorizationServer(env).validateToken(
        'https://other.example/mcp',
        String(body.access_token),
        env,
      ),
    ).rejects.toThrow();
  });

  it('refreshes, rotating the refresh token', async () => {
    const { body } = await authorizeAndExchange();
    const response = await call(app, '/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: String(body.refresh_token),
        client_id: clientId,
      }),
    });
    expect(response.status).toBe(200);
    const refreshed = await response.json<Record<string, unknown>>();
    expect(refreshed.access_token).not.toBe(body.access_token);
    expect(refreshed.refresh_token).not.toBe(body.refresh_token);
  });

  it('stops refreshing 90 days after the user approved, however often it was refreshed', async () => {
    const { body } = await authorizeAndExchange();
    setOAuthClock(() => NOW + GRANT_MAX_AGE_SECONDS + 1);
    const response = await call(app, '/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: String(body.refresh_token),
        client_id: clientId,
      }),
    });
    expect(response.status).toBe(400);
    expect((await response.json<{ error: string }>()).error).toBe('invalid_grant');
  });

  it('cannot exchange a code twice', async () => {
    const { path, verifier } = await authorizeUrl();
    const consent = await openConsent(path);
    const approved = await submitConsent(consent.handle, consent.cookies);
    const code = new URL(approved.headers.get('Location') ?? '').searchParams.get('code') ?? '';
    expect((await exchangeCode(code, verifier)).response.status).toBe(200);
    expect((await exchangeCode(code, verifier)).response.status).toBe(400);
  });

  it('rejects a wrong PKCE verifier', async () => {
    const { path } = await authorizeUrl();
    const consent = await openConsent(path);
    const approved = await submitConsent(consent.handle, consent.cookies);
    const code = new URL(approved.headers.get('Location') ?? '').searchParams.get('code') ?? '';
    expect((await exchangeCode(code, randomToken(48))).response.status).toBe(400);
  });
});

describe('/authorize request validation', () => {
  it('sends a signed-out user to sign-in and back', async () => {
    const { path } = await authorizeUrl();
    const response = await call(app, path);
    expect(response.status).toBe(303);
    const location = new URL(response.headers.get('Location') ?? '', ORIGIN);
    expect(location.pathname).toBe('/login');
    expect(location.searchParams.get('return_to')).toBe(path);
  });

  it.each([
    ['no PKCE', { code_challenge: null, code_challenge_method: null }, 'invalid_request'],
    ['plain PKCE', { code_challenge_method: 'plain' }, 'invalid_request'],
    ['no resource', { resource: null }, 'invalid_target'],
    ['an unknown resource', { resource: 'https://other.example/mcp' }, 'invalid_target'],
  ])('redirects back with an error for %s', async (_label, overrides, error) => {
    const { path } = await authorizeUrl(overrides);
    const response = await call(app, path, { cookies: { '__Host-session': session } });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.origin + location.pathname).toBe(REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe(error);
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
  });

  it.each([
    ['an unregistered redirect URI', { redirect_uri: 'https://evil.example/callback' }],
    ['an unknown client', { client_id: 'no-such-client' }],
  ])('never redirects for %s; it shows an error page', async (_label, overrides) => {
    const { path } = await authorizeUrl(overrides);
    const response = await call(app, path, {
      cookies: { '__Host-session': session },
      headers: { Accept: 'text/html' },
    });
    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
    expect(await response.text()).toContain('isn’t valid');
  });
});

describe('consent page', () => {
  it('names the app, where access goes, and each permission', async () => {
    const { path } = await authorizeUrl();
    const { response, html } = await openConsent(path);
    expect(response.status).toBe(200);
    expect(html).toContain('Test MCP Client');
    expect(html).toContain('client.example');
    expect(html).toContain('This app named itself');
    expect(html).toContain('2earl MCP gateway (mcp.2earl.com)');
    expect(html).toContain('See which tools are available to you');
    expect(html).toContain('Use those tools on your behalf');
  });

  it('cannot be framed and lets the approval redirect leave the site', async () => {
    const { path } = await authorizeUrl();
    const { response } = await openConsent(path);
    expect(response.headers.get('Content-Security-Policy')).toBe(CONSENT_CSP);
    expect(response.headers.get('Cache-Control')).toContain('no-store');
  });

  it('escapes what the client controls', async () => {
    const evil = await oauth().createClient({
      redirectUris: [REDIRECT_URI],
      clientName: '<img src=x onerror=alert(1)>',
      tokenEndpointAuthMethod: 'none',
    });
    clientId = evil.clientId;
    const { path } = await authorizeUrl();
    const { html } = await openConsent(path);
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('sends access_denied back to the app when the user denies', async () => {
    const { path } = await authorizeUrl();
    const consent = await openConsent(path);
    const response = await submitConsent(consent.handle, consent.cookies, { decision: 'deny' });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe('client-state-123');
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
  });

  it('treats an approval with every permission unticked as a denial', async () => {
    const { path } = await authorizeUrl();
    const consent = await openConsent(path);
    const response = await submitConsent(consent.handle, consent.cookies, { scope: [] });
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.searchParams.get('error')).toBe('access_denied');
  });

  it('refuses an approval posted from another site', async () => {
    const { path } = await authorizeUrl();
    const consent = await openConsent(path);
    const response = await submitConsent(
      consent.handle,
      consent.cookies,
      {},
      {
        Origin: 'https://evil.example',
        'Sec-Fetch-Site': 'cross-site',
      },
    );
    expect(response.status).toBe(403);
  });

  it('works once: a replayed approval is refused', async () => {
    const { path } = await authorizeUrl();
    const consent = await openConsent(path);
    expect((await submitConsent(consent.handle, consent.cookies)).status).toBe(302);
    expect((await submitConsent(consent.handle, consent.cookies)).status).toBe(400);
  });

  it('refuses an approval from a browser that did not open the page', async () => {
    const { path } = await authorizeUrl();
    const consent = await openConsent(path);
    const response = await submitConsent(consent.handle, {});
    expect(response.status).toBe(400);
  });

  it('is skipped next time when the user chose to be remembered', async () => {
    const first = await authorizeUrl();
    const consent = await openConsent(first.path);
    const approved = await submitConsent(consent.handle, consent.cookies, { remember: 'on' });
    const cookies = { ...consent.cookies, ...setCookies(approved) };

    const second = await authorizeUrl();
    const response = await call(app, second.path, {
      cookies: { '__Host-session': session, ...cookies },
    });
    expect(response.status).toBe(302);
    expect(new URL(response.headers.get('Location') ?? '').searchParams.get('code')).toBeTruthy();
    expect(await count('audit_events', "event = 'consent.reused'")).toBe(1);
  });
});

describe('connected apps', () => {
  it('lists an approved app on the account page', async () => {
    await authorizeAndExchange();
    const response = await call(app, '/account', { cookies: { '__Host-session': session } });
    const html = await response.text();
    expect(html).toContain('Test MCP Client');
    expect(html).toContain('Disconnect');
  });

  it('disconnecting revokes the app’s tokens immediately', async () => {
    const { body } = await authorizeAndExchange();
    const grants = await oauth().listUserGrants(
      (await env.DB.prepare('SELECT id FROM users').first<{ id: string }>())?.id ?? '',
    );
    const grantId = grants.items[0]?.id ?? '';

    const response = await call(app, '/account/apps/disconnect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...SAME_ORIGIN },
      body: new URLSearchParams({ grant: grantId }),
      cookies: { '__Host-session': session },
    });
    expect(response.status).toBe(303);
    expect(
      await authorizationServer(env).validateToken(RESOURCE, String(body.access_token), env),
    ).toBeNull();
    expect(await count('audit_events', "event = 'grant.revoked'")).toBe(1);
  });

  it('refuses a disconnect posted from another site', async () => {
    await authorizeAndExchange();
    const response = await call(app, '/account/apps/disconnect', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://evil.example',
      },
      body: new URLSearchParams({ grant: 'anything' }),
      cookies: { '__Host-session': session },
    });
    expect(response.status).toBe(403);
  });
});
