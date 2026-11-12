import { env } from 'cloudflare:workers';
import { createLocalJWKSet, decodeJwt, jwtVerify, type JSONWebKeySet } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken } from '../src/crypto';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import { ID_TOKEN_TTL_SECONDS, sectorFor } from '../src/oidc';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  consentBody,
  count,
  makeApp,
  parseConsent,
  resetDatabase,
  setCookies,
  signIn,
} from './helpers';

/** Phase 8b (DESIGN §4.11): login as an OpenID Connect provider. */

const REDIRECT_URI = 'https://rp.example/callback';
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };

let google: FakeGoogle;
let app: ReturnType<typeof makeApp>;
let session: string;
let clientId: string;
let now: number;

async function newClient(redirectUri = REDIRECT_URI, name = 'Relying Party') {
  const client = await authorizationServer(env)
    .getOAuthApi(env)
    .createClient({
      redirectUris: [redirectUri],
      clientName: name,
      tokenEndpointAuthMethod: 'none',
    });
  return client.clientId;
}

async function authorizePath(overrides: Record<string, string | null> = {}, id = clientId) {
  const verifier = randomToken(48);
  const params: Record<string, string | null> = {
    response_type: 'code',
    client_id: id,
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile email',
    state: 'rp-state',
    nonce: 'rp-nonce-123',
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    ...overrides,
  };
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== null) query.set(key, value);
  return { path: `/authorize?${query.toString()}`, verifier };
}

async function approve(path: string, scope = ['openid', 'profile', 'email'], value = session) {
  const page = await call(app, path, { cookies: { '__Host-session': value } });
  const html = await page.text();
  const handle = parseConsent(html);
  const body = consentBody(handle, { decision: 'approve' });
  body.delete('scope');
  for (const s of scope) body.append('scope', s);
  const approved = await call(app, '/authorize', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body,
    cookies: { '__Host-session': value, ...setCookies(page) },
  });
  return { html, approved, location: new URL(approved.headers.get('Location') ?? 'about:blank') };
}

async function token(params: Record<string, string>) {
  const response = await call(app, '/oauth/token', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(params),
  });
  return { response, body: await response.json<Record<string, unknown>>() };
}

/** authorize → consent → code → tokens, as a relying party does it. */
async function signInWith2earl(overrides: Record<string, string | null> = {}, id = clientId) {
  const { path, verifier } = await authorizePath(overrides, id);
  const { location, html } = await approve(path);
  const code = location.searchParams.get('code') ?? '';
  const { response, body } = await token({
    grant_type: 'authorization_code',
    code,
    redirect_uri: overrides.redirect_uri ?? REDIRECT_URI,
    client_id: id,
    code_verifier: verifier,
  });
  return { response, body, location, html };
}

async function keySet() {
  const jwks = await (await call(app, '/.well-known/jwks.json')).json<JSONWebKeySet>();
  return createLocalJWKSet(jwks);
}

async function verified(idToken: unknown, audience = clientId) {
  const { payload, protectedHeader } = await jwtVerify(String(idToken), await keySet(), {
    issuer: ORIGIN,
    audience,
    currentDate: new Date(now * 1000),
  });
  return { payload, protectedHeader };
}

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  await env.DB.prepare('DELETE FROM oidc_subjects').run();
  google = new FakeGoogle();
  app = makeApp(google, () => now);
  session = (await signIn(app, google)).session ?? '';
  clientId = await newClient();
});

describe('discovery and keys', () => {
  it('publishes OpenID Connect metadata on top of the OAuth metadata', async () => {
    const response = await call(app, '/.well-known/openid-configuration');
    expect(response.status).toBe(200);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    const meta = await response.json<Record<string, unknown>>();
    expect(meta.issuer).toBe(ORIGIN);
    expect(meta.authorization_endpoint).toBe(`${ORIGIN}/authorize`);
    expect(meta.token_endpoint).toBe(`${ORIGIN}/oauth/token`);
    expect(meta.userinfo_endpoint).toBe(`${ORIGIN}/userinfo`);
    expect(meta.jwks_uri).toBe(`${ORIGIN}/.well-known/jwks.json`);
    expect(meta.end_session_endpoint).toBe(`${ORIGIN}/oidc/logout`);
    expect(meta.response_types_supported).toEqual(['code']);
    expect(meta.subject_types_supported).toEqual(['pairwise']);
    expect(meta.id_token_signing_alg_values_supported).toEqual(['ES256']);
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
    expect(meta.scopes_supported).toEqual(expect.arrayContaining(['openid', 'profile', 'email']));
  });

  it('publishes one public ES256 key, named by its thumbprint, and never the private part', async () => {
    const jwks = await (await call(app, '/.well-known/jwks.json')).json<{ keys: JsonWebKey[] }>();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
    expect(jwks.keys[0]).not.toHaveProperty('d');
    expect((jwks.keys[0] as { kid?: string }).kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('signing in with 2earl', () => {
  it('issues a signed ID token with the nonce, the sign-in time and how the person signed in', async () => {
    const { response, body, location, html } = await signInWith2earl();
    expect(html).toContain('<input type="checkbox" checked disabled>'); // openid can't be unticked
    expect(location.searchParams.get('state')).toBe('rp-state');
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
    expect(response.status).toBe(200);
    expect(body.scope).toBe('openid profile email');

    const { payload, protectedHeader } = await verified(body.id_token);
    expect(protectedHeader.alg).toBe('ES256');
    expect(payload.nonce).toBe('rp-nonce-123');
    expect(payload.azp).toBe(clientId);
    expect(payload.exp).toBe(now + ID_TOKEN_TTL_SECONDS);
    expect(payload.acr).toBe('urn:2earl:aal1');
    expect(payload.amr).toEqual(['fed']);
    expect(payload.email).toBe('ffrhtd@gmail.com');
    expect(payload.email_verified).toBe(true);
    expect(typeof payload.auth_time).toBe('number');
    expect(typeof payload.at_hash).toBe('string');

    // The subject is this site's own ID for the person, not the internal account ID.
    const user = await env.DB.prepare('SELECT id FROM users').first<{ id: string }>();
    expect(payload.sub).not.toBe(user?.id);
    expect(await count('oidc_subjects')).toBe(1);
  });

  it('answers UserInfo with the same subject and only the claims the scopes allow', async () => {
    const { body } = await signInWith2earl({ scope: 'openid email' });
    const sub = decodeJwt(String(body.id_token)).sub;
    const response = await call(app, '/userinfo', {
      headers: { Authorization: `Bearer ${String(body.access_token)}` },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      sub,
      email: 'ffrhtd@gmail.com',
      email_verified: true,
    });
  });

  it('refuses UserInfo without a token, or with a token for another resource', async () => {
    const none = await call(app, '/userinfo');
    expect(none.status).toBe(401);
    expect(none.headers.get('WWW-Authenticate')).toBe(
      'Bearer error="invalid_token", DPoP algs="ES256 EdDSA RS256 PS256"',
    );

    // A token for the MCP gateway is bound to the gateway: useless here (RFC 8707).
    const mcp = await authorizePath({
      scope: 'mcp:tools.read',
      resource: env.MCP_RESOURCE,
      nonce: null,
    });
    const { location } = await approve(mcp.path, ['mcp:tools.read']);
    const { body } = await token({
      grant_type: 'authorization_code',
      code: location.searchParams.get('code') ?? '',
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: mcp.verifier,
      resource: env.MCP_RESOURCE,
    });
    expect(body.id_token).toBeUndefined();
    const wrongAudience = await call(app, '/userinfo', {
      headers: { Authorization: `Bearer ${String(body.access_token)}` },
    });
    expect(wrongAudience.status).toBe(401);
  });

  it('gives each site its own subject, and the same one again on the next sign-in', async () => {
    const first = decodeJwt(String((await signInWith2earl()).body.id_token)).sub;
    const again = decodeJwt(String((await signInWith2earl()).body.id_token)).sub;
    expect(again).toBe(first);

    const otherSite = await newClient('https://other-rp.example/cb', 'Other');
    const other = await signInWith2earl({ redirect_uri: 'https://other-rp.example/cb' }, otherSite);
    expect(decodeJwt(String(other.body.id_token)).sub).not.toBe(first);
  });

  it('returns a new ID token on refresh, without the nonce', async () => {
    const { body } = await signInWith2earl();
    now += 60;
    const refreshed = await token({
      grant_type: 'refresh_token',
      refresh_token: String(body.refresh_token),
      client_id: clientId,
    });
    expect(refreshed.response.status).toBe(200);
    const { payload } = await verified(refreshed.body.id_token);
    expect(payload.nonce).toBeUndefined();
    expect(payload.sub).toBe(decodeJwt(String(body.id_token)).sub);
  });

  it('keeps openid even if the form leaves it out', async () => {
    const { path, verifier } = await authorizePath();
    const { location } = await approve(path, ['email']);
    const { body } = await token({
      grant_type: 'authorization_code',
      code: location.searchParams.get('code') ?? '',
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
    });
    expect(body.scope).toBe('openid email');
    expect(typeof body.id_token).toBe('string');
  });

  it('refuses a nonce changed in the consent form', async () => {
    const { path } = await authorizePath();
    const page = await call(app, path, { cookies: { '__Host-session': session } });
    const handle = parseConsent(await page.text());
    const body = consentBody(handle, { decision: 'approve', nonce: 'attacker-nonce' });
    const response = await call(app, '/authorize', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body,
      cookies: { '__Host-session': session, ...setCookies(page) },
    });
    expect(response.status).toBe(400);
  });

  it('never mixes openid with a service’s scopes, and still needs resource without openid', async () => {
    const mixed = await authorizePath({
      scope: 'openid mcp:tools.read',
      resource: env.MCP_RESOURCE,
    });
    const one = await call(app, mixed.path, { cookies: { '__Host-session': session } });
    expect(new URL(one.headers.get('Location') ?? 'about:blank').searchParams.get('error')).toBe(
      'invalid_scope',
    );

    const plain = await authorizePath({ scope: 'mcp:tools.read', nonce: null });
    const two = await call(app, plain.path, { cookies: { '__Host-session': session } });
    expect(new URL(two.headers.get('Location') ?? 'about:blank').searchParams.get('error')).toBe(
      'invalid_target',
    );
  });
});

describe('prompt and max_age', () => {
  it('prompt=none: login_required without a session, consent_required without consent', async () => {
    const { path } = await authorizePath({ prompt: 'none' });
    const signedOut = await call(app, path);
    const a = new URL(signedOut.headers.get('Location') ?? 'about:blank');
    expect(a.origin + a.pathname).toBe(REDIRECT_URI);
    expect(a.searchParams.get('error')).toBe('login_required');
    expect(a.searchParams.get('state')).toBe('rp-state');

    const signedIn = await call(app, path, { cookies: { '__Host-session': session } });
    const b = new URL(signedIn.headers.get('Location') ?? 'about:blank');
    expect(b.searchParams.get('error')).toBe('consent_required');
  });

  it('prompt=login and an old sign-in (max_age) ask the person to sign in again, once', async () => {
    const { path } = await authorizePath({ prompt: 'login' });
    const response = await call(app, path, { cookies: { '__Host-session': session } });
    const location = new URL(response.headers.get('Location') ?? 'about:blank', ORIGIN);
    expect(location.pathname).toBe('/login');
    expect(location.searchParams.get('reauth')).toBe('1');
    const back = location.searchParams.get('return_to') ?? '';
    expect(back).toContain('/authorize?');
    expect(back).not.toContain('prompt=login');

    now += 3600;
    const aged = await authorizePath({ max_age: '600' });
    const old = await call(app, aged.path, { cookies: { '__Host-session': session } });
    expect(new URL(old.headers.get('Location') ?? 'about:blank', ORIGIN).pathname).toBe('/login');

    const fresh = await authorizePath({ max_age: '7200' });
    const ok = await call(app, fresh.path, { cookies: { '__Host-session': session } });
    expect(ok.status).toBe(200); // the consent page
  });
});

describe('signing out from an app (RP-Initiated Logout)', () => {
  it('asks first, then signs out and returns to the app’s registered address with state', async () => {
    const query = new URLSearchParams({
      client_id: clientId,
      post_logout_redirect_uri: REDIRECT_URI,
      state: 'bye',
    }).toString();
    const ask = await call(app, `/oidc/logout?${query}`, {
      cookies: { '__Host-session': session },
    });
    expect(ask.status).toBe(200);
    const html = await ask.text();
    expect(html).toContain('Sign out of 2earl?');
    expect(html).toContain('Relying Party');

    const done = await call(app, '/oidc/logout', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ query, decision: 'sign_out' }),
      cookies: { '__Host-session': session },
    });
    expect(done.headers.get('Location')).toBe(`${REDIRECT_URI}?state=bye`);
    expect(await count('sessions')).toBe(0);
  });

  it('accepts the app named by an ID token, and never an address the app didn’t register', async () => {
    const { body } = await signInWith2earl();
    const hinted = new URLSearchParams({
      id_token_hint: String(body.id_token),
      post_logout_redirect_uri: REDIRECT_URI,
    }).toString();
    const ok = await call(app, '/oidc/logout', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ query: hinted, decision: 'sign_out' }),
      cookies: { '__Host-session': session },
    });
    expect(ok.headers.get('Location')).toBe(REDIRECT_URI);

    session = (await signIn(app, google)).session ?? '';
    const evil = new URLSearchParams({
      client_id: clientId,
      post_logout_redirect_uri: 'https://evil.example/',
    }).toString();
    const refused = await call(app, '/oidc/logout', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ query: evil, decision: 'sign_out' }),
      cookies: { '__Host-session': session },
    });
    expect(refused.status).toBe(200);
    expect(await refused.text()).toContain('You’re signed out');
  });

  it('stays signed in when the person says so, and refuses posts from other sites', async () => {
    const stay = await call(app, '/oidc/logout', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ query: '', decision: 'stay' }),
      cookies: { '__Host-session': session },
    });
    expect(stay.headers.get('Location')).toBe('/account');
    const crossSite = await call(app, '/oidc/logout', {
      method: 'POST',
      headers: { ...FORM, Origin: 'https://evil.example' },
      body: new URLSearchParams({ query: '', decision: 'sign_out' }),
      cookies: { '__Host-session': session },
    });
    expect(crossSite.status).toBe(403);
    expect(await count('sessions')).toBe(1);
  });
});

describe('sectors', () => {
  it('are the redirect host, or the app itself for apps on this device', () => {
    expect(sectorFor('c1', 'https://rp.example/cb')).toBe('rp.example');
    expect(sectorFor('c1', 'http://127.0.0.1:8080/cb')).toBe('client:c1');
    expect(sectorFor('c2', 'http://localhost/cb')).toBe('client:c2');
  });
});
