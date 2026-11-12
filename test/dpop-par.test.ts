import { env, exports } from 'cloudflare:workers';
import {
  SignJWT,
  base64url,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  type JWK,
} from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken, sha256 } from '../src/crypto';
import { createResourceServer } from '../src/introspection';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import { REQUEST_URI_PREFIX } from '../src/par';
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

/** Phase 9d (DESIGN §4.15): DPoP (RFC 9449) and pushed authorization requests (RFC 9126). */

const REDIRECT_URI = 'https://rp.example/callback';
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const TOKEN_URL = `${ORIGIN}/oauth/token`;
const USERINFO_URL = `${ORIGIN}/userinfo`;

let google: FakeGoogle;
let app: ReturnType<typeof makeApp>;
let session: string;
let clientId: string;
let now: number;

interface DpopKey {
  privateKey: CryptoKey;
  jwk: JWK;
  jkt: string;
}

async function dpopKey(): Promise<DpopKey> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk, jkt: await calculateJwkThumbprint(jwk) };
}

async function proof(
  key: DpopKey,
  method: string,
  url: string,
  options: { accessToken?: string; iat?: number; jti?: string; typ?: string } = {},
): Promise<string> {
  return new SignJWT({
    jti: options.jti ?? randomToken(16),
    htm: method,
    htu: url,
    iat: options.iat ?? now,
    ...(options.accessToken ? { ath: base64url.encode(await sha256(options.accessToken)) } : {}),
  })
    .setProtectedHeader({ alg: 'ES256', typ: options.typ ?? 'dpop+jwt', jwk: key.jwk })
    .sign(key.privateKey);
}

function authorizeParams(verifier: Promise<string>, overrides: Record<string, string> = {}) {
  return verifier.then((challenge) => ({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile',
    state: 'rp-state',
    nonce: 'rp-nonce',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...overrides,
  }));
}

/** Opens the consent page at `path` and approves it; returns the code. */
async function approve(path: string, scope: string[]) {
  const page = await call(app, path, { cookies: { '__Host-session': session } });
  expect(page.status).toBe(200);
  const body = consentBody(parseConsent(await page.text()), { decision: 'approve' });
  body.delete('scope');
  for (const s of scope) body.append('scope', s);
  const approved = await call(app, '/authorize', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body,
    cookies: { '__Host-session': session, ...setCookies(page) },
  });
  const location = new URL(approved.headers.get('Location') ?? 'about:blank');
  return { code: location.searchParams.get('code') ?? '', location };
}

async function tokenRequest(params: Record<string, string>, dpop?: string) {
  const response = await call(app, '/oauth/token', {
    method: 'POST',
    headers: { ...FORM, ...(dpop ? { DPoP: dpop } : {}) },
    body: new URLSearchParams(params),
  });
  return { response, body: await response.json<Record<string, string>>() };
}

/** A complete sign-in; with `key`, the code exchange carries a DPoP proof. */
async function tokens(options: { key?: DpopKey; resource?: string } = {}) {
  const verifier = randomToken(48);
  const scope = options.resource ? ['mcp:tools.read'] : ['openid', 'profile'];
  const params = await authorizeParams(pkceChallenge(verifier), {
    scope: scope.join(' '),
    ...(options.resource ? { resource: options.resource } : {}),
  });
  const { code } = await approve(`/authorize?${new URLSearchParams(params).toString()}`, scope);
  return tokenRequest(
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
      ...(options.resource ? { resource: options.resource } : {}),
    },
    options.key ? await proof(options.key, 'POST', TOKEN_URL) : undefined,
  );
}

function userinfo(token: string, scheme: 'Bearer' | 'DPoP', dpop?: string) {
  return call(app, '/userinfo', {
    headers: { Authorization: `${scheme} ${token}`, ...(dpop ? { DPoP: dpop } : {}) },
  });
}

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM dpop_proofs'),
    env.DB.prepare('DELETE FROM pushed_requests'),
    env.DB.prepare('DELETE FROM resource_servers'),
  ]);
  google = new FakeGoogle();
  app = makeApp(google, () => now);
  session = (await signIn(app, google)).session ?? '';
  clientId = (
    await authorizationServer(env)
      .getOAuthApi(env)
      .createClient({
        redirectUris: [REDIRECT_URI],
        clientName: 'Relying Party',
        tokenEndpointAuthMethod: 'none',
      })
  ).clientId;
});

describe('metadata', () => {
  it('announces DPoP and pushed authorization requests', async () => {
    for (const path of [
      '/.well-known/oauth-authorization-server',
      '/.well-known/openid-configuration',
    ]) {
      const meta = await (await call(app, path)).json<Record<string, unknown>>();
      expect(meta.dpop_signing_alg_values_supported, path).toEqual([
        'ES256',
        'EdDSA',
        'RS256',
        'PS256',
      ]);
      expect(meta.pushed_authorization_request_endpoint, path).toBe(`${ORIGIN}/oauth/par`);
      expect(meta.require_pushed_authorization_requests, path).toBe(false);
    }
  });
});

describe('DPoP (RFC 9449)', () => {
  it('binds a UserInfo token to the key, which then needs a fresh proof every time', async () => {
    const key = await dpopKey();
    const { response, body } = await tokens({ key });
    expect(response.status).toBe(200);
    expect(body.token_type).toBe('DPoP');
    const token = body.access_token ?? '';

    // As a bearer token it is useless.
    const bearer = await userinfo(token, 'Bearer');
    expect(bearer.status).toBe(401);
    expect(await userinfo(token, 'DPoP')).toHaveProperty('status', 401);

    const first = await proof(key, 'GET', USERINFO_URL, { accessToken: token });
    expect((await userinfo(token, 'DPoP', first)).status).toBe(200);
    // A proof works once.
    const replayed = await userinfo(token, 'DPoP', first);
    expect(replayed.status).toBe(401);
    expect(replayed.headers.get('WWW-Authenticate')).toMatch(/^DPoP error="invalid_dpop_proof"/);

    // Another key, another URL or another token: refused.
    const other = await dpopKey();
    for (const wrong of [
      await proof(other, 'GET', USERINFO_URL, { accessToken: token }),
      await proof(key, 'GET', `${ORIGIN}/account`, { accessToken: token }),
      await proof(key, 'POST', USERINFO_URL, { accessToken: token }),
      await proof(key, 'GET', USERINFO_URL, { accessToken: 'another-token' }),
      await proof(key, 'GET', USERINFO_URL),
      await proof(key, 'GET', USERINFO_URL, { accessToken: token, iat: now - 120 }),
    ]) {
      expect((await userinfo(token, 'DPoP', wrong)).status).toBe(401);
    }
  });

  it('binds the refresh token too: a refresh without the key’s proof ends the grant', async () => {
    const key = await dpopKey();
    const refresh = (token: string) => ({
      grant_type: 'refresh_token',
      refresh_token: token,
      client_id: clientId,
    });
    const first = (await tokens({ key })).body;
    const renewed = await tokenRequest(
      refresh(first.refresh_token ?? ''),
      await proof(key, 'POST', TOKEN_URL),
    );
    expect(renewed.response.status).toBe(200);
    expect(renewed.body.token_type).toBe('DPoP');

    // Presented without the key, the token is treated as stolen: the grant ends.
    const next = refresh(renewed.body.refresh_token ?? '');
    expect((await tokenRequest(next)).body.error).toBe('invalid_grant');
    expect(
      (await tokenRequest(next, await proof(key, 'POST', TOKEN_URL))).body.error_description,
    ).toBe('Grant not found');

    // The same with another key.
    const second = (await tokens({ key })).body;
    const other = await dpopKey();
    const stolen = refresh(second.refresh_token ?? '');
    expect((await tokenRequest(stolen, await proof(other, 'POST', TOKEN_URL))).body.error).toBe(
      'invalid_grant',
    );
    expect((await tokenRequest(stolen, await proof(key, 'POST', TOKEN_URL))).body.error).toBe(
      'invalid_grant',
    );
  });

  it('gives a bearer token for a resource that doesn’t check proofs, and binds the refresh token', async () => {
    const key = await dpopKey();
    const { body } = await tokens({ key, resource: env.MCP_RESOURCE });
    expect(body.token_type).toBe('bearer');
    const validated = await exports.default.validateToken(
      env.MCP_RESOURCE,
      body.access_token ?? '',
    );
    expect(validated?.scope).toEqual(['mcp:tools.read']);
    const refresh = {
      grant_type: 'refresh_token',
      refresh_token: body.refresh_token ?? '',
      client_id: clientId,
      resource: env.MCP_RESOURCE,
    };
    const renewed = await tokenRequest(refresh, await proof(key, 'POST', TOKEN_URL));
    expect(renewed.body.token_type).toBe('bearer');
    expect(
      (await tokenRequest({ ...refresh, refresh_token: renewed.body.refresh_token ?? '' })).body
        .error,
    ).toBe('invalid_grant');
  });

  it('refuses a bad proof at the token endpoint, and changes nothing without one', async () => {
    const key = await dpopKey();
    for (const bad of [
      'not-a-jwt',
      await proof(key, 'POST', TOKEN_URL, { typ: 'JWT' }),
      await proof(key, 'GET', TOKEN_URL),
      await proof(key, 'POST', `${ORIGIN}/oauth/other`),
      await proof(key, 'POST', TOKEN_URL, { iat: now + 300 }),
      await proof(key, 'POST', TOKEN_URL, { jti: 'short' }),
      `${await proof(key, 'POST', TOKEN_URL)}, ${await proof(key, 'POST', TOKEN_URL)}`,
    ]) {
      const { response, body } = await tokenRequest(
        { grant_type: 'refresh_token', refresh_token: 'x', client_id: clientId },
        bad,
      );
      expect(response.status).toBe(400);
      expect(body.error).toBe('invalid_dpop_proof');
    }
    // An HMAC "proof" (symmetric key) is refused.
    const hmac = await new SignJWT({ jti: randomToken(16), htm: 'POST', htu: TOKEN_URL, iat: now })
      .setProtectedHeader({
        alg: 'HS256',
        typ: 'dpop+jwt',
        jwk: { kty: 'oct', k: 'c2VjcmV0' } as never,
      })
      .sign(new TextEncoder().encode('secret'));
    expect(
      (await tokenRequest({ grant_type: 'refresh_token', refresh_token: 'x' }, hmac)).body.error,
    ).toBe('invalid_dpop_proof');

    // Without DPoP, everything is as before; an unbound token can't use the DPoP scheme.
    const { body } = await tokens();
    expect(body.token_type).toBe('bearer');
    expect((await userinfo(body.access_token ?? '', 'Bearer')).status).toBe(200);
    expect(
      (
        await userinfo(
          body.access_token ?? '',
          'DPoP',
          await proof(key, 'GET', USERINFO_URL, { accessToken: body.access_token ?? '' }),
        )
      ).status,
    ).toBe(401);
  });

  it('introspection names the key; the gateway entrypoint checks proofs or refuses bound tokens', async () => {
    const key = await dpopKey();
    const { body } = await tokens({ key });
    const token = body.access_token ?? '';
    const rs = await createResourceServer(env.DB, now, 'Site', `${ORIGIN}/userinfo`);
    const introspected = await (
      await call(app, '/oauth/introspect', {
        method: 'POST',
        headers: { ...FORM, Authorization: `Basic ${btoa(`${rs.id}:${rs.secret}`)}` },
        body: new URLSearchParams({ token }),
      })
    ).json<Record<string, unknown>>();
    expect(introspected).toMatchObject({ active: true, token_type: 'DPoP', cnf: { jkt: key.jkt } });

    // validateToken is for bearer tokens: a bound one is refused there.
    expect(await exports.default.validateToken(`${ORIGIN}/userinfo`, token)).toBeNull();
    // validateRequest checks the proof (it runs on the real clock).
    const real = Math.floor(Date.now() / 1000);
    const ok = await exports.default.validateRequest(`${ORIGIN}/userinfo`, {
      authorization: `DPoP ${token}`,
      dpop: await proof(key, 'GET', `${ORIGIN}/userinfo`, { accessToken: token, iat: real }),
      method: 'GET',
      url: `${ORIGIN}/userinfo?x=1`,
    });
    expect(ok.ok && ok.token.jkt).toBe(key.jkt);
    const refused = await exports.default.validateRequest(`${ORIGIN}/userinfo`, {
      authorization: `Bearer ${token}`,
      dpop: null,
      method: 'GET',
      url: `${ORIGIN}/userinfo`,
    });
    expect(refused).toMatchObject({ ok: false, error: 'invalid_token' });
    expect(!refused.ok && refused.wwwAuthenticate).toMatch(
      /^Bearer error="invalid_token", DPoP algs=/,
    );
  });
});

describe('pushed authorization requests (RFC 9126)', () => {
  async function push(params: Record<string, string>) {
    const response = await call(app, '/oauth/par', {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams(params),
    });
    return { response, body: await response.json<Record<string, unknown>>() };
  }

  it('takes the request from the client, so the browser carries only its reference', async () => {
    const verifier = randomToken(48);
    const params = await authorizeParams(pkceChallenge(verifier));
    const { response, body } = await push(params);
    expect(response.status).toBe(201);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(body.expires_in).toBe(600);
    const requestUri = String(body.request_uri);
    expect(requestUri.startsWith(REQUEST_URI_PREFIX)).toBe(true);

    // Anything else in the URL is ignored: the pushed state comes back, not the browser's.
    const path = `/authorize?${new URLSearchParams({ client_id: clientId, request_uri: requestUri, state: 'evil', scope: 'openid email' }).toString()}`;
    const { code, location } = await approve(path, ['openid', 'profile']);
    expect(location.searchParams.get('state')).toBe('rp-state');
    const exchanged = await tokenRequest({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
    });
    expect(exchanged.response.status).toBe(200);
    expect(exchanged.body.scope).toBe('openid profile');
  });

  it('keeps the short URL through sign-in, and refuses unknown, expired or another client’s references', async () => {
    const params = await authorizeParams(pkceChallenge(randomToken(48)));
    const requestUri = String((await push(params)).body.request_uri);
    const path = `/authorize?${new URLSearchParams({ client_id: clientId, request_uri: requestUri }).toString()}`;
    const signedOut = await call(app, path);
    expect(signedOut.headers.get('Location')).toBe(`/login?return_to=${encodeURIComponent(path)}`);

    const other = (
      await authorizationServer(env)
        .getOAuthApi(env)
        .createClient({ redirectUris: [REDIRECT_URI], tokenEndpointAuthMethod: 'none' })
    ).clientId;
    const cookies = { '__Host-session': session };
    for (const bad of [
      `/authorize?client_id=${other}&request_uri=${encodeURIComponent(requestUri)}`,
      `/authorize?request_uri=${encodeURIComponent(requestUri)}`,
      `/authorize?client_id=${clientId}&request_uri=${encodeURIComponent(`${REQUEST_URI_PREFIX}unknown`)}`,
      `/authorize?client_id=${clientId}&request_uri=https%3A%2F%2Fevil.example%2Fr`,
    ]) {
      expect((await call(app, bad, { cookies })).status, bad).toBe(400);
    }
    now += 601;
    expect((await call(app, path, { cookies })).status).toBe(400);
  });

  it('checks the request when it is pushed', async () => {
    const params = await authorizeParams(pkceChallenge(randomToken(48)));
    expect((await push({ ...params, client_id: '' })).body.error).toBe('invalid_request');
    const unknown = await push({ ...params, client_id: 'no-such-client' });
    expect(unknown.response.status).toBe(401);
    expect(unknown.body.error).toBe('invalid_client');
    const noPkce: Record<string, string> = { ...params };
    delete noPkce.code_challenge;
    delete noPkce.code_challenge_method;
    expect((await push(noPkce)).body.error).toBe('invalid_request');
    expect((await push({ ...params, redirect_uri: 'https://evil.example/cb' })).body.error).toBe(
      'invalid_request',
    );
    expect((await push({ ...params, request_uri: `${REQUEST_URI_PREFIX}x` })).body.error).toBe(
      'invalid_request',
    );
    expect((await push({ ...params, request: 'eyJ.x.y' })).body.error).toBe(
      'request_not_supported',
    );
  });
});
