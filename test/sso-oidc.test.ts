import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from 'jose';
import { setOAuthClock } from '../src/oauth';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  count,
  freshIp,
  resetDatabase,
  signIn,
  testJwks,
} from './helpers';

/** Phase 10c (DESIGN §4.20): single sign-on with OpenID Connect. */

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};

let google: FakeGoogle;
let app: ReturnType<typeof createApp>;
let now: number;
let dns: Record<string, string[]>;

interface Person {
  id: string;
  session: string;
  email: string;
}

const fetcher: typeof fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  if (url.hostname === 'cloudflare-dns.com') {
    const records = dns[url.searchParams.get('name') ?? ''] ?? [];
    return Promise.resolve(
      Response.json({
        Status: records.length ? 0 : 3,
        Answer: records.map((data) => ({ type: 16, data: `"${data}"` })),
      }),
    );
  }
  if (url.hostname === 'idp.example.net') return idp(url, init);
  // Google Workspace's discovery, pointing at the fake provider's endpoints.
  if (url.href === 'https://accounts.google.com/.well-known/openid-configuration') {
    return Promise.resolve(
      Response.json({
        issuer: 'https://accounts.google.com',
        authorization_endpoint: 'https://idp.example.net/tenant/authorize',
        token_endpoint: 'https://idp.example.net/tenant/token',
        jwks_uri: 'https://idp.example.net/tenant/keys',
      }),
    );
  }
  return google.fetch(input, init);
};

// ---- A fake OpenID provider ------------------------------------------------------------------

const ISSUER = 'https://idp.example.net/tenant';
let signingKey: CryptoKey;
let jwks: unknown;
/** What the provider puts in the next ID token; tests change it. */
let claims: Record<string, unknown>;
let nonce = '';
let idpIssuer = ISSUER;
let tokenIssuer = ISSUER;
let tokenRequests: { authorization: string | null; body: string }[];

async function idp(url: URL, init?: RequestInit): Promise<Response> {
  if (url.pathname === '/tenant/.well-known/openid-configuration') {
    return Response.json({
      issuer: idpIssuer,
      authorization_endpoint: 'https://idp.example.net/tenant/authorize',
      token_endpoint: 'https://idp.example.net/tenant/token',
      jwks_uri: 'https://idp.example.net/tenant/keys',
    });
  }
  if (url.pathname === '/tenant/keys') return Response.json(jwks);
  if (url.pathname === '/tenant/token') {
    const headers = new Headers(init?.headers);
    tokenRequests.push({
      authorization: headers.get('Authorization'),
      body: typeof init?.body === 'string' ? init.body : '',
    });
    const idToken = await new SignJWT({ nonce, ...claims })
      .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
      .setIssuer(tokenIssuer)
      .setAudience('client-1')
      .setSubject('idp-user-1')
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(signingKey);
    return Response.json({ id_token: idToken, access_token: 'x', token_type: 'Bearer' });
  }
  return new Response('not found', { status: 404 });
}

async function person(key: string, domain = 'example.com'): Promise<Person> {
  const email = `${key}@${domain}`;
  await env.DB.prepare(
    "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES (?, 'email', ?, 'test', 0) ON CONFLICT DO NOTHING",
  )
    .bind(`al-${key}`, email)
    .run();
  const { session } = await signIn(app, google, {
    claims: { sub: `sub-${key}`, email, name: key },
  });
  const row = await env.DB.prepare(
    'SELECT user_id AS id FROM identities WHERE provider = ? AND subject = ?',
  )
    .bind('google', `sub-${key}`)
    .first<{ id: string }>();
  return { id: row?.id ?? '', session: session ?? '', email };
}

function post(who: Person, path: string, body: Record<string, string> = {}) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(body),
    cookies: { '__Host-session': who.session },
    ip: freshIp(),
  });
}

function get(who: Person, path: string) {
  return call(app, path, { cookies: { '__Host-session': who.session }, ip: freshIp() });
}

/** An organization owned by `owner` with example.com verified. */
async function organization(owner: Person) {
  const created = await post(owner, '/orgs', { name: 'Example Inc' });
  const id = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  await post(owner, `/orgs/${id}/domains`, { domain: 'example.com' });
  const row = await env.DB.prepare('SELECT challenge FROM org_domains WHERE org_id = ?')
    .bind(id)
    .first<{ challenge: string }>();
  dns['_2earl-challenge.example.com'] = [row?.challenge ?? ''];
  await post(owner, `/orgs/${id}/domains/verify`, { domain: 'example.com' });
  return { orgId: id };
}

/** Turns managing on for example.com; the owner (at that domain too) then joins. */
async function manage(owner: Person, id: string) {
  await post(owner, `/orgs/${id}/domains/manage`, { domain: 'example.com', on: '1', accept: 'on' });
  await post(owner, '/account/managed', { org: id, choice: 'join' });
}

let ada: Person;
let bob: Person;
let orgId: string;

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  dns = {};
  google = new FakeGoogle();
  app = createApp({ fetch: fetcher, googleJwks: testJwks, now: () => now });
  const pair = await generateKeyPair('ES256');
  signingKey = pair.privateKey;
  jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'ES256' }] };
  claims = { email: 'bob@example.com', email_verified: true };
  idpIssuer = ISSUER;
  tokenIssuer = ISSUER;
  tokenRequests = [];
  ada = await person('ada');
  bob = await person('bob');
  ({ orgId } = await organization(ada));
});

function connect(fields: Record<string, string> = {}) {
  return post(ada, `/orgs/${orgId}/oidc`, {
    issuer: ISSUER,
    client_id: 'client-1',
    client_secret: 'secret:with:colons',
    enabled: 'on',
    ...fields,
  });
}

/** Starts single sign-on for `email`; returns the provider's URL and the browser cookie. */
async function start(email: string) {
  const response = await call(app, '/login/sso', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({ email }),
    ip: freshIp(),
  });
  const location = new URL(response.headers.get('Location') ?? 'https://invalid');
  const cookie = /__Host-oidc_tx=([^;]+)/.exec(response.headers.get('Set-Cookie') ?? '')?.[1] ?? '';
  nonce = location.searchParams.get('nonce') ?? '';
  return { response, location, cookie };
}

/** Comes back from the provider with a code. */
function back(state: string, cookie: string, code = 'code-1') {
  return call(app, `/sso/${orgId}/oidc?code=${code}&state=${state}`, {
    cookies: { '__Host-oidc_tx': cookie },
    ip: freshIp(),
  });
}

const sessionOf = (response: Response) =>
  /__Host-session=([^;]+)/.exec(response.headers.get('Set-Cookie') ?? '')?.[1];

describe('connecting a provider', () => {
  it('checks the provider answers as that issuer, and stores the secret encrypted', async () => {
    const saved = await connect();
    expect(saved.headers.get('Location')).toBe(`/orgs/${orgId}/directory?done=saml`);
    const row = await env.DB.prepare(
      'SELECT issuer, client_id, client_secret_enc, enabled FROM org_oidc WHERE org_id = ?',
    )
      .bind(orgId)
      .first<{ issuer: string; client_id: string; client_secret_enc: string; enabled: number }>();
    expect(row?.enabled).toBe(1);
    expect(row?.client_secret_enc).not.toContain('secret');

    idpIssuer = 'https://idp.example.net/someone-else';
    expect((await connect()).status).toBe(400);
    expect(
      (await connect({ issuer: 'https://login.microsoftonline.com/common/v2.0' })).status,
    ).toBe(400);
    expect((await connect({ issuer: 'http://idp.example.net/tenant' })).status).toBe(400);
  });

  it('runs one way of single sign-on at a time', async () => {
    await env.DB.prepare(
      `INSERT INTO org_saml (org_id, idp_entity_id, sso_url, certificate, enabled, created_at, updated_at)
       VALUES (?, 'https://idp', 'https://idp/sso', 'cert', 1, 0, 0)`,
    )
      .bind(orgId)
      .run();
    await connect();
    expect(await count('org_saml', 'org_id = ? AND enabled = 1', orgId)).toBe(0);
    // Keeping the saved secret: an empty field changes nothing.
    await connect({ client_secret: '' });
    expect(await count('org_oidc', 'org_id = ? AND enabled = 1', orgId)).toBe(1);
  });
});

describe('signing in', () => {
  it('signs in the account with the asserted address, with PKCE, a nonce and the secret', async () => {
    await connect();
    const { location, cookie } = await start('bob@example.com');
    expect(location.origin + location.pathname).toBe('https://idp.example.net/tenant/authorize');
    expect(location.searchParams.get('code_challenge_method')).toBe('S256');
    expect(location.searchParams.get('redirect_uri')).toBe(
      `https://login.2earl.com/sso/${orgId}/oidc`,
    );
    const done = await back(location.searchParams.get('state') ?? '', cookie);
    expect(done.status).toBe(303);
    expect(sessionOf(done)).toBeTruthy();
    expect(await count('sessions', "user_id = ? AND method = 'oidc'", bob.id)).toBe(1);
    expect(tokenRequests[0]?.authorization).toBe(
      `Basic ${btoa('client-1:secret%3Awith%3Acolons')}`,
    );
    expect(tokenRequests[0]?.body).toContain('code_verifier=');
  });

  it('refuses a wrong nonce, another browser, a reused state, and addresses outside the domains', async () => {
    await connect();
    let flow = await start('bob@example.com');
    nonce = 'not-the-one';
    expect((await back(flow.location.searchParams.get('state') ?? '', flow.cookie)).status).toBe(
      400,
    );

    flow = await start('bob@example.com');
    expect(
      (await back(flow.location.searchParams.get('state') ?? '', 'other-browser')).status,
    ).toBe(400);

    flow = await start('bob@example.com');
    claims = { email: 'mallory@elsewhere.example', email_verified: true };
    expect((await back(flow.location.searchParams.get('state') ?? '', flow.cookie)).status).toBe(
      400,
    );

    flow = await start('bob@example.com');
    claims = { email: 'bob@example.com', email_verified: false };
    expect((await back(flow.location.searchParams.get('state') ?? '', flow.cookie)).status).toBe(
      400,
    );
    expect(await count('sessions', "method = 'oidc'")).toBe(0);
  });

  it('takes Entra ID’s sign-in name when there is no email claim', async () => {
    await connect();
    claims = { preferred_username: 'Bob@Example.com' };
    const flow = await start('bob@example.com');
    const done = await back(flow.location.searchParams.get('state') ?? '', flow.cookie);
    expect(sessionOf(done)).toBeTruthy();
  });

  it('counts as single sign-on where the organization requires it', async () => {
    await connect();
    await manage(ada, orgId);
    await post(bob, '/account/managed', { org: orgId, choice: 'join' });
    await env.DB.prepare('UPDATE organizations SET require_sso = 1 WHERE id = ?').bind(orgId).run();
    // Bob's Google session ends; signing in through the provider works.
    expect((await get(bob, '/account')).headers.get('Location')).toMatch(/^\/login/);
    const flow = await start('bob@example.com');
    const done = await back(flow.location.searchParams.get('state') ?? '', flow.cookie);
    const session = sessionOf(done) ?? '';
    const account = await call(app, '/account', {
      cookies: { '__Host-session': session },
      ip: freshIp(),
    });
    expect(account.status).toBe(200);
  });

  it('with Google Workspace, takes only the company’s own Workspace accounts', async () => {
    await connect({ issuer: 'https://accounts.google.com' });
    tokenIssuer = 'https://accounts.google.com';
    // A personal Google account made with the work address: no hosted domain.
    claims = { email: 'bob@example.com', email_verified: true };
    let flow = await start('bob@example.com');
    expect((await back(flow.location.searchParams.get('state') ?? '', flow.cookie)).status).toBe(
      400,
    );
    claims = { email: 'bob@example.com', email_verified: true, hd: 'example.com' };
    flow = await start('bob@example.com');
    const done = await back(flow.location.searchParams.get('state') ?? '', flow.cookie);
    expect(sessionOf(done)).toBeTruthy();
  });
});
