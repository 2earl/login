import { env, exports } from 'cloudflare:workers';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { makeStaff } from './staff-helpers';
import { effective } from '../src/authz/engine';
import { assignRole } from '../src/authz/store';
import { createApp } from '../src/app';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import {
  cleanUpServiceAccounts,
  createServiceAccount,
  serviceAccountCallback,
  serviceAccountScopes,
} from '../src/service-accounts';
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

/** Phase 13c (DESIGN §4.33): service accounts and the client credentials grant. */

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const SAME_ORIGIN = { ...FORM, Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };

let google: FakeGoogle;
let app: ReturnType<typeof createApp>;
let session: string;
let userId: string;
let orgId: string;

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  await env.DB.prepare('DELETE FROM service_account_cleanup').run();
  google = new FakeGoogle();
  app = createApp({ fetch: google.fetch, googleJwks: testJwks, now: () => NOW });
  session = (await signIn(app, google)).session ?? '';
  userId = (await env.DB.prepare('SELECT id FROM users').first<{ id: string }>())?.id ?? '';
  await makeStaff(session);
  const created = await post('/orgs', { name: 'Acme Bank' });
  orgId = /\/orgs\/([^?/]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
});

function post(path: string, body: Record<string, string | string[]>) {
  const form = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) for (const x of [v].flat()) form.append(k, x);
  return call(app, path, {
    method: 'POST',
    headers: SAME_ORIGIN,
    body: form,
    cookies: { '__Host-session': session },
    ip: freshIp(),
  });
}

/** Creates a service account on the settings page; returns its ID and secret. */
async function createWithSecret(scopes: string[]): Promise<{ id: string; secret: string }> {
  const page = await (
    await post(`/orgs/${orgId}/service-accounts`, {
      action: 'create',
      name: 'Onboarding backend',
      scope: scopes.map((s) => `${env.KYC_RESOURCE} ${s}`),
    })
  ).text();
  return {
    id: /Client ID <code>(sa_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '',
    secret: /<code class="secret">(2earl_sa_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '',
  };
}

function token(body: Record<string, string>, headers: Record<string, string> = {}) {
  return call(app, '/oauth/token', {
    method: 'POST',
    headers: { ...FORM, ...headers },
    body: new URLSearchParams({ grant_type: 'client_credentials', ...body }),
  });
}

const basic = (id: string, secret: string) => ({
  Authorization: `Basic ${btoa(`${id}:${secret}`)}`,
});

describe('creating service accounts', () => {
  it('offers a service’s scopes, never login’s own or an app’s sign-in scope', () => {
    const kyc = serviceAccountScopes(env, env.KYC_RESOURCE);
    expect(kyc).toContain('kyc:sessions.write');
    expect(kyc).not.toContain('kyc:console');
    expect(serviceAccountScopes(env, `${env.ISSUER}/userinfo`)).toEqual([]);
    expect(serviceAccountScopes(env, env.EMANET_MERKEZ_RESOURCE)).toEqual([]);
  });

  it('shows the secret once and records who made it', async () => {
    const { id, secret } = await createWithSecret(['kyc:sessions.write', 'kyc:sessions.read']);
    expect(id).toMatch(/^sa_/);
    expect(secret).toMatch(/^2earl_sa_/);
    const row = await env.DB.prepare('SELECT * FROM service_accounts WHERE id = ?')
      .bind(id)
      .first<{ scopes: string; secret_hash: string; created_by: string }>();
    expect(row?.scopes).toBe('kyc:sessions.read kyc:sessions.write');
    expect(row?.secret_hash).not.toContain(secret);
    expect(row?.created_by).toBe(userId);
    expect(await count('audit_events', "event = 'org.service_account_created'")).toBe(1);
    const again = await (
      await call(app, `/orgs/${orgId}/settings`, { cookies: { '__Host-session': session } })
    ).text();
    expect(again).toContain(id);
    expect(again).not.toContain(secret);
  });

  it('refuses scopes of two services, none, or keys that aren’t public signing keys', async () => {
    const mixed = await post(`/orgs/${orgId}/service-accounts`, {
      action: 'create',
      name: 'Mixed',
      scope: [`${env.KYC_RESOURCE} kyc:usage.read`, `${env.MCP_RESOURCE} mcp:tools.read`],
    });
    expect(mixed.status).toBe(400);
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const leaked = await post(`/orgs/${orgId}/service-accounts`, {
      action: 'create',
      name: 'Leaky',
      scope: `${env.KYC_RESOURCE} kyc:usage.read`,
      jwks: JSON.stringify({ keys: [await exportJWK(privateKey)] }),
    });
    expect(leaked.status).toBe(400);
    expect(await count('service_accounts')).toBe(0);
  });

  it('is for owners only', async () => {
    await env.DB.prepare(
      "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES ('al-o', 'email', 'other@example.com', 'test', 0)",
    ).run();
    const other = await signIn(app, google, {
      claims: { sub: 'google-sub-other', email: 'other@example.com', name: 'Other' },
    });
    const response = await call(app, `/orgs/${orgId}/service-accounts`, {
      method: 'POST',
      headers: SAME_ORIGIN,
      body: new URLSearchParams({
        action: 'create',
        name: 'X',
        scope: `${env.KYC_RESOURCE} kyc:usage.read`,
      }),
      cookies: { '__Host-session': other.session ?? '' },
    });
    expect(other.session).toBeTruthy();
    expect(response.status).toBe(404);
  });
});

describe('the client credentials grant', () => {
  it('issues a 15-minute access token, and nothing else', async () => {
    const { id, secret } = await createWithSecret(['kyc:sessions.write', 'kyc:sessions.read']);
    const response = await token({ resource: env.KYC_RESOURCE }, basic(id, secret));
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    const body = await response.json<Record<string, unknown>>();
    expect(Object.keys(body).sort()).toEqual(['access_token', 'expires_in', 'scope', 'token_type']);
    expect(body.expires_in).toBe(900);
    expect(body.scope).toBe('kyc:sessions.read kyc:sessions.write');

    const validated = await exports.default.validateToken(
      env.KYC_RESOURCE,
      String(body.access_token),
    );
    expect(validated?.userId).toBe(id);
    expect(validated?.props).toMatchObject({ uid: id, kind: 'service_account', org: orgId });
    expect(await count('audit_events', "event = 'service_account.used'")).toBe(1);
  });

  it('takes the secret in the form too, and a narrower scope', async () => {
    const { id, secret } = await createWithSecret(['kyc:sessions.write', 'kyc:sessions.read']);
    const response = await token({
      client_id: id,
      client_secret: secret,
      scope: 'kyc:sessions.read',
    });
    expect(response.status).toBe(200);
    expect((await response.json<{ scope: string }>()).scope).toBe('kyc:sessions.read');
  });

  it('refuses a wrong secret, an unknown account, more scopes, and another resource', async () => {
    const { id, secret } = await createWithSecret(['kyc:sessions.read']);
    expect((await token({}, basic(id, 'wrong'))).status).toBe(401);
    expect((await token({}, basic('sa_doesnotexist00', secret))).status).toBe(401);
    expect((await token({})).status).toBe(401);
    const more = await token({ scope: 'kyc:sessions.read kyc:evidence.read' }, basic(id, secret));
    expect((await more.json<{ error: string }>()).error).toBe('invalid_scope');
    const elsewhere = await token({ resource: env.MCP_RESOURCE }, basic(id, secret));
    expect((await elsewhere.json<{ error: string }>()).error).toBe('invalid_target');
  });

  it('accepts a signed JWT from the account’s own key, once', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const created = await createServiceAccount(env, NOW, {
      orgId,
      name: 'Signed',
      resource: env.KYC_RESOURCE,
      scopes: ['kyc:usage.read'],
      jwks: JSON.stringify({ keys: [await exportJWK(publicKey)] }),
      createdBy: userId,
    });
    if (!created.ok) throw new Error(created.reason);
    expect(created.secret).toBeNull();
    const id = created.account.id;
    const assertion = (claims: { aud?: string; exp?: number; jti?: string } = {}) =>
      new SignJWT({})
        .setProtectedHeader({ alg: 'ES256' })
        .setIssuer(id)
        .setSubject(id)
        .setAudience(claims.aud ?? `${env.ISSUER}/oauth/token`)
        .setIssuedAt(NOW)
        .setExpirationTime(claims.exp ?? NOW + 60)
        .setJti(claims.jti ?? crypto.randomUUID())
        .sign(privateKey);
    const send = async (jwt: string) =>
      token({
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: jwt,
      });

    const jwt = await assertion();
    expect((await send(jwt)).status).toBe(200);
    // The same assertion again: refused (RFC 7523 §3).
    expect((await send(jwt)).status).toBe(401);
    expect((await send(await assertion({ aud: 'https://elsewhere.example' }))).status).toBe(401);
    expect((await send(await assertion({ exp: NOW + 3600 }))).status).toBe(401);
    expect((await send(await assertion({ exp: NOW - 120 }))).status).toBe(401);
    // A secret doesn't work for an account with keys.
    expect((await token({ client_id: id, client_secret: 'x' })).status).toBe(401);
  });

  it('is advertised in the metadata', async () => {
    const meta = await (
      await call(app, '/.well-known/oauth-authorization-server')
    ).json<{
      grant_types_supported: string[];
      token_endpoint_auth_methods_supported: string[];
    }>();
    expect(meta.grant_types_supported).toContain('client_credentials');
    expect(meta.token_endpoint_auth_methods_supported).toEqual(
      expect.arrayContaining(['client_secret_basic', 'client_secret_post', 'private_key_jwt']),
    );
  });

  it('can’t be used to sign a person in', async () => {
    const { id } = await createWithSecret(['kyc:sessions.read']);
    const row = await env.DB.prepare('SELECT client_id FROM service_accounts WHERE id = ?')
      .bind(id)
      .first<{ client_id: string }>();
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: row?.client_id ?? '',
      redirect_uri: serviceAccountCallback(env),
      scope: 'kyc:sessions.read',
      state: 's',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
      resource: env.KYC_RESOURCE,
    });
    const response = await call(app, `/authorize?${query.toString()}`, {
      cookies: { '__Host-session': session },
    });
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('service account');
  });
});

describe('ending a service account', () => {
  it('ends its tokens and its client when deleted', async () => {
    const { id, secret } = await createWithSecret(['kyc:sessions.read']);
    const body = await (await token({}, basic(id, secret))).json<{ access_token: string }>();
    const clientId = (
      await env.DB.prepare('SELECT client_id FROM service_accounts WHERE id = ?')
        .bind(id)
        .first<{ client_id: string }>()
    )?.client_id;
    await post(`/orgs/${orgId}/service-accounts`, { action: 'delete', id });
    expect(await count('service_accounts')).toBe(0);
    expect(await exports.default.validateToken(env.KYC_RESOURCE, body.access_token)).toBeNull();
    expect(
      await authorizationServer(env)
        .getOAuthApi(env)
        .lookupClient(clientId ?? ''),
    ).toBeNull();
    expect(await count('service_account_cleanup')).toBe(0);
    expect((await token({}, basic(id, secret))).status).toBe(401);
  });

  it('goes with its organization, and the cron finishes the clean-up', async () => {
    const { id, secret } = await createWithSecret(['kyc:sessions.read']);
    const body = await (await token({}, basic(id, secret))).json<{ access_token: string }>();
    await env.DB.prepare('DELETE FROM organizations WHERE id = ?').bind(orgId).run();
    expect(await count('service_account_cleanup')).toBe(1);
    expect(await cleanUpServiceAccounts(env)).toBe(1);
    expect(await exports.default.validateToken(env.KYC_RESOURCE, body.access_token)).toBeNull();
  });

  it('gets no new token while its organization is suspended', async () => {
    const { id, secret } = await createWithSecret(['kyc:sessions.read']);
    await env.DB.prepare("UPDATE organizations SET status = 'suspended' WHERE id = ?")
      .bind(orgId)
      .run();
    const response = await token({}, basic(id, secret));
    expect(response.status).toBe(400);
    expect((await response.json<{ error: string }>()).error).toBe('invalid_grant');
  });
});

describe('roles for service accounts', () => {
  it('holds only what it was given, in its own organization', async () => {
    const { id } = await createWithSecret(['kyc:sessions.read']);
    const sa = { type: 'service_account' as const, id };
    const permissions = async (org: string | null) =>
      [...(await effective(env, { subject: sa, service: 'kyc', orgId: org })).permissions].sort();
    expect(await permissions(orgId)).toEqual([]);
    const given = await assignRole(env, NOW, {
      orgId,
      principal: { kind: 'service_account', id },
      role: 'kyc:tenant_developer',
      grantedBy: userId,
    });
    expect(given.ok).toBe(true);
    expect(await permissions(orgId)).toEqual(['kyc:tenant.develop', 'kyc:tenant.view']);
    expect(await permissions(null)).toEqual([]);
    await env.DB.prepare('DELETE FROM service_accounts WHERE id = ?').bind(id).run();
    expect(await count('authz_assignments')).toBe(0);
  });
});
