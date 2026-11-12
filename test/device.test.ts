import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { DEVICE_GRANT, deviceCallback, normaliseUserCode } from '../src/device';
import { authorizationServer, setOAuthClock } from '../src/oauth';
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

/** Phase 8d (DESIGN §4.13): the device authorization grant, RFC 8628. */

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };

let app: ReturnType<typeof makeApp>;
let google: FakeGoogle;
let session: string;
let cli: string;
let now: number;

interface DeviceStart {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

async function start(params: Record<string, string> = {}, clientId = cli) {
  const response = await call(app, '/oauth/device_authorization', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({
      client_id: clientId,
      scope: 'mcp:tools.read',
      resource: env.MCP_RESOURCE,
      ...params,
    }),
  });
  return { response, body: await response.json<DeviceStart & { error?: string }>() };
}

async function poll(deviceCode: string, clientId = cli) {
  const response = await call(app, '/oauth/token', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({
      grant_type: DEVICE_GRANT,
      device_code: deviceCode,
      client_id: clientId,
    }),
  });
  return { response, body: await response.json<Record<string, unknown>>() };
}

/** The person's side: enter the code, then the ordinary consent page. */
async function approveOnPhone(userCode: string, decision: 'approve' | 'deny' = 'approve') {
  const cookies = { '__Host-session': session };
  const entered = await call(app, '/device', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body: new URLSearchParams({ user_code: userCode }),
    cookies,
  });
  expect(entered.status).toBe(303);
  const authorize = entered.headers.get('Location') ?? '';
  expect(authorize).toMatch(/^\/authorize\?/);
  const page = await call(app, authorize, { cookies });
  const html = await page.text();
  const handle = parseConsent(html);
  const scope = new URL(authorize, ORIGIN).searchParams.get('scope') ?? '';
  const body = consentBody(handle, { decision });
  body.delete('scope');
  for (const s of scope.split(' ')) body.append('scope', s);
  const decided = await call(app, '/authorize', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body,
    cookies: { ...cookies, ...setCookies(page) },
  });
  const callback = new URL(decided.headers.get('Location') ?? 'about:blank');
  expect(callback.origin + callback.pathname).toBe(deviceCallback(env));
  const done = await call(app, callback.pathname + callback.search, { cookies });
  return { html, done: await done.text(), doneStatus: done.status };
}

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  await env.DB.prepare('DELETE FROM device_codes').run();
  google = new FakeGoogle();
  app = makeApp(google, () => now);
  session = (await signIn(app, google)).session ?? '';
  cli = (
    await authorizationServer(env)
      .getOAuthApi(env)
      .createClient({
        redirectUris: [deviceCallback(env)],
        clientName: '2earl CLI',
        tokenEndpointAuthMethod: 'none',
      })
  ).clientId;
});

describe('device sign-in (RFC 8628)', () => {
  it('is announced in the server metadata', async () => {
    const meta = await (
      await call(app, '/.well-known/oauth-authorization-server')
    ).json<Record<string, unknown>>();
    expect(meta.device_authorization_endpoint).toBe(`${ORIGIN}/oauth/device_authorization`);
    expect(meta.grant_types_supported).toEqual(expect.arrayContaining([DEVICE_GRANT]));
    const oidc = await (
      await call(app, '/.well-known/openid-configuration')
    ).json<Record<string, unknown>>();
    expect(oidc.grant_types_supported).toEqual(expect.arrayContaining([DEVICE_GRANT]));
  });

  it('signs the device in after the person approves, with the ordinary consent page', async () => {
    const { response, body } = await start();
    expect(response.status).toBe(200);
    expect(body.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(body.verification_uri).toBe(`${ORIGIN}/device`);
    expect(body.verification_uri_complete).toBe(`${ORIGIN}/device?user_code=${body.user_code}`);
    expect(body).toMatchObject({ expires_in: 600, interval: 5 });

    // Only a hash of the device code is stored.
    const stored = await env.DB.prepare('SELECT id_hash FROM device_codes').first<{
      id_hash: string;
    }>();
    expect(stored?.id_hash).not.toBe(body.device_code);

    expect((await poll(body.device_code)).body.error).toBe('authorization_pending');
    expect((await poll(body.device_code)).body.error).toBe('slow_down');

    // The prefilled link shows the code; it never approves anything by itself.
    const link = await call(app, `/device?user_code=${body.user_code}`, {
      cookies: { '__Host-session': session },
    });
    expect(await link.text()).toContain(`value="${body.user_code}"`);
    expect(await count('device_codes', "status = 'pending'")).toBe(1);

    const { html, done } = await approveOnPhone(body.user_code.toLowerCase().replace('-', ' '));
    expect(html).toContain('2earl CLI');
    expect(done).toContain('Your device is signed in');

    now += 15;
    const tokens = await poll(body.device_code);
    expect(tokens.response.status).toBe(200);
    expect(tokens.body.token_type).toBe('bearer');
    const validated = await authorizationServer(env).validateToken(
      env.MCP_RESOURCE,
      String(tokens.body.access_token),
      env,
    );
    expect(validated?.scope).toEqual(['mcp:tools.read']);
    expect(await count('audit_events', "event = 'device.approved'")).toBe(1);

    // Collected once.
    expect((await poll(body.device_code)).body.error).toBe('invalid_grant');
  });

  it('works for OpenID Connect too: an ID token for `2earl whoami`', async () => {
    const { body } = await start({ scope: 'openid profile email', resource: '' });
    await approveOnPhone(body.user_code);
    now += 15;
    const tokens = await poll(body.device_code);
    expect(tokens.response.status).toBe(200);
    expect(typeof tokens.body.id_token).toBe('string');
  });

  it('tells the device when the person said no', async () => {
    const { body } = await start();
    const { done } = await approveOnPhone(body.user_code, 'deny');
    expect(done).toContain('Nothing was approved');
    now += 15;
    expect((await poll(body.device_code)).body.error).toBe('access_denied');
  });

  it('expires after 10 minutes', async () => {
    const { body } = await start();
    now += 601;
    expect((await poll(body.device_code)).body.error).toBe('expired_token');
    const late = await call(app, '/device', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ user_code: body.user_code }),
      cookies: { '__Host-session': session },
    });
    expect(late.status).toBe(400);
  });

  it('only for apps that registered the device callback, and only to the app that asked', async () => {
    const web = (
      await authorizationServer(env)
        .getOAuthApi(env)
        .createClient({ redirectUris: ['https://app.example/cb'], tokenEndpointAuthMethod: 'none' })
    ).clientId;
    const refused = await start({}, web);
    expect(refused.response.status).toBe(400);
    expect(refused.body.error).toBe('unauthorized_client');

    const { body } = await start();
    expect((await poll(body.device_code, web)).body.error).toBe('invalid_grant');
    expect((await poll('not-a-device-code')).body.error).toBe('invalid_grant');
  });

  it('checks scopes and resource like the authorization endpoint', async () => {
    expect((await start({ resource: '' })).body.error).toBe('invalid_target');
    expect((await start({ scope: 'mcp:tools.read openid' })).body.error).toBe('invalid_scope');
    expect((await start({ resource: 'https://evil.example/mcp' })).body.error).toBe(
      'invalid_target',
    );
  });

  it('asks a signed-out person to sign in first, and refuses wrong codes', async () => {
    const signedOut = await call(app, '/device?user_code=BCDF-GHJK');
    expect(signedOut.headers.get('Location')).toBe(
      `/login?return_to=${encodeURIComponent('/device?user_code=BCDF-GHJK')}`,
    );
    const wrong = await call(app, '/device', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ user_code: 'BCDF-GHJK' }),
      cookies: { '__Host-session': session },
    });
    expect(wrong.status).toBe(400);
    expect(await wrong.text()).toContain('isn’t valid or has expired');
  });

  it('reads codes the way people type them', () => {
    expect(normaliseUserCode('bcdf ghjk')).toBe('BCDF-GHJK');
    expect(normaliseUserCode('BCDF-GHJK')).toBe('BCDF-GHJK');
    expect(normaliseUserCode('BCDFGHJ')).toBeNull();
    expect(normaliseUserCode('AEIO-UBCD')).toBeNull();
  });
});
