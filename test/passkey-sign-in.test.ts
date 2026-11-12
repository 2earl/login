import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { deviceLabel } from '../src/devices';
import { setOAuthClock } from '../src/oauth';
import { MFA_CSP } from '../src/security-headers';
import { SoftAuthenticator } from './authenticator';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  count,
  freshIp,
  makeApp,
  resetDatabase,
  setCookies,
  signIn,
} from './helpers';

/** Phase 8a (DESIGN §4.10, §7): sign in with a passkey alone, and signed-in devices. */

const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };
const JSON_POST = { 'Content-Type': 'application/json', ...SAME_ORIGIN };
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', ...SAME_ORIGIN };
const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0';

let google: FakeGoogle;
let now: number;
let app: ReturnType<typeof makeApp>;
let ip: string;

function postJson(path: string, body: unknown, cookies: Record<string, string> = {}) {
  return call(app, path, {
    method: 'POST',
    headers: JSON_POST,
    body: JSON.stringify(body),
    cookies,
    ip,
  });
}

/** A signed-in owner with one passkey added under Security. */
async function accountWithPasskey(key = new SoftAuthenticator()) {
  const session = (await signIn(app, google)).session ?? '';
  const cookies = { '__Host-session': session };
  const options = await postJson('/account/security/passkeys/options', {}, cookies);
  const added = await postJson(
    '/account/security/passkeys',
    { label: 'Laptop', response: await key.register(await options.json()) },
    cookies,
  );
  expect(added.status).toBe(200);
  return { key, session };
}

/** A browser with no session signs in with this passkey. */
async function passkeySignIn(
  key: SoftAuthenticator,
  extra: { returnTo?: string; userVerified?: boolean; cookies?: Record<string, string> } = {},
) {
  const options = await postJson('/login/passkey/options', {}, extra.cookies ?? {});
  expect(options.status).toBe(200);
  const tx = setCookies(options)['__Host-passkey_tx'] ?? '';
  const body = await options.json<{ challenge: string; allowCredentials?: unknown[] }>();
  const answer = await key.authenticate(body, { userVerified: extra.userVerified ?? true });
  const response = await postJson(
    '/login/passkey',
    { returnTo: extra.returnTo ?? '/account', response: answer },
    { ...(extra.cookies ?? {}), '__Host-passkey_tx': tx },
  );
  return { response, tx, answer, options: body };
}

beforeEach(async () => {
  now = NOW;
  ip = freshIp();
  setOAuthClock(() => now);
  await resetDatabase();
  google = new FakeGoogle();
  app = makeApp(google, () => now);
});

describe('signing in with a passkey', () => {
  it('signs in with the passkey alone, at aal2, and goes back where it was going', async () => {
    const { key } = await accountWithPasskey();
    const { response, options } = await passkeySignIn(key, { returnTo: '/account/security' });
    expect(options.allowCredentials ?? []).toEqual([]); // the browser offers its own passkeys
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ redirect: '/account/security' });
    const session = setCookies(response)['__Host-session'] ?? '';
    expect(session).not.toBe('');

    const row = await env.DB.prepare(
      'SELECT aal, method FROM sessions ORDER BY created_at DESC, rowid DESC LIMIT 1',
    ).first<{ aal: string; method: string }>();
    expect(row).toEqual({ aal: 'aal2', method: 'passkey' });
    // No second-factor step: the passkey already was both.
    const page = await call(app, '/account', {
      cookies: { '__Host-session': session },
      vars: { MFA_REQUIRED: 'true' },
    });
    expect(page.status).toBe(200);
  });

  it('needs user verification: a tap alone is not enough', async () => {
    const { key } = await accountWithPasskey();
    const { response } = await passkeySignIn(key, { userVerified: false });
    expect(response.status).toBe(400);
    expect(setCookies(response)['__Host-session']).toBeUndefined();
  });

  it('uses each challenge once, and only in the browser that asked for it', async () => {
    const { key } = await accountWithPasskey();
    const first = await passkeySignIn(key);
    expect(first.response.status).toBe(200);
    const replay = await postJson(
      '/login/passkey',
      { returnTo: '/account', response: first.answer },
      { '__Host-passkey_tx': first.tx },
    );
    expect(replay.status).toBe(400);

    const options = await postJson('/login/passkey/options', {});
    const answer = await key.authenticate(await options.json());
    const otherBrowser = await postJson('/login/passkey', {
      returnTo: '/account',
      response: answer,
    });
    expect(otherBrowser.status).toBe(400);
  });

  it('expires the challenge after 5 minutes', async () => {
    const { key } = await accountWithPasskey();
    const options = await postJson('/login/passkey/options', {});
    const tx = setCookies(options)['__Host-passkey_tx'] ?? '';
    const answer = await key.authenticate(await options.json());
    now += 5 * 60 + 1;
    const late = await postJson(
      '/login/passkey',
      { returnTo: '/account', response: answer },
      { '__Host-passkey_tx': tx },
    );
    expect(late.status).toBe(400);
  });

  it('refuses a passkey no account has, and logs the attempt', async () => {
    await accountWithPasskey();
    const { response } = await passkeySignIn(new SoftAuthenticator());
    expect(response.status).toBe(400);
    expect((await response.json<{ message: string }>()).message).toContain(
      'isn’t on a 2earl account',
    );
    expect(await count('audit_events', "event = 'login.failed'")).toBe(1);
  });

  it('refuses a passkey answer made for another site', async () => {
    const { key } = await accountWithPasskey();
    const phished = new SoftAuthenticator('login.2earl.com', 'https://login-2earl.example');
    Object.assign(phished, {
      credentialId: key.credentialId,
      keys: (key as unknown as { keys: unknown }).keys,
    });
    const { response } = await passkeySignIn(phished);
    expect(response.status).toBe(400);
  });

  it('refuses a suspended account', async () => {
    const { key } = await accountWithPasskey();
    await env.DB.prepare("UPDATE users SET status = 'suspended'").run();
    const { response } = await passkeySignIn(key);
    expect(response.status).toBe(403);
    expect(setCookies(response)['__Host-session']).toBeUndefined();
  });

  it('when confirming it’s you, accepts only the signed-in account’s own passkeys', async () => {
    const mine = await accountWithPasskey();
    const cookies = { '__Host-session': mine.session };
    const options = await postJson('/login/passkey/options', { reauth: true }, cookies);
    const body = await options.json<{ challenge: string; allowCredentials: { id: string }[] }>();
    expect(body.allowCredentials.map((c) => c.id)).toEqual([mine.key.id]);

    // Another account's passkey answers the same challenge: refused.
    const other = new SoftAuthenticator();
    await env.DB.prepare(
      "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES ('o', 'email', 'other@example.com', 'test', 0)",
    ).run();
    const otherSession =
      (await signIn(app, google, { claims: { sub: 'g-other', email: 'other@example.com' } }))
        .session ?? '';
    const otherOptions = await postJson(
      '/account/security/passkeys/options',
      {},
      {
        '__Host-session': otherSession,
      },
    );
    await postJson(
      '/account/security/passkeys',
      { label: 'Other', response: await other.register(await otherOptions.json()) },
      { '__Host-session': otherSession },
    );
    const refused = await postJson(
      '/login/passkey',
      { returnTo: '/account', response: await other.authenticate(body) },
      { ...cookies, '__Host-passkey_tx': setCookies(options)['__Host-passkey_tx'] ?? '' },
    );
    expect(refused.status).toBe(400);
  });

  it('refuses requests from other sites', async () => {
    const response = await call(app, '/login/passkey/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
      body: '{}',
      ip,
    });
    expect(response.status).toBe(403);
  });

  it('offers the passkey on the sign-in page, with autofill on the email field', async () => {
    const response = await call(app, '/');
    expect(response.headers.get('Content-Security-Policy')).toBe(MFA_CSP);
    const html = await response.text();
    expect(html).toContain('data-passkey="sign-in"');
    expect(html).toContain('autocomplete="email webauthn"');
    expect(html).toMatch(/<script type="module" src="\/passkey\.js\?v=[0-9a-f]{12}"><\/script>/);
  });
});

describe('signed-in devices', () => {
  async function sessionOn(userAgent: string): Promise<string> {
    const started = await signIn(app, google, { userAgent });
    return started.session ?? '';
  }

  it('lists each device by a coarse name, never the user agent', async () => {
    const laptop = await sessionOn(FIREFOX);
    const page = await call(app, '/account/sessions', { cookies: { '__Host-session': laptop } });
    const html = await page.text();
    expect(html).toContain('Firefox on Windows');
    expect(html).toContain('This device');
    expect(html).toContain('with Google');
    expect(html).not.toContain('Gecko');
    const stored = await env.DB.prepare('SELECT device FROM sessions').all<{ device: string }>();
    expect(stored.results.map((r) => r.device)).toEqual(['Firefox on Windows']);
  });

  it('signs out one other device, or all of them, never this one', async () => {
    const a = await sessionOn(FIREFOX);
    await sessionOn(
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1',
    );
    await sessionOn(
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/131.0 Safari/537.36',
    );
    expect(await count('sessions')).toBe(3);

    const html = await (
      await call(app, '/account/sessions', { cookies: { '__Host-session': a } })
    ).text();
    const refs = [...html.matchAll(/name="session" value="([0-9a-f]+)"/g)].map((m) => m[1] ?? '');
    expect(refs).toHaveLength(2); // the current device has no sign-out button

    const one = await call(app, '/account/sessions/end', {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams({ session: refs[0] ?? '' }),
      cookies: { '__Host-session': a },
      ip,
    });
    expect(one.headers.get('Location')).toBe('/account/sessions?ended=one');
    expect(await count('sessions')).toBe(2);

    const bogus = await call(app, '/account/sessions/end', {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams({ session: 'ffffffffffffffffffffffff' }),
      cookies: { '__Host-session': a },
      ip,
    });
    expect(bogus.status).toBe(303);
    expect(await count('sessions')).toBe(2);

    const rest = await call(app, '/account/sessions/end-others', {
      method: 'POST',
      headers: FORM,
      body: '',
      cookies: { '__Host-session': a },
      ip,
    });
    expect(rest.headers.get('Location')).toBe('/account/sessions?ended=others');
    expect(await count('sessions')).toBe(1);
    expect(await count('audit_events', "event = 'session.ended'")).toBe(2);
    // This browser is still signed in.
    expect((await call(app, '/account', { cookies: { '__Host-session': a } })).status).toBe(200);
  });

  it('refuses a sign-out posted from another site', async () => {
    const a = await sessionOn(FIREFOX);
    await sessionOn(FIREFOX);
    const response = await call(app, '/account/sessions/end-others', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://evil.example',
      },
      body: '',
      cookies: { '__Host-session': a },
      ip,
    });
    expect(response.status).toBe(403);
    expect(await count('sessions')).toBe(2);
  });
});

describe('device names', () => {
  it('names the browser and the system, and nothing more', () => {
    expect(deviceLabel(FIREFOX)).toBe('Firefox on Windows');
    expect(
      deviceLabel(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
      ),
    ).toBe('Edge on macOS');
    expect(
      deviceLabel(
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
      ),
    ).toBe('Chrome on Android');
    expect(
      deviceLabel(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
      ),
    ).toBe('Safari on iPhone');
    expect(deviceLabel('curl/8.0')).toBeNull();
    expect(deviceLabel(undefined)).toBeNull();
  });
});
