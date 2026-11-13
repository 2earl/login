import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { setOAuthClock } from '../src/oauth';
import { MFA_CSP } from '../src/security-headers';
import { base32Encode, totpCode, totpStep, verifyTotp } from '../src/totp';
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

const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', ...SAME_ORIGIN };
const JSON_POST = { 'Content-Type': 'application/json', ...SAME_ORIGIN };

let google: FakeGoogle;
let now: number;
let app: ReturnType<typeof makeApp>;
let session: string;
/** One client IP per test, so the per-network rate limiter doesn't carry over between tests. */
let ip: string;

const cookie = (value = session) => ({ '__Host-session': value });

async function newSession(): Promise<string> {
  return (await signIn(app, google)).session ?? '';
}

function post(path: string, body: Record<string, string>, value = session) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(body),
    cookies: cookie(value),
    ip,
  });
}

function postJson(path: string, body: unknown, value = session) {
  return call(app, path, {
    method: 'POST',
    headers: JSON_POST,
    body: JSON.stringify(body),
    cookies: cookie(value),
    ip,
  });
}

/** Opens the authenticator-app setup page and returns the secret it shows. */
async function openTotpSetup(): Promise<string> {
  const page = await call(app, '/account/security/totp', { cookies: cookie() });
  expect(page.status).toBe(200);
  const secret = /<code class="secret">([A-Z2-7 ]+)<\/code>/.exec(await page.text())?.[1] ?? '';
  return secret.replace(/ /g, '');
}

/** Sets up an authenticator app; returns its secret and the recovery codes shown once. */
async function enrolTotp(): Promise<{ secret: string; codes: string[] }> {
  const secret = await openTotpSetup();
  const turnOn = await post('/account/security/totp', {
    code: await totpCode(secret, totpStep(now)),
  });
  expect(turnOn.status).toBe(303);
  expect(turnOn.headers.get('Location')).toBe('/account/security/recovery-codes');
  const page = await (
    await call(app, '/account/security/recovery-codes', { cookies: cookie() })
  ).text();
  const codes = [...page.matchAll(/<li><code>([0-9a-z-]+)<\/code><\/li>/g)].map((m) => m[1] ?? '');
  return { secret, codes };
}

async function enrolPasskey(authenticator: SoftAuthenticator, label = 'Test key') {
  const options = await postJson('/account/security/passkeys/options', {});
  expect(options.status).toBe(200);
  const body = await options.json<{ challenge: string; rp: { id: string } }>();
  expect(body.rp.id).toBe('login.2earl.com');
  return postJson('/account/security/passkeys', {
    label,
    response: await authenticator.register(body),
  });
}

async function passkeyChallenge(authenticator: SoftAuthenticator, value = session) {
  const options = await postJson('/mfa/passkey/options', {}, value);
  expect(options.status).toBe(200);
  const body = await options.json<{ challenge: string }>();
  return postJson(
    '/mfa/passkey',
    { returnTo: '/account', response: await authenticator.authenticate(body) },
    value,
  );
}

beforeEach(async () => {
  now = NOW;
  ip = freshIp();
  setOAuthClock(() => now);
  await resetDatabase();
  google = new FakeGoogle();
  app = makeApp(google, () => now);
  session = await newSession();
});

describe('TOTP (RFC 6238)', () => {
  // RFC 6238 Appendix B, SHA-1 seed "12345678901234567890"; the last 6 of the 8-digit values.
  const seed = base32Encode(new TextEncoder().encode('12345678901234567890'));

  it('matches the RFC test vectors', async () => {
    expect(await totpCode(seed, totpStep(59))).toBe('287082');
    expect(await totpCode(seed, totpStep(1111111109))).toBe('081804');
    expect(await totpCode(seed, totpStep(2000000000))).toBe('279037');
  });

  it('accepts one step of drift, never a step at or before the last one used', async () => {
    const t = 1111111109;
    const previous = await totpCode(seed, totpStep(t) - 1);
    expect(await verifyTotp(seed, previous, t, null)).toBe(totpStep(t) - 1);
    expect(await verifyTotp(seed, previous, t, totpStep(t) - 1)).toBeNull();
    expect(await verifyTotp(seed, await totpCode(seed, totpStep(t) - 2), t, null)).toBeNull();
    expect(await verifyTotp(seed, 'abc123', t, null)).toBeNull();
  });
});

describe('security page', () => {
  it('shows the factors and loads the passkey script, with a CSP that allows only it', async () => {
    const account = await (await call(app, '/account', { cookies: cookie() })).text();
    expect(account).toContain('glance-alert">Off<');

    const response = await call(app, '/account/security', { cookies: cookie() });
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Security-Policy')).toBe(MFA_CSP);
    const html = await response.text();
    expect(html).toMatch(/<script type="module" src="\/passkey\.js\?v=[0-9a-f]{12}"><\/script>/);
    expect(html).toContain('data-passkey="register"');
  });

  it('keeps scripts off every other page', async () => {
    const account = await call(app, '/account', { cookies: cookie() });
    expect(account.headers.get('Content-Security-Policy')).not.toContain('script-src');
    expect(await account.text()).not.toContain('<script');
  });
});

describe('authenticator app', () => {
  it('turns on with a correct code, stores the secret encrypted, shows codes once', async () => {
    const { secret, codes } = await enrolTotp();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);

    const row = await env.DB.prepare('SELECT totp_secret_enc FROM mfa_factors').first<{
      totp_secret_enc: string;
    }>();
    expect(row?.totp_secret_enc).not.toContain(secret);
    expect(await count('recovery_codes', 'used_at IS NULL')).toBe(10);
    expect(await count('audit_events', "event = 'mfa.enrolled'")).toBe(1);

    const again = await call(app, '/account/security/recovery-codes', { cookies: cookie() });
    expect(again.headers.get('Location')).toBe('/account/security');
  });

  it('rejects a wrong code during setup and keeps the same secret to retry', async () => {
    const secret = await openTotpSetup();
    const wrong = await post('/account/security/totp', { code: '000000' });
    expect(wrong.status).toBe(400);
    expect(await wrong.text()).toContain(secret.slice(0, 4));
    expect(await count('mfa_factors')).toBe(0);
  });

  it('challenges every new session, and refuses a code used before', async () => {
    const { secret } = await enrolTotp();
    session = await newSession();

    const account = await call(app, '/account', { cookies: cookie() });
    expect(account.status).toBe(303);
    expect(account.headers.get('Location')).toBe('/mfa?return_to=%2Faccount');
    const disconnect = await post('/account/apps/disconnect', { grant: 'x' });
    expect(disconnect.status).toBe(403);

    const challenge = await call(app, '/mfa?return_to=%2Faccount', { cookies: cookie() });
    expect(challenge.status).toBe(200);
    expect(await challenge.text()).toContain('Code from your authenticator app');

    // The code used for setup was this step; it can't be used again.
    const reused = await post('/mfa/totp', {
      code: await totpCode(secret, totpStep(now)),
      return_to: '/account',
    });
    expect(reused.status).toBe(400);

    now += 30;
    const ok = await post('/mfa/totp', {
      code: await totpCode(secret, totpStep(now)),
      return_to: '/account',
    });
    expect(ok.status).toBe(303);
    expect(ok.headers.get('Location')).toBe('/account');
    expect((await call(app, '/account', { cookies: cookie() })).status).toBe(200);
  });

  it('accepts a code once even when it arrives twice at the same moment', async () => {
    const { secret } = await enrolTotp();
    session = await newSession();
    now += 30;
    const code = await totpCode(secret, totpStep(now));
    const results = await Promise.all([
      post('/mfa/totp', { code, return_to: '/account' }),
      post('/mfa/totp', { code, return_to: '/account' }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([303, 400]);
  });

  it('locks the step for 15 minutes after 5 wrong codes', async () => {
    const { secret } = await enrolTotp();
    session = await newSession();
    for (let i = 0; i < 4; i++) {
      expect((await post('/mfa/totp', { code: '000000', return_to: '/account' })).status).toBe(400);
    }
    const fifth = await post('/mfa/totp', { code: '000000', return_to: '/account' });
    expect(fifth.status).toBe(429);
    expect(await fifth.text()).toContain('Too many wrong codes');

    now += 60;
    const locked = await post('/mfa/totp', {
      code: await totpCode(secret, totpStep(now)),
      return_to: '/account',
    });
    expect(locked.status).toBe(429);
    expect(await count('audit_events', "event = 'mfa.locked'")).toBe(1);

    now += 15 * 60;
    const unlocked = await post('/mfa/totp', {
      code: await totpCode(secret, totpStep(now)),
      return_to: '/account',
    });
    expect(unlocked.status).toBe(303);
  });

  it('refuses a challenge posted from another site', async () => {
    await enrolTotp();
    const response = await call(app, '/mfa/totp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://evil.example',
      },
      body: new URLSearchParams({ code: '000000' }),
      cookies: cookie(),
    });
    expect(response.status).toBe(403);
  });
});

describe('recovery codes', () => {
  it('each code works once, in any case and with or without the dash', async () => {
    const { codes } = await enrolTotp();
    const code = codes[0] ?? '';
    session = await newSession();

    const used = await post('/mfa/recovery', {
      code: code.toUpperCase().replace('-', ''),
      return_to: '/account',
    });
    expect(used.status).toBe(303);
    expect(used.headers.get('Location')).toBe('/account');
    expect(await count('recovery_codes', 'used_at IS NULL')).toBe(9);

    session = await newSession();
    expect((await post('/mfa/recovery', { code, return_to: '/account' })).status).toBe(400);
  });
});

describe('passkeys', () => {
  it('adds a passkey and uses it for the challenge', async () => {
    const key = new SoftAuthenticator();
    const added = await enrolPasskey(key, 'Laptop');
    expect(added.status).toBe(200);
    expect(await added.json()).toEqual({ redirect: '/account/security/recovery-codes' });
    const row = await env.DB.prepare(
      'SELECT label, webauthn_credential_id, webauthn_sign_count FROM mfa_factors',
    ).first<{ label: string; webauthn_credential_id: string; webauthn_sign_count: number }>();
    expect(row).toEqual({
      label: 'Laptop',
      webauthn_credential_id: key.id,
      webauthn_sign_count: 0,
    });

    session = await newSession();
    expect((await call(app, '/account', { cookies: cookie() })).status).toBe(303);
    const passed = await passkeyChallenge(key);
    expect(passed.status).toBe(200);
    expect(await passed.json()).toEqual({ redirect: '/account' });
    expect((await call(app, '/account', { cookies: cookie() })).status).toBe(200);

    const counter = await env.DB.prepare('SELECT webauthn_sign_count AS n FROM mfa_factors').first<{
      n: number;
    }>();
    expect(counter?.n).toBe(1);
  });

  it('rejects a passkey that is not on this account', async () => {
    await enrolPasskey(new SoftAuthenticator());
    session = await newSession();
    const response = await passkeyChallenge(new SoftAuthenticator());
    expect(response.status).toBe(400);
    expect(await count('audit_events', "event = 'mfa.failed'")).toBe(1);
  });

  it('rejects a passkey answer made for another site', async () => {
    const key = new SoftAuthenticator();
    await enrolPasskey(key);
    session = await newSession();
    const phished = new SoftAuthenticator('login.2earl.com', 'https://login-2earl.example');
    Object.assign(phished, {
      credentialId: key.credentialId,
      keys: (key as unknown as { keys: unknown }).keys,
    });
    const response = await passkeyChallenge(phished);
    expect(response.status).toBe(400);
  });

  it('refuses a challenge answer used twice', async () => {
    const key = new SoftAuthenticator();
    await enrolPasskey(key);
    session = await newSession();
    const options = await (
      await postJson('/mfa/passkey/options', {})
    ).json<{ challenge: string }>();
    const answer = await key.authenticate(options);
    expect(
      (await postJson('/mfa/passkey', { returnTo: '/account', response: answer })).status,
    ).toBe(200);
    expect(
      (await postJson('/mfa/passkey', { returnTo: '/account', response: answer })).status,
    ).toBe(400);
  });
});

describe('changing factors', () => {
  it('needs a recent Google sign-in for the first factor', async () => {
    now += 11 * 60;
    const page = await call(app, '/account/security/totp', { cookies: cookie() });
    expect(page.headers.get('Location')).toBe(
      '/login?reauth=1&return_to=%2Faccount%2Fsecurity%2Ftotp',
    );
    const options = await postJson('/account/security/passkeys/options', {});
    expect(await options.json()).toEqual({
      redirect: '/login?reauth=1&return_to=%2Faccount%2Fsecurity',
    });
    // reauth=1 asks a signed-in browser to sign in again, with the account's own methods.
    const reauth = await call(app, '/login?reauth=1&return_to=%2Faccount%2Fsecurity', {
      cookies: cookie(),
    });
    const html = await reauth.text();
    expect(html).toContain('Confirm it’s you');
    expect(html).toContain('href="/login/google?return_to=%2Faccount%2Fsecurity&amp;reauth=1"');
    expect(html).not.toContain('name="email" type="email"');
    const google = await call(app, '/login/google?return_to=%2Faccount%2Fsecurity&reauth=1', {
      cookies: cookie(),
    });
    expect(google.headers.get('Location')).toMatch(/^https:\/\/accounts\.google\.com\//);
  });

  it('needs a second-factor check from the last 5 minutes to add or remove one', async () => {
    await enrolTotp();
    const factor = await env.DB.prepare('SELECT id FROM mfa_factors').first<{ id: string }>();
    now += 6 * 60;

    const options = await postJson('/account/security/passkeys/options', {});
    expect(await options.json()).toEqual({
      redirect: '/mfa?step_up=1&return_to=%2Faccount%2Fsecurity',
    });
    const remove = await post('/account/security/factors/remove', { factor: factor?.id ?? '' });
    expect(remove.headers.get('Location')).toBe('/mfa?step_up=1&return_to=%2Faccount%2Fsecurity');
    expect(await count('mfa_factors')).toBe(1);
  });

  it('removing the last factor also removes the recovery codes', async () => {
    await enrolTotp();
    const factor = await env.DB.prepare('SELECT id FROM mfa_factors').first<{ id: string }>();
    const removed = await post('/account/security/factors/remove', { factor: factor?.id ?? '' });
    expect(removed.headers.get('Location')).toBe('/account/security?done=removed');
    expect(await count('mfa_factors')).toBe(0);
    expect(await count('recovery_codes')).toBe(0);
  });
});

describe('MFA_REQUIRED', () => {
  const required = { MFA_REQUIRED: 'true' };

  it('sends a user without a factor to set one up, and nowhere else', async () => {
    const account = await call(app, '/account', { cookies: cookie(), vars: required });
    expect(account.headers.get('Location')).toBe('/account/security?return_to=%2Faccount');
    const security = await call(app, '/account/security', { cookies: cookie(), vars: required });
    expect(security.status).toBe(200);
    expect(await security.text()).toContain('2earl requires a second factor');
    // Data-protection rights stay available.
    expect((await call(app, '/account/export', { cookies: cookie(), vars: required })).status).toBe(
      200,
    );
  });

  it('refuses to remove the only factor', async () => {
    await enrolTotp();
    const factor = await env.DB.prepare('SELECT id FROM mfa_factors').first<{ id: string }>();
    const response = await call(app, '/account/security/factors/remove', {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams({ factor: factor?.id ?? '' }),
      cookies: cookie(),
      vars: required,
    });
    expect(response.status).toBe(400);
    expect(await count('mfa_factors')).toBe(1);
  });

  it('turning the flag off never skips the challenge for an enrolled user', async () => {
    await enrolTotp();
    session = await newSession();
    const account = await call(app, '/account', {
      cookies: cookie(),
      vars: { MFA_REQUIRED: 'false' },
    });
    expect(account.headers.get('Location')).toBe('/mfa?return_to=%2Faccount');
  });
});

describe('with an account that has a second factor', () => {
  it('deletion needs a second-factor check from the last 5 minutes', async () => {
    await enrolTotp();
    now += 6 * 60;
    const response = await post('/account/delete', { confirm: 'on' });
    expect(response.headers.get('Location')).toBe('/mfa?step_up=1&return_to=%2Faccount%2Fdelete');
    expect(await count('login_tx', "purpose = 'delete_account'")).toBe(0);
  });

  it('the export lists factors without their secrets', async () => {
    const { secret, codes } = await enrolTotp();
    const raw = await (await call(app, '/account/export', { cookies: cookie() })).text();
    const data = JSON.parse(raw) as {
      secondFactor: { factors: unknown[]; recoveryCodesUnused: number };
    };
    expect(data.secondFactor.factors).toEqual([
      expect.objectContaining({ type: 'authenticator app', name: 'Authenticator app' }),
    ]);
    expect(data.secondFactor.recoveryCodesUnused).toBe(10);
    expect(raw).not.toContain(secret);
    for (const code of codes) expect(raw).not.toContain(code);
  });

  it('a new sign-in can reach the consent page only after the challenge', async () => {
    await enrolTotp();
    session = await newSession();
    const authorize = await call(app, '/authorize?client_id=x', { cookies: cookie() });
    expect(authorize.status).toBe(303);
    expect(authorize.headers.get('Location')).toBe('/mfa?return_to=%2Fauthorize%3Fclient_id%3Dx');
    expect(setCookies(authorize)['__Host-session']).toBeUndefined();
  });
});

describe('the security page', () => {
  it('lists recent security activity, with where it came from', async () => {
    await resetDatabase();
    const google = new FakeGoogle();
    const signed = makeApp(google, () => NOW);
    const { session } = await signIn(signed, google);
    const html = await (
      await call(signed, '/account/security', { cookies: { '__Host-session': session ?? '' } })
    ).text();
    expect(html).toContain('Recent activity');
    expect(html).toContain('Signed in with Google');
  });
});
