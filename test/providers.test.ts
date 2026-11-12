import { env } from 'cloudflare:workers';
import { exportPKCS8, exportSPKI, generateKeyPair, importSPKI, jwtVerify } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { setOAuthClock } from '../src/oauth';
import {
  APPLE_ISSUER,
  APPLE_TOKEN_URL,
  GITHUB_API,
  GITHUB_TOKEN_URL,
  MICROSOFT_CONSUMER_TENANT,
  MICROSOFT_TOKEN_URL,
} from '../src/providers';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  OWNER_EMAIL,
  call,
  count,
  freshIp,
  resetDatabase,
  setCookies,
  signIdToken,
  signIn,
  testJwks,
} from './helpers';

/** Phase 8e (DESIGN §4.14): sign in with Microsoft, GitHub and Apple. */

const appleKeys = await generateKeyPair('ES256', { extractable: true });
const applePublic = await importSPKI(await exportSPKI(appleKeys.publicKey), 'ES256');

const VARS = {
  LOGIN_LOCKED: 'false',
  MICROSOFT_CLIENT_ID: 'ms-client',
  MICROSOFT_CLIENT_SECRET: 'ms-secret',
  GITHUB_CLIENT_ID: 'gh-client',
  GITHUB_CLIENT_SECRET: 'gh-secret',
  APPLE_CLIENT_ID: 'com.2earl.login',
  APPLE_TEAM_ID: 'TEAM123456',
  APPLE_KEY_ID: 'KEY1234567',
  APPLE_PRIVATE_KEY: await exportPKCS8(appleKeys.privateKey),
};
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };

/** Microsoft's, GitHub's and Apple's endpoints, answering like the real ones. */
class FakeProviders {
  idToken: Record<string, unknown> = {};
  githubUser: Record<string, unknown> = { id: 4242, login: 'octo', name: 'Octo Cat' };
  githubEmails: Record<string, unknown>[] = [
    { email: 'octo@example.com', primary: true, verified: true },
  ];
  readonly requests: { url: string; body: URLSearchParams | null; auth: string | null }[] = [];
  readonly google = new FakeGoogle();

  readonly fetch: typeof fetch = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    const body = init?.body instanceof URLSearchParams ? init.body : null;
    const auth = new Headers(init?.headers).get('Authorization');
    this.requests.push({ url, body, auth });
    if (url === MICROSOFT_TOKEN_URL || url === APPLE_TOKEN_URL) {
      if (url === APPLE_TOKEN_URL) {
        // Apple's client secret: an ES256 JWT from the team's key.
        const { payload, protectedHeader } = await jwtVerify(
          body?.get('client_secret') ?? '',
          applePublic,
          {
            issuer: VARS.APPLE_TEAM_ID,
            audience: APPLE_ISSUER,
            subject: VARS.APPLE_CLIENT_ID,
            currentDate: new Date(now * 1000),
          },
        );
        expect(protectedHeader.kid).toBe(VARS.APPLE_KEY_ID);
        expect(payload.exp).toBeDefined();
      }
      return Response.json({ access_token: 'x', id_token: await signIdToken(this.idToken) });
    }
    if (url === GITHUB_TOKEN_URL) {
      if (!body?.get('code_verifier')) return Response.json({ error: 'bad_verification_code' });
      return Response.json({ access_token: 'gho_token', token_type: 'bearer' });
    }
    if (url === `${GITHUB_API}/user`) return Response.json(this.githubUser);
    if (url === `${GITHUB_API}/user/emails`) return Response.json(this.githubEmails);
    return this.google.fetch(input, init);
  };
}

let idps: FakeProviders;
let app: ReturnType<typeof createApp>;
let ip: string;
let now: number;

type CallInit = NonNullable<Parameters<typeof call>[2]>;

function req(path: string, init: Omit<CallInit, 'vars'> & { vars?: Record<string, unknown> } = {}) {
  // Optional provider secrets aren't in the generated Env type (src/providers.ts `setting`).
  const vars = { ...VARS, ...(init.vars ?? {}) } as NonNullable<CallInit['vars']>;
  return call(app, path, { ip, ...init, vars });
}

/** Starts a trip to `provider` and returns its state, nonce and the browser's cookie. */
async function start(path: string, cookies: Record<string, string> = {}) {
  const response = await req(path, { cookies });
  expect(response.status).toBe(302);
  const location = new URL(response.headers.get('Location') ?? 'about:blank');
  return {
    location,
    state: location.searchParams.get('state') ?? '',
    nonce: location.searchParams.get('nonce') ?? '',
    tx: setCookies(response)['__Host-login_tx'] ?? '',
  };
}

async function finish(
  provider: 'microsoft' | 'github',
  trip: { state: string; tx: string },
  cookies: Record<string, string> = {},
) {
  return req(`/callback/${provider}?code=the-code&state=${encodeURIComponent(trip.state)}`, {
    cookies: { ...cookies, '__Host-login_tx': trip.tx },
  });
}

function microsoftClaims(nonce: string, extra: Record<string, unknown> = {}) {
  return {
    iss: `https://login.microsoftonline.com/${MICROSOFT_CONSUMER_TENANT}/v2.0`,
    aud: VARS.MICROSOFT_CLIENT_ID,
    tid: MICROSOFT_CONSUMER_TENANT,
    sub: 'ms-sub-1',
    email: 'Person@Outlook.com',
    name: 'Ms Person',
    nonce,
    ...extra,
  };
}

beforeEach(async () => {
  now = NOW;
  ip = freshIp();
  setOAuthClock(() => now);
  await resetDatabase();
  await env.DB.prepare('DELETE FROM callback_tickets').run();
  idps = new FakeProviders();
  app = createApp({
    fetch: idps.fetch,
    googleJwks: testJwks,
    microsoftJwks: testJwks,
    appleJwks: testJwks,
    now: () => now,
  });
});

describe('the sign-in page', () => {
  it('offers only the providers whose keys are set', async () => {
    const on = await (await req('/')).text();
    for (const name of ['Microsoft', 'GitHub', 'Apple'])
      expect(on).toContain(`Continue with ${name}`);
    const off = await (
      await req('/', { vars: { GITHUB_CLIENT_SECRET: '', APPLE_PRIVATE_KEY: '' } })
    ).text();
    expect(off).toContain('Continue with Microsoft');
    expect(off).not.toContain('Continue with GitHub');
    expect(off).not.toContain('Continue with Apple');
    expect((await req('/login/github', { vars: { GITHUB_CLIENT_SECRET: '' } })).status).toBe(404);
  });
});

describe('Microsoft', () => {
  it('signs up a personal account, with PKCE and nonce, keyed on its subject', async () => {
    const trip = await start('/login/microsoft');
    expect(trip.location.origin + trip.location.pathname).toBe(
      'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    );
    expect(trip.location.searchParams.get('code_challenge_method')).toBe('S256');
    idps.idToken = microsoftClaims(trip.nonce);
    const response = await finish('microsoft', trip);
    expect(response.headers.get('Location')).toMatch(/^\/welcome/);
    const row = await env.DB.prepare(
      "SELECT i.subject, i.email, u.display_name FROM identities i JOIN users u ON u.id = i.user_id WHERE i.provider = 'microsoft'",
    ).first();
    expect(row).toEqual({
      subject: 'ms-sub-1',
      email: 'person@outlook.com',
      display_name: 'Ms Person',
    });
    const token = idps.requests.find((r) => r.url === MICROSOFT_TOKEN_URL);
    expect(token?.body?.get('code_verifier')).toBeTruthy();
    expect(await count('sessions', "method = 'microsoft'")).toBe(1);
  });

  it('refuses a work account whose domain isn’t verified, and accepts one that is', async () => {
    const tenant = '11111111-2222-3333-4444-555555555555';
    const work = {
      iss: `https://login.microsoftonline.com/${tenant}/v2.0`,
      tid: tenant,
      email: 'ceo@bank.example',
    };
    let trip = await start('/login/microsoft');
    idps.idToken = microsoftClaims(trip.nonce, work);
    const refused = await finish('microsoft', trip);
    expect(refused.status).toBe(400);
    expect(await refused.text()).toContain('no verified email address');

    trip = await start('/login/microsoft');
    idps.idToken = microsoftClaims(trip.nonce, { ...work, xms_edov: true });
    expect((await finish('microsoft', trip)).status).toBe(303);
  });

  it('refuses a token whose issuer names another tenant, or with the wrong nonce', async () => {
    let trip = await start('/login/microsoft');
    idps.idToken = microsoftClaims(trip.nonce, {
      iss: 'https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0',
    });
    expect((await finish('microsoft', trip)).status).toBe(400);
    trip = await start('/login/microsoft');
    idps.idToken = microsoftClaims('another-nonce');
    expect((await finish('microsoft', trip)).status).toBe(400);
    expect(await count('users')).toBe(0);
  });
});

describe('GitHub', () => {
  it('signs up with the verified primary address, keyed on the numeric ID', async () => {
    const trip = await start('/login/github');
    expect(trip.location.searchParams.get('scope')).toBe('read:user user:email');
    const response = await finish('github', trip);
    expect(response.headers.get('Location')).toMatch(/^\/welcome/);
    const row = await env.DB.prepare(
      "SELECT subject, email FROM identities WHERE provider = 'github'",
    ).first();
    expect(row).toEqual({ subject: '4242', email: 'octo@example.com' });
    const api = idps.requests.find((r) => r.url === `${GITHUB_API}/user`);
    expect(api?.auth).toBe('Bearer gho_token');
  });

  it('refuses an account without a verified primary address', async () => {
    idps.githubEmails = [{ email: 'octo@example.com', primary: true, verified: false }];
    const trip = await start('/login/github');
    const response = await finish('github', trip);
    expect(response.status).toBe(400);
    expect(await count('users')).toBe(0);
  });

  it('can’t finish a trip that went to another provider', async () => {
    const trip = await start('/login/microsoft');
    expect((await finish('github', trip)).status).toBe(400);
    expect(await count('users')).toBe(0);
  });
});

describe('Apple', () => {
  it('takes the cross-site form post through a ticket, then signs up with the name Apple sent once', async () => {
    const trip = await start('/login/apple');
    expect(trip.location.searchParams.get('response_mode')).toBe('form_post');
    idps.idToken = {
      iss: APPLE_ISSUER,
      aud: VARS.APPLE_CLIENT_ID,
      sub: 'apple-sub-1',
      email: 'x1y2@privaterelay.appleid.com',
      email_verified: 'true',
      nonce: trip.nonce,
    };
    // Apple's POST comes from appleid.apple.com: no cookies.
    const posted = await req('/callback/apple', {
      method: 'POST',
      headers: { ...FORM, Origin: 'https://appleid.apple.com' },
      body: new URLSearchParams({
        state: trip.state,
        code: 'apple-code',
        user: JSON.stringify({ name: { firstName: 'Ada', lastName: 'Apple' } }),
      }),
    });
    expect(posted.status).toBe(303);
    const next = posted.headers.get('Location') ?? '';
    expect(next).toMatch(/^\/callback\/apple\?ticket=/);

    const done = await req(next, { cookies: { '__Host-login_tx': trip.tx } });
    expect(done.headers.get('Location')).toMatch(/^\/welcome/);
    const user = await env.DB.prepare('SELECT display_name, primary_email FROM users').first();
    expect(user).toEqual({
      display_name: 'Ada Apple',
      primary_email: 'x1y2@privaterelay.appleid.com',
    });

    // The ticket works once.
    expect((await req(next, { cookies: { '__Host-login_tx': trip.tx } })).status).toBe(400);
  });

  it('needs this browser’s cookie: a ticket alone signs nobody in', async () => {
    const trip = await start('/login/apple');
    idps.idToken = {
      iss: APPLE_ISSUER,
      aud: VARS.APPLE_CLIENT_ID,
      sub: 's',
      email: 'a@b.example',
      email_verified: true,
      nonce: trip.nonce,
    };
    const posted = await req('/callback/apple', {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams({ state: trip.state, code: 'c' }),
    });
    const stolen = await req(posted.headers.get('Location') ?? '');
    expect(stolen.status).toBe(400);
    expect(await count('users')).toBe(0);
  });
});

describe('one account per address (THREAT_MODEL B3)', () => {
  it('sends a new GitHub sign-up to the Google account that has its address', async () => {
    await signIn(app, idps.google);
    idps.githubEmails = [{ email: OWNER_EMAIL, primary: true, verified: true }];
    const trip = await start('/login/github');
    const response = await finish('github', trip);
    expect(response.status).toBe(409);
    expect(await response.text()).toContain('Continue with Google');
    expect(await count('identities', "provider = 'github'")).toBe(0);
  });

  it('sends an email-code sign-up to the GitHub account that has its address', async () => {
    await finish('github', await start('/login/github'));
    const sent: { text: string }[] = [];
    const mailer = {
      send: (message: { text: string }) => {
        sent.push(message);
        return Promise.resolve({ messageId: 'm' });
      },
    };
    const asked = await req('/login/email', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ email: 'octo@example.com' }),
      vars: { MAILER: mailer },
    });
    expect(asked.status).toBe(303);
    const code = /\b(\d{6})\b/.exec(sent.at(-1)?.text ?? '')?.[1] ?? '';
    const typed = await req('/login/email/code', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ code }),
      cookies: { '__Host-email_code': setCookies(asked)['__Host-email_code'] ?? '' },
      vars: { MAILER: mailer },
    });
    expect(typed.status).toBe(409);
    expect(await typed.text()).toContain('Continue with GitHub');
    expect(await count('identities', "provider = 'email'")).toBe(0);
  });

  it('lets a signed-in account add GitHub, but not one that belongs to someone else', async () => {
    // Someone else already signs in with this GitHub account.
    await finish('github', await start('/login/github'));
    await env.DB.prepare('DELETE FROM sessions').run();

    const owner = (await signIn(app, idps.google)).session ?? '';
    const cookies = { '__Host-session': owner };
    const link = await req('/account/methods/github', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: '',
      cookies,
    });
    const trip = {
      state: new URL(link.headers.get('Location') ?? 'about:blank').searchParams.get('state') ?? '',
      tx: setCookies(link)['__Host-login_tx'] ?? '',
    };
    const taken = await finish('github', trip, cookies);
    expect(taken.status).toBe(409);
    expect(await taken.text()).toContain('That GitHub account belongs to another 2earl account');

    idps.githubUser = { id: 777, login: 'mine' };
    idps.githubEmails = [{ email: 'mine@example.com', primary: true, verified: true }];
    const again = await req('/account/methods/github', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: '',
      cookies,
    });
    const added = await finish(
      'github',
      {
        state:
          new URL(again.headers.get('Location') ?? 'about:blank').searchParams.get('state') ?? '',
        tx: setCookies(again)['__Host-login_tx'] ?? '',
      },
      cookies,
    );
    expect(added.headers.get('Location')).toBe('/account?added=github');
    const page = await (await req('/account', { cookies })).text();
    expect(page).toContain('GitHub');
    expect(page).toContain('Add Microsoft');
    expect(page).not.toContain('Add GitHub');
  });
});

describe('deleting an account that signs in with GitHub', () => {
  it('confirms with GitHub, the same GitHub account', async () => {
    const signedUp = await finish('github', await start('/login/github'));
    const session = setCookies(signedUp)['__Host-session'] ?? '';
    const cookies = { '__Host-session': session };
    const page = await (await req('/account/delete', { cookies })).text();
    expect(page).toContain('Confirm with GitHub');

    const asked = await req('/account/delete', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams({ confirm: 'on', method: 'github' }),
      cookies,
    });
    expect(asked.status).toBe(302);
    const location = new URL(asked.headers.get('Location') ?? 'about:blank');
    expect(location.origin).toBe('https://github.com');
    const done = await finish(
      'github',
      {
        state: location.searchParams.get('state') ?? '',
        tx: setCookies(asked)['__Host-login_tx'] ?? '',
      },
      cookies,
    );
    expect(done.status).toBe(303);
    expect(await count('users')).toBe(0);
  });
});

describe('sign-up by invitation only', () => {
  it('refuses a new GitHub account without an invitation', async () => {
    const trip = await start('/login/github');
    const response = await req(`/callback/github?code=c&state=${trip.state}`, {
      cookies: { '__Host-login_tx': trip.tx },
      vars: { LOGIN_LOCKED: 'true' },
    });
    expect(response.status).toBe(403);
    expect(await count('users')).toBe(0);
  });
});
