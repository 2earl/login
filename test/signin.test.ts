import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { SESSION_ABSOLUTE_SECONDS, SESSION_IDLE_SECONDS } from '../src/sessions';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  OWNER_EMAIL,
  call,
  count,
  foreignKey,
  freshIp,
  makeApp,
  rawSetCookie,
  resetDatabase,
  setCookies,
  signIdToken,
  signIn,
  startLogin,
} from './helpers';

let google: FakeGoogle;
let app: ReturnType<typeof makeApp>;

beforeEach(async () => {
  await resetDatabase();
  google = new FakeGoogle();
  app = makeApp(google);
});

describe('GET /login', () => {
  it('redirects to Google with state, nonce and an S256 PKCE challenge', async () => {
    const { response, location } = await startLogin(app, freshIp());
    expect(response.status).toBe(302);
    expect(location.origin + location.pathname).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
    const p = location.searchParams;
    expect(p.get('client_id')).toBe(env.GOOGLE_CLIENT_ID);
    expect(p.get('redirect_uri')).toBe(`${ORIGIN}/callback/google`);
    expect(p.get('response_type')).toBe('code');
    expect(p.get('scope')).toBe('openid email profile');
    expect(p.get('code_challenge_method')).toBe('S256');
    expect(p.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get('state')?.length).toBeGreaterThanOrEqual(43);
    expect(p.get('nonce')?.length).toBeGreaterThanOrEqual(43);
  });

  it('binds the sign-in to the browser with a __Host- cookie', async () => {
    const { response } = await startLogin(app, freshIp());
    const cookie = rawSetCookie(response, '__Host-login_tx') ?? '';
    expect(cookie).toContain('Path=/');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Max-Age=600');
    expect(cookie).not.toContain('Domain=');
  });

  it('stores only a hash of the transaction cookie', async () => {
    const { txCookie } = await startLogin(app, freshIp());
    expect(await count('login_tx', 'id_hash = ?', txCookie)).toBe(0);
    expect(await count('login_tx')).toBe(1);
  });

  it('rate-limits repeated attempts from one address', async () => {
    const ip = freshIp();
    const statuses: number[] = [];
    for (let i = 0; i < 25; i++) statuses.push((await call(app, '/login', { ip })).status);
    expect(statuses).toContain(429);
  });
});

describe('GET /callback/google', () => {
  it('signs the owner in and creates the account', async () => {
    const { callback, session } = await signIn(app, google);
    expect(callback.status).toBe(303);
    expect(callback.headers.get('Location')).toBe('/account');
    expect(session).toBeTruthy();
    expect(await count('users')).toBe(1);
    expect(await count('identities', "provider = 'google' AND subject = 'google-sub-owner'")).toBe(
      1,
    );
  });

  it('sends the PKCE verifier and the exact redirect URI to Google', async () => {
    await signIn(app, google);
    const request = google.tokenRequests[0];
    expect(request?.get('grant_type')).toBe('authorization_code');
    expect(request?.get('code')).toBe('auth-code');
    expect(request?.get('redirect_uri')).toBe(`${ORIGIN}/callback/google`);
    expect(request?.get('code_verifier')?.length).toBeGreaterThanOrEqual(43);
    expect(request?.get('client_secret')).toBe(env.GOOGLE_CLIENT_SECRET);
  });

  it('sets a __Host- session cookie with a 7-day lifetime and stores only its hash', async () => {
    const { callback, session } = await signIn(app, google);
    const cookie = rawSetCookie(callback, '__Host-session') ?? '';
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain(`Max-Age=${String(SESSION_ABSOLUTE_SECONDS)}`);
    expect(await count('sessions', 'id_hash = ?', session)).toBe(0);
    expect(await count('sessions')).toBe(1);
  });

  it('pins the owner allowlist entry to the Google subject on first sign-in', async () => {
    await signIn(app, google);
    expect(await count('allowlist', "kind = 'google_sub' AND value = 'google-sub-owner'")).toBe(1);
    expect(await count('allowlist', "kind = 'email'")).toBe(0);
  });

  it('then refuses a different Google account that has the same email', async () => {
    await signIn(app, google);
    const second = await signIn(app, google, { claims: { sub: 'google-sub-other' } });
    expect(second.callback.status).toBe(403);
    expect(second.session).toBeUndefined();
  });

  it('refuses accounts that are not on the allowlist, without creating them', async () => {
    const { callback, session } = await signIn(app, google, {
      claims: { sub: 'google-sub-stranger', email: 'stranger@example.com' },
    });
    expect(callback.status).toBe(403);
    expect(session).toBeUndefined();
    expect(await count('users')).toBe(0);
    expect(await count('audit_events', "event = 'login.denied'")).toBe(1);
  });

  it('cannot be replayed: the transaction is single-use', async () => {
    const ip = freshIp();
    const login = await startLogin(app, ip);
    google.nextIdToken = await signIdToken({ nonce: login.nonce });
    const path = `/callback/google?code=auth-code&state=${encodeURIComponent(login.state)}`;
    const cookies = { '__Host-login_tx': login.txCookie };
    expect((await call(app, path, { ip, cookies })).status).toBe(303);
    expect((await call(app, path, { ip, cookies })).status).toBe(400);
  });

  it('rejects a wrong state', async () => {
    const ip = freshIp();
    const login = await startLogin(app, ip);
    google.nextIdToken = await signIdToken({ nonce: login.nonce });
    const response = await call(app, '/callback/google?code=auth-code&state=forged', {
      ip,
      cookies: { '__Host-login_tx': login.txCookie },
    });
    expect(response.status).toBe(400);
    expect(google.tokenRequests).toHaveLength(0);
  });

  it('rejects a callback without the transaction cookie (login CSRF)', async () => {
    const ip = freshIp();
    const login = await startLogin(app, ip);
    const response = await call(
      app,
      `/callback/google?code=auth-code&state=${encodeURIComponent(login.state)}`,
      { ip },
    );
    expect(response.status).toBe(400);
  });

  it('rejects an expired transaction', async () => {
    const ip = freshIp();
    const login = await startLogin(app, ip);
    google.nextIdToken = await signIdToken({ nonce: login.nonce });
    const later = makeApp(google, () => NOW + 601);
    const response = await call(
      later,
      `/callback/google?code=auth-code&state=${encodeURIComponent(login.state)}`,
      { ip, cookies: { '__Host-login_tx': login.txCookie } },
    );
    expect(response.status).toBe(400);
  });

  it.each([
    ['a wrong nonce', { nonce: 'other-nonce' }],
    ['a wrong audience', { aud: 'someone-elses-client' }],
    ['a wrong issuer', { iss: 'https://evil.example' }],
    ['an unverified email', { email_verified: false }],
    ['an expired token', { exp: NOW - 120 }],
  ])('rejects an ID token with %s', async (_label, claims) => {
    const ip = freshIp();
    const login = await startLogin(app, ip);
    google.nextIdToken = await signIdToken({ nonce: login.nonce, ...claims });
    const response = await call(
      app,
      `/callback/google?code=auth-code&state=${encodeURIComponent(login.state)}`,
      { ip, cookies: { '__Host-login_tx': login.txCookie } },
    );
    expect(response.status).toBe(400);
    expect(setCookies(response)['__Host-session']).toBeUndefined();
  });

  it('rejects an ID token signed by an unknown key', async () => {
    const ip = freshIp();
    const login = await startLogin(app, ip);
    google.nextIdToken = await signIdToken({ nonce: login.nonce }, { key: foreignKey });
    const response = await call(
      app,
      `/callback/google?code=auth-code&state=${encodeURIComponent(login.state)}`,
      { ip, cookies: { '__Host-login_tx': login.txCookie } },
    );
    expect(response.status).toBe(400);
  });

  it('handles an error returned by Google', async () => {
    const ip = freshIp();
    const login = await startLogin(app, ip);
    const response = await call(
      app,
      `/callback/google?error=access_denied&state=${encodeURIComponent(login.state)}`,
      { ip, cookies: { '__Host-login_tx': login.txCookie } },
    );
    expect(response.status).toBe(400);
    expect(google.tokenRequests).toHaveLength(0);
  });

  it('never redirects outside this site after sign-in', async () => {
    const { callback } = await signIn(app, google, {
      query: '?return_to=' + encodeURIComponent('https://evil.example/steal'),
    });
    expect(callback.headers.get('Location')).toBe('/account');
  });

  it('records events without the email address', async () => {
    await signIn(app, google);
    const { results } = await env.DB.prepare('SELECT event, detail FROM audit_events').all<{
      event: string;
      detail: string | null;
    }>();
    expect(results.map((r) => r.event)).toEqual(
      expect.arrayContaining([
        'login.started',
        'allowlist.pinned',
        'user.created',
        'login.succeeded',
      ]),
    );
    expect(JSON.stringify(results)).not.toContain(OWNER_EMAIL);
  });
});

describe('sessions', () => {
  it('show the account page to a signed-in user', async () => {
    const { session } = await signIn(app, google);
    const response = await call(app, '/account', { cookies: { '__Host-session': session ?? '' } });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain(OWNER_EMAIL);
  });

  it('send anonymous visitors of /account to sign-in', async () => {
    const response = await call(app, '/account');
    expect(response.status).toBe(303);
    expect(response.headers.get('Location')).toBe('/login?return_to=%2Faccount');
  });

  it('expire after 12 hours without use', async () => {
    const { session } = await signIn(app, google);
    const later = makeApp(google, () => NOW + SESSION_IDLE_SECONDS + 1);
    const response = await call(later, '/account', {
      cookies: { '__Host-session': session ?? '' },
    });
    expect(response.status).toBe(303);
    expect(await count('sessions')).toBe(0);
  });

  it('end on sign-out', async () => {
    const { session } = await signIn(app, google);
    const response = await call(app, '/logout', {
      method: 'POST',
      headers: { Origin: ORIGIN },
      cookies: { '__Host-session': session ?? '' },
    });
    expect(response.status).toBe(303);
    expect(rawSetCookie(response, '__Host-session')).toContain('Max-Age=0');
    expect(await count('sessions')).toBe(0);
  });

  it('refuse a sign-out posted from another site', async () => {
    const { session } = await signIn(app, google);
    const response = await call(app, '/logout', {
      method: 'POST',
      headers: { Origin: 'https://evil.example' },
      cookies: { '__Host-session': session ?? '' },
    });
    expect(response.status).toBe(403);
    expect(await count('sessions')).toBe(1);
  });

  it('accept a sign-out the browser marks as same-origin', async () => {
    const { session } = await signIn(app, google);
    const response = await call(app, '/logout', {
      method: 'POST',
      headers: { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' },
      cookies: { '__Host-session': session ?? '' },
    });
    expect(response.status).toBe(303);
    expect(await count('sessions')).toBe(0);
  });

  it('refuse a sign-out the browser marks as cross-site, even with a matching Origin', async () => {
    const { session } = await signIn(app, google);
    const response = await call(app, '/logout', {
      method: 'POST',
      headers: { Origin: ORIGIN, 'Sec-Fetch-Site': 'cross-site' },
      cookies: { '__Host-session': session ?? '' },
    });
    expect(response.status).toBe(403);
    expect(await count('sessions')).toBe(1);
  });

  it('are replaced on a new sign-in (no session fixation)', async () => {
    const first = await signIn(app, google);
    const ip = freshIp();
    const login = await startLogin(app, ip);
    google.nextIdToken = await signIdToken({ nonce: login.nonce });
    const callback = await call(
      app,
      `/callback/google?code=auth-code&state=${encodeURIComponent(login.state)}`,
      { ip, cookies: { '__Host-login_tx': login.txCookie, '__Host-session': first.session ?? '' } },
    );
    expect(callback.status).toBe(303);
    expect(setCookies(callback)['__Host-session']).not.toBe(first.session);
    expect(await count('sessions')).toBe(1);
  });

  it('stop working when the user is suspended', async () => {
    const { session } = await signIn(app, google);
    await env.DB.prepare("UPDATE users SET status = 'suspended'").run();
    const response = await call(app, '/account', { cookies: { '__Host-session': session ?? '' } });
    expect(response.status).toBe(303);
  });
});
