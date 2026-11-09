import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken } from '../src/crypto';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  OWNER_EMAIL,
  call,
  count,
  freshIp,
  makeApp,
  rawSetCookie,
  resetDatabase,
  setCookies,
  signIdToken,
  signIn,
  consentBody,
  parseConsent,
} from './helpers';

const REDIRECT_URI = 'https://client.example/callback';
const RESOURCE = env.MCP_RESOURCE;
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };

let google: FakeGoogle;
let app: ReturnType<typeof makeApp>;
let session: string;
let userId: string;
let clientId: string;

function oauth() {
  return authorizationServer(env).getOAuthApi(env);
}

/** authorize → consent → token for the test client; returns the token response body. */
async function connectApp(): Promise<Record<string, unknown>> {
  const verifier = randomToken(48);
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'mcp:tools.read mcp:tools.invoke',
    state: 'client-state',
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    resource: RESOURCE,
  });
  const consent = await call(app, `/authorize?${query.toString()}`, {
    cookies: { '__Host-session': session },
  });
  const handle = parseConsent(await consent.text());
  const body = consentBody(handle, { decision: 'approve' });
  body.append('scope', 'mcp:tools.read');
  body.append('scope', 'mcp:tools.invoke');
  const approved = await call(app, '/authorize', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body,
    cookies: { '__Host-session': session, ...setCookies(consent) },
  });
  const code = new URL(approved.headers.get('Location') ?? 'about:blank').searchParams.get('code');
  const token = await call(app, '/oauth/token', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code ?? '',
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
      resource: RESOURCE,
    }),
  });
  expect(token.status).toBe(200);
  return token.json<Record<string, unknown>>();
}

async function refresh(refreshToken: string): Promise<Response> {
  return call(app, '/oauth/token', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    }),
  });
}

/** Posts the deletion form and returns the Google redirect and the transaction cookie. */
async function startDeletion(ip: string, cookies: Record<string, string> = {}) {
  const response = await call(app, '/account/delete', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body: new URLSearchParams({ confirm: 'on' }),
    cookies: { '__Host-session': session, ...cookies },
    ip,
  });
  const location = new URL(response.headers.get('Location') ?? 'about:blank');
  return {
    response,
    location,
    state: location.searchParams.get('state') ?? '',
    nonce: location.searchParams.get('nonce') ?? '',
    txCookie: setCookies(response)['__Host-login_tx'] ?? '',
  };
}

/** Comes back from Google for a deletion. `claims` override the ID token. */
async function finishDeletion(
  started: Awaited<ReturnType<typeof startDeletion>>,
  ip: string,
  options: { claims?: Record<string, unknown>; sessionCookie?: string | null; query?: string } = {},
) {
  google.nextIdToken = await signIdToken({ nonce: started.nonce, ...options.claims });
  const cookies: Record<string, string> = { '__Host-login_tx': started.txCookie };
  const sessionCookie = options.sessionCookie === undefined ? session : options.sessionCookie;
  if (sessionCookie) cookies['__Host-session'] = sessionCookie;
  return call(
    app,
    `/callback/google?${options.query ?? 'code=auth-code'}&state=${encodeURIComponent(started.state)}`,
    { ip, cookies },
  );
}

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  google = new FakeGoogle();
  app = makeApp(google);
  session = (await signIn(app, google)).session ?? '';
  userId =
    (await env.DB.prepare('SELECT id FROM users').first<{ id: string }>())?.id ?? 'missing-user';
  const client = await oauth().createClient({
    redirectUris: [REDIRECT_URI],
    clientName: 'Test MCP Client',
    tokenEndpointAuthMethod: 'none',
  });
  clientId = client.clientId;
});

describe('account page', () => {
  it('offers the data download and account deletion', async () => {
    const html = await (
      await call(app, '/account', { cookies: { '__Host-session': session } })
    ).text();
    expect(html).toContain('href="/account/export"');
    expect(html).toContain('href="/account/delete"');
  });
});

describe('data export', () => {
  it('requires sign-in and returns there afterwards', async () => {
    const response = await call(app, '/account/export');
    expect(response.status).toBe(303);
    expect(response.headers.get('Location')).toBe('/login?return_to=%2Faccount%2Fexport');
  });

  it('downloads the account, sign-in method, sessions, apps and security log as JSON', async () => {
    const tokens = await connectApp();
    const response = await call(app, '/account/export', { cookies: { '__Host-session': session } });
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toBe('application/json; charset=utf-8');
    expect(response.headers.get('Content-Disposition')).toBe(
      `attachment; filename="2earl-account-${new Date(NOW * 1000).toISOString().slice(0, 10)}.json"`,
    );
    expect(response.headers.get('Cache-Control')).toBe('no-store');

    const raw = await response.text();
    const data = JSON.parse(raw) as Record<string, unknown> & {
      account: Record<string, unknown>;
      signInMethods: Record<string, unknown>[];
      sessions: Record<string, unknown>[];
      connectedApps: Record<string, unknown>[];
      securityLog: Record<string, unknown>[];
      invitation: Record<string, unknown> | null;
    };
    expect(data.format).toBe('2earl-login-export/1');
    expect(data.account).toMatchObject({ id: userId, email: OWNER_EMAIL, status: 'active' });
    expect(data.signInMethods).toEqual([
      expect.objectContaining({ provider: 'google', accountId: 'google-sub-owner' }),
    ]);
    expect(data.sessions).toEqual([expect.objectContaining({ thisBrowser: true })]);
    expect(data.connectedApps).toEqual([
      expect.objectContaining({
        clientId,
        name: 'Test MCP Client',
        permissions: ['mcp:tools.read', 'mcp:tools.invoke'],
      }),
    ]);
    expect(data.invitation).not.toBeNull();
    const events = data.securityLog.map((e) => e.event);
    expect(events).toEqual(
      expect.arrayContaining(['user.created', 'login.succeeded', 'consent.approved']),
    );

    // Hashes and credentials stay out of the file.
    expect(raw).not.toContain(session);
    expect(raw).not.toContain(String(tokens.access_token));
    expect(raw).not.toContain(String(tokens.refresh_token));
    expect(raw).not.toContain('id_hash');
    expect(
      await count('audit_events', "event = 'account.exported' AND actor_user_id = ?", userId),
    ).toBe(1);
  });

  it('contains only the signed-in user’s data', async () => {
    await env.DB.prepare(
      "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES ('other', 'email', 'other@example.com', 'test', 0)",
    ).run();
    const other = await signIn(app, google, {
      claims: { sub: 'google-sub-other', email: 'other@example.com', name: 'Other' },
    });
    const raw = await (
      await call(app, '/account/export', { cookies: { '__Host-session': other.session ?? '' } })
    ).text();
    expect(raw).toContain('other@example.com');
    expect(raw).not.toContain(OWNER_EMAIL);
    expect(raw).not.toContain('google-sub-owner');
  });
});

describe('account deletion', () => {
  it('shows what is deleted and what is kept, behind sign-in', async () => {
    expect((await call(app, '/account/delete')).headers.get('Location')).toBe(
      '/login?return_to=%2Faccount%2Fdelete',
    );
    await connectApp();
    const html = await (
      await call(app, '/account/delete', { cookies: { '__Host-session': session } })
    ).text();
    expect(html).toContain('Access for your connected app');
    expect(html).toContain(OWNER_EMAIL);
    expect(html).toContain('name="confirm"');
    expect(html).toContain('Your invitation');
  });

  it('refuses a deletion posted from another site', async () => {
    const response = await call(app, '/account/delete', {
      method: 'POST',
      headers: { ...FORM, Origin: 'https://evil.example', 'Sec-Fetch-Site': 'cross-site' },
      body: new URLSearchParams({ confirm: 'on' }),
      cookies: { '__Host-session': session },
    });
    expect(response.status).toBe(403);
    expect(await count('login_tx')).toBe(0);
  });

  it('requires the confirmation box', async () => {
    const response = await call(app, '/account/delete', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body: new URLSearchParams(),
      cookies: { '__Host-session': session },
    });
    expect(response.status).toBe(303);
    expect(response.headers.get('Location')).toBe('/account/delete');
    expect(await count('login_tx')).toBe(0);
  });

  it('sends the user to Google to confirm, with their account pre-selected', async () => {
    const started = await startDeletion(freshIp());
    expect(started.response.status).toBe(302);
    expect(started.location.origin + started.location.pathname).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
    expect(started.location.searchParams.get('login_hint')).toBe(OWNER_EMAIL);
    expect(started.location.searchParams.get('prompt')).toBe('select_account');
    expect(started.location.searchParams.get('code_challenge_method')).toBe('S256');
    expect(started.txCookie).not.toBe('');
    expect(await count('users')).toBe(1);
  });

  it('deletes the account, revokes apps and ends sessions once Google confirms', async () => {
    const tokens = await connectApp();
    const ip = freshIp();
    const response = await finishDeletion(await startDeletion(ip), ip);

    expect(response.status).toBe(303);
    expect(response.headers.get('Location')).toBe('/account/deleted');
    expect(rawSetCookie(response, '__Host-session')).toContain('Max-Age=0');
    expect(rawSetCookie(response, '__Host-oauth-approvals')).toContain('Max-Age=0');

    expect(await count('users')).toBe(0);
    expect(await count('identities')).toBe(0);
    expect(await count('sessions')).toBe(0);
    expect(await count('login_tx')).toBe(0);
    expect(await count('allowlist')).toBe(0);
    expect((await oauth().listUserGrants(userId)).items).toEqual([]);
    expect(
      await authorizationServer(env).validateToken(RESOURCE, String(tokens.access_token), env),
    ).toBeNull();
    expect((await refresh(String(tokens.refresh_token))).status).toBe(400);

    // The security log stays, keyed to a random correlation ID instead of the user.
    expect(await count('audit_events', 'actor_user_id = ?', userId)).toBe(0);
    const deleted = await env.DB.prepare(
      "SELECT actor_user_id, detail FROM audit_events WHERE event = 'user.deleted'",
    ).first<{ actor_user_id: string; detail: string }>();
    expect(deleted?.actor_user_id).toMatch(/^deleted:/);
    expect(JSON.parse(deleted?.detail ?? '{}')).toEqual({ grants: 1 });
    expect(
      await count('audit_events', 'actor_user_id = ?', deleted?.actor_user_id),
    ).toBeGreaterThan(1);

    // No new session was created, and the old cookie is dead.
    expect(setCookies(response)['__Host-session']).toBe('');
    const account = await call(app, '/account', { cookies: { '__Host-session': session } });
    expect(account.headers.get('Location')).toBe('/login?return_to=%2Faccount');
  });

  it('keeps the account when a different Google account confirms', async () => {
    const ip = freshIp();
    const response = await finishDeletion(await startDeletion(ip), ip, {
      claims: { sub: 'google-sub-someone-else', email: 'someone@example.com' },
    });
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('You chose a different Google account');
    expect(await count('users')).toBe(1);
    expect(
      await count(
        'audit_events',
        "event = 'account.deletion_stopped' AND detail = ?",
        JSON.stringify({ reason: 'different_account' }),
      ),
    ).toBe(1);
  });

  it('keeps the account when Google sign-in is cancelled', async () => {
    const ip = freshIp();
    const response = await finishDeletion(await startDeletion(ip), ip, {
      query: 'error=access_denied',
    });
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('Your account was not deleted');
    expect(await count('users')).toBe(1);
  });

  it('keeps the account when the browser is no longer signed in to it', async () => {
    const ip = freshIp();
    const started = await startDeletion(ip);
    const response = await finishDeletion(started, ip, { sessionCookie: null });
    expect(response.status).toBe(400);
    expect(await count('users')).toBe(1);
  });

  it('cannot be completed with a sign-in transaction, or replayed', async () => {
    const ip = freshIp();
    const started = await startDeletion(ip);
    expect((await finishDeletion(started, ip)).status).toBe(303);
    // The same callback again: the transaction is gone.
    const again = await finishDeletion(started, ip);
    expect(again.status).toBe(400);

    // The invitation went with the account: signing in again needs a new one.
    const fresh = await signIn(app, google);
    expect(fresh.callback.status).toBe(403);
    expect(await count('users')).toBe(0);
  });

  it('shows the confirmation page only when signed out', async () => {
    expect((await call(app, '/account/deleted')).status).toBe(200);
    const signedIn = await call(app, '/account/deleted', {
      cookies: { '__Host-session': session },
    });
    expect(signedIn.headers.get('Location')).toBe('/account');
  });
});

describe('token exchange for an inactive account', () => {
  it('refuses to refresh for a suspended user and revokes the grant', async () => {
    const tokens = await connectApp();
    await env.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").bind(userId).run();
    const response = await refresh(String(tokens.refresh_token));
    expect(response.status).toBe(400);
    expect((await response.json<{ error: string }>()).error).toBe('invalid_grant');
    expect((await oauth().listUserGrants(userId)).items).toEqual([]);
    expect(await count('audit_events', "event = 'grant.refused'")).toBe(1);
  });
});
