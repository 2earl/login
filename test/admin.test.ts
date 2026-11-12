import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import { totpCode, totpStep } from '../src/totp';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  OWNER_EMAIL,
  call,
  count,
  freshIp,
  makeApp,
  resetDatabase,
  signIn,
} from './helpers';

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};
const OTHER = { sub: 'google-sub-other', email: 'other@example.com', name: 'Other Person' };

let google: FakeGoogle;
let now: number;
let ip: string;
let app: ReturnType<typeof makeApp>;
let owner: string;

const as = (session: string) => ({ '__Host-session': session });

function post(path: string, body: Record<string, string>, session = owner) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(body),
    cookies: as(session),
    ip,
  });
}

/** Sets up an authenticator app for the signed-in owner; the session becomes aal2. */
async function giveOwnerAFactor(): Promise<void> {
  const page = await (await call(app, '/account/security/totp', { cookies: as(owner) })).text();
  const secret = (/<code class="secret">([A-Z2-7 ]+)<\/code>/.exec(page)?.[1] ?? '').replace(
    / /g,
    '',
  );
  const response = await post('/account/security/totp', {
    code: await totpCode(secret, totpStep(now)),
  });
  expect(response.status).toBe(303);
}

async function inviteAndSignInOther(): Promise<{ session: string; userId: string }> {
  await env.DB.prepare(
    "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES ('inv-other', 'email', ?, 'test', 0)",
  )
    .bind(OTHER.email)
    .run();
  const result = await signIn(app, google, { claims: OTHER });
  const row = await env.DB.prepare('SELECT id FROM users WHERE primary_email = ?')
    .bind(OTHER.email)
    .first<{ id: string }>();
  return { session: result.session ?? '', userId: row?.id ?? '' };
}

beforeEach(async () => {
  now = NOW;
  ip = freshIp();
  setOAuthClock(() => now);
  await resetDatabase();
  google = new FakeGoogle();
  app = makeApp(google, () => now);
  owner = (await signIn(app, google)).session ?? '';
});

describe('who can open /admin', () => {
  it('sends a signed-out visitor to sign in first', async () => {
    const response = await call(app, '/admin/users');
    expect(response.headers.get('Location')).toBe('/login?return_to=%2Fadmin%2Fusers');
  });

  it('answers 404 to anyone but the owner', async () => {
    const other = await inviteAndSignInOther();
    for (const path of ['/admin/users', '/admin/invitations', '/admin/apps', '/admin/log']) {
      expect((await call(app, path, { cookies: as(other.session) })).status, path).toBe(404);
    }
    const change = await post(
      '/admin/invitations',
      { action: 'add', email: 'x@example.com' },
      other.session,
    );
    expect(change.status).toBe(404);
    expect(await count('allowlist', "value = 'x@example.com'")).toBe(0);
  });

  it('requires the owner to have a second factor, even with MFA_REQUIRED off', async () => {
    const response = await call(app, '/admin/users', { cookies: as(owner) });
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('Admin needs a second factor');
  });

  it('sends an owner session without the second step to /mfa', async () => {
    await giveOwnerAFactor();
    owner = (await signIn(app, google)).session ?? '';
    const response = await call(app, '/admin/users', { cookies: as(owner) });
    expect(response.headers.get('Location')).toBe('/mfa?return_to=%2Fadmin%2Fusers');
  });

  it('opens for the owner after the second step, with every tab', async () => {
    await giveOwnerAFactor();
    for (const path of ['/admin/users', '/admin/invitations', '/admin/apps', '/admin/log']) {
      const response = await call(app, path, { cookies: as(owner) });
      expect(response.status, path).toBe(200);
      expect(response.headers.get('Content-Security-Policy')).not.toContain('script-src');
    }
  });

  it('asks for the second factor again before changes after 15 minutes', async () => {
    await giveOwnerAFactor();
    now += 16 * 60;
    const response = await post('/admin/invitations', { action: 'add', email: 'x@example.com' });
    expect(response.headers.get('Location')).toBe(
      '/mfa?step_up=1&return_to=%2Fadmin%2Finvitations',
    );
    expect(await count('allowlist', "value = 'x@example.com'")).toBe(0);
  });

  it('refuses changes posted from another site', async () => {
    await giveOwnerAFactor();
    const response = await call(app, '/admin/invitations', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://evil.example',
      },
      body: new URLSearchParams({ action: 'add', email: 'x@example.com' }),
      cookies: as(owner),
      ip,
    });
    expect(response.status).toBe(403);
  });
});

describe('users', () => {
  beforeEach(giveOwnerAFactor);

  it('lists accounts; the owner’s own row has no actions', async () => {
    await inviteAndSignInOther();
    const html = await (await call(app, '/admin/users', { cookies: as(owner) })).text();
    expect(html).toContain('other@example.com');
    expect(html).toContain('Owner');
    expect(html).toContain('Manage your own account on the account page.');
    expect(html.match(/name="action" value="suspend"/g)).toHaveLength(1);
  });

  it('suspends: signs the user out and blocks sign-in; reactivating lets them back', async () => {
    const other = await inviteAndSignInOther();
    const response = await post('/admin/users', { action: 'suspend', user: other.userId });
    expect(response.headers.get('Location')).toBe('/admin/users?done=suspended');
    expect(await count('sessions', 'user_id = ?', other.userId)).toBe(0);
    expect((await call(app, '/account', { cookies: as(other.session) })).status).toBe(303);
    expect((await signIn(app, google, { claims: OTHER })).callback.status).toBe(403);
    expect(await count('audit_events', "event = 'admin.user_suspended'")).toBe(1);

    await post('/admin/users', { action: 'reactivate', user: other.userId });
    expect((await signIn(app, google, { claims: OTHER })).callback.status).toBe(303);
  });

  it('resets a user’s second factor and ends their sessions', async () => {
    const other = await inviteAndSignInOther();
    await env.DB.prepare(
      "INSERT INTO mfa_factors (id, user_id, kind, label, created_at, totp_secret_enc) VALUES ('f1', ?, 'totp', 'Authenticator app', 0, 'x.y')",
    )
      .bind(other.userId)
      .run();
    await post('/admin/users', { action: 'reset_mfa', user: other.userId });
    expect(await count('mfa_factors', 'user_id = ?', other.userId)).toBe(0);
    expect(await count('sessions', 'user_id = ?', other.userId)).toBe(0);
    expect(await count('audit_events', "event = 'admin.mfa_reset'")).toBe(1);
  });

  it('deletes a user only with the confirmation box', async () => {
    const other = await inviteAndSignInOther();
    expect((await post('/admin/users', { action: 'delete', user: other.userId })).status).toBe(400);
    expect(await count('users', 'id = ?', other.userId)).toBe(1);

    const response = await post('/admin/users', {
      action: 'delete',
      user: other.userId,
      confirm: 'on',
    });
    expect(response.headers.get('Location')).toBe('/admin/users?done=deleted');
    expect(await count('users', 'id = ?', other.userId)).toBe(0);
    expect(await count('allowlist', "id = 'inv-other'")).toBe(0);
    expect(await count('audit_events', "event = 'admin.user_deleted'")).toBe(1);
  });

  it('refuses to act on the owner’s own account', async () => {
    const ownerId =
      (
        await env.DB.prepare(
          "SELECT user_id FROM identities WHERE subject = 'google-sub-owner'",
        ).first<{ user_id: string }>()
      )?.user_id ?? '';
    const response = await post('/admin/users', { action: 'suspend', user: ownerId });
    expect(response.status).toBe(400);
    expect(await count('users', "status = 'active'")).toBe(1);
  });
});

describe('invitations', () => {
  beforeEach(giveOwnerAFactor);

  it('adds an address in lower case, once, and the invited account can sign in', async () => {
    const added = await post('/admin/invitations', { action: 'add', email: ' Other@Example.com ' });
    expect(added.headers.get('Location')).toBe('/admin/invitations?done=invited');
    expect(await count('allowlist', "kind = 'email' AND value = 'other@example.com'")).toBe(1);
    const again = await post('/admin/invitations', { action: 'add', email: 'other@example.com' });
    expect(again.headers.get('Location')).toBe('/admin/invitations?done=already_invited');

    expect(
      (await signIn(app, google, { claims: { ...OTHER, email: 'Other@Example.com' } })).callback
        .status,
    ).toBe(303);
  });

  it('switches sign-up open and closed without a deploy', async () => {
    const page = await (await call(app, '/admin/invitations', { cookies: as(owner) })).text();
    expect(page).toContain('<strong>By invitation.</strong>');
    expect((await signIn(app, google, { claims: OTHER })).callback.status).toBe(403);

    const opened = await post('/admin/invitations', { action: 'signup', mode: 'open' });
    expect(opened.headers.get('Location')).toBe('/admin/invitations?done=signup_open');
    expect(await count('audit_events', "event = 'admin.signup_changed'")).toBe(1);
    const joined = await signIn(app, google, { claims: OTHER });
    expect(joined.callback.headers.get('Location')).toBe('/welcome?return_to=%2Faccount');

    await post('/admin/invitations', { action: 'signup', mode: 'invite' });
    // An account made while sign-up was open keeps working; a new one needs an invitation.
    expect((await signIn(app, google, { claims: OTHER })).callback.status).toBe(303);
    const stranger = { sub: 'google-sub-stranger', email: 'stranger@example.com', name: 'S' };
    expect((await signIn(app, google, { claims: stranger })).callback.status).toBe(403);
  });

  it('rejects an invalid address', async () => {
    const response = await post('/admin/invitations', { action: 'add', email: 'not-an-email' });
    expect(response.status).toBe(400);
  });

  it('withdraws an invitation, but never the owner’s own', async () => {
    await post('/admin/invitations', { action: 'add', email: 'x@example.com' });
    const added = await env.DB.prepare(
      "SELECT id FROM allowlist WHERE value = 'x@example.com'",
    ).first<{ id: string }>();
    await post('/admin/invitations', { action: 'remove', id: added?.id ?? '' });
    expect(await count('allowlist', "value = 'x@example.com'")).toBe(0);

    const own = await env.DB.prepare(
      "SELECT id FROM allowlist WHERE value = 'google-sub-owner'",
    ).first<{ id: string }>();
    await post('/admin/invitations', { action: 'remove', id: own?.id ?? '' });
    expect(await count('allowlist', "value = 'google-sub-owner'")).toBe(1);
  });
});

describe('apps', () => {
  beforeEach(giveOwnerAFactor);

  it('registers a public client, verifies it, then deletes it', async () => {
    const registered = await post('/admin/apps', {
      action: 'register',
      name: 'Desktop client',
      redirect_uris: 'http://127.0.0.1:33418/callback\nhttps://client.example/cb',
    });
    expect(registered.status).toBe(200);
    const clientId = /Its client ID is ([^.<]+)\./.exec(await registered.text())?.[1] ?? '';
    const oauth = authorizationServer(env).getOAuthApi(env);
    const client = await oauth.lookupClient(clientId);
    expect(client?.tokenEndpointAuthMethod).toBe('none');
    expect(client?.redirectUris).toEqual([
      'http://127.0.0.1:33418/callback',
      'https://client.example/cb',
    ]);

    await post('/admin/apps', { action: 'trust', client_id: clientId, note: 'Ours' });
    expect(await count('trusted_clients', 'client_id = ?', clientId)).toBe(1);

    await post('/admin/apps', { action: 'unregister', client_id: clientId });
    expect(await oauth.lookupClient(clientId)).toBeNull();
    expect(await count('trusted_clients')).toBe(0);
  });

  it('rejects redirect URIs that are not https or loopback', async () => {
    const response = await post('/admin/apps', {
      action: 'register',
      name: 'Bad',
      redirect_uris: 'http://client.example/cb',
    });
    expect(response.status).toBe(400);
  });

  it('refuses to verify an unknown client ID', async () => {
    const response = await post('/admin/apps', { action: 'trust', client_id: 'no-such-client' });
    expect(response.status).toBe(400);
    expect(await count('trusted_clients')).toBe(0);
  });
});

describe('security log', () => {
  beforeEach(giveOwnerAFactor);

  it('shows recent events with the account, and filters by kind', async () => {
    await post('/admin/invitations', { action: 'add', email: 'x@example.com' });
    const all = await (await call(app, '/admin/log', { cookies: as(owner) })).text();
    expect(all).toContain('login.succeeded');
    expect(all).toContain('admin.invitation_added');
    expect(all).toContain(OWNER_EMAIL);
    // Read as words, the event's own name on hover.
    expect(all).toContain('<span title="login.succeeded">Signed in</span>');
    expect(all).toContain('<span title="admin.invitation_added">Invitation added</span>');
    // The owner's account page links here.
    expect(await (await call(app, '/account', { cookies: as(owner) })).text()).toContain(
      'href="/admin"',
    );

    const adminOnly = await (
      await call(app, '/admin/log?event=admin.', { cookies: as(owner) })
    ).text();
    expect(adminOnly).toContain('admin.invitation_added');
    expect(adminOnly).not.toContain('login.succeeded');

    // An unknown filter shows everything rather than building a query from it.
    const odd = await (
      await call(app, '/admin/log?event=%27%20OR%201%3D1', { cookies: as(owner) })
    ).text();
    expect(odd).toContain('login.succeeded');
  });
});

describe('resource servers (DESIGN §4.12)', () => {
  it('creates credentials shown once, stores only a hash, and revokes them', async () => {
    await giveOwnerAFactor();
    const created = await post('/admin/apps', {
      action: 'rs_create',
      name: 'Backup server',
      resource: env.MCP_RESOURCE,
    });
    expect(created.status).toBe(200);
    const html = await created.text();
    const id = /ID <code>(rs_[A-Za-z0-9_-]+)<\/code><\/p>/.exec(html)?.[1] ?? '';
    const secret = /Secret <code>([A-Za-z0-9_-]{43})<\/code>/.exec(html)?.[1] ?? '';
    expect(id).not.toBe('');
    expect(secret).not.toBe('');
    const row = await env.DB.prepare('SELECT secret_hash FROM resource_servers WHERE id = ?')
      .bind(id)
      .first<{ secret_hash: string }>();
    expect(row?.secret_hash).not.toContain(secret);
    expect(await count('audit_events', "event = 'admin.resource_server_created'")).toBe(1);

    // Shown once: the list never shows the secret again.
    const list = await (await call(app, '/admin/apps', { cookies: as(owner) })).text();
    expect(list).toContain('Backup server');
    expect(list).not.toContain(secret);

    const unknown = await post('/admin/apps', {
      action: 'rs_create',
      name: 'Elsewhere',
      resource: 'https://evil.example/mcp',
    });
    expect(unknown.status).toBe(400);

    const revoked = await post('/admin/apps', { action: 'rs_delete', id });
    expect(revoked.headers.get('Location')).toBe('/admin/apps?done=rs_deleted');
    expect(await count('resource_servers')).toBe(0);
  });
});

describe('organizations in /admin (DESIGN §4.14)', () => {
  it('lists them, suspends and reactivates, and deletes', async () => {
    await giveOwnerAFactor();
    const other = await inviteAndSignInOther();
    const created = await post('/orgs', { name: 'Other’s team' }, other.session);
    const orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';

    const list = await (await call(app, '/admin/orgs', { cookies: as(owner) })).text();
    expect(list).toContain('Other’s team');
    expect(list).toContain('owners: other@example.com');

    expect((await post('/admin/orgs', { action: 'suspend', org: orgId })).status).toBe(303);
    expect(await count('organizations', "status = 'suspended'")).toBe(1);
    const frozen = await post(`/orgs/${orgId}/name`, { name: 'Renamed' }, other.session);
    expect(frozen.status).toBe(403);
    expect((await post('/admin/orgs', { action: 'reactivate', org: orgId })).status).toBe(303);
    expect(await count('organizations', "status = 'active'")).toBe(1);

    expect((await post('/admin/orgs', { action: 'delete', org: orgId })).status).toBe(400);
    const deleted = await post('/admin/orgs', { action: 'delete', org: orgId, confirm: 'on' });
    expect(deleted.headers.get('Location')).toBe('/admin/orgs?done=org_deleted');
    expect(await count('organizations')).toBe(0);
    expect(await count('audit_events', "event = 'admin.org_deleted'")).toBe(1);
  });

  it('answers 404 to anyone but the owner', async () => {
    const other = await inviteAndSignInOther();
    expect((await call(app, '/admin/orgs', { cookies: as(other.session) })).status).toBe(404);
  });
});
