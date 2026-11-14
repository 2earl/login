import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { setOAuthClock } from '../src/oauth';
import { inRange, parseRanges } from '../src/org-policy';
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

/** Phase 10b (DESIGN §4.19): security rules for managed accounts. */

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
  return google.fetch(input, init);
};

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
  ada = await person('ada');
  bob = await person('bob');
  ({ orgId } = await organization(ada));
  await manage(ada, orgId);
  await post(bob, '/account/managed', { org: orgId, choice: 'join' });
});

/** Saves the rules through the owner's form. */
function rules(fields: Record<string, string | string[]>, who: Person = ada) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    for (const v of Array.isArray(value) ? value : [value]) body.append(key, v);
  }
  return call(app, `/orgs/${orgId}/policy`, {
    method: 'POST',
    headers: FORM,
    body,
    cookies: { '__Host-session': who.session },
    ip: freshIp(),
  });
}

const ALL = { methods: ['google', 'email', 'passkey'] };

function asBob(path: string, ip: string) {
  return call(app, path, { cookies: { '__Host-session': bob.session }, ip });
}

describe('network ranges', () => {
  it('parses IPv4 and IPv6 ranges and refuses nonsense and the whole internet', () => {
    expect(parseRanges('203.0.113.0/24, 2001:db8::/32\n198.51.100.7')).toEqual({
      ranges: ['203.0.113.0/24', '2001:db8::/32', '198.51.100.7/32'],
      invalid: [],
    });
    expect(parseRanges('0.0.0.0/0 ::/0 300.1.1.1/24 example.com 10.0.0.0/33').invalid).toHaveLength(
      5,
    );
  });

  it('matches addresses', () => {
    expect(inRange('203.0.113.99', '203.0.113.0/24')).toBe(true);
    expect(inRange('203.0.114.1', '203.0.113.0/24')).toBe(false);
    expect(inRange('2001:db8:1::5', '2001:db8::/32')).toBe(true);
    expect(inRange('2001:db9::5', '2001:db8::/32')).toBe(false);
    expect(inRange('203.0.113.9', '2001:db8::/32')).toBe(false);
  });
});

describe('saving the rules', () => {
  it('is for owners, with valid values', async () => {
    expect((await rules({ ...ALL, ip_ranges: 'not-a-range' })).status).toBe(400);
    expect((await rules({ ...ALL, session_hours: '5' })).status).toBe(400);
    // No way to sign in, and no SSO: refused.
    expect((await rules({})).status).toBe(400);
    const saved = await rules({ ...ALL, session_hours: '8', ip_ranges: '203.0.113.0/24' });
    expect(saved.headers.get('Location')).toBe(`/orgs/${orgId}/directory?done=policy`);
    expect(await count('org_policies', 'org_id = ? AND session_hours = 8', orgId)).toBe(1);
    expect(await count('audit_events', "event = 'org.policy_changed'")).toBe(1);

    // An admin isn't an owner: the rules aren't theirs to change.
    await env.DB.prepare("UPDATE org_members SET role = 'admin' WHERE user_id = ?")
      .bind(bob.id)
      .run();
    const byAdmin = await call(app, `/orgs/${orgId}/policy`, {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams({ methods: 'google' }),
      cookies: { '__Host-session': bob.session },
      ip: '203.0.113.5',
    });
    expect(byAdmin.status).toBe(404);
  });
});

describe('a required second factor', () => {
  it('sends everyone managed, owners too, to add one, saying who asks', async () => {
    await rules({ ...ALL, require_factor: '1' });
    for (const who of [bob, ada]) {
      const response = await get(who, '/account');
      expect(response.headers.get('Location')).toBe('/account/security?return_to=%2Faccount');
    }
    const page = await (await get(bob, '/account/security')).text();
    expect(page).toContain('Example Inc');
    expect(page).toContain('requires a second factor');
  });

  it('with passkeys only, asks an account with an authenticator app for a passkey', async () => {
    await rules({ ...ALL, passkeys_only: '1' });
    await env.DB.prepare(
      "INSERT INTO mfa_factors (id, user_id, kind, label, created_at, totp_secret_enc) VALUES ('f-totp', ?, 'totp', 'App', 0, 'x')",
    )
      .bind(bob.id)
      .run();
    // First the challenge with what it has...
    expect((await get(bob, '/account')).headers.get('Location')).toMatch(/^\/mfa\?/);
    // ...then, verified, it must add a passkey.
    await env.DB.prepare("UPDATE sessions SET aal = 'aal2', aal2_at = ? WHERE user_id = ?")
      .bind(now, bob.id)
      .run();
    expect((await get(bob, '/account')).headers.get('Location')).toMatch(/^\/account\/security/);
    expect(await (await get(bob, '/account/security')).text()).toContain('requires a passkey');
  });

  it('with passkeys only, refuses authenticator codes once there is a passkey, and keeps the last passkey', async () => {
    await rules({ ...ALL, passkeys_only: '1' });
    await env.DB.prepare(
      `INSERT INTO mfa_factors (id, user_id, kind, label, created_at, webauthn_credential_id, webauthn_public_key, totp_secret_enc)
       VALUES ('f-key', ?1, 'webauthn', 'Key', 0, 'cred-1', 'pk', NULL), ('f-app', ?1, 'totp', 'App', 0, NULL, NULL, 'x')`,
    )
      .bind(bob.id)
      .run();
    const code = await post(bob, '/mfa/totp', { code: '123456', return_to: '/account' });
    expect(code.status).toBe(403);
    expect(await code.text()).toContain('requires a passkey');

    await env.DB.prepare("UPDATE sessions SET aal = 'aal2', aal2_at = ? WHERE user_id = ?")
      .bind(now, bob.id)
      .run();
    const removed = await post(bob, '/account/security/factors/remove', { factor: 'f-key' });
    expect(removed.status).toBe(400);
    expect(await count('mfa_factors', "id = 'f-key'")).toBe(1);
    // The authenticator app can go.
    await post(bob, '/account/security/factors/remove', { factor: 'f-app' });
    expect(await count('mfa_factors', "id = 'f-app'")).toBe(0);
  });
});

describe('session length', () => {
  it('ends sessions that many hours after sign-in, owners’ too', async () => {
    await rules({ ...ALL, session_hours: '1' });
    now += 3599;
    expect((await get(bob, '/account')).status).toBe(200);
    now += 1;
    for (const who of [bob, ada]) {
      expect((await get(who, '/account')).headers.get('Location')).toMatch(/^\/login/);
    }
  });
});

describe('ways to sign in', () => {
  it('ends sessions started a way no longer allowed, refuses that way, and exempts owners', async () => {
    await rules({ methods: ['email'] });
    expect((await get(bob, '/account')).headers.get('Location')).toMatch(/^\/login/);
    expect((await get(ada, '/account')).status).toBe(200);
    const again = await signIn(app, google, {
      claims: { sub: 'sub-bob', email: 'bob@example.com', name: 'bob' },
    });
    expect(again.callback.status).toBe(403);
    expect(await again.callback.text()).toContain('allow signing in this way');
    expect(again.session).toBeUndefined();
  });
});

describe('allowed networks', () => {
  it('ends sessions used from elsewhere, refuses sign-in there, and exempts owners', async () => {
    await rules({ ...ALL, ip_ranges: '203.0.113.0/24' });
    expect((await asBob('/account', '203.0.113.20')).status).toBe(200);
    expect((await get(ada, '/account')).status).toBe(200);
    const outside = await asBob('/account', '198.51.100.1');
    expect(outside.headers.get('Location')).toMatch(/^\/login/);
    expect(await count('sessions', 'user_id = ?', bob.id)).toBe(0);

    const elsewhere = await signIn(app, google, {
      ip: '198.51.100.1',
      claims: { sub: 'sub-bob', email: 'bob@example.com', name: 'bob' },
    });
    expect(elsewhere.callback.status).toBe(403);
    expect(await elsewhere.callback.text()).toContain('its own networks');
    const fromOffice = await signIn(app, google, {
      ip: '203.0.113.20',
      claims: { sub: 'sub-bob', email: 'bob@example.com', name: 'bob' },
    });
    expect(fromOffice.session).toBeTruthy();
  });
});

describe('accounts the organization doesn’t manage', () => {
  it('aren’t touched by its rules', async () => {
    const carol = await person('carol', 'elsewhere.example');
    await env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'member', 0)",
    )
      .bind(orgId, carol.id)
      .run();
    await rules({
      methods: ['email'],
      require_factor: '1',
      session_hours: '1',
      ip_ranges: '203.0.113.0/24',
    });
    expect((await get(carol, '/account')).status).toBe(200);
  });
});
