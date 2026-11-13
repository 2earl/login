import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { DELETE_AFTER_SECONDS, dueDeletions, setRequireSso } from '../src/managed';
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

/** Phase 10a (DESIGN §4.18): accounts an organization manages. */

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

function scim(token: string, path: string, init: { method?: string; body?: unknown } = {}) {
  return call(app, `/scim/v2${path}`, {
    method: init.method ?? 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body ? { 'Content-Type': 'application/scim+json' } : {}),
    },
    ...(init.body ? { body: JSON.stringify(init.body) } : {}),
  });
}

const user = (userName: string, extra: Record<string, unknown> = {}) => ({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  userName,
  name: { givenName: 'Grace', familyName: 'Hopper' },
  active: true,
  ...extra,
});

async function userRow(id: string) {
  return env.DB.prepare(
    'SELECT status, managed_by, deactivated_at, delete_after, primary_email, display_name FROM users WHERE id = ?',
  )
    .bind(id)
    .first<{
      status: string;
      managed_by: string | null;
      deactivated_at: number | null;
      delete_after: number | null;
      primary_email: string | null;
      display_name: string | null;
    }>();
}

/** An organization owned by `owner` with example.com verified and a SCIM token. */
async function organization(owner: Person) {
  const created = await post(owner, '/orgs', { name: 'Example Inc' });
  const orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  await post(owner, `/orgs/${orgId}/domains`, { domain: 'example.com' });
  const row = await env.DB.prepare('SELECT challenge FROM org_domains WHERE org_id = ?')
    .bind(orgId)
    .first<{ challenge: string }>();
  dns['_2earl-challenge.example.com'] = [row?.challenge ?? ''];
  await post(owner, `/orgs/${orgId}/domains/verify`, { domain: 'example.com' });
  const page = await (await post(owner, `/orgs/${orgId}/scim-tokens`)).text();
  const token = /<code class="secret">(scim_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '';
  return { orgId, token };
}

/** Turns managing on for example.com; the owner (at that domain too) then joins. */
async function manage(owner: Person, orgId: string) {
  const response = await post(owner, `/orgs/${orgId}/domains/manage`, {
    domain: 'example.com',
    on: '1',
    accept: 'on',
  });
  expect(response.headers.get('Location')).toBe(`/orgs/${orgId}/directory?done=managed`);
  const joined = await post(owner, '/account/managed', { org: orgId, choice: 'join' });
  expect(joined.status).toBe(303);
}

let ada: Person;
let bob: Person;

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  dns = {};
  google = new FakeGoogle();
  app = createApp({ fetch: fetcher, googleJwks: testJwks, now: () => now });
  ada = await person('ada');
  bob = await person('bob');
});

describe('turning on managing for a domain', () => {
  it('needs a verified domain, an owner and the data processing terms', async () => {
    const { orgId } = await organization(ada);
    const refused = await post(ada, `/orgs/${orgId}/domains/manage`, {
      domain: 'example.com',
      on: '1',
    });
    expect(refused.status).toBe(400);
    expect(await count('org_domains', 'managed_at IS NOT NULL')).toBe(0);
    // A member who isn't an owner: the organization doesn't exist for this.
    await env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'admin', 0)",
    )
      .bind(orgId, bob.id)
      .run();
    const notOwner = await post(bob, `/orgs/${orgId}/domains/manage`, {
      domain: 'example.com',
      on: '1',
      accept: 'on',
    });
    expect(notOwner.status).toBe(404);
  });

  it('asks people with an account at the domain to choose, and takes nothing over', async () => {
    const { orgId } = await organization(ada);
    await manage(ada, orgId);
    expect((await userRow(ada.id))?.managed_by).toBe(orgId);
    expect((await userRow(bob.id))?.managed_by).toBeNull();

    // Bob is sent to the choice from anywhere, and can't authorize apps meanwhile.
    const account = await get(bob, '/account');
    expect(account.headers.get('Location')).toBe('/account/managed?return_to=%2Faccount');
    const authorize = await get(bob, '/authorize?client_id=x');
    expect(authorize.headers.get('Location')).toMatch(/^\/account\/managed\?return_to=/);
    const change = await post(bob, '/account/name', { name: 'Bobby' });
    expect(change.status).toBe(403);
    // The choice page names the organization and the address; the organization learns nothing.
    const page = await (await get(bob, '/account/managed')).text();
    expect(page).toContain('Example Inc');
    expect(page).toContain('bob@example.com');
    const directory = await (await get(ada, `/orgs/${orgId}/directory`)).text();
    expect(directory).toContain('1 managed');
    expect(directory).not.toContain('bob@example.com');
  });

  it('lets a person join as a managed account', async () => {
    const { orgId } = await organization(ada);
    await manage(ada, orgId);
    const joined = await post(bob, '/account/managed', {
      org: orgId,
      choice: 'join',
      return_to: '/account',
    });
    expect(joined.headers.get('Location')).toBe('/account');
    expect((await userRow(bob.id))?.managed_by).toBe(orgId);
    expect(await count('org_members', 'org_id = ? AND user_id = ?', orgId, bob.id)).toBe(1);
    expect((await get(bob, '/account')).status).toBe(200);
    expect(await count('audit_events', "event = 'org.account_managed'")).toBe(2);
  });

  it('lets a person keep the account, without the address, once they have another way in', async () => {
    const { orgId } = await organization(ada);
    await manage(ada, orgId);
    const alone = await post(bob, '/account/managed', { org: orgId, choice: 'personal' });
    expect(alone.status).toBe(409);
    expect(await count('identities', 'user_id = ?', bob.id)).toBe(1);

    await env.DB.prepare(
      `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
       VALUES ('id-bob-home', ?, 'email', 'bob@home.test', 'bob@home.test', 1, 0, 0)`,
    )
      .bind(bob.id)
      .run();
    const kept = await post(bob, '/account/managed', { org: orgId, choice: 'personal' });
    expect(kept.status).toBe(303);
    const row = await userRow(bob.id);
    expect(row?.managed_by).toBeNull();
    expect(row?.primary_email).toBe('bob@home.test');
    expect(await count('identities', "user_id = ? AND email LIKE '%@example.com'", bob.id)).toBe(0);
    expect((await get(bob, '/account')).status).toBe(200);
  });
});

describe('new accounts at a managed domain', () => {
  it('are created by the directory, managed and named', async () => {
    const { orgId, token } = await organization(ada);
    await manage(ada, orgId);
    const created = await scim(token, '/Users', {
      method: 'POST',
      body: user('grace@example.com'),
    });
    expect(created.status).toBe(201);
    const id = (
      await env.DB.prepare('SELECT user_id FROM identities WHERE subject = ?')
        .bind('grace@example.com')
        .first<{ user_id: string }>()
    )?.user_id;
    expect(id).toBeTruthy();
    const row = await userRow(id ?? '');
    expect(row?.managed_by).toBe(orgId);
    expect(row?.display_name).toBe('Grace Hopper');
    expect(await count('org_members', 'org_id = ? AND user_id = ?', orgId, id)).toBe(1);
  });

  it('are not created where the organization doesn’t manage the domain', async () => {
    const { token } = await organization(ada);
    await scim(token, '/Users', { method: 'POST', body: user('grace@example.com') });
    expect(await count('identities', 'subject = ?', 'grace@example.com')).toBe(0);
  });

  it('are managed from the start when someone signs up at the domain', async () => {
    const { orgId } = await organization(ada);
    await manage(ada, orgId);
    const carol = await person('carol');
    expect((await userRow(carol.id))?.managed_by).toBe(orgId);
    expect((await get(carol, '/account')).status).toBe(200);
  });
});

describe('what the organization does with managed accounts', () => {
  async function managedBob() {
    const { orgId, token } = await organization(ada);
    await manage(ada, orgId);
    await post(bob, '/account/managed', { org: orgId, choice: 'join' });
    return { orgId, token };
  }

  it('deactivates and reactivates; removing is refused', async () => {
    const { orgId } = await managedBob();
    const removed = await post(ada, `/orgs/${orgId}/members/remove`, { user: bob.id });
    expect(removed.status).toBe(409);

    await post(ada, `/orgs/${orgId}/members/deactivate`, { user: bob.id });
    const row = await userRow(bob.id);
    expect(row?.status).toBe('suspended');
    expect(row?.deactivated_at).toBe(now);
    expect(await count('sessions', 'user_id = ?', bob.id)).toBe(0);
    expect((await get(bob, '/account')).headers.get('Location')).toMatch(/^\/login/);

    await post(ada, `/orgs/${orgId}/members/reactivate`, { user: bob.id });
    expect((await userRow(bob.id))?.status).toBe('active');
  });

  it('never lifts 2earl’s own suspension', async () => {
    const { orgId } = await managedBob();
    await env.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").bind(bob.id).run();
    await post(ada, `/orgs/${orgId}/members/reactivate`, { user: bob.id });
    expect((await userRow(bob.id))?.status).toBe('suspended');
    await post(ada, `/orgs/${orgId}/members/deactivate`, { user: bob.id });
    expect((await userRow(bob.id))?.deactivated_at).toBeNull();
  });

  it('lets only owners delete, after confirming', async () => {
    const { orgId } = await managedBob();
    const unconfirmed = await post(ada, `/orgs/${orgId}/accounts/delete`, { user: bob.id });
    expect(unconfirmed.status).toBe(400);
    expect(await count('users', 'id = ?', bob.id)).toBe(1);
    const deleted = await post(ada, `/orgs/${orgId}/accounts/delete`, {
      user: bob.id,
      confirm: 'on',
    });
    expect(deleted.headers.get('Location')).toBe(`/orgs/${orgId}?done=account_deleted`);
    expect(await count('users', 'id = ?', bob.id)).toBe(0);
    expect(await count('audit_events', "event = 'user.deleted'")).toBe(1);
    expect(await count('audit_events', "event = 'org.account_deleted'")).toBe(1);
  });

  it('follows the directory: inactive deactivates, DELETE deletes 30 days later', async () => {
    const { token } = await managedBob();
    const listed = await (
      await scim(token, '/Users', { method: 'POST', body: user('bob@example.com') })
    ).json<{ id: string }>();
    expect((await userRow(bob.id))?.status).toBe('active');

    await scim(token, `/Users/${listed.id}`, {
      method: 'PUT',
      body: user('bob@example.com', { active: false }),
    });
    expect((await userRow(bob.id))?.status).toBe('suspended');
    await scim(token, `/Users/${listed.id}`, { method: 'PUT', body: user('bob@example.com') });
    expect((await userRow(bob.id))?.status).toBe('active');

    const removed = await scim(token, `/Users/${listed.id}`, { method: 'DELETE' });
    expect(removed.status).toBe(204);
    const row = await userRow(bob.id);
    expect(row?.status).toBe('suspended');
    expect(row?.delete_after).toBe(now + DELETE_AFTER_SECONDS);
    expect(await dueDeletions(env.DB, now)).toEqual([]);
    expect(await dueDeletions(env.DB, now + DELETE_AFTER_SECONDS)).toEqual([bob.id]);
  });

  it('cancels a scheduled deletion when an owner reactivates the account', async () => {
    const { orgId, token } = await managedBob();
    const listed = await (
      await scim(token, '/Users', { method: 'POST', body: user('bob@example.com') })
    ).json<{ id: string }>();
    await scim(token, `/Users/${listed.id}`, { method: 'DELETE' });
    await post(ada, `/orgs/${orgId}/members/reactivate`, { user: bob.id });
    expect((await userRow(bob.id))?.delete_after).toBeNull();
    expect(await dueDeletions(env.DB, now + DELETE_AFTER_SECONDS)).toEqual([]);
  });
});

describe('what a managed person can’t do', () => {
  it('can’t leave, delete the account, or take the managed address off', async () => {
    const { orgId } = await organization(ada);
    await manage(ada, orgId);
    await post(bob, '/account/managed', { org: orgId, choice: 'join' });
    await env.DB.prepare(
      `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
       VALUES ('id-bob-home', ?, 'email', 'bob@home.test', 'bob@home.test', 1, 0, 0)`,
    )
      .bind(bob.id)
      .run();

    const left = await post(bob, `/orgs/${orgId}/leave`, { confirm: 'on' });
    expect(left.status).toBe(409);
    expect(await count('org_members', 'org_id = ? AND user_id = ?', orgId, bob.id)).toBe(1);

    const deletePage = await get(bob, '/account/delete');
    expect(deletePage.status).toBe(403);
    expect(await deletePage.text()).toContain('Example Inc');

    const managedIdentity = await env.DB.prepare(
      "SELECT id FROM identities WHERE user_id = ? AND provider = 'google'",
    )
      .bind(bob.id)
      .first<{ id: string }>();
    await post(bob, '/account/methods/remove', { identity: managedIdentity?.id ?? '' });
    expect(await count('identities', 'user_id = ?', bob.id)).toBe(2);
    // The other address can go.
    await post(bob, '/account/methods/remove', { identity: 'id-bob-home' });
    expect(await count('identities', 'user_id = ?', bob.id)).toBe(1);
  });
});

describe('required single sign-on', () => {
  async function ssoOrg() {
    const { orgId } = await organization(ada);
    await manage(ada, orgId);
    await post(bob, '/account/managed', { org: orgId, choice: 'join' });
    await env.DB.prepare(
      `INSERT INTO org_saml (org_id, idp_entity_id, sso_url, certificate, enabled, created_at, updated_at)
       VALUES (?, 'https://idp.example.com', 'https://idp.example.com/sso', 'cert', 1, 0, 0)`,
    )
      .bind(orgId)
      .run();
    return orgId;
  }

  it('needs the owner turning it on to have a second factor', async () => {
    const orgId = await ssoOrg();
    const refused = await post(ada, `/orgs/${orgId}/require-sso`, { on: '1' });
    expect(refused.status).toBe(409);
    expect(await count('organizations', 'require_sso = 1')).toBe(0);
  });

  it('ends other sessions, refuses other sign-ins, and exempts owners', async () => {
    const orgId = await ssoOrg();
    await setRequireSso(env.DB, now, orgId, true);
    expect(await count('sessions', 'user_id = ?', bob.id)).toBe(0);
    expect(await count('sessions', 'user_id = ?', ada.id)).toBeGreaterThan(0);

    const again = await signIn(app, google, {
      claims: { sub: 'sub-bob', email: 'bob@example.com', name: 'bob' },
    });
    expect(again.callback.status).toBe(403);
    expect(await again.callback.text()).toContain('single sign-on');
    expect(again.session).toBeUndefined();

    expect((await get(ada, '/account')).status).toBe(200);
  });

  it('ends a session started another way at its next request', async () => {
    const orgId = await ssoOrg();
    // Set without ending sessions, as if a session had slipped through.
    await env.DB.prepare('UPDATE organizations SET require_sso = 1 WHERE id = ?').bind(orgId).run();
    expect((await get(bob, '/account')).headers.get('Location')).toMatch(/^\/login/);
    expect(await count('sessions', 'user_id = ?', bob.id)).toBe(0);
  });

  it('lapses while single sign-on is off', async () => {
    const orgId = await ssoOrg();
    await setRequireSso(env.DB, now, orgId, true);
    await env.DB.prepare('UPDATE org_saml SET enabled = 0 WHERE org_id = ?').bind(orgId).run();
    const again = await signIn(app, google, {
      claims: { sub: 'sub-bob', email: 'bob@example.com', name: 'bob' },
    });
    expect(again.session).toBeTruthy();
  });
});

describe('releasing managed accounts', () => {
  it('gives the accounts back when the domain stops being managed, or the organization goes', async () => {
    const { orgId } = await organization(ada);
    await manage(ada, orgId);
    await post(bob, '/account/managed', { org: orgId, choice: 'join' });
    await post(ada, `/orgs/${orgId}/domains/manage`, { domain: 'example.com', on: '0' });
    expect((await userRow(bob.id))?.managed_by).toBeNull();
    expect(await count('org_members', 'org_id = ? AND user_id = ?', orgId, bob.id)).toBe(1);

    await manage(ada, orgId);
    // Ada is still managed by it; Bob must choose again.
    expect((await get(bob, '/account')).headers.get('Location')).toMatch(/^\/account\/managed/);
    await post(bob, '/account/managed', { org: orgId, choice: 'join' });
    await env.DB.prepare('DELETE FROM organizations WHERE id = ?').bind(orgId).run();
    expect((await userRow(bob.id))?.managed_by).toBeNull();
  });
});
