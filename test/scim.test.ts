import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { normaliseDomain } from '../src/org-domains';
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

/** Phase 9b (DESIGN §4.16): verified domains and SCIM 2.0 provisioning. */

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};

let google: FakeGoogle;
let app: ReturnType<typeof createApp>;
let now: number;
/** TXT records the stand-in DNS answers with, by name. */
let dns: Record<string, string[]>;

interface Person {
  id: string;
  session: string;
  email: string;
}

const people: Record<string, Person> = {};

/** Google for sign-in; DNS over HTTPS for domain checks. */
const fetcher: typeof fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  if (url.hostname === 'cloudflare-dns.com') {
    const name = url.searchParams.get('name') ?? '';
    const records = dns[name] ?? [];
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
    "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES (?, 'email', ?, 'test', 0)",
  )
    .bind(`al-${key}`, email)
    .run();
  const { session } = await signIn(app, google, {
    claims: { sub: `sub-${key}`, email, name: key },
  });
  const row = await env.DB.prepare('SELECT id FROM users WHERE primary_email = ?')
    .bind(email)
    .first<{ id: string }>();
  const p = { id: row?.id ?? '', session: session ?? '', email };
  people[key] = p;
  return p;
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

function scim(token: string | null, path: string, init: { method?: string; body?: unknown } = {}) {
  return call(app, `/scim/v2${path}`, {
    method: init.method ?? 'GET',
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.body ? { 'Content-Type': 'application/scim+json' } : {}),
    },
    ...(init.body ? { body: JSON.stringify(init.body) } : {}),
  });
}

async function orgWithDirectory(owner: Person) {
  const created = await post(owner, '/orgs', { name: 'Example Inc' });
  const orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  await post(owner, `/orgs/${orgId}/domains`, { domain: 'Example.COM.' });
  const row = await env.DB.prepare('SELECT challenge FROM org_domains WHERE org_id = ?')
    .bind(orgId)
    .first<{ challenge: string }>();
  dns['_2earl-challenge.example.com'] = ['unrelated', row?.challenge ?? ''];
  const verified = await post(owner, `/orgs/${orgId}/domains/verify`, { domain: 'example.com' });
  expect(verified.headers.get('Location')).toBe(`/orgs/${orgId}/directory?done=verified`);
  const page = await (await post(owner, `/orgs/${orgId}/scim-tokens`)).text();
  const token = /<code class="secret">(scim_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '';
  expect(token).not.toBe('');
  return { orgId, token };
}

const user = (userName: string, extra: Record<string, unknown> = {}) => ({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  userName,
  name: { givenName: 'Given', familyName: 'Family' },
  active: true,
  ...extra,
});

const patch = (Operations: unknown[]) => ({
  schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
  Operations,
});

const roleOf = async (orgId: string, userId: string) =>
  (
    await env.DB.prepare('SELECT role FROM org_members WHERE org_id = ? AND user_id = ?')
      .bind(orgId, userId)
      .first<{ role: string }>()
  )?.role ?? null;

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  dns = {};
  google = new FakeGoogle();
  app = createApp({ fetch: fetcher, googleJwks: testJwks, now: () => now });
  await person('ada');
  await person('bob');
});

describe('verified domains', () => {
  it('are proved with a TXT record, and belong to one organization at a time', async () => {
    const ada = people.ada as Person;
    const created = await post(ada, '/orgs', { name: 'First' });
    const orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
    await post(ada, `/orgs/${orgId}/domains`, { domain: 'example.com' });
    const missing = await post(ada, `/orgs/${orgId}/domains/verify`, { domain: 'example.com' });
    expect(missing.status).toBe(409);
    expect(await missing.text()).toContain('The TXT record isn’t there yet');
    // No directory token before a verified domain.
    expect((await post(ada, `/orgs/${orgId}/scim-tokens`)).status).toBe(409);

    const second = await orgWithDirectory(people.bob as Person);
    const challenge =
      (
        await env.DB.prepare('SELECT challenge FROM org_domains WHERE org_id = ?')
          .bind(orgId)
          .first<{ challenge: string }>()
      )?.challenge ?? '';
    dns['_2earl-challenge.example.com'] = [challenge];
    const taken = await post(ada, `/orgs/${orgId}/domains/verify`, { domain: 'example.com' });
    expect(await taken.text()).toContain('Another organization has already verified this domain');
    expect(await count('org_domains', 'verified_at IS NOT NULL')).toBe(1);
    expect(second.token).toMatch(/^scim_/);
  });

  it('are host names only', () => {
    expect(normaliseDomain(' Example.COM. ')).toBe('example.com');
    expect(normaliseDomain('bücher.example')).toBe('xn--bcher-kva.example');
    for (const bad of [
      'localhost',
      '192.168.1.1',
      'a b.com',
      'user@example.com',
      'https://x.com/',
      '-x.com',
      '',
    ]) {
      expect(normaliseDomain(bad), bad).toBeNull();
    }
  });

  it('only owners manage them', async () => {
    const { orgId } = await orgWithDirectory(people.ada as Person);
    const bob = people.bob as Person;
    expect(
      (
        await call(app, `/orgs/${orgId}/directory`, {
          cookies: { '__Host-session': bob.session },
        })
      ).status,
    ).toBe(404);
    expect((await post(bob, `/orgs/${orgId}/domains`, { domain: 'other.com' })).status).toBe(404);
  });
});

describe('SCIM 2.0', () => {
  it('needs the organization’s token, and describes itself', async () => {
    const { token } = await orgWithDirectory(people.ada as Person);
    expect((await scim(null, '/Users')).status).toBe(401);
    expect((await scim('scim_wrong', '/Users')).status).toBe(401);
    const config = await (
      await scim(token, '/ServiceProviderConfig')
    ).json<{ patch: { supported: boolean } }>();
    expect(config.patch.supported).toBe(true);
    expect((await scim(token, '/Groups')).status).toBe(200);
    expect((await scim(token, '/Bulk', { method: 'POST', body: {} })).status).toBe(501);
  });

  it('adds an existing account at a verified domain, and only such addresses', async () => {
    const { orgId, token } = await orgWithDirectory(people.ada as Person);
    const bob = people.bob as Person;
    const created = await scim(token, '/Users', {
      method: 'POST',
      body: user('Bob@Example.com', { externalId: 'okta-1' }),
    });
    expect(created.status).toBe(201);
    expect(created.headers.get('Content-Type')).toBe('application/scim+json');
    const body = await created.json<{ id: string; userName: string; active: boolean }>();
    expect(body).toMatchObject({ userName: 'bob@example.com', active: true });
    expect(await roleOf(orgId, bob.id)).toBe('member');

    expect(
      (await scim(token, '/Users', { method: 'POST', body: user('bob@example.com') })).status,
    ).toBe(409);
    const outside = await scim(token, '/Users', {
      method: 'POST',
      body: user('someone@gmail.com'),
    });
    expect(outside.status).toBe(400);
    expect(await count('scim_users')).toBe(1);

    const found = await (
      await scim(token, `/Users?filter=${encodeURIComponent('externalId eq "okta-1"')}`)
    ).json<{ totalResults: number; Resources: { id: string }[] }>();
    expect(found.totalResults).toBe(1);
    expect(found.Resources[0]?.id).toBe(body.id);
    expect((await scim(token, `/Users?filter=${encodeURIComponent('emails co "x"')}`)).status).toBe(
      400,
    );
  });

  it('makes someone without an account a member when they first sign in', async () => {
    const { orgId, token } = await orgWithDirectory(people.ada as Person);
    await scim(token, '/Users', { method: 'POST', body: user('carol@example.com') });
    expect(await count('org_members', 'org_id = ?', orgId)).toBe(1);
    const carol = await person('carol');
    expect(await roleOf(orgId, carol.id)).toBe('member');
  });

  it('follows deactivation, reactivation and deletion; the last owner stays', async () => {
    const ada = people.ada as Person;
    const bob = people.bob as Person;
    const { orgId, token } = await orgWithDirectory(ada);
    const { id } = await (
      await scim(token, '/Users', { method: 'POST', body: user('bob@example.com') })
    ).json<{ id: string }>();

    // Microsoft Entra sends booleans as strings.
    const off = await scim(token, `/Users/${id}`, {
      method: 'PATCH',
      body: patch([{ op: 'Replace', path: 'active', value: 'False' }]),
    });
    expect(off.status).toBe(200);
    expect(await roleOf(orgId, bob.id)).toBeNull();
    await scim(token, `/Users/${id}`, {
      method: 'PATCH',
      body: patch([{ op: 'replace', value: { active: true, displayName: 'Bob B' } }]),
    });
    expect(await roleOf(orgId, bob.id)).toBe('member');
    expect(
      (await (await scim(token, `/Users/${id}`)).json<{ displayName: string }>()).displayName,
    ).toBe('Bob B');

    expect((await scim(token, `/Users/${id}`, { method: 'DELETE' })).status).toBe(204);
    expect(await roleOf(orgId, bob.id)).toBeNull();
    expect((await scim(token, `/Users/${id}`)).status).toBe(404);

    const owner = await (
      await scim(token, '/Users', { method: 'POST', body: user('ada@example.com') })
    ).json<{ id: string }>();
    const refused = await scim(token, `/Users/${owner.id}`, {
      method: 'PATCH',
      body: patch([{ op: 'replace', path: 'active', value: false }]),
    });
    expect(refused.status).toBe(409);
    expect(await roleOf(orgId, ada.id)).toBe('owner');
  });

  it('moves membership with a changed address (PUT), and sees only its own organization', async () => {
    const { orgId, token } = await orgWithDirectory(people.ada as Person);
    const bob = people.bob as Person;
    const carol = await person('carol');
    const { id } = await (
      await scim(token, '/Users', { method: 'POST', body: user('bob@example.com') })
    ).json<{ id: string }>();
    const moved = await scim(token, `/Users/${id}`, {
      method: 'PUT',
      body: user('carol@example.com'),
    });
    expect(moved.status).toBe(200);
    expect(await roleOf(orgId, bob.id)).toBeNull();
    expect(await roleOf(orgId, carol.id)).toBe('member');

    // Another organization's token can't see or change this user.
    const other = await person('dan', 'other.org');
    const created = await post(other, '/orgs', { name: 'Other' });
    const otherOrg = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
    await post(other, `/orgs/${otherOrg}/domains`, { domain: 'other.org' });
    const challenge =
      (
        await env.DB.prepare('SELECT challenge FROM org_domains WHERE org_id = ?')
          .bind(otherOrg)
          .first<{ challenge: string }>()
      )?.challenge ?? '';
    dns['_2earl-challenge.other.org'] = [challenge];
    await post(other, `/orgs/${otherOrg}/domains/verify`, { domain: 'other.org' });
    const page = await (await post(other, `/orgs/${otherOrg}/scim-tokens`)).text();
    const otherToken = /<code class="secret">(scim_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '';
    expect((await scim(otherToken, `/Users/${id}`)).status).toBe(404);
    expect((await scim(otherToken, `/Users/${id}`, { method: 'DELETE' })).status).toBe(404);
  });

  it('stops working when the token is revoked or the organization is suspended', async () => {
    const ada = people.ada as Person;
    const { orgId, token } = await orgWithDirectory(ada);
    expect((await scim(token, '/Users')).status).toBe(200);
    await env.DB.prepare("UPDATE organizations SET status = 'suspended' WHERE id = ?")
      .bind(orgId)
      .run();
    expect((await scim(token, '/Users')).status).toBe(401);
    await env.DB.prepare("UPDATE organizations SET status = 'active' WHERE id = ?")
      .bind(orgId)
      .run();
    const id =
      (await env.DB.prepare('SELECT id FROM scim_tokens').first<{ id: string }>())?.id ?? '';
    await post(ada, `/orgs/${orgId}/scim-tokens/revoke`, { token: id });
    expect((await scim(token, '/Users')).status).toBe(401);
  });

  it('“Download your data” includes what directories said about you', async () => {
    const { token } = await orgWithDirectory(people.ada as Person);
    await scim(token, '/Users', {
      method: 'POST',
      body: user('bob@example.com', { externalId: 'e-7' }),
    });
    const data = await (
      await call(app, '/account/export', {
        cookies: { '__Host-session': (people.bob as Person).session },
      })
    ).json<{ directoryRecords: { externalId: string }[] }>();
    expect(data.directoryRecords).toEqual([
      expect.objectContaining({ externalId: 'e-7', givenName: 'Given' }),
    ]);
  });
});

describe('SCIM groups (DESIGN §4.21)', () => {
  /** Ada's organization, with Bob provisioned and linked. */
  async function withBob() {
    const ada = people.ada as Person;
    const bob = people.bob as Person;
    const { orgId, token } = await orgWithDirectory(ada);
    const listed = await (
      await scim(token, '/Users', { method: 'POST', body: user('bob@example.com') })
    ).json<{ id: string }>();
    return { ada, bob, orgId, token, bobScim: listed.id };
  }

  const group = (displayName: string, members: string[] = []) => ({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    displayName,
    members: members.map((value) => ({ value })),
  });

  it('are created, listed, filtered, patched the ways Entra ID and Okta do, and deleted', async () => {
    const { token, bobScim } = await withBob();
    const created = await scim(token, '/Groups', {
      method: 'POST',
      body: group('Engineering', [bobScim, 'scu_unknown']),
    });
    expect(created.status).toBe(201);
    const engineering = await created.json<{ id: string; members: { value: string }[] }>();
    // Unknown users are skipped.
    expect(engineering.members.map((m) => m.value)).toEqual([bobScim]);
    expect(
      (await scim(token, '/Groups', { method: 'POST', body: group('engineering') })).status,
    ).toBe(409);

    const found = await (
      await scim(
        token,
        `/Groups?filter=${encodeURIComponent('displayName eq "Engineering"')}&excludedAttributes=members`,
      )
    ).json<{ totalResults: number; Resources: Record<string, unknown>[] }>();
    expect(found.totalResults).toBe(1);
    expect(found.Resources[0]?.members).toBeUndefined();

    const path = `/Groups/${engineering.id}`;
    // Okta: remove by path filter.
    await scim(token, path, {
      method: 'PATCH',
      body: patch([{ op: 'remove', path: `members[value eq "${bobScim}"]` }]),
    });
    expect(await count('scim_group_members', 'group_id = ?', engineering.id)).toBe(0);
    // Entra ID: capitalized ops, add by value, rename without a path.
    await scim(token, path, {
      method: 'PATCH',
      body: patch([
        { op: 'Add', path: 'members', value: [{ value: bobScim }] },
        { op: 'Replace', value: { displayName: 'Platform' } },
      ]),
    });
    const after = await (
      await scim(token, path)
    ).json<{
      displayName: string;
      members: unknown[];
    }>();
    expect(after.displayName).toBe('Platform');
    expect(after.members).toHaveLength(1);
    // Entra ID: remove by value.
    await scim(token, path, {
      method: 'PATCH',
      body: patch([{ op: 'Remove', path: 'members', value: [{ value: bobScim }] }]),
    });
    expect(await count('scim_group_members', 'group_id = ?', engineering.id)).toBe(0);
    expect(
      (
        await scim(token, path, {
          method: 'PATCH',
          body: patch([{ op: 'move', path: 'members' }]),
        })
      ).status,
    ).toBe(400);
    expect((await scim(token, path, { method: 'DELETE' })).status).toBe(204);
    expect(await count('scim_groups')).toBe(0);
  });

  it('give roles once an owner marks a group admin; owners never change', async () => {
    const { ada, bob, orgId, token, bobScim } = await withBob();
    const admins = await (
      await scim(token, '/Groups', { method: 'POST', body: group('2earl admins', [bobScim]) })
    ).json<{ id: string }>();
    // No group has a role yet: the directory doesn't touch roles.
    expect(await roleOf(orgId, bob.id)).toBe('member');

    const marked = await post(ada, `/orgs/${orgId}/groups/role`, {
      group: admins.id,
      role: 'admin',
    });
    expect(marked.headers.get('Location')).toBe(`/orgs/${orgId}/directory?done=group_role`);
    expect(await roleOf(orgId, bob.id)).toBe('admin');

    // Leaving the group in the directory makes Bob a member again.
    await scim(token, `/Groups/${admins.id}`, {
      method: 'PATCH',
      body: patch([{ op: 'remove', path: 'members' }]),
    });
    expect(await roleOf(orgId, bob.id)).toBe('member');

    // In 2earl, the role can't be changed by hand any more, except to owner.
    const byHand = await post(ada, `/orgs/${orgId}/members/role`, { user: bob.id, role: 'admin' });
    expect(byHand.status).toBe(409);
    expect(await roleOf(orgId, ada.id)).toBe('owner');
    // A member isn't the owner who can mark groups.
    expect(
      (await post(bob, `/orgs/${orgId}/groups/role`, { group: admins.id, role: '' })).status,
    ).toBe(404);
  });
});
