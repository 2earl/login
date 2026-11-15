import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
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

/** Phase 10g (DESIGN §4.24): the organization's API. */

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

async function createKey(access: 'read' | 'write'): Promise<string> {
  const page = await (
    await post(ada, `/orgs/${orgId}/api-keys`, { action: 'create', name: 'Script', access })
  ).text();
  return /<code class="secret">(2earl_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '';
}

function api(key: string, path: string, body?: unknown) {
  return call(app, `/api/v1${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      Authorization: `Bearer ${key}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    ip: freshIp(),
  });
}

describe('the published reference', () => {
  it('is served by login itself, for everyone, since the repository is private', async () => {
    const response = await call(app, '/docs/api');
    expect(response.status).toBe(200);
    const page = await response.text();
    expect(page).toContain('The organization API');
    expect(page).toContain('id="directory-sync-scim-2-0"');
    expect(page).toContain('<code>https://login.2earl.com/api/v1</code>');
    expect(page).not.toContain('github.com');
    const settings = await (
      await call(app, `/orgs/${orgId}/settings`, { cookies: { '__Host-session': ada.session } })
    ).text();
    expect(settings).toContain('href="/docs/api"');
  });
});

describe('the organization’s API', () => {
  it('reads members, domains and the audit log with a key', async () => {
    const key = await createKey('read');
    expect(key).toMatch(/^2earl_/);
    expect(await count('org_api_keys', 'key_hash = ?', key)).toBe(0);

    const members = await (
      await api(key, '/members')
    ).json<{
      data: { id: string; email: string; role: string; managed: boolean }[];
    }>();
    expect(members.data.map((m) => [m.email, m.role, m.managed])).toEqual(
      expect.arrayContaining([
        ['ada@example.com', 'owner', true],
        ['bob@example.com', 'member', true],
      ]),
    );
    const domains = await (await api(key, '/domains')).json<{ data: unknown[] }>();
    expect(domains.data).toEqual([{ domain: 'example.com', verified: true, managed: true }]);

    now += 60;
    const first = await (
      await api(key, '/audit?limit=2')
    ).json<{
      data: { event: string }[];
      next_cursor: string;
    }>();
    expect(first.data).toHaveLength(2);
    const second = await (
      await api(key, `/audit?limit=100&cursor=${encodeURIComponent(first.next_cursor)}`)
    ).json<{ data: { id: string }[] }>();
    expect(second.data.length).toBeGreaterThan(0);
    expect(await count('audit_events', "event = 'org.api_key_created'")).toBe(1);
  });

  it('changes members with a write key, never owners', async () => {
    const read = await createKey('read');
    expect((await api(read, `/members/${bob.id}/role`, { role: 'admin' })).status).toBe(403);
    const write = await createKey('write');
    expect((await api(write, `/members/${bob.id}/role`, { role: 'admin' })).status).toBe(200);
    expect(await count('org_members', "user_id = ? AND role = 'admin'", bob.id)).toBe(1);
    expect((await api(write, `/members/${ada.id}/deactivate`, {})).status).toBe(409);
    expect((await api(write, `/members/${bob.id}/remove`, {})).status).toBe(409);

    expect((await api(write, `/members/${bob.id}/deactivate`, {})).status).toBe(200);
    expect(await count('users', "id = ? AND status = 'suspended'", bob.id)).toBe(1);
    expect((await api(write, `/members/${bob.id}/reactivate`, {})).status).toBe(200);
    expect(await count('users', "id = ? AND status = 'active'", bob.id)).toBe(1);
    expect(
      await count('audit_events', "json_extract(detail, '$.via') = 'api'"),
    ).toBeGreaterThanOrEqual(3);
  });

  it('refuses unknown and revoked keys, and is for owners to manage', async () => {
    expect((await api('2earl_notarealkeynotarealkey00', '/members')).status).toBe(401);
    expect((await call(app, '/api/v1/members')).status).toBe(401);
    const key = await createKey('read');
    const id = (await env.DB.prepare('SELECT id FROM org_api_keys').first<{ id: string }>())?.id;
    await post(ada, `/orgs/${orgId}/api-keys`, { action: 'revoke', key: id ?? '' });
    expect((await api(key, '/members')).status).toBe(401);
    await env.DB.prepare("UPDATE org_members SET role = 'admin' WHERE user_id = ?")
      .bind(bob.id)
      .run();
    expect(
      (await post(bob, `/orgs/${orgId}/api-keys`, { action: 'create', name: 'x', access: 'write' }))
        .status,
    ).toBe(404);
  });
});
