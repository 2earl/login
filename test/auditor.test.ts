import { env } from 'cloudflare:workers';
import { makeStaff } from './staff-helpers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { setOAuthClock } from '../src/oauth';
import { setGroupRole } from '../src/scim-groups';
import { FakeGoogle, NOW, ORIGIN, call, freshIp, resetDatabase, signIn, testJwks } from './helpers';

/** Phase 10k (DESIGN §4.28): the auditor role sees everything and changes nothing. */

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};

interface Sent {
  to: string;
  subject: string;
  text: string;
}
interface Person {
  id: string;
  session: string;
  email: string;
}

let google: FakeGoogle;
let app: ReturnType<typeof createApp>;
let sent: Sent[];
const mailer = {
  send: (message: Sent) => {
    sent.push(message);
    return Promise.resolve({ messageId: 'm' });
  },
};

async function person(key: string): Promise<Person> {
  const email = `${key}@example.com`;
  await env.DB.prepare(
    "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES (?, 'email', ?, 'test', 0)",
  )
    .bind(`al-${key}`, email)
    .run();
  const { session } = await signIn(app, google, {
    claims: { sub: `sub-${key}`, email, name: key.charAt(0).toUpperCase() + key.slice(1) },
  });
  const row = await env.DB.prepare(
    "SELECT user_id AS id FROM identities WHERE provider = 'google' AND subject = ?",
  )
    .bind(`sub-${key}`)
    .first<{ id: string }>();
  return { id: row?.id ?? '', session: session ?? '', email };
}

const send = (who: Person, path: string, body?: Record<string, string>) =>
  call(app, path, {
    ...(body
      ? { method: 'POST', headers: FORM, body: new URLSearchParams(body) }
      : { headers: { Accept: 'text/html' } }),
    cookies: { '__Host-session': who.session },
    ip: freshIp(),
    vars: { MAILER: mailer },
  });

const roleOf = async (userId: string) =>
  (
    await env.DB.prepare('SELECT role FROM org_members WHERE org_id = ? AND user_id = ?')
      .bind(orgId, userId)
      .first<{ role: string }>()
  )?.role;

let ada: Person;
let bob: Person;
let carol: Person;
let orgId: string;

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  sent = [];
  google = new FakeGoogle();
  app = createApp({
    fetch: (input, init) => google.fetch(input, init),
    googleJwks: testJwks,
    now: () => NOW,
  });
  ada = await person('ada');
  bob = await person('bob');
  carol = await person('carol');
  await makeStaff(ada.session);
  const created = await send(ada, '/orgs', { name: 'Example Inc' });
  orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'member', 0)",
    ).bind(orgId, bob.id),
    env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'member', 0)",
    ).bind(orgId, carol.id),
  ]);
  sent = [];
});

describe('giving the role', () => {
  it('an owner makes someone an auditor, and the owners hear of it', async () => {
    await send(ada, `/orgs/${orgId}/members/role`, { user: bob.id, role: 'auditor' });
    expect(await roleOf(bob.id)).toBe('auditor');
    expect(sent.find((m) => m.to === ada.email)?.text).toContain(
      'made Bob (bob@example.com) an auditor',
    );
  });

  it('can be invited for', async () => {
    const response = await send(ada, `/orgs/${orgId}/invitations`, {
      email: 'dave@example.com',
      role: 'auditor',
    });
    expect(response.status).toBeLessThan(400);
    const row = await env.DB.prepare('SELECT role FROM org_invitations WHERE org_id = ?')
      .bind(orgId)
      .first<{ role: string }>();
    expect(row?.role).toBe('auditor');
    expect(sent.find((m) => m.to === 'dave@example.com')?.text).toContain('auditor (read-only)');
  });
});

describe('an auditor', () => {
  beforeEach(async () => {
    await env.DB.prepare("UPDATE org_members SET role = 'auditor' WHERE user_id = ?")
      .bind(bob.id)
      .run();
  });

  it('sees the members and the activity, and downloads it', async () => {
    const members = await (await send(bob, `/orgs/${orgId}`)).text();
    expect(members).toContain('Carol');
    expect(members).toContain('Activity');
    expect(members).not.toContain('Invite people');
    expect(members).not.toContain(`action="/orgs/${orgId}/members/role"`);
    expect((await send(bob, `/orgs/${orgId}/activity`)).status).toBe(200);
    const csv = await send(bob, `/orgs/${orgId}/activity/export?format=csv`);
    expect(csv.status).toBe(200);
  });

  it('changes nothing', async () => {
    const tries: [string, Record<string, string>][] = [
      [`/orgs/${orgId}/invitations`, { email: 'eve@example.com', role: 'member' }],
      [`/orgs/${orgId}/members/role`, { user: carol.id, role: 'admin' }],
      [`/orgs/${orgId}/members/remove`, { user: carol.id }],
      [`/orgs/${orgId}/name`, { name: 'Taken' }],
      [`/orgs/${orgId}/api-keys`, { action: 'create', name: 'x', access: 'read' }],
    ];
    for (const [path, body] of tries) {
      const response = await send(bob, path, body);
      expect(response.status, path).toBeGreaterThanOrEqual(400);
    }
    expect(await roleOf(carol.id)).toBe('member');
    expect(await roleOf(bob.id)).toBe('auditor');
    expect((await send(bob, `/orgs/${orgId}/directory`)).status).toBe(404);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM org_invitations').first('n')).toBe(0);
  });
});

describe('directory groups', () => {
  it('give the auditor role, and admin wins', async () => {
    const now = NOW;
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO scim_users (id, org_id, user_name, user_id, active, created_at, updated_at) VALUES ('su-bob', ?1, 'bob@example.com', ?2, 1, 0, 0), ('su-carol', ?1, 'carol@example.com', ?3, 1, 0, 0)",
      ).bind(orgId, bob.id, carol.id),
      env.DB.prepare(
        "INSERT INTO scim_groups (id, org_id, display_name, created_at, updated_at) VALUES ('g-sec', ?1, 'Security', 0, 0), ('g-it', ?1, 'IT', 0, 0)",
      ).bind(orgId),
      env.DB.prepare(
        "INSERT INTO scim_group_members (group_id, scim_user_id) VALUES ('g-sec', 'su-bob'), ('g-sec', 'su-carol'), ('g-it', 'su-carol')",
      ),
    ]);
    await setGroupRole(env.DB, now, orgId, 'g-sec', 'auditor');
    expect(await roleOf(bob.id)).toBe('auditor');
    expect(await roleOf(carol.id)).toBe('auditor');
    await setGroupRole(env.DB, now, orgId, 'g-it', 'admin');
    expect(await roleOf(carol.id)).toBe('admin');
    expect(await roleOf(bob.id)).toBe('auditor');
    // The owner never changes.
    expect(await roleOf(ada.id)).toBe('owner');
    await setGroupRole(env.DB, now, orgId, 'g-sec', null);
    expect(await roleOf(bob.id)).toBe('member');
  });

  it('can be marked auditors on Domains & SSO', async () => {
    await env.DB.prepare(
      "INSERT INTO scim_groups (id, org_id, display_name, created_at, updated_at) VALUES ('g-sec', ?, 'Security', 0, 0)",
    )
      .bind(orgId)
      .run();
    const saved = await send(ada, `/orgs/${orgId}/groups/role`, {
      group: 'g-sec',
      role: 'auditor',
    });
    expect(saved.status).toBe(303);
    expect(
      await env.DB.prepare("SELECT role FROM scim_groups WHERE id = 'g-sec'").first('role'),
    ).toBe('auditor');
  });
});
