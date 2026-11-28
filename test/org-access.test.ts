import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { makeStaff } from './staff-helpers';
import { check } from '../src/authz/engine';
import { mayDefineRole, mayGrant } from '../src/authz/grant';
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

/** Phase 13b (DESIGN §4.32): roles in 2earl's apps, given in the organization. */

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};

interface Person {
  id: string;
  session: string;
}

let google: FakeGoogle;
let app: ReturnType<typeof createApp>;
let ada: Person; // owner
let bob: Person; // admin
let cy: Person; // member
let dee: Person; // auditor
let orgId: string;

async function person(key: string): Promise<Person> {
  await env.DB.prepare(
    "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES (?, 'email', ?, 'test', 0) ON CONFLICT DO NOTHING",
  )
    .bind(`al-${key}`, `${key}@example.com`)
    .run();
  const { session } = await signIn(app, google, {
    claims: { sub: `sub-${key}`, email: `${key}@example.com`, name: key },
  });
  const row = await env.DB.prepare('SELECT user_id AS id FROM identities WHERE subject = ?')
    .bind(`sub-${key}`)
    .first<{ id: string }>();
  return { id: row?.id ?? '', session: session ?? '' };
}

function post(who: Person, path: string, body: Record<string, string | string[]>, headers = FORM) {
  const form = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) for (const x of [v].flat()) form.append(k, x);
  return call(app, path, {
    method: 'POST',
    headers,
    body: form,
    cookies: { '__Host-session': who.session },
    ip: freshIp(),
  });
}

const page = (who: Person) =>
  call(app, `/orgs/${orgId}/access`, { cookies: { '__Host-session': who.session } });

const can = (who: Person, action: string) =>
  check(env, { subject: { type: 'user', id: who.id }, action, orgId, context: { now: NOW } });

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  google = new FakeGoogle();
  app = createApp({ fetch: google.fetch, googleJwks: testJwks, now: () => NOW });
  ada = await person('ada');
  bob = await person('bob');
  cy = await person('cy');
  dee = await person('dee');
  await makeStaff(ada.session);
  const created = await post(ada, '/orgs', { name: 'Acme Bank' });
  orgId = /\/orgs\/([^?/]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  for (const [who, role] of [
    [bob, 'admin'],
    [cy, 'member'],
    [dee, 'auditor'],
  ] as const) {
    await env.DB.prepare(
      'INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)',
    )
      .bind(orgId, who.id, role, NOW)
      .run();
  }
});

describe('the roles-in-apps page', () => {
  it('is for owners, admins and auditors; members don’t see it', async () => {
    for (const who of [ada, bob, dee]) expect((await page(who)).status).toBe(200);
    expect((await page(cy)).status).toBe(404);
    const html = await (await page(dee)).text();
    expect(html).toContain('Emanet Kurumsal');
    expect(html).toContain('KYC');
    expect(html).toContain('Partner admin');
    // Auditors read; they get no forms.
    expect(html).not.toContain('Give role');
  });
});

describe('giving roles', () => {
  it('an owner gives a member a role, and it applies at once; taking it back ends it', async () => {
    expect(await can(cy, 'emanet:integrations.manage')).toBe(false);
    const given = await post(ada, `/orgs/${orgId}/access/assign`, {
      action: 'assign',
      principal: `user:${cy.id}`,
      role: 'emanet:partner_admin',
      days: '7',
      reason: 'Runs the API pilot',
    });
    expect(given.headers.get('Location')).toBe(`/orgs/${orgId}/access?done=assigned`);
    expect(await can(cy, 'emanet:integrations.manage')).toBe(true);
    const row = await env.DB.prepare('SELECT id, expires_at, reason FROM authz_assignments').first<{
      id: string;
      expires_at: number;
      reason: string;
    }>();
    expect(row?.expires_at).toBe(NOW + 7 * 86400);
    expect(row?.reason).toBe('Runs the API pilot');
    expect(await count('audit_events', "event = 'authz.assigned'")).toBe(1);

    await post(ada, `/orgs/${orgId}/access/assign`, { action: 'revoke', id: row?.id ?? '' });
    expect(await can(cy, 'emanet:integrations.manage')).toBe(false);
    expect(await count('audit_events', "event = 'authz.unassigned'")).toBe(1);
  });

  it('an admin gives roles too, but never to themselves', async () => {
    const ok = await post(bob, `/orgs/${orgId}/access/assign`, {
      action: 'assign',
      principal: `user:${cy.id}`,
      role: 'kyc:tenant_reviewer',
    });
    expect(ok.status).toBe(303);
    expect(await can(cy, 'kyc:tenant.review')).toBe(true);
    const self = await post(bob, `/orgs/${orgId}/access/assign`, {
      action: 'assign',
      principal: `user:${bob.id}`,
      role: 'kyc:tenant_developer',
    });
    expect(self.status).toBe(403);
    expect(await self.text()).toContain('You can’t give yourself a role');
  });

  it('members and auditors give nothing, whatever they post', async () => {
    for (const who of [cy, dee]) {
      const response = await post(who, `/orgs/${orgId}/access/assign`, {
        action: 'assign',
        principal: `user:${ada.id}`,
        role: 'emanet:viewer',
      });
      expect(response.status).toBe(404);
    }
    expect(await count('authz_assignments')).toBe(0);
  });

  it('never gives login’s own roles, and checks same-origin', async () => {
    const owner = await post(ada, `/orgs/${orgId}/access/assign`, {
      action: 'assign',
      principal: `user:${cy.id}`,
      role: 'login:admin',
    });
    expect(owner.status).toBe(403);
    const crossSite = await post(
      ada,
      `/orgs/${orgId}/access/assign`,
      { action: 'assign', principal: `user:${cy.id}`, role: 'emanet:viewer' },
      {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://evil.example',
        'Sec-Fetch-Site': 'cross-site',
      },
    );
    expect(crossSite.status).toBe(403);
    expect(await count('authz_assignments')).toBe(0);
  });

  it('refuses a role whose permissions the giver doesn’t hold', async () => {
    // The check itself, with an actor who claims to be an admin but is a member in the data.
    expect(
      await mayGrant(env, { userId: cy.id, role: 'admin' }, orgId, {
        role: 'emanet:partner_admin',
        principal: { kind: 'user', id: dee.id },
      }),
    ).toEqual({ ok: false, reason: 'exceeds' });
    expect(
      await mayDefineRole(env, { userId: cy.id, role: 'owner' }, orgId, 'emanet', [
        'emanet:integrations.manage',
      ]),
    ).toEqual({ ok: false, reason: 'exceeds' });
  });
});

describe('the organization’s own roles', () => {
  it('owners create one, admins give it, and deleting it takes it back', async () => {
    const created = await post(ada, `/orgs/${orgId}/access/roles`, {
      action: 'create',
      service: 'emanet',
      name: 'Integrations only',
      permission: ['emanet:integrations.manage', 'emanet:cases.read'],
    });
    expect(created.headers.get('Location')).toBe(`/orgs/${orgId}/access?done=role_created`);
    const role = await env.DB.prepare('SELECT id FROM authz_roles').first<{ id: string }>();
    // Admins don't define roles.
    expect(
      (
        await post(bob, `/orgs/${orgId}/access/roles`, {
          action: 'create',
          service: 'emanet',
          name: 'Mine',
          permission: 'emanet:cases.read',
        })
      ).status,
    ).toBe(404);
    await post(bob, `/orgs/${orgId}/access/assign`, {
      action: 'assign',
      principal: `user:${dee.id}`,
      role: role?.id ?? '',
    });
    expect(await can(dee, 'emanet:integrations.manage')).toBe(true);
    expect(await (await page(ada)).text()).toContain('Integrations only');

    await post(ada, `/orgs/${orgId}/access/roles`, { action: 'delete', id: role?.id ?? '' });
    expect(await can(dee, 'emanet:integrations.manage')).toBe(false);
    expect(await count('authz_assignments')).toBe(0);
    expect(
      await count('audit_events', "event IN ('authz.role_created', 'authz.role_deleted')"),
    ).toBe(2);
  });

  it('can’t be made for login itself', async () => {
    const response = await post(ada, `/orgs/${orgId}/access/roles`, {
      action: 'create',
      service: 'login',
      name: 'Inviters',
      permission: 'login:members.invite',
    });
    expect(response.status).toBe(403);
    expect(await count('authz_roles')).toBe(0);
  });
});
