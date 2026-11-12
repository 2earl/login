import { env, exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { deleteAccount } from '../src/account';
import { deliverDeletionNotices } from '../src/deletion-notices';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import { userClaims } from '../src/oidc';
import { canRemove, canSetRole, orgName } from '../src/orgs';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  count,
  envOverride,
  freshIp,
  makeApp,
  resetDatabase,
  signIn,
} from './helpers';

/** Phase 9a (DESIGN §4.14): organizations and roles. */

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

let app: ReturnType<typeof makeApp>;
let google: FakeGoogle;
let sent: Sent[];
let now: number;

const mailer = {
  send: (message: Sent) => {
    sent.push(message);
    return Promise.resolve({ messageId: 'm' });
  },
};

interface Person {
  id: string;
  session: string;
  email: string;
}

const people: Record<string, Person> = {};

/** Signs up a person with Google (invited, since tests run with sign-up closed). */
async function person(key: string, name: string): Promise<Person> {
  const email = `${key}@example.com`;
  await env.DB.prepare(
    "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES (?, 'email', ?, 'test', 0)",
  )
    .bind(`al-${key}`, email)
    .run();
  const { session } = await signIn(app, google, {
    claims: { sub: `google-sub-${key}`, email, name },
  });
  const row = await env.DB.prepare('SELECT id FROM users WHERE primary_email = ?')
    .bind(email)
    .first<{ id: string }>();
  const p = { id: row?.id ?? '', session: session ?? '', email };
  people[key] = p;
  return p;
}

async function post(who: Person, path: string, body: Record<string, string> = {}) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(body),
    cookies: { '__Host-session': who.session },
    ip: freshIp(),
    vars: { MAILER: mailer },
  });
}

async function get(who: Person | null, path: string) {
  return call(app, path, who ? { cookies: { '__Host-session': who.session } } : {});
}

async function createOrg(owner: Person, name = 'Acme Research'): Promise<string> {
  const response = await post(owner, '/orgs', { name });
  expect(response.status).toBe(303);
  const location = response.headers.get('Location') ?? '';
  const id = /^\/orgs\/(org_[A-Za-z0-9_-]+)\?done=created$/.exec(location)?.[1];
  expect(id).toBeTruthy();
  return id ?? '';
}

/** Invites `email` and returns the token from the email's link. */
async function invite(from: Person, orgId: string, email: string, role = 'member') {
  const response = await post(from, `/orgs/${orgId}/invitations`, { email, role });
  expect(response.status).toBe(303);
  const mail = sent.at(-1);
  expect(mail?.to).toBe(email);
  return /\/invite\/([A-Za-z0-9_-]+)/.exec(mail?.text ?? '')?.[1] ?? '';
}

async function join(who: Person, orgId: string, role = 'member') {
  const token = await invite(people.ada as Person, orgId, who.email, role);
  const accepted = await post(who, `/invite/${token}`, { decision: 'accept' });
  expect(accepted.headers.get('Location')).toBe(`/orgs/${orgId}?done=joined`);
}

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
  sent = [];
  google = new FakeGoogle();
  app = makeApp(google, () => now);
  await person('ada', 'Ada Lovelace');
  await person('bob', 'Bob Example');
  await person('cy', 'Cy Example');
});

describe('organizations', () => {
  it('are created with their creator as the only owner, and listed on the account page', async () => {
    const ada = people.ada as Person;
    const orgId = await createOrg(ada);
    expect(await roleOf(orgId, ada.id)).toBe('owner');
    const page = await (await get(ada, `/orgs/${orgId}?done=created`)).text();
    expect(page).toContain('Acme Research');
    expect(page).toContain('Organization created.');
    const account = await (await get(ada, '/account')).text();
    expect(account).toContain(`href="/orgs/${orgId}"`);
    expect(account).toContain('Owner · 1 member');
  });

  it('don’t exist for anyone outside them, and refuse cross-site changes', async () => {
    const orgId = await createOrg(people.ada as Person);
    const bob = people.bob as Person;
    expect((await get(bob, `/orgs/${orgId}`)).status).toBe(404);
    expect((await post(bob, `/orgs/${orgId}/name`, { name: 'Taken' })).status).toBe(404);
    expect((await get(null, `/orgs/${orgId}`)).headers.get('Location')).toBe(
      `/login?return_to=${encodeURIComponent(`/orgs/${orgId}`)}`,
    );
    const crossSite = await call(app, `/orgs/${orgId}/name`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://evil.example',
      },
      body: new URLSearchParams({ name: 'Evil' }),
      cookies: { '__Host-session': (people.ada as Person).session },
    });
    expect(crossSite.status).toBe(403);
  });

  it('take plain names only: no links in invitation emails', async () => {
    expect(orgName('  Acme   Research ')).toBe('Acme Research');
    expect(orgName('Café Ünïcode')).toBe('Café Ünïcode');
    for (const bad of [
      '',
      'x'.repeat(61),
      'Visit https://evil.example',
      'www.evil',
      'login-2earl.com',
      'Bad\u202eName',
      '<b>',
    ]) {
      expect(orgName(bad)).toBeNull();
    }
    const response = await post(people.ada as Person, '/orgs', { name: 'paypal.com support' });
    expect(response.status).toBe(400);
    expect(await count('organizations')).toBe(0);
  });
});

describe('invitations', () => {
  it('are emailed, and only an account with the invited address can accept, once', async () => {
    const ada = people.ada as Person;
    const bob = people.bob as Person;
    const cy = people.cy as Person;
    const orgId = await createOrg(ada);
    const token = await invite(ada, orgId, bob.email);
    expect(sent.at(-1)?.subject).toBe('Join “Acme Research” on 2earl');
    expect(sent.at(-1)?.text).toContain('Ada Lovelace (ada@example.com) invited you');
    // Only an HMAC of the token is stored.
    expect(await count('org_invitations', 'token_hash = ?', token)).toBe(0);

    // A forwarded link is useless to anyone else, and they can't decline it either.
    const page = await (await get(cy, `/invite/${token}`)).text();
    expect(page).toContain('Join “Acme Research”');
    expect((await post(cy, `/invite/${token}`, { decision: 'accept' })).status).toBe(403);
    expect((await post(cy, `/invite/${token}`, { decision: 'decline' })).status).toBe(403);
    expect(await roleOf(orgId, cy.id)).toBeNull();

    const accepted = await post(bob, `/invite/${token}`, { decision: 'accept' });
    expect(accepted.headers.get('Location')).toBe(`/orgs/${orgId}?done=joined`);
    expect(await roleOf(orgId, bob.id)).toBe('member');
    expect((await get(bob, `/invite/${token}`)).status).toBe(404);
    // Members see each other.
    expect(await (await get(bob, `/orgs/${orgId}`)).text()).toContain('ada@example.com');
  });

  it('send someone signed out to sign in first, and expire after 7 days', async () => {
    const ada = people.ada as Person;
    const orgId = await createOrg(ada);
    const token = await invite(ada, orgId, (people.bob as Person).email);
    expect((await get(null, `/invite/${token}`)).headers.get('Location')).toBe(
      `/login?return_to=${encodeURIComponent(`/invite/${token}`)}`,
    );
    // Seven days later (moved back, rather than the clock forward, so the session still works).
    await env.DB.prepare('UPDATE org_invitations SET expires_at = expires_at - ?')
      .bind(7 * 24 * 60 * 60)
      .run();
    expect((await get(people.bob as Person, `/invite/${token}`)).status).toBe(404);
    expect((await get(people.bob as Person, `/invite/not-a-token`)).status).toBe(404);
  });

  it('can be declined or withdrawn, and aren’t sent twice or to members', async () => {
    const ada = people.ada as Person;
    const bob = people.bob as Person;
    const orgId = await createOrg(ada);
    const token = await invite(ada, orgId, bob.email);
    const again = await post(ada, `/orgs/${orgId}/invitations`, {
      email: bob.email,
      role: 'member',
    });
    expect(again.status).toBe(409);
    expect(await post(bob, `/invite/${token}`, { decision: 'decline' })).toHaveProperty(
      'status',
      303,
    );
    expect(await count('org_invitations')).toBe(0);

    await invite(ada, orgId, 'nobody-yet@example.com');
    const id = (await env.DB.prepare('SELECT id FROM org_invitations').first<{ id: string }>())?.id;
    await post(ada, `/orgs/${orgId}/invitations/revoke`, { invitation: id ?? '' });
    expect(await count('org_invitations')).toBe(0);

    const self = await post(ada, `/orgs/${orgId}/invitations`, {
      email: ada.email,
      role: 'member',
    });
    expect(self.status).toBe(409);
    expect(await self.text()).toContain('already belongs to a member');
  });

  it('are limited to 50 a day for each account', async () => {
    const ada = people.ada as Person;
    const orgId = await createOrg(ada);
    await env.DB.batch(
      Array.from({ length: 50 }, (_, i) =>
        env.DB.prepare(
          `INSERT INTO audit_events (id, at, event, actor_user_id) VALUES (?, ?, 'org.invited', ?)`,
        ).bind(`a${String(i)}`, now - 60, ada.id),
      ),
    );
    const refused = await post(ada, `/orgs/${orgId}/invitations`, {
      email: 'x@example.com',
      role: 'member',
    });
    expect(refused.status).toBe(429);
    expect(sent).toHaveLength(0);
  });
});

describe('roles', () => {
  it('follow the rules: admins manage members, only owners touch owners', () => {
    expect(canSetRole('admin', 'member', 'admin')).toBe(true);
    expect(canSetRole('admin', 'member', 'owner')).toBe(false);
    expect(canSetRole('admin', 'owner', 'member')).toBe(false);
    expect(canSetRole('member', 'member', 'admin')).toBe(false);
    expect(canSetRole('owner', 'owner', 'member')).toBe(true);
    expect(canRemove('admin', 'admin')).toBe(true);
    expect(canRemove('admin', 'owner')).toBe(false);
    expect(canRemove('member', 'member')).toBe(false);
  });

  it('are enforced, and an organization always keeps an owner', async () => {
    const ada = people.ada as Person;
    const bob = people.bob as Person;
    const cy = people.cy as Person;
    const orgId = await createOrg(ada);
    await join(bob, orgId, 'admin');
    await join(cy, orgId);

    // An admin can't make an owner, remove one, rename or delete.
    expect(
      (await post(bob, `/orgs/${orgId}/members/role`, { user: cy.id, role: 'owner' })).status,
    ).toBe(403);
    expect((await post(bob, `/orgs/${orgId}/members/remove`, { user: ada.id })).status).toBe(403);
    expect((await post(bob, `/orgs/${orgId}/name`, { name: 'Mine now' })).status).toBe(403);
    expect((await post(bob, `/orgs/${orgId}/delete`, { name: 'Acme Research' })).status).toBe(403);
    // A member can't invite or change anyone.
    expect(
      (await post(cy, `/orgs/${orgId}/invitations`, { email: 'z@example.com', role: 'member' }))
        .status,
    ).toBe(403);
    expect((await post(cy, `/orgs/${orgId}/members/remove`, { user: bob.id })).status).toBe(403);
    // An admin can promote a member to admin.
    expect(
      (await post(bob, `/orgs/${orgId}/members/role`, { user: cy.id, role: 'admin' })).status,
    ).toBe(303);
    expect(await roleOf(orgId, cy.id)).toBe('admin');
    // Nobody changes their own role here.
    expect(
      (await post(ada, `/orgs/${orgId}/members/role`, { user: ada.id, role: 'member' })).status,
    ).toBe(400);

    // The only owner can't leave; after making another owner, they can.
    expect((await post(ada, `/orgs/${orgId}/leave`, { confirm: 'on' })).status).toBe(409);
    expect(
      (await post(ada, `/orgs/${orgId}/members/role`, { user: bob.id, role: 'owner' })).status,
    ).toBe(303);
    expect(
      (await post(ada, `/orgs/${orgId}/leave`, { confirm: 'on' })).headers.get('Location'),
    ).toBe('/account?saved=left');
    expect(await roleOf(orgId, ada.id)).toBeNull();
    // Now bob is the only owner: demoting or removing him is refused by the database itself.
    expect((await post(cy, `/orgs/${orgId}/members/remove`, { user: bob.id })).status).toBe(403);
  });

  it('making an owner needs a recent proof it’s you', async () => {
    const ada = people.ada as Person;
    const bob = people.bob as Person;
    const orgId = await createOrg(ada);
    await join(bob, orgId);
    now += 2 * 60 * 60;
    const later = await post(ada, `/orgs/${orgId}/members/role`, { user: bob.id, role: 'owner' });
    expect(later.status).toBe(303);
    expect(later.headers.get('Location')).toMatch(/^\/login\?reauth=1&return_to=/);
    expect(await roleOf(orgId, bob.id)).toBe('member');
  });
});

describe('deleting', () => {
  it('an organization needs its name typed, and takes its members and invitations with it', async () => {
    const ada = people.ada as Person;
    const orgId = await createOrg(ada);
    await join(people.bob as Person, orgId);
    await invite(ada, orgId, 'later@example.com');
    expect((await get(ada, `/orgs/${orgId}/delete`)).status).toBe(200);
    const wrong = await post(ada, `/orgs/${orgId}/delete`, { name: 'Acme' });
    expect(wrong.status).toBe(400);
    expect(await wrong.text()).toContain('doesn’t match');
    const done = await post(ada, `/orgs/${orgId}/delete`, { name: 'Acme Research' });
    expect(done.headers.get('Location')).toBe('/account?saved=org_deleted');
    expect(await count('organizations')).toBe(0);
    expect(await count('org_members')).toBe(0);
    expect(await count('org_invitations')).toBe(0);
    // No service keeps data for organizations yet, so there is nobody to tell.
    expect(await count('org_deletion_notices')).toBe(0);
  });

  it('an account passes its organizations on: to the longest-standing admin, else deleted', async () => {
    const ada = people.ada as Person;
    const bob = people.bob as Person;
    const cy = people.cy as Person;
    const shared = await createOrg(ada, 'Shared');
    await join(bob, shared);
    now += 10;
    await join(cy, shared, 'admin');
    const alone = await createOrg(ada, 'Alone');

    const page = await (await get(ada, '/account/delete')).text();
    expect(page).toContain('The organization “Alone”, which has no other members');
    expect(page).toContain('Your ownership of “Shared”: Cy Example becomes its owner');

    const oauth = authorizationServer(env).getOAuthApi(env);
    const plan = await deleteAccount(env.DB, oauth, ada.id, now, null);
    expect(plan.passed.map((p) => p.to)).toEqual([cy.id]);
    expect(await roleOf(shared, cy.id)).toBe('owner');
    expect(await roleOf(shared, bob.id)).toBe('member');
    expect(await count('organizations', 'id = ?', alone)).toBe(0);
    expect(
      await count('audit_events', "event = 'org.ownership_passed' AND actor_user_id = ?", cy.id),
    ).toBe(1);
  });
});

describe('for services and apps', () => {
  it('OrganizationDirectory reports active members of active organizations, live', async () => {
    const ada = people.ada as Person;
    const bob = people.bob as Person;
    const orgId = await createOrg(ada);
    await join(bob, orgId);
    expect(await exports.OrganizationDirectory.roleOf(orgId, bob.id)).toBe('member');
    expect(await exports.OrganizationDirectory.membershipsOf(ada.id)).toEqual([
      { orgId, name: 'Acme Research', role: 'owner' },
    ]);
    expect(await exports.OrganizationDirectory.members(orgId)).toHaveLength(2);

    await env.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").bind(bob.id).run();
    expect(await exports.OrganizationDirectory.roleOf(orgId, bob.id)).toBeNull();
    await env.DB.prepare("UPDATE organizations SET status = 'suspended' WHERE id = ?")
      .bind(orgId)
      .run();
    expect(await exports.OrganizationDirectory.membershipsOf(ada.id)).toEqual([]);
    expect(await exports.OrganizationDirectory.members(orgId)).toBeNull();
    // A suspended organization can't be changed, but its members can still leave.
    expect(
      (await post(ada, `/orgs/${orgId}/invitations`, { email: 'x@example.com', role: 'member' }))
        .status,
    ).toBe(403);
    expect(await (await get(ada, `/orgs/${orgId}`)).text()).toContain('suspended by 2earl');
  });

  it('the `organizations` scope releases the orgs claim, nothing without it', async () => {
    const ada = people.ada as Person;
    const orgId = await createOrg(ada);
    expect((await userClaims(env.DB, ada.id, ['openid', 'organizations']))?.orgs).toEqual([
      { id: orgId, name: 'Acme Research', role: 'owner' },
    ]);
    expect((await userClaims(env.DB, ada.id, ['openid', 'profile']))?.orgs).toBeUndefined();
    const meta = await (
      await call(app, '/.well-known/openid-configuration')
    ).json<{
      scopes_supported: string[];
      claims_supported: string[];
    }>();
    expect(meta.scopes_supported).toContain('organizations');
    expect(meta.claims_supported).toContain('orgs');
  });

  it('“Download your data” includes memberships and open invitations sent', async () => {
    const ada = people.ada as Person;
    const orgId = await createOrg(ada);
    await invite(ada, orgId, 'later@example.com', 'admin');
    const data = await (
      await get(ada, '/account/export')
    ).json<{
      organizations: { id: string; role: string }[];
      invitationsSent: { email: string; role: string }[];
    }>();
    expect(data.organizations).toEqual([expect.objectContaining({ id: orgId, role: 'owner' })]);
    expect(data.invitationsSent).toEqual([
      expect.objectContaining({ email: 'later@example.com', role: 'admin' }),
    ]);
  });
});

describe('organization deletion notices', () => {
  it('reach a service that keeps data for organizations, and wait for one that can’t take them', async () => {
    await env.DB.prepare(
      "INSERT INTO org_deletion_notices (service, org_id, created_at) VALUES ('mcp', 'org_gone', ?)",
    )
      .bind(now)
      .run();
    // A service without deleteOrganization: the notice waits.
    const plain = await deliverDeletionNotices(
      envOverride({
        MCP_GATEWAY_EVENTS: {
          deleteUser: () => Promise.resolve(),
          exportUser: () => Promise.resolve(null),
        },
        PROMPTSHARE_EVENTS: undefined,
      }),
      now,
    );
    expect(plain.waiting).toBeGreaterThanOrEqual(1);
    expect(await count('org_deletion_notices')).toBe(1);

    const deleted: string[] = [];
    const result = await deliverDeletionNotices(
      envOverride({
        MCP_GATEWAY_EVENTS: {
          deleteUser: () => Promise.resolve(),
          exportUser: () => Promise.resolve(null),
          deleteOrganization: (id: string) => {
            deleted.push(id);
            return Promise.resolve();
          },
        },
        PROMPTSHARE_EVENTS: undefined,
      }),
      now,
    );
    expect(result.delivered).toBe(1);
    expect(deleted).toEqual(['org_gone']);
    expect(await count('org_deletion_notices')).toBe(0);
  });
});
