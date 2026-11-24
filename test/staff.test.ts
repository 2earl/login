import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { setOAuthClock } from '../src/oauth';
import { totpCode, totpStep } from '../src/totp';
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

/**
 * Phase 11: 2earl staff (DESIGN §4.29) and organizations set up by invitation (§4.30).
 */

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
let now: number;
let sent: Sent[];
const mailer = {
  send: (message: Sent) => {
    sent.push(message);
    return Promise.resolve({ messageId: 'm' });
  },
};

let owner: Person;
let ada: Person;
let bob: Person;

async function person(key: string, invite = true): Promise<Person> {
  const email = `${key}@staff-test.example`;
  if (invite) {
    await env.DB.prepare(
      "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES (?, 'email', ?, 'test', 0)",
    )
      .bind(`al-${key}`, email)
      .run();
  }
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

function get(who: Person, path: string) {
  return call(app, path, { cookies: { '__Host-session': who.session }, ip: freshIp() });
}

function post(who: Person, path: string, body: Record<string, string>) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(body),
    cookies: { '__Host-session': who.session },
    ip: freshIp(),
    vars: { MAILER: mailer },
  });
}

/** Sets up an authenticator app; the session becomes aal2, with a fresh second factor. */
async function giveFactor(who: Person): Promise<void> {
  const page = await (await get(who, '/account/security/totp')).text();
  const secret = (/<code class="secret">([A-Z2-7 ]+)<\/code>/.exec(page)?.[1] ?? '').replace(
    / /g,
    '',
  );
  const response = await post(who, '/account/security/totp', {
    code: await totpCode(secret, totpStep(now)),
  });
  expect(response.status).toBe(303);
  sent = [];
}

const roleOf = async (userId: string) =>
  (
    await env.DB.prepare('SELECT role FROM staff WHERE user_id = ?')
      .bind(userId)
      .first<{ role: string }>()
  )?.role ?? null;

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  await env.DB.prepare('DELETE FROM org_setup_invitations').run();
  sent = [];
  google = new FakeGoogle();
  app = createApp({
    fetch: (input, init) => google.fetch(input, init),
    googleJwks: testJwks,
    now: () => now,
  });
  const signedIn = await signIn(app, google);
  const ownerRow = await env.DB.prepare(
    "SELECT user_id AS id FROM identities WHERE provider = 'google' AND subject = ?",
  )
    .bind(env.OWNER_GOOGLE_SUB)
    .first<{ id: string }>();
  owner = { id: ownerRow?.id ?? '', session: signedIn.session ?? '', email: '' };
  ada = await person('ada');
  bob = await person('bob');
});

describe('creating organizations', () => {
  it('is closed to accounts that aren’t 2earl’s owner or admins', async () => {
    const page = await get(ada, '/orgs/new');
    expect(page.status).toBe(403);
    expect(await page.text()).toContain('Organizations are set up by invitation');
    const created = await post(ada, '/orgs', { name: 'Example Inc' });
    expect(created.status).toBe(403);
    expect(await count('organizations')).toBe(0);
    const list = await (await get(ada, '/account/orgs')).text();
    expect(list).not.toContain('href="/orgs/new"');
  });

  it('is open to the owner and admins, not to support', async () => {
    expect((await get(owner, '/orgs/new')).status).toBe(200);
    await env.DB.prepare(
      "INSERT INTO staff (user_id, role, granted_by, granted_at) VALUES (?, 'support', NULL, 0), (?, 'admin', NULL, 0)",
    )
      .bind(ada.id, bob.id)
      .run();
    expect((await get(ada, '/orgs/new')).status).toBe(403);
    expect((await get(bob, '/orgs/new')).status).toBe(200);
    expect(await (await get(bob, '/account/orgs')).text()).toContain('href="/orgs/new"');
    expect((await post(bob, '/orgs', { name: 'Example Inc' })).status).toBe(303);
  });
});

describe('staff roles', () => {
  it('are given and taken by the owner only, and the person is told', async () => {
    await giveFactor(owner);
    const granted = await post(owner, '/admin/team', {
      action: 'grant',
      email: ada.email,
      role: 'support',
    });
    expect(granted.headers.get('Location')).toBe('/admin/team?done=staff_granted');
    expect(await roleOf(ada.id)).toBe('support');
    expect(sent.map((m) => [m.to, m.subject])).toEqual([
      [ada.email, 'You’re now support at 2earl'],
    ]);

    const promoted = await post(owner, '/admin/team', {
      action: 'grant_user',
      user: ada.id,
      role: 'admin',
    });
    expect(promoted.status).toBe(303);
    expect(await roleOf(ada.id)).toBe('admin');

    // An admin can't open the staff page or change roles.
    await giveFactor(ada);
    expect((await get(ada, '/admin/team')).status).toBe(404);
    const refused = await post(ada, '/admin/team', {
      action: 'grant',
      email: bob.email,
      role: 'admin',
    });
    expect(refused.status).toBe(404);
    expect(await roleOf(bob.id)).toBeNull();

    sent = [];
    const revoked = await post(owner, '/admin/team', { action: 'revoke', user: ada.id });
    expect(revoked.headers.get('Location')).toBe('/admin/team?done=staff_revoked');
    expect(await roleOf(ada.id)).toBeNull();
    expect(sent[0]?.to).toBe(ada.email);
    expect((await get(ada, '/admin/users')).status).toBe(404);
    expect(
      await count('audit_events', "event IN ('admin.staff_granted', 'admin.staff_revoked')"),
    ).toBe(3);
  });

  it('can’t be given to an unknown address, the owner, or a managed account', async () => {
    await giveFactor(owner);
    const unknown = await post(owner, '/admin/team', {
      action: 'grant',
      email: 'nobody@staff-test.example',
      role: 'admin',
    });
    expect(unknown.status).toBe(404);
    expect(await unknown.text()).toContain('No 2earl account signs in with that address');
    const self = await post(owner, '/admin/team', {
      action: 'grant_user',
      user: owner.id,
      role: 'admin',
    });
    expect(self.status).toBe(404);
    expect(await count('staff')).toBe(0);
  });

  it('shows support only what support may do', async () => {
    await env.DB.prepare(
      "INSERT INTO staff (user_id, role, granted_by, granted_at) VALUES (?, 'support', NULL, 0)",
    )
      .bind(ada.id)
      .run();
    // No second factor yet: the admin pages ask for one.
    expect((await get(ada, '/admin/users')).status).toBe(403);
    await giveFactor(ada);

    const users = await (await get(ada, '/admin/users')).text();
    expect(users).toContain('Sign out everywhere');
    expect(users).not.toContain('value="suspend"');
    expect(users).not.toContain('href="/admin/apps"');
    expect(users).not.toContain('href="/admin/team"');
    for (const path of ['/admin/apps', '/admin/invitations', '/admin/team']) {
      expect((await get(ada, path)).status, path).toBe(404);
    }
    for (const path of ['/admin/users', '/admin/orgs', '/admin/log']) {
      expect((await get(ada, path)).status, path).toBe(200);
    }

    // Support can't suspend, but can sign someone out everywhere; they are told by email.
    const suspend = await post(ada, '/admin/users', { action: 'suspend', user: bob.id });
    expect(suspend.status).toBe(400);
    expect(await count('users', "id = ? AND status = 'active'", bob.id)).toBe(1);
    const signedOut = await post(ada, '/admin/users', { action: 'sign_out', user: bob.id });
    expect(signedOut.headers.get('Location')).toBe('/admin/users?done=signed_out');
    expect(await count('sessions', 'user_id = ?', bob.id)).toBe(0);
    expect(sent.map((m) => [m.to, m.subject])).toEqual([
      [bob.email, 'You were signed out of 2earl everywhere'],
    ]);

    // Nor act on the owner.
    const onOwner = await post(ada, '/admin/users', { action: 'sign_out', user: owner.id });
    expect(onOwner.status).toBe(400);
    expect(await count('sessions', 'user_id = ?', owner.id)).toBeGreaterThan(0);
  });

  it('lets an admin manage users, but not other staff', async () => {
    await env.DB.prepare(
      "INSERT INTO staff (user_id, role, granted_by, granted_at) VALUES (?, 'admin', NULL, 0), (?, 'support', NULL, 0)",
    )
      .bind(ada.id, bob.id)
      .run();
    await giveFactor(ada);
    const onStaff = await post(ada, '/admin/users', { action: 'suspend', user: bob.id });
    expect(onStaff.status).toBe(400);
    expect(await onStaff.text()).toContain('Staff accounts are managed by the owner');
    await env.DB.prepare('DELETE FROM staff WHERE user_id = ?').bind(bob.id).run();
    const suspended = await post(ada, '/admin/users', { action: 'suspend', user: bob.id });
    expect(suspended.headers.get('Location')).toBe('/admin/users?done=suspended');
  });

  it('finds users by address or name', async () => {
    await giveFactor(owner);
    const found = await (await get(owner, '/admin/users?q=BOB')).text();
    expect(found).toContain(bob.email);
    expect(found).not.toContain(ada.email);
    expect(found).toContain('1 account found');
  });
});

describe('organizations set up by invitation', () => {
  const invite = async (email: string, name = 'Example Inc') => {
    const response = await post(owner, '/admin/orgs', { action: 'setup_invite', email, name });
    return response;
  };
  const invitationId = async () =>
    (
      await env.DB.prepare('SELECT id FROM org_setup_invitations ORDER BY created_at DESC').first<{
        id: string;
      }>()
    )?.id ?? '';

  it('emails a link; the invited person signs up, names it and becomes its owner', async () => {
    await giveFactor(owner);
    const response = await invite('carol@staff-test.example');
    expect(response.headers.get('Location')).toBe('/admin/orgs?done=setup_sent');
    const id = await invitationId();
    expect(id).toMatch(/^osi_/);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.to).toBe('carol@staff-test.example');
    expect(sent[0]?.subject).toBe('Set up “Example Inc” on 2earl');
    expect(sent[0]?.text).toContain(`/orgs/setup/${id}`);

    // Carol wasn't invited to sign up: the setup invitation lets her in.
    const carol = await person('carol', false);
    expect(carol.id).not.toBe('');
    const list = await (await get(carol, '/account/orgs')).text();
    expect(list).toContain(`/orgs/setup/${id}`);

    const page = await get(carol, `/orgs/setup/${id}`);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('value="Example Inc"');

    const done = await post(carol, `/orgs/setup/${id}`, { name: 'Carol’s Company' });
    expect(done.status).toBe(303);
    const orgId = /^\/orgs\/(org_[A-Za-z0-9_-]+)\?done=created$/.exec(
      done.headers.get('Location') ?? '',
    )?.[1];
    expect(orgId).toBeTruthy();
    expect(
      await count('org_members', "org_id = ? AND user_id = ? AND role = 'owner'", orgId, carol.id),
    ).toBe(1);
    expect(await count('organizations', 'name = ?', 'Carol’s Company')).toBe(1);

    // Used once: a second try goes to the organization, a stranger is told it's gone.
    const again = await get(carol, `/orgs/setup/${id}`);
    expect(again.headers.get('Location')).toBe(`/orgs/${orgId ?? ''}`);
    expect((await get(bob, `/orgs/setup/${id}`)).status).toBe(410);
    expect((await post(carol, `/orgs/setup/${id}`, { name: 'Twice' })).status).toBe(410);
    expect(await count('organizations')).toBe(1);

    // The owner adds an admin, who helps run it.
    const invited = await post(carol, `/orgs/${orgId ?? ''}/invitations`, {
      email: bob.email,
      role: 'admin',
    });
    expect(invited.status).toBe(303);

    // The admin page links the set-up organization.
    const admin = await (await get(owner, '/admin/orgs')).text();
    expect(admin).toContain(`/admin/orgs/${orgId ?? ''}`);
  });

  it('works only for an account that signs in with the invited address', async () => {
    await giveFactor(owner);
    await invite(ada.email);
    const id = await invitationId();
    const wrong = await get(bob, `/orgs/setup/${id}`);
    expect(wrong.status).toBe(403);
    expect(await wrong.text()).toContain('doesn’t sign in with');
    expect((await post(bob, `/orgs/setup/${id}`, { name: 'Stolen' })).status).toBe(403);
    expect(await count('organizations')).toBe(0);
    expect((await post(ada, `/orgs/setup/${id}`, { name: 'Ada Ltd' })).status).toBe(303);
  });

  it('is sent by admins, sent again by support, and withdrawn by admins', async () => {
    await env.DB.prepare(
      "INSERT INTO staff (user_id, role, granted_by, granted_at) VALUES (?, 'admin', NULL, 0), (?, 'support', NULL, 0)",
    )
      .bind(ada.id, bob.id)
      .run();
    await giveFactor(ada);
    await giveFactor(bob);

    // Support can't send a new one.
    const bySupport = await post(bob, '/admin/orgs', {
      action: 'setup_invite',
      email: 'dan@staff-test.example',
    });
    expect(bySupport.status).toBe(400);
    expect(await count('org_setup_invitations')).toBe(0);

    expect(
      (await post(ada, '/admin/orgs', { action: 'setup_invite', email: 'dan@staff-test.example' }))
        .status,
    ).toBe(303);
    const id = await invitationId();
    // One waiting invitation per address.
    const duplicate = await post(ada, '/admin/orgs', {
      action: 'setup_invite',
      email: 'DAN@staff-test.example',
    });
    expect(duplicate.status).toBe(409);

    sent = [];
    // Sent again at most every 10 minutes.
    expect(
      (await post(bob, '/admin/orgs', { action: 'setup_resend', invitation: id })).status,
    ).toBe(429);
    now += 11 * 60;
    const resent = await post(bob, '/admin/orgs', { action: 'setup_resend', invitation: id });
    expect(resent.headers.get('Location')).toBe('/admin/orgs?done=setup_resent');
    expect(sent.map((m) => m.to)).toEqual(['dan@staff-test.example']);

    // Support can't withdraw it; an admin can, and the address can no longer sign up.
    const notWithdrawn = await post(bob, '/admin/orgs', {
      action: 'setup_withdraw',
      invitation: id,
    });
    expect(notWithdrawn.status).toBe(400);
    expect(await count('org_setup_invitations')).toBe(1);
    const withdrawn = await post(ada, '/admin/orgs', { action: 'setup_withdraw', invitation: id });
    expect(withdrawn.headers.get('Location')).toBe('/admin/orgs?done=setup_withdrawn');
    expect(await count('org_setup_invitations')).toBe(0);
    expect(await count('allowlist', 'value = ?', 'dan@staff-test.example')).toBe(0);
  });
});

describe('the organization’s view of staff', () => {
  it('shows staff opening it as “2earl”, without who or from where', async () => {
    await makeOrgOwnedBy(ada);
    await giveFactor(owner);
    const orgId = (await env.DB.prepare('SELECT id FROM organizations').first<{ id: string }>())
      ?.id;
    const detail = await get(owner, `/admin/orgs/${orgId ?? ''}`);
    expect(detail.status).toBe(200);
    expect(await detail.text()).toContain(ada.email);
    // Opened twice within the hour: recorded once.
    await get(owner, `/admin/orgs/${orgId ?? ''}`);
    expect(await count('audit_events', "event = 'admin.org_viewed'")).toBe(1);

    const activity = await (await get(ada, `/orgs/${orgId ?? ''}/activity`)).text();
    expect(activity).toContain('<strong>2earl</strong> <span>staff opened the organization');
    const exported = await get(ada, `/orgs/${orgId ?? ''}/activity/export?days=7&format=json`);
    const { events: records } = await exported.json<{
      events: {
        event: string;
        actor: { id: string; email: string | null } | null;
        ip_prefix: string | null;
      }[];
    }>();
    const viewed = records.find((r) => r.event === 'admin.org_viewed');
    expect(viewed?.actor).toEqual({ id: '2earl', email: null });
    expect(viewed?.ip_prefix).toBeNull();
  });
});

async function makeOrgOwnedBy(who: Person): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO staff (user_id, role, granted_by, granted_at) VALUES (?, 'admin', NULL, 0)",
  )
    .bind(who.id)
    .run();
  const created = await post(who, '/orgs', { name: 'Example Inc' });
  expect(created.status).toBe(303);
  await env.DB.prepare('DELETE FROM staff WHERE user_id = ?').bind(who.id).run();
}
