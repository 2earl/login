import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { alertFor, alertOwners } from '../src/org-alerts';
import { setOAuthClock } from '../src/oauth';
import { CERT } from './certs';
import { FakeGoogle, NOW, ORIGIN, call, freshIp, resetDatabase, signIn, testJwks } from './helpers';

/** Phase 10j (DESIGN §4.27): security changes are emailed to every owner. */

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
  const created = await post(ada, '/orgs', { name: 'Example Inc' });
  orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'owner', 0)",
    ).bind(orgId, carol.id),
    env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'member', 0)",
    ).bind(orgId, bob.id),
  ]);
  sent = [];
});

describe('changes that decide who can get in', () => {
  it('are emailed to every owner, the one who made them too', async () => {
    await env.DB.prepare(
      "INSERT INTO org_domains (org_id, domain, challenge, verified_at, created_at) VALUES (?, 'example.com', 'c', 1, 0)",
    )
      .bind(orgId)
      .run();
    const saved = await post(ada, `/orgs/${orgId}/saml`, {
      idp_entity_id: 'https://idp.example.com/entity',
      sso_url: 'https://idp.example.com/sso',
      certificate: CERT,
      enabled: 'on',
    });
    expect(saved.status).toBe(303);
    expect(sent.map((m) => m.to).sort()).toEqual([ada.email, carol.email]);
    const mail = sent[0];
    expect(mail?.subject).toBe('Security change in “Example Inc”');
    expect(mail?.text).toContain('Ada (ada@example.com) changed the SAML single sign-on settings');
    expect(mail?.text).toContain(`/orgs/${orgId}/activity`);
    expect(mail?.text).toContain('When');
  });

  it('name the person given rights', async () => {
    await post(ada, `/orgs/${orgId}/members/role`, { user: bob.id, role: 'admin' });
    expect(sent).toHaveLength(2);
    expect(sent[0]?.text).toContain('made Bob (bob@example.com) an admin');
    sent = [];
    await post(ada, `/orgs/${orgId}/members/role`, { user: bob.id, role: 'member' });
    expect(sent[0]?.text).toContain('changed Bob (bob@example.com) from admin to member');
  });

  it('include keys and what they did', async () => {
    const page = await (
      await post(ada, `/orgs/${orgId}/api-keys`, {
        action: 'create',
        name: 'Script',
        access: 'write',
      })
    ).text();
    expect(sent[0]?.text).toContain('created an API key “Script” with read and write access');
    const key = /<code class="secret">(2earl_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '';
    sent = [];
    const response = await call(app, `/api/v1/members/${bob.id}/role`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'admin' }),
      ip: freshIp(),
      vars: { MAILER: mailer },
    });
    expect(response.status).toBe(200);
    expect(sent[0]?.text).toContain('The API key “Script” made Bob (bob@example.com) an admin');
  });
});

describe('everyday changes', () => {
  it('aren’t emailed', async () => {
    expect((await post(ada, `/orgs/${orgId}/name`, { name: 'Example GmbH' })).status).toBe(303);
    await post(ada, `/orgs/${orgId}/invitations`, { email: 'dave@example.com', role: 'member' });
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'org.renamed'",
      ).first('n'),
    ).toBe(1);
    expect(sent.filter((m) => m.subject.startsWith('Security change'))).toHaveLength(0);
  });

  it('only the risky direction alerts', () => {
    expect(alertFor('org.require_sso_changed', { on: true })).toBeNull();
    expect(alertFor('org.require_sso_changed', { on: false })).toContain('stopped requiring');
    expect(alertFor('org.group_role_changed', { role: null, name: 'Staff' })).toBeNull();
    expect(alertFor('org.group_role_changed', { role: 'admin', name: 'IT' })).toContain(
      '“IT” admins',
    );
    expect(alertFor('org.renamed', {})).toBeNull();
  });
});

it('changes 2earl makes on its own come from 2earl', async () => {
  const told = await alertOwners(
    { ...env, MAILER: mailer } as unknown as Env,
    orgId,
    'org.saml_metadata_refreshed',
    {},
    { system: true },
  );
  expect(told).toBe(2);
  expect(sent[0]?.text).toContain('2earl took new SAML signing certificates');
});
