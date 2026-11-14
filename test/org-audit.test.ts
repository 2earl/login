import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { setOAuthClock } from '../src/oauth';
import { deliverStreams } from '../src/org-audit';
import { hmacHex } from '../src/crypto';
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

/** Phase 10f (DESIGN §4.23): the organization's audit log, downloaded and streamed. */

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

describe('the audit log', () => {
  it('shows the organization’s events and its managed accounts’ sign-ins, not others’', async () => {
    const carol = await person('carol', 'elsewhere.example');
    await env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'member', 0)",
    )
      .bind(orgId, carol.id)
      .run();
    // Bob (managed) and Carol (not) sign in again.
    now += 60;
    await signIn(app, google, {
      claims: { sub: 'sub-bob', email: 'bob@example.com', name: 'bob' },
    });
    await signIn(app, google, {
      claims: { sub: 'sub-carol', email: 'carol@elsewhere.example', name: 'carol' },
    });
    now += 60;
    const json = await (
      await get(ada, `/orgs/${orgId}/activity/export?days=7&format=json`)
    ).json<{ events: { event: string; actor: { id: string; email: string | null } | null }[] }>();
    const signIns = json.events.filter((e) => e.event === 'login.succeeded');
    expect(signIns.some((e) => e.actor?.id === bob.id && e.actor.email === 'bob@example.com')).toBe(
      true,
    );
    expect(signIns.some((e) => e.actor?.id === carol.id)).toBe(false);
    expect(json.events.some((e) => e.event === 'org.domain_managed')).toBe(true);

    const page = await (await get(ada, `/orgs/${orgId}/activity`)).text();
    expect(page).toContain('signed in with Google');
  });

  it('downloads as CSV for owners and admins, safe to open in a spreadsheet', async () => {
    await env.DB.prepare(
      `INSERT INTO audit_events (id, at, event, actor_user_id, detail)
       VALUES ('ev-x', ?, 'org.renamed', ?, json_object('org', ?, 'note', '=HYPERLINK("x")'))`,
    )
      .bind(now, ada.id, orgId)
      .run();
    now += 10;
    const csv = await get(ada, `/orgs/${orgId}/activity/export?days=30`);
    expect(csv.headers.get('Content-Type')).toContain('text/csv');
    expect(csv.headers.get('Content-Disposition')).toContain('attachment');
    const text = await csv.text();
    expect(text.split('\r\n')[0]).toBe(
      'time,event,actor_id,actor_email,target_id,target_email,client_id,ip_prefix,detail',
    );
    expect(text).toContain('org.renamed');
    expect(await count('audit_events', "event = 'org.audit_exported'")).toBe(1);
    // Bob is a member, not an admin: no log.
    expect((await get(bob, `/orgs/${orgId}/activity/export`)).status).toBe(404);
    await env.DB.prepare("UPDATE org_members SET role = 'admin' WHERE user_id = ?")
      .bind(bob.id)
      .run();
    expect((await get(bob, `/orgs/${orgId}/activity/export`)).status).toBe(200);
  });
});

describe('the audit stream', () => {
  let received: { body: string; signature: string | null }[];
  let answer: number;
  const receiver: typeof fetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.hostname !== 'siem.example.org')
      return Promise.resolve(new Response('no', { status: 404 }));
    const headers = new Headers(init?.headers);
    received.push({
      body: typeof init?.body === 'string' ? init.body : '',
      signature: headers.get('X-2earl-Signature'),
    });
    return Promise.resolve(new Response(null, { status: answer }));
  };

  beforeEach(() => {
    received = [];
    answer = 204;
  });

  async function create(): Promise<string> {
    const page = await (
      await post(ada, `/orgs/${orgId}/activity/stream`, {
        url: 'https://siem.example.org/2earl',
        enabled: 'on',
        action: 'save',
      })
    ).text();
    return /<code class="secret">(whsec_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '';
  }

  it('sends new events, signed, once each, and retries until accepted', async () => {
    const secret = await create();
    expect(secret).toMatch(/^whsec_/);
    expect(await count('org_audit_streams', 'secret_enc LIKE ?', '%whsec%')).toBe(0);

    now += 60;
    await post(ada, `/orgs/${orgId}/name`, { name: 'Example Research' });
    now += 60;

    // The endpoint fails: nothing is lost.
    answer = 500;
    await deliverStreams(env, receiver, now);
    expect(received).toHaveLength(1);
    answer = 204;
    // Backing off: not before a minute has passed.
    await deliverStreams(env, receiver, now + 10);
    expect(received).toHaveLength(1);
    await deliverStreams(env, receiver, now + 61);
    expect(received).toHaveLength(2);

    const delivery = received[1];
    const body = JSON.parse(delivery?.body ?? '{}') as { events: { event: string }[] };
    expect(body.events.map((e) => e.event)).toContain('org.renamed');
    const [t, v1] = (delivery?.signature ?? '').split(',');
    const timestamp = t?.slice(2) ?? '';
    expect(v1).toBe(`v1=${await hmacHex(secret, `${timestamp}.${delivery?.body ?? ''}`)}`);

    // Nothing new: nothing sent.
    await deliverStreams(env, receiver, now + 200);
    expect(received).toHaveLength(2);
  });

  it('is for owners only, and can be removed', async () => {
    await env.DB.prepare("UPDATE org_members SET role = 'admin' WHERE user_id = ?")
      .bind(bob.id)
      .run();
    const byAdmin = await post(bob, `/orgs/${orgId}/activity/stream`, {
      url: 'https://siem.example.org/2earl',
      action: 'save',
    });
    expect(byAdmin.status).toBe(404);
    await create();
    await post(ada, `/orgs/${orgId}/activity/stream`, { action: 'delete' });
    expect(await count('org_audit_streams')).toBe(0);
    expect(
      (
        await post(ada, `/orgs/${orgId}/activity/stream`, {
          url: 'http://siem.example.org/plain',
          action: 'save',
        })
      ).status,
    ).toBe(400);
  });
});
