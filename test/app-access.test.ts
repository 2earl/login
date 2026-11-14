import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { pkceChallenge, randomToken } from '../src/crypto';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  consentBody,
  parseConsent,
  setCookies,
  count,
  freshIp,
  resetDatabase,
  signIn,
  testJwks,
} from './helpers';

/** Phase 10e (DESIGN §4.22): which apps managed accounts may use. */

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

const REDIRECT_URI = 'https://client.example/callback';
const RESOURCE = env.MCP_RESOURCE;

let ada: Person;
let bob: Person;
let orgId: string;
let clientId: string;
let token: string;

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
  const page = await (await post(ada, `/orgs/${orgId}/scim-tokens`)).text();
  token = /<code class="secret">(scim_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '';
  const client = await authorizationServer(env)
    .getOAuthApi(env)
    .createClient({
      redirectUris: [REDIRECT_URI],
      clientName: 'Test MCP Client',
      tokenEndpointAuthMethod: 'none',
    });
  clientId = client.clientId;
});

function apps(fields: Record<string, string>) {
  return post(ada, `/orgs/${orgId}/apps`, fields);
}

function scim(path: string, method: string, body: unknown) {
  return call(app, `/scim/v2${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/scim+json' },
    body: JSON.stringify(body),
  });
}

/** authorize → consent → token for `who`; the authorize response if it stops there. */
async function connect(who: Person): Promise<{ authorize: Response; refreshToken?: string }> {
  const verifier = randomToken(48);
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'mcp:tools.read',
    state: 's',
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    resource: RESOURCE,
  });
  const authorize = await call(app, `/authorize?${query.toString()}`, {
    cookies: { '__Host-session': who.session },
  });
  if (authorize.status !== 200) return { authorize };
  const handle = parseConsent(await authorize.clone().text());
  const body = consentBody(handle, { decision: 'approve' });
  body.append('scope', 'mcp:tools.read');
  const approved = await call(app, '/authorize', {
    method: 'POST',
    headers: FORM,
    body,
    cookies: { '__Host-session': who.session, ...setCookies(authorize) },
  });
  const code = new URL(approved.headers.get('Location') ?? 'about:blank').searchParams.get('code');
  const exchanged = await call(app, '/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code ?? '',
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
      resource: RESOURCE,
    }),
  });
  const tokens = await exchanged.json<{ refresh_token?: string }>();
  return { authorize, ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}) };
}

function refresh(refreshToken: string) {
  return call(app, '/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    }),
  });
}

describe('app access', () => {
  it('lets managed accounts use any app until the organization restricts them', async () => {
    const { refreshToken } = await connect(bob);
    expect(refreshToken).toBeTruthy();
    // The app shows up as in use, ready to allow.
    const page = await (await get(ada, `/orgs/${orgId}/directory`)).text();
    expect(page).toContain('Test MCP Client');

    await apps({ action: 'restrict', on: '1' });
    // Owners too: nothing is allowed yet.
    for (const who of [bob, ada]) {
      const { authorize } = await connect(who);
      expect(authorize.status).toBe(403);
      expect(await authorize.text()).toContain('allows only some apps');
    }
    // The app Bob connected before loses access at its next refresh.
    const refused = await refresh(refreshToken ?? '');
    expect(refused.status).toBe(400);
    expect(await count('audit_events', "event = 'grant.refused'")).toBe(1);
  });

  it('allows an app for everyone, or for a directory group', async () => {
    await apps({ action: 'restrict', on: '1' });
    expect((await apps({ action: 'allow', client_id: 'no-such-app' })).status).toBe(400);

    await apps({ action: 'allow', client_id: clientId });
    expect((await connect(bob)).refreshToken).toBeTruthy();

    // Now only for a group Bob isn't in.
    await apps({ action: 'remove', client_id: clientId, group: '' });
    const provisioned = await (
      await scim('/Users', 'POST', {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'bob@example.com',
        active: true,
      })
    ).json<{ id: string }>();
    const group = await (
      await scim('/Groups', 'POST', {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        displayName: 'Engineering',
        members: [],
      })
    ).json<{ id: string }>();
    await apps({ action: 'allow', client_id: clientId, group: group.id });
    expect((await connect(bob)).authorize.status).toBe(403);
    // The directory puts Bob in the group: now he may.
    await scim(`/Groups/${group.id}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'add', path: 'members', value: [{ value: provisioned.id }] }],
    });
    expect((await connect(bob)).refreshToken).toBeTruthy();
  });

  it('is for owners, and never reaches accounts the organization doesn’t manage', async () => {
    const carol = await person('carol', 'elsewhere.example');
    await env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'admin', 0)",
    )
      .bind(orgId, carol.id)
      .run();
    expect((await post(carol, `/orgs/${orgId}/apps`, { action: 'restrict', on: '1' })).status).toBe(
      404,
    );
    await apps({ action: 'restrict', on: '1' });
    expect((await connect(carol)).refreshToken).toBeTruthy();
  });
});
