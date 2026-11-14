import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { setRequireSso } from '../src/managed';
import { setOAuthClock } from '../src/oauth';
import { certificateExpiry } from '../src/saml';
import { dateField, samlExpiry, warnExpiringSso, warningDue } from '../src/sso-upkeep';
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

/** Phase 10h (DESIGN §4.25): single sign-on that keeps working. */

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};
const IDP = 'https://idp.example.com';

/** A self-signed test certificate (public part only); it expires 2027-12-19 12:13:39 UTC. */
const CERT = `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUJkhCy0vdWuNEP0N32JNZEKy7L2EwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPaWRwLmV4YW1wbGUuY29tMB4XDTI2MTExNDEyMTMzOVoX
DTI3MTIxOTEyMTMzOVowGjEYMBYGA1UEAwwPaWRwLmV4YW1wbGUuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv6MKmA6Jp9RQFo6VbLVY99S2kasu
jvu4kXNMXAcilJNQE1KGcqpKE5bryT8xIezBUwZtnpqGXQT1HwBi51563xM0uzg/
Sk/X3FSizzEIUcYI5LjAJyV0DXBnphV/inYm9x26lEbmW3yeNXJGg/NccQPc8eSs
xWN1ParYJquq8Tywawm9T2lWrHvsOBSBHYXD32HK0QVLnYHGbkfTm4ikYJMqgoCr
bsN02XGaePv/bX6KGH/4LL0lV67YnL+sgc3O9pey6lH4O2NCnVVwq7ucSfocFGHi
jQE5VpSBoNJOHKxtuDTXT59lpfw1xm1RPix782fM6odMaijrEFBkH1ENtwIDAQAB
o1MwUTAdBgNVHQ4EFgQUz14pURbQmT80OrbIIhFxAz4645IwHwYDVR0jBBgwFoAU
z14pURbQmT80OrbIIhFxAz4645IwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAqinQfzDqKOWpoBZ3lPUy52eC3VqpAXxULGT8x3boh0CDh1P3GiqT
OyrD1S2/2O4vfokZIFlWm/oqKFyVXEvdywq7YCG61lqHDRBLYAy0CjmD0gzLLP4i
7JgqKI6qpLJra9gDuzZQsMS86Tq6wR/QgvBH3kwdz6lkBpNRsrd6DbtW6FPe82RS
4D0xVW8/3GWJPzDkbbzg3LFwq9UicMOVFXFOVcmycc5LQYhc+PQ1Rn2UEch8fGZ1
YDEG5mm3OMlicFpFtvYlDMjhWFoO42qRV67uuR4dkKMSEsYs9vGiTL2nX+quDXV7
4yOM383Xxzex6u5eyaJ62UMTV6K5aASm5A==
-----END CERTIFICATE-----`;
const CERT_EXPIRES = Date.parse('2027-12-19T12:13:39Z') / 1000;
const DAY = 86_400;

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
let dns: Record<string, string[]>;
let sent: Sent[];
const mailer = {
  send: (message: Sent) => {
    sent.push(message);
    return Promise.resolve({ messageId: 'm' });
  },
};

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
  if (url.origin === IDP && url.pathname === '/.well-known/openid-configuration') {
    return Promise.resolve(
      Response.json({
        issuer: IDP,
        authorization_endpoint: `${IDP}/authorize`,
        token_endpoint: `${IDP}/token`,
        jwks_uri: `${IDP}/jwks`,
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

function post(who: Person | null, path: string, body: Record<string, string> = {}) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(body),
    ...(who ? { cookies: { '__Host-session': who.session } } : {}),
    ip: freshIp(),
    vars: { MAILER: mailer },
  });
}

let ada: Person;
let bob: Person;
let orgId: string;

beforeEach(async () => {
  now = NOW;
  setOAuthClock(() => now);
  await resetDatabase();
  dns = {};
  sent = [];
  google = new FakeGoogle();
  app = createApp({ fetch: fetcher, googleJwks: testJwks, now: () => now });
  ada = await person('ada');
  bob = await person('bob');
  const created = await post(ada, '/orgs', { name: 'Example Inc' });
  orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  await post(ada, `/orgs/${orgId}/domains`, { domain: 'example.com' });
  const row = await env.DB.prepare('SELECT challenge FROM org_domains WHERE org_id = ?')
    .bind(orgId)
    .first<{ challenge: string }>();
  dns['_2earl-challenge.example.com'] = [row?.challenge ?? ''];
  await post(ada, `/orgs/${orgId}/domains/verify`, { domain: 'example.com' });
});

const saveSaml = (fields: Record<string, string> = {}) =>
  post(ada, `/orgs/${orgId}/saml`, {
    idp_entity_id: `${IDP}/metadata`,
    sso_url: `${IDP}/sso`,
    certificate: CERT,
    enabled: 'on',
    ...fields,
  });

const saveOidc = (fields: Record<string, string> = {}) =>
  post(ada, `/orgs/${orgId}/oidc`, {
    issuer: IDP,
    client_id: 'client-1',
    client_secret: 'secret-1',
    enabled: 'on',
    ...fields,
  });

describe('signing in from the provider’s app dashboard', () => {
  it('starts SAML from login’s own request, keeping only targets on login', async () => {
    expect((await call(app, `/sso/${orgId}/start`)).status).toBe(404);
    await saveSaml();
    const started = await call(
      app,
      `/sso/${orgId}/start?target_link_uri=${encodeURIComponent(`${ORIGIN}/account/apps`)}`,
      {
        ip: freshIp(),
      },
    );
    expect(started.status).toBe(302);
    const location = new URL(started.headers.get('Location') ?? '');
    expect(location.origin + location.pathname).toBe(`${IDP}/sso`);
    expect(location.searchParams.get('RelayState')).toBeTruthy();
    expect(await count('saml_states', "return_to = '/account/apps'")).toBe(1);
    // Somewhere else: not followed.
    await call(
      app,
      `/sso/${orgId}/start?target_link_uri=${encodeURIComponent('https://evil.example/x')}`,
      {
        ip: freshIp(),
      },
    );
    expect(await count('saml_states', 'return_to IS NULL')).toBe(1);
  });

  it('starts OpenID Connect with the hint, and only for the organization’s own issuer', async () => {
    await saveOidc();
    const started = await call(
      app,
      `/sso/${orgId}/start?iss=${encodeURIComponent(IDP)}&login_hint=${encodeURIComponent('Bob@Example.com')}`,
      { ip: freshIp() },
    );
    expect(started.status).toBe(302);
    const location = new URL(started.headers.get('Location') ?? '');
    expect(location.origin + location.pathname).toBe(`${IDP}/authorize`);
    expect(location.searchParams.get('login_hint')).toBe('bob@example.com');
    const other = await call(
      app,
      `/sso/${orgId}/start?iss=${encodeURIComponent('https://elsewhere.example')}`,
      { ip: freshIp() },
    );
    expect(other.status).toBe(400);
    // Without a hint, the provider asks.
    const plain = await call(app, `/sso/${orgId}/start`, { ip: freshIp() });
    expect(new URL(plain.headers.get('Location') ?? '').searchParams.has('login_hint')).toBe(false);
  });

  it('shows the link to owners', async () => {
    const page = await (
      await call(app, `/orgs/${orgId}/directory`, { cookies: { '__Host-session': ada.session } })
    ).text();
    expect(page).toContain(`${ORIGIN}/sso/${orgId}/start`);
  });
});

describe('certificates and secrets that expire', () => {
  it('reads expiry from certificates, not from public keys, and parses dates strictly', () => {
    expect(certificateExpiry(CERT)).toBe(CERT_EXPIRES);
    expect(
      certificateExpiry('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----'),
    ).toBeNull();
    expect(dateField('2027-03-01')).toBe(Date.UTC(2027, 2, 1) / 1000);
    expect(dateField('2027-02-31')).toBeNull();
    expect(dateField('tomorrow')).toBeNull();
    expect(samlExpiry(100, 200, true)).toBe(200);
    expect(samlExpiry(100, null, true)).toBeNull();
    expect(samlExpiry(100, null, false)).toBe(100);
    expect(warningDue(1000 + 31 * DAY, 1000)).toBeNull();
    expect(warningDue(1000 + 20 * DAY, 1000)).toBe(30);
    expect(warningDue(1000 + 5 * DAY, 1000)).toBe(7);
    expect(warningDue(1000 + DAY, 1000)).toBe(1);
    expect(warningDue(1000, 1000)).toBe(0);
  });

  it('stores the next certificate and both expiries, and refuses a broken one', async () => {
    expect((await saveSaml({ certificate_next: 'not a certificate' })).status).toBe(400);
    const saved = await saveSaml({ certificate_next: CERT });
    expect(saved.status).toBe(303);
    const row = await env.DB.prepare(
      'SELECT certificate_next, certificate_expires_at, certificate_next_expires_at FROM org_saml WHERE org_id = ?',
    )
      .bind(orgId)
      .first<{
        certificate_next: string;
        certificate_expires_at: number;
        certificate_next_expires_at: number;
      }>();
    expect(row?.certificate_next).toContain('BEGIN CERTIFICATE');
    expect(row?.certificate_expires_at).toBe(CERT_EXPIRES);
    expect(row?.certificate_next_expires_at).toBe(CERT_EXPIRES);
    const page = await (
      await call(app, `/orgs/${orgId}/directory`, { cookies: { '__Host-session': ada.session } })
    ).text();
    expect(page).toContain('Expires 19 December 2027');
  });

  it('tells owners once per threshold, and again after they save', async () => {
    await saveSaml();
    const mailEnv = { ...env, MAILER: mailer } as unknown as Env;
    sent = [];
    expect(await warnExpiringSso(mailEnv, CERT_EXPIRES - 40 * DAY)).toBe(0);
    expect(await warnExpiringSso(mailEnv, CERT_EXPIRES - 20 * DAY)).toBe(1);
    expect(sent.map((m) => m.to)).toEqual([ada.email]);
    expect(sent[0]?.subject).toContain('certificate expires on 19 December 2027');
    expect(sent[0]?.text).toContain(`/orgs/${orgId}/directory`);
    // The same threshold the next day: nothing new.
    expect(await warnExpiringSso(mailEnv, CERT_EXPIRES - 19 * DAY)).toBe(0);
    expect(await warnExpiringSso(mailEnv, CERT_EXPIRES - 6 * DAY)).toBe(1);
    expect(await warnExpiringSso(mailEnv, CERT_EXPIRES + DAY)).toBe(1);
    expect(sent.at(-1)?.subject).toContain('has expired');
    expect(await count('audit_events', "event = 'org.sso_expiry_warned'")).toBe(3);
    // Saving starts over.
    await saveSaml();
    expect(await warnExpiringSso(mailEnv, CERT_EXPIRES + DAY)).toBe(1);
  });

  it('warns about an OpenID Connect client secret by the date the owner gave', async () => {
    expect((await saveOidc({ secret_expires: '2027-02-31' })).status).toBe(400);
    expect((await saveOidc({ secret_expires: '2027-06-01' })).status).toBe(303);
    const expires = Date.UTC(2027, 5, 1) / 1000;
    const mailEnv = { ...env, MAILER: mailer } as unknown as Env;
    sent = [];
    expect(await warnExpiringSso(mailEnv, expires - 3 * DAY)).toBe(1);
    expect(sent[0]?.subject).toContain('client secret expires on 1 June 2027');
    // Cleared: nothing to warn about.
    await saveOidc({ secret_expires: '' });
    expect(await warnExpiringSso(mailEnv, expires - DAY)).toBe(0);
  });
});

describe('addresses that must use single sign-on', () => {
  beforeEach(async () => {
    await post(ada, `/orgs/${orgId}/domains/manage`, {
      domain: 'example.com',
      on: '1',
      accept: 'on',
    });
    await post(ada, '/account/managed', { org: orgId, choice: 'join' });
    await saveSaml();
  });

  it('are offered single sign-on instead of a code, the same for every address there', async () => {
    // Not yet required: a code, as before.
    expect((await post(null, '/login/email', { email: 'bob@example.com' })).status).toBe(303);
    await setRequireSso(env.DB, now, orgId, true);
    sent = [];
    for (const email of ['bob@example.com', 'nobody@example.com', 'ada@example.com']) {
      const response = await post(null, '/login/email', { email, return_to: '/account' });
      expect(response.status, email).toBe(200);
      const page = await response.text();
      expect(page).toContain('Continue with single sign-on');
      expect(page).toContain(`value="${email}"`);
    }
    expect(sent).toHaveLength(0);
    // An owner asks for a code anyway.
    const code = await post(null, '/login/email', { email: 'ada@example.com', code: '1' });
    expect(code.headers.get('Location')).toBe('/login/email/code');
    expect(sent).toHaveLength(1);
    // Other domains are untouched.
    expect((await post(null, '/login/email', { email: 'carol@elsewhere.example' })).status).toBe(
      303,
    );
  });
});

describe('signing a managed person out everywhere', () => {
  beforeEach(async () => {
    await post(ada, `/orgs/${orgId}/domains/manage`, {
      domain: 'example.com',
      on: '1',
      accept: 'on',
    });
    await post(ada, '/account/managed', { org: orgId, choice: 'join' });
    await post(bob, '/account/managed', { org: orgId, choice: 'join' });
  });

  it('ends their sessions and keeps the account active, from the members page', async () => {
    expect(await count('sessions', 'user_id = ?', bob.id)).toBeGreaterThan(0);
    sent = [];
    const done = await post(ada, `/orgs/${orgId}/members/sign-out`, { user: bob.id });
    expect(done.headers.get('Location')).toBe(`/orgs/${orgId}?done=signed_out`);
    expect(await count('sessions', 'user_id = ?', bob.id)).toBe(0);
    expect(await count('users', "id = ? AND status = 'active'", bob.id)).toBe(1);
    expect(await count('audit_events', "event = 'org.account_signed_out'")).toBe(1);
    expect(sent.map((m) => m.to)).toEqual([bob.email]);
    expect(await count('sessions', 'user_id = ?', ada.id)).toBeGreaterThan(0);
  });

  it('is for accounts the organization manages, and also in the API', async () => {
    const carol = await person('carol', 'elsewhere.example');
    await env.DB.prepare(
      "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, 'member', 0)",
    )
      .bind(orgId, carol.id)
      .run();
    expect((await post(ada, `/orgs/${orgId}/members/sign-out`, { user: carol.id })).status).toBe(
      409,
    );
    expect(await count('sessions', 'user_id = ?', carol.id)).toBeGreaterThan(0);

    const page = await (
      await post(ada, `/orgs/${orgId}/api-keys`, {
        action: 'create',
        name: 'Script',
        access: 'write',
      })
    ).text();
    const key = /<code class="secret">(2earl_[A-Za-z0-9_-]+)<\/code>/.exec(page)?.[1] ?? '';
    const api = (id: string) =>
      call(app, `/api/v1/members/${id}/sign-out`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: '{}',
        ip: freshIp(),
      });
    const ok = await api(bob.id);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ id: bob.id, signed_out: true });
    expect((await api(carol.id)).status).toBe(409);
    // Never owners.
    expect((await api(ada.id)).status).toBe(409);
  });
});
