import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { SignedXml } from 'xml-crypto';
import { createApp } from '../src/app';
import { randomToken } from '../src/crypto';
import { setOAuthClock } from '../src/oauth';
import { signingKeyPem } from '../src/saml';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  count,
  freshIp,
  resetDatabase,
  setCookies,
  signIn,
  testJwks,
} from './helpers';

/** Phase 9c (DESIGN §4.17): SAML 2.0 sign-in through an organization's identity provider. */

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};
const IDP_ENTITY = 'https://idp.example.com/metadata';
const IDP_SSO = 'https://idp.example.com/sso';

let google: FakeGoogle;
let app: ReturnType<typeof createApp>;
let dns: Record<string, string[]>;
let idp: { privateKey: string; publicKey: string };
let orgId: string;
let ada: { session: string };

const fetcher: typeof fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  if (url.hostname === 'cloudflare-dns.com') {
    const records = dns[url.searchParams.get('name') ?? ''] ?? [];
    return Promise.resolve(
      Response.json({
        Status: 0,
        Answer: records.map((data) => ({ type: 16, data: `"${data}"` })),
      }),
    );
  }
  return google.fetch(input, init);
};

function pem(kind: string, der: ArrayBuffer): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  return `-----BEGIN ${kind}-----\n${(b64.match(/.{1,64}/g) ?? []).join('\n')}\n-----END ${kind}-----\n`;
}

async function newIdpKey() {
  const pair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  return {
    privateKey: pem(
      'PRIVATE KEY',
      (await crypto.subtle.exportKey('pkcs8', pair.privateKey)) as ArrayBuffer,
    ),
    publicKey: pem(
      'PUBLIC KEY',
      (await crypto.subtle.exportKey('spki', pair.publicKey)) as ArrayBuffer,
    ),
  };
}

async function person(key: string) {
  const email = `${key}@example.com`;
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
  return { id: row?.id ?? '', session: session ?? '' };
}

function post(session: string, path: string, body: Record<string, string>) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(body),
    cookies: { '__Host-session': session },
    ip: freshIp(),
  });
}

/** Starts SSO for `email`; returns the browser's cookie, the RelayState and the request's ID. */
async function startSso(email: string) {
  const response = await call(app, '/login/sso', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({ email, return_to: '/account' }),
    ip: freshIp(),
  });
  expect(response.status).toBe(302);
  const location = new URL(response.headers.get('Location') ?? '');
  expect(location.origin + location.pathname).toBe(IDP_SSO);
  const key =
    (
      await env.DB.prepare('SELECT key FROM saml_cache ORDER BY rowid DESC LIMIT 1').first<{
        key: string;
      }>()
    )?.key ?? '';
  return {
    cookie: setCookies(response)['__Host-saml_tx'] ?? '',
    relayState: location.searchParams.get('RelayState') ?? '',
    requestId: key.slice(key.lastIndexOf(':') + 1),
  };
}

function iso(offsetSeconds = 0) {
  return new Date(Date.now() + offsetSeconds * 1000).toISOString();
}

/** What the IdP posts back: a Response with an assertion signed by `key` (unless `sign` is false). */
function samlResponse(options: {
  requestId: string;
  email: string;
  key?: string;
  sign?: boolean;
  audience?: string;
  tamper?: (xml: string) => string;
}) {
  const sp = `${ORIGIN}/saml/${orgId}`;
  const assertionId = `_a${randomToken(16)}`;
  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${iso()}">` +
    `<saml:Issuer>${IDP_ENTITY}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${options.email}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${options.requestId}" NotOnOrAfter="${iso(300)}" Recipient="${sp}/acs"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${iso(-30)}" NotOnOrAfter="${iso(300)}"><saml:AudienceRestriction><saml:Audience>${options.audience ?? sp}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso()}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    '</saml:Assertion>';
  let signed = assertion;
  if (options.sign !== false) {
    const sig = new SignedXml({
      privateKey: options.key ?? idp.privateKey,
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    });
    sig.addReference({
      xpath: "//*[local-name(.)='Assertion']",
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    });
    sig.computeSignature(assertion, {
      location: {
        reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
        action: 'after',
      },
    });
    signed = sig.getSignedXml();
  }
  const response =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r${randomToken(16)}" Version="2.0" IssueInstant="${iso()}" Destination="${sp}/acs" InResponseTo="${options.requestId}">` +
    `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${IDP_ENTITY}</saml:Issuer>` +
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    signed +
    '</samlp:Response>';
  return btoa((options.tamper ?? ((x: string) => x))(response));
}

/** The IdP's POST, then the same-site GET with the browser's cookie. */
async function finish(cookie: string | null, relayState: string, response: string) {
  const posted = await call(app, `/saml/${orgId}/acs`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'https://idp.example.com',
    },
    body: new URLSearchParams({ SAMLResponse: response, RelayState: relayState }),
    ip: freshIp(),
  });
  if (posted.status !== 303) return posted;
  return call(app, posted.headers.get('Location') ?? '', {
    ...(cookie ? { cookies: { '__Host-saml_tx': cookie } } : {}),
    ip: freshIp(),
  });
}

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM saml_cache'),
    env.DB.prepare('DELETE FROM saml_states'),
  ]);
  dns = {};
  google = new FakeGoogle();
  app = createApp({ fetch: fetcher, googleJwks: testJwks, now: () => NOW });
  idp = await newIdpKey();
  ada = await person('ada');
  const created = await post(ada.session, '/orgs', { name: 'Example Inc' });
  orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  await post(ada.session, `/orgs/${orgId}/domains`, { domain: 'example.com' });
  const challenge =
    (await env.DB.prepare('SELECT challenge FROM org_domains').first<{ challenge: string }>())
      ?.challenge ?? '';
  dns['_2earl-challenge.example.com'] = [challenge];
  await post(ada.session, `/orgs/${orgId}/domains/verify`, { domain: 'example.com' });
  const saved = await post(ada.session, `/orgs/${orgId}/saml`, {
    idp_entity_id: IDP_ENTITY,
    sso_url: IDP_SSO,
    certificate: idp.publicKey,
    enabled: 'on',
  });
  expect(saved.headers.get('Location')).toBe(`/orgs/${orgId}/directory?done=saml`);
});

describe('SAML sign-in', () => {
  it('signs in the account with the asserted address, after a signed assertion', async () => {
    const bob = await person('bob');
    const { cookie, relayState, requestId } = await startSso('Bob@Example.com');
    const done = await finish(
      cookie,
      relayState,
      samlResponse({ requestId, email: 'bob@example.com' }),
    );
    expect(done.status).toBe(303);
    expect(done.headers.get('Location')).toBe('/account');
    expect(setCookies(done)['__Host-session']).toBeTruthy();
    expect(await count('sessions', "user_id = ? AND method = 'saml'", bob.id)).toBe(1);
    expect(await count('saml_states')).toBe(0);
  });

  it('refuses unsigned, tampered, wrongly signed or misaddressed assertions', async () => {
    await person('bob');
    const other = await newIdpKey();
    const cases: [string, (requestId: string) => string][] = [
      [
        'unsigned',
        (requestId) => samlResponse({ requestId, email: 'bob@example.com', sign: false }),
      ],
      [
        'other key',
        (requestId) => samlResponse({ requestId, email: 'bob@example.com', key: other.privateKey }),
      ],
      [
        'tampered',
        (requestId) =>
          samlResponse({
            requestId,
            email: 'ada@example.com',
            tamper: (x) => x.replace('>ada@example.com<', '>bob@example.com<'),
          }),
      ],
      [
        'other audience',
        (requestId) =>
          samlResponse({
            requestId,
            email: 'bob@example.com',
            audience: 'https://elsewhere.example',
          }),
      ],
      ['other request', () => samlResponse({ requestId: '_not-ours', email: 'bob@example.com' })],
      ['outside the domain', (requestId) => samlResponse({ requestId, email: 'bob@gmail.com' })],
    ];
    for (const [name, build] of cases) {
      const { cookie, relayState, requestId } = await startSso('bob@example.com');
      const done = await finish(cookie, relayState, build(requestId));
      expect(done.status, name).toBe(400);
      expect(setCookies(done)['__Host-session'], name).toBeUndefined();
    }
    expect(await count('sessions', "method = 'saml'")).toBe(0);
  });

  it('works once, only in the browser that started it, and never IdP-initiated', async () => {
    await person('bob');
    const first = await startSso('bob@example.com');
    const response = samlResponse({ requestId: first.requestId, email: 'bob@example.com' });
    // Another browser (no cookie) can't finish it.
    expect((await finish(null, first.relayState, response)).status).toBe(400);
    // Replaying the same response in a new sign-in: it answers a request already used.
    const second = await startSso('bob@example.com');
    expect((await finish(second.cookie, second.relayState, response)).status).toBe(400);
    // Without RelayState (IdP-initiated).
    const idpInitiated = await call(app, `/saml/${orgId}/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ SAMLResponse: response }),
    });
    expect(idpInitiated.status).toBe(400);
  });

  it('creates an account for a new address only when sign-up allows it', async () => {
    const first = await startSso('carol@example.com');
    const refused = await finish(
      first.cookie,
      first.relayState,
      samlResponse({ requestId: first.requestId, email: 'carol@example.com' }),
    );
    expect(refused.status).toBe(403);
    expect(await count('users', "primary_email = 'carol@example.com'")).toBe(0);

    await env.DB.prepare(
      "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES ('al-carol', 'email', 'carol@example.com', 'test', 0)",
    ).run();
    const second = await startSso('carol@example.com');
    const done = await finish(
      second.cookie,
      second.relayState,
      samlResponse({ requestId: second.requestId, email: 'carol@example.com' }),
    );
    expect(done.headers.get('Location')).toBe('/welcome?return_to=%2Faccount');
    expect(await count('identities', "provider = 'email' AND subject = 'carol@example.com'")).toBe(
      1,
    );
  });

  it('is offered only for domains with single sign-on on, and publishes the SP metadata', async () => {
    const none = await call(app, '/login/sso', {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams({ email: 'someone@other.org' }),
    });
    expect(none.status).toBe(404);
    expect(await none.text()).toContain('No organization signs in this address');
    expect(await (await call(app, '/login')).text()).toContain('href="/login/sso"');
    const metadata = await call(app, `/saml/${orgId}/metadata`);
    expect(metadata.headers.get('Content-Type')).toContain('application/samlmetadata+xml');
    expect(await metadata.text()).toContain(`entityID="${ORIGIN}/saml/${orgId}"`);

    await post(ada.session, `/orgs/${orgId}/saml`, {
      idp_entity_id: IDP_ENTITY,
      sso_url: IDP_SSO,
      certificate: idp.publicKey,
    });
    expect(
      (
        await call(app, '/login/sso', {
          method: 'POST',
          headers: FORM,
          body: new URLSearchParams({ email: 'bob@example.com' }),
        })
      ).status,
    ).toBe(404);
  });

  it('accepts the next signing certificate too, so the provider can switch (§4.25)', async () => {
    await person('bob');
    const next = await newIdpKey();
    const stranger = await newIdpKey();
    await post(ada.session, `/orgs/${orgId}/saml`, {
      idp_entity_id: IDP_ENTITY,
      sso_url: IDP_SSO,
      certificate: idp.publicKey,
      certificate_next: next.publicKey,
      enabled: 'on',
    });
    for (const [key, status] of [
      [idp.privateKey, 303],
      [next.privateKey, 303],
      [stranger.privateKey, 400],
    ] as const) {
      const { cookie, relayState, requestId } = await startSso('bob@example.com');
      const done = await finish(
        cookie,
        relayState,
        samlResponse({ requestId, email: 'bob@example.com', key }),
      );
      expect(done.status).toBe(status);
    }
  });

  it('settings need an https URL and a certificate, from an owner', async () => {
    expect(signingKeyPem('not a certificate')).toBeNull();
    expect(signingKeyPem(idp.publicKey)).toContain('-----BEGIN PUBLIC KEY-----');
    const bad = await post(ada.session, `/orgs/${orgId}/saml`, {
      idp_entity_id: IDP_ENTITY,
      sso_url: 'http://idp.example.com/sso',
      certificate: idp.publicKey,
      enabled: 'on',
    });
    expect(bad.status).toBe(400);
    const bob = await person('bob');
    expect(
      (
        await post(bob.session, `/orgs/${orgId}/saml`, {
          idp_entity_id: 'x',
          sso_url: IDP_SSO,
          certificate: idp.publicKey,
        })
      ).status,
    ).toBe(404);
  });
});
