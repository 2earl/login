import { env } from 'cloudflare:workers';
import { makeStaff } from './staff-helpers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { setOAuthClock } from '../src/oauth';
import { MetadataError, parseMetadata, refreshSamlMetadata } from '../src/saml-metadata';
import { CERT, CERT2, CERT2_EXPIRES, CERT_EXPIRES } from './certs';
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

/** Phase 10i (DESIGN §4.26): SAML settings from the provider's metadata URL. */

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};
const IDP = 'https://idp.example.com';
const METADATA = `${IDP}/federationmetadata.xml?appid=1`;

const body = (pem: string) => pem.replace(/-----[A-Z ]+-----|\s/g, '');

/** Metadata the way Entra ID publishes it: signing keys, an encryption key, two bindings. */
function metadata(
  opts: { entityId?: string; certs?: string[]; sso?: string; extra?: string } = {},
): string {
  const keys = (opts.certs ?? [CERT])
    .map(
      (pem) =>
        `<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${body(pem)}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>`,
    )
    .join('');
  return `<?xml version="1.0" encoding="utf-8"?>${opts.extra ?? ''}
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${opts.entityId ?? `${IDP}/entity`}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ${keys}
    <KeyDescriptor use="encryption"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${body(CERT2)}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${IDP}/post"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${opts.sso ?? `${IDP}/saml2`}"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
}

let served: { status: number; text: string };
let google: FakeGoogle;
let app: ReturnType<typeof createApp>;
let dns: Record<string, string[]>;

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
  if (url.toString() === METADATA) {
    return Promise.resolve(new Response(served.text, { status: served.status }));
  }
  return google.fetch(input, init);
};

let session: string;
let orgId: string;

function post(path: string, fields: Record<string, string>) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(fields),
    cookies: { '__Host-session': session },
    ip: freshIp(),
  });
}

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  dns = {};
  served = { status: 200, text: metadata() };
  google = new FakeGoogle();
  app = createApp({ fetch: fetcher, googleJwks: testJwks, now: () => NOW });
  await env.DB.prepare(
    "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES ('al-ada', 'email', 'ada@example.com', 'test', 0)",
  ).run();
  session =
    (
      await signIn(app, google, {
        claims: { sub: 'sub-ada', email: 'ada@example.com', name: 'Ada' },
      })
    ).session ?? '';
  await makeStaff(session);
  const created = await post('/orgs', { name: 'Example Inc' });
  orgId = /\/orgs\/([^?]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  await post(`/orgs/${orgId}/domains`, { domain: 'example.com' });
  const row = await env.DB.prepare('SELECT challenge FROM org_domains WHERE org_id = ?')
    .bind(orgId)
    .first<{ challenge: string }>();
  dns['_2earl-challenge.example.com'] = [row?.challenge ?? ''];
  await post(`/orgs/${orgId}/domains/verify`, { domain: 'example.com' });
});

const saml = () =>
  env.DB.prepare(
    `SELECT idp_entity_id, sso_url, certificate, certificate_next, certificate_expires_at,
            certificate_next_expires_at, metadata_url, metadata_error FROM org_saml WHERE org_id = ?`,
  )
    .bind(orgId)
    .first<Record<string, string | number | null>>();

describe('reading metadata', () => {
  it('takes the entity ID, the HTTP-Redirect URL and only the signing certificates', () => {
    const parsed = parseMetadata(metadata({ certs: [CERT, CERT2] }));
    expect(parsed.entityId).toBe(`${IDP}/entity`);
    expect(parsed.ssoUrl).toBe(`${IDP}/saml2`);
    expect(parsed.certificates.map(body)).toEqual([body(CERT), body(CERT2)]);
    // The encryption key alone isn't a signing certificate.
    expect(parseMetadata(metadata()).certificates).toHaveLength(1);
  });

  it('refuses what it can’t trust or use', () => {
    const refuse = (xml: string) => {
      expect(() => parseMetadata(xml)).toThrow(MetadataError);
    };
    refuse(metadata({ extra: '<!DOCTYPE x [<!ENTITY a "aaaa">]>' }));
    refuse('<EntityDescriptor');
    refuse(metadata({ sso: 'http://idp.example.com/saml2' }));
    refuse(metadata({ certs: ['not base64!'] }));
    refuse(
      `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">${metadata().replace(/<\?xml[^>]*>/, '')}${metadata({ entityId: 'other' }).replace(/<\?xml[^>]*>/, '')}</EntitiesDescriptor>`,
    );
  });
});

describe('saving from a metadata URL', () => {
  it('fills the settings from it, and says why it can’t', async () => {
    const saved = await post(`/orgs/${orgId}/saml`, { metadata_url: METADATA, enabled: 'on' });
    expect(saved.status).toBe(303);
    const row = await saml();
    expect(row).toMatchObject({
      idp_entity_id: `${IDP}/entity`,
      sso_url: `${IDP}/saml2`,
      certificate_expires_at: CERT_EXPIRES,
      certificate_next: null,
      metadata_url: METADATA,
    });
    const page = await (
      await call(app, `/orgs/${orgId}/directory`, { cookies: { '__Host-session': session } })
    ).text();
    expect(page).toContain('Last read recently');

    expect(
      (await post(`/orgs/${orgId}/saml`, { metadata_url: 'http://idp.example.com/m' })).status,
    ).toBe(400);
    served = { status: 404, text: '' };
    const failed = await post(`/orgs/${orgId}/saml`, { metadata_url: METADATA });
    expect(failed.status).toBe(400);
    expect(await failed.text()).toContain('The metadata URL answered 404.');
  });
});

describe('the daily read', () => {
  beforeEach(async () => {
    await post(`/orgs/${orgId}/saml`, { metadata_url: METADATA, enabled: 'on' });
  });

  it('takes a new certificate, starting the expiry warnings over', async () => {
    await env.DB.prepare("UPDATE org_saml SET expiry_notice = 'x' WHERE org_id = ?")
      .bind(orgId)
      .run();
    expect(await refreshSamlMetadata(env, fetcher, NOW + 86_400)).toEqual({
      changed: 0,
      failed: 0,
    });
    served = { status: 200, text: metadata({ certs: [CERT, CERT2] }) };
    expect(await refreshSamlMetadata(env, fetcher, NOW + 86_400)).toEqual({
      changed: 1,
      failed: 0,
    });
    expect(await saml()).toMatchObject({
      certificate_next_expires_at: CERT2_EXPIRES,
      metadata_error: null,
    });
    expect(await count('org_saml', 'expiry_notice IS NULL')).toBe(1);
    expect(await count('audit_events', "event = 'org.saml_metadata_refreshed'")).toBe(1);
  });

  it('changes nothing when the provider seems to be another one, and says why', async () => {
    served = {
      status: 200,
      text: metadata({ entityId: 'https://evil.example/entity', certs: [CERT2] }),
    };
    expect((await refreshSamlMetadata(env, fetcher, NOW)).failed).toBe(1);
    expect(await saml()).toMatchObject({ idp_entity_id: `${IDP}/entity`, certificate_next: null });
    expect(String((await saml())?.metadata_error)).toContain('different entity ID');

    served = { status: 200, text: metadata({ sso: 'https://evil.example/saml2', certs: [CERT2] }) };
    await refreshSamlMetadata(env, fetcher, NOW);
    expect(String((await saml())?.metadata_error)).toContain('another host');
    expect((await saml())?.sso_url).toBe(`${IDP}/saml2`);

    served = { status: 500, text: '' };
    await refreshSamlMetadata(env, fetcher, NOW);
    expect((await saml())?.metadata_error).toBe('The metadata URL answered 500.');
    const page = await (
      await call(app, `/orgs/${orgId}/directory`, { cookies: { '__Host-session': session } })
    ).text();
    expect(page).toContain('The metadata URL answered 500.');
  });

  it('leaves settings entered by hand alone', async () => {
    await post(`/orgs/${orgId}/saml`, {
      idp_entity_id: `${IDP}/entity`,
      sso_url: `${IDP}/saml2`,
      certificate: CERT,
      enabled: 'on',
    });
    expect((await saml())?.metadata_url).toBeNull();
    served = { status: 200, text: metadata({ certs: [CERT2] }) };
    expect(await refreshSamlMetadata(env, fetcher, NOW)).toEqual({ changed: 0, failed: 0 });
  });
});
