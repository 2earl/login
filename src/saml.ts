import { X509Certificate } from 'node:crypto';
import { ssoOnSql } from './managed';
import { SAML, ValidateInResponseTo, type CacheProvider, type Profile } from '@node-saml/node-saml';
import { normaliseEmail } from './directory';

/**
 * SAML 2.0 single sign-on for organizations (DESIGN §4.17). login is the service provider;
 * an organization's identity provider (Okta, Microsoft Entra ID, Google Workspace…) proves who is
 * signing in, for addresses at the organization's verified domains. Only sign-ins login starts
 * (SP-initiated): responses must answer a request login sent, once.
 *
 * XML signatures are checked by node-saml and xml-crypto, never by code of our own.
 */

export const SAML_REQUEST_TTL_SECONDS = 10 * 60;
const CLOCK_SKEW_MS = 60_000;
const MAX_ASSERTION_AGE_MS = 10 * 60_000;
export const MAX_RESPONSE_LENGTH = 200_000;

export interface OrgSaml {
  orgId: string;
  idpEntityId: string;
  ssoUrl: string;
  certificate: string;
  /** The provider's next signing certificate, accepted too while it changes over (§4.25). */
  certificateNext: string | null;
  /** When each expires, from the certificate; null for a bare public key. */
  certificateExpiresAt: number | null;
  certificateNextExpiresAt: number | null;
  enabled: boolean;
}

export const spEntityId = (env: Env, orgId: string) => `${env.ISSUER}/saml/${orgId}`;
export const acsUrl = (env: Env, orgId: string) => `${env.ISSUER}/saml/${orgId}/acs`;

export async function samlConfig(db: D1Database, orgId: string): Promise<OrgSaml | null> {
  const row = await db
    .prepare(
      `SELECT s.org_id, s.idp_entity_id, s.sso_url, s.certificate, s.certificate_next,
              s.certificate_expires_at, s.certificate_next_expires_at, s.enabled
       FROM org_saml s JOIN organizations o ON o.id = s.org_id AND o.status = 'active'
       WHERE s.org_id = ?`,
    )
    .bind(orgId)
    .first<{
      org_id: string;
      idp_entity_id: string;
      sso_url: string;
      certificate: string;
      certificate_next: string | null;
      certificate_expires_at: number | null;
      certificate_next_expires_at: number | null;
      enabled: number;
    }>();
  return row
    ? {
        orgId: row.org_id,
        idpEntityId: row.idp_entity_id,
        ssoUrl: row.sso_url,
        certificate: row.certificate,
        certificateNext: row.certificate_next,
        certificateExpiresAt: row.certificate_expires_at,
        certificateNextExpiresAt: row.certificate_next_expires_at,
        enabled: row.enabled === 1,
      }
    : null;
}

/**
 * The organization that signs in addresses at this email's domain with single sign-on (SAML or
 * OpenID Connect), if any.
 */
export async function ssoOrgForEmail(db: D1Database, email: string): Promise<string | null> {
  const domain = email.slice(email.lastIndexOf('@') + 1);
  const row = await db
    .prepare(
      `SELECT d.org_id FROM org_domains d
       JOIN organizations o ON o.id = d.org_id AND o.status = 'active'
       WHERE d.domain = ? AND d.verified_at IS NOT NULL AND ${ssoOnSql('d.org_id')}`,
    )
    .bind(domain)
    .first<{ org_id: string }>();
  return row?.org_id ?? null;
}

/**
 * The IdP's signing certificate or public key as PEM: a pasted PEM, or the bare base64 that IdP
 * metadata contains. Null if it isn't one.
 */
export function signingKeyPem(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const text = raw.trim();
  const match = /^-----BEGIN (CERTIFICATE|PUBLIC KEY)-----([\s\S]+?)-----END \1-----$/.exec(text);
  const kind = match?.[1] ?? 'CERTIFICATE';
  const body = (match?.[2] ?? text).replace(/\s+/g, '');
  if (body.length < 200 || body.length > 12_000 || !/^[A-Za-z0-9+/]+=*$/.test(body)) return null;
  try {
    atob(body);
  } catch {
    return null;
  }
  const lines = body.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${kind}-----\n${lines.join('\n')}\n-----END ${kind}-----`;
}

/**
 * When a certificate expires (Unix seconds), or null for a public key or anything unreadable.
 * login doesn't refuse an expired certificate, but providers change certificates around then.
 */
export function certificateExpiry(pem: string): number | null {
  if (!pem.startsWith('-----BEGIN CERTIFICATE-----')) return null;
  try {
    const time = Date.parse(new X509Certificate(pem).validTo);
    return Number.isNaN(time) ? null : Math.floor(time / 1000);
  } catch {
    return null;
  }
}

/** An https URL for the IdP's sign-in endpoint. */
export function ssoUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  try {
    const url = new URL(raw.trim());
    return url.protocol === 'https:' && !url.username && !url.password ? url.toString() : null;
  } catch {
    return null;
  }
}

/**
 * node-saml's cache in D1: request IDs and assertion IDs, each used once. Scoped to one sign-in
 * (the organization and its RelayState's hash), so a response is accepted only by the sign-in
 * whose request it answers.
 */
function d1Cache(db: D1Database, scope: string, nowMs: () => number): CacheProvider {
  const k = (key: string) => `${scope}:${key}`;
  const expiry = () => Math.floor(nowMs() / 1000) + SAML_REQUEST_TTL_SECONDS;
  return {
    async saveAsync(key, value) {
      await db
        .prepare('INSERT OR REPLACE INTO saml_cache (key, value, expires_at) VALUES (?, ?, ?)')
        .bind(k(key), value, expiry())
        .run();
      return { value, createdAt: nowMs() };
    },
    async getAsync(key) {
      const row = await db
        .prepare('SELECT value FROM saml_cache WHERE key = ? AND expires_at > ?')
        .bind(k(key), Math.floor(nowMs() / 1000))
        .first<{ value: string }>();
      return row?.value ?? null;
    },
    async removeAsync(key) {
      if (key === null) return null;
      const row = await db
        .prepare('DELETE FROM saml_cache WHERE key = ? RETURNING value')
        .bind(k(key))
        .first<{ value: string }>();
      return row?.value ?? null;
    },
    async consumeAsync(key) {
      const row = await db
        .prepare('DELETE FROM saml_cache WHERE key = ? AND expires_at > ? RETURNING value')
        .bind(k(key), Math.floor(nowMs() / 1000))
        .first<{ value: string }>();
      return row?.value ?? null;
    },
    async saveIfAbsentAsync(key, value, expiresAtMs) {
      const result = await db
        .prepare(
          `INSERT INTO saml_cache (key, value, expires_at) VALUES (?, ?, ?)
           ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at
           WHERE saml_cache.expires_at <= ?`,
        )
        .bind(k(key), value, Math.ceil(expiresAtMs / 1000), Math.floor(nowMs() / 1000))
        .run();
      return result.meta.changes > 0;
    },
  };
}

/** The service provider for one organization's IdP, for one sign-in (`flow`: its state's hash). */
export function samlFor(env: Env, config: OrgSaml, nowMs: () => number, flow = 'metadata'): SAML {
  return new SAML({
    entryPoint: config.ssoUrl,
    issuer: spEntityId(env, config.orgId),
    audience: spEntityId(env, config.orgId),
    callbackUrl: acsUrl(env, config.orgId),
    // The next certificate too, so the provider can switch without breaking sign-in.
    idpCert: config.certificateNext
      ? [config.certificate, config.certificateNext]
      : config.certificate,
    idpIssuer: config.idpEntityId,
    // The assertion itself must be signed: a signed envelope around an unsigned assertion isn't enough.
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    signatureAlgorithm: 'sha256',
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    disableRequestedAuthnContext: true,
    acceptedClockSkewMs: CLOCK_SKEW_MS,
    maxAssertionAgeMs: MAX_ASSERTION_AGE_MS,
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: SAML_REQUEST_TTL_SECONDS * 1000,
    rejectReplayedAssertions: true,
    cacheProvider: d1Cache(env.DB, `${config.orgId}:${flow}`, nowMs),
  });
}

/** The address the IdP vouches for: an email attribute, else an email-format NameID. */
export function assertedEmail(profile: Profile): string | null {
  const candidates = [
    profile.email,
    profile.mail,
    profile['urn:oid:0.9.2342.19200300.100.1.3'],
    profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
    profile.nameIDFormat === 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
      ? profile.nameID
      : undefined,
  ];
  for (const value of candidates) {
    const text: unknown = Array.isArray(value) ? (value as unknown[])[0] : value;
    if (typeof text === 'string') {
      const email = normaliseEmail(text);
      if (email) return email;
    }
  }
  return null;
}
