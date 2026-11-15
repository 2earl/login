import { DOMParser, type XmlElement } from '@xmldom/xmldom/lib/dom-parser.js';
import { audit } from './audit';
import { certificateExpiry, signingKeyPem, ssoUrl } from './saml';

/**
 * SAML settings from the identity provider's metadata (DESIGN §4.26). Entra ID and Okta publish
 * it at a URL; login reads it when the owner saves, and again every day, so a new signing
 * certificate is picked up before the provider starts using it, with nothing to paste.
 */

const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
/** Metadata larger than this is refused. Entra ID's is about 10 KB. */
const MAX_BYTES = 512 * 1024;

export interface IdpMetadata {
  entityId: string;
  ssoUrl: string;
  /** Signing certificates as PEM, at most two: the current one and the next. */
  certificates: string[];
}

/** Why metadata couldn't be used, in words for the owner. */
export class MetadataError extends Error {}

/** An https URL without credentials, at most 1,000 characters (queries allowed: Entra ID's has one). */
export function metadataUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const text = raw.trim();
  if (!text || text.length > 1000) return null;
  try {
    const url = new URL(text);
    return url.protocol === 'https:' && !url.username && !url.password && !url.hash
      ? url.toString()
      : null;
  } catch {
    return null;
  }
}

/** Reads the identity provider's metadata from its URL. */
export async function fetchMetadata(fetcher: typeof fetch, url: string): Promise<IdpMetadata> {
  let response: Response;
  try {
    response = await fetcher(url, {
      redirect: 'manual',
      headers: { Accept: 'application/samlmetadata+xml, application/xml, text/xml' },
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    throw new MetadataError('The metadata URL didn’t answer.');
  }
  if (!response.ok) {
    throw new MetadataError(`The metadata URL answered ${String(response.status)}.`);
  }
  const text = await response.text();
  if (text.length > MAX_BYTES) throw new MetadataError('The metadata is too large.');
  return parseMetadata(text);
}

const children = (parent: XmlElement, ns: string, name: string): XmlElement[] =>
  Array.from(parent.getElementsByTagNameNS(ns, name));

/**
 * The identity provider's entity ID, its HTTP-Redirect sign-in URL and its signing certificates,
 * from one EntityDescriptor with an IDPSSODescriptor.
 */
export function parseMetadata(xml: string): IdpMetadata {
  // Metadata never needs a DTD; refusing one rules out entity expansion.
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new MetadataError('The metadata has a DTD.');
  const errors: string[] = [];
  const doc = new DOMParser({
    errorHandler: {
      warning: () => undefined,
      error: (message: string) => errors.push(message),
      fatalError: (message: string) => errors.push(message),
    },
  }).parseFromString(xml, 'text/xml');
  if (errors.length > 0 || !doc.documentElement) {
    throw new MetadataError('The metadata isn’t valid XML.');
  }
  const idps = children(doc.documentElement, MD, 'IDPSSODescriptor');
  if (idps.length !== 1) {
    throw new MetadataError(
      idps.length === 0
        ? 'The metadata describes no identity provider.'
        : 'The metadata describes more than one identity provider.',
    );
  }
  const idp = idps[0] as XmlElement;
  const entityId = idp.parentNode?.getAttribute('entityID')?.trim() ?? '';
  if (!entityId || entityId.length > 500) {
    throw new MetadataError('The metadata names no entity ID.');
  }
  const redirect = children(idp, MD, 'SingleSignOnService').find(
    (service) => service.getAttribute('Binding') === REDIRECT,
  );
  const url = ssoUrl(redirect?.getAttribute('Location'));
  if (!url) throw new MetadataError('The metadata has no https sign-in URL for HTTP-Redirect.');
  const certificates: string[] = [];
  for (const key of children(idp, MD, 'KeyDescriptor')) {
    const use = key.getAttribute('use');
    if (use && use !== 'signing') continue;
    for (const cert of children(key, DS, 'X509Certificate')) {
      const pem = signingKeyPem(cert.textContent ?? '');
      if (pem && !certificates.includes(pem)) certificates.push(pem);
    }
  }
  if (certificates.length === 0)
    throw new MetadataError('The metadata has no signing certificate.');
  // With more than two, the two that last longest: older ones are on their way out.
  if (certificates.length > 2) {
    certificates.sort((a, b) => (certificateExpiry(b) ?? 0) - (certificateExpiry(a) ?? 0));
    certificates.length = 2;
  }
  return { entityId, ssoUrl: url, certificates };
}

/** The columns a metadata read sets. */
export function certificateColumns(metadata: IdpMetadata) {
  const [certificate = '', next = null] = metadata.certificates;
  return {
    certificate,
    certificateNext: next,
    certificateExpiresAt: certificateExpiry(certificate),
    certificateNextExpiresAt: next ? certificateExpiry(next) : null,
  };
}

/**
 * Daily: reads each organization's metadata URL again. New certificates and a moved sign-in URL
 * are taken; a different entity ID or a sign-in URL at another host is not (that is another
 * provider, or someone else's), and the owners see why on Domains & SSO.
 */
export async function refreshSamlMetadata(
  env: Env,
  fetcher: typeof fetch,
  now: number,
): Promise<{ changed: number; failed: number }> {
  const { results } = await env.DB.prepare(
    `SELECT s.org_id, s.metadata_url, s.idp_entity_id, s.sso_url, s.certificate, s.certificate_next
     FROM org_saml s JOIN organizations o ON o.id = s.org_id AND o.status = 'active'
     WHERE s.metadata_url IS NOT NULL`,
  ).all<{
    org_id: string;
    metadata_url: string;
    idp_entity_id: string;
    sso_url: string;
    certificate: string;
    certificate_next: string | null;
  }>();
  let changed = 0;
  let failed = 0;
  for (const row of results) {
    let error: string | null = null;
    try {
      const metadata = await fetchMetadata(fetcher, row.metadata_url);
      if (metadata.entityId !== row.idp_entity_id) {
        throw new MetadataError(
          'The metadata now names a different entity ID. Nothing was changed: save the settings again if the provider really changed.',
        );
      }
      if (new URL(metadata.ssoUrl).host !== new URL(row.sso_url).host) {
        throw new MetadataError(
          'The metadata now has a sign-in URL at another host. Nothing was changed: save the settings again if that is right.',
        );
      }
      const columns = certificateColumns(metadata);
      if (
        columns.certificate !== row.certificate ||
        columns.certificateNext !== row.certificate_next ||
        metadata.ssoUrl !== row.sso_url
      ) {
        await env.DB.prepare(
          `UPDATE org_saml SET sso_url = ?1, certificate = ?2, certificate_next = ?3,
             certificate_expires_at = ?4, certificate_next_expires_at = ?5, expiry_notice = NULL,
             updated_at = ?6
           WHERE org_id = ?7`,
        )
          .bind(
            metadata.ssoUrl,
            columns.certificate,
            columns.certificateNext,
            columns.certificateExpiresAt,
            columns.certificateNextExpiresAt,
            now,
            row.org_id,
          )
          .run();
        await audit(env.DB, now, 'org.saml_metadata_refreshed', {
          detail: { org: row.org_id, certificates: metadata.certificates.length },
        });
        changed += 1;
      }
    } catch (cause) {
      error = cause instanceof MetadataError ? cause.message : 'The metadata couldn’t be read.';
      failed += 1;
    }
    await env.DB.prepare(
      'UPDATE org_saml SET metadata_checked_at = ?, metadata_error = ? WHERE org_id = ?',
    )
      .bind(now, error, row.org_id)
      .run();
  }
  return { changed, failed };
}
