import { randomToken } from './crypto';

/**
 * Domains an organization controls (DESIGN §4.16), proved with a DNS TXT record. Directory sync
 * (SCIM) only provisions addresses at a verified domain, so an organization can't add someone it
 * has no authority over.
 */

export const MAX_DOMAINS = 10;
export const CHALLENGE_PREFIX = '2earl-verification=';
const DNS_JSON = 'https://cloudflare-dns.com/dns-query';

export interface OrgDomain {
  domain: string;
  challenge: string;
  verifiedAt: number | null;
  createdAt: number;
  /** The organization manages the accounts at this domain (DESIGN §4.18). */
  managedAt: number | null;
}

/** A registrable host name, lower case and in ASCII (punycode); null if it isn't one. */
export function normaliseDomain(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const text = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!text || text.length > 253 || /[/:@\s]/.test(text)) return null;
  let host: string;
  try {
    host = new URL(`https://${text}`).hostname;
  } catch {
    return null;
  }
  const labels = host.split('.');
  if (labels.length < 2) return null;
  if (!labels.every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return null;
  // Not an IP address: the last label of a name is never all digits.
  if (/^\d+$/.test(labels[labels.length - 1] ?? '')) return null;
  return host;
}

export function challengeRecordName(domain: string): string {
  return `_2earl-challenge.${domain}`;
}

export async function listDomains(db: D1Database, orgId: string): Promise<OrgDomain[]> {
  const { results } = await db
    .prepare(
      `SELECT domain, challenge, verified_at, created_at, managed_at FROM org_domains
       WHERE org_id = ? ORDER BY domain`,
    )
    .bind(orgId)
    .all<{
      domain: string;
      challenge: string;
      verified_at: number | null;
      created_at: number;
      managed_at: number | null;
    }>();
  return results.map((r) => ({
    domain: r.domain,
    challenge: r.challenge,
    verifiedAt: r.verified_at,
    createdAt: r.created_at,
    managedAt: r.managed_at,
  }));
}

export async function addDomain(
  db: D1Database,
  now: number,
  orgId: string,
  domain: string,
): Promise<'added' | 'exists' | 'full'> {
  const result = await db
    .prepare(
      `INSERT INTO org_domains (org_id, domain, challenge, created_at)
       SELECT ?1, ?2, ?3, ?4 WHERE (SELECT COUNT(*) FROM org_domains WHERE org_id = ?1) < ?5
       ON CONFLICT (org_id, domain) DO NOTHING`,
    )
    .bind(orgId, domain, `${CHALLENGE_PREFIX}${randomToken(24)}`, now, MAX_DOMAINS)
    .run();
  if (result.meta.changes > 0) return 'added';
  const existing = await db
    .prepare('SELECT 1 AS ok FROM org_domains WHERE org_id = ? AND domain = ?')
    .bind(orgId, domain)
    .first<{ ok: number }>();
  return existing ? 'exists' : 'full';
}

export async function removeDomain(db: D1Database, orgId: string, domain: string) {
  const result = await db
    .prepare('DELETE FROM org_domains WHERE org_id = ? AND domain = ?')
    .bind(orgId, domain)
    .run();
  return result.meta.changes > 0;
}

/** The TXT records at `name`, through DNS over HTTPS. Throws when DNS can't be asked. */
async function txtRecords(fetcher: typeof fetch, name: string): Promise<string[]> {
  const response = await fetcher(`${DNS_JSON}?name=${encodeURIComponent(name)}&type=TXT`, {
    headers: { Accept: 'application/dns-json' },
  });
  if (!response.ok) throw new Error(`dns ${String(response.status)}`);
  const body = await response.json<{
    Status?: number;
    Answer?: { type: number; data: string }[];
  }>();
  if (body.Status !== 0 && body.Status !== 3) throw new Error('dns status');
  return (body.Answer ?? [])
    .filter((a) => a.type === 16)
    .map((a) => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
}

export type VerifyResult = 'verified' | 'not_found' | 'taken' | 'dns_error' | 'unknown';

/**
 * Looks for the challenge in DNS and, if it's there, marks the domain verified. A domain verified
 * by another organization stays theirs until they remove it.
 */
export async function verifyDomain(
  db: D1Database,
  fetcher: typeof fetch,
  now: number,
  orgId: string,
  domain: string,
): Promise<VerifyResult> {
  const row = await db
    .prepare('SELECT challenge, verified_at FROM org_domains WHERE org_id = ? AND domain = ?')
    .bind(orgId, domain)
    .first<{ challenge: string; verified_at: number | null }>();
  if (!row) return 'unknown';
  if (row.verified_at !== null) return 'verified';
  let records: string[];
  try {
    records = await txtRecords(fetcher, challengeRecordName(domain));
  } catch {
    return 'dns_error';
  }
  if (!records.includes(row.challenge)) return 'not_found';
  try {
    await db
      .prepare('UPDATE org_domains SET verified_at = ? WHERE org_id = ? AND domain = ?')
      .bind(now, orgId, domain)
      .run();
  } catch (error) {
    if (error instanceof Error && /UNIQUE/i.test(error.message)) return 'taken';
    throw error;
  }
  return 'verified';
}

/** Whether `email` is at a domain the organization verified. */
export async function addressAtVerifiedDomain(
  db: D1Database,
  orgId: string,
  email: string,
): Promise<boolean> {
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
  if (!domain) return false;
  const row = await db
    .prepare(
      'SELECT 1 AS ok FROM org_domains WHERE org_id = ? AND domain = ? AND verified_at IS NOT NULL',
    )
    .bind(orgId, domain)
    .first<{ ok: number }>();
  return Boolean(row);
}
