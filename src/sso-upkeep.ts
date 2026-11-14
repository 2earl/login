import { audit } from './audit';
import { notify } from './mail';

/**
 * Keeping single sign-on working (DESIGN §4.25). Most SSO outages aren't attacks: the identity
 * provider starts signing with a new certificate, or a client secret expires, and nobody at the
 * company remembers 2earl needs the new one. login accepts the next certificate alongside the
 * current one, and tells owners ahead of time.
 */

/** Days before an expiry when owners are told. */
export const WARN_DAYS = [30, 7, 1] as const;

const DAY = 86_400;

/** A date from a form's date field (YYYY-MM-DD), as Unix seconds at its start (UTC); else null. */
export function dateField(raw: string): number | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw.trim());
  if (!match) return null;
  const time = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  const date = new Date(time);
  // Refuses 2026-02-31 and the like, which Date would roll over.
  if (date.getUTCDate() !== Number(match[3])) return null;
  const year = date.getUTCFullYear();
  return year >= 2000 && year <= 2100 ? Math.floor(time / 1000) : null;
}

/** The date field's value for a stored time. */
export function dateValue(at: number | null): string {
  return at === null ? '' : new Date(at * 1000).toISOString().slice(0, 10);
}

/**
 * When single sign-on with these certificates stops working at the latest: when the last of them
 * expires. Null when any is a bare public key (no expiry to go by).
 */
export function samlExpiry(current: number | null, next: number | null, hasNext: boolean) {
  if (current === null || (hasNext && next === null)) return null;
  return hasNext && next !== null ? Math.max(current, next) : current;
}

/** Which warning applies: the smallest threshold reached (0 once expired), or null. */
export function warningDue(expiresAt: number, now: number): number | null {
  const left = expiresAt - now;
  if (left <= 0) return 0;
  const reached = WARN_DAYS.filter((days) => left <= days * DAY);
  return reached.length > 0 ? Math.min(...reached) : null;
}

interface Due {
  orgId: string;
  orgName: string;
  protocol: 'saml' | 'oidc';
  expiresAt: number;
  notice: string | null;
}

/**
 * Daily: emails the owners of organizations whose provider's certificate or client secret expires
 * soon, once per threshold (30, 7 and 1 days, and once expired). Returns how many organizations
 * were told.
 */
export async function warnExpiringSso(env: Env, now: number): Promise<number> {
  const { results: saml } = await env.DB.prepare(
    `SELECT s.org_id, o.name, s.certificate_expires_at, s.certificate_next_expires_at,
            s.certificate_next IS NOT NULL AS has_next, s.expiry_notice
     FROM org_saml s JOIN organizations o ON o.id = s.org_id AND o.status = 'active'
     WHERE s.enabled = 1 AND s.certificate_expires_at IS NOT NULL`,
  ).all<{
    org_id: string;
    name: string;
    certificate_expires_at: number;
    certificate_next_expires_at: number | null;
    has_next: number;
    expiry_notice: string | null;
  }>();
  const { results: oidc } = await env.DB.prepare(
    `SELECT x.org_id, o.name, x.secret_expires_at, x.expiry_notice
     FROM org_oidc x JOIN organizations o ON o.id = x.org_id AND o.status = 'active'
     WHERE x.enabled = 1 AND x.secret_expires_at IS NOT NULL`,
  ).all<{
    org_id: string;
    name: string;
    secret_expires_at: number;
    expiry_notice: string | null;
  }>();
  const due: Due[] = [];
  for (const row of saml) {
    const expiresAt = samlExpiry(
      row.certificate_expires_at,
      row.certificate_next_expires_at,
      row.has_next === 1,
    );
    if (expiresAt !== null) {
      due.push({
        orgId: row.org_id,
        orgName: row.name,
        protocol: 'saml',
        expiresAt,
        notice: row.expiry_notice,
      });
    }
  }
  for (const row of oidc) {
    due.push({
      orgId: row.org_id,
      orgName: row.name,
      protocol: 'oidc',
      expiresAt: row.secret_expires_at,
      notice: row.expiry_notice,
    });
  }

  let told = 0;
  for (const item of due) {
    const days = warningDue(item.expiresAt, now);
    if (days === null) continue;
    const mark = `${String(item.expiresAt)}:${String(days)}`;
    if (item.notice === mark) continue;
    // Recorded first: a failed email isn't retried every day for the same threshold.
    const table = item.protocol === 'saml' ? 'org_saml' : 'org_oidc';
    const claimed = await env.DB.prepare(
      `UPDATE ${table} SET expiry_notice = ?1 WHERE org_id = ?2 AND (expiry_notice IS NULL OR expiry_notice != ?1)`,
    )
      .bind(mark, item.orgId)
      .run();
    if (claimed.meta.changes === 0) continue;
    const { results: owners } = await env.DB.prepare(
      "SELECT user_id FROM org_members WHERE org_id = ? AND role = 'owner'",
    )
      .bind(item.orgId)
      .all<{ user_id: string }>();
    await Promise.allSettled(
      owners.map((owner) =>
        notify(env, owner.user_id, {
          kind: 'sso_expiring',
          org: item.orgName,
          orgId: item.orgId,
          protocol: item.protocol,
          expiresAt: item.expiresAt,
          expired: days === 0,
        }),
      ),
    );
    await audit(env.DB, now, 'org.sso_expiry_warned', {
      detail: { org: item.orgId, protocol: item.protocol, days, expires_at: item.expiresAt },
    });
    told += 1;
  }
  return told;
}
