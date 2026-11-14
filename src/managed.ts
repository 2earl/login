import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';
import { revokeAllGrants } from './account';
import { audit } from './audit';
import { MAX_MEMBERSHIPS } from './orgs';

/**
 * Accounts an organization manages (DESIGN §4.18). An owner turns on managing for a verified
 * domain; accounts made at that domain are managed from the start, and existing ones are managed
 * once their person agrees. The organization can then deactivate, reactivate and delete them, and
 * require its single sign-on.
 */

/** A directory's DELETE takes effect after this long, unless the account is reactivated first. */
export const DELETE_AFTER_SECONDS = 30 * 24 * 60 * 60;
/** Notices sent when a domain becomes managed; the rest see the choice when they next sign in. */
const MAX_NOTICES = 200;

/** The part after the last @, lower case. */
export function domainOf(email: string): string {
  return email.slice(email.lastIndexOf('@') + 1).toLowerCase();
}

/**
 * SQL for "this identity's address is at a domain organization `org` manages". `i` is the
 * identities row, `org` an SQL expression.
 */
const AT_MANAGED_DOMAIN = (org: string) =>
  `EXISTS (SELECT 1 FROM org_domains d
           WHERE d.org_id = ${org} AND d.managed_at IS NOT NULL AND d.verified_at IS NOT NULL
             AND d.domain = substr(i.email, instr(i.email, '@') + 1) COLLATE NOCASE)`;

export interface ManagingOrg {
  orgId: string;
  name: string;
}

/** The active organization that manages accounts at the address's domain, if any. */
export async function managingOrgFor(db: D1Database, email: string): Promise<ManagingOrg | null> {
  const domain = domainOf(email);
  if (!domain) return null;
  const row = await db
    .prepare(
      `SELECT o.id, o.name FROM org_domains d JOIN organizations o ON o.id = d.org_id
       WHERE d.domain = ? AND d.verified_at IS NOT NULL AND d.managed_at IS NOT NULL
         AND o.status = 'active'`,
    )
    .bind(domain)
    .first<{ id: string; name: string }>();
  return row ? { orgId: row.id, name: row.name } : null;
}

/** The organization that manages the account, if any. */
export async function managerOf(db: D1Database, userId: string): Promise<ManagingOrg | null> {
  const row = await db
    .prepare(
      `SELECT o.id, o.name FROM users u JOIN organizations o ON o.id = u.managed_by
       WHERE u.id = ?`,
    )
    .bind(userId)
    .first<{ id: string; name: string }>();
  return row ? { orgId: row.id, name: row.name } : null;
}

/** Makes the account managed by `orgId` and a member of it. False when the account can't join. */
async function manage(
  db: D1Database,
  now: number,
  userId: string,
  orgId: string,
  how: 'created' | 'joined',
): Promise<boolean> {
  const [membership, managed] = await db.batch([
    db
      .prepare(
        `INSERT INTO org_members (org_id, user_id, role, joined_at)
         SELECT ?1, ?2, 'member', ?3
         WHERE (SELECT COUNT(*) FROM org_members WHERE user_id = ?2) < ?4
         ON CONFLICT (org_id, user_id) DO NOTHING`,
      )
      .bind(orgId, userId, now, MAX_MEMBERSHIPS),
    db
      .prepare(
        `UPDATE users SET managed_by = ?1, managed_since = ?3, updated_at = ?3
         WHERE id = ?2 AND managed_by IS NULL
           AND EXISTS (SELECT 1 FROM org_members WHERE org_id = ?1 AND user_id = ?2)`,
      )
      .bind(orgId, userId, now),
  ]);
  if (!managed || managed.meta.changes === 0) return false;
  if (membership && membership.meta.changes > 0) {
    await audit(db, now, 'org.joined', {
      actorUserId: userId,
      detail: { org: orgId, via: 'managed' },
    });
  }
  await audit(db, now, 'org.account_managed', {
    actorUserId: userId,
    detail: { org: orgId, how },
  });
  return true;
}

/**
 * A new account at a managed domain is managed from the start (DESIGN §4.18). Call right after
 * creating it. Returns the organization, if one manages it now.
 */
export async function adoptNewAccount(
  db: D1Database,
  now: number,
  userId: string,
  email: string,
): Promise<ManagingOrg | null> {
  const org = await managingOrgFor(db, email);
  if (!org) return null;
  return (await manage(db, now, userId, org.orgId, 'created')) ? org : null;
}

export interface PendingChoice {
  orgId: string;
  orgName: string;
  /** The account's addresses at the organization's managed domains. */
  addresses: string[];
  /** False when another organization already manages the account: the addresses can only go. */
  canJoin: boolean;
  /** Whether the account keeps a way in without those addresses. */
  hasOtherWay: boolean;
}

/**
 * The organization this account must answer, if any: one that manages a domain where the account
 * has a verified address, but doesn't manage the account. Session gate (DESIGN §4.18).
 */
export async function pendingChoice(db: D1Database, userId: string): Promise<PendingChoice | null> {
  const row = await db
    .prepare(
      `SELECT d.org_id, o.name, u.managed_by FROM identities i
       JOIN users u ON u.id = i.user_id
       JOIN org_domains d ON d.managed_at IS NOT NULL AND d.verified_at IS NOT NULL
         AND d.domain = substr(i.email, instr(i.email, '@') + 1) COLLATE NOCASE
       JOIN organizations o ON o.id = d.org_id AND o.status = 'active'
       WHERE i.user_id = ? AND i.email_verified = 1 AND d.org_id IS NOT u.managed_by
       ORDER BY d.managed_at LIMIT 1`,
    )
    .bind(userId)
    .first<{ org_id: string; name: string; managed_by: string | null }>();
  if (!row) return null;
  const { results } = await db
    .prepare(
      `SELECT i.email, ${AT_MANAGED_DOMAIN('?2')} AS managed FROM identities i
       WHERE i.user_id = ?1 ORDER BY i.created_at`,
    )
    .bind(userId, row.org_id)
    .all<{ email: string | null; managed: number }>();
  const addresses = [
    ...new Set(results.filter((r) => r.managed === 1 && r.email).map((r) => r.email as string)),
  ];
  return {
    orgId: row.org_id,
    orgName: row.name,
    addresses,
    canJoin: row.managed_by === null,
    hasOtherWay: results.some((r) => r.managed !== 1),
  };
}

/** The person agreed: the organization manages the account from now on. */
export async function joinManaged(
  db: D1Database,
  now: number,
  userId: string,
  orgId: string,
): Promise<'joined' | 'too_many' | 'stale'> {
  const choice = await pendingChoice(db, userId);
  if (choice?.orgId !== orgId || !choice.canJoin) return 'stale';
  return (await manage(db, now, userId, orgId, 'joined')) ? 'joined' : 'too_many';
}

/**
 * The person keeps the account their own: every sign-in method with an address at the
 * organization's managed domains goes. Refused when nothing else would be left.
 */
export async function keepPersonal(
  db: D1Database,
  now: number,
  userId: string,
  orgId: string,
): Promise<'kept' | 'no_other_way' | 'stale'> {
  const choice = await pendingChoice(db, userId);
  if (choice?.orgId !== orgId) return 'stale';
  if (!choice.hasOtherWay) return 'no_other_way';
  await db.batch([
    db
      .prepare(`DELETE FROM identities AS i WHERE i.user_id = ?1 AND ${AT_MANAGED_DOMAIN('?2')}`)
      .bind(userId, orgId),
    // The account's address moves to one it keeps.
    db
      .prepare(
        `UPDATE users SET updated_at = ?3,
           primary_email = (SELECT email FROM identities WHERE user_id = ?1 AND email IS NOT NULL
                            ORDER BY created_at LIMIT 1)
         WHERE id = ?1 AND (primary_email IS NULL OR substr(primary_email, instr(primary_email, '@') + 1)
           IN (SELECT domain FROM org_domains WHERE org_id = ?2 AND managed_at IS NOT NULL))`,
      )
      .bind(userId, orgId, now),
  ]);
  await audit(db, now, 'org.account_kept_personal', {
    actorUserId: userId,
    detail: { org: orgId, removed: choice.addresses.length },
  });
  return 'kept';
}

// ---- Managing a domain ------------------------------------------------------------------------

/**
 * Turns managing on or off for a verified domain. On: returns the accounts to tell (existing
 * accounts at the domain, which choose at their next sign-in). Off: releases the accounts that
 * were managed only through this domain.
 */
export async function setDomainManaged(
  db: D1Database,
  now: number,
  orgId: string,
  domain: string,
  on: boolean,
): Promise<{ changed: boolean; notify: string[] }> {
  if (!on) {
    const result = await db
      .prepare(
        'UPDATE org_domains SET managed_at = NULL WHERE org_id = ? AND domain = ? AND managed_at IS NOT NULL',
      )
      .bind(orgId, domain)
      .run();
    if (result.meta.changes > 0) await releaseAccounts(db, now, orgId);
    return { changed: result.meta.changes > 0, notify: [] };
  }
  const result = await db
    .prepare(
      `UPDATE org_domains SET managed_at = ?
       WHERE org_id = ? AND domain = ? AND verified_at IS NOT NULL AND managed_at IS NULL`,
    )
    .bind(now, orgId, domain)
    .run();
  if (result.meta.changes === 0) return { changed: false, notify: [] };
  const { results } = await db
    .prepare(
      `SELECT DISTINCT i.user_id FROM identities i JOIN users u ON u.id = i.user_id
       WHERE i.email_verified = 1 AND u.status = 'active' AND u.managed_by IS NOT ?1
         AND substr(i.email, instr(i.email, '@') + 1) = ?2 COLLATE NOCASE
       LIMIT ?3`,
    )
    .bind(orgId, domain, MAX_NOTICES)
    .all<{ user_id: string }>();
  return { changed: true, notify: results.map((r) => r.user_id) };
}

/**
 * Accounts the organization manages without an address at a domain it still manages become
 * their people's own again: still members, deactivated ones still deactivated, pending deletions
 * cancelled. Run after a domain stops being managed, is removed, or the organization is deleted.
 */
export async function releaseAccounts(db: D1Database, now: number, orgId: string): Promise<number> {
  const result = await db.batch(releaseStatements(db, now, orgId));
  const released = result[0]?.meta.changes ?? 0;
  if (released > 0) {
    await audit(db, now, 'org.accounts_released', { detail: { org: orgId, count: released } });
  }
  return released;
}

/** The release, as statements (also for the organization's deletion, with `all`). */
export function releaseStatements(
  db: D1Database,
  now: number,
  orgId: string,
  all = false,
): D1PreparedStatement[] {
  return [
    db
      .prepare(
        `UPDATE users SET managed_by = NULL, managed_since = NULL, delete_after = NULL, updated_at = ?2
         WHERE managed_by = ?1 ${
           all
             ? ''
             : `AND NOT EXISTS (SELECT 1 FROM identities i
                                WHERE i.user_id = users.id AND i.email_verified = 1
                                  AND ${AT_MANAGED_DOMAIN('?1')})`
         }`,
      )
      .bind(orgId, now),
  ];
}

// ---- What the organization does with its accounts -------------------------------------------

/** Whether the account is managed by `orgId`. */
export async function isManagedBy(db: D1Database, userId: string, orgId: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT 1 AS ok FROM users WHERE id = ? AND managed_by = ?')
    .bind(userId, orgId)
    .first<{ ok: number }>();
  return row !== null;
}

/**
 * Deactivates a managed account: no sign-in, sessions ended, every app's access revoked. The
 * account and its data stay. `deleteAfter` schedules the deletion (a directory's DELETE).
 */
export async function deactivate(
  db: D1Database,
  oauth: OAuthHelpers,
  now: number,
  userId: string,
  orgId: string,
  deleteAfter: number | null = null,
): Promise<boolean> {
  const [updated] = await db.batch([
    db
      .prepare(
        `UPDATE users SET status = 'suspended', deactivated_at = COALESCE(deactivated_at, ?3),
           delete_after = COALESCE(?4, delete_after), updated_at = ?3
         WHERE id = ?1 AND managed_by = ?2
           AND (status = 'active' OR deactivated_at IS NOT NULL)`,
      )
      .bind(userId, orgId, now, deleteAfter),
    db
      .prepare(
        `DELETE FROM sessions WHERE user_id = ?1
           AND EXISTS (SELECT 1 FROM users WHERE id = ?1 AND managed_by = ?2)`,
      )
      .bind(userId, orgId),
  ]);
  if (!updated || updated.meta.changes === 0) return false;
  await revokeAllGrants(oauth, userId);
  return true;
}

/** Lifts the organization's own deactivation, and a scheduled deletion; never 2earl's suspension. */
export async function reactivate(
  db: D1Database,
  now: number,
  userId: string,
  orgId: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE users SET status = 'active', deactivated_at = NULL, delete_after = NULL, updated_at = ?3
       WHERE id = ?1 AND managed_by = ?2 AND deactivated_at IS NOT NULL`,
    )
    .bind(userId, orgId, now)
    .run();
  return result.meta.changes > 0;
}

/** Managed accounts whose scheduled deletion is due (daily clean-up). */
export async function dueDeletions(db: D1Database, now: number, limit = 20): Promise<string[]> {
  const { results } = await db
    .prepare(
      `SELECT id FROM users
       WHERE delete_after IS NOT NULL AND delete_after <= ?
         AND managed_by IS NOT NULL AND deactivated_at IS NOT NULL
       ORDER BY delete_after LIMIT ?`,
    )
    .bind(now, limit)
    .all<{ id: string }>();
  return results.map((r) => r.id);
}

// ---- Required single sign-on --------------------------------------------------------------------

/** SQL: the organization `org` has single sign-on on, SAML or OpenID Connect (§4.17, §4.20). */
export const ssoOnSql = (org: string) =>
  `(EXISTS (SELECT 1 FROM org_saml WHERE org_id = ${org} AND enabled = 1)
    OR EXISTS (SELECT 1 FROM org_oidc WHERE org_id = ${org} AND enabled = 1))`;

/** Whether the organization has single sign-on on. */
export async function ssoOn(db: D1Database, orgId: string): Promise<boolean> {
  const row = await db
    .prepare(`SELECT ${ssoOnSql('?1')} AS ok`)
    .bind(orgId)
    .first<{ ok: number }>();
  return row?.ok === 1;
}

/**
 * SQL: the account `u` must sign in through its organization's SSO. Owners are exempt; the rule
 * applies only while the organization is active and its SSO is on.
 */
export const SSO_REQUIRED_SQL = `EXISTS (
  SELECT 1 FROM organizations o
  WHERE o.id = u.managed_by AND o.require_sso = 1 AND o.status = 'active'
    AND ${ssoOnSql('o.id')}
    AND NOT EXISTS (SELECT 1 FROM org_members m
                    WHERE m.org_id = o.id AND m.user_id = u.id AND m.role = 'owner'))`;

/** The organization whose SSO this account must use, if any. */
export async function ssoRequiredBy(db: D1Database, userId: string): Promise<ManagingOrg | null> {
  const row = await db
    .prepare(
      `SELECT o.id, o.name FROM users u JOIN organizations o ON o.id = u.managed_by
       WHERE u.id = ? AND ${SSO_REQUIRED_SQL}`,
    )
    .bind(userId)
    .first<{ id: string; name: string }>();
  return row ? { orgId: row.id, name: row.name } : null;
}

/** Turns required SSO on or off. Ends the sessions it no longer allows. */
export async function setRequireSso(
  db: D1Database,
  now: number,
  orgId: string,
  on: boolean,
): Promise<number> {
  const statements = [
    db
      .prepare('UPDATE organizations SET require_sso = ?, updated_at = ? WHERE id = ?')
      .bind(on ? 1 : 0, now, orgId),
  ];
  if (on) {
    statements.push(
      db
        .prepare(
          `DELETE FROM sessions WHERE (method IS NULL OR method NOT IN ('saml', 'oidc'))
             AND user_id IN (SELECT u.id FROM users u WHERE u.managed_by = ? AND ${SSO_REQUIRED_SQL})`,
        )
        .bind(orgId),
    );
  }
  const results = await db.batch(statements);
  return results[1]?.meta.changes ?? 0;
}

/** Counts for the organization's directory page. */
export async function managedCounts(
  db: D1Database,
  orgId: string,
): Promise<{ managed: number; deactivated: number }> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS managed, SUM(CASE WHEN deactivated_at IS NOT NULL THEN 1 ELSE 0 END) AS deactivated
       FROM users WHERE managed_by = ?`,
    )
    .bind(orgId)
    .first<{ managed: number; deactivated: number | null }>();
  return { managed: row?.managed ?? 0, deactivated: row?.deactivated ?? 0 };
}
