import { audit } from './audit';
import { randomToken, sha256Hex } from './crypto';
import { MAX_MEMBERSHIPS } from './orgs';

/**
 * SCIM 2.0 provisioning (RFC 7643, 7644; DESIGN §4.16): what an organization's directory
 * (Okta, Microsoft Entra ID and others) may do to its members. Routes are in scim-routes.ts.
 *
 * A provisioned user is an address at one of the organization's verified domains. It never
 * creates a 2earl account: the person who signs in with that address (now or later) becomes a
 * member while the directory says they're active, and stops being one when it says otherwise.
 */

export const MAX_SCIM_TOKENS = 2;
export const SCIM_TOKEN_PREFIX = 'scim_';

// ---- Credentials --------------------------------------------------------------------------------

export interface ScimTokenInfo {
  id: string;
  createdAt: number;
  lastUsedAt: number | null;
}

export async function listScimTokens(db: D1Database, orgId: string): Promise<ScimTokenInfo[]> {
  const { results } = await db
    .prepare(
      'SELECT id, created_at, last_used_at FROM scim_tokens WHERE org_id = ? ORDER BY created_at',
    )
    .bind(orgId)
    .all<{ id: string; created_at: number; last_used_at: number | null }>();
  return results.map((r) => ({ id: r.id, createdAt: r.created_at, lastUsedAt: r.last_used_at }));
}

/** A new token, returned this once; null when the organization already has two (rotate first). */
export async function createScimToken(
  db: D1Database,
  now: number,
  orgId: string,
): Promise<{ id: string; token: string } | null> {
  const id = `st_${randomToken(9)}`;
  const token = `${SCIM_TOKEN_PREFIX}${randomToken(32)}`;
  const result = await db
    .prepare(
      `INSERT INTO scim_tokens (id, org_id, token_hash, created_at)
       SELECT ?1, ?2, ?3, ?4 WHERE (SELECT COUNT(*) FROM scim_tokens WHERE org_id = ?2) < ?5`,
    )
    .bind(id, orgId, await sha256Hex(token), now, MAX_SCIM_TOKENS)
    .run();
  return result.meta.changes > 0 ? { id, token } : null;
}

export async function revokeScimToken(db: D1Database, orgId: string, id: string) {
  const result = await db
    .prepare('DELETE FROM scim_tokens WHERE id = ? AND org_id = ?')
    .bind(id, orgId)
    .run();
  return result.meta.changes > 0;
}

/** The organization a bearer token belongs to: active organizations only. */
export async function orgForScimToken(
  db: D1Database,
  now: number,
  token: string,
): Promise<string | null> {
  if (!token.startsWith(SCIM_TOKEN_PREFIX) || token.length > 200) return null;
  const row = await db
    .prepare(
      `UPDATE scim_tokens SET last_used_at = ?
       WHERE token_hash = ? AND org_id IN (SELECT id FROM organizations WHERE status = 'active')
       RETURNING org_id`,
    )
    .bind(now, await sha256Hex(token))
    .first<{ org_id: string }>();
  return row?.org_id ?? null;
}

// ---- Users --------------------------------------------------------------------------------------

export interface ScimUserRow {
  id: string;
  org_id: string;
  user_name: string;
  external_id: string | null;
  display_name: string | null;
  given_name: string | null;
  family_name: string | null;
  active: number;
  user_id: string | null;
  created_at: number;
  updated_at: number;
}

export interface ScimUserInput {
  userName: string;
  externalId: string | null;
  displayName: string | null;
  givenName: string | null;
  familyName: string | null;
  active: boolean;
}

/** The one active account that signs in with `email` (a verified address), or null. */
export async function accountFor(db: D1Database, email: string): Promise<string | null> {
  const { results } = await db
    .prepare(
      `SELECT DISTINCT u.id FROM users u
       LEFT JOIN identities i ON i.user_id = u.id AND i.email = ?1 COLLATE NOCASE AND i.email_verified = 1
       WHERE u.status = 'active' AND (i.id IS NOT NULL OR u.primary_email = ?1 COLLATE NOCASE)
       LIMIT 2`,
    )
    .bind(email)
    .all<{ id: string }>();
  return results.length === 1 && results[0] ? results[0].id : null;
}

/**
 * Makes membership follow the directory for one provisioned user: links the account that signs in
 * with the address, then adds it as a member while active, or removes it while inactive. The last
 * owner is never removed; returns false then, so the caller can say so.
 */
export async function syncMembership(
  db: D1Database,
  now: number,
  row: ScimUserRow,
): Promise<boolean> {
  let userId = row.user_id;
  if (!userId && row.active) {
    userId = await accountFor(db, row.user_name);
    if (userId) {
      await db
        .prepare('UPDATE scim_users SET user_id = ? WHERE id = ? AND user_id IS NULL')
        .bind(userId, row.id)
        .run();
    }
  }
  if (!userId) return true;
  if (row.active) {
    const added = await db
      .prepare(
        `INSERT INTO org_members (org_id, user_id, role, joined_at)
         SELECT ?1, ?2, 'member', ?3
         WHERE (SELECT COUNT(*) FROM org_members WHERE user_id = ?2) < ?4
         ON CONFLICT (org_id, user_id) DO NOTHING`,
      )
      .bind(row.org_id, userId, now, MAX_MEMBERSHIPS)
      .run();
    if (added.meta.changes > 0) {
      await audit(db, now, 'scim.member_added', { detail: { org: row.org_id, target: userId } });
    }
    return true;
  }
  const member = await db
    .prepare('SELECT 1 AS ok FROM org_members WHERE org_id = ? AND user_id = ?')
    .bind(row.org_id, userId)
    .first<{ ok: number }>();
  if (!member) return true;
  const removed = await db
    .prepare(
      `DELETE FROM org_members
       WHERE org_id = ?1 AND user_id = ?2
         AND (role != 'owner'
              OR (SELECT COUNT(*) FROM org_members WHERE org_id = ?1 AND role = 'owner') > 1)`,
    )
    .bind(row.org_id, userId)
    .run();
  if (removed.meta.changes === 0) return false;
  await audit(db, now, 'scim.member_removed', { detail: { org: row.org_id, target: userId } });
  return true;
}

/**
 * At sign-in: memberships the directory provisioned for this account's addresses before the
 * account existed (or before it had the address). Never fails a sign-in.
 */
export async function claimProvisioned(db: D1Database, now: number, userId: string): Promise<void> {
  try {
    const { results } = await db
      .prepare(
        `SELECT s.* FROM scim_users s
         JOIN organizations o ON o.id = s.org_id AND o.status = 'active'
         JOIN org_domains d ON d.org_id = s.org_id AND d.verified_at IS NOT NULL
           AND d.domain = substr(s.user_name, instr(s.user_name, '@') + 1) COLLATE NOCASE
         WHERE s.user_id IS NULL AND s.active = 1
           AND s.user_name IN (
             SELECT email FROM identities WHERE user_id = ?1 AND email_verified = 1
             UNION SELECT primary_email FROM users WHERE id = ?1 AND primary_email IS NOT NULL)
         LIMIT 20`,
      )
      .bind(userId)
      .all<ScimUserRow>();
    for (const row of results) await syncMembership(db, now, row);
  } catch (error) {
    console.error('scim claim failed', error instanceof Error ? error.name : 'unknown');
  }
}
