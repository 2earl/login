/**
 * Which apps the accounts an organization manages may use (DESIGN §4.22). Off by default: then
 * they may connect any app, as everyone can. On: only apps the organization allows, for everyone
 * it manages or for the members of directory groups (§4.21). Checked when an app is authorized
 * and at every token exchange and refresh, so access ends within one access token's lifetime.
 */

export const MAX_ALLOWED_APPS = 200;
const EVERYONE = '';

export interface AppDecision {
  allowed: boolean;
  orgName: string | null;
}

/** Whether the account may use the app. Accounts no organization restricts may use any. */
export async function appAllowed(
  db: D1Database,
  userId: string,
  clientId: string,
): Promise<AppDecision> {
  const row = await db
    .prepare(
      `SELECT o.name,
              EXISTS (
                SELECT 1 FROM org_app_access a
                WHERE a.org_id = o.id AND a.client_id = ?2
                  AND (a.group_id = '' OR a.group_id IN (
                    SELECT gm.group_id FROM scim_group_members gm
                    JOIN scim_users su ON su.id = gm.scim_user_id
                    WHERE su.org_id = o.id AND su.user_id = u.id AND su.active = 1))
              ) AS allowed
       FROM users u JOIN organizations o
         ON o.id = u.managed_by AND o.status = 'active' AND o.restrict_apps = 1
       WHERE u.id = ?1`,
    )
    .bind(userId, clientId)
    .first<{ name: string; allowed: number }>();
  return row ? { allowed: row.allowed === 1, orgName: row.name } : { allowed: true, orgName: null };
}

export interface AllowedApp {
  clientId: string;
  /** '' for everyone. */
  groupId: string;
  groupName: string | null;
}

export async function listAllowedApps(db: D1Database, orgId: string): Promise<AllowedApp[]> {
  const { results } = await db
    .prepare(
      `SELECT a.client_id, a.group_id, g.display_name FROM org_app_access a
       LEFT JOIN scim_groups g ON g.id = a.group_id
       WHERE a.org_id = ? ORDER BY a.client_id, a.group_id`,
    )
    .bind(orgId)
    .all<{ client_id: string; group_id: string; display_name: string | null }>();
  return results.map((r) => ({
    clientId: r.client_id,
    groupId: r.group_id,
    groupName: r.display_name,
  }));
}

export async function restrictsApps(db: D1Database, orgId: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT restrict_apps FROM organizations WHERE id = ?')
    .bind(orgId)
    .first<{ restrict_apps: number }>();
  return row?.restrict_apps === 1;
}

export async function setRestrictApps(
  db: D1Database,
  now: number,
  orgId: string,
  on: boolean,
): Promise<void> {
  await db
    .prepare('UPDATE organizations SET restrict_apps = ?, updated_at = ? WHERE id = ?')
    .bind(on ? 1 : 0, now, orgId)
    .run();
}

/** Allows an app, for everyone or a group of this organization. False if it can't be added. */
export async function allowApp(
  db: D1Database,
  now: number,
  orgId: string,
  clientId: string,
  groupId: string,
): Promise<'added' | 'unknown_group' | 'too_many'> {
  if (groupId !== EVERYONE) {
    const group = await db
      .prepare('SELECT 1 AS ok FROM scim_groups WHERE id = ? AND org_id = ?')
      .bind(groupId, orgId)
      .first<{ ok: number }>();
    if (!group) return 'unknown_group';
  }
  const result = await db
    .prepare(
      `INSERT INTO org_app_access (org_id, client_id, group_id, created_at)
       SELECT ?1, ?2, ?3, ?4
       WHERE (SELECT COUNT(*) FROM org_app_access WHERE org_id = ?1) < ?5
       ON CONFLICT DO NOTHING`,
    )
    .bind(orgId, clientId, groupId, now, MAX_ALLOWED_APPS)
    .run();
  if (result.meta.changes > 0) return 'added';
  const exists = await db
    .prepare(
      'SELECT 1 AS ok FROM org_app_access WHERE org_id = ? AND client_id = ? AND group_id = ?',
    )
    .bind(orgId, clientId, groupId)
    .first<{ ok: number }>();
  return exists ? 'added' : 'too_many';
}

export async function disallowApp(
  db: D1Database,
  orgId: string,
  clientId: string,
  groupId: string,
): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM org_app_access WHERE org_id = ? AND client_id = ? AND group_id = ?')
    .bind(orgId, clientId, groupId)
    .run();
  return result.meta.changes > 0;
}

/**
 * Apps the people this organization manages connected in the last 90 days (from the security
 * log, which keeps 90 days), so an owner can allow them without typing client IDs.
 */
export async function appsInUse(db: D1Database, orgId: string): Promise<string[]> {
  const { results } = await db
    .prepare(
      `SELECT DISTINCT e.client_id FROM audit_events e
       JOIN users u ON u.id = e.actor_user_id AND u.managed_by = ?
       WHERE e.event IN ('consent.approved', 'consent.reused') AND e.client_id IS NOT NULL
       ORDER BY e.client_id LIMIT 100`,
    )
    .bind(orgId)
    .all<{ client_id: string }>();
  return results.map((r) => r.client_id);
}
