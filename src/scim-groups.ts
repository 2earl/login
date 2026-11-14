import { audit } from './audit';
import { randomToken } from './crypto';

/**
 * Groups from an organization's directory (SCIM 2.0 Groups, DESIGN §4.21). A group holds
 * provisioned users (`scim_users`); an owner can give a group's members the admin role. Once any
 * group has a role, the directory decides admin or member for every account it provisioned;
 * owners are never changed, and nobody is made an owner by the directory.
 */

export const MAX_GROUPS = 500;
export const MAX_GROUP_MEMBERS = 5000;

export interface ScimGroupRow {
  id: string;
  org_id: string;
  display_name: string;
  external_id: string | null;
  role: 'admin' | null;
  created_at: number;
  updated_at: number;
}

export interface GroupInput {
  displayName: string;
  externalId: string | null;
  /** SCIM user IDs; null leaves members as they are. */
  members: string[] | null;
}

export async function findGroup(
  db: D1Database,
  orgId: string,
  id: string,
): Promise<ScimGroupRow | null> {
  return db
    .prepare('SELECT * FROM scim_groups WHERE id = ? AND org_id = ?')
    .bind(id, orgId)
    .first<ScimGroupRow>();
}

export async function groupMembers(
  db: D1Database,
  groupId: string,
): Promise<{ id: string; userName: string }[]> {
  const { results } = await db
    .prepare(
      `SELECT u.id, u.user_name FROM scim_group_members gm JOIN scim_users u ON u.id = gm.scim_user_id
       WHERE gm.group_id = ? ORDER BY u.user_name`,
    )
    .bind(groupId)
    .all<{ id: string; user_name: string }>();
  return results.map((r) => ({ id: r.id, userName: r.user_name }));
}

/** Keeps only IDs of users this organization's directory provisioned; unknown ones are skipped. */
async function knownUsers(db: D1Database, orgId: string, ids: string[]): Promise<string[]> {
  const unique = [...new Set(ids)].slice(0, MAX_GROUP_MEMBERS);
  const known: string[] = [];
  // D1 limits bound parameters per statement: check in slices.
  for (let i = 0; i < unique.length; i += 90) {
    const slice = unique.slice(i, i + 90);
    const { results } = await db
      .prepare(
        `SELECT id FROM scim_users WHERE org_id = ? AND id IN (${slice.map(() => '?').join(',')})`,
      )
      .bind(orgId, ...slice)
      .all<{ id: string }>();
    known.push(...results.map((r) => r.id));
  }
  return known;
}

/** Creates or replaces a group. Null when the name is taken or there are too many groups. */
export async function saveGroup(
  db: D1Database,
  now: number,
  orgId: string,
  input: GroupInput,
  existing: ScimGroupRow | null,
): Promise<ScimGroupRow | 'name_taken' | 'too_many'> {
  let row: ScimGroupRow | null;
  try {
    if (existing) {
      row = await db
        .prepare(
          `UPDATE scim_groups SET display_name = ?, external_id = ?, updated_at = ?
           WHERE id = ? AND org_id = ? RETURNING *`,
        )
        .bind(input.displayName, input.externalId, now, existing.id, orgId)
        .first<ScimGroupRow>();
    } else {
      const count = await db
        .prepare('SELECT COUNT(*) AS n FROM scim_groups WHERE org_id = ?')
        .bind(orgId)
        .first<{ n: number }>();
      if ((count?.n ?? 0) >= MAX_GROUPS) return 'too_many';
      row = await db
        .prepare(
          `INSERT INTO scim_groups (id, org_id, display_name, external_id, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?) RETURNING *`,
        )
        .bind(`scg_${randomToken(12)}`, orgId, input.displayName, input.externalId, now, now)
        .first<ScimGroupRow>();
    }
  } catch (error) {
    if (error instanceof Error && /UNIQUE/i.test(error.message)) return 'name_taken';
    throw error;
  }
  if (!row) return 'name_taken';
  if (input.members !== null) await setMembers(db, now, row, input.members);
  return row;
}

/** Replaces the group's members. */
export async function setMembers(
  db: D1Database,
  now: number,
  group: ScimGroupRow,
  ids: string[],
): Promise<void> {
  const known = await knownUsers(db, group.org_id, ids);
  await db.batch([
    db.prepare('DELETE FROM scim_group_members WHERE group_id = ?').bind(group.id),
    ...known.map((id) =>
      db
        .prepare('INSERT INTO scim_group_members (group_id, scim_user_id) VALUES (?, ?)')
        .bind(group.id, id),
    ),
    db.prepare('UPDATE scim_groups SET updated_at = ? WHERE id = ?').bind(now, group.id),
  ]);
}

export async function addMembers(
  db: D1Database,
  now: number,
  group: ScimGroupRow,
  ids: string[],
): Promise<void> {
  const known = await knownUsers(db, group.org_id, ids);
  if (known.length === 0) return;
  await db.batch([
    ...known.map((id) =>
      db
        .prepare(
          `INSERT INTO scim_group_members (group_id, scim_user_id)
           SELECT ?1, ?2 WHERE (SELECT COUNT(*) FROM scim_group_members WHERE group_id = ?1) < ?3
           ON CONFLICT DO NOTHING`,
        )
        .bind(group.id, id, MAX_GROUP_MEMBERS),
    ),
    db.prepare('UPDATE scim_groups SET updated_at = ? WHERE id = ?').bind(now, group.id),
  ]);
}

export async function removeMembers(
  db: D1Database,
  now: number,
  group: ScimGroupRow,
  ids: string[] | 'all',
): Promise<void> {
  if (ids === 'all') {
    await setMembers(db, now, group, []);
    return;
  }
  await db.batch([
    ...ids.map((id) =>
      db
        .prepare('DELETE FROM scim_group_members WHERE group_id = ? AND scim_user_id = ?')
        .bind(group.id, id),
    ),
    db.prepare('UPDATE scim_groups SET updated_at = ? WHERE id = ?').bind(now, group.id),
  ]);
}

// ---- Roles --------------------------------------------------------------------------------------

/** Whether the directory decides roles in this organization: some group has a role. */
export async function directoryDecidesRoles(db: D1Database, orgId: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS ok FROM scim_groups WHERE org_id = ? AND role = 'admin' LIMIT 1")
    .bind(orgId)
    .first<{ ok: number }>();
  return row !== null;
}

/**
 * Makes roles follow the groups: admin for members of a group with the admin role, member for
 * everyone else the directory provisioned. Owners, and accounts the directory didn't provision,
 * keep their roles. Nothing happens while no group has a role.
 */
export async function syncRoles(db: D1Database, now: number, orgId: string): Promise<number> {
  const { results } = await db
    .prepare(
      `UPDATE org_members AS m
       SET role = CASE WHEN EXISTS (
             SELECT 1 FROM scim_users su
             JOIN scim_group_members gm ON gm.scim_user_id = su.id
             JOIN scim_groups g ON g.id = gm.group_id AND g.role = 'admin'
             WHERE su.org_id = ?1 AND su.user_id = m.user_id AND su.active = 1) THEN 'admin' ELSE 'member' END
       WHERE m.org_id = ?1 AND m.role != 'owner'
         AND EXISTS (SELECT 1 FROM scim_groups WHERE org_id = ?1 AND role = 'admin')
         AND EXISTS (SELECT 1 FROM scim_users WHERE org_id = ?1 AND user_id = m.user_id)
         AND m.role != CASE WHEN EXISTS (
             SELECT 1 FROM scim_users su
             JOIN scim_group_members gm ON gm.scim_user_id = su.id
             JOIN scim_groups g ON g.id = gm.group_id AND g.role = 'admin'
             WHERE su.org_id = ?1 AND su.user_id = m.user_id AND su.active = 1) THEN 'admin' ELSE 'member' END
       RETURNING user_id, role`,
    )
    .bind(orgId)
    .all<{ user_id: string; role: string }>();
  for (const row of results) {
    await audit(db, now, 'scim.role_changed', {
      detail: { org: orgId, target: row.user_id, role: row.role },
    });
  }
  return results.length;
}

/** Gives a group's members a role (or none), then makes roles follow. */
export async function setGroupRole(
  db: D1Database,
  now: number,
  orgId: string,
  groupId: string,
  role: 'admin' | null,
): Promise<boolean> {
  const result = await db
    .prepare('UPDATE scim_groups SET role = ?, updated_at = ? WHERE id = ? AND org_id = ?')
    .bind(role, now, groupId, orgId)
    .run();
  if (result.meta.changes === 0) return false;
  await syncRoles(db, now, orgId);
  return true;
}

export interface GroupSummary {
  id: string;
  name: string;
  members: number;
  role: 'admin' | null;
}

export async function listGroups(db: D1Database, orgId: string): Promise<GroupSummary[]> {
  const { results } = await db
    .prepare(
      `SELECT g.id, g.display_name, g.role,
              (SELECT COUNT(*) FROM scim_group_members gm WHERE gm.group_id = g.id) AS members
       FROM scim_groups g WHERE g.org_id = ? ORDER BY g.display_name COLLATE NOCASE LIMIT ?`,
    )
    .bind(orgId, MAX_GROUPS)
    .all<{ id: string; display_name: string; role: 'admin' | null; members: number }>();
  return results.map((r) => ({ id: r.id, name: r.display_name, members: r.members, role: r.role }));
}
