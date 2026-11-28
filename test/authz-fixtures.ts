import { env } from 'cloudflare:workers';

/** Plain rows for authorization tests (DESIGN §4.32), without going through the pages. */

export const T0 = 1_764_300_000;

export async function resetAuthz(): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM authz_assignments'),
    env.DB.prepare('DELETE FROM authz_roles'),
    env.DB.prepare('DELETE FROM scim_group_members'),
    env.DB.prepare('DELETE FROM scim_groups'),
    env.DB.prepare('DELETE FROM scim_users'),
    env.DB.prepare('DELETE FROM org_members'),
    env.DB.prepare('DELETE FROM organizations'),
    env.DB.prepare('DELETE FROM staff'),
    env.DB.prepare('DELETE FROM identities'),
    env.DB.prepare('DELETE FROM users'),
  ]);
}

export async function user(id: string, status: 'active' | 'suspended' = 'active'): Promise<string> {
  await env.DB.prepare(
    'INSERT INTO users (id, status, primary_email, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
  )
    .bind(id, status, `${id}@example.com`, T0, T0)
    .run();
  return id;
}

/** The 2earl owner: the account whose Google identity is OWNER_GOOGLE_SUB. */
export async function owner(id: string): Promise<string> {
  await user(id);
  await env.DB.prepare(
    `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
     VALUES (?, ?, 'google', ?, ?, 1, ?, ?)`,
  )
    .bind(`idn-${id}`, id, env.OWNER_GOOGLE_SUB, `${id}@example.com`, T0, T0)
    .run();
  return id;
}

export async function staff(id: string, role: 'admin' | 'support'): Promise<void> {
  await env.DB.prepare('INSERT INTO staff (user_id, role, granted_at) VALUES (?, ?, ?)')
    .bind(id, role, T0)
    .run();
}

export async function org(id: string, status: 'active' | 'suspended' = 'active'): Promise<string> {
  await env.DB.prepare(
    'INSERT INTO organizations (id, name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
  )
    .bind(id, `Org ${id}`, status, T0, T0)
    .run();
  return id;
}

export async function member(
  orgId: string,
  userId: string,
  role: 'owner' | 'admin' | 'auditor' | 'member',
): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)',
  )
    .bind(orgId, userId, role, T0)
    .run();
}

/** A directory group with these accounts as active (or inactive) directory users. */
export async function group(
  orgId: string,
  groupId: string,
  members: { userId: string; active?: boolean }[],
): Promise<string> {
  await env.DB.prepare(
    `INSERT INTO scim_groups (id, org_id, display_name, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(groupId, orgId, `Group ${groupId}`, T0, T0)
    .run();
  for (const m of members) {
    const scimId = `scu-${orgId}-${m.userId}`;
    await env.DB.prepare(
      `INSERT INTO scim_users (id, org_id, user_name, active, user_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`,
    )
      .bind(scimId, orgId, `${m.userId}@example.com`, m.active === false ? 0 : 1, m.userId, T0, T0)
      .run();
    await env.DB.prepare('INSERT INTO scim_group_members (group_id, scim_user_id) VALUES (?, ?)')
      .bind(groupId, scimId)
      .run();
  }
  return groupId;
}
