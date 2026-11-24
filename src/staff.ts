/**
 * 2earl's own staff (DESIGN §4.29). Three roles, from the most trusted:
 *
 * - **owner**: the account whose Google identity is OWNER_GOOGLE_SUB. Everything, and the only
 *   one who gives and takes staff roles.
 * - **admin**: runs 2earl: users, invitations, organizations and their setup invitations, apps.
 *   Can't give or take staff roles, and can't act on other staff.
 * - **support**: helps people and organizations: sees users, organizations and the security log,
 *   signs a person out everywhere, sends a setup invitation again. Changes nothing else.
 *
 * Every staff page needs a second factor; every change a fresh one (§4.6).
 */
/** Whether `userId` is the owner: the account whose Google identity is OWNER_GOOGLE_SUB. */
export async function isOwnerUser(env: Env, userId: string): Promise<boolean> {
  const ownerSub: string = env.OWNER_GOOGLE_SUB;
  if (ownerSub.length === 0) return false;
  const row = await env.DB.prepare(
    "SELECT 1 AS ok FROM identities WHERE user_id = ? AND provider = 'google' AND subject = ?",
  )
    .bind(userId, ownerSub)
    .first<{ ok: number }>();
  return row !== null;
}

export type StaffRole = 'owner' | 'admin' | 'support';
export type GrantableStaffRole = Exclude<StaffRole, 'owner'>;

export const STAFF_LABEL: Record<StaffRole, string> = {
  owner: 'Owner',
  admin: 'Admin',
  support: 'Support',
};

export function isGrantableStaffRole(value: unknown): value is GrantableStaffRole {
  return value === 'admin' || value === 'support';
}

/** The account's staff role, or null for everyone else. */
export async function staffRoleOf(env: Env, userId: string): Promise<StaffRole | null> {
  if (await isOwnerUser(env, userId)) return 'owner';
  const row = await env.DB.prepare('SELECT role FROM staff WHERE user_id = ?')
    .bind(userId)
    .first<{ role: GrantableStaffRole }>();
  return row?.role ?? null;
}

const runs = (role: StaffRole) => role === 'owner' || role === 'admin';
/** Every staff role. */
const anyStaff = (role: StaffRole) => STAFF_LABEL[role] !== '';

/** What each role may do; the routes only ask these. */
export const staffCan = {
  /** See /admin: users, organizations, the security log. */
  view: anyStaff,
  /** Suspend, reactivate, reset a second factor, delete. */
  manageUsers: runs,
  /** End every session and app grant of an account (lost device, hijacked session). */
  signOutUsers: anyStaff,
  /** The sign-up switch and the sign-up invitations. */
  manageSignUp: runs,
  /** Suspend, reactivate, delete organizations. */
  manageOrgs: runs,
  /** Invite someone to set up an organization, withdraw such invitations, create one directly. */
  createOrgs: runs,
  /** Send an open setup invitation again. */
  resendOrgInvitations: anyStaff,
  /** Registered apps and resource servers. */
  manageApps: runs,
  /** Give and take staff roles. */
  manageStaff: (role: StaffRole) => role === 'owner',
  /**
   * Act on `target`'s account at all: never on the owner or yourself; on other staff only as
   * the owner.
   */
  actOn: (role: StaffRole, target: StaffRole | null) =>
    target === 'owner' ? false : target === null ? true : role === 'owner',
};

export interface StaffMember {
  userId: string;
  email: string | null;
  name: string | null;
  role: GrantableStaffRole;
  grantedAt: number;
  grantedBy: string | null;
}

export async function listStaff(db: D1Database): Promise<StaffMember[]> {
  const { results } = await db
    .prepare(
      `SELECT s.user_id, s.role, s.granted_at, u.primary_email, u.display_name,
              g.primary_email AS granted_by
       FROM staff s JOIN users u ON u.id = s.user_id
       LEFT JOIN users g ON g.id = s.granted_by
       ORDER BY CASE s.role WHEN 'admin' THEN 0 ELSE 1 END, s.granted_at`,
    )
    .all<{
      user_id: string;
      role: GrantableStaffRole;
      granted_at: number;
      primary_email: string | null;
      display_name: string | null;
      granted_by: string | null;
    }>();
  return results.map((r) => ({
    userId: r.user_id,
    email: r.primary_email,
    name: r.display_name,
    role: r.role,
    grantedAt: r.granted_at,
    grantedBy: r.granted_by,
  }));
}

export type GrantResult =
  | { ok: true; userId: string; previous: GrantableStaffRole | null }
  | { ok: false; reason: 'no_account' | 'owner' | 'managed' | 'suspended' | 'same' };

/**
 * Gives `role` to the account that signs in with `email`. Not to an account an organization
 * manages: its sign-in would then be the customer's identity provider's to decide (§4.18).
 */
export async function grantStaff(
  db: D1Database,
  now: number,
  email: string,
  role: GrantableStaffRole,
  grantedBy: string,
  ownerUserId: string,
): Promise<GrantResult> {
  const user = await db
    .prepare(
      `SELECT u.id, u.status, u.managed_by, s.role AS staff_role FROM users u
       LEFT JOIN staff s ON s.user_id = u.id
       WHERE u.primary_email = ?1 COLLATE NOCASE
          OR u.id IN (SELECT user_id FROM identities WHERE email = ?1 COLLATE NOCASE AND email_verified = 1)
       LIMIT 1`,
    )
    .bind(email)
    .first<{
      id: string;
      status: string;
      managed_by: string | null;
      staff_role: GrantableStaffRole | null;
    }>();
  if (!user) return { ok: false, reason: 'no_account' };
  if (user.id === ownerUserId) return { ok: false, reason: 'owner' };
  if (user.managed_by) return { ok: false, reason: 'managed' };
  if (user.status !== 'active') return { ok: false, reason: 'suspended' };
  if (user.staff_role === role) return { ok: false, reason: 'same' };
  await db
    .prepare(
      `INSERT INTO staff (user_id, role, granted_by, granted_at) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT (user_id) DO UPDATE SET role = ?2, granted_by = ?3, granted_at = ?4`,
    )
    .bind(user.id, role, grantedBy, now)
    .run();
  return { ok: true, userId: user.id, previous: user.staff_role };
}

export async function revokeStaff(
  db: D1Database,
  userId: string,
): Promise<GrantableStaffRole | null> {
  const row = await db
    .prepare('DELETE FROM staff WHERE user_id = ? RETURNING role')
    .bind(userId)
    .first<{ role: GrantableStaffRole }>();
  return row?.role ?? null;
}
