import { hmacHex, randomToken } from './crypto';
import { SERVICES } from './services';

/**
 * Organizations and roles (DESIGN §4.14). A team of 2earl accounts; each member is an owner, an
 * admin or a member. What each role may do is decided here, by `can*`, and the routes only ask.
 * An organization always keeps at least one owner: every statement that could remove the last one
 * checks it in SQL, so two requests at once can't both succeed.
 */

export type OrgRole = 'owner' | 'admin' | 'member';
export const ORG_ROLES: readonly OrgRole[] = ['owner', 'admin', 'member'];
export const ROLE_LABEL: Record<OrgRole, string> = {
  owner: 'Owner',
  admin: 'Admin',
  member: 'Member',
};

export const INVITATION_TTL_SECONDS = 7 * 24 * 60 * 60;
/** Organizations one account can belong to. */
export const MAX_MEMBERSHIPS = 50;
/** Members plus open invitations, per organization. */
export const MAX_SEATS = 1000;
/** Open invitations per organization. */
export const MAX_OPEN_INVITATIONS = 100;
/** Invitation emails one account can send in 24 hours, across organizations. */
export const MAX_INVITATIONS_PER_DAY = 50;
export const ORG_NAME_MAX = 60;

export function isOrgRole(value: unknown): value is OrgRole {
  return typeof value === 'string' && (ORG_ROLES as readonly string[]).includes(value);
}

// ---- Who may do what ----------------------------------------------------------------------------

/** Invite people and withdraw invitations. */
export const canInvite = (actor: OrgRole): boolean => actor !== 'member';

/** Change `target`'s role to `next`. Only owners make or unmake owners. */
export function canSetRole(actor: OrgRole, target: OrgRole, next: OrgRole): boolean {
  if (actor === 'owner') return true;
  if (actor === 'admin') return target !== 'owner' && next !== 'owner';
  return false;
}

/** Remove someone else. Admins can't remove owners. */
export function canRemove(actor: OrgRole, target: OrgRole): boolean {
  return actor === 'owner' || (actor === 'admin' && target !== 'owner');
}

/** Rename or delete the organization. */
export const canManageOrganization = (actor: OrgRole): boolean => actor === 'owner';

// ---- Names --------------------------------------------------------------------------------------

/**
 * An organization's name, as people see it in pages and in invitation emails. Plain words only:
 * no links or web addresses, so an invitation can't carry someone else's link (THREAT_MODEL O2).
 */
export function orgName(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const name = raw.normalize('NFC').replace(/\s+/g, ' ').trim();
  if (name.length === 0 || name.length > ORG_NAME_MAX) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069<>]/.test(name)) {
    return null;
  }
  if (/:\/\/|www\.|\.(com|net|org|io|cc|app|dev|xyz|info|link|me)\b/i.test(name)) return null;
  return name;
}

// ---- Reading ------------------------------------------------------------------------------------

export interface OrgSummary {
  id: string;
  name: string;
  status: 'active' | 'suspended';
  role: OrgRole;
  members: number;
}

/** The organizations an account belongs to, with its role in each. */
export async function membershipsOf(db: D1Database, userId: string): Promise<OrgSummary[]> {
  const { results } = await db
    .prepare(
      `SELECT o.id, o.name, o.status, m.role,
              (SELECT COUNT(*) FROM org_members x WHERE x.org_id = o.id) AS members
       FROM org_members m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? ORDER BY o.name COLLATE NOCASE, o.id`,
    )
    .bind(userId)
    .all<{
      id: string;
      name: string;
      status: 'active' | 'suspended';
      role: OrgRole;
      members: number;
    }>();
  return results;
}

export interface Organization {
  id: string;
  name: string;
  status: 'active' | 'suspended';
  createdAt: number;
}

/** The organization and the account's role in it; null if it isn't a member. */
export async function membership(
  db: D1Database,
  orgId: string,
  userId: string,
): Promise<{ org: Organization; role: OrgRole } | null> {
  const row = await db
    .prepare(
      `SELECT o.id, o.name, o.status, o.created_at, m.role
       FROM organizations o JOIN org_members m ON m.org_id = o.id
       WHERE o.id = ? AND m.user_id = ?`,
    )
    .bind(orgId, userId)
    .first<{
      id: string;
      name: string;
      status: 'active' | 'suspended';
      created_at: number;
      role: OrgRole;
    }>();
  if (!row) return null;
  return {
    org: { id: row.id, name: row.name, status: row.status, createdAt: row.created_at },
    role: row.role,
  };
}

export interface Member {
  userId: string;
  name: string | null;
  email: string | null;
  role: OrgRole;
  joinedAt: number;
}

/** Owners first, then admins, then members; each by when they joined. */
export async function listMembers(db: D1Database, orgId: string): Promise<Member[]> {
  const { results } = await db
    .prepare(
      `SELECT m.user_id, u.display_name, u.primary_email, m.role, m.joined_at
       FROM org_members m JOIN users u ON u.id = m.user_id
       WHERE m.org_id = ?
       ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, m.joined_at, m.user_id
       LIMIT ?`,
    )
    .bind(orgId, MAX_SEATS)
    .all<{
      user_id: string;
      display_name: string | null;
      primary_email: string | null;
      role: OrgRole;
      joined_at: number;
    }>();
  return results.map((r) => ({
    userId: r.user_id,
    name: r.display_name,
    email: r.primary_email,
    role: r.role,
    joinedAt: r.joined_at,
  }));
}

export interface OpenInvitation {
  id: string;
  email: string;
  role: Exclude<OrgRole, 'owner'>;
  invitedBy: string | null;
  createdAt: number;
  expiresAt: number;
}

export async function listInvitations(
  db: D1Database,
  orgId: string,
  now: number,
): Promise<OpenInvitation[]> {
  const { results } = await db
    .prepare(
      `SELECT i.id, i.email, i.role, COALESCE(u.display_name, u.primary_email) AS invited_by,
              i.created_at, i.expires_at
       FROM org_invitations i LEFT JOIN users u ON u.id = i.invited_by
       WHERE i.org_id = ? AND i.expires_at > ? ORDER BY i.created_at`,
    )
    .bind(orgId, now)
    .all<{
      id: string;
      email: string;
      role: 'admin' | 'member';
      invited_by: string | null;
      created_at: number;
      expires_at: number;
    }>();
  return results.map((r) => ({
    id: r.id,
    email: r.email,
    role: r.role,
    invitedBy: r.invited_by,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
  }));
}

// ---- Changing -----------------------------------------------------------------------------------

/** Creates an organization with `userId` as its owner. Null when the account is in too many. */
export async function createOrganization(
  db: D1Database,
  now: number,
  userId: string,
  name: string,
): Promise<string | null> {
  const id = `org_${randomToken(12)}`;
  const [, member] = await db.batch([
    db
      .prepare(
        `INSERT INTO organizations (id, name, created_at, updated_at)
         SELECT ?1, ?2, ?3, ?3
         WHERE (SELECT COUNT(*) FROM org_members WHERE user_id = ?4) < ?5`,
      )
      .bind(id, name, now, userId, MAX_MEMBERSHIPS),
    db
      .prepare(
        `INSERT INTO org_members (org_id, user_id, role, joined_at)
         SELECT ?1, ?2, 'owner', ?3 WHERE EXISTS (SELECT 1 FROM organizations WHERE id = ?1)`,
      )
      .bind(id, userId, now),
  ]);
  return (member?.meta.changes ?? 0) > 0 ? id : null;
}

export async function renameOrganization(db: D1Database, now: number, orgId: string, name: string) {
  await db
    .prepare('UPDATE organizations SET name = ?, updated_at = ? WHERE id = ?')
    .bind(name, now, orgId)
    .run();
}

const inviteTokenHash = (env: Env, token: string) =>
  hmacHex(env.SESSION_PEPPER, `org-invite:${token}`);

export type InviteResult =
  { ok: true; token: string; id: string } | { ok: false; reason: 'member' | 'invited' | 'full' };

/**
 * Invites an address. The token goes only into the email; the address is checked again when
 * the invitation is accepted (it must be one the accepting account signs in with).
 */
export async function createInvitation(
  env: Env,
  now: number,
  params: { orgId: string; email: string; role: 'admin' | 'member'; invitedBy: string },
): Promise<InviteResult> {
  const db = env.DB;
  const member = await db
    .prepare(
      `SELECT 1 AS ok FROM org_members m
       WHERE m.org_id = ?1 AND m.user_id IN (
         SELECT id FROM users WHERE primary_email = ?2 COLLATE NOCASE
         UNION SELECT user_id FROM identities WHERE email = ?2 COLLATE NOCASE AND email_verified = 1)`,
    )
    .bind(params.orgId, params.email)
    .first<{ ok: number }>();
  if (member) return { ok: false, reason: 'member' };

  // An earlier invitation to the same address that has expired makes way for this one.
  await db
    .prepare('DELETE FROM org_invitations WHERE org_id = ? AND email = ? AND expires_at <= ?')
    .bind(params.orgId, params.email, now)
    .run();

  const token = randomToken(32);
  const id = `inv_${randomToken(12)}`;
  const result = await db
    .prepare(
      `INSERT INTO org_invitations (id, token_hash, org_id, email, role, invited_by, created_at, expires_at)
       SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
       WHERE (SELECT COUNT(*) FROM org_invitations WHERE org_id = ?3 AND expires_at > ?7) < ?9
         AND (SELECT COUNT(*) FROM org_members WHERE org_id = ?3)
           + (SELECT COUNT(*) FROM org_invitations WHERE org_id = ?3 AND expires_at > ?7) < ?10
       ON CONFLICT (org_id, email) DO NOTHING`,
    )
    .bind(
      id,
      await inviteTokenHash(env, token),
      params.orgId,
      params.email,
      params.role,
      params.invitedBy,
      now,
      now + INVITATION_TTL_SECONDS,
      MAX_OPEN_INVITATIONS,
      MAX_SEATS,
    )
    .run();
  if (result.meta.changes > 0) return { ok: true, token, id };
  const existing = await db
    .prepare('SELECT 1 AS ok FROM org_invitations WHERE org_id = ? AND email = ?')
    .bind(params.orgId, params.email)
    .first<{ ok: number }>();
  return { ok: false, reason: existing ? 'invited' : 'full' };
}

export interface InvitationView {
  id: string;
  orgId: string;
  orgName: string;
  orgStatus: 'active' | 'suspended';
  email: string;
  role: 'admin' | 'member';
  inviter: string | null;
  expiresAt: number;
}

export async function invitationByToken(
  env: Env,
  now: number,
  token: string,
): Promise<InvitationView | null> {
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(token)) return null;
  const row = await env.DB.prepare(
    `SELECT i.id, i.org_id, o.name, o.status, i.email, i.role, i.expires_at,
            u.display_name, u.primary_email
     FROM org_invitations i JOIN organizations o ON o.id = i.org_id
     LEFT JOIN users u ON u.id = i.invited_by
     WHERE i.token_hash = ? AND i.expires_at > ?`,
  )
    .bind(await inviteTokenHash(env, token), now)
    .first<{
      id: string;
      org_id: string;
      name: string;
      status: 'active' | 'suspended';
      email: string;
      role: 'admin' | 'member';
      expires_at: number;
      display_name: string | null;
      primary_email: string | null;
    }>();
  if (!row) return null;
  return {
    id: row.id,
    orgId: row.org_id,
    orgName: row.name,
    orgStatus: row.status,
    email: row.email,
    role: row.role,
    inviter: inviterLabel(row.display_name, row.primary_email),
    expiresAt: row.expires_at,
  };
}

/** "Ada Lovelace (ada@example.com)", or whichever of the two the account has. */
export function inviterLabel(name: string | null, email: string | null): string | null {
  if (name && email) return `${name} (${email})`;
  return name ?? email;
}

/** Whether the account signs in with `email` (a verified address of one of its methods). */
export async function accountHasAddress(
  db: D1Database,
  userId: string,
  email: string,
): Promise<boolean> {
  const row = await db
    .prepare(
      `SELECT 1 AS ok FROM identities
       WHERE user_id = ?1 AND email = ?2 COLLATE NOCASE AND email_verified = 1
       UNION SELECT 1 FROM users WHERE id = ?1 AND primary_email = ?2 COLLATE NOCASE
       LIMIT 1`,
    )
    .bind(userId, email)
    .first<{ ok: number }>();
  return Boolean(row);
}

export type AcceptResult =
  | { ok: true; orgId: string; role: 'admin' | 'member' }
  | { ok: false; reason: 'wrong_address' | 'suspended' | 'too_many' };

/**
 * Accepts the invitation for `userId`: only an account that signs in with the invited address,
 * so a forwarded link is useless to anyone else.
 */
export async function acceptInvitation(
  db: D1Database,
  now: number,
  invitation: InvitationView,
  userId: string,
): Promise<AcceptResult> {
  if (!(await accountHasAddress(db, userId, invitation.email))) {
    return { ok: false, reason: 'wrong_address' };
  }
  if (invitation.orgStatus !== 'active') return { ok: false, reason: 'suspended' };
  const [joined] = await db.batch([
    db
      .prepare(
        `INSERT INTO org_members (org_id, user_id, role, joined_at)
         SELECT ?1, ?2, ?3, ?4
         WHERE (SELECT COUNT(*) FROM org_members WHERE user_id = ?2) < ?5
           AND EXISTS (SELECT 1 FROM org_invitations WHERE id = ?6 AND expires_at > ?4)
         ON CONFLICT (org_id, user_id) DO NOTHING`,
      )
      .bind(invitation.orgId, userId, invitation.role, now, MAX_MEMBERSHIPS, invitation.id),
    db
      .prepare(
        `DELETE FROM org_invitations WHERE id = ?1
           AND EXISTS (SELECT 1 FROM org_members WHERE org_id = ?2 AND user_id = ?3)`,
      )
      .bind(invitation.id, invitation.orgId, userId),
  ]);
  if ((joined?.meta.changes ?? 0) === 0) {
    // Already a member (the invitation is used up all the same), or in too many organizations.
    const already = await membership(db, invitation.orgId, userId);
    if (!already) return { ok: false, reason: 'too_many' };
  }
  return { ok: true, orgId: invitation.orgId, role: invitation.role };
}

export async function deleteInvitation(db: D1Database, orgId: string, invitationId: string) {
  const result = await db
    .prepare('DELETE FROM org_invitations WHERE id = ? AND org_id = ?')
    .bind(invitationId, orgId)
    .run();
  return result.meta.changes > 0;
}

/** True if changed. Never leaves the organization without an owner. */
export async function setRole(
  db: D1Database,
  orgId: string,
  userId: string,
  role: OrgRole,
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE org_members SET role = ?3
       WHERE org_id = ?1 AND user_id = ?2 AND role != ?3
         AND (role != 'owner'
              OR (SELECT COUNT(*) FROM org_members WHERE org_id = ?1 AND role = 'owner') > 1)`,
    )
    .bind(orgId, userId, role)
    .run();
  return result.meta.changes > 0;
}

/** True if removed. The last owner can't be removed and can't leave. */
export async function removeMember(db: D1Database, orgId: string, userId: string) {
  const result = await db
    .prepare(
      `DELETE FROM org_members
       WHERE org_id = ?1 AND user_id = ?2
         AND (role != 'owner'
              OR (SELECT COUNT(*) FROM org_members WHERE org_id = ?1 AND role = 'owner') > 1)`,
    )
    .bind(orgId, userId)
    .run();
  return result.meta.changes > 0;
}

/** The statements that delete an organization and tell the services that keep data for one. */
export function deleteOrganizationStatements(
  db: D1Database,
  now: number,
  orgId: string,
): D1PreparedStatement[] {
  return [
    ...SERVICES.filter((service) => service.organizationEvents).map((service) =>
      db
        .prepare(
          `INSERT INTO org_deletion_notices (service, org_id, created_at) VALUES (?, ?, ?)
           ON CONFLICT (service, org_id) DO NOTHING`,
        )
        .bind(service.id, orgId, now),
    ),
    // Members and invitations go with it (ON DELETE CASCADE).
    db.prepare('DELETE FROM organizations WHERE id = ?').bind(orgId),
  ];
}

export async function deleteOrganization(db: D1Database, now: number, orgId: string) {
  await db.batch(deleteOrganizationStatements(db, now, orgId));
}

// ---- When an owner deletes their account ----------------------------------------------------------

export interface OwnershipPlan {
  /** Organizations where the account is the only owner; ownership passes to `to`. */
  passed: { orgId: string; name: string; to: string; toLabel: string | null }[];
  /** Organizations with no other member: deleted with the account. */
  deleted: { orgId: string; name: string }[];
}

/**
 * What deleting the account does to its organizations. Where it is the only owner, the next
 * person in line becomes owner: the longest-standing admin, else the longest-standing member.
 * An organization with nobody else in it is deleted.
 */
export async function ownershipPlan(db: D1Database, userId: string): Promise<OwnershipPlan> {
  const { results } = await db
    .prepare(
      `SELECT p.id, p.name, p.successor,
              (SELECT COALESCE(display_name, primary_email) FROM users WHERE id = p.successor) AS label
       FROM (
         SELECT o.id, o.name,
                (SELECT s.user_id FROM org_members s
                 WHERE s.org_id = o.id AND s.user_id != ?1
                 ORDER BY CASE s.role WHEN 'admin' THEN 0 ELSE 1 END, s.joined_at, s.user_id
                 LIMIT 1) AS successor
         FROM org_members m JOIN organizations o ON o.id = m.org_id
         WHERE m.user_id = ?1 AND m.role = 'owner'
           AND NOT EXISTS (SELECT 1 FROM org_members x
                           WHERE x.org_id = o.id AND x.role = 'owner' AND x.user_id != ?1)
       ) p
       ORDER BY p.name COLLATE NOCASE`,
    )
    .bind(userId)
    .all<{ id: string; name: string; successor: string | null; label: string | null }>();
  const plan: OwnershipPlan = { passed: [], deleted: [] };
  for (const row of results) {
    if (row.successor) {
      plan.passed.push({ orgId: row.id, name: row.name, to: row.successor, toLabel: row.label });
    } else {
      plan.deleted.push({ orgId: row.id, name: row.name });
    }
  }
  return plan;
}

/** The plan, as statements for the account-deletion transaction. */
export function ownershipStatements(
  db: D1Database,
  now: number,
  plan: OwnershipPlan,
): D1PreparedStatement[] {
  return [
    ...plan.passed.map((p) =>
      db
        .prepare("UPDATE org_members SET role = 'owner' WHERE org_id = ? AND user_id = ?")
        .bind(p.orgId, p.to),
    ),
    ...plan.deleted.flatMap((d) => deleteOrganizationStatements(db, now, d.orgId)),
  ];
}
