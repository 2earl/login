import { randomToken } from './crypto';
import { accountHasAddress, createOrganization } from './orgs';

/**
 * Organizations are set up by invitation (DESIGN §4.30). Only 2earl's owner and admins create
 * organizations, or invite someone to: the invited person signs in (or creates an account) with
 * the invited address, names the organization and becomes its owner, the organization's top
 * admin, who then adds admins and members.
 *
 * No secret token: the invitation is used by an account that signs in with the invited address,
 * which is what a token sent to that address would prove, and a forwarded link is useless.
 */

/** How long a setup invitation works. */
export const SETUP_INVITATION_TTL_SECONDS = 14 * 24 * 60 * 60;
/** Open setup invitations at once, all of 2earl. */
export const MAX_OPEN_SETUP_INVITATIONS = 200;
/** Sending one again: not more often than this. */
export const RESEND_INTERVAL_SECONDS = 10 * 60;

export interface SetupInvitation {
  id: string;
  email: string;
  orgName: string | null;
  invitedBy: string | null;
  createdAt: number;
  sentAt: number;
  expiresAt: number;
  usedAt: number | null;
  orgId: string | null;
  /** The organization it set up, by its current name. */
  orgNow: string | null;
}

interface Row {
  id: string;
  email: string;
  org_name: string | null;
  inviter: string | null;
  created_at: number;
  sent_at: number;
  expires_at: number;
  used_at: number | null;
  org_id: string | null;
  org_now: string | null;
}

const SELECT = `SELECT i.id, i.email, i.org_name, u.primary_email AS inviter, i.created_at, i.sent_at,
                       i.expires_at, i.used_at, i.org_id, o.name AS org_now
                FROM org_setup_invitations i
                LEFT JOIN users u ON u.id = i.invited_by
                LEFT JOIN organizations o ON o.id = i.org_id`;

const fromRow = (r: Row): SetupInvitation => ({
  id: r.id,
  email: r.email,
  orgName: r.org_name,
  invitedBy: r.inviter,
  createdAt: r.created_at,
  sentAt: r.sent_at,
  expiresAt: r.expires_at,
  usedAt: r.used_at,
  orgId: r.org_id,
  orgNow: r.org_now,
});

/** For /admin: open ones first, then the last 50 used or expired. */
export async function listSetupInvitations(
  db: D1Database,
  now: number,
): Promise<SetupInvitation[]> {
  const { results } = await db
    .prepare(
      `${SELECT} ORDER BY (i.used_at IS NULL AND i.expires_at > ?1) DESC, i.created_at DESC LIMIT 250`,
    )
    .bind(now)
    .all<Row>();
  return results.map(fromRow);
}

export async function setupInvitation(db: D1Database, id: string): Promise<SetupInvitation | null> {
  if (!/^osi_[A-Za-z0-9_-]{8,40}$/.test(id)) return null;
  const row = await db.prepare(`${SELECT} WHERE i.id = ?`).bind(id).first<Row>();
  return row ? fromRow(row) : null;
}

export const isOpen = (invitation: SetupInvitation, now: number) =>
  invitation.usedAt === null && invitation.expiresAt > now;

/** Open invitations for any address the account signs in with. */
export async function setupInvitationsFor(
  db: D1Database,
  now: number,
  userId: string,
): Promise<SetupInvitation[]> {
  const { results } = await db
    .prepare(
      `${SELECT}
       WHERE i.used_at IS NULL AND i.expires_at > ?1
         AND i.email IN (
           SELECT email FROM identities WHERE user_id = ?2 AND email_verified = 1 AND email IS NOT NULL
           UNION SELECT primary_email FROM users WHERE id = ?2 AND primary_email IS NOT NULL)
       ORDER BY i.created_at`,
    )
    .bind(now, userId)
    .all<Row>();
  return results.map(fromRow);
}

export type CreateSetupResult =
  { ok: true; id: string } | { ok: false; reason: 'pending' | 'full' };

/**
 * Invites `email` to set up an organization. The address may also sign up while sign-up is
 * invite-only: it goes on the sign-up invitations (allowlist) too.
 */
export async function createSetupInvitation(
  db: D1Database,
  now: number,
  params: { email: string; orgName: string | null; invitedBy: string },
): Promise<CreateSetupResult> {
  const id = `osi_${randomToken(12)}`;
  const [inserted] = await db.batch([
    db
      .prepare(
        `INSERT INTO org_setup_invitations (id, email, org_name, invited_by, created_at, sent_at, expires_at)
         SELECT ?1, ?2, ?3, ?4, ?5, ?5, ?6
         WHERE NOT EXISTS (SELECT 1 FROM org_setup_invitations
                           WHERE email = ?2 AND used_at IS NULL AND expires_at > ?5)
           AND (SELECT COUNT(*) FROM org_setup_invitations WHERE used_at IS NULL AND expires_at > ?5) < ?7`,
      )
      .bind(
        id,
        params.email,
        params.orgName,
        params.invitedBy,
        now,
        now + SETUP_INVITATION_TTL_SECONDS,
        MAX_OPEN_SETUP_INVITATIONS,
      ),
    db
      .prepare(
        `INSERT INTO allowlist (id, kind, value, added_by, created_at)
         SELECT ?1, 'email', ?2, 'org_setup', ?3
         WHERE EXISTS (SELECT 1 FROM org_setup_invitations WHERE id = ?4)
         ON CONFLICT (kind, value) DO NOTHING`,
      )
      .bind(crypto.randomUUID(), params.email, now, id),
  ]);
  if ((inserted?.meta.changes ?? 0) > 0) return { ok: true, id };
  const pending = await db
    .prepare(
      'SELECT 1 AS ok FROM org_setup_invitations WHERE email = ? AND used_at IS NULL AND expires_at > ?',
    )
    .bind(params.email, now)
    .first<{ ok: number }>();
  return { ok: false, reason: pending ? 'pending' : 'full' };
}

/** Marks an open invitation as sent again, at most every 10 minutes; false if it can't be. */
export async function markResent(db: D1Database, now: number, id: string): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE org_setup_invitations SET sent_at = ?1, expires_at = ?2
       WHERE id = ?3 AND used_at IS NULL AND expires_at > ?1 AND sent_at <= ?1 - ?4`,
    )
    .bind(now, now + SETUP_INVITATION_TTL_SECONDS, id, RESEND_INTERVAL_SECONDS)
    .run();
  return result.meta.changes > 0;
}

/** Withdraws an open invitation. */
export async function withdrawSetupInvitation(
  db: D1Database,
  now: number,
  id: string,
): Promise<boolean> {
  // The sign-up invitation it added goes too, unless an account already used it.
  const [, deleted] = await db.batch([
    db
      .prepare(
        `DELETE FROM allowlist WHERE kind = 'email' AND added_by = 'org_setup'
           AND value = (SELECT email FROM org_setup_invitations
                        WHERE id = ?1 AND used_at IS NULL AND expires_at > ?2)`,
      )
      .bind(id, now),
    db
      .prepare(
        'DELETE FROM org_setup_invitations WHERE id = ? AND used_at IS NULL AND expires_at > ?',
      )
      .bind(id, now),
  ]);
  return (deleted?.meta.changes ?? 0) > 0;
}

export type SetupResult =
  { ok: true; orgId: string } | { ok: false; reason: 'gone' | 'wrong_address' | 'too_many' };

/**
 * Sets up the organization: the account must sign in with the invited address. The invitation
 * is claimed first, so two tabs can't set up two organizations from one invitation.
 */
export async function useSetupInvitation(
  db: D1Database,
  now: number,
  invitation: SetupInvitation,
  userId: string,
  name: string,
): Promise<SetupResult> {
  if (!isOpen(invitation, now)) return { ok: false, reason: 'gone' };
  if (!(await accountHasAddress(db, userId, invitation.email))) {
    return { ok: false, reason: 'wrong_address' };
  }
  const claimed = await db
    .prepare(
      'UPDATE org_setup_invitations SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?',
    )
    .bind(now, invitation.id, now)
    .run();
  if (claimed.meta.changes === 0) return { ok: false, reason: 'gone' };
  const orgId = await createOrganization(db, now, userId, name);
  if (!orgId) {
    // Not set up after all (the account is in too many organizations): the invitation stays.
    await db
      .prepare('UPDATE org_setup_invitations SET used_at = NULL WHERE id = ?')
      .bind(invitation.id)
      .run();
    return { ok: false, reason: 'too_many' };
  }
  await db
    .prepare('UPDATE org_setup_invitations SET org_id = ? WHERE id = ?')
    .bind(orgId, invitation.id)
    .run();
  return { ok: true, orgId };
}
