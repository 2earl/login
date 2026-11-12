import { WorkerEntrypoint } from 'cloudflare:workers';
import type { OrgRole } from './orgs';

/**
 * Organizations for 2earl services (DESIGN §4.14): which organizations an account belongs to and
 * with which role, read live on every call, so a removed member loses access at once. A named
 * entrypoint for Service Bindings only; the public Internet can't reach it.
 *
 * Suspended organizations and suspended accounts are left out, as if they weren't there.
 */
export class OrganizationDirectory extends WorkerEntrypoint<Env> {
  /** The active organizations an active account belongs to. */
  async membershipsOf(userId: string): Promise<{ orgId: string; name: string; role: OrgRole }[]> {
    const { results } = await this.env.DB.prepare(
      `SELECT o.id AS orgId, o.name, m.role
       FROM org_members m
       JOIN organizations o ON o.id = m.org_id AND o.status = 'active'
       JOIN users u ON u.id = m.user_id AND u.status = 'active'
       WHERE m.user_id = ? ORDER BY o.id`,
    )
      .bind(userId)
      .all<{ orgId: string; name: string; role: OrgRole }>();
    return results;
  }

  /** The account's role in the organization, or null if it isn't an active member. */
  async roleOf(orgId: string, userId: string): Promise<OrgRole | null> {
    const row = await this.env.DB.prepare(
      `SELECT m.role FROM org_members m
       JOIN organizations o ON o.id = m.org_id AND o.status = 'active'
       JOIN users u ON u.id = m.user_id AND u.status = 'active'
       WHERE m.org_id = ? AND m.user_id = ?`,
    )
      .bind(orgId, userId)
      .first<{ role: OrgRole }>();
    return row?.role ?? null;
  }

  /** The active members of an active organization: account IDs and roles, nothing else. */
  async members(orgId: string): Promise<{ userId: string; role: OrgRole }[] | null> {
    const org = await this.env.DB.prepare(
      "SELECT 1 AS ok FROM organizations WHERE id = ? AND status = 'active'",
    )
      .bind(orgId)
      .first<{ ok: number }>();
    if (!org) return null;
    const { results } = await this.env.DB.prepare(
      `SELECT m.user_id AS userId, m.role FROM org_members m
       JOIN users u ON u.id = m.user_id AND u.status = 'active'
       WHERE m.org_id = ? ORDER BY m.joined_at, m.user_id LIMIT 1000`,
    )
      .bind(orgId)
      .all<{ userId: string; role: OrgRole }>();
    return results;
  }
}
