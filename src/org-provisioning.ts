import { WorkerEntrypoint } from 'cloudflare:workers';
import { audit } from './audit';
import { accountHasAddress, createOrganization, orgName } from './orgs';
import { staffRoleOf, isOwnerUser } from './staff';

/**
 * Organizations set up from another 2earl service's own invitation (DESIGN §4.30), for Service
 * Bindings only; only Emanet Kurumsal binds it. 2earl staff invite a company in Emanet Merkez;
 * the person invited follows the link in the email, signs in here, and the organization is created
 * with them as its owner, like a setup invitation from login's own admin.
 *
 * The same checks as a setup invitation: the account must sign in with the invited address (so a
 * forwarded link is useless), must be active, and the invitation must come from a member of 2earl
 * staff. Nothing is created otherwise.
 */
export type ProvisionResult =
  | { ok: true; orgId: string }
  | { ok: false; reason: 'no_account' | 'wrong_address' | 'not_staff' | 'invalid_name' | 'full' };

export class OrganizationProvisioning extends WorkerEntrypoint<Env> {
  /** Whether the account signs in with this address: to tell the invited person early. */
  async hasAddress(userId: string, email: string): Promise<boolean> {
    return accountHasAddress(this.env.DB, userId, email);
  }

  async create(request: {
    ownerId: string;
    email: string;
    name: string;
    invitedBy: string;
    service: string;
  }): Promise<ProvisionResult> {
    const db = this.env.DB;
    const now = Math.floor(Date.now() / 1000);
    const active = await db
      .prepare("SELECT 1 AS ok FROM users WHERE id = ? AND status = 'active'")
      .bind(request.ownerId)
      .first<{ ok: number }>();
    if (!active) return { ok: false, reason: 'no_account' };
    if (!(await accountHasAddress(db, request.ownerId, request.email))) {
      return { ok: false, reason: 'wrong_address' };
    }
    const inviterIsStaff =
      (await isOwnerUser(this.env, request.invitedBy)) ||
      (await staffRoleOf(this.env, request.invitedBy)) !== null;
    if (!inviterIsStaff) return { ok: false, reason: 'not_staff' };
    const name = orgName(request.name);
    if (!name) return { ok: false, reason: 'invalid_name' };
    const orgId = await createOrganization(db, now, request.ownerId, name);
    if (!orgId) return { ok: false, reason: 'full' };
    await audit(db, now, 'org.created', {
      actorUserId: request.ownerId,
      detail: { org: orgId, via: request.service.slice(0, 40), invited_by: request.invitedBy },
    });
    return { ok: true, orgId };
  }
}
