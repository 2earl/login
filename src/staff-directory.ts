import { WorkerEntrypoint } from 'cloudflare:workers';
import { isOwnerUser, staffRoleOf, type StaffRole } from './staff';

/**
 * 2earl's staff for 2earl's own back offices (DESIGN §4.29): which staff role an account has, read
 * live on every call, so taking a role away takes effect at once. A named entrypoint for Service
 * Bindings only; only staff tools (Emanet Merkez) bind it.
 */
export class StaffDirectory extends WorkerEntrypoint<Env> {
  /** The account's staff role, or null for everyone else and for suspended accounts. */
  async roleOf(userId: string): Promise<StaffRole | null> {
    const active = await this.env.DB.prepare(
      "SELECT 1 AS ok FROM users WHERE id = ? AND status = 'active'",
    )
      .bind(userId)
      .first<{ ok: number }>();
    if (!active) return null;
    if (await isOwnerUser(this.env, userId)) return 'owner';
    return staffRoleOf(this.env, userId);
  }
}
