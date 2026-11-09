import { audit } from './audit';
import { serviceById } from './services';

/**
 * Delivers account-deletion notices to the services in src/services.ts (DESIGN §4.8). Each
 * service exposes `AccountEvents.deleteUser(userId)` over a Service Binding; a notice is deleted
 * only after that call returns. Runs right after a deletion and on every cron trigger, so a
 * service that is down receives its notices once it is back.
 */

/** What a service's `AccountEvents` entrypoint looks like through its binding. */
export interface AccountEventsBinding {
  deleteUser(userId: string): Promise<void>;
}

export interface DeliveryResult {
  delivered: number;
  failed: number;
  /** Notices whose service has no binding yet (not deployed): kept for later. */
  waiting: number;
}

const BATCH = 100;

function bindingFor(env: Env, name: string): AccountEventsBinding | null {
  const value = (env as unknown as Record<string, unknown>)[name];
  return value !== null &&
    typeof value === 'object' &&
    typeof (value as Partial<AccountEventsBinding>).deleteUser === 'function'
    ? (value as AccountEventsBinding)
    : null;
}

export async function deliverDeletionNotices(env: Env, now: number): Promise<DeliveryResult> {
  const result: DeliveryResult = { delivered: 0, failed: 0, waiting: 0 };
  const { results } = await env.DB.prepare(
    'SELECT service, user_id FROM deletion_notices ORDER BY created_at LIMIT ?',
  )
    .bind(BATCH)
    .all<{ service: string; user_id: string }>();

  for (const notice of results) {
    const service = serviceById(notice.service);
    const binding = service ? bindingFor(env, service.deletionBinding) : null;
    if (!binding) {
      result.waiting += 1;
      continue;
    }
    try {
      await binding.deleteUser(notice.user_id);
    } catch (error) {
      result.failed += 1;
      const name = error instanceof Error ? error.name : 'unknown';
      console.error('deletion notice failed', notice.service, name);
      await env.DB.prepare(
        `UPDATE deletion_notices SET attempts = attempts + 1, last_attempt_at = ?, last_error = ?
         WHERE service = ? AND user_id = ?`,
      )
        .bind(now, name, notice.service, notice.user_id)
        .run();
      continue;
    }
    result.delivered += 1;
    await env.DB.prepare('DELETE FROM deletion_notices WHERE service = ? AND user_id = ?')
      .bind(notice.service, notice.user_id)
      .run();
    // Names the service only: the deleted account's ID is not kept anywhere once delivered.
    await audit(env.DB, now, 'user.deletion_delivered', { detail: { service: notice.service } });
  }
  return result;
}

export interface PendingNotices {
  service: string;
  name: string;
  count: number;
  oldest: number;
  attempts: number;
  lastError: string | null;
}

/** For /admin: notices still waiting, per service. */
export async function pendingNotices(db: D1Database): Promise<PendingNotices[]> {
  const { results } = await db
    .prepare(
      `SELECT service, COUNT(*) AS count, MIN(created_at) AS oldest, MAX(attempts) AS attempts,
              (SELECT last_error FROM deletion_notices d2 WHERE d2.service = d.service
                 AND d2.last_error IS NOT NULL ORDER BY last_attempt_at DESC LIMIT 1) AS last_error
       FROM deletion_notices d GROUP BY service ORDER BY service`,
    )
    .all<{
      service: string;
      count: number;
      oldest: number;
      attempts: number;
      last_error: string | null;
    }>();
  return results.map((row) => ({
    service: row.service,
    name: serviceById(row.service)?.name ?? row.service,
    count: row.count,
    oldest: row.oldest,
    attempts: row.attempts,
    lastError: row.last_error,
  }));
}
