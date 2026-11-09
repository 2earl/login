/**
 * Security audit trail (DESIGN §6.1). Never pass tokens, codes, cookies, full URLs or email
 * addresses in `detail`. Writing an audit event never fails the request.
 */
export type AuditEvent =
  | 'login.started'
  | 'login.succeeded'
  | 'login.denied'
  | 'login.failed'
  | 'allowlist.pinned'
  | 'user.created'
  | 'logout'
  | 'consent.approved'
  | 'consent.denied'
  | 'consent.reused'
  | 'grant.revoked'
  | 'grant.refused'
  | 'account.exported'
  | 'account.deletion_started'
  | 'account.deletion_stopped'
  | 'user.deleted';

export async function audit(
  db: D1Database,
  now: number,
  event: AuditEvent,
  fields: {
    actorUserId?: string | null;
    clientId?: string | null;
    ipPrefix?: string | null;
    detail?: Record<string, string | number | boolean | null>;
  } = {},
): Promise<void> {
  try {
    await db
      .prepare(
        `INSERT INTO audit_events (id, at, event, actor_user_id, client_id, ip_prefix, detail)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        crypto.randomUUID(),
        now,
        event,
        fields.actorUserId ?? null,
        fields.clientId ?? null,
        fields.ipPrefix ?? null,
        fields.detail ? JSON.stringify(fields.detail) : null,
      )
      .run();
  } catch (error) {
    console.error('audit write failed', event, error instanceof Error ? error.name : 'unknown');
  }
}
