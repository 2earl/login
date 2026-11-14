import { hmacHex, randomToken } from './crypto';
import { decryptSecret, encryptSecret } from './mfa';

/**
 * The organization's audit log (DESIGN §4.23): what happened in the organization (events naming
 * it) and what the accounts it manages did (sign-ins, second factors, sign-in methods, apps). For
 * managed accounts the organization is the controller (§4.18), so their security events are its
 * to see. Kept 90 days, like the whole security log; organizations that need longer download it
 * or stream it to their own security monitoring.
 */

export const MAX_EXPORT = 20_000;
/** Events per delivery to a stream. */
const BATCH = 500;
/** Retry: 1 minute doubling, up to 6 hours. */
const MAX_BACKOFF_SECONDS = 6 * 60 * 60;

export interface OrgAuditRecord {
  id: string;
  time: string;
  /** Unix seconds, for ordering. */
  at: number;
  event: string;
  actor: { id: string; email: string | null } | null;
  target: { id: string; email: string | null } | null;
  clientId: string | null;
  ipPrefix: string | null;
  detail: Record<string, unknown>;
}

interface Row {
  id: string;
  at: number;
  event: string;
  actor_user_id: string | null;
  actor_email: string | null;
  target_id: string | null;
  target_email: string | null;
  client_id: string | null;
  ip_prefix: string | null;
  detail: string | null;
}

/**
 * The organization's events in (at, id) order, after the cursor and up to `until`. Emails are
 * given for the organization's own members only.
 */
export async function orgAuditEvents(
  db: D1Database,
  orgId: string,
  params: { afterAt: number; afterId?: string; until: number; limit: number },
): Promise<OrgAuditRecord[]> {
  const { results } = await db
    .prepare(
      `WITH picked AS (
         SELECT e.* FROM audit_events e
         WHERE json_extract(e.detail, '$.org') = ?1 AND e.at <= ?4
           AND (e.at > ?2 OR (e.at = ?2 AND e.id > ?3))
         UNION
         SELECT e.* FROM audit_events e
         JOIN users u ON u.id = e.actor_user_id AND u.managed_by = ?1
         WHERE e.at <= ?4 AND (e.at > ?2 OR (e.at = ?2 AND e.id > ?3))
       )
       SELECT p.id, p.at, p.event, p.actor_user_id, p.client_id, p.ip_prefix, p.detail,
              (SELECT u.primary_email FROM users u JOIN org_members m ON m.user_id = u.id AND m.org_id = ?1
               WHERE u.id = p.actor_user_id) AS actor_email,
              json_extract(p.detail, '$.target') AS target_id,
              (SELECT u.primary_email FROM users u JOIN org_members m ON m.user_id = u.id AND m.org_id = ?1
               WHERE u.id = json_extract(p.detail, '$.target')) AS target_email
       FROM picked p ORDER BY p.at, p.id LIMIT ?5`,
    )
    .bind(orgId, params.afterAt, params.afterId ?? '', params.until, params.limit)
    .all<Row>();
  return results.map((r) => {
    let detail: Record<string, unknown>;
    try {
      detail = r.detail ? (JSON.parse(r.detail) as Record<string, unknown>) : {};
    } catch {
      detail = {};
    }
    return {
      id: r.id,
      time: new Date(r.at * 1000).toISOString(),
      at: r.at,
      event: r.event,
      actor: r.actor_user_id ? { id: r.actor_user_id, email: r.actor_email } : null,
      target: typeof r.target_id === 'string' ? { id: r.target_id, email: r.target_email } : null,
      clientId: r.client_id,
      ipPrefix: r.ip_prefix,
      detail,
    };
  });
}

/** One record as the download and the stream give it (no internal fields). */
export function publicRecord(r: OrgAuditRecord) {
  return {
    id: r.id,
    time: r.time,
    event: r.event,
    actor: r.actor,
    target: r.target,
    client_id: r.clientId,
    ip_prefix: r.ipPrefix,
    detail: r.detail,
  };
}

const csvCell = (value: string | null | undefined): string => {
  const text = value ?? '';
  // Spreadsheet formula injection: a leading =, +, - or @ is quoted with an apostrophe.
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};

export function toCsv(records: OrgAuditRecord[]): string {
  const header = [
    'time',
    'event',
    'actor_id',
    'actor_email',
    'target_id',
    'target_email',
    'client_id',
    'ip_prefix',
    'detail',
  ];
  const lines = records.map((r) =>
    [
      r.time,
      r.event,
      r.actor?.id,
      r.actor?.email,
      r.target?.id,
      r.target?.email,
      r.clientId,
      r.ipPrefix,
      JSON.stringify(r.detail),
    ]
      .map(csvCell)
      .join(','),
  );
  return [header.join(','), ...lines].join('\r\n') + '\r\n';
}

// ---- Streaming ----------------------------------------------------------------------------------

export interface AuditStream {
  orgId: string;
  url: string;
  enabled: boolean;
  failures: number;
  lastStatus: string | null;
  lastDeliveredAt: number | null;
}

const streamContext = (orgId: string) => `audit-stream-secret:${orgId}`;

export async function readStream(db: D1Database, orgId: string): Promise<AuditStream | null> {
  const row = await db
    .prepare(
      'SELECT org_id, url, enabled, failures, last_status, last_delivered_at FROM org_audit_streams WHERE org_id = ?',
    )
    .bind(orgId)
    .first<{
      org_id: string;
      url: string;
      enabled: number;
      failures: number;
      last_status: string | null;
      last_delivered_at: number | null;
    }>();
  return row
    ? {
        orgId: row.org_id,
        url: row.url,
        enabled: row.enabled === 1,
        failures: row.failures,
        lastStatus: row.last_status,
        lastDeliveredAt: row.last_delivered_at,
      }
    : null;
}

/** An https URL without credentials or fragment, at most 1000 characters; else null. */
export function streamUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const text = raw.trim();
  if (text.length > 1000) return null;
  try {
    const url = new URL(text);
    return url.protocol === 'https:' && !url.username && !url.password && !url.hash
      ? url.toString()
      : null;
  } catch {
    return null;
  }
}

/**
 * Creates or changes the stream. A new stream (or `rotate`) gets a new secret, returned once.
 * A new stream starts from now: events before it are in the download.
 */
export async function saveStream(
  env: Env,
  now: number,
  orgId: string,
  input: { url: string; enabled: boolean; rotate: boolean },
): Promise<string | null> {
  const existing = await readStream(env.DB, orgId);
  const secret = !existing || input.rotate ? `whsec_${randomToken(32)}` : null;
  const sealed = secret
    ? await encryptSecret(env.MFA_ENCRYPTION_KEY, streamContext(orgId), secret)
    : null;
  await env.DB.prepare(
    `INSERT INTO org_audit_streams (org_id, url, secret_enc, enabled, cursor_at, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5)
     ON CONFLICT (org_id) DO UPDATE SET url = ?2, secret_enc = COALESCE(?3, secret_enc),
       enabled = ?4, failures = 0, next_attempt_at = 0, updated_at = ?5`,
  )
    .bind(orgId, input.url, sealed, input.enabled ? 1 : 0, now)
    .run();
  return secret;
}

export async function deleteStream(db: D1Database, orgId: string): Promise<void> {
  await db.prepare('DELETE FROM org_audit_streams WHERE org_id = ?').bind(orgId).run();
}

/** The signature header: `t=<unix seconds>,v1=<HMAC-SHA256 hex of "t.body">`. */
export async function signature(secret: string, timestamp: number, body: string): Promise<string> {
  return `t=${String(timestamp)},v1=${await hmacHex(secret, `${String(timestamp)}.${body}`)}`;
}

/** Sends one batch. Returns the HTTP status, or an error word. */
async function post(
  fetcher: typeof fetch,
  url: string,
  secret: string,
  now: number,
  payload: unknown,
): Promise<{ ok: boolean; status: string }> {
  const body = JSON.stringify(payload);
  try {
    const response = await fetcher(url, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': '2earl-audit-stream/1',
        'X-2earl-Delivery': crypto.randomUUID(),
        'X-2earl-Signature': await signature(secret, now, body),
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });
    await response.body?.cancel();
    return { ok: response.status >= 200 && response.status < 300, status: String(response.status) };
  } catch (error) {
    return {
      ok: false,
      status: error instanceof Error && error.name === 'TimeoutError' ? 'timeout' : 'unreachable',
    };
  }
}

/** A test delivery the owner asks for: one made-up event, not from the log. */
export async function sendTest(
  env: Env,
  fetcher: typeof fetch,
  now: number,
  orgId: string,
): Promise<string> {
  const row = await env.DB.prepare('SELECT url, secret_enc FROM org_audit_streams WHERE org_id = ?')
    .bind(orgId)
    .first<{ url: string; secret_enc: string }>();
  if (!row) return 'no stream';
  const secret = await decryptSecret(env.MFA_ENCRYPTION_KEY, streamContext(orgId), row.secret_enc);
  const result = await post(fetcher, row.url, secret, now, {
    organization: orgId,
    test: true,
    events: [
      {
        id: `test_${randomToken(8)}`,
        time: new Date(now * 1000).toISOString(),
        event: 'stream.test',
        actor: null,
        target: null,
        client_id: null,
        ip_prefix: null,
        detail: {},
      },
    ],
  });
  return result.status;
}

/**
 * Delivers what's new to every stream that's due (the minute cron). A batch that isn't accepted
 * is retried with backoff; nothing is skipped, so the endpoint gets every event once it answers,
 * as long as the event is still in the 90-day log.
 */
export async function deliverStreams(
  env: Env,
  fetcher: typeof fetch,
  now: number,
): Promise<{ delivered: number; failed: number }> {
  const { results } = await env.DB.prepare(
    `SELECT s.org_id, s.url, s.secret_enc, s.cursor_at, s.cursor_id, s.failures
     FROM org_audit_streams s JOIN organizations o ON o.id = s.org_id AND o.status = 'active'
     WHERE s.enabled = 1 AND s.next_attempt_at <= ? LIMIT 50`,
  )
    .bind(now)
    .all<{
      org_id: string;
      url: string;
      secret_enc: string;
      cursor_at: number;
      cursor_id: string;
      failures: number;
    }>();
  let delivered = 0;
  let failed = 0;
  for (const stream of results) {
    const events = await orgAuditEvents(env.DB, stream.org_id, {
      afterAt: stream.cursor_at,
      afterId: stream.cursor_id,
      // A few seconds' margin, so events written in the same second as the read aren't skipped.
      until: now - 5,
      limit: BATCH,
    });
    if (events.length === 0) continue;
    const secret = await decryptSecret(
      env.MFA_ENCRYPTION_KEY,
      streamContext(stream.org_id),
      stream.secret_enc,
    );
    const result = await post(fetcher, stream.url, secret, now, {
      organization: stream.org_id,
      events: events.map(publicRecord),
    });
    const last = events[events.length - 1];
    if (result.ok && last) {
      delivered += events.length;
      await env.DB.prepare(
        `UPDATE org_audit_streams SET cursor_at = ?, cursor_id = ?, failures = 0, next_attempt_at = 0,
           last_status = ?, last_delivered_at = ? WHERE org_id = ?`,
      )
        .bind(last.at, last.id, result.status, now, stream.org_id)
        .run();
    } else {
      failed += 1;
      const backoff = Math.min(MAX_BACKOFF_SECONDS, 60 * 2 ** Math.min(stream.failures, 12));
      await env.DB.prepare(
        `UPDATE org_audit_streams SET failures = failures + 1, next_attempt_at = ?, last_status = ?
         WHERE org_id = ?`,
      )
        .bind(now + backoff, result.status, stream.org_id)
        .run();
    }
  }
  return { delivered, failed };
}
