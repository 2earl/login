import { hmacHex, randomToken } from './crypto';

/** DESIGN §7: 12 h idle, 7 days absolute. */
export const SESSION_IDLE_SECONDS = 12 * 60 * 60;
export const SESSION_ABSOLUTE_SECONDS = 7 * 24 * 60 * 60;
/** last_seen_at is written at most this often, to avoid a database write on every request. */
const TOUCH_INTERVAL_SECONDS = 5 * 60;

export interface SessionUser {
  id: string;
  displayName: string | null;
  primaryEmail: string | null;
  createdAt: number;
}

export interface Session {
  idHash: string;
  /** aal2 once a second factor was verified in this session (DESIGN §4.7). */
  aal: 'aal1' | 'aal2';
  aal2At: number | null;
  /** Whether the user has enrolled a second factor. */
  hasFactor: boolean;
  createdAt: number;
  expiresAt: number;
  user: SessionUser;
}

export interface SessionMeta {
  ipPrefix: string | null;
  userAgentHash: string | null;
}

async function hashSessionId(pepper: string, cookieValue: string): Promise<string> {
  return hmacHex(pepper, `session:${cookieValue}`);
}

export async function createSession(
  db: D1Database,
  pepper: string,
  now: number,
  userId: string,
  meta: SessionMeta,
): Promise<{ cookieValue: string; expiresAt: number }> {
  const cookieValue = randomToken(32);
  const expiresAt = now + SESSION_ABSOLUTE_SECONDS;
  await db
    .prepare(
      `INSERT INTO sessions (id_hash, user_id, aal, created_at, last_seen_at, expires_at, ip_prefix, user_agent_hash)
       VALUES (?, ?, 'aal1', ?, ?, ?, ?, ?)`,
    )
    .bind(
      await hashSessionId(pepper, cookieValue),
      userId,
      now,
      now,
      expiresAt,
      meta.ipPrefix,
      meta.userAgentHash,
    )
    .run();
  return { cookieValue, expiresAt };
}

/** Returns the active session for this cookie, or null. Expired sessions are deleted. */
export async function getSession(
  db: D1Database,
  pepper: string,
  now: number,
  cookieValue: string | undefined,
): Promise<Session | null> {
  if (!cookieValue) return null;
  const idHash = await hashSessionId(pepper, cookieValue);

  const row = await db
    .prepare(
      `SELECT s.aal, s.aal2_at, s.created_at, s.last_seen_at, s.expires_at,
              u.id AS user_id, u.status, u.display_name, u.primary_email, u.created_at AS user_created_at,
              EXISTS (SELECT 1 FROM mfa_factors f WHERE f.user_id = u.id) AS has_factor
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.id_hash = ?`,
    )
    .bind(idHash)
    .first<{
      aal: 'aal1' | 'aal2';
      aal2_at: number | null;
      has_factor: number;
      created_at: number;
      last_seen_at: number;
      expires_at: number;
      user_id: string;
      status: string;
      display_name: string | null;
      primary_email: string | null;
      user_created_at: number;
    }>();
  if (!row) return null;

  const expired = row.expires_at <= now || row.last_seen_at + SESSION_IDLE_SECONDS <= now;
  if (expired || row.status !== 'active') {
    await db.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(idHash).run();
    return null;
  }

  if (now - row.last_seen_at >= TOUCH_INTERVAL_SECONDS) {
    await db
      .prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?')
      .bind(now, idHash)
      .run();
  }

  return {
    idHash,
    aal: row.aal,
    aal2At: row.aal2_at,
    hasFactor: row.has_factor === 1,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    user: {
      id: row.user_id,
      displayName: row.display_name,
      primaryEmail: row.primary_email,
      createdAt: row.user_created_at,
    },
  };
}

export async function deleteSession(db: D1Database, idHash: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(idHash).run();
}
