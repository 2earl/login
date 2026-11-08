import type { GoogleIdentity } from './google';

/**
 * While the service is locked (DESIGN D9) only allowlisted accounts may sign in. An entry may
 * name a Google subject or an email address. An email entry is converted to a subject entry on
 * the first successful sign-in (see pinAllowlistToSubject), so it cannot later admit a different
 * Google account that receives the same address.
 */
export async function allowlistMatch(
  db: D1Database,
  identity: GoogleIdentity,
): Promise<'google_sub' | 'email' | null> {
  const row = await db
    .prepare(
      `SELECT kind FROM allowlist
       WHERE (kind = 'google_sub' AND value = ?) OR (kind = 'email' AND value = ?)
       ORDER BY CASE kind WHEN 'google_sub' THEN 0 ELSE 1 END
       LIMIT 1`,
    )
    .bind(identity.subject, identity.email)
    .first<{ kind: 'google_sub' | 'email' }>();
  return row?.kind ?? null;
}

export async function pinAllowlistToSubject(
  db: D1Database,
  now: number,
  identity: GoogleIdentity,
): Promise<void> {
  await db.batch([
    db
      .prepare(
        `INSERT OR IGNORE INTO allowlist (id, kind, value, added_by, created_at)
         VALUES (?, 'google_sub', ?, 'pinned-on-first-sign-in', ?)`,
      )
      .bind(crypto.randomUUID(), identity.subject, now),
    db.prepare("DELETE FROM allowlist WHERE kind = 'email' AND value = ?").bind(identity.email),
  ]);
}

/**
 * Finds the user for this Google account, or creates one. Lookup is by (provider, subject) only;
 * an existing account with the same email but a different subject is never reused.
 */
export async function upsertGoogleUser(
  db: D1Database,
  now: number,
  identity: GoogleIdentity,
): Promise<{ userId: string; created: boolean }> {
  const existing = await db
    .prepare("SELECT user_id FROM identities WHERE provider = 'google' AND subject = ?")
    .bind(identity.subject)
    .first<{ user_id: string }>();

  if (existing) {
    await db.batch([
      db
        .prepare(
          `UPDATE identities SET email = ?, email_verified = 1, last_login_at = ?
           WHERE provider = 'google' AND subject = ?`,
        )
        .bind(identity.email, now, identity.subject),
      db
        .prepare(
          'UPDATE users SET display_name = ?, primary_email = ?, updated_at = ? WHERE id = ?',
        )
        .bind(identity.name, identity.email, now, existing.user_id),
    ]);
    return { userId: existing.user_id, created: false };
  }

  const userId = crypto.randomUUID();
  await db.batch([
    db
      .prepare(
        `INSERT INTO users (id, status, display_name, primary_email, created_at, updated_at)
         VALUES (?, 'active', ?, ?, ?, ?)`,
      )
      .bind(userId, identity.name, identity.email, now, now),
    db
      .prepare(
        `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
         VALUES (?, ?, 'google', ?, ?, 1, ?, ?)`,
      )
      .bind(crypto.randomUUID(), userId, identity.subject, identity.email, now, now),
  ]);
  return { userId, created: true };
}

export async function isUserActive(db: D1Database, userId: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT status FROM users WHERE id = ?')
    .bind(userId)
    .first<{ status: string }>();
  return row?.status === 'active';
}
