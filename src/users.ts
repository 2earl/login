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
    // Invitations are stored in lower case (admin.ts).
    .bind(identity.subject, identity.email.toLowerCase())
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
      // Google's name fills in only a missing one, so a name the user chose stays. The address
      // follows Google only when the account has no email method of its own.
      db
        .prepare(
          `UPDATE users SET display_name = COALESCE(display_name, ?1),
             primary_email = CASE
               WHEN EXISTS (SELECT 1 FROM identities WHERE user_id = ?4 AND provider = 'email')
               THEN primary_email ELSE ?2 END,
             updated_at = ?3
           WHERE id = ?4`,
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

// ---- Sign-in methods (DESIGN §4.9) ------------------------------------------------------------

export type Provider = 'google' | 'email';

export interface Identity {
  id: string;
  provider: Provider;
  /** The address: the Google account's, or the email method's own. */
  email: string | null;
  createdAt: number;
  lastLoginAt: number;
  /** The owner's Google account: removing it would lock the owner out of /admin. */
  isOwner: boolean;
  /** An address at a domain of the organization that manages the account: it stays (§4.18). */
  locked: boolean;
}

export async function listIdentities(env: Env, userId: string): Promise<Identity[]> {
  const ownerSub: string = env.OWNER_GOOGLE_SUB;
  const { results } = await env.DB.prepare(
    `SELECT i.id, i.provider, i.subject, i.email, i.created_at, i.last_login_at,
            EXISTS (SELECT 1 FROM users u JOIN org_domains d ON d.org_id = u.managed_by
                    WHERE u.id = i.user_id AND d.managed_at IS NOT NULL
                      AND d.domain = substr(i.email, instr(i.email, '@') + 1) COLLATE NOCASE) AS locked
     FROM identities i
     WHERE i.user_id = ? ORDER BY i.created_at, i.provider`,
  )
    .bind(userId)
    .all<{
      id: string;
      provider: Provider;
      subject: string;
      email: string | null;
      created_at: number;
      last_login_at: number;
      locked: number;
    }>();
  return results.map((row) => ({
    id: row.id,
    provider: row.provider,
    email: row.email,
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
    isOwner: row.provider === 'google' && ownerSub.length > 0 && row.subject === ownerSub,
    locked: row.locked === 1,
  }));
}

/** The account that signs in with this address, by its email method. */
export async function userForEmail(db: D1Database, email: string): Promise<string | null> {
  const row = await db
    .prepare("SELECT user_id FROM identities WHERE provider = 'email' AND subject = ?")
    .bind(email)
    .first<{ user_id: string }>();
  return row?.user_id ?? null;
}

/**
 * Another account that already has this address, verified, by any method. Accounts are never
 * joined by address (THREAT_MODEL B3): a second account with it is refused instead, and the
 * person is sent to the account they have.
 */
export async function accountWithEmail(
  db: D1Database,
  email: string,
  exceptUserId: string | null = null,
): Promise<{ userId: string; provider: Provider } | null> {
  const row = await db
    .prepare(
      `SELECT user_id, provider FROM identities
       WHERE email = ? COLLATE NOCASE AND email_verified = 1 AND user_id IS NOT ?
       ORDER BY CASE provider WHEN 'email' THEN 0 ELSE 1 END LIMIT 1`,
    )
    .bind(email, exceptUserId)
    .first<{ user_id: string; provider: Provider }>();
  return row ? { userId: row.user_id, provider: row.provider } : null;
}

/** Whether an invitation names this address (sign-up by invitation only). */
export async function emailInvited(db: D1Database, email: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS ok FROM allowlist WHERE kind = 'email' AND value = ?")
    .bind(email)
    .first<{ ok: number }>();
  return row !== null;
}

export async function createEmailUser(db: D1Database, now: number, email: string): Promise<string> {
  const userId = crypto.randomUUID();
  await db.batch([
    db
      .prepare(
        `INSERT INTO users (id, status, display_name, primary_email, created_at, updated_at)
         VALUES (?, 'active', NULL, ?, ?, ?)`,
      )
      .bind(userId, email, now, now),
    db
      .prepare(
        `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
         VALUES (?, ?, 'email', ?, ?, 1, ?, ?)`,
      )
      .bind(crypto.randomUUID(), userId, email, email, now, now),
  ]);
  return userId;
}

export async function touchEmailIdentity(db: D1Database, now: number, email: string) {
  await db
    .prepare("UPDATE identities SET last_login_at = ? WHERE provider = 'email' AND subject = ?")
    .bind(now, email)
    .run();
}

export async function addEmailIdentity(db: D1Database, now: number, userId: string, email: string) {
  await db
    .prepare(
      `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
       VALUES (?, ?, 'email', ?, ?, 1, ?, ?)`,
    )
    .bind(crypto.randomUUID(), userId, email, email, now, now)
    .run();
}

export async function addGoogleIdentity(
  db: D1Database,
  now: number,
  userId: string,
  identity: GoogleIdentity,
) {
  await db
    .prepare(
      `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
       VALUES (?, ?, 'google', ?, ?, 1, ?, ?)`,
    )
    .bind(crypto.randomUUID(), userId, identity.subject, identity.email, now, now)
    .run();
}

/** The Google account's owner, if it is already linked to an account. */
export async function userForGoogle(db: D1Database, subject: string): Promise<string | null> {
  const row = await db
    .prepare("SELECT user_id FROM identities WHERE provider = 'google' AND subject = ?")
    .bind(subject)
    .first<{ user_id: string }>();
  return row?.user_id ?? null;
}

/**
 * Removes one sign-in method, never the last. When it carried the account's address, the
 * address of a remaining method takes its place.
 */
export async function removeIdentity(
  db: D1Database,
  now: number,
  userId: string,
  identityId: string,
): Promise<Identity['provider'] | null> {
  const rows = await db
    .prepare('SELECT id, provider, email FROM identities WHERE user_id = ? ORDER BY created_at')
    .bind(userId)
    .all<{ id: string; provider: Provider; email: string | null }>();
  const target = rows.results.find((row) => row.id === identityId);
  const remaining = rows.results.filter((row) => row.id !== identityId);
  if (!target || remaining.length === 0) return null;
  const fallback = remaining.find((row) => row.email)?.email ?? null;
  await db.batch([
    db.prepare('DELETE FROM identities WHERE id = ? AND user_id = ?').bind(identityId, userId),
    db
      .prepare(
        `UPDATE users SET primary_email = ?, updated_at = ?
         WHERE id = ? AND (primary_email IS NULL OR primary_email = ? COLLATE NOCASE)`,
      )
      .bind(fallback, now, userId, target.email ?? ''),
  ]);
  return target.provider;
}

export async function setDisplayName(db: D1Database, now: number, userId: string, name: string) {
  const clean = name.trim().replace(/\s+/g, ' ').slice(0, 80);
  await db
    .prepare('UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?')
    .bind(clean.length > 0 ? clean : null, now, userId)
    .run();
}
