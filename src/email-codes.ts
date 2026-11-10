import { hmacHex, randomToken, timingSafeEqual } from './crypto';
import type { CodePurpose } from './mail';

/**
 * One-time codes sent by email (DESIGN §4.9). A code is bound to the browser that asked for it
 * by the __Host-email_code cookie (only its HMAC is stored), so a code or link that reaches
 * someone else's browser signs nobody in, and nobody can be signed in to someone else's account
 * by being sent a link (login CSRF).
 */

export const EMAIL_CODE_COOKIE = '__Host-email_code';
export const EMAIL_CODE_TTL_SECONDS = 10 * 60;
export const MAX_CODE_ATTEMPTS = 5;

/** How many codes may be sent, so the form can't be used to flood an inbox or our sender. */
export const SEND_LIMITS = {
  perAddressPerHour: 5,
  perAddressPerDay: 10,
  perNetworkPerHour: 20,
  perDay: 2000,
} as const;

export interface EmailCodeRow {
  idHash: string;
  email: string;
  purpose: CodePurpose;
  userId: string | null;
  returnTo: string | null;
  attempts: number;
  expiresAt: number;
}

interface Row {
  id_hash: string;
  email: string;
  purpose: CodePurpose;
  user_id: string | null;
  return_to: string | null;
  attempts: number;
  expires_at: number;
  code_hash: string;
}

function toRow(row: Row): EmailCodeRow {
  return {
    idHash: row.id_hash,
    email: row.email,
    purpose: row.purpose,
    userId: row.user_id,
    returnTo: row.return_to,
    attempts: row.attempts,
    expiresAt: row.expires_at,
  };
}

/** Six digits, uniformly random. */
export function newCode(): string {
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    const value = buffer[0] ?? 0;
    // Rejection sampling: 4_294_000_000 is the largest multiple of 1_000_000 below 2^32.
    if (value < 4_294_000_000) return String(value % 1_000_000).padStart(6, '0');
  }
}

const idHashOf = (pepper: string, cookie: string) => hmacHex(pepper, `email_code:${cookie}`);
const codeHashOf = (pepper: string, idHash: string, code: string) =>
  hmacHex(pepper, `email_code_value:${idHash}:${code}`);
const linkHashOf = (pepper: string, token: string) => hmacHex(pepper, `email_link:${token}`);

/** Which limit sending one more code to `email` from `ipPrefix` would exceed, if any. */
export async function sendLimit(
  db: D1Database,
  now: number,
  email: string,
  ipPrefix: string | null,
): Promise<'address' | 'network' | 'service' | null> {
  const row = await db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM email_codes WHERE email = ?1 AND created_at > ?2) AS address_hour,
         (SELECT COUNT(*) FROM email_codes WHERE email = ?1 AND created_at > ?3) AS address_day,
         (SELECT COUNT(*) FROM email_codes WHERE ip_prefix = ?4 AND created_at > ?2) AS network_hour,
         (SELECT COUNT(*) FROM email_codes WHERE created_at > ?3) AS day`,
    )
    .bind(email, now - 3600, now - 86_400, ipPrefix ?? '')
    .first<{ address_hour: number; address_day: number; network_hour: number; day: number }>();
  if (!row) return null;
  if (row.day >= SEND_LIMITS.perDay) return 'service';
  if (row.address_hour >= SEND_LIMITS.perAddressPerHour) return 'address';
  if (row.address_day >= SEND_LIMITS.perAddressPerDay) return 'address';
  if (ipPrefix && row.network_hour >= SEND_LIMITS.perNetworkPerHour) return 'network';
  return null;
}

export async function createEmailCode(
  db: D1Database,
  pepper: string,
  now: number,
  input: {
    email: string;
    purpose: CodePurpose;
    userId?: string | null;
    returnTo?: string | null;
    ipPrefix: string | null;
  },
): Promise<{ cookieValue: string; code: string; linkToken: string }> {
  const cookieValue = randomToken(32);
  const linkToken = randomToken(32);
  const code = newCode();
  const idHash = await idHashOf(pepper, cookieValue);
  await db.batch([
    // Rows are kept a day after they expire: the send limits count them.
    db.prepare('DELETE FROM email_codes WHERE created_at < ?').bind(now - 2 * 86_400),
    db
      .prepare(
        `INSERT INTO email_codes
           (id_hash, email, code_hash, link_hash, purpose, user_id, return_to, ip_prefix, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        idHash,
        input.email,
        await codeHashOf(pepper, idHash, code),
        await linkHashOf(pepper, linkToken),
        input.purpose,
        input.userId ?? null,
        input.returnTo ?? null,
        input.ipPrefix,
        now,
        now + EMAIL_CODE_TTL_SECONDS,
      ),
  ]);
  return { cookieValue, code, linkToken };
}

/** Removes a code that was never sent (the email failed). */
export async function discardEmailCode(db: D1Database, pepper: string, cookie: string) {
  await db
    .prepare('DELETE FROM email_codes WHERE id_hash = ?')
    .bind(await idHashOf(pepper, cookie))
    .run();
}

/** The code this browser is waiting for, if it is still usable. */
export async function pendingEmailCode(
  db: D1Database,
  pepper: string,
  now: number,
  cookie: string | undefined,
): Promise<EmailCodeRow | null> {
  if (!cookie) return null;
  const row = await db
    .prepare(
      `SELECT * FROM email_codes
       WHERE id_hash = ? AND used_at IS NULL AND expires_at >= ? AND attempts < ?`,
    )
    .bind(await idHashOf(pepper, cookie), now, MAX_CODE_ATTEMPTS)
    .first<Row>();
  return row ? toRow(row) : null;
}

export type CodeCheck =
  | { ok: true; row: EmailCodeRow }
  | { ok: false; reason: 'expired' }
  | { ok: false; reason: 'wrong'; triesLeft: number };

/** Checks a typed code. A wrong code uses up a try; the right one uses up the code. */
export async function checkEmailCode(
  db: D1Database,
  pepper: string,
  now: number,
  cookie: string | undefined,
  typed: string,
): Promise<CodeCheck> {
  const pending = await pendingEmailCode(db, pepper, now, cookie);
  if (!pending) return { ok: false, reason: 'expired' };
  const row = await db
    .prepare('SELECT code_hash FROM email_codes WHERE id_hash = ?')
    .bind(pending.idHash)
    .first<{ code_hash: string }>();
  const digits = typed.replace(/\D/g, '');
  const expected = row?.code_hash ?? '';
  const given = await codeHashOf(pepper, pending.idHash, digits);
  if (digits.length !== 6 || !timingSafeEqual(given, expected)) {
    await db
      .prepare('UPDATE email_codes SET attempts = attempts + 1 WHERE id_hash = ?')
      .bind(pending.idHash)
      .run();
    const triesLeft = MAX_CODE_ATTEMPTS - pending.attempts - 1;
    return triesLeft > 0
      ? { ok: false, reason: 'wrong', triesLeft }
      : { ok: false, reason: 'expired' };
  }
  return useUp(db, now, pending);
}

/** Checks a link from the email, in the browser that asked for the code. */
export async function checkEmailLink(
  db: D1Database,
  pepper: string,
  now: number,
  cookie: string | undefined,
  token: string,
): Promise<CodeCheck> {
  const pending = await pendingEmailCode(db, pepper, now, cookie);
  if (!pending || token.length < 20) return { ok: false, reason: 'expired' };
  const row = await db
    .prepare('SELECT link_hash FROM email_codes WHERE id_hash = ?')
    .bind(pending.idHash)
    .first<{ link_hash: string }>();
  if (!timingSafeEqual(await linkHashOf(pepper, token), row?.link_hash ?? '')) {
    return { ok: false, reason: 'expired' };
  }
  return useUp(db, now, pending);
}

/** Marks a code used, once: of two requests racing with the same code, one wins. */
async function useUp(db: D1Database, now: number, pending: EmailCodeRow): Promise<CodeCheck> {
  const result = await db
    .prepare('UPDATE email_codes SET used_at = ? WHERE id_hash = ? AND used_at IS NULL')
    .bind(now, pending.idHash)
    .run();
  return result.meta.changes === 1 ? { ok: true, row: pending } : { ok: false, reason: 'expired' };
}

/** "f•••@example.com": enough to recognise the address on a shared screen. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf('@');
  if (at < 1) return email;
  const local = email.slice(0, at);
  return `${local.slice(0, Math.min(2, local.length - 1))}•••${email.slice(at)}`;
}
