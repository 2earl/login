import { base64url, hmacHex, sha256 } from './crypto';

/**
 * Second factor (DESIGN §4.7): storage, policy and lockout. The WebAuthn and TOTP checks are in
 * app.ts (passkeys, via @simplewebauthn/server) and totp.ts.
 */

/** A second-factor proof counts as fresh for this long (factor changes, deletion). */
export const STEP_UP_MAX_AGE_SECONDS = 5 * 60;
/** Enrolling the first factor needs a Google sign-in at most this old. */
export const FIRST_FACTOR_MAX_SESSION_AGE_SECONDS = 10 * 60;
export const PENDING_TTL_SECONDS = 10 * 60;
export const MAX_FAILED_ATTEMPTS = 5;
export const LOCKOUT_SECONDS = 15 * 60;
export const RECOVERY_CODE_COUNT = 10;

export type FactorKind = 'webauthn' | 'totp';

export interface Factor {
  id: string;
  kind: FactorKind;
  label: string;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface PasskeyRecord {
  id: string;
  credentialId: string;
  publicKey: string;
  signCount: number;
  transports: string[];
}

export interface TotpRecord {
  id: string;
  secretEnc: string;
  lastStep: number | null;
}

/** What the session must do before it can be used. */
export type MfaGate = 'challenge' | 'enrol' | null;

export function mfaRequired(env: Env): boolean {
  const flag: string = env.MFA_REQUIRED;
  return flag === 'true';
}

/** Enrolled users are always challenged, whatever the flag; the flag only forces enrolment. */
export function mfaGate(env: Env, session: { aal: 'aal1' | 'aal2'; hasFactor: boolean }): MfaGate {
  if (session.hasFactor) return session.aal === 'aal2' ? null : 'challenge';
  return mfaRequired(env) ? 'enrol' : null;
}

export function isStepUpFresh(
  session: { aal: 'aal1' | 'aal2'; aal2At: number | null },
  now: number,
): boolean {
  return (
    session.aal === 'aal2' &&
    session.aal2At !== null &&
    now - session.aal2At <= STEP_UP_MAX_AGE_SECONDS
  );
}

// ---- Encryption of secrets at rest ------------------------------------------------------------

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const aesKeys = new Map<string, Promise<CryptoKey>>();

/** AES-256-GCM key derived from the MFA_ENCRYPTION_KEY secret (any string format). */
function aesKey(secret: string): Promise<CryptoKey> {
  let key = aesKeys.get(secret);
  if (!key) {
    key = sha256(`mfa-encryption:${secret}`).then((raw) =>
      crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']),
    );
    aesKeys.set(secret, key);
  }
  return key;
}

function fromBase64url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** Encrypts `plaintext` bound to `context` (user ID or session), which must match on decrypt. */
export async function encryptSecret(
  secret: string,
  context: string,
  plaintext: string,
): Promise<string> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(context) },
    await aesKey(secret),
    encoder.encode(plaintext),
  );
  return `${base64url(iv)}.${base64url(new Uint8Array(ciphertext))}`;
}

export async function decryptSecret(
  secret: string,
  context: string,
  sealed: string,
): Promise<string> {
  const [iv, data] = sealed.split('.');
  if (!iv || !data) throw new Error('malformed ciphertext');
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64url(iv), additionalData: encoder.encode(context) },
    await aesKey(secret),
    fromBase64url(data),
  );
  return decoder.decode(plaintext);
}

// ---- Factors ----------------------------------------------------------------------------------

export async function listFactors(db: D1Database, userId: string): Promise<Factor[]> {
  const { results } = await db
    .prepare(
      `SELECT id, kind, label, created_at, last_used_at FROM mfa_factors
       WHERE user_id = ? ORDER BY created_at, id`,
    )
    .bind(userId)
    .all<{
      id: string;
      kind: FactorKind;
      label: string;
      created_at: number;
      last_used_at: number | null;
    }>();
  return results.map((row) => ({
    id: row.id,
    kind: row.kind,
    label: row.label,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  }));
}

export async function listPasskeys(db: D1Database, userId: string): Promise<PasskeyRecord[]> {
  const { results } = await db
    .prepare(
      `SELECT id, webauthn_credential_id, webauthn_public_key, webauthn_sign_count, webauthn_transports
       FROM mfa_factors WHERE user_id = ? AND kind = 'webauthn'`,
    )
    .bind(userId)
    .all<{
      id: string;
      webauthn_credential_id: string;
      webauthn_public_key: string;
      webauthn_sign_count: number | null;
      webauthn_transports: string | null;
    }>();
  return results.map((row) => ({
    id: row.id,
    credentialId: row.webauthn_credential_id,
    publicKey: row.webauthn_public_key,
    signCount: row.webauthn_sign_count ?? 0,
    transports: row.webauthn_transports ? (JSON.parse(row.webauthn_transports) as string[]) : [],
  }));
}

export async function getTotp(db: D1Database, userId: string): Promise<TotpRecord | null> {
  const row = await db
    .prepare(
      "SELECT id, totp_secret_enc, totp_last_step FROM mfa_factors WHERE user_id = ? AND kind = 'totp'",
    )
    .bind(userId)
    .first<{ id: string; totp_secret_enc: string; totp_last_step: number | null }>();
  return row ? { id: row.id, secretEnc: row.totp_secret_enc, lastStep: row.totp_last_step } : null;
}

export async function addPasskey(
  db: D1Database,
  userId: string,
  now: number,
  passkey: {
    credentialId: string;
    publicKey: string;
    signCount: number;
    transports: string[];
    label: string;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO mfa_factors (id, user_id, kind, label, created_at, webauthn_credential_id,
         webauthn_public_key, webauthn_sign_count, webauthn_transports)
       VALUES (?, ?, 'webauthn', ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      crypto.randomUUID(),
      userId,
      passkey.label,
      now,
      passkey.credentialId,
      passkey.publicKey,
      passkey.signCount,
      JSON.stringify(passkey.transports),
    )
    .run();
}

export async function addTotp(
  db: D1Database,
  userId: string,
  now: number,
  secretEnc: string,
  step: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO mfa_factors (id, user_id, kind, label, created_at, last_used_at, totp_secret_enc, totp_last_step)
       VALUES (?, ?, 'totp', 'Authenticator app', ?, ?, ?, ?)`,
    )
    .bind(crypto.randomUUID(), userId, now, now, secretEnc, step)
    .run();
}

/** Removes one of the user's factors. The last one also takes the recovery codes with it. */
export async function removeFactor(
  db: D1Database,
  userId: string,
  factorId: string,
): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM mfa_factors WHERE id = ? AND user_id = ?')
    .bind(factorId, userId)
    .run();
  if (result.meta.changes === 0) return false;
  await db
    .prepare(
      'DELETE FROM recovery_codes WHERE user_id = ? AND NOT EXISTS (SELECT 1 FROM mfa_factors WHERE user_id = ?)',
    )
    .bind(userId, userId)
    .run();
  return true;
}

// ---- Recovery codes ---------------------------------------------------------------------------

/** Crockford base32, lowercase: no i, l, o or u, so codes read back unambiguously. */
const CODE_ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';

function normalizeRecoveryCode(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^0-9a-z]/g, '')
    .replace(/o/g, '0')
    .replace(/[il]/g, '1');
}

function newRecoveryCode(): string {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  const chars = Array.from(bytes, (b) => CODE_ALPHABET[b & 31]).join(''); // 50 bits
  return `${chars.slice(0, 5)}-${chars.slice(5)}`;
}

function recoveryHash(key: string, userId: string, code: string): Promise<string> {
  return hmacHex(key, `recovery:${userId}:${normalizeRecoveryCode(code)}`);
}

/** Replaces the user's recovery codes with ten new ones and returns them (shown once). */
export async function regenerateRecoveryCodes(
  db: D1Database,
  key: string,
  userId: string,
): Promise<string[]> {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, newRecoveryCode);
  const hashes = await Promise.all(codes.map((code) => recoveryHash(key, userId, code)));
  await db.batch([
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(userId),
    ...hashes.map((hash) =>
      db
        .prepare('INSERT INTO recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)')
        .bind(crypto.randomUUID(), userId, hash),
    ),
  ]);
  return codes;
}

/** Marks a matching unused code as used. Returns how many unused codes remain, or null. */
export async function useRecoveryCode(
  db: D1Database,
  key: string,
  userId: string,
  code: string,
  now: number,
): Promise<number | null> {
  if (normalizeRecoveryCode(code).length !== 10) return null;
  const hash = await recoveryHash(key, userId, code);
  const used = await db
    .prepare(
      'UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL',
    )
    .bind(now, userId, hash)
    .run();
  if (used.meta.changes === 0) return null;
  return remainingRecoveryCodes(db, userId);
}

export async function remainingRecoveryCodes(db: D1Database, userId: string): Promise<number> {
  const row = await db
    .prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
    .bind(userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

// ---- Pending steps ----------------------------------------------------------------------------

export type PendingPurpose =
  'webauthn_register' | 'webauthn_authenticate' | 'totp_enrol' | 'recovery_codes';

export async function putPending(
  db: D1Database,
  sessionHash: string,
  purpose: PendingPurpose,
  value: string,
  now: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO mfa_pending (session_hash, purpose, value, expires_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (session_hash, purpose) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`,
    )
    .bind(sessionHash, purpose, value, now + PENDING_TTL_SECONDS)
    .run();
}

/** Reads and deletes a pending value, so each challenge or secret is used once. */
export async function takePending(
  db: D1Database,
  sessionHash: string,
  purpose: PendingPurpose,
  now: number,
): Promise<string | null> {
  const row = await db
    .prepare(
      'DELETE FROM mfa_pending WHERE session_hash = ? AND purpose = ? RETURNING value, expires_at',
    )
    .bind(sessionHash, purpose)
    .first<{ value: string; expires_at: number }>();
  return row && row.expires_at >= now ? row.value : null;
}

export async function peekPending(
  db: D1Database,
  sessionHash: string,
  purpose: PendingPurpose,
  now: number,
): Promise<string | null> {
  const row = await db
    .prepare('SELECT value, expires_at FROM mfa_pending WHERE session_hash = ? AND purpose = ?')
    .bind(sessionHash, purpose)
    .first<{ value: string; expires_at: number }>();
  return row && row.expires_at >= now ? row.value : null;
}

// ---- Session assurance and lockout ------------------------------------------------------------

export async function markSessionAal2(
  db: D1Database,
  sessionHash: string,
  now: number,
): Promise<void> {
  await db
    .prepare("UPDATE sessions SET aal = 'aal2', aal2_at = ? WHERE id_hash = ?")
    .bind(now, sessionHash)
    .run();
}

/** Unix time until which the user's second-factor step is locked, or null. */
export async function lockedUntil(
  db: D1Database,
  userId: string,
  now: number,
): Promise<number | null> {
  const row = await db
    .prepare('SELECT mfa_locked_until FROM users WHERE id = ?')
    .bind(userId)
    .first<{ mfa_locked_until: number | null }>();
  const until = row?.mfa_locked_until ?? null;
  return until !== null && until > now ? until : null;
}

/** Counts a wrong code; the fifth in a row locks the step. Returns true if now locked. */
export async function recordFailure(db: D1Database, userId: string, now: number): Promise<boolean> {
  const row = await db
    .prepare(
      `UPDATE users SET
         mfa_failed_attempts = CASE WHEN mfa_failed_attempts + 1 >= ?1 THEN 0 ELSE mfa_failed_attempts + 1 END,
         mfa_locked_until    = CASE WHEN mfa_failed_attempts + 1 >= ?1 THEN ?2 ELSE mfa_locked_until END
       WHERE id = ?3 RETURNING mfa_locked_until`,
    )
    .bind(MAX_FAILED_ATTEMPTS, now + LOCKOUT_SECONDS, userId)
    .first<{ mfa_locked_until: number | null }>();
  return (row?.mfa_locked_until ?? 0) > now;
}

export async function clearFailures(db: D1Database, userId: string): Promise<void> {
  await db
    .prepare('UPDATE users SET mfa_failed_attempts = 0, mfa_locked_until = NULL WHERE id = ?')
    .bind(userId)
    .run();
}
