import { hmacHex, randomToken, timingSafeEqual } from './crypto';

/** A sign-in in progress (DESIGN §4.2). Lives at most 10 minutes and is used once. */
export const LOGIN_TX_TTL_SECONDS = 600;

/**
 * Why the trip to Google was started. `delete_account` is the re-authentication before an
 * account is deleted (DESIGN §6.3); it never creates a session.
 */
export type LoginPurpose = 'sign_in' | 'delete_account' | 'link_google';

export interface NewLoginTx {
  /** Value for the __Host-login_tx cookie. Only its HMAC is stored. */
  cookieValue: string;
  state: string;
  nonce: string;
  pkceVerifier: string;
}

export interface LoginTx {
  nonce: string;
  pkceVerifier: string;
  returnTo: string | null;
  purpose: LoginPurpose;
  /** For `delete_account`: the account the user asked to delete. */
  userId: string | null;
}

export async function createLoginTx(
  db: D1Database,
  pepper: string,
  now: number,
  returnTo: string | null,
  options: { purpose?: LoginPurpose; userId?: string } = {},
): Promise<NewLoginTx> {
  const tx: NewLoginTx = {
    cookieValue: randomToken(32),
    state: randomToken(32),
    nonce: randomToken(32),
    pkceVerifier: randomToken(48),
  };
  const idHash = await hmacHex(pepper, `login_tx:${tx.cookieValue}`);

  await db.batch([
    // Opportunistic cleanup keeps the table small without a separate job.
    db.prepare('DELETE FROM login_tx WHERE expires_at < ?').bind(now),
    db
      .prepare(
        `INSERT INTO login_tx
           (id_hash, state, nonce, pkce_verifier, return_to, purpose, user_id, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        idHash,
        tx.state,
        tx.nonce,
        tx.pkceVerifier,
        returnTo,
        options.purpose ?? 'sign_in',
        options.userId ?? null,
        now,
        now + LOGIN_TX_TTL_SECONDS,
      ),
  ]);
  return tx;
}

/**
 * Consumes the transaction bound to this browser. It is deleted whether or not the checks pass,
 * so a callback can never be replayed. Returns null if the cookie, state or lifetime is wrong.
 */
export async function consumeLoginTx(
  db: D1Database,
  pepper: string,
  now: number,
  cookieValue: string | undefined,
  state: string | undefined,
): Promise<LoginTx | null> {
  if (!cookieValue || !state) return null;
  const idHash = await hmacHex(pepper, `login_tx:${cookieValue}`);

  const row = await db
    .prepare(
      `DELETE FROM login_tx WHERE id_hash = ?
       RETURNING state, nonce, pkce_verifier, return_to, purpose, user_id, expires_at`,
    )
    .bind(idHash)
    .first<{
      state: string;
      nonce: string;
      pkce_verifier: string;
      return_to: string | null;
      purpose: LoginPurpose;
      user_id: string | null;
      expires_at: number;
    }>();

  if (!row) return null;
  if (row.expires_at < now) return null;
  if (!timingSafeEqual(row.state, state)) return null;
  return {
    nonce: row.nonce,
    pkceVerifier: row.pkce_verifier,
    returnTo: row.return_to,
    purpose: row.purpose,
    userId: row.user_id,
  };
}
