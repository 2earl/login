import { hmacHex, randomToken, timingSafeEqual } from './crypto';

/** A sign-in in progress (DESIGN §4.2). Lives at most 10 minutes and is used once. */
export const LOGIN_TX_TTL_SECONDS = 600;

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
}

export async function createLoginTx(
  db: D1Database,
  pepper: string,
  now: number,
  returnTo: string,
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
        `INSERT INTO login_tx (id_hash, state, nonce, pkce_verifier, return_to, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(idHash, tx.state, tx.nonce, tx.pkceVerifier, returnTo, now, now + LOGIN_TX_TTL_SECONDS),
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
       RETURNING state, nonce, pkce_verifier, return_to, expires_at`,
    )
    .bind(idHash)
    .first<{
      state: string;
      nonce: string;
      pkce_verifier: string;
      return_to: string | null;
      expires_at: number;
    }>();

  if (!row) return null;
  if (row.expires_at < now) return null;
  if (!timingSafeEqual(row.state, state)) return null;
  return { nonce: row.nonce, pkceVerifier: row.pkce_verifier, returnTo: row.return_to };
}
