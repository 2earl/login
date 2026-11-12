import { EmbeddedJWK, base64url, calculateJwkThumbprint, jwtVerify, type JWK } from 'jose';
import { sha256, sha256Hex } from './crypto';

/**
 * DPoP, RFC 9449 (DESIGN §4.15): proof that the caller holds the private key a token is bound
 * to. Checked at the token endpoint and wherever login accepts its own access tokens.
 */

/** Asymmetric algorithms only; never `none` or an HMAC (RFC 9449 §4.3). */
export const DPOP_ALGS = ['ES256', 'EdDSA', 'RS256', 'PS256'];
/** How old a proof may be, and how far ahead of our clock (seconds). */
const MAX_AGE_SECONDS = 60;
const MAX_FUTURE_SECONDS = 10;
/** Proofs seen are remembered this long: longer than a proof is accepted. */
const REPLAY_WINDOW_SECONDS = 2 * 60;

export class DpopError extends Error {
  constructor(readonly description: string) {
    super(description);
    this.name = 'DpopError';
  }
}

/** The URL without query or fragment, as `htu` is compared (RFC 9449 §4.3, point 9). */
function targetUri(value: string): string | null {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host.toLowerCase()}${url.pathname}`;
  } catch {
    return null;
  }
}

/**
 * Checks one DPoP proof for this request and returns the thumbprint of its key (`jkt`).
 * `accessToken`: the token presented with it to a resource, which the proof must name (`ath`).
 * Throws DpopError, whose description is safe to return to the client.
 */
export async function verifyDpopProof(
  db: D1Database,
  now: number,
  params: { proof: string | null | undefined; method: string; url: string; accessToken?: string },
): Promise<{ jkt: string }> {
  const proof = params.proof?.trim();
  // One DPoP header only: two are joined with a comma, which a compact JWT never contains.
  if (!proof || proof.includes(',') || proof.length > 8192) {
    throw new DpopError('Send exactly one DPoP proof');
  }
  let payload;
  let jwk: JWK | undefined;
  try {
    const verified = await jwtVerify(proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: DPOP_ALGS,
      currentDate: new Date(now * 1000),
    });
    payload = verified.payload;
    jwk = verified.protectedHeader.jwk;
  } catch {
    throw new DpopError('The DPoP proof is not valid');
  }
  if (!jwk || 'd' in jwk || 'k' in jwk) throw new DpopError('The DPoP key must be a public key');
  const { jti, htm, htu, iat, ath } = payload as Record<string, unknown>;
  if (typeof jti !== 'string' || jti.length < 8 || jti.length > 256) {
    throw new DpopError('The DPoP proof needs a unique jti');
  }
  if (htm !== params.method) throw new DpopError('The DPoP proof is for another method');
  if (typeof htu !== 'string' || targetUri(htu) !== targetUri(params.url)) {
    throw new DpopError('The DPoP proof is for another URL');
  }
  if (typeof iat !== 'number' || iat < now - MAX_AGE_SECONDS || iat > now + MAX_FUTURE_SECONDS) {
    throw new DpopError('The DPoP proof is too old or from the future');
  }
  if (params.accessToken !== undefined) {
    const expected = base64url.encode(await sha256(params.accessToken));
    if (ath !== expected) throw new DpopError('The DPoP proof is for another access token');
  }
  const jkt = await calculateJwkThumbprint(jwk, 'sha256');

  // Each proof works once (RFC 9449 §11.1).
  const seen = await db
    .prepare(
      `INSERT INTO dpop_proofs (id_hash, expires_at) VALUES (?, ?)
       ON CONFLICT (id_hash) DO NOTHING`,
    )
    .bind(await sha256Hex(`${jkt}:${jti}`), now + REPLAY_WINDOW_SECONDS)
    .run();
  if (seen.meta.changes === 0) throw new DpopError('This DPoP proof was already used');
  return { jkt };
}

/**
 * What the token endpoint tells the authorization server's callback about this request's proof
 * (src/oauth.ts), and what the callback reports back: whether the access token was bound.
 */
export interface DpopContext {
  jkt: string;
  accessTokenBound: boolean;
}

/** The env for one token request, carrying its DPoP context to the callback. */
export function withDpop(env: Env, jkt: string): Env & { DPOP: DpopContext } {
  const context: DpopContext = { jkt, accessTokenBound: false };
  return Object.create(env, { DPOP: { value: context, enumerable: true } }) as Env & {
    DPOP: DpopContext;
  };
}

export function dpopOf(env: Env): DpopContext | null {
  const value = (env as { DPOP?: unknown }).DPOP;
  return value !== null && typeof value === 'object' ? (value as DpopContext) : null;
}

/** `Authorization: Bearer <token>` or `Authorization: DPoP <token>`. */
export function readAuthorization(
  header: string | null | undefined,
): { scheme: 'bearer' | 'dpop'; token: string } | null {
  // The library's tokens contain `:`, outside RFC 6750's b64token; any non-space value is read.
  const match = /^(Bearer|DPoP)\s+(\S+)$/i.exec((header ?? '').trim());
  if (!match?.[1] || !match[2]) return null;
  return { scheme: match[1].toLowerCase() === 'dpop' ? 'dpop' : 'bearer', token: match[2] };
}
