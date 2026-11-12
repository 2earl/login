import { SignJWT, base64url, calculateJwkThumbprint, importJWK, jwtVerify, type JWK } from 'jose';
import type { GrantProps } from './oauth';
import { ACR_AAL2 } from './oauth';
import { IDENTITY } from './services';

/**
 * login as an OpenID Connect provider (DESIGN §4.11): signing keys, ID tokens, pairwise subject
 * identifiers and the claims each scope releases. Routes are in oidc-routes.ts.
 *
 * Signing: ES256 with one P-256 key, the Worker secret OIDC_SIGNING_KEY (a private JWK made by
 * `pnpm oidc:key`). Its public half is published at /.well-known/jwks.json, named by its RFC 7638
 * thumbprint. Rotation: publish the next key's public half first (OIDC_NEXT_PUBLIC_KEY), then
 * swap; the old public key stays published until ID tokens signed with it have expired.
 */

export const ID_TOKEN_TTL_SECONDS = 10 * 60;
export const ACR_AAL1 = 'urn:2earl:aal1';
export const OIDC_SCOPES = ['openid', 'profile', 'email'] as const;

interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

const keys = new Map<string, Promise<SigningKey>>();

function parseJwk(text: string, name: string): JWK {
  let jwk: JWK;
  try {
    jwk = JSON.parse(text) as JWK;
  } catch {
    throw new Error(`${name} is not a JSON Web Key`);
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error(`${name} must be an EC P-256 key`);
  return jwk;
}

async function publicOf(jwk: JWK): Promise<JWK> {
  const pub: JWK = { kty: 'EC', crv: 'P-256', x: jwk.x ?? '', y: jwk.y ?? '' };
  return { ...pub, kid: await calculateJwkThumbprint(pub), alg: 'ES256', use: 'sig' };
}

/** The current signing key, parsed once per isolate. */
export function signingKey(env: Env): Promise<SigningKey> {
  const secret = env.OIDC_SIGNING_KEY;
  let key = keys.get(secret);
  if (!key) {
    key = (async () => {
      const jwk = parseJwk(secret, 'OIDC_SIGNING_KEY');
      if (!jwk.d) throw new Error('OIDC_SIGNING_KEY must be a private key');
      const publicJwk = await publicOf(jwk);
      const privateKey = (await importJWK({ ...jwk, alg: 'ES256' }, 'ES256')) as CryptoKey;
      return { kid: publicJwk.kid ?? '', privateKey, publicJwk };
    })();
    keys.set(secret, key);
  }
  return key;
}

/** Every public key a relying party may meet: the current one, and the next one if announced. */
export async function publicKeys(env: Env): Promise<JWK[]> {
  const current = (await signingKey(env)).publicJwk;
  const next = env.OIDC_NEXT_PUBLIC_KEY.trim();
  if (!next) return [current];
  const announced = await publicOf(parseJwk(next, 'OIDC_NEXT_PUBLIC_KEY'));
  return announced.kid === current.kid ? [current] : [current, announced];
}

// ---- Pairwise subjects (OIDC Core §8.1) ---------------------------------------------------------

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * The sector a site belongs to: the host it redirects to. Apps on the user's own device (loopback
 * redirects) all share those hosts, so each is its own sector, by client ID.
 */
export function sectorFor(clientId: string, redirectUri: string): string {
  try {
    const host = new URL(redirectUri).hostname;
    if (!LOOPBACK.has(host)) return host;
  } catch {
    // An invalid redirect URI never reaches here (the library checks it); fall back safely.
  }
  return `client:${clientId}`;
}

/** The subject this sector knows the user by, created on first use. Random, not derived. */
export async function pairwiseSubject(
  db: D1Database,
  now: number,
  userId: string,
  sector: string,
): Promise<string> {
  const candidate = base64url.encode(crypto.getRandomValues(new Uint8Array(24)));
  const row = await db
    .prepare(
      `INSERT INTO oidc_subjects (sub, user_id, sector, created_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (user_id, sector) DO UPDATE SET sector = excluded.sector
       RETURNING sub`,
    )
    .bind(candidate, userId, sector, now)
    .first<{ sub: string }>();
  if (!row) throw new Error('pairwise subject not stored');
  return row.sub;
}

// ---- Claims -------------------------------------------------------------------------------------

/** When and how the grant's session signed in, wherever the grant recorded it. */
export function signInOf(props: GrantProps): {
  signedInAt: number;
  method: 'google' | 'email' | 'passkey' | null;
} {
  return {
    signedInAt: props.signedInAt ?? props.oidc?.signedInAt ?? props.authTime,
    method: props.method ?? props.oidc?.method ?? null,
  };
}

/** `acr`: whether a second factor or passkey was verified when the grant was approved. */
export function acrFor(props: GrantProps): string {
  return props.aal2At !== null ? ACR_AAL2 : ACR_AAL1;
}

/** RFC 8176 authentication method references for how the session signed in. */
export function amrFor(props: GrantProps): string[] {
  const { method } = signInOf(props);
  const aal2 = props.aal2At !== null;
  const base =
    method === 'google'
      ? ['fed']
      : method === 'email'
        ? ['otp']
        : method === 'passkey'
          ? ['pop', 'user']
          : [];
  return aal2 && !base.includes('mfa') ? [...base, 'mfa'] : base;
}

export interface UserClaims {
  name?: string;
  email?: string;
  email_verified?: boolean;
  updated_at?: number;
}

/** What `profile` and `email` release about the account, now. */
export async function userClaims(
  db: D1Database,
  userId: string,
  scope: readonly string[],
): Promise<UserClaims | null> {
  const user = await db
    .prepare(
      "SELECT display_name, primary_email, updated_at FROM users WHERE id = ? AND status = 'active'",
    )
    .bind(userId)
    .first<{ display_name: string | null; primary_email: string | null; updated_at: number }>();
  if (!user) return null;
  const claims: UserClaims = {};
  if (scope.includes('profile')) {
    if (user.display_name) claims.name = user.display_name;
    claims.updated_at = user.updated_at;
  }
  if (scope.includes('email') && user.primary_email) {
    // Every address on an account was verified: by Google, or by a code sent to it.
    claims.email = user.primary_email;
    claims.email_verified = true;
  }
  return claims;
}

/** `at_hash`: the left half of the SHA-256 of the access token (OIDC Core §3.1.3.6). */
async function atHash(accessToken: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken)),
  );
  return base64url.encode(digest.slice(0, 16));
}

/** Signs the ID token for one token response. `nonce` only for the code exchange. */
export async function issueIdToken(
  env: Env,
  db: D1Database,
  params: {
    now: number;
    clientId: string;
    props: GrantProps;
    scope: readonly string[];
    accessToken: string;
    includeNonce: boolean;
  },
): Promise<string | null> {
  const oidc = params.props.oidc;
  if (!oidc) return null;
  const claims = await userClaims(db, params.props.uid, params.scope);
  if (!claims) return null;
  const key = await signingKey(env);
  const body: Record<string, unknown> = {
    ...claims,
    auth_time: signInOf(params.props).signedInAt,
    acr: acrFor(params.props),
    amr: amrFor(params.props),
    at_hash: await atHash(params.accessToken),
    azp: params.clientId,
  };
  if (params.includeNonce && oidc.nonce) body.nonce = oidc.nonce;
  return new SignJWT(body)
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: key.kid })
    .setIssuer(env.ISSUER)
    .setSubject(oidc.sub)
    .setAudience(params.clientId)
    .setIssuedAt(params.now)
    .setExpirationTime(params.now + ID_TOKEN_TTL_SECONDS)
    .sign(key.privateKey);
}

/**
 * Reads an `id_token_hint` (RP-Initiated Logout §2): our signature and issuer, expired or not, as
 * the spec allows. Returns the app it was issued to and the subject, or null.
 */
export async function readIdTokenHint(
  env: Env,
  token: string,
): Promise<{ clientId: string; sub: string } | null> {
  try {
    const { publicJwk } = await signingKey(env);
    const key = await importJWK(publicJwk, 'ES256');
    const { payload } = await jwtVerify(token, key, {
      issuer: env.ISSUER,
      algorithms: ['ES256'],
      // An expired hint still names the app and user it was for.
      currentDate: new Date(0),
    });
    const aud = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;
    if (typeof aud !== 'string' || typeof payload.sub !== 'string') return null;
    return { clientId: aud, sub: payload.sub };
  } catch {
    return null;
  }
}

/** The UserInfo resource: the audience OpenID Connect access tokens are bound to. */
export function userInfoResource(env: Env): string {
  return IDENTITY.resource(env);
}
