import { jwtVerify, type JWTVerifyGetKey } from 'jose';

/** We are an OpenID Connect client of Google (DESIGN §4.2). */
export const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
export const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export interface GoogleIdentity {
  /** Google's stable account ID. Accounts are keyed on this, never on email. */
  subject: string;
  email: string;
  name: string | null;
}

/** A sign-in failure. `reason` is a fixed code that is safe to log and audit. */
export class GoogleSignInError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = 'GoogleSignInError';
  }
}

export function buildGoogleAuthUrl(params: {
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  codeChallenge: string;
}): string {
  const url = new URL(GOOGLE_AUTH_URL);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', params.state);
  url.searchParams.set('nonce', params.nonce);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('prompt', 'select_account');
  return url.toString();
}

/** Exchanges the authorization code for Google's ID token. Google's access token is discarded. */
export async function exchangeCode(
  fetchFn: typeof fetch,
  params: {
    clientId: string;
    clientSecret: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
  },
): Promise<string> {
  let response: Response;
  try {
    response = await fetchFn(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: params.clientId,
        client_secret: params.clientSecret,
        code: params.code,
        code_verifier: params.codeVerifier,
        redirect_uri: params.redirectUri,
      }),
    });
  } catch {
    throw new GoogleSignInError('token_request_failed');
  }
  if (!response.ok) throw new GoogleSignInError('token_exchange_rejected');

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new GoogleSignInError('token_response_invalid');
  }
  const idToken = (body as { id_token?: unknown }).id_token;
  if (typeof idToken !== 'string' || idToken.length === 0) {
    throw new GoogleSignInError('id_token_missing');
  }
  return idToken;
}

/**
 * Verifies Google's ID token: signature against Google's keys, issuer, audience, expiry (60 s
 * skew), nonce, and a verified email address.
 */
export async function verifyGoogleIdToken(
  idToken: string,
  options: { jwks: JWTVerifyGetKey; clientId: string; nonce: string; now: number },
): Promise<GoogleIdentity> {
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(idToken, options.jwks, {
      issuer: GOOGLE_ISSUERS,
      audience: options.clientId,
      algorithms: ['RS256'],
      clockTolerance: 60,
      currentDate: new Date(options.now * 1000),
      requiredClaims: ['sub', 'exp', 'iat'],
    }));
  } catch {
    throw new GoogleSignInError('id_token_invalid');
  }

  if (payload.nonce !== options.nonce) throw new GoogleSignInError('nonce_mismatch');
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new GoogleSignInError('subject_missing');
  }
  if (typeof payload.email !== 'string' || payload.email.length === 0) {
    throw new GoogleSignInError('email_missing');
  }
  if (payload.email_verified !== true) throw new GoogleSignInError('email_not_verified');

  return {
    subject: payload.sub,
    email: payload.email.toLowerCase(),
    name: typeof payload.name === 'string' && payload.name.length > 0 ? payload.name : null,
  };
}
