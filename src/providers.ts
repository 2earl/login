import { SignJWT, importPKCS8, jwtVerify, type JWTVerifyGetKey } from 'jose';

/**
 * Sign-in with Microsoft, GitHub and Apple (DESIGN §4.14), beside Google (google.ts). Each is a
 * way into an account like Google: keyed on the provider's stable account ID, never on the email
 * address, and never joined to another account by address (THREAT_MODEL B3). A provider is on
 * only when its client ID (a var) and its secret are both set; until then it doesn't appear.
 *
 * Only a verified email address is accepted, because login sends security notices to it and
 * refuses a second account with it:
 * - Microsoft: personal accounts (their addresses are verified by Microsoft), or a work or school
 *   account whose token says its domain is verified (`xms_edov`, an optional claim to switch on
 *   in the app registration). Other work accounts are refused: their `email` claim is whatever
 *   the tenant's admin typed (the "nOAuth" problem).
 * - GitHub: the account's primary address, if GitHub marks it verified.
 * - Apple: the address in the ID token (possibly a private relay address), marked verified.
 */

export type FederatedProvider = 'microsoft' | 'github' | 'apple';
export const FEDERATED_PROVIDERS: readonly FederatedProvider[] = ['microsoft', 'github', 'apple'];

export const PROVIDER_NAMES: Record<FederatedProvider | 'google' | 'email', string> = {
  google: 'Google',
  email: 'email code',
  microsoft: 'Microsoft',
  github: 'GitHub',
  apple: 'Apple',
};

export const MICROSOFT_AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
export const MICROSOFT_TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
export const MICROSOFT_JWKS_URL = 'https://login.microsoftonline.com/common/discovery/v2.0/keys';
/** The tenant of personal Microsoft accounts (outlook.com, hotmail.com, live.com). */
export const MICROSOFT_CONSUMER_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';

export const GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize';
export const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
export const GITHUB_API = 'https://api.github.com';

export const APPLE_ISSUER = 'https://appleid.apple.com';
export const APPLE_AUTH_URL = 'https://appleid.apple.com/auth/authorize';
export const APPLE_TOKEN_URL = 'https://appleid.apple.com/auth/token';
export const APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys';

export interface FederatedIdentity {
  provider: FederatedProvider;
  /** The provider's stable account ID. */
  subject: string;
  /** Verified, lower case. */
  email: string;
  name: string | null;
}

/** A failed sign-in. `reason` is a fixed code, safe to log and audit. */
export class ProviderSignInError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = 'ProviderSignInError';
  }
}

export interface ProviderDeps {
  fetch: typeof fetch;
  microsoftJwks: JWTVerifyGetKey;
  appleJwks: JWTVerifyGetKey;
}

/** A var or secret that may be unset (optional secrets aren't in the generated Env type). */
/** A provider's display name, or the raw value for anything unknown. */
export function providerName(provider: string): string {
  const names: Record<string, string | undefined> = PROVIDER_NAMES;
  return names[provider] ?? provider;
}

export function setting(env: Env, name: string): string {
  const value = (env as unknown as Record<string, unknown>)[name];
  return typeof value === 'string' ? value.trim() : '';
}

const CONFIG: Record<FederatedProvider, { id: string; secret: string; extra: string[] }> = {
  microsoft: { id: 'MICROSOFT_CLIENT_ID', secret: 'MICROSOFT_CLIENT_SECRET', extra: [] },
  github: { id: 'GITHUB_CLIENT_ID', secret: 'GITHUB_CLIENT_SECRET', extra: [] },
  apple: {
    id: 'APPLE_CLIENT_ID',
    secret: 'APPLE_PRIVATE_KEY',
    extra: ['APPLE_TEAM_ID', 'APPLE_KEY_ID'],
  },
};

export function providerEnabled(env: Env, provider: FederatedProvider): boolean {
  const config = CONFIG[provider];
  return [config.id, config.secret, ...config.extra].every((name) => setting(env, name) !== '');
}

export function enabledProviders(env: Env): FederatedProvider[] {
  return FEDERATED_PROVIDERS.filter((p) => providerEnabled(env, p));
}

export function isFederatedProvider(value: unknown): value is FederatedProvider {
  return typeof value === 'string' && (FEDERATED_PROVIDERS as readonly string[]).includes(value);
}

export function callbackUrl(env: Env, provider: FederatedProvider): string {
  return `${env.ISSUER}/callback/${provider}`;
}

/** Where to send the browser to sign in with `provider`. */
export function authorizationUrl(
  env: Env,
  provider: FederatedProvider,
  params: { state: string; nonce: string; codeChallenge: string; loginHint?: string | null },
): string {
  const clientId = setting(env, CONFIG[provider].id);
  const redirectUri = callbackUrl(env, provider);
  let url: URL;
  switch (provider) {
    case 'microsoft':
      url = new URL(MICROSOFT_AUTH_URL);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('response_mode', 'query');
      url.searchParams.set('scope', 'openid email profile');
      url.searchParams.set('nonce', params.nonce);
      url.searchParams.set('code_challenge', params.codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
      url.searchParams.set('prompt', 'select_account');
      if (params.loginHint) url.searchParams.set('login_hint', params.loginHint);
      break;
    case 'github':
      url = new URL(GITHUB_AUTH_URL);
      url.searchParams.set('scope', 'read:user user:email');
      url.searchParams.set('code_challenge', params.codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
      url.searchParams.set('allow_signup', 'true');
      break;
    case 'apple':
      // Apple sends the name and address only with form_post (DESIGN §4.14).
      url = new URL(APPLE_AUTH_URL);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('response_mode', 'form_post');
      url.searchParams.set('scope', 'name email');
      url.searchParams.set('nonce', params.nonce);
      break;
  }
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('state', params.state);
  return url.toString();
}

async function postForm(
  deps: ProviderDeps,
  url: string,
  form: Record<string, string>,
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await deps.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(form),
    });
  } catch {
    throw new ProviderSignInError('token_request_failed');
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new ProviderSignInError('token_response_invalid');
  }
  // GitHub answers errors with 200 and an `error` field.
  if (!response.ok || (body as { error?: unknown }).error !== undefined) {
    throw new ProviderSignInError('token_exchange_rejected');
  }
  return body as Record<string, unknown>;
}

const lower = (email: string) => email.trim().toLowerCase();

async function microsoftIdentity(
  env: Env,
  deps: ProviderDeps,
  params: { code: string; codeVerifier: string; nonce: string; now: number },
): Promise<FederatedIdentity> {
  const clientId = setting(env, 'MICROSOFT_CLIENT_ID');
  const body = await postForm(deps, MICROSOFT_TOKEN_URL, {
    grant_type: 'authorization_code',
    client_id: clientId,
    client_secret: setting(env, 'MICROSOFT_CLIENT_SECRET'),
    code: params.code,
    code_verifier: params.codeVerifier,
    redirect_uri: callbackUrl(env, 'microsoft'),
    scope: 'openid email profile',
  });
  if (typeof body.id_token !== 'string') throw new ProviderSignInError('id_token_missing');
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(body.id_token, deps.microsoftJwks, {
      audience: clientId,
      algorithms: ['RS256'],
      clockTolerance: 60,
      currentDate: new Date(params.now * 1000),
      requiredClaims: ['sub', 'exp', 'iat', 'iss', 'tid'],
    }));
  } catch {
    throw new ProviderSignInError('id_token_invalid');
  }
  // Multi-tenant: the issuer names the account's tenant, and must match it exactly.
  const tid = payload.tid;
  if (typeof tid !== 'string' || !/^[0-9a-f-]{36}$/.test(tid)) {
    throw new ProviderSignInError('tenant_invalid');
  }
  if (payload.iss !== `https://login.microsoftonline.com/${tid}/v2.0`) {
    throw new ProviderSignInError('issuer_invalid');
  }
  if (payload.nonce !== params.nonce) throw new ProviderSignInError('nonce_mismatch');
  if (typeof payload.sub !== 'string' || payload.sub === '') {
    throw new ProviderSignInError('subject_missing');
  }
  if (typeof payload.email !== 'string' || payload.email === '') {
    throw new ProviderSignInError('email_missing');
  }
  const verified = tid === MICROSOFT_CONSUMER_TENANT || payload.xms_edov === true;
  if (!verified) throw new ProviderSignInError('email_not_verified');
  return {
    provider: 'microsoft',
    // `sub` is stable for this app and this account, across tenants' renames.
    subject: payload.sub,
    email: lower(payload.email),
    name: typeof payload.name === 'string' && payload.name !== '' ? payload.name : null,
  };
}

async function githubIdentity(
  env: Env,
  deps: ProviderDeps,
  params: { code: string; codeVerifier: string },
): Promise<FederatedIdentity> {
  const body = await postForm(deps, GITHUB_TOKEN_URL, {
    client_id: setting(env, 'GITHUB_CLIENT_ID'),
    client_secret: setting(env, 'GITHUB_CLIENT_SECRET'),
    code: params.code,
    code_verifier: params.codeVerifier,
    redirect_uri: callbackUrl(env, 'github'),
  });
  if (typeof body.access_token !== 'string') throw new ProviderSignInError('token_missing');
  // GitHub's token is used for these two reads only, then dropped.
  const api = async (path: string): Promise<unknown> => {
    let response: Response;
    try {
      response = await deps.fetch(`${GITHUB_API}${path}`, {
        headers: {
          Authorization: `Bearer ${String(body.access_token)}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'login.2earl.com',
        },
      });
    } catch {
      throw new ProviderSignInError('api_request_failed');
    }
    if (!response.ok) throw new ProviderSignInError('api_rejected');
    return response.json().catch(() => {
      throw new ProviderSignInError('api_response_invalid');
    });
  };
  const user = (await api('/user')) as { id?: unknown; login?: unknown; name?: unknown };
  if (typeof user.id !== 'number' || !Number.isSafeInteger(user.id)) {
    throw new ProviderSignInError('subject_missing');
  }
  const emails = (await api('/user/emails')) as {
    email?: unknown;
    primary?: unknown;
    verified?: unknown;
  }[];
  const primary = Array.isArray(emails)
    ? emails.find((e) => e.primary === true && e.verified === true && typeof e.email === 'string')
    : undefined;
  if (!primary || typeof primary.email !== 'string') {
    throw new ProviderSignInError('email_not_verified');
  }
  const name =
    typeof user.name === 'string' && user.name !== ''
      ? user.name
      : typeof user.login === 'string'
        ? user.login
        : null;
  return { provider: 'github', subject: String(user.id), email: lower(primary.email), name };
}

/** Apple's client secret: a short-lived ES256 JWT signed with the team's key. */
export async function appleClientSecret(env: Env, now: number): Promise<string> {
  const key = await importPKCS8(setting(env, 'APPLE_PRIVATE_KEY').replace(/\\n/g, '\n'), 'ES256');
  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: setting(env, 'APPLE_KEY_ID') })
    .setIssuer(setting(env, 'APPLE_TEAM_ID'))
    .setSubject(setting(env, 'APPLE_CLIENT_ID'))
    .setAudience(APPLE_ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

async function appleIdentity(
  env: Env,
  deps: ProviderDeps,
  params: { code: string; nonce: string; now: number; name: string | null },
): Promise<FederatedIdentity> {
  const clientId = setting(env, 'APPLE_CLIENT_ID');
  let secret: string;
  try {
    secret = await appleClientSecret(env, params.now);
  } catch {
    throw new ProviderSignInError('client_secret_invalid');
  }
  const body = await postForm(deps, APPLE_TOKEN_URL, {
    grant_type: 'authorization_code',
    client_id: clientId,
    client_secret: secret,
    code: params.code,
    redirect_uri: callbackUrl(env, 'apple'),
  });
  if (typeof body.id_token !== 'string') throw new ProviderSignInError('id_token_missing');
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(body.id_token, deps.appleJwks, {
      issuer: APPLE_ISSUER,
      audience: clientId,
      algorithms: ['RS256'],
      clockTolerance: 60,
      currentDate: new Date(params.now * 1000),
      requiredClaims: ['sub', 'exp', 'iat'],
    }));
  } catch {
    throw new ProviderSignInError('id_token_invalid');
  }
  if (payload.nonce !== params.nonce) throw new ProviderSignInError('nonce_mismatch');
  if (typeof payload.sub !== 'string' || payload.sub === '') {
    throw new ProviderSignInError('subject_missing');
  }
  if (typeof payload.email !== 'string' || payload.email === '') {
    throw new ProviderSignInError('email_missing');
  }
  // Apple sends the flag as a boolean or as the string "true".
  if (payload.email_verified !== true && payload.email_verified !== 'true') {
    throw new ProviderSignInError('email_not_verified');
  }
  return {
    provider: 'apple',
    subject: payload.sub,
    email: lower(payload.email),
    name: params.name,
  };
}

/** Exchanges the code and returns the verified identity. */
export function identityFromCode(
  env: Env,
  deps: ProviderDeps,
  provider: FederatedProvider,
  params: { code: string; codeVerifier: string; nonce: string; now: number; name: string | null },
): Promise<FederatedIdentity> {
  switch (provider) {
    case 'microsoft':
      return microsoftIdentity(env, deps, params);
    case 'github':
      return githubIdentity(env, deps, params);
    case 'apple':
      return appleIdentity(env, deps, params);
  }
}

/** The name Apple sends once, on the first sign-in, in the form's `user` field. */
export function appleName(userField: unknown): string | null {
  if (typeof userField !== 'string' || userField.length > 2000) return null;
  try {
    const parsed = JSON.parse(userField) as { name?: { firstName?: unknown; lastName?: unknown } };
    const parts = [parsed.name?.firstName, parsed.name?.lastName].filter(
      (p): p is string => typeof p === 'string' && p.trim() !== '',
    );
    return parts.length > 0 ? parts.join(' ').slice(0, 80) : null;
  } catch {
    return null;
  }
}
