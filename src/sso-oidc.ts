import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';
import { pkceChallenge, randomToken } from './crypto';
import { decryptSecret, encryptSecret } from './mfa';

/**
 * Single sign-on with OpenID Connect (DESIGN §4.20): login is the relying party of the
 * organization's own identity provider (Microsoft Entra ID, Google Workspace, Okta, …), the same
 * way it is a SAML service provider (§4.17). Authorization code flow with PKCE, a nonce, and a
 * client secret; the ID token is checked against the provider's published keys.
 */

/** How long a sign-in at the provider may take. */
export const OIDC_REQUEST_TTL_SECONDS = 10 * 60;
/** Responses from the provider larger than this are refused. */
const MAX_BODY = 256 * 1024;
/** Signing algorithms accepted for ID tokens. */
const ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384'];

export interface OrgOidc {
  orgId: string;
  issuer: string;
  clientId: string;
  /** Encrypted with MFA_ENCRYPTION_KEY, bound to the organization. */
  clientSecretEnc: string;
  enabled: boolean;
}

export interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

/** Where the provider sends people back; owners give it to their provider. */
export const oidcRedirectUri = (env: Env, orgId: string) => `${env.ISSUER}/sso/${orgId}/oidc`;

const secretContext = (orgId: string) => `oidc-client-secret:${orgId}`;

export async function oidcConfig(db: D1Database, orgId: string): Promise<OrgOidc | null> {
  const row = await db
    .prepare(
      `SELECT x.org_id, x.issuer, x.client_id, x.client_secret_enc, x.enabled
       FROM org_oidc x JOIN organizations o ON o.id = x.org_id AND o.status = 'active'
       WHERE x.org_id = ?`,
    )
    .bind(orgId)
    .first<{
      org_id: string;
      issuer: string;
      client_id: string;
      client_secret_enc: string;
      enabled: number;
    }>();
  return row
    ? {
        orgId: row.org_id,
        issuer: row.issuer,
        clientId: row.client_id,
        clientSecretEnc: row.client_secret_enc,
        enabled: row.enabled === 1,
      }
    : null;
}

/** Saves the connection. A blank secret keeps the stored one. Turning it on turns SAML off. */
export async function saveOidc(
  env: Env,
  now: number,
  orgId: string,
  input: { issuer: string; clientId: string; clientSecret: string | null; enabled: boolean },
): Promise<void> {
  const sealed = input.clientSecret
    ? await encryptSecret(env.MFA_ENCRYPTION_KEY, secretContext(orgId), input.clientSecret)
    : null;
  const statements = [
    env.DB.prepare(
      `INSERT INTO org_oidc (org_id, issuer, client_id, client_secret_enc, enabled, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
       ON CONFLICT (org_id) DO UPDATE SET issuer = ?2, client_id = ?3,
         client_secret_enc = COALESCE(?4, client_secret_enc), enabled = ?5, updated_at = ?6`,
    ).bind(orgId, input.issuer, input.clientId, sealed, input.enabled ? 1 : 0, now),
  ];
  // One way of single sign-on at a time (DESIGN §4.20).
  if (input.enabled) {
    statements.push(
      env.DB.prepare('UPDATE org_saml SET enabled = 0, updated_at = ? WHERE org_id = ?').bind(
        now,
        orgId,
      ),
    );
  }
  await env.DB.batch(statements);
}

/** An https URL without credentials, query or fragment, at most 500 characters; else null. */
export function issuerUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const text = raw.trim().replace(/\/+$/, '');
  if (text.length > 500) return null;
  try {
    const url = new URL(text);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
      return null;
    }
    return text;
  } catch {
    return null;
  }
}

/** Reads JSON from the provider, with a size limit. */
async function fetchJson(
  fetcher: typeof fetch,
  url: string,
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<unknown> {
  const response = await fetcher(url, {
    ...init,
    redirect: 'manual',
    headers: { Accept: 'application/json', ...init.headers },
    signal: AbortSignal.timeout(8000),
  });
  const text = await response.text();
  if (text.length > MAX_BODY) throw new Error('response too large');
  if (!response.ok) throw new Error(`provider answered ${String(response.status)}`);
  return JSON.parse(text) as unknown;
}

const isHttps = (value: unknown): value is string => {
  if (typeof value !== 'string') return false;
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
};

/**
 * The provider's configuration (OpenID Connect Discovery). The issuer it names must be the one
 * the owner entered, exactly: a different one is another tenant or a misconfiguration.
 */
export async function discover(fetcher: typeof fetch, issuer: string): Promise<Discovery> {
  const doc = (await fetchJson(fetcher, `${issuer}/.well-known/openid-configuration`)) as Record<
    string,
    unknown
  >;
  const named = typeof doc.issuer === 'string' ? doc.issuer.replace(/\/+$/, '') : '';
  if (named !== issuer) throw new Error('issuer mismatch');
  if (
    !isHttps(doc.authorization_endpoint) ||
    !isHttps(doc.token_endpoint) ||
    !isHttps(doc.jwks_uri)
  ) {
    throw new Error('endpoints missing');
  }
  return {
    issuer: doc.issuer as string,
    authorization_endpoint: doc.authorization_endpoint,
    token_endpoint: doc.token_endpoint,
    jwks_uri: doc.jwks_uri,
  };
}

export interface OidcRequest {
  url: string;
  state: string;
  nonce: string;
  verifier: string;
}

/** Where to send the person, and what to remember for the way back. */
export async function authorizeRequest(
  discovery: Discovery,
  config: OrgOidc,
  redirectUri: string,
  loginHint: string,
): Promise<OidcRequest> {
  const state = randomToken(32);
  const nonce = randomToken(32);
  const verifier = randomToken(48);
  const url = new URL(discovery.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: redirectUri,
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    // The person's work address, so the provider can skip asking for it.
    login_hint: loginHint,
  }).toString();
  return { url: url.toString(), state, nonce, verifier };
}

/**
 * Exchanges the code and checks the ID token: the provider's signature, issuer, audience, the
 * nonce, and its age. Returns the address it asserts.
 */
export async function finishOidc(
  env: Env,
  fetcher: typeof fetch,
  config: OrgOidc,
  params: { code: string; verifier: string; nonce: string; redirectUri: string; now: number },
): Promise<{ email: string | null; subject: string }> {
  const discovery = await discover(fetcher, config.issuer);
  const secret = await decryptSecret(
    env.MFA_ENCRYPTION_KEY,
    secretContext(config.orgId),
    config.clientSecretEnc,
  );
  const basic = btoa(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(secret)}`);
  const tokens = (await fetchJson(fetcher, discovery.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.verifier,
    }).toString(),
  })) as Record<string, unknown>;
  if (typeof tokens.id_token !== 'string') throw new Error('no id token');
  const jwks = (await fetchJson(fetcher, discovery.jwks_uri)) as JSONWebKeySet;
  const { payload } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), {
    issuer: discovery.issuer,
    audience: config.clientId,
    algorithms: ALGORITHMS,
    maxTokenAge: '10m',
    currentDate: new Date(params.now * 1000),
  });
  if (payload.nonce !== params.nonce) throw new Error('nonce mismatch');
  if (typeof payload.sub !== 'string') throw new Error('no subject');
  // An address the provider says isn't verified isn't one to sign in with.
  if (payload.email_verified === false) return { email: null, subject: payload.sub };
  // Microsoft Entra ID sends `email` only when configured; its sign-in name is the address
  // otherwise. Either way it must be at a verified domain of the organization (the caller checks).
  const claimed =
    typeof payload.email === 'string'
      ? payload.email
      : typeof payload.preferred_username === 'string' && payload.preferred_username.includes('@')
        ? payload.preferred_username
        : null;
  const email = claimed ? claimed.trim().toLowerCase() : null;
  // Google signs in anyone with a Google account, including personal accounts made with a work
  // address. Only the company's own Google Workspace accounts count: `hd` is its domain.
  if (discovery.issuer === GOOGLE_ISSUER) {
    const domain = email ? email.slice(email.lastIndexOf('@') + 1) : '';
    if (payload.hd !== domain) return { email: null, subject: payload.sub };
  }
  return { email, subject: payload.sub };
}

export const GOOGLE_ISSUER = 'https://accounts.google.com';
