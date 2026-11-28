import { createLocalJWKSet, decodeJwt, importJWK, jwtVerify, type JWK } from 'jose';
import { audit } from './audit';
import { pkceChallenge, randomToken, sha256Hex, timingSafeEqual } from './crypto';
import { workerCtx, type AppContext } from './http';
import { ACCESS_TOKEN_TTL_SECONDS, authorizationServer, type GrantProps } from './oauth';
import { IDENTITY, allResources, scopesFor, serviceForResource } from './services';

/**
 * Service accounts (DESIGN §4.33): an organization's backends, which act for the organization and
 * never for a person. A backend gets an access token with the client credentials grant
 * (RFC 6749 §4.4), authenticated with a secret (HTTP Basic or form fields) or with a JWT signed by
 * its own key (RFC 7523, `private_key_jwt`).
 *
 * The OAuth library has no client credentials grant, so, as for the device grant, login builds it
 * on the library's code flow and never mints tokens itself: each service account has a client of
 * its own in the library, login completes an authorization for the account and exchanges the code
 * at once. Its tokens are validated like everyone else's: `userId` is the account (`sa_…`), and
 * `props` say so (`kind: 'service_account'`, `org`). No refresh token, no ID token, no session, no
 * consent; access ends when the token does (15 minutes) or when the account is disabled.
 */

export const CLIENT_CREDENTIALS = 'client_credentials';
export const JWT_BEARER_ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
export const ASSERTION_ALGS = ['ES256', 'EdDSA', 'RS256'] as const;
export const MAX_SERVICE_ACCOUNTS = 20;
/** The longest a client assertion may be valid for, in seconds. */
export const MAX_ASSERTION_LIFETIME = 5 * 60;
const ID = /^sa_[A-Za-z0-9_-]{8,40}$/;
const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

/** The redirect URI of service accounts' library clients: login's own, with no page behind it. */
export const serviceAccountCallback = (env: Env) => `${env.ISSUER}/service-accounts/callback`;

export interface ServiceAccount {
  id: string;
  orgId: string;
  name: string;
  status: 'active' | 'disabled';
  clientId: string;
  resource: string;
  scopes: string[];
  auth: 'secret' | 'private_key_jwt';
  createdAt: number;
  lastUsedAt: number | null;
}

interface Row {
  id: string;
  org_id: string;
  name: string;
  status: 'active' | 'disabled';
  client_id: string;
  resource: string;
  scopes: string;
  secret_hash: string | null;
  jwks: string | null;
  created_at: number;
  last_used_at: number | null;
}

const toAccount = (row: Row): ServiceAccount => ({
  id: row.id,
  orgId: row.org_id,
  name: row.name,
  status: row.status,
  clientId: row.client_id,
  resource: row.resource,
  scopes: row.scopes.split(' ').filter(Boolean),
  auth: row.jwks ? 'private_key_jwt' : 'secret',
  createdAt: row.created_at,
  lastUsedAt: row.last_used_at,
});

/**
 * The scopes a service account may hold for a resource: the service's, but never login's own
 * (`openid`, `email`, …: an account is nobody's sign-in) and never an app's own sign-in scope.
 */
export function serviceAccountScopes(env: Env, resource: string): string[] {
  const service = serviceForResource(env, resource);
  if (!service || service.id === IDENTITY.id) return [];
  return Object.keys(service.scopes).filter((s) => !service.firstPartyClients?.[s]);
}

/** Resources a service account can be made for. */
export function serviceAccountResources(env: Env): string[] {
  return allResources(env).filter((r) => serviceAccountScopes(env, r).length > 0);
}

/** A public JWK set: 1 to 5 signing keys of the allowed kinds, no private parts. */
export async function parsePublicJwks(text: string): Promise<{ keys: JWK[] } | null> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  const keys = (parsed as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 5) return null;
  const clean: JWK[] = [];
  for (const raw of keys as JWK[]) {
    if (typeof raw !== 'object' || 'd' in raw || 'p' in raw || 'k' in raw) return null;
    const alg = raw.alg ?? (raw.kty === 'EC' ? 'ES256' : raw.kty === 'OKP' ? 'EdDSA' : 'RS256');
    if (!(ASSERTION_ALGS as readonly string[]).includes(alg)) return null;
    if (raw.use !== undefined && raw.use !== 'sig') return null;
    try {
      await importJWK({ ...raw, alg }, alg);
    } catch {
      return null;
    }
    const { kty, crv, x, y, n, e, kid } = raw;
    clean.push(
      Object.fromEntries(
        Object.entries({ kty, crv, x, y, n, e, kid, alg, use: 'sig' }).filter(
          ([, v]) => v !== undefined,
        ),
      ),
    );
  }
  return { keys: clean };
}

export type CreateResult =
  | { ok: true; account: ServiceAccount; secret: string | null }
  | {
      ok: false;
      reason: 'invalid_name' | 'invalid_resource' | 'invalid_scopes' | 'invalid_keys' | 'too_many';
    };

export async function createServiceAccount(
  env: Env,
  now: number,
  input: {
    orgId: string;
    name: string;
    resource: string;
    scopes: readonly string[];
    /** A public JWK set as JSON for private_key_jwt; null for a secret. */
    jwks: string | null;
    createdBy: string;
  },
): Promise<CreateResult> {
  const name = input.name.replace(/\s+/g, ' ').trim().slice(0, 60);
  if (!name) return { ok: false, reason: 'invalid_name' };
  const allowed = serviceAccountScopes(env, input.resource);
  if (allowed.length === 0) return { ok: false, reason: 'invalid_resource' };
  const scopes = [...new Set(input.scopes)].sort();
  if (scopes.length === 0 || !scopes.every((s) => allowed.includes(s))) {
    return { ok: false, reason: 'invalid_scopes' };
  }
  let jwks: string | null = null;
  if (input.jwks !== null) {
    const parsed = await parsePublicJwks(input.jwks);
    if (!parsed) return { ok: false, reason: 'invalid_keys' };
    jwks = JSON.stringify(parsed);
  }
  const existing = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM service_accounts WHERE org_id = ?',
  )
    .bind(input.orgId)
    .first<{ n: number }>();
  if ((existing?.n ?? 0) >= MAX_SERVICE_ACCOUNTS) return { ok: false, reason: 'too_many' };

  const id = `sa_${randomToken(12)}`;
  const secret = jwks === null ? `2earl_sa_${randomToken(32)}` : null;
  const client = await authorizationServer(env)
    .getOAuthApi(env)
    .createClient({
      clientName: `Service account: ${name}`,
      redirectUris: [serviceAccountCallback(env)],
      tokenEndpointAuthMethod: 'none',
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
    });
  await env.DB.prepare(
    `INSERT INTO service_accounts
       (id, org_id, name, client_id, resource, scopes, secret_hash, jwks, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      input.orgId,
      name,
      client.clientId,
      input.resource,
      scopes.join(' '),
      secret === null ? null : await sha256Hex(secret),
      jwks,
      input.createdBy,
      now,
    )
    .run();
  const row = await env.DB.prepare('SELECT * FROM service_accounts WHERE id = ?')
    .bind(id)
    .first<Row>();
  if (!row) throw new Error('service account not stored');
  return { ok: true, account: toAccount(row), secret };
}

export async function listServiceAccounts(
  db: D1Database,
  orgId: string,
): Promise<ServiceAccount[]> {
  const { results } = await db
    .prepare('SELECT * FROM service_accounts WHERE org_id = ? ORDER BY created_at, id')
    .bind(orgId)
    .all<Row>();
  return results.map(toAccount);
}

export async function serviceAccount(db: D1Database, id: string): Promise<ServiceAccount | null> {
  if (!ID.test(id)) return null;
  const row = await db.prepare('SELECT * FROM service_accounts WHERE id = ?').bind(id).first<Row>();
  return row ? toAccount(row) : null;
}

/** Ends every token the account holds (within a minute everywhere: KV). */
async function revokeAll(env: Env, id: string): Promise<void> {
  const oauth = authorizationServer(env).getOAuthApi(env);
  let cursor: string | undefined;
  do {
    const page = await oauth.listUserGrants(id, { limit: 100, ...(cursor ? { cursor } : {}) });
    for (const grant of page.items) await oauth.revokeGrant(grant.id, id);
    cursor = page.cursor;
  } while (cursor);
}

/**
 * Deletes the account. Its tokens are revoked and its library client deleted right after, and
 * again by the cron until done (`service_account_cleanup`, filled by a trigger).
 */
export async function deleteServiceAccount(
  env: Env,
  orgId: string,
  id: string,
): Promise<ServiceAccount | null> {
  const account = await serviceAccount(env.DB, id);
  if (account?.orgId !== orgId) return null;
  await env.DB.prepare('DELETE FROM service_accounts WHERE id = ? AND org_id = ?')
    .bind(id, orgId)
    .run();
  await cleanUpServiceAccounts(env);
  return account;
}

/** Revokes the tokens and deletes the library clients of deleted accounts. */
export async function cleanUpServiceAccounts(env: Env): Promise<number> {
  const { results } = await env.DB.prepare(
    'SELECT id, client_id FROM service_account_cleanup ORDER BY created_at LIMIT 50',
  ).all<{ id: string; client_id: string }>();
  const oauth = authorizationServer(env).getOAuthApi(env);
  let done = 0;
  for (const row of results) {
    try {
      await revokeAll(env, row.id);
      await oauth.deleteClient(row.client_id);
      await env.DB.prepare('DELETE FROM service_account_cleanup WHERE id = ?').bind(row.id).run();
      done++;
    } catch (error) {
      console.error(
        'service account clean-up failed',
        error instanceof Error ? error.name : 'unknown',
      );
    }
  }
  return done;
}

// ---- The client credentials grant --------------------------------------------------------------

function tokenError(c: AppContext, error: string, description: string, status = 400): Response {
  const headers: Record<string, string> = { ...NO_STORE };
  if (error === 'invalid_client') headers['WWW-Authenticate'] = 'Basic realm="login.2earl.com"';
  return c.json({ error, error_description: description }, status as 400, headers);
}

function basicCredentials(header: string | undefined): { id: string; secret: string } | null {
  const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header?.trim() ?? '');
  if (!match?.[1]) return null;
  try {
    const decoded = atob(match[1]);
    const colon = decoded.indexOf(':');
    if (colon < 1) return null;
    return {
      id: decodeURIComponent(decoded.slice(0, colon).replace(/\+/g, ' ')),
      secret: decodeURIComponent(decoded.slice(colon + 1).replace(/\+/g, ' ')),
    };
  } catch {
    return null;
  }
}

/** Authenticates the calling backend. Null for any failure: the caller learns nothing more. */
async function authenticate(
  c: AppContext,
  now: number,
  form: FormData,
): Promise<{
  row: Row;
  method: 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt';
} | null> {
  const field = (name: string) => {
    const v = form.get(name);
    return typeof v === 'string' ? v : null;
  };
  const assertion = field('client_assertion');
  if (assertion !== null) {
    if (field('client_assertion_type') !== JWT_BEARER_ASSERTION) return null;
    let claimed: string | undefined;
    try {
      claimed = decodeJwt(assertion).iss;
    } catch {
      return null;
    }
    if (typeof claimed !== 'string' || !ID.test(claimed)) return null;
    const sent = field('client_id');
    if (sent !== null && sent !== claimed) return null;
    const row = await c.env.DB.prepare('SELECT * FROM service_accounts WHERE id = ?')
      .bind(claimed)
      .first<Row>();
    if (!row?.jwks) return null;
    try {
      const { payload } = await jwtVerify(
        assertion,
        createLocalJWKSet(JSON.parse(row.jwks) as { keys: JWK[] }),
        {
          issuer: row.id,
          subject: row.id,
          audience: [c.env.ISSUER, `${c.env.ISSUER}/oauth/token`],
          algorithms: [...ASSERTION_ALGS],
          currentDate: new Date(now * 1000),
          clockTolerance: 30,
        },
      );
      if (typeof payload.exp !== 'number' || typeof payload.jti !== 'string') return null;
      if (payload.jti.length === 0 || payload.jti.length > 200) return null;
      const issuedAt = typeof payload.iat === 'number' ? payload.iat : now;
      if (
        payload.exp - issuedAt > MAX_ASSERTION_LIFETIME ||
        payload.exp > now + MAX_ASSERTION_LIFETIME
      )
        return null;
      // Used once (RFC 7523 §3): the ID is remembered until the assertion has expired.
      const used = await c.env.DB.prepare(
        'INSERT INTO client_assertion_jti (id_hash, expires_at) VALUES (?, ?) ON CONFLICT DO NOTHING',
      )
        .bind(await sha256Hex(`${row.id}\n${payload.jti}`), payload.exp + 60)
        .run();
      if (used.meta.changes === 0) return null;
    } catch {
      return null;
    }
    return { row, method: 'private_key_jwt' };
  }

  const basic = basicCredentials(c.req.header('Authorization'));
  const id = basic?.id ?? field('client_id');
  const secret = basic?.secret ?? field('client_secret');
  if (!id || !secret || !ID.test(id)) {
    // Hash anyway, so unknown IDs take as long as wrong secrets.
    await sha256Hex(secret ?? '');
    return null;
  }
  const row = await c.env.DB.prepare('SELECT * FROM service_accounts WHERE id = ?')
    .bind(id)
    .first<Row>();
  const presented = await sha256Hex(secret);
  if (!row?.secret_hash || !timingSafeEqual(presented, row.secret_hash)) return null;
  return { row, method: basic ? 'client_secret_basic' : 'client_secret_post' };
}

/**
 * The token endpoint's answer for `grant_type=client_credentials`. Called from app.ts for that
 * grant only. `exchangeEnv` carries a DPoP proof's key when the request had one.
 */
export async function clientCredentialsResponse(
  c: AppContext,
  now: number,
  form: FormData,
  exchangeEnv: Env = c.env,
): Promise<Response> {
  const auth = await authenticate(c, now, form);
  if (!auth) return tokenError(c, 'invalid_client', 'Client authentication failed', 401);
  const account = toAccount(auth.row);
  if (account.status !== 'active') {
    return tokenError(c, 'invalid_client', 'Client authentication failed', 401);
  }
  const resourceField = form.get('resource');
  const resource = typeof resourceField === 'string' ? resourceField : account.resource;
  if (resource !== account.resource) {
    return tokenError(c, 'invalid_target', 'This service account is for another resource');
  }
  const scopeField = form.get('scope');
  const requested =
    typeof scopeField === 'string' ? scopeField.split(' ').filter(Boolean) : account.scopes;
  const service = serviceForResource(c.env, resource);
  if (
    !service ||
    requested.length === 0 ||
    !requested.every((s) => account.scopes.includes(s)) ||
    scopesFor(service, requested).length !== requested.length
  ) {
    return tokenError(c, 'invalid_scope', 'Ask for scopes this service account was given');
  }

  const oauth = authorizationServer(c.env).getOAuthApi(c.env);
  const verifier = randomToken(48);
  const props: GrantProps = {
    uid: account.id,
    authTime: now,
    aal2At: null,
    kind: 'service_account',
    org: account.orgId,
  };
  const { redirectTo } = await oauth.completeAuthorization({
    request: {
      responseType: 'code',
      clientId: account.clientId,
      redirectUri: serviceAccountCallback(c.env),
      scope: requested,
      state: randomToken(16),
      codeChallenge: await pkceChallenge(verifier),
      codeChallengeMethod: 'S256',
      resource,
    },
    userId: account.id,
    metadata: { serviceAccount: account.id },
    scope: requested,
    props,
  });
  const code = new URL(redirectTo).searchParams.get('code');
  if (!code) throw new Error('no authorization code for the service account');
  const exchanged = await authorizationServer(c.env).fetch(
    new Request(`${c.env.ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: serviceAccountCallback(c.env),
        client_id: account.clientId,
        code_verifier: verifier,
        resource,
      }),
    }),
    exchangeEnv,
    workerCtx(c),
  );
  if (!exchanged.ok) return exchanged;
  const body = await exchanged.json<Record<string, unknown>>();

  // Earlier grants whose tokens have expired: gone, so an account's grants don't pile up.
  const older = await oauth.listUserGrants(account.id, { limit: 100 });
  for (const grant of older.items) {
    if (grant.createdAt < now - ACCESS_TOKEN_TTL_SECONDS - 60) {
      await oauth.revokeGrant(grant.id, account.id);
    }
  }
  if (account.lastUsedAt === null || now - account.lastUsedAt > 3600) {
    await c.env.DB.prepare('UPDATE service_accounts SET last_used_at = ? WHERE id = ?')
      .bind(now, account.id)
      .run();
    await audit(c.env.DB, now, 'service_account.used', {
      clientId: account.clientId,
      detail: { org: account.orgId, service_account: account.id, method: auth.method },
    });
  }
  return c.json(
    {
      access_token: body.access_token,
      token_type: body.token_type,
      expires_in: body.expires_in,
      scope: body.scope,
    },
    200,
    NO_STORE,
  );
}
