import type { Hono } from 'hono';
import type { Deps } from './app';
import { randomToken, sha256Hex, timingSafeEqual } from './crypto';
import { clientIp, type AppContext, type AppEnv } from './http';
import { authorizationServer, type GrantProps } from './oauth';
import { acrFor, amrFor, signInOf } from './oidc';
import { boundKey } from './token-check';

/**
 * Token introspection, RFC 7662 (DESIGN §4.12). For resource servers that can't use a Service
 * Binding: they authenticate with HTTP Basic (their ID and secret from /admin/apps) and learn
 * whether an access token is active, for whom, with which scopes, and when and how the person
 * signed in (RFC 9470: `acr`, `auth_time`). A resource server only ever sees tokens issued for its
 * own resource: any other token is reported inactive, exactly like an unknown one.
 */

export interface ResourceServer {
  id: string;
  name: string;
  resource: string;
  createdAt: number;
  lastUsedAt: number | null;
}

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

/** Creates credentials for a resource server; the secret is returned this once. */
export async function createResourceServer(
  db: D1Database,
  now: number,
  name: string,
  resource: string,
): Promise<{ id: string; secret: string }> {
  const id = `rs_${randomToken(12)}`;
  const secret = randomToken(32);
  await db
    .prepare(
      `INSERT INTO resource_servers (id, name, resource, secret_hash, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(id, name, resource, await sha256Hex(secret), now)
    .run();
  return { id, secret };
}

export async function listResourceServers(db: D1Database): Promise<ResourceServer[]> {
  const { results } = await db
    .prepare(
      'SELECT id, name, resource, created_at, last_used_at FROM resource_servers ORDER BY created_at',
    )
    .all<{
      id: string;
      name: string;
      resource: string;
      created_at: number;
      last_used_at: number | null;
    }>();
  return results.map((r) => ({
    id: r.id,
    name: r.name,
    resource: r.resource,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
  }));
}

export async function deleteResourceServer(db: D1Database, id: string): Promise<boolean> {
  const result = await db.prepare('DELETE FROM resource_servers WHERE id = ?').bind(id).run();
  return result.meta.changes > 0;
}

/** HTTP Basic credentials (RFC 7617; the parts are form-encoded per RFC 6749 §2.3.1). */
function basicCredentials(c: AppContext): { id: string; secret: string } | null {
  const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(c.req.header('Authorization')?.trim() ?? '');
  if (!match?.[1]) return null;
  let decoded: string;
  try {
    decoded = atob(match[1]);
  } catch {
    return null;
  }
  const colon = decoded.indexOf(':');
  if (colon < 1) return null;
  try {
    return {
      id: decodeURIComponent(decoded.slice(0, colon).replace(/\+/g, ' ')),
      secret: decodeURIComponent(decoded.slice(colon + 1).replace(/\+/g, ' ')),
    };
  } catch {
    return null;
  }
}

async function authenticate(c: AppContext, now: number): Promise<ResourceServer | null> {
  const credentials = basicCredentials(c);
  if (!credentials) return null;
  const row = await c.env.DB.prepare(
    'SELECT id, name, resource, secret_hash, created_at, last_used_at FROM resource_servers WHERE id = ?',
  )
    .bind(credentials.id)
    .first<{
      id: string;
      name: string;
      resource: string;
      secret_hash: string;
      created_at: number;
      last_used_at: number | null;
    }>();
  // Hash even for an unknown ID, so both cases take the same time.
  const presented = await sha256Hex(credentials.secret);
  if (!row || !timingSafeEqual(presented, row.secret_hash)) return null;
  if (row.last_used_at === null || now - row.last_used_at > 3600) {
    await c.env.DB.prepare('UPDATE resource_servers SET last_used_at = ? WHERE id = ?')
      .bind(now, row.id)
      .run();
  }
  return {
    id: row.id,
    name: row.name,
    resource: row.resource,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  };
}

export function registerIntrospection(app: Hono<AppEnv>, deps: Deps): void {
  app.post('/oauth/introspect', async (c) => {
    const { success } = await c.env.TOKEN_RATE_LIMITER.limit({ key: clientIp(c) ?? 'unknown' });
    if (!success) return c.json({ error: 'temporarily_unavailable' }, 429, NO_STORE);
    const now = deps.now();
    const server = await authenticate(c, now);
    if (!server) {
      return c.json({ error: 'invalid_client' }, 401, {
        ...NO_STORE,
        'WWW-Authenticate': 'Basic realm="login.2earl.com", charset="UTF-8"',
      });
    }
    const form = await c.req.raw.formData().catch(() => null);
    const token = form?.get('token');
    if (typeof token !== 'string' || token.length === 0) {
      return c.json({ error: 'invalid_request' }, 400, NO_STORE);
    }

    // Only access tokens for this server's resource; refresh tokens and everything else are
    // simply "not active" (RFC 7662 §2.2), which tells the caller nothing about them.
    const validated = await authorizationServer(c.env).validateToken(server.resource, token, c.env);
    if (!validated) return c.json({ active: false }, 200, NO_STORE);
    const props = validated.props as GrantProps;
    // A DPoP-bound token (DESIGN §4.15): the resource server checks the proof against this key.
    const jkt = boundKey(props);
    return c.json(
      {
        active: true,
        token_type: jkt ? 'DPoP' : 'Bearer',
        ...(jkt ? { cnf: { jkt } } : {}),
        scope: validated.scope.join(' '),
        client_id: validated.clientId,
        sub: props.uid,
        aud: validated.audience,
        iss: c.env.ISSUER,
        exp: validated.expiresAt,
        // RFC 9470: what a resource server needs to decide whether to ask for a step-up.
        auth_time: signInOf(props).signedInAt,
        acr: acrFor(props),
        amr: amrFor(props),
      },
      200,
      NO_STORE,
    );
  });
}
