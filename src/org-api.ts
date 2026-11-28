import { ASSIGNABLE_SERVICES } from './authz/grant';
import {
  assignRole,
  customRole,
  listAssignments,
  listCustomRoles,
  revokeAssignment,
  type Assignment,
} from './authz/store';
import { CUSTOM_ROLE_PATTERN } from './authz/types';
import { systemRole } from './services';
import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import { randomToken, sha256Hex } from './crypto';
import { clientIp, workerCtx, type AppContext, type AppEnv } from './http';
import { noticeContext } from './sign-in';
import { API_DOCS_HTML } from './api-docs.generated';
import { alertFor, alertOwners } from './org-alerts';
import { page } from './pages';
import { deactivate, isManagedBy, reactivate, signOutEverywhere } from './managed';
import { authorizationServer } from './oauth';
import { listDomains } from './org-domains';
import { orgAuditEvents, publicRecord } from './org-audit';
import { listMembers, removeMember, setRole } from './orgs';

/**
 * The organization's API (DESIGN §4.24): an owner creates a key on Settings, and the
 * organization's own scripts read members, domains and the audit log, and (with a write key)
 * change members' roles, deactivate and reactivate managed accounts, and remove members.
 * It never acts on owners. Streaming (§4.23) is how changes are pushed.
 */

export const MAX_KEYS = 5;
const PAGE = 100;
const AUDIT_DAYS = 90;

export type ApiAccess = 'read' | 'write';

export interface ApiKeyInfo {
  id: string;
  name: string;
  access: ApiAccess;
  createdAt: number;
  lastUsedAt: number | null;
}

export async function listApiKeys(db: D1Database, orgId: string): Promise<ApiKeyInfo[]> {
  const { results } = await db
    .prepare(
      'SELECT id, name, access, created_at, last_used_at FROM org_api_keys WHERE org_id = ? ORDER BY created_at',
    )
    .bind(orgId)
    .all<{
      id: string;
      name: string;
      access: ApiAccess;
      created_at: number;
      last_used_at: number | null;
    }>();
  return results.map((r) => ({
    id: r.id,
    name: r.name,
    access: r.access,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
  }));
}

/** A new key, returned once; null when the organization has the most it may. */
export async function createApiKey(
  db: D1Database,
  now: number,
  orgId: string,
  input: { name: string; access: ApiAccess; createdBy: string },
): Promise<{ id: string; key: string } | null> {
  const id = `oak_${randomToken(9)}`;
  const key = `2earl_${randomToken(32)}`;
  const result = await db
    .prepare(
      `INSERT INTO org_api_keys (id, org_id, name, key_hash, access, created_by, created_at)
       SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
       WHERE (SELECT COUNT(*) FROM org_api_keys WHERE org_id = ?2) < ?8`,
    )
    .bind(id, orgId, input.name, await sha256Hex(key), input.access, input.createdBy, now, MAX_KEYS)
    .run();
  return result.meta.changes > 0 ? { id, key } : null;
}

export async function revokeApiKey(db: D1Database, orgId: string, id: string): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM org_api_keys WHERE id = ? AND org_id = ?')
    .bind(id, orgId)
    .run();
  return result.meta.changes > 0;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });

const problem = (status: number, error: string, message: string) =>
  json({ error, message }, status);

export function registerOrgApiRoutes(app: Hono<AppEnv>, deps: Deps): void {
  /** The key's organization and access, or the error to answer with. */
  async function authenticate(
    c: AppContext,
    need: ApiAccess,
  ): Promise<{ orgId: string; keyId: string } | Response> {
    const key = c.req.header('Authorization')?.match(/^Bearer\s+(2earl_[A-Za-z0-9_-]{20,})$/)?.[1];
    const { success } = await c.env.TOKEN_RATE_LIMITER.limit({
      key: `orgapi:${clientIp(c) ?? 'unknown'}`,
    });
    if (!success) return problem(429, 'rate_limited', 'Too many requests.');
    if (!key) return problem(401, 'unauthorized', 'An organization API key is required.');
    const row = await c.env.DB.prepare(
      `SELECT k.id, k.org_id, k.access FROM org_api_keys k
       JOIN organizations o ON o.id = k.org_id AND o.status = 'active'
       WHERE k.key_hash = ?`,
    )
      .bind(await sha256Hex(key))
      .first<{ id: string; org_id: string; access: ApiAccess }>();
    if (!row) return problem(401, 'unauthorized', 'The key is unknown or was revoked.');
    if (need === 'write' && row.access !== 'write') {
      return problem(403, 'forbidden', 'This key can only read.');
    }
    await c.env.DB.prepare('UPDATE org_api_keys SET last_used_at = ? WHERE id = ?')
      .bind(deps.now(), row.id)
      .run();
    return { orgId: row.org_id, keyId: row.id };
  }

  const record =
    (
      orgId: string,
      keyId: string,
      event: Parameters<typeof audit>[2],
      detail: Record<string, unknown>,
    ) =>
    async (c: AppContext) => {
      const now = deps.now();
      const full = { org: orgId, via: 'api', key: keyId, ...detail };
      await audit(c.env.DB, now, event, { ipPrefix: clientIp(c), detail: full });
      // Owners hear of a key granting rights too (DESIGN §4.27).
      if (alertFor(event, full)) {
        workerCtx(c).waitUntil(
          alertOwners(c.env, orgId, event, full, { apiKey: keyId }, noticeContext(c, now)),
        );
      }
    };

  app.get('/api/v1/members', async (c) => {
    const auth = await authenticate(c, 'read');
    if (auth instanceof Response) return auth;
    const members = await listMembers(c.env.DB, auth.orgId);
    return json({
      data: members.map((m) => ({
        id: m.userId,
        email: m.email,
        name: m.name,
        role: m.role,
        managed: m.managed,
        deactivated: m.deactivated,
        role_from_directory: m.roleFromDirectory,
        joined_at: new Date(m.joinedAt * 1000).toISOString(),
      })),
    });
  });

  app.get('/api/v1/domains', async (c) => {
    const auth = await authenticate(c, 'read');
    if (auth instanceof Response) return auth;
    const domains = await listDomains(c.env.DB, auth.orgId);
    return json({
      data: domains.map((d) => ({
        domain: d.domain,
        verified: d.verifiedAt !== null,
        managed: d.managedAt !== null,
      })),
    });
  });

  // The audit log, oldest first, from `since` (ISO time) or a cursor from the previous page.
  app.get('/api/v1/audit', async (c) => {
    const auth = await authenticate(c, 'read');
    if (auth instanceof Response) return auth;
    const now = deps.now();
    const floor = now - AUDIT_DAYS * 86_400;
    let afterAt = floor;
    let afterId = '';
    const cursor = c.req.query('cursor');
    const since = c.req.query('since');
    if (cursor) {
      const match = /^(\d{1,12})\.([A-Za-z0-9_~-]{0,64})$/.exec(cursor);
      if (!match) return problem(400, 'invalid_cursor', 'The cursor is not one this API gave.');
      afterAt = Math.max(floor, Number(match[1]));
      afterId = match[2] ?? '';
    } else if (since) {
      const time = Date.parse(since);
      if (Number.isNaN(time))
        return problem(400, 'invalid_since', 'since must be an ISO 8601 time.');
      // Everything at or after `since`: '~' sorts after every event ID in the second before.
      afterAt = Math.max(floor, Math.floor(time / 1000) - 1);
      afterId = '~';
    }
    const limit = Math.min(PAGE, Math.max(1, Number(c.req.query('limit') ?? PAGE) || PAGE));
    const events = await orgAuditEvents(c.env.DB, auth.orgId, {
      afterAt,
      afterId,
      // A few seconds' margin, so a page never ends before events written in the same second.
      until: now - 5,
      limit,
    });
    const last = events[events.length - 1];
    return json({
      data: events.map(publicRecord),
      // Where to go on from; with no new events, the same place.
      next_cursor: last ? `${String(last.at)}.${last.id}` : `${String(afterAt)}.${afterId}`,
    });
  });

  /** The member a change is about: never an owner. */
  async function memberFor(c: AppContext, orgId: string, userId: string) {
    const member = (await listMembers(c.env.DB, orgId)).find((m) => m.userId === userId);
    if (!member) return problem(404, 'not_found', 'No such member.');
    if (member.role === 'owner') {
      return problem(409, 'owner', 'The API doesn’t act on owners: change them in 2earl.');
    }
    return member;
  }

  app.post('/api/v1/members/:id/role', async (c) => {
    const auth = await authenticate(c, 'write');
    if (auth instanceof Response) return auth;
    const member = await memberFor(c, auth.orgId, c.req.param('id'));
    if (member instanceof Response) return member;
    const body = (await c.req.json().catch(() => null)) as { role?: unknown } | null;
    const role = body?.role;
    if (role !== 'admin' && role !== 'auditor' && role !== 'member') {
      return problem(400, 'invalid_role', 'role must be "admin", "auditor" or "member".');
    }
    if (member.roleFromDirectory) {
      return problem(409, 'directory', 'The directory decides this member’s role.');
    }
    if (await setRole(c.env.DB, auth.orgId, member.userId, role)) {
      await record(auth.orgId, auth.keyId, 'org.role_changed', {
        target: member.userId,
        role,
        from: member.role,
      })(c);
    }
    return json({ id: member.userId, role });
  });

  for (const action of ['deactivate', 'reactivate'] as const) {
    app.post(`/api/v1/members/:id/${action}`, async (c) => {
      const auth = await authenticate(c, 'write');
      if (auth instanceof Response) return auth;
      const member = await memberFor(c, auth.orgId, c.req.param('id'));
      if (member instanceof Response) return member;
      if (!(await isManagedBy(c.env.DB, member.userId, auth.orgId))) {
        return problem(409, 'not_managed', 'The organization doesn’t manage this account.');
      }
      const now = deps.now();
      const changed =
        action === 'deactivate'
          ? await deactivate(
              c.env.DB,
              authorizationServer(c.env).getOAuthApi(c.env),
              now,
              member.userId,
              auth.orgId,
            )
          : await reactivate(c.env.DB, now, member.userId, auth.orgId);
      if (changed) {
        await record(
          auth.orgId,
          auth.keyId,
          action === 'deactivate' ? 'org.account_deactivated' : 'org.account_reactivated',
          { target: member.userId },
        )(c);
      }
      return json({ id: member.userId, deactivated: action === 'deactivate' });
    });
  }

  // ---- Roles in 2earl's apps (DESIGN §4.32) ----------------------------------------------------

  app.get('/api/v1/roles', async (c) => {
    const auth = await authenticate(c, 'read');
    if (auth instanceof Response) return auth;
    const custom = await listCustomRoles(c.env.DB, auth.orgId);
    return json({
      data: ASSIGNABLE_SERVICES.flatMap((service) => [
        ...Object.entries(service.authz.roles)
          .filter(([, r]) => r.assignable === 'org')
          .map(([id, r]) => ({
            id,
            service: service.id,
            name: r.name,
            kind: 'built_in',
            privileged: r.privileged === true,
            permissions: [...r.permissions],
          })),
        ...custom
          .filter((r) => r.service === service.id)
          .map((r) => ({
            id: r.id,
            service: r.service,
            name: r.name,
            kind: 'custom',
            privileged: false,
            permissions: r.permissions,
          })),
      ]),
    });
  });

  const assignmentJson = (a: Assignment) => ({
    id: a.id,
    service: a.service,
    role: a.role,
    principal: { type: a.principal.kind, id: a.principal.id },
    expires_at: a.expiresAt === null ? null : new Date(a.expiresAt * 1000).toISOString(),
    granted_at: new Date(a.grantedAt * 1000).toISOString(),
    reason: a.reason,
  });

  app.get('/api/v1/assignments', async (c) => {
    const auth = await authenticate(c, 'read');
    if (auth instanceof Response) return auth;
    const assignments = await listAssignments(c.env.DB, auth.orgId, deps.now());
    return json({ data: assignments.map(assignmentJson) });
  });

  /** A key gives only roles of 2earl's apps, never privileged ones (never login's own). */
  async function keyMayGive(c: AppContext, orgId: string, role: string): Promise<boolean> {
    if (CUSTOM_ROLE_PATTERN.test(role)) return (await customRole(c.env.DB, orgId, role)) !== null;
    const system = systemRole(role);
    return (
      system?.assignable === 'org' &&
      system.privileged !== true &&
      ASSIGNABLE_SERVICES.some((s) => s.authz.roles[role] === system)
    );
  }

  app.post('/api/v1/assignments', async (c) => {
    const auth = await authenticate(c, 'write');
    if (auth instanceof Response) return auth;
    const body = (await c.req.json().catch(() => null)) as {
      role?: unknown;
      principal?: { type?: unknown; id?: unknown };
      days?: unknown;
      reason?: unknown;
    } | null;
    const role = typeof body?.role === 'string' ? body.role : '';
    const type = body?.principal?.type;
    const id = body?.principal?.id;
    if (
      (type !== 'user' && type !== 'group' && type !== 'service_account') ||
      typeof id !== 'string'
    ) {
      return problem(400, 'invalid_principal', 'principal must be { type, id }.');
    }
    if (!(await keyMayGive(c, auth.orgId, role))) {
      return problem(403, 'forbidden', 'This role can’t be given with an API key.');
    }
    const days = body?.days;
    if (
      days !== undefined &&
      days !== null &&
      (!Number.isInteger(days) || (days as number) < 1 || (days as number) > 365)
    ) {
      return problem(400, 'invalid_days', 'days must be a whole number from 1 to 365.');
    }
    const now = deps.now();
    const result = await assignRole(c.env, now, {
      orgId: auth.orgId,
      principal: { kind: type, id },
      role,
      expiresAt: typeof days === 'number' ? now + days * 24 * 60 * 60 : null,
      grantedBy: auth.keyId,
      reason: typeof body?.reason === 'string' ? body.reason : '',
    });
    if (!result.ok) {
      return problem(result.reason === 'duplicate' ? 409 : 400, result.reason, 'Nothing changed.');
    }
    await record(auth.orgId, auth.keyId, 'authz.assigned', {
      assignment: result.assignment.id,
      role,
      principal: `${type}:${id}`,
      days: typeof days === 'number' ? days : null,
    })(c);
    return json(assignmentJson(result.assignment), 201);
  });

  app.post('/api/v1/assignments/:id/revoke', async (c) => {
    const auth = await authenticate(c, 'write');
    if (auth instanceof Response) return auth;
    const current = (await listAssignments(c.env.DB, auth.orgId, 0)).find(
      (a) => a.id === c.req.param('id'),
    );
    if (!current) return problem(404, 'not_found', 'No such assignment.');
    if (!(await keyMayGive(c, auth.orgId, current.role))) {
      return problem(403, 'forbidden', 'This role can’t be taken back with an API key.');
    }
    await revokeAssignment(c.env.DB, auth.orgId, current.id);
    await record(auth.orgId, auth.keyId, 'authz.unassigned', {
      assignment: current.id,
      role: current.role,
      principal: `${current.principal.kind}:${current.principal.id}`,
    })(c);
    return json({ id: current.id, revoked: true });
  });

  app.post('/api/v1/members/:id/sign-out', async (c) => {
    const auth = await authenticate(c, 'write');
    if (auth instanceof Response) return auth;
    const member = await memberFor(c, auth.orgId, c.req.param('id'));
    if (member instanceof Response) return member;
    const signedOut = await signOutEverywhere(
      c.env.DB,
      authorizationServer(c.env).getOAuthApi(c.env),
      member.userId,
      auth.orgId,
    );
    if (!signedOut) {
      return problem(409, 'not_managed', 'The organization doesn’t manage this account.');
    }
    await record(auth.orgId, auth.keyId, 'org.account_signed_out', { target: member.userId })(c);
    return json({ id: member.userId, signed_out: true });
  });

  app.post('/api/v1/members/:id/remove', async (c) => {
    const auth = await authenticate(c, 'write');
    if (auth instanceof Response) return auth;
    const member = await memberFor(c, auth.orgId, c.req.param('id'));
    if (member instanceof Response) return member;
    if (member.managed) {
      return problem(409, 'managed', 'Managed accounts are deactivated, not removed.');
    }
    if (await removeMember(c.env.DB, auth.orgId, member.userId)) {
      await record(auth.orgId, auth.keyId, 'org.member_removed', { target: member.userId })(c);
    }
    return json({ id: member.userId, removed: true });
  });

  // The reference, for customers, from docs/API.md (scripts/api-docs.mjs).
  app.get('/docs/api', (c) =>
    c.html(
      page('API reference', `<article class="docs">${API_DOCS_HTML}</article>`, {
        section: 'Developers',
      }),
    ),
  );

  app.all('/api/v1/*', () => problem(404, 'not_found', 'No such endpoint.'));
}
