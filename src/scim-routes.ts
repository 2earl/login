import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import { randomToken } from './crypto';
import { normaliseEmail } from './directory';
import { clientIp, type AppContext, type AppEnv } from './http';
import { addressAtVerifiedDomain } from './org-domains';
import { orgForScimToken, syncMembership, type ScimUserInput, type ScimUserRow } from './scim';
import { DELETE_AFTER_SECONDS } from './managed';
import { authorizationServer } from './oauth';

const oauth = (c: AppContext) => authorizationServer(c.env).getOAuthApi(c.env);

/**
 * The SCIM 2.0 service provider (RFC 7644, DESIGN §4.16) at /scim/v2: Users only. Each request
 * carries one organization's bearer token and sees only that organization's users.
 */

const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const SCIM_JSON = { 'Content-Type': 'application/scim+json', 'Cache-Control': 'no-store' };
const MAX_COUNT = 100;
const MAX_BODY_BYTES = 64 * 1024;
const NAME_MAX = 200;

function scimError(
  status: 400 | 401 | 404 | 409 | 413 | 429 | 501,
  detail: string,
  scimType?: string,
): Response {
  return new Response(
    JSON.stringify({
      schemas: [ERROR_SCHEMA],
      status: String(status),
      detail,
      ...(scimType ? { scimType } : {}),
    }),
    {
      status,
      headers: {
        ...SCIM_JSON,
        ...(status === 401 ? { 'WWW-Authenticate': 'Bearer realm="2earl SCIM"' } : {}),
      },
    },
  );
}

const scimJson = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { ...SCIM_JSON, ...extra } });

const iso = (unixSeconds: number) => new Date(unixSeconds * 1000).toISOString();

function representation(env: Env, row: ScimUserRow) {
  const location = `${env.ISSUER}/scim/v2/Users/${row.id}`;
  return {
    schemas: [USER_SCHEMA],
    id: row.id,
    ...(row.external_id ? { externalId: row.external_id } : {}),
    userName: row.user_name,
    ...(row.given_name || row.family_name
      ? {
          name: {
            ...(row.given_name ? { givenName: row.given_name } : {}),
            ...(row.family_name ? { familyName: row.family_name } : {}),
          },
        }
      : {}),
    ...(row.display_name ? { displayName: row.display_name } : {}),
    emails: [{ value: row.user_name, type: 'work', primary: true }],
    active: row.active === 1,
    meta: {
      resourceType: 'User',
      created: iso(row.created_at),
      lastModified: iso(row.updated_at),
      location,
    },
  };
}

/** A string attribute, trimmed and bounded; null for absent or empty. */
function text(value: unknown, max = NAME_MAX): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, max) : null;
}

/** SCIM booleans arrive as true/false, and from some directories as "True"/"False". */
function bool(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string' && /^(true|false)$/i.test(value))
    return value.toLowerCase() === 'true';
  return null;
}

/** A full User resource from a POST or PUT body. */
function readUser(body: Record<string, unknown>): ScimUserInput | string {
  const userName = typeof body.userName === 'string' ? normaliseEmail(body.userName) : null;
  if (!userName) return 'userName must be an email address';
  const name = (body.name ?? {}) as Record<string, unknown>;
  const active = body.active === undefined ? true : bool(body.active);
  if (active === null) return 'active must be true or false';
  return {
    userName,
    externalId: text(body.externalId),
    displayName: text(body.displayName),
    givenName: text(name.givenName),
    familyName: text(name.familyName),
    active,
  };
}

/** Applies RFC 7644 §3.5.2 PATCH operations to what is stored; returns the result or an error. */
function applyPatch(current: ScimUserInput, operations: unknown): ScimUserInput | string {
  if (!Array.isArray(operations) || operations.length === 0 || operations.length > 50) {
    return 'Operations must be a list of 1 to 50 operations';
  }
  const next: ScimUserInput = { ...current };
  const set = (path: string, value: unknown, remove: boolean): string | null => {
    switch (path.toLowerCase()) {
      case 'active': {
        const b = remove ? null : bool(value);
        if (b === null) return 'active must be true or false';
        next.active = b;
        return null;
      }
      case 'username': {
        const email = typeof value === 'string' ? normaliseEmail(value) : null;
        if (!email || remove) return 'userName must be an email address';
        next.userName = email;
        return null;
      }
      case 'externalid':
        next.externalId = remove ? null : text(value);
        return null;
      case 'displayname':
        next.displayName = remove ? null : text(value);
        return null;
      case 'name.givenname':
        next.givenName = remove ? null : text(value);
        return null;
      case 'name.familyname':
        next.familyName = remove ? null : text(value);
        return null;
      case 'name': {
        const name = (remove ? {} : (value ?? {})) as Record<string, unknown>;
        next.givenName = text(name.givenName);
        next.familyName = text(name.familyName);
        return null;
      }
      default:
        // Attributes login doesn't keep (phone numbers, titles…) are accepted and ignored.
        return null;
    }
  };
  for (const raw of operations) {
    const op = raw as { op?: unknown; path?: unknown; value?: unknown };
    const kind = typeof op.op === 'string' ? op.op.toLowerCase() : '';
    if (kind !== 'add' && kind !== 'replace' && kind !== 'remove')
      return 'op must be add, replace or remove';
    if (typeof op.path === 'string' && op.path) {
      // `emails[type eq "work"].value` and similar address paths change the user name.
      const path = /^emails(\[.*\])?(\.value)?$/i.test(op.path) ? 'userName' : op.path;
      const error = set(path, op.value, kind === 'remove');
      if (error) return error;
    } else if (kind !== 'remove' && op.value && typeof op.value === 'object') {
      for (const [key, value] of Object.entries(op.value as Record<string, unknown>)) {
        const error = set(key, value, false);
        if (error) return error;
      }
    } else {
      return 'A path is required';
    }
  }
  return next;
}

/** `userName eq "…"` or `externalId eq "…"`, the filters directories use to find a user. */
function readFilter(filter: string): { column: 'user_name' | 'external_id'; value: string } | null {
  const match = /^\s*(userName|externalId)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i.exec(filter);
  if (!match?.[1] || match[2] === undefined) return null;
  return {
    column: match[1].toLowerCase() === 'username' ? 'user_name' : 'external_id',
    value: match[2].replace(/\\(.)/g, '$1'),
  };
}

export function registerScimRoutes(app: Hono<AppEnv>, deps: Deps): void {
  /** The organization the request's token belongs to, or the error to answer with. */
  async function orgOf(c: AppContext): Promise<string | Response> {
    const key = c.req.header('Authorization')?.match(/^Bearer\s+(\S+)$/i)?.[1];
    // Directories call from a few addresses each: the token endpoint's generous per-address limit.
    const { success } = await c.env.TOKEN_RATE_LIMITER.limit({
      key: `scim:${clientIp(c) ?? 'unknown'}`,
    });
    if (!success) return scimError(429, 'Too many requests');
    const orgId = key ? await orgForScimToken(c.env.DB, deps.now(), key) : null;
    return orgId ?? scimError(401, 'A valid bearer token is required');
  }

  async function body(c: AppContext): Promise<Record<string, unknown> | Response> {
    const raw = await c.req.text();
    if (raw.length > MAX_BODY_BYTES) return scimError(413, 'The request is too large');
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Answered below.
    }
    return scimError(400, 'The body must be a JSON object', 'invalidSyntax');
  }

  const findUser = (c: AppContext, orgId: string, id: string) =>
    c.env.DB.prepare('SELECT * FROM scim_users WHERE id = ? AND org_id = ?')
      .bind(id, orgId)
      .first<ScimUserRow>();

  /** Stores `input` for the user and makes membership follow it. */
  async function save(
    c: AppContext,
    orgId: string,
    input: ScimUserInput,
    existing: ScimUserRow | null,
  ): Promise<ScimUserRow | Response> {
    if (!(await addressAtVerifiedDomain(c.env.DB, orgId, input.userName))) {
      return scimError(
        400,
        'userName must be an address at one of the organization’s verified domains',
        'invalidValue',
      );
    }
    const now = deps.now();
    let row: ScimUserRow | null;
    try {
      if (existing) {
        // A new address belongs to someone else: unlink, so membership follows the new address.
        const relink = existing.user_name.toLowerCase() !== input.userName;
        if (relink && existing.user_id) {
          await syncMembership(c.env.DB, now, { ...existing, active: 0 }, { oauth: oauth(c) });
        }
        row = await c.env.DB.prepare(
          `UPDATE scim_users SET user_name = ?, external_id = ?, display_name = ?, given_name = ?,
             family_name = ?, active = ?, updated_at = ?,
             user_id = CASE WHEN ? THEN NULL ELSE user_id END
           WHERE id = ? AND org_id = ? RETURNING *`,
        )
          .bind(
            input.userName,
            input.externalId,
            input.displayName,
            input.givenName,
            input.familyName,
            input.active ? 1 : 0,
            now,
            relink ? 1 : 0,
            existing.id,
            orgId,
          )
          .first<ScimUserRow>();
      } else {
        row = await c.env.DB.prepare(
          `INSERT INTO scim_users (id, org_id, user_name, external_id, display_name, given_name,
             family_name, active, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`,
        )
          .bind(
            `scu_${randomToken(12)}`,
            orgId,
            input.userName,
            input.externalId,
            input.displayName,
            input.givenName,
            input.familyName,
            input.active ? 1 : 0,
            now,
            now,
          )
          .first<ScimUserRow>();
      }
    } catch (error) {
      if (error instanceof Error && /UNIQUE/i.test(error.message)) {
        return scimError(409, 'A user with this userName already exists', 'uniqueness');
      }
      throw error;
    }
    if (!row) return scimError(404, 'User not found');
    if (!(await syncMembership(c.env.DB, now, row, { oauth: oauth(c) }))) {
      return scimError(
        409,
        'This person is the organization’s last owner: make someone else an owner in 2earl first',
        'mutability',
      );
    }
    await audit(c.env.DB, now, existing ? 'scim.user_updated' : 'scim.user_created', {
      detail: { org: orgId, user: row.id },
    });
    return (await findUser(c, orgId, row.id)) ?? row;
  }

  // ---- Discovery (RFC 7644 §4) ----------------------------------------------------------------

  app.get('/scim/v2/ServiceProviderConfig', (c) =>
    scimJson({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      documentationUri: 'https://github.com/2earl/login/blob/main/docs/DESIGN.md',
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: MAX_COUNT },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          type: 'oauthbearertoken',
          name: 'Bearer token',
          description: 'A token an owner creates on the organization’s Directory page',
        },
      ],
      meta: {
        resourceType: 'ServiceProviderConfig',
        location: `${c.env.ISSUER}/scim/v2/ServiceProviderConfig`,
      },
    }),
  );

  app.get('/scim/v2/ResourceTypes', (c) =>
    scimJson({
      schemas: [LIST_SCHEMA],
      totalResults: 1,
      Resources: [
        {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
          id: 'User',
          name: 'User',
          endpoint: '/Users',
          schema: USER_SCHEMA,
          meta: {
            resourceType: 'ResourceType',
            location: `${c.env.ISSUER}/scim/v2/ResourceTypes/User`,
          },
        },
      ],
    }),
  );

  app.get('/scim/v2/Schemas', (c) =>
    scimJson({
      schemas: [LIST_SCHEMA],
      totalResults: 1,
      Resources: [
        {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
          id: USER_SCHEMA,
          name: 'User',
          attributes: [
            {
              name: 'userName',
              type: 'string',
              required: true,
              uniqueness: 'server',
              caseExact: false,
              mutability: 'readWrite',
              returned: 'default',
            },
            {
              name: 'externalId',
              type: 'string',
              required: false,
              mutability: 'readWrite',
              returned: 'default',
            },
            {
              name: 'displayName',
              type: 'string',
              required: false,
              mutability: 'readWrite',
              returned: 'default',
            },
            {
              name: 'name',
              type: 'complex',
              required: false,
              subAttributes: [
                { name: 'givenName', type: 'string', mutability: 'readWrite' },
                { name: 'familyName', type: 'string', mutability: 'readWrite' },
              ],
            },
            {
              name: 'active',
              type: 'boolean',
              required: false,
              mutability: 'readWrite',
              returned: 'default',
            },
          ],
          meta: {
            resourceType: 'Schema',
            location: `${c.env.ISSUER}/scim/v2/Schemas/${USER_SCHEMA}`,
          },
        },
      ],
    }),
  );

  // ---- Users ----------------------------------------------------------------------------------

  app.get('/scim/v2/Users', async (c) => {
    const orgId = await orgOf(c);
    if (orgId instanceof Response) return orgId;
    const startIndex = Math.max(1, Number.parseInt(c.req.query('startIndex') ?? '1', 10) || 1);
    const count = Math.min(
      MAX_COUNT,
      Math.max(0, Number.parseInt(c.req.query('count') ?? String(MAX_COUNT), 10) || 0),
    );
    const filterText = c.req.query('filter');
    let where = 'org_id = ?';
    const binds: unknown[] = [orgId];
    if (filterText) {
      const filter = readFilter(filterText);
      if (!filter)
        return scimError(
          400,
          'Only userName eq and externalId eq filters are supported',
          'invalidFilter',
        );
      where += ` AND ${filter.column} = ?${filter.column === 'user_name' ? ' COLLATE NOCASE' : ''}`;
      binds.push(filter.value);
    }
    const total = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM scim_users WHERE ${where}`)
      .bind(...binds)
      .first<{ n: number }>();
    const { results } = await c.env.DB.prepare(
      `SELECT * FROM scim_users WHERE ${where} ORDER BY created_at, id LIMIT ? OFFSET ?`,
    )
      .bind(...binds, count, startIndex - 1)
      .all<ScimUserRow>();
    return scimJson({
      schemas: [LIST_SCHEMA],
      totalResults: total?.n ?? 0,
      startIndex,
      itemsPerPage: results.length,
      Resources: results.map((row) => representation(c.env, row)),
    });
  });

  app.get('/scim/v2/Users/:id', async (c) => {
    const orgId = await orgOf(c);
    if (orgId instanceof Response) return orgId;
    const row = await findUser(c, orgId, c.req.param('id'));
    return row ? scimJson(representation(c.env, row)) : scimError(404, 'User not found');
  });

  app.post('/scim/v2/Users', async (c) => {
    const orgId = await orgOf(c);
    if (orgId instanceof Response) return orgId;
    const parsed = await body(c);
    if (parsed instanceof Response) return parsed;
    const input = readUser(parsed);
    if (typeof input === 'string') return scimError(400, input, 'invalidValue');
    const row = await save(c, orgId, input, null);
    if (row instanceof Response) return row;
    const resource = representation(c.env, row);
    return scimJson(resource, 201, { Location: resource.meta.location });
  });

  app.put('/scim/v2/Users/:id', async (c) => {
    const orgId = await orgOf(c);
    if (orgId instanceof Response) return orgId;
    const existing = await findUser(c, orgId, c.req.param('id'));
    if (!existing) return scimError(404, 'User not found');
    const parsed = await body(c);
    if (parsed instanceof Response) return parsed;
    const input = readUser(parsed);
    if (typeof input === 'string') return scimError(400, input, 'invalidValue');
    const row = await save(c, orgId, input, existing);
    return row instanceof Response ? row : scimJson(representation(c.env, row));
  });

  app.patch('/scim/v2/Users/:id', async (c) => {
    const orgId = await orgOf(c);
    if (orgId instanceof Response) return orgId;
    const existing = await findUser(c, orgId, c.req.param('id'));
    if (!existing) return scimError(404, 'User not found');
    const parsed = await body(c);
    if (parsed instanceof Response) return parsed;
    if (!Array.isArray(parsed.schemas) || !parsed.schemas.includes(PATCH_SCHEMA)) {
      return scimError(400, 'A PatchOp request is required', 'invalidSyntax');
    }
    const input = applyPatch(
      {
        userName: existing.user_name.toLowerCase(),
        externalId: existing.external_id,
        displayName: existing.display_name,
        givenName: existing.given_name,
        familyName: existing.family_name,
        active: existing.active === 1,
      },
      parsed.Operations,
    );
    if (typeof input === 'string') return scimError(400, input, 'invalidValue');
    const row = await save(c, orgId, input, existing);
    return row instanceof Response ? row : scimJson(representation(c.env, row));
  });

  app.delete('/scim/v2/Users/:id', async (c) => {
    const orgId = await orgOf(c);
    if (orgId instanceof Response) return orgId;
    const existing = await findUser(c, orgId, c.req.param('id'));
    if (!existing) return scimError(404, 'User not found');
    const now = deps.now();
    // A managed account is deactivated now and deleted in 30 days (DESIGN §4.18).
    const removed = await syncMembership(
      c.env.DB,
      now,
      { ...existing, active: 0 },
      { oauth: oauth(c), deleteAfter: now + DELETE_AFTER_SECONDS },
    );
    if (!removed) {
      return scimError(
        409,
        'This person is the organization’s last owner: make someone else an owner in 2earl first',
        'mutability',
      );
    }
    await c.env.DB.prepare('DELETE FROM scim_users WHERE id = ? AND org_id = ?')
      .bind(existing.id, orgId)
      .run();
    await audit(c.env.DB, now, 'scim.user_deleted', { detail: { org: orgId, user: existing.id } });
    return new Response(null, { status: 204 });
  });

  app.all('/scim/v2/*', () => scimError(501, 'Not supported: login offers Users only'));
}
