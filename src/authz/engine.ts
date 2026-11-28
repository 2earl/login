import { staffRoleOf } from '../staff';
import { authzOf, systemRole } from '../services';
import { CUSTOM_ROLE_PATTERN, serviceOf, type BaseOrgRole, type BaseStaffRole } from './types';

/**
 * How a decision is made (DESIGN §4.32). Read live from D1 on every call; nothing is cached, and
 * tokens never carry the result.
 *
 * In one service, a principal's permissions are:
 * - **in an organization**: the role its base role (`org_members.role`) implies, plus its
 *   assignments in that organization, held directly or through a directory group it is an active
 *   member of;
 * - **across 2earl** (no organization): the role its staff role implies, plus its platform
 *   assignments.
 *
 * The two never mix: staff hold nothing inside an organization because they are staff, and an
 * organization role gives nothing across 2earl. Inactive accounts and organizations hold nothing;
 * assignments that expired or carry a condition (phase 13e) give nothing.
 */

export interface Subject {
  type: 'user' | 'service_account';
  id: string;
}

export interface Resource {
  type: string;
  id: string;
}

export interface Context {
  /**
   * The scopes of the access token the request came with. When given, the answer is limited to
   * what they allow (`scopeGrants`): an app never does more than the person let it.
   */
  scopes?: readonly string[];
  /** Unix seconds; tests only. */
  now?: number;
}

export interface Effective {
  /** Permissions held for every resource. */
  permissions: Set<string>;
  /** Permission → the resources (`<type>:<id>`) it is held for, beyond the ones above. */
  scoped: Map<string, Set<string>>;
  /** System role IDs and custom role IDs the permissions came from. */
  roles: string[];
  /** The base role the defaults came from, or null. */
  baseRole: BaseOrgRole | BaseStaffRole | null;
}

export class AuthzError extends Error {
  override name = 'AuthzError';
}

const empty = (): Effective => ({
  permissions: new Set(),
  scoped: new Map(),
  roles: [],
  baseRole: null,
});

const MAX_RESOURCE_LENGTH = 200;
const RESOURCE_TYPE = /^[a-z][a-z0-9_-]{0,39}$/;

/** `<type>:<id>`, or null if the resource can't be named. */
export function resourceKey(resource: Resource | undefined): string | null {
  if (!resource) return null;
  if (!RESOURCE_TYPE.test(resource.type)) return null;
  if (resource.id.length === 0 || resource.id.length > MAX_RESOURCE_LENGTH) return null;
  return `${resource.type}:${resource.id}`;
}

/** Everything `subject` may do in `service`, in `orgId` or (without it) across 2earl. */
export async function effective(
  env: Env,
  query: { subject: Subject; service: string; orgId?: string | null; context?: Context },
): Promise<Effective> {
  const manifest = authzOf(query.service);
  if (!manifest) throw new AuthzError(`unknown service: ${query.service}`);
  const { subject } = query;
  const orgId = query.orgId ?? null;
  const now = query.context?.now ?? Math.floor(Date.now() / 1000);
  const db = env.DB;
  const result = empty();
  const roleIds: { role: string; resource: string }[] = [];

  if (subject.type === 'service_account') {
    // A service account (DESIGN §4.33) holds only what it was given, in its own organization.
    const account = await db
      .prepare(
        `SELECT s.org_id FROM service_accounts s
         JOIN organizations o ON o.id = s.org_id AND o.status = 'active'
         WHERE s.id = ? AND s.status = 'active'`,
      )
      .bind(subject.id)
      .first<{ org_id: string }>();
    if (!account || orgId === null || account.org_id !== orgId) return empty();
  } else {
    const user = await db
      .prepare('SELECT status FROM users WHERE id = ?')
      .bind(subject.id)
      .first<{ status: string }>();
    if (user?.status !== 'active') return empty();
  }

  if (subject.type === 'service_account') {
    // No base role.
  } else if (orgId !== null) {
    const member = await db
      .prepare(
        `SELECT m.role FROM org_members m
         JOIN organizations o ON o.id = m.org_id AND o.status = 'active'
         WHERE m.org_id = ? AND m.user_id = ?`,
      )
      .bind(orgId, subject.id)
      .first<{ role: BaseOrgRole }>();
    // Only members hold anything in an organization.
    if (!member) return empty();
    result.baseRole = member.role;
    const implied = manifest.orgDefaults?.[member.role];
    if (implied) roleIds.push({ role: implied, resource: '' });
  } else {
    const staff = await staffRoleOf(env, subject.id);
    result.baseRole = staff;
    const implied = staff ? manifest.staffDefaults?.[staff] : undefined;
    if (implied) roleIds.push({ role: implied, resource: '' });
  }

  const { results: assigned } = await db
    .prepare(
      `SELECT a.role, a.resource FROM authz_assignments a
       WHERE a.service = ?1 AND a.condition = ''
         AND (a.expires_at IS NULL OR a.expires_at > ?2)
         AND ((?3 IS NULL AND a.scope_kind = 'platform')
              OR (a.scope_kind = 'org' AND a.org_id = ?3))
         AND ((a.principal_kind = ?5 AND a.principal_id = ?4)
              OR (?5 = 'user' AND a.principal_kind = 'group' AND a.scope_kind = 'org' AND a.principal_id IN (
                SELECT gm.group_id FROM scim_group_members gm
                JOIN scim_users su ON su.id = gm.scim_user_id
                WHERE su.user_id = ?4 AND su.active = 1 AND su.org_id = a.org_id)))
       ORDER BY a.role, a.resource
       LIMIT 500`,
    )
    .bind(query.service, now, orgId, subject.id, subject.type)
    .all<{ role: string; resource: string }>();
  roleIds.push(...assigned);

  // Custom roles: only the organization's own, of this service.
  const customIds = [
    ...new Set(roleIds.map((r) => r.role).filter((r) => CUSTOM_ROLE_PATTERN.test(r))),
  ];
  const custom = new Map<string, string[]>();
  if (customIds.length > 0 && orgId !== null) {
    const { results } = await db
      .prepare(
        `SELECT p.role_id, p.permission FROM authz_role_permissions p
         JOIN authz_roles r ON r.id = p.role_id
         WHERE r.org_id = ?1 AND r.service = ?2
           AND r.id IN (SELECT value FROM json_each(?3))`,
      )
      .bind(orgId, query.service, JSON.stringify(customIds))
      .all<{ role_id: string; permission: string }>();
    for (const row of results) {
      const list = custom.get(row.role_id) ?? [];
      list.push(row.permission);
      custom.set(row.role_id, list);
    }
  }

  const roles = new Set<string>();
  for (const { role, resource } of roleIds) {
    let permissions: readonly string[] | undefined;
    if (CUSTOM_ROLE_PATTERN.test(role)) {
      permissions = custom.get(role);
    } else if (serviceOf(role) === query.service) {
      const system = systemRole(role);
      // A role held in the wrong kind of scope gives nothing.
      if (system && system.assignable === (orgId === null ? 'platform' : 'org')) {
        permissions = system.permissions;
      }
    }
    if (!permissions) continue;
    roles.add(role);
    for (const permission of permissions) {
      // A permission the code no longer declares gives nothing.
      if (!Object.hasOwn(manifest.permissions, permission)) continue;
      if (resource === '') {
        result.permissions.add(permission);
      } else {
        const set = result.scoped.get(permission) ?? new Set<string>();
        set.add(resource);
        result.scoped.set(permission, set);
      }
    }
  }
  result.roles = [...roles];
  for (const permission of result.permissions) result.scoped.delete(permission);
  return limitToScopes(result, manifest.scopeGrants, query.context);
}

/** The answer, limited to what the token's scopes allow, when the caller passed them. */
function limitToScopes(
  result: Effective,
  scopeGrants: Readonly<Record<string, readonly string[] | '*'>>,
  context: Context | undefined,
): Effective {
  if (!context?.scopes) return result;
  const allowed = new Set<string>();
  for (const scope of context.scopes) {
    const grants = scopeGrants[scope];
    if (grants === '*') return result;
    for (const permission of grants ?? []) allowed.add(permission);
  }
  for (const permission of [...result.permissions]) {
    if (!allowed.has(permission)) result.permissions.delete(permission);
  }
  for (const permission of [...result.scoped.keys()]) {
    if (!allowed.has(permission)) result.scoped.delete(permission);
  }
  return result;
}

/** Whether `subject` may do `action` (for `resource`, if given). Unknown permissions throw. */
export async function check(
  env: Env,
  query: {
    subject: Subject;
    action: string;
    orgId?: string | null;
    resource?: Resource;
    context?: Context;
  },
): Promise<boolean> {
  const service = serviceOf(query.action);
  if (!Object.hasOwn(authzOf(service)?.permissions ?? {}, query.action)) {
    throw new AuthzError(`unknown permission: ${query.action}`);
  }
  const found = await effective(env, {
    subject: query.subject,
    service,
    orgId: query.orgId ?? null,
    ...(query.context ? { context: query.context } : {}),
  });
  if (found.permissions.has(query.action)) return true;
  const key = resourceKey(query.resource);
  return key !== null && (found.scoped.get(query.action)?.has(key) ?? false);
}

/**
 * The accounts that hold `action` in an organization, for every resource: their base role's
 * default or an assignment, directly or through a group. Up to 1,000.
 */
export async function subjectsWith(
  env: Env,
  query: { action: string; orgId: string; context?: Context },
): Promise<Subject[]> {
  const service = serviceOf(query.action);
  const manifest = authzOf(service);
  if (!manifest || !Object.hasOwn(manifest.permissions, query.action)) {
    throw new AuthzError(`unknown permission: ${query.action}`);
  }
  const now = query.context?.now ?? Math.floor(Date.now() / 1000);
  const holding = (role: string) => systemRole(role)?.permissions.includes(query.action) ?? false;
  const baseRoles = Object.entries(manifest.orgDefaults ?? {})
    .filter(([, role]) => holding(role))
    .map(([base]) => base);
  const systemRoles = Object.keys(manifest.roles).filter(
    (role) => manifest.roles[role]?.assignable === 'org' && holding(role),
  );
  const { results } = await env.DB.prepare(
    `WITH active_members AS (
       SELECT m.user_id, m.role FROM org_members m
       JOIN organizations o ON o.id = m.org_id AND o.status = 'active'
       JOIN users u ON u.id = m.user_id AND u.status = 'active'
       WHERE m.org_id = ?1
     ),
     granting AS (
       SELECT a.principal_kind, a.principal_id FROM authz_assignments a
       WHERE a.scope_kind = 'org' AND a.org_id = ?1 AND a.service = ?2 AND a.resource = ''
         AND a.condition = '' AND (a.expires_at IS NULL OR a.expires_at > ?3)
         AND (a.role IN (SELECT value FROM json_each(?4))
              OR a.role IN (SELECT p.role_id FROM authz_role_permissions p
                            JOIN authz_roles r ON r.id = p.role_id
                            WHERE r.org_id = ?1 AND r.service = ?2 AND p.permission = ?5))
     )
     SELECT user_id FROM active_members WHERE role IN (SELECT value FROM json_each(?6))
     UNION
     SELECT m.user_id FROM active_members m JOIN granting g
       ON g.principal_kind = 'user' AND g.principal_id = m.user_id
     UNION
     SELECT m.user_id FROM active_members m
       JOIN scim_users su ON su.user_id = m.user_id AND su.org_id = ?1 AND su.active = 1
       JOIN scim_group_members gm ON gm.scim_user_id = su.id
       JOIN granting g ON g.principal_kind = 'group' AND g.principal_id = gm.group_id
     ORDER BY 1 LIMIT 1000`,
  )
    .bind(
      query.orgId,
      service,
      now,
      JSON.stringify(systemRoles),
      query.action,
      JSON.stringify(baseRoles),
    )
    .all<{ user_id: string }>();
  return results.map((r) => ({ type: 'user', id: r.user_id }));
}
