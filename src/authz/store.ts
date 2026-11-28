import { randomToken } from '../crypto';
import { orgName } from '../orgs';
import { staffRoleOf } from '../staff';
import { authzOf, systemRole } from '../services';
import { resourceKey } from './engine';
import { NEVER_ASSIGNABLE } from './login-manifest';
import { CUSTOM_ROLE_PATTERN, serviceOf } from './types';

/**
 * Custom roles and role assignments (DESIGN §4.32). These functions keep the data valid whoever
 * asks; whether the person asking may make the change is `mayGrant`'s question (phase 13b), asked
 * by the routes before they call these.
 */

export const MAX_CUSTOM_ROLES = 50;
export const MAX_ROLE_PERMISSIONS = 200;
export const MAX_ASSIGNMENTS = 5000;
export const MAX_REASON = 300;
export const MAX_DESCRIPTION = 300;

export interface CustomRole {
  id: string;
  orgId: string;
  service: string;
  name: string;
  description: string;
  permissions: string[];
  createdAt: number;
  updatedAt: number;
}

export type RoleResult =
  | { ok: true; role: CustomRole }
  | {
      ok: false;
      reason:
        | 'unknown_service'
        | 'invalid_name'
        | 'invalid_permissions'
        | 'too_many'
        | 'duplicate'
        | 'not_found';
    };

/** The permissions a custom role may hold: the service's own, never the ones that make owners. */
function validPermissions(service: string, permissions: readonly string[]): string[] | null {
  const manifest = authzOf(service);
  if (!manifest) return null;
  const unique = [...new Set(permissions)].sort();
  if (unique.length === 0 || unique.length > MAX_ROLE_PERMISSIONS) return null;
  for (const permission of unique) {
    if (!Object.hasOwn(manifest.permissions, permission)) return null;
    if (NEVER_ASSIGNABLE.has(permission)) return null;
  }
  return unique;
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;

function cleanDescription(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  return raw.replace(CONTROL, ' ').trim().slice(0, MAX_DESCRIPTION);
}

export async function createCustomRole(
  db: D1Database,
  now: number,
  input: {
    orgId: string;
    service: string;
    name: string;
    description?: string;
    permissions: readonly string[];
    createdBy: string;
  },
): Promise<RoleResult> {
  if (!authzOf(input.service)) return { ok: false, reason: 'unknown_service' };
  const name = orgName(input.name);
  if (!name) return { ok: false, reason: 'invalid_name' };
  const permissions = validPermissions(input.service, input.permissions);
  if (!permissions) return { ok: false, reason: 'invalid_permissions' };
  const id = `rol_${randomToken(12)}`;
  const description = cleanDescription(input.description);
  const [inserted] = await db.batch([
    db
      .prepare(
        `INSERT INTO authz_roles (id, org_id, service, name, description, created_by, created_at, updated_at)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7
         WHERE (SELECT COUNT(*) FROM authz_roles WHERE org_id = ?2) < ?8
         ON CONFLICT DO NOTHING`,
      )
      .bind(
        id,
        input.orgId,
        input.service,
        name,
        description,
        input.createdBy,
        now,
        MAX_CUSTOM_ROLES,
      ),
    ...permissions.map((permission) =>
      db
        .prepare(
          `INSERT INTO authz_role_permissions (role_id, permission)
           SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM authz_roles WHERE id = ?1)`,
        )
        .bind(id, permission),
    ),
  ]);
  if ((inserted?.meta.changes ?? 0) === 0) {
    const duplicate = await db
      .prepare(
        'SELECT 1 AS ok FROM authz_roles WHERE org_id = ? AND service = ? AND name = ? COLLATE NOCASE',
      )
      .bind(input.orgId, input.service, name)
      .first<{ ok: number }>();
    return { ok: false, reason: duplicate ? 'duplicate' : 'too_many' };
  }
  return {
    ok: true,
    role: {
      id,
      orgId: input.orgId,
      service: input.service,
      name,
      description,
      permissions,
      createdAt: now,
      updatedAt: now,
    },
  };
}

/** Replaces a custom role's name, description and permissions. */
export async function updateCustomRole(
  db: D1Database,
  now: number,
  input: {
    orgId: string;
    roleId: string;
    name: string;
    description?: string;
    permissions: readonly string[];
  },
): Promise<RoleResult> {
  const current = await customRole(db, input.orgId, input.roleId);
  if (!current) return { ok: false, reason: 'not_found' };
  const name = orgName(input.name);
  if (!name) return { ok: false, reason: 'invalid_name' };
  const permissions = validPermissions(current.service, input.permissions);
  if (!permissions) return { ok: false, reason: 'invalid_permissions' };
  const clash = await db
    .prepare(
      `SELECT 1 AS ok FROM authz_roles
       WHERE org_id = ? AND service = ? AND name = ? COLLATE NOCASE AND id != ?`,
    )
    .bind(input.orgId, current.service, name, input.roleId)
    .first<{ ok: number }>();
  if (clash) return { ok: false, reason: 'duplicate' };
  const description = cleanDescription(input.description);
  await db.batch([
    db
      .prepare(
        'UPDATE authz_roles SET name = ?, description = ?, updated_at = ? WHERE id = ? AND org_id = ?',
      )
      .bind(name, description, now, input.roleId, input.orgId),
    db.prepare('DELETE FROM authz_role_permissions WHERE role_id = ?').bind(input.roleId),
    ...permissions.map((permission) =>
      db
        .prepare('INSERT INTO authz_role_permissions (role_id, permission) VALUES (?, ?)')
        .bind(input.roleId, permission),
    ),
  ]);
  return { ok: true, role: { ...current, name, description, permissions, updatedAt: now } };
}

/** Deletes a custom role; its assignments go with it (migration 0029). */
export async function deleteCustomRole(
  db: D1Database,
  orgId: string,
  roleId: string,
): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM authz_roles WHERE id = ? AND org_id = ?')
    .bind(roleId, orgId)
    .run();
  return result.meta.changes > 0;
}

export async function customRole(
  db: D1Database,
  orgId: string,
  roleId: string,
): Promise<CustomRole | null> {
  if (!CUSTOM_ROLE_PATTERN.test(roleId)) return null;
  const row = await db
    .prepare(
      `SELECT id, org_id, service, name, description, created_at, updated_at,
              (SELECT json_group_array(permission) FROM
                (SELECT permission FROM authz_role_permissions WHERE role_id = r.id ORDER BY permission)
              ) AS permissions
       FROM authz_roles r WHERE id = ? AND org_id = ?`,
    )
    .bind(roleId, orgId)
    .first<{
      id: string;
      org_id: string;
      service: string;
      name: string;
      description: string;
      created_at: number;
      updated_at: number;
      permissions: string;
    }>();
  if (!row) return null;
  return {
    id: row.id,
    orgId: row.org_id,
    service: row.service,
    name: row.name,
    description: row.description,
    permissions: JSON.parse(row.permissions) as string[],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function listCustomRoles(db: D1Database, orgId: string): Promise<CustomRole[]> {
  const { results } = await db
    .prepare(
      `SELECT id, org_id, service, name, description, created_at, updated_at,
              (SELECT json_group_array(permission) FROM
                (SELECT permission FROM authz_role_permissions WHERE role_id = r.id ORDER BY permission)
              ) AS permissions
       FROM authz_roles r WHERE org_id = ? ORDER BY service, name COLLATE NOCASE`,
    )
    .bind(orgId)
    .all<{
      id: string;
      org_id: string;
      service: string;
      name: string;
      description: string;
      created_at: number;
      updated_at: number;
      permissions: string;
    }>();
  return results.map((row) => ({
    id: row.id,
    orgId: row.org_id,
    service: row.service,
    name: row.name,
    description: row.description,
    permissions: JSON.parse(row.permissions) as string[],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

// ---- Assignments ------------------------------------------------------------------------------

export type Principal = { kind: 'user' | 'group'; id: string };

export interface Assignment {
  id: string;
  scopeKind: 'platform' | 'org';
  orgId: string | null;
  resource: string;
  principal: Principal;
  role: string;
  service: string;
  expiresAt: number | null;
  grantedBy: string | null;
  grantedAt: number;
  reason: string;
}

export type AssignResult =
  | { ok: true; assignment: Assignment }
  | {
      ok: false;
      reason:
        | 'unknown_role'
        | 'wrong_scope'
        | 'not_assignable'
        | 'unknown_principal'
        | 'invalid_resource'
        | 'invalid_expiry'
        | 'exclusive'
        | 'duplicate'
        | 'too_many';
    };

/** The permissions of a role: system or the organization's custom one. Null if it isn't one. */
async function roleInfo(
  db: D1Database,
  orgId: string | null,
  role: string,
): Promise<{
  service: string;
  permissions: readonly string[];
  assignable: 'org' | 'platform';
} | null> {
  if (CUSTOM_ROLE_PATTERN.test(role)) {
    if (orgId === null) return null;
    const custom = await customRole(db, orgId, role);
    return custom
      ? { service: custom.service, permissions: custom.permissions, assignable: 'org' }
      : null;
  }
  const system = systemRole(role);
  return system ? { service: serviceOf(role), ...system } : null;
}

/** The base-role default plus direct assignments a user holds in a scope: for exclusive roles. */
async function rolesHeld(
  db: D1Database,
  env: Env,
  service: string,
  orgId: string | null,
  userId: string,
): Promise<Set<string>> {
  const manifest = authzOf(service);
  const held = new Set<string>();
  if (orgId !== null) {
    const member = await db
      .prepare('SELECT role FROM org_members WHERE org_id = ? AND user_id = ?')
      .bind(orgId, userId)
      .first<{ role: 'owner' | 'admin' | 'auditor' | 'member' }>();
    const implied = member ? manifest?.orgDefaults?.[member.role] : undefined;
    if (implied) held.add(implied);
  } else {
    const staff = await staffRoleOf(env, userId);
    const implied = staff ? manifest?.staffDefaults?.[staff] : undefined;
    if (implied) held.add(implied);
  }
  const { results } = await db
    .prepare(
      `SELECT role FROM authz_assignments
       WHERE service = ? AND scope_kind = ? AND org_id IS ? AND principal_kind = 'user' AND principal_id = ?`,
    )
    .bind(service, orgId === null ? 'platform' : 'org', orgId, userId)
    .all<{ role: string }>();
  for (const r of results) held.add(r.role);
  return held;
}

/**
 * Gives `role` to `principal` in an organization (`orgId`) or across 2earl (`orgId` null).
 * Checks that the data makes sense: the role exists and fits the scope, holds nothing that makes
 * owners or staff, the principal belongs where the role is given (a member, a group of the
 * organization, or 2earl staff), and no exclusive pair would be held together.
 */
export async function assignRole(
  env: Env,
  now: number,
  input: {
    orgId: string | null;
    principal: Principal;
    role: string;
    resource?: { type: string; id: string };
    expiresAt?: number | null;
    grantedBy: string;
    reason?: string;
  },
): Promise<AssignResult> {
  const db = env.DB;
  const { orgId, principal } = input;
  const info = await roleInfo(db, orgId, input.role);
  if (!info) return { ok: false, reason: 'unknown_role' };
  if (info.assignable !== (orgId === null ? 'platform' : 'org')) {
    return { ok: false, reason: 'wrong_scope' };
  }
  if (info.permissions.some((p) => NEVER_ASSIGNABLE.has(p))) {
    return { ok: false, reason: 'not_assignable' };
  }

  let resource = '';
  if (input.resource) {
    const key = resourceKey(input.resource);
    const types = authzOf(info.service)?.resourceTypes ?? [];
    if (orgId === null || !key || !types.includes(input.resource.type)) {
      return { ok: false, reason: 'invalid_resource' };
    }
    resource = key;
  }
  const expiresAt = input.expiresAt ?? null;
  if (expiresAt !== null && (!Number.isInteger(expiresAt) || expiresAt <= now)) {
    return { ok: false, reason: 'invalid_expiry' };
  }

  if (principal.kind === 'user') {
    if (orgId !== null) {
      const member = await db
        .prepare('SELECT 1 AS ok FROM org_members WHERE org_id = ? AND user_id = ?')
        .bind(orgId, principal.id)
        .first<{ ok: number }>();
      if (!member) return { ok: false, reason: 'unknown_principal' };
    } else if (!(await staffRoleOf(env, principal.id))) {
      return { ok: false, reason: 'unknown_principal' };
    }
    const exclusive = authzOf(info.service)?.exclusive ?? [];
    if (exclusive.length > 0) {
      const held = await rolesHeld(db, env, info.service, orgId, principal.id);
      for (const [a, b] of exclusive) {
        if ((input.role === a && held.has(b)) || (input.role === b && held.has(a))) {
          return { ok: false, reason: 'exclusive' };
        }
      }
    }
  } else {
    if (orgId === null) return { ok: false, reason: 'unknown_principal' };
    const group = await db
      .prepare('SELECT 1 AS ok FROM scim_groups WHERE id = ? AND org_id = ?')
      .bind(principal.id, orgId)
      .first<{ ok: number }>();
    if (!group) return { ok: false, reason: 'unknown_principal' };
  }

  const id = `asg_${randomToken(12)}`;
  const reason = cleanDescription(input.reason).slice(0, MAX_REASON);
  const result = await db
    .prepare(
      `INSERT INTO authz_assignments
         (id, scope_kind, org_id, resource, principal_kind, principal_id, role, service,
          expires_at, granted_by, granted_at, reason)
       SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
       WHERE ?3 IS NULL OR (SELECT COUNT(*) FROM authz_assignments WHERE org_id = ?3) < ?13
       ON CONFLICT DO NOTHING`,
    )
    .bind(
      id,
      orgId === null ? 'platform' : 'org',
      orgId,
      resource,
      principal.kind,
      principal.id,
      input.role,
      info.service,
      expiresAt,
      input.grantedBy,
      now,
      reason,
      MAX_ASSIGNMENTS,
    )
    .run();
  if (result.meta.changes === 0) {
    const existing = await db
      .prepare(
        `SELECT 1 AS ok FROM authz_assignments
         WHERE scope_kind = ? AND org_id IS ? AND resource = ? AND principal_kind = ?
           AND principal_id = ? AND role = ?`,
      )
      .bind(
        orgId === null ? 'platform' : 'org',
        orgId,
        resource,
        principal.kind,
        principal.id,
        input.role,
      )
      .first<{ ok: number }>();
    return { ok: false, reason: existing ? 'duplicate' : 'too_many' };
  }
  return {
    ok: true,
    assignment: {
      id,
      scopeKind: orgId === null ? 'platform' : 'org',
      orgId,
      resource,
      principal,
      role: input.role,
      service: info.service,
      expiresAt,
      grantedBy: input.grantedBy,
      grantedAt: now,
      reason,
    },
  };
}

/** Removes one assignment in a scope. Returns it, or null if there was none. */
export async function revokeAssignment(
  db: D1Database,
  orgId: string | null,
  assignmentId: string,
): Promise<Assignment | null> {
  const row = await db
    .prepare(
      `DELETE FROM authz_assignments WHERE id = ? AND org_id IS ?
       RETURNING ${ASSIGNMENT_COLUMNS}`,
    )
    .bind(assignmentId, orgId)
    .first<AssignmentRow>();
  return row ? toAssignment(row) : null;
}

/** An organization's assignments (`orgId`), or 2earl's platform ones (null). */
export async function listAssignments(
  db: D1Database,
  orgId: string | null,
  now: number,
): Promise<Assignment[]> {
  const { results } = await db
    .prepare(
      `SELECT ${ASSIGNMENT_COLUMNS} FROM authz_assignments
       WHERE org_id IS ? AND (expires_at IS NULL OR expires_at > ?)
       ORDER BY service, role, principal_kind, principal_id, resource LIMIT ?`,
    )
    .bind(orgId, now, MAX_ASSIGNMENTS)
    .all<AssignmentRow>();
  return results.map(toAssignment);
}

/** Daily: assignments whose time is up. */
export function expiredAssignmentsStatement(db: D1Database, now: number): D1PreparedStatement {
  return db
    .prepare('DELETE FROM authz_assignments WHERE expires_at IS NOT NULL AND expires_at <= ?')
    .bind(now);
}

const ASSIGNMENT_COLUMNS = `id, scope_kind, org_id, resource, principal_kind, principal_id, role,
  service, expires_at, granted_by, granted_at, reason`;

interface AssignmentRow {
  id: string;
  scope_kind: 'platform' | 'org';
  org_id: string | null;
  resource: string;
  principal_kind: 'user' | 'group';
  principal_id: string;
  role: string;
  service: string;
  expires_at: number | null;
  granted_by: string | null;
  granted_at: number;
  reason: string;
}

function toAssignment(row: AssignmentRow): Assignment {
  return {
    id: row.id,
    scopeKind: row.scope_kind,
    orgId: row.org_id,
    resource: row.resource,
    principal: { kind: row.principal_kind, id: row.principal_id },
    role: row.role,
    service: row.service,
    expiresAt: row.expires_at,
    grantedBy: row.granted_by,
    grantedAt: row.granted_at,
    reason: row.reason,
  };
}
