import { orgRoleCan, type OrgRole } from '../orgs';
import { AUTHZ_SERVICES, authzOf, systemRole } from '../services';
import { effective } from './engine';
import { NEVER_ASSIGNABLE } from './login-manifest';
import { customRole, type Principal } from './store';
import { CUSTOM_ROLE_PATTERN, serviceOf } from './types';

/**
 * Who may give what (DESIGN §4.32). One place, asked by every route and the API before they
 * change roles or assignments:
 * - giving a role needs `login:access.assign`, and every permission in the role held by the
 *   person giving it, in the same organization: nobody hands out more than they have;
 * - a privileged role needs an owner;
 * - nobody gives themselves a role;
 * - defining a role needs `login:roles.manage`, and every permission in it held the same way.
 *
 * login's own permissions aren't given by roles in apps: its rules for owners, admins, auditors
 * and members stay the base roles of §4.14.
 */

export type GrantRefusal = 'not_allowed' | 'privileged' | 'self' | 'exceeds' | 'unknown_role';

/** The services whose roles an organization gives: every one with a manifest but login. */
export const ASSIGNABLE_SERVICES = AUTHZ_SERVICES.filter((s) => s.id !== 'login');

const isAssignableService = (service: string) => ASSIGNABLE_SERVICES.some((s) => s.id === service);

async function holdsAll(
  env: Env,
  actorId: string,
  orgId: string,
  service: string,
  permissions: readonly string[],
): Promise<boolean> {
  const held = await effective(env, {
    subject: { type: 'user', id: actorId },
    service,
    orgId,
  });
  return permissions.every((p) => held.permissions.has(p));
}

export async function mayGrant(
  env: Env,
  actor: { userId: string; role: OrgRole },
  orgId: string,
  input: { role: string; principal: Principal },
): Promise<{ ok: true } | { ok: false; reason: GrantRefusal }> {
  if (!orgRoleCan(actor.role, 'login:access.assign')) return { ok: false, reason: 'not_allowed' };
  if (input.principal.kind === 'user' && input.principal.id === actor.userId) {
    return { ok: false, reason: 'self' };
  }
  let service: string;
  let permissions: readonly string[];
  let privileged = false;
  if (CUSTOM_ROLE_PATTERN.test(input.role)) {
    const custom = await customRole(env.DB, orgId, input.role);
    if (!custom) return { ok: false, reason: 'unknown_role' };
    service = custom.service;
    permissions = custom.permissions;
  } else {
    const system = systemRole(input.role);
    if (system?.assignable !== 'org') return { ok: false, reason: 'unknown_role' };
    service = serviceOf(input.role);
    permissions = system.permissions;
    privileged = system.privileged === true;
  }
  if (!isAssignableService(service)) return { ok: false, reason: 'unknown_role' };
  if (permissions.some((p) => NEVER_ASSIGNABLE.has(p))) return { ok: false, reason: 'privileged' };
  if (privileged && actor.role !== 'owner') return { ok: false, reason: 'privileged' };
  if (!(await holdsAll(env, actor.userId, orgId, service, permissions))) {
    return { ok: false, reason: 'exceeds' };
  }
  return { ok: true };
}

/** Taking a role back: the same rules as giving it, so an admin can't remove an owner's grant. */
export const mayRevoke = mayGrant;

export async function mayDefineRole(
  env: Env,
  actor: { userId: string; role: OrgRole },
  orgId: string,
  service: string,
  permissions: readonly string[],
): Promise<{ ok: true } | { ok: false; reason: GrantRefusal }> {
  if (!orgRoleCan(actor.role, 'login:roles.manage')) return { ok: false, reason: 'not_allowed' };
  if (!isAssignableService(service) || !authzOf(service)) {
    return { ok: false, reason: 'unknown_role' };
  }
  if (!(await holdsAll(env, actor.userId, orgId, service, permissions))) {
    return { ok: false, reason: 'exceeds' };
  }
  return { ok: true };
}
