import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuthzError, check, effective, subjectsWith } from '../src/authz/engine';
import {
  MAX_CUSTOM_ROLES,
  assignRole,
  createCustomRole,
  deleteCustomRole,
  expiredAssignmentsStatement,
  listAssignments,
  revokeAssignment,
  updateCustomRole,
} from '../src/authz/store';
import { T0, group, member, org, owner, resetAuthz, staff, user } from './authz-fixtures';

const ctx = { now: T0 + 10 };
const u = (id: string) => ({ type: 'user' as const, id });
const perms = async (id: string, service: string, orgId: string | null, scopes?: string[]) =>
  [
    ...(
      await effective(env, {
        subject: u(id),
        service,
        orgId,
        context: { ...ctx, ...(scopes ? { scopes } : {}) },
      })
    ).permissions,
  ].sort();

beforeEach(resetAuthz);

describe('base roles (DESIGN §4.32)', () => {
  beforeEach(async () => {
    await org('o1');
    for (const role of ['owner', 'admin', 'auditor', 'member'] as const) {
      await user(role);
      await member('o1', role, role);
    }
  });

  it('give each organization role what Emanet Kurumsal’s `can` map gave', async () => {
    expect(await perms('owner', 'emanet', 'o1')).toEqual([
      'emanet:cases.read',
      'emanet:cases.write',
      'emanet:integrations.manage',
    ]);
    expect(await perms('admin', 'emanet', 'o1')).toEqual(await perms('owner', 'emanet', 'o1'));
    expect(await perms('member', 'emanet', 'o1')).toEqual([
      'emanet:cases.read',
      'emanet:cases.write',
    ]);
    expect(await perms('auditor', 'emanet', 'o1')).toEqual(['emanet:cases.read']);
  });

  it('give nothing outside the organization, or in another one', async () => {
    await org('o2');
    expect(await perms('owner', 'emanet', 'o2')).toEqual([]);
    expect(await perms('owner', 'emanet', null)).toEqual([]);
    await user('stranger');
    expect(await perms('stranger', 'emanet', 'o1')).toEqual([]);
  });

  it('give nothing to a suspended account or in a suspended organization', async () => {
    await env.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = 'member'").run();
    expect(await perms('member', 'emanet', 'o1')).toEqual([]);
    await env.DB.prepare("UPDATE organizations SET status = 'suspended' WHERE id = 'o1'").run();
    expect(await perms('owner', 'emanet', 'o1')).toEqual([]);
  });

  it('give staff what Emanet Merkez’s `can` map gave, across 2earl only', async () => {
    await owner('boss');
    await user('ops');
    await staff('ops', 'admin');
    await user('help');
    await staff('help', 'support');
    const all = ['emanet:control.change', 'emanet:control.review'];
    expect(await perms('boss', 'emanet', null)).toEqual(all);
    expect(await perms('ops', 'emanet', null)).toEqual(all);
    expect(await perms('help', 'emanet', null)).toEqual(['emanet:control.review']);
    expect(await perms('owner', 'emanet', null)).toEqual([]);
    // Staff hold nothing inside an organization because they are staff.
    expect(await perms('ops', 'emanet', 'o1')).toEqual([]);
  });

  it('are limited to what the token’s scopes allow, when the caller passes them', async () => {
    expect(await perms('owner', 'emanet', 'o1', ['emanet:field'])).toEqual([]);
    expect(await perms('owner', 'emanet', 'o1', ['emanet:partner'])).toHaveLength(3);
    expect(await perms('owner', 'emanet', 'o1', [])).toEqual([]);
  });

  it('report the base role and the roles the permissions came from', async () => {
    const found = await effective(env, { subject: u('auditor'), service: 'emanet', orgId: 'o1' });
    expect(found.baseRole).toBe('auditor');
    expect(found.roles).toEqual(['emanet:viewer']);
  });
});

describe('assignments', () => {
  beforeEach(async () => {
    await org('o1');
    await user('ada');
    await member('o1', 'ada', 'auditor');
    await user('bob');
    await member('o1', 'bob', 'owner');
  });

  it('add a system role to the base role', async () => {
    const result = await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'user', id: 'ada' },
      role: 'emanet:case_manager',
      grantedBy: 'bob',
      reason: 'covers for Bob',
    });
    expect(result.ok).toBe(true);
    expect(await perms('ada', 'emanet', 'o1')).toEqual(['emanet:cases.read', 'emanet:cases.write']);
    expect(
      await check(env, {
        subject: u('ada'),
        action: 'emanet:cases.write',
        orgId: 'o1',
        context: ctx,
      }),
    ).toBe(true);
  });

  it('end when they expire, and are swept daily', async () => {
    await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'user', id: 'ada' },
      role: 'emanet:partner_admin',
      expiresAt: T0 + 5,
      grantedBy: 'bob',
    });
    expect(await perms('ada', 'emanet', 'o1')).toEqual(['emanet:cases.read']);
    await expiredAssignmentsStatement(env.DB, T0 + 10).run();
    expect(await listAssignments(env.DB, 'o1', T0)).toEqual([]);
  });

  it('give nothing while they carry a condition (phase 13e)', async () => {
    await env.DB.prepare(
      `INSERT INTO authz_assignments (id, scope_kind, org_id, principal_kind, principal_id, role, service, condition, granted_at)
       VALUES ('asg_c', 'org', 'o1', 'user', 'ada', 'emanet:partner_admin', 'emanet', '{"aal2Within":300}', ?)`,
    )
      .bind(T0)
      .run();
    expect(await perms('ada', 'emanet', 'o1')).toEqual(['emanet:cases.read']);
  });

  it('come through directory groups, while the person is active in the directory', async () => {
    await user('cem');
    await member('o1', 'cem', 'auditor');
    await group('o1', 'scg_ops', [{ userId: 'ada' }, { userId: 'cem', active: false }]);
    const result = await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'group', id: 'scg_ops' },
      role: 'emanet:partner_admin',
      grantedBy: 'bob',
    });
    expect(result.ok).toBe(true);
    expect(await perms('ada', 'emanet', 'o1')).toHaveLength(3);
    expect(await perms('cem', 'emanet', 'o1')).toEqual(['emanet:cases.read']);
    // Deleting the group ends what it gave.
    await env.DB.prepare("DELETE FROM scim_groups WHERE id = 'scg_ops'").run();
    expect(await perms('ada', 'emanet', 'o1')).toEqual(['emanet:cases.read']);
    expect(await listAssignments(env.DB, 'o1', T0)).toEqual([]);
  });

  it('end when the person leaves the organization or the account is deleted', async () => {
    await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'user', id: 'ada' },
      role: 'emanet:partner_admin',
      grantedBy: 'bob',
    });
    await env.DB.prepare("DELETE FROM org_members WHERE user_id = 'ada'").run();
    expect(await listAssignments(env.DB, 'o1', T0)).toEqual([]);
    await member('o1', 'ada', 'member');
    await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'user', id: 'ada' },
      role: 'emanet:partner_admin',
      grantedBy: 'bob',
    });
    await env.DB.prepare("DELETE FROM users WHERE id = 'ada'").run();
    const { results } = await env.DB.prepare('SELECT id FROM authz_assignments').all();
    expect(results).toEqual([]);
  });

  it('go with the organization', async () => {
    await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'user', id: 'ada' },
      role: 'emanet:partner_admin',
      grantedBy: 'bob',
    });
    await env.DB.prepare("DELETE FROM organizations WHERE id = 'o1'").run();
    const { results } = await env.DB.prepare('SELECT id FROM authz_assignments').all();
    expect(results).toEqual([]);
  });

  it('can be withdrawn, in their own scope only', async () => {
    const result = await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'user', id: 'ada' },
      role: 'emanet:partner_admin',
      grantedBy: 'bob',
    });
    if (!result.ok) throw new Error(result.reason);
    await org('o2');
    expect(await revokeAssignment(env.DB, 'o2', result.assignment.id)).toBeNull();
    expect(await revokeAssignment(env.DB, null, result.assignment.id)).toBeNull();
    expect((await revokeAssignment(env.DB, 'o1', result.assignment.id))?.role).toBe(
      'emanet:partner_admin',
    );
    expect(await perms('ada', 'emanet', 'o1')).toEqual(['emanet:cases.read']);
  });

  it('are refused when the data doesn’t make sense', async () => {
    const give = (over: Partial<Parameters<typeof assignRole>[2]>) =>
      assignRole(env, T0, {
        orgId: 'o1',
        principal: { kind: 'user', id: 'ada' },
        role: 'emanet:partner_admin',
        grantedBy: 'bob',
        ...over,
      });
    expect(await give({ role: 'emanet:nope' })).toEqual({ ok: false, reason: 'unknown_role' });
    expect(await give({ role: 'emanet:staff_admin' })).toEqual({
      ok: false,
      reason: 'wrong_scope',
    });
    // Owners are made as §4.14 says, never through an assignment.
    expect(await give({ role: 'login:owner' })).toEqual({ ok: false, reason: 'not_assignable' });
    expect(await give({ principal: { kind: 'user', id: 'nobody' } })).toEqual({
      ok: false,
      reason: 'unknown_principal',
    });
    expect(await give({ principal: { kind: 'group', id: 'scg_none' } })).toEqual({
      ok: false,
      reason: 'unknown_principal',
    });
    expect(await give({ resource: { type: 'case', id: '1' } })).toEqual({
      ok: false,
      reason: 'invalid_resource',
    });
    expect(await give({ expiresAt: T0 })).toEqual({ ok: false, reason: 'invalid_expiry' });
    expect((await give({})).ok).toBe(true);
    expect(await give({})).toEqual({ ok: false, reason: 'duplicate' });
  });
});

describe('platform assignments (staff)', () => {
  it('go only to staff, and end when the staff role does', async () => {
    await user('ops');
    await user('outsider');
    expect(
      await assignRole(env, T0, {
        orgId: null,
        principal: { kind: 'user', id: 'outsider' },
        role: 'emanet:staff_reviewer',
        grantedBy: 'boss',
      }),
    ).toEqual({ ok: false, reason: 'unknown_principal' });
    await staff('ops', 'support');
    const result = await assignRole(env, T0, {
      orgId: null,
      principal: { kind: 'user', id: 'ops' },
      role: 'emanet:staff_admin',
      grantedBy: 'boss',
    });
    expect(result.ok).toBe(true);
    expect(await perms('ops', 'emanet', null)).toEqual([
      'emanet:control.change',
      'emanet:control.review',
    ]);
    await env.DB.prepare("DELETE FROM staff WHERE user_id = 'ops'").run();
    expect(await perms('ops', 'emanet', null)).toEqual([]);
    expect(await listAssignments(env.DB, null, T0)).toEqual([]);
  });

  it('never give the permissions that make staff', async () => {
    await user('ops');
    await staff('ops', 'admin');
    expect(
      await assignRole(env, T0, {
        orgId: null,
        principal: { kind: 'user', id: 'ops' },
        role: 'login:staff_owner',
        grantedBy: 'boss',
      }),
    ).toEqual({ ok: false, reason: 'not_assignable' });
  });
});

describe('custom roles', () => {
  beforeEach(async () => {
    await org('o1');
    await user('ada');
    await member('o1', 'ada', 'auditor');
  });

  it('hold a chosen set of one service’s permissions', async () => {
    const created = await createCustomRole(env.DB, T0, {
      orgId: 'o1',
      service: 'emanet',
      name: 'Integrations only',
      permissions: ['emanet:integrations.manage', 'emanet:integrations.manage'],
      createdBy: 'ada',
    });
    if (!created.ok) throw new Error(created.reason);
    expect(created.role.permissions).toEqual(['emanet:integrations.manage']);
    await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'user', id: 'ada' },
      role: created.role.id,
      grantedBy: 'bob',
    });
    expect(await perms('ada', 'emanet', 'o1')).toEqual([
      'emanet:cases.read',
      'emanet:integrations.manage',
    ]);

    const updated = await updateCustomRole(env.DB, T0 + 1, {
      orgId: 'o1',
      roleId: created.role.id,
      name: 'Writers',
      permissions: ['emanet:cases.write'],
    });
    expect(updated.ok).toBe(true);
    expect(await perms('ada', 'emanet', 'o1')).toEqual(['emanet:cases.read', 'emanet:cases.write']);

    // Deleting the role ends its assignments.
    expect(await deleteCustomRole(env.DB, 'o1', created.role.id)).toBe(true);
    expect(await listAssignments(env.DB, 'o1', T0)).toEqual([]);
  });

  it('are refused permissions of another service, unknown ones, and the ones that make owners', async () => {
    const make = (permissions: string[], service = 'emanet', name = 'R') =>
      createCustomRole(env.DB, T0, { orgId: 'o1', service, name, permissions, createdBy: 'ada' });
    expect(await make(['login:members.read'])).toEqual({
      ok: false,
      reason: 'invalid_permissions',
    });
    expect(await make(['emanet:cases.delete'])).toEqual({
      ok: false,
      reason: 'invalid_permissions',
    });
    expect(await make([])).toEqual({ ok: false, reason: 'invalid_permissions' });
    expect(await make(['login:owners.manage'], 'login')).toEqual({
      ok: false,
      reason: 'invalid_permissions',
    });
    expect(await make(['emanet:cases.read'], 'nope')).toEqual({
      ok: false,
      reason: 'unknown_service',
    });
    expect(await make(['emanet:cases.read'], 'emanet', 'see https://x.com')).toEqual({
      ok: false,
      reason: 'invalid_name',
    });
    expect((await make(['emanet:cases.read'], 'emanet', 'Readers')).ok).toBe(true);
    expect(await make(['emanet:cases.read'], 'emanet', 'readers')).toEqual({
      ok: false,
      reason: 'duplicate',
    });
  });

  it('are another organization’s to nobody', async () => {
    await org('o2');
    const created = await createCustomRole(env.DB, T0, {
      orgId: 'o2',
      service: 'emanet',
      name: 'Theirs',
      permissions: ['emanet:integrations.manage'],
      createdBy: 'ada',
    });
    if (!created.ok) throw new Error(created.reason);
    expect(
      await assignRole(env, T0, {
        orgId: 'o1',
        principal: { kind: 'user', id: 'ada' },
        role: created.role.id,
        grantedBy: 'x',
      }),
    ).toEqual({ ok: false, reason: 'unknown_role' });
    // Even a row written by hand gives nothing across organizations.
    await env.DB.prepare(
      `INSERT INTO authz_assignments (id, scope_kind, org_id, principal_kind, principal_id, role, service, granted_at)
       VALUES ('asg_x', 'org', 'o1', 'user', 'ada', ?, 'emanet', ?)`,
    )
      .bind(created.role.id, T0)
      .run();
    expect(await perms('ada', 'emanet', 'o1')).toEqual(['emanet:cases.read']);
  });

  it('are limited per organization', async () => {
    for (let i = 0; i < MAX_CUSTOM_ROLES; i++) {
      const r = await createCustomRole(env.DB, T0, {
        orgId: 'o1',
        service: 'emanet',
        name: `Role ${String(i)}`,
        permissions: ['emanet:cases.read'],
        createdBy: 'ada',
      });
      expect(r.ok).toBe(true);
    }
    expect(
      await createCustomRole(env.DB, T0, {
        orgId: 'o1',
        service: 'emanet',
        name: 'One more',
        permissions: ['emanet:cases.read'],
        createdBy: 'ada',
      }),
    ).toEqual({ ok: false, reason: 'too_many' });
  });
});

describe('resources', () => {
  it('a role held for one resource covers only that one', async () => {
    await org('o1');
    await user('ada');
    await member('o1', 'ada', 'auditor');
    await env.DB.prepare(
      `INSERT INTO authz_assignments (id, scope_kind, org_id, resource, principal_kind, principal_id, role, service, granted_at)
       VALUES ('asg_r', 'org', 'o1', 'case:42', 'user', 'ada', 'emanet:case_manager', 'emanet', ?)`,
    )
      .bind(T0)
      .run();
    const q = (id: string) =>
      check(env, {
        subject: u('ada'),
        action: 'emanet:cases.write',
        orgId: 'o1',
        resource: { type: 'case', id },
        context: ctx,
      });
    expect(await q('42')).toBe(true);
    expect(await q('43')).toBe(false);
    expect(await check(env, { subject: u('ada'), action: 'emanet:cases.write', orgId: 'o1' })).toBe(
      false,
    );
  });
});

describe('questions the engine refuses', () => {
  it('throws on a permission or service nobody declared', async () => {
    await expect(
      check(env, { subject: u('x'), action: 'emanet:cases.delete', orgId: 'o1' }),
    ).rejects.toBeInstanceOf(AuthzError);
    await expect(
      effective(env, { subject: u('x'), service: 'promptshare', orgId: null }),
    ).rejects.toBeInstanceOf(AuthzError);
  });

  it('gives an unknown service account nothing', async () => {
    const found = await effective(env, {
      subject: { type: 'service_account', id: 'sa_1' },
      service: 'emanet',
      orgId: 'o1',
    });
    expect([...found.permissions]).toEqual([]);
  });
});

describe('subjectsWith', () => {
  it('lists who holds a permission: defaults, direct assignments and groups', async () => {
    await org('o1');
    for (const [id, role] of [
      ['own', 'owner'],
      ['adm', 'admin'],
      ['aud', 'auditor'],
      ['mem', 'member'],
      ['grp', 'auditor'],
      ['off', 'admin'],
    ] as const) {
      await user(id, id === 'off' ? 'suspended' : 'active');
      await member('o1', id, role);
    }
    await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'user', id: 'mem' },
      role: 'emanet:partner_admin',
      grantedBy: 'own',
    });
    await group('o1', 'scg_g', [{ userId: 'grp' }]);
    const custom = await createCustomRole(env.DB, T0, {
      orgId: 'o1',
      service: 'emanet',
      name: 'Integrations',
      permissions: ['emanet:integrations.manage'],
      createdBy: 'own',
    });
    if (!custom.ok) throw new Error(custom.reason);
    await assignRole(env, T0, {
      orgId: 'o1',
      principal: { kind: 'group', id: 'scg_g' },
      role: custom.role.id,
      grantedBy: 'own',
    });
    const holders = await subjectsWith(env, {
      action: 'emanet:integrations.manage',
      orgId: 'o1',
      context: ctx,
    });
    expect(holders.map((s) => s.id)).toEqual(['adm', 'grp', 'mem', 'own']);
  });
});
