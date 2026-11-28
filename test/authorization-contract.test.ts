import { env, exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { assignRole } from '../src/authz/store';
import { T0, member, org, owner, resetAuthz, staff, user } from './authz-fixtures';

/**
 * The Authorization entrypoint (DESIGN §4.34), called the way an app's Service Binding calls it:
 * through the Worker's real export, with the app's service ID as props.
 */
const as = (service: string) => exports.Authorization({ props: { service } });
const emanet = () => as('emanet');
const ada = { type: 'user' as const, id: 'ada' };

/** The error message of an RPC call that should fail. Handled on the RPC promise itself:
 * Vitest's `.rejects` leaves the runtime reporting it. */
const failure = (call: Promise<unknown>) =>
  call.then(
    () => 'resolved',
    (error: unknown) => (error instanceof Error ? error.message : 'non-error'),
  );

beforeEach(async () => {
  await resetAuthz();
  await org('org_one');
  await user('ada');
  await member('org_one', 'ada', 'auditor');
});

describe('Authorization.check', () => {
  it('answers from the base role and assignments, live', async () => {
    expect(
      await emanet().check({ subject: ada, action: 'emanet:cases.read', orgId: 'org_one' }),
    ).toEqual({ decision: true });
    expect(
      await emanet().check({ subject: ada, action: 'emanet:cases.write', orgId: 'org_one' }),
    ).toEqual({ decision: false });
    await assignRole(env, T0, {
      orgId: 'org_one',
      principal: { kind: 'user', id: 'ada' },
      role: 'emanet:case_manager',
      grantedBy: 'ada',
    });
    expect(
      await emanet().check({ subject: ada, action: 'emanet:cases.write', orgId: 'org_one' }),
    ).toEqual({ decision: true });
  });

  it('limits the answer to the token’s scopes', async () => {
    expect(
      await emanet().check({
        subject: ada,
        action: 'emanet:cases.read',
        orgId: 'org_one',
        context: { scopes: ['emanet:field'] },
      }),
    ).toEqual({ decision: false });
  });

  it('answers false for people who aren’t members and for accounts that don’t exist', async () => {
    for (const id of ['nobody', 'ada']) {
      expect(
        await emanet().check({
          subject: { type: 'user', id },
          action: 'emanet:cases.read',
          orgId: id === 'ada' ? 'org_two' : 'org_one',
        }),
      ).toEqual({ decision: false });
    }
  });

  it('throws on another service’s permission, an unknown one, or a malformed question', async () => {
    const bad = [
      { subject: ada, action: 'login:members.read', orgId: 'org_one' },
      { subject: ada, action: 'emanet:cases.delete', orgId: 'org_one' },
      { subject: { type: 'robot', id: 'x' }, action: 'emanet:cases.read' },
      { subject: ada, action: 'emanet:cases.read', orgId: 'o1' },
      { subject: ada, action: 'emanet:cases.read', context: { scopes: 'emanet:partner' } },
    ];
    for (const query of bad) {
      expect(await failure(emanet().check(query as never)), JSON.stringify(query)).not.toBe(
        'resolved',
      );
    }
  });

  it('refuses a binding without a known service', async () => {
    expect(
      await failure(as('promptshare').check({ subject: ada, action: 'emanet:cases.read' })),
    ).toMatch(/props/);
    expect(
      await failure(exports.Authorization.check({ subject: ada, action: 'emanet:cases.read' })),
    ).toMatch(/props/);
  });
});

describe('Authorization.checkMany', () => {
  it('answers in order, at most 50', async () => {
    expect(
      await emanet().checkMany({
        subject: ada,
        orgId: 'org_one',
        evaluations: [{ action: 'emanet:cases.write' }, { action: 'emanet:cases.read' }],
      }),
    ).toEqual([{ decision: false }, { decision: true }]);
    expect(
      await failure(
        emanet().checkMany({
          subject: ada,
          evaluations: Array.from({ length: 51 }, () => ({ action: 'emanet:cases.read' })),
        }),
      ),
    ).toMatch(/up to 50/);
  });
});

describe('Authorization.permissionsOf', () => {
  it('lists the calling service’s permissions, roles and base role', async () => {
    expect(await emanet().permissionsOf({ subject: ada, orgId: 'org_one' })).toEqual({
      permissions: ['emanet:cases.read'],
      scoped: {},
      roles: ['emanet:viewer'],
      baseRole: 'auditor',
    });
  });

  it('answers staff permissions across 2earl without an organization', async () => {
    await owner('boss');
    await user('help');
    await staff('help', 'support');
    expect(
      (await emanet().permissionsOf({ subject: { type: 'user', id: 'boss' } })).permissions,
    ).toEqual(['emanet:control.change', 'emanet:control.review']);
    expect(
      (await emanet().permissionsOf({ subject: { type: 'user', id: 'help' } })).permissions,
    ).toEqual(['emanet:control.review']);
    expect((await emanet().permissionsOf({ subject: ada })).permissions).toEqual([]);
  });
});

describe('Authorization.subjectsWith', () => {
  it('lists who holds a permission in an organization', async () => {
    await user('bob');
    await member('org_one', 'bob', 'admin');
    expect(
      await emanet().subjectsWith({ action: 'emanet:integrations.manage', orgId: 'org_one' }),
    ).toEqual([{ type: 'user', id: 'bob' }]);
    expect(
      await failure(emanet().subjectsWith({ action: 'emanet:integrations.manage' } as never)),
    ).toMatch(/orgId/);
  });
});
