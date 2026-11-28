import { describe, expect, it } from 'vitest';
import {
  ORG_ROLES,
  canInvite,
  canManageOrganization,
  canRemove,
  canSeeActivity,
  canSetRole,
  type OrgRole,
} from '../src/orgs';
import { staffCan, type StaffRole } from '../src/staff';

/**
 * login's own rules moved onto its manifest (DESIGN §4.32). The inputs are closed sets of roles,
 * so every combination is compared with the rules as they were written before phase 13: these
 * reference functions are those rules, copied unchanged from src/orgs.ts and src/staff.ts.
 */
const before = {
  canInvite: (actor: OrgRole) => actor === 'owner' || actor === 'admin',
  canSeeActivity: (actor: OrgRole) => actor !== 'member',
  canSetRole(actor: OrgRole, target: OrgRole, next: OrgRole) {
    if (actor === 'owner') return true;
    if (actor === 'admin') return target !== 'owner' && next !== 'owner';
    return false;
  },
  canRemove: (actor: OrgRole, target: OrgRole) =>
    actor === 'owner' || (actor === 'admin' && target !== 'owner'),
  canManageOrganization: (actor: OrgRole) => actor === 'owner',
};

const runs = (role: StaffRole) => role === 'owner' || role === 'admin';
const anyStaff = () => true;
const staffBefore = {
  view: anyStaff,
  manageUsers: runs,
  signOutUsers: anyStaff,
  manageSignUp: runs,
  manageOrgs: runs,
  createOrgs: runs,
  resendOrgInvitations: anyStaff,
  manageApps: runs,
  manageStaff: (role: StaffRole) => role === 'owner',
  actOn: (role: StaffRole, target: StaffRole | null) =>
    target === 'owner' ? false : target === null ? true : role === 'owner',
};

const STAFF_ROLES: readonly StaffRole[] = ['owner', 'admin', 'support'];

describe('organization roles (DESIGN §4.14, §4.28) on the manifest', () => {
  it('answer every combination as before', () => {
    let compared = 0;
    for (const actor of ORG_ROLES) {
      expect(canInvite(actor), `canInvite ${actor}`).toBe(before.canInvite(actor));
      expect(canSeeActivity(actor), `canSeeActivity ${actor}`).toBe(before.canSeeActivity(actor));
      expect(canManageOrganization(actor), `canManageOrganization ${actor}`).toBe(
        before.canManageOrganization(actor),
      );
      for (const target of ORG_ROLES) {
        expect(canRemove(actor, target), `canRemove ${actor} ${target}`).toBe(
          before.canRemove(actor, target),
        );
        for (const next of ORG_ROLES) {
          expect(canSetRole(actor, target, next), `canSetRole ${actor} ${target} ${next}`).toBe(
            before.canSetRole(actor, target, next),
          );
          compared++;
        }
      }
    }
    expect(compared).toBe(64);
  });
});

describe('staff roles (DESIGN §4.29) on the manifest', () => {
  it('answer every combination as before', () => {
    for (const role of STAFF_ROLES) {
      for (const key of Object.keys(staffBefore) as (keyof typeof staffBefore)[]) {
        if (key === 'actOn') {
          for (const target of [...STAFF_ROLES, null]) {
            expect(staffCan.actOn(role, target), `actOn ${role} ${String(target)}`).toBe(
              staffBefore.actOn(role, target),
            );
          }
        } else {
          expect(staffCan[key](role), `${key} ${role}`).toBe(staffBefore[key](role));
        }
      }
    }
  });
});
