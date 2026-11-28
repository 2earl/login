import { describe, expect, it } from 'vitest';
import { NEVER_ASSIGNABLE } from '../src/authz/login-manifest';
import { PERMISSION_PATTERN, SYSTEM_ROLE_PATTERN, serviceOf } from '../src/authz/types';
import { translate } from '../src/i18n';
import { AUTHZ_SERVICES, authzOf, permissionExists, systemRole } from '../src/services';

/** DESIGN §4.32: every service's permissions and roles are consistent and translated. */
describe('authorization manifests', () => {
  it('lists login, Emanet and KYC', () => {
    expect(AUTHZ_SERVICES.map((s) => s.id)).toEqual(['login', 'emanet', 'kyc']);
  });

  for (const service of AUTHZ_SERVICES) {
    const { authz } = service;
    describe(service.id, () => {
      it('names every permission <service>:<object>.<action>', () => {
        const permissions = Object.keys(authz.permissions);
        expect(permissions.length).toBeGreaterThan(0);
        for (const permission of permissions) {
          expect(permission).toMatch(PERMISSION_PATTERN);
          expect(serviceOf(permission)).toBe(service.id);
        }
      });

      it('builds roles only from its own permissions', () => {
        for (const [id, role] of Object.entries(authz.roles)) {
          expect(id).toMatch(SYSTEM_ROLE_PATTERN);
          expect(serviceOf(id)).toBe(service.id);
          expect(role.permissions.length).toBeGreaterThan(0);
          expect(new Set(role.permissions).size).toBe(role.permissions.length);
          for (const permission of role.permissions) {
            expect(authz.permissions, `${id} → ${permission}`).toHaveProperty([permission]);
          }
        }
      });

      it('defaults to roles that exist, held where they can be', () => {
        for (const role of Object.values(authz.orgDefaults ?? {})) {
          expect(authz.roles[role]?.assignable, role).toBe('org');
        }
        for (const role of Object.values(authz.staffDefaults ?? {})) {
          expect(authz.roles[role]?.assignable, role).toBe('platform');
        }
        for (const [a, b] of authz.exclusive ?? []) {
          expect(authz.roles).toHaveProperty([a]);
          expect(authz.roles).toHaveProperty([b]);
        }
      });

      it('lets only its own scopes carry only its own permissions', () => {
        for (const [scope, grants] of Object.entries(authz.scopeGrants)) {
          expect(service.scopes, scope).toHaveProperty([scope]);
          if (grants === '*') continue;
          for (const permission of grants) expect(permissionExists(permission)).toBe(true);
        }
      });

      it('has Turkish for every permission and role name', () => {
        const texts = [
          ...Object.values(authz.permissions),
          ...Object.values(authz.roles).map((r) => r.name),
        ];
        for (const text of texts) expect(translate(text, 'tr'), text).not.toBe(text);
      });
    });
  }

  it('finds roles and permissions by name, and nothing else', () => {
    expect(systemRole('emanet:viewer')?.permissions).toEqual(['emanet:cases.read']);
    expect(systemRole('login:owner')?.privileged).toBe(true);
    expect(systemRole('emanet:nope')).toBeUndefined();
    expect(systemRole('nope')).toBeUndefined();
    expect(permissionExists('emanet:cases.write')).toBe(true);
    expect(permissionExists('emanet:cases.delete')).toBe(false);
    expect(permissionExists('mcp:tools.read')).toBe(false);
    expect(authzOf('promptshare')).toBeUndefined();
  });

  it('keeps the permissions that make owners and staff out of every assignable role', () => {
    for (const permission of NEVER_ASSIGNABLE) expect(permissionExists(permission)).toBe(true);
    for (const service of AUTHZ_SERVICES) {
      for (const [id, role] of Object.entries(service.authz.roles)) {
        if (!role.permissions.some((p) => NEVER_ASSIGNABLE.has(p))) continue;
        // Only the base roles hold them, and those are privileged.
        expect(role.privileged, id).toBe(true);
      }
    }
  });
});
