import { env, exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { allResources, scopesFor, serviceForResource } from '../src/services';
import { resetDatabase } from './helpers';

/** Emanet's three apps as login sees them (src/services.ts), and its staff lookup. */

describe('Emanet in the service registry', () => {
  it('gives each app its own resource and scope', () => {
    const resources = allResources(env);
    for (const resource of [
      env.EMANET_KURUMSAL_RESOURCE,
      env.EMANET_SAHA_RESOURCE,
      env.EMANET_MERKEZ_RESOURCE,
    ]) {
      expect(resources).toContain(resource);
    }
    const saha = serviceForResource(env, env.EMANET_SAHA_RESOURCE);
    expect(saha?.name).toBe('Emanet Saha');
    // A token for the agents' app carries only the agents' scope.
    expect(
      scopesFor(saha ?? { id: '', name: '', resource: () => '', scopes: {}, deletionBinding: '' }, [
        'emanet:field',
        'emanet:control',
        'emanet:partner',
      ]),
    ).toEqual(['emanet:field']);
    const merkez = serviceForResource(env, env.EMANET_MERKEZ_RESOURCE);
    expect(Object.keys(merkez?.scopes ?? {})).toEqual(['emanet:control']);
    expect(serviceForResource(env, env.EMANET_KURUMSAL_RESOURCE)?.deletionBinding).toBe(
      'EMANET_EVENTS',
    );
  });
});

describe('StaffDirectory.roleOf', () => {
  beforeEach(resetDatabase);

  async function user(id: string, status = 'active') {
    await env.DB.prepare(
      'INSERT INTO users (id, status, created_at, updated_at) VALUES (?, ?, 0, 0)',
    )
      .bind(id, status)
      .run();
  }

  it('answers the staff role, read live, and nothing for everyone else', async () => {
    await user('s-admin');
    await user('s-support');
    await user('s-suspended', 'suspended');
    await user('plain');
    await env.DB.batch(
      [
        ['s-admin', 'admin'],
        ['s-support', 'support'],
        ['s-suspended', 'admin'],
      ].map(([id, role]) =>
        env.DB.prepare(
          'INSERT INTO staff (user_id, role, granted_by, granted_at) VALUES (?, ?, NULL, 0)',
        ).bind(id, role),
      ),
    );
    const directory = exports.StaffDirectory;
    expect(await directory.roleOf('s-admin')).toBe('admin');
    expect(await directory.roleOf('s-support')).toBe('support');
    expect(await directory.roleOf('s-suspended')).toBeNull();
    expect(await directory.roleOf('plain')).toBeNull();
    expect(await directory.roleOf('nobody')).toBeNull();
    await env.DB.prepare("DELETE FROM staff WHERE user_id = 's-admin'").run();
    expect(await directory.roleOf('s-admin')).toBeNull();
  });
});

describe('OrganizationProvisioning', () => {
  beforeEach(resetDatabase);

  async function user(id: string, email: string, status = 'active') {
    await env.DB.prepare(
      'INSERT INTO users (id, status, primary_email, created_at, updated_at) VALUES (?, ?, ?, 0, 0)',
    )
      .bind(id, status, email)
      .run();
  }

  it('creates the organization for the invited address, from a staff invitation only', async () => {
    await user('staff-1', 'staff@2earl.example');
    await env.DB.prepare(
      "INSERT INTO staff (user_id, role, granted_by, granted_at) VALUES ('staff-1', 'admin', NULL, 0)",
    ).run();
    await user('contact', 'Ops@Bank.example');
    await user('gone', 'gone@bank.example', 'suspended');
    const provisioning = exports.OrganizationProvisioning;
    const request = {
      ownerId: 'contact',
      email: 'ops@bank.example',
      name: 'Örnek Bank A.Ş.',
      invitedBy: 'staff-1',
      service: 'emanet',
    };
    expect(await provisioning.hasAddress('contact', 'ops@bank.example')).toBe(true);
    expect(await provisioning.hasAddress('contact', 'other@bank.example')).toBe(false);
    expect(await provisioning.create({ ...request, email: 'other@bank.example' })).toEqual({
      ok: false,
      reason: 'wrong_address',
    });
    expect(await provisioning.create({ ...request, invitedBy: 'contact' })).toEqual({
      ok: false,
      reason: 'not_staff',
    });
    expect(
      await provisioning.create({ ...request, ownerId: 'gone', email: 'gone@bank.example' }),
    ).toEqual({
      ok: false,
      reason: 'no_account',
    });
    expect(await provisioning.create({ ...request, name: '  ' })).toEqual({
      ok: false,
      reason: 'invalid_name',
    });
    const created = await provisioning.create(request);
    expect(created.ok).toBe(true);
    const orgId = created.ok ? created.orgId : '';
    const member = await env.DB.prepare(
      'SELECT o.name, m.role FROM organizations o JOIN org_members m ON m.org_id = o.id WHERE o.id = ?',
    )
      .bind(orgId)
      .first<{ name: string; role: string }>();
    expect(member).toEqual({ name: 'Örnek Bank A.Ş.', role: 'owner' });
    const event = await env.DB.prepare(
      "SELECT actor_user_id, detail FROM audit_events WHERE event = 'org.created'",
    ).first<{ actor_user_id: string; detail: string }>();
    expect(event?.actor_user_id).toBe('contact');
    expect(JSON.parse(event?.detail ?? '{}')).toMatchObject({
      org: orgId,
      via: 'emanet',
      invited_by: 'staff-1',
    });
  });
});
