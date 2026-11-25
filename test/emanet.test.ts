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
