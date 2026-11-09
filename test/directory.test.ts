import { env, exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { normaliseEmail } from '../src/directory';
import { resetDatabase } from './helpers';

/** Prompt share's lookup by email (DESIGN §4.8), called on the real named entrypoint. */

async function user(id: string, email: string, verified = 1, status = 'active') {
  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO users (id, status, primary_email, created_at, updated_at) VALUES (?, ?, ?, 0, 0)',
    ).bind(id, status, email),
    env.DB.prepare(
      `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
       VALUES (?, ?, 'google', ?, ?, ?, 0, 0)`,
    ).bind(`i-${id}`, id, `sub-${id}`, email, verified),
  ]);
}

describe('PromptshareDirectory.uidForEmail', () => {
  beforeEach(resetDatabase);

  it('finds an active account by its verified address, ignoring case and spaces', async () => {
    await user('u1', 'Ada@Example.com');
    expect(await exports.PromptshareDirectory.uidForEmail('  ada@example.COM ')).toBe('u1');
  });

  it('answers none for unknown, unverified, suspended or ambiguous addresses', async () => {
    await user('u2', 'unverified@example.com', 0);
    await user('u3', 'suspended@example.com', 1, 'suspended');
    await user('u4', 'twice@example.com');
    await user('u5', 'twice@example.com');
    for (const email of [
      'nobody@example.com',
      'unverified@example.com',
      'suspended@example.com',
      'twice@example.com',
      'not an address',
      '%@example.com',
    ]) {
      expect(await exports.PromptshareDirectory.uidForEmail(email)).toBeNull();
    }
  });

  it('treats LIKE wildcards literally', async () => {
    await user('u6', 'a_b@example.com');
    expect(await exports.PromptshareDirectory.uidForEmail('axb@example.com')).toBeNull();
  });
});

describe('normaliseEmail', () => {
  it('accepts one address and rejects anything else', () => {
    expect(normaliseEmail(' X@Y.de ')).toBe('x@y.de');
    expect(normaliseEmail('a@b')).toBeNull();
    expect(normaliseEmail('a b@c.de')).toBeNull();
    expect(normaliseEmail('a@b@c.de')).toBeNull();
    expect(normaliseEmail(`${'a'.repeat(250)}@b.de`)).toBeNull();
  });
});
