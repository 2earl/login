import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';

const NOW = 1_762_600_000;

async function insertUser(id: string): Promise<void> {
  await env.DB.prepare('INSERT INTO users (id, created_at, updated_at) VALUES (?, ?, ?)')
    .bind(id, NOW, NOW)
    .run();
}

async function insertIdentity(id: string, userId: string, subject: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO identities (id, user_id, provider, subject, email, email_verified, created_at, last_login_at)
     VALUES (?, ?, 'google', ?, 'a@example.com', 1, ?, ?)`,
  )
    .bind(id, userId, subject, NOW, NOW)
    .run();
}

describe('schema (migrations/0001_initial.sql)', () => {
  beforeEach(async () => {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM identities'),
      env.DB.prepare('DELETE FROM sessions'),
      env.DB.prepare('DELETE FROM users'),
    ]);
  });

  it('creates every table in the design', async () => {
    const { results } = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    ).all<{ name: string }>();
    const names = results.map((r) => r.name);
    for (const table of [
      'allowlist',
      'audit_events',
      'identities',
      'login_tx',
      'sessions',
      'trusted_clients',
      'users',
    ]) {
      expect(names).toContain(table);
    }
  });

  it('allows one account per Google subject', async () => {
    await insertUser('u1');
    await insertUser('u2');
    await insertIdentity('i1', 'u1', 'google-sub-1');
    await expect(insertIdentity('i2', 'u2', 'google-sub-1')).rejects.toThrow(/UNIQUE/);
  });

  it('allows two accounts with the same email but different subjects', async () => {
    // Users are keyed on subject, never on email (THREAT_MODEL B3).
    await insertUser('u1');
    await insertUser('u2');
    await insertIdentity('i1', 'u1', 'google-sub-1');
    await insertIdentity('i2', 'u2', 'google-sub-2');
    const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM identities').first<{ n: number }>();
    expect(row?.n).toBe(2);
  });

  it('deletes identities and sessions with the user', async () => {
    await insertUser('u1');
    await insertIdentity('i1', 'u1', 'google-sub-1');
    await env.DB.prepare(
      'INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?)',
    )
      .bind('h1', 'u1', NOW, NOW, NOW + 3600)
      .run();

    await env.DB.prepare('DELETE FROM users WHERE id = ?').bind('u1').run();

    const identities = await env.DB.prepare('SELECT COUNT(*) AS n FROM identities').first<{
      n: number;
    }>();
    const sessions = await env.DB.prepare('SELECT COUNT(*) AS n FROM sessions').first<{
      n: number;
    }>();
    expect(identities?.n).toBe(0);
    expect(sessions?.n).toBe(0);
  });

  it('rejects values outside the allowed sets', async () => {
    await expect(
      env.DB.prepare(
        "INSERT INTO users (id, status, created_at, updated_at) VALUES ('u3', 'admin', ?, ?)",
      )
        .bind(NOW, NOW)
        .run(),
    ).rejects.toThrow(/CHECK/);
  });

  it('is STRICT: rejects a text value in an integer column', async () => {
    await expect(
      env.DB.prepare("INSERT INTO users (id, created_at, updated_at) VALUES ('u4', 'yesterday', ?)")
        .bind(NOW)
        .run(),
    ).rejects.toThrow();
  });
});
