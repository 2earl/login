import { env } from 'cloudflare:workers';
import { hmacHex } from '../src/crypto';

/**
 * Makes the account behind a session cookie 2earl staff (DESIGN §4.29). Only staff owners and
 * admins create organizations, so tests that need one call this first.
 */
export async function makeStaff(
  session: string,
  role: 'admin' | 'support' = 'admin',
): Promise<void> {
  const idHash = await hmacHex(env.SESSION_PEPPER, `session:${session}`);
  const result = await env.DB.prepare(
    `INSERT INTO staff (user_id, role, granted_by, granted_at)
     SELECT user_id, ?, NULL, 0 FROM sessions WHERE id_hash = ?
     ON CONFLICT (user_id) DO UPDATE SET role = excluded.role`,
  )
    .bind(role, idHash)
    .run();
  if (result.meta.changes === 0) throw new Error('makeStaff: no such session');
}
