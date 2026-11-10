/**
 * Settings the owner changes on /admin without a deploy (migration 0007).
 *
 * Sign-up (DESIGN D9, §4.9): 'open' lets anyone create an account; 'invite' admits only invited
 * Google accounts and addresses. Without a saved setting, LOGIN_LOCKED decides.
 */
export type SignupMode = 'open' | 'invite';

export async function signupMode(env: Env): Promise<SignupMode> {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'signup'").first<{
    value: string;
  }>();
  if (row?.value === 'open' || row?.value === 'invite') return row.value;
  const locked: string = env.LOGIN_LOCKED;
  return locked === 'false' ? 'open' : 'invite';
}

export async function setSignupMode(db: D1Database, now: number, mode: SignupMode) {
  await db
    .prepare(
      `INSERT INTO settings (key, value, updated_at) VALUES ('signup', ?, ?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
    .bind(mode, now)
    .run();
}
