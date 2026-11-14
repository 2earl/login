import { hmacHex, randomToken } from './crypto';
import { SSO_REQUIRED_SQL } from './managed';
import { methodAllowed, policyFromRow, type SessionPolicy } from './org-policy';

/** DESIGN §7: 12 h idle, 7 days absolute. */
export const SESSION_IDLE_SECONDS = 12 * 60 * 60;
export const SESSION_ABSOLUTE_SECONDS = 7 * 24 * 60 * 60;
/** last_seen_at is written at most this often, to avoid a database write on every request. */
const TOUCH_INTERVAL_SECONDS = 5 * 60;

export interface SessionUser {
  id: string;
  displayName: string | null;
  primaryEmail: string | null;
  createdAt: number;
  /** The organization that manages the account (DESIGN §4.18). */
  managedBy: string | null;
  /**
   * An organization now manages a domain where the account has an address: the person must
   * choose before going on (`/account/managed`).
   */
  mustChoose: boolean;
  /** The managing organization's security rules (DESIGN §4.19), if it set any. */
  policy: SessionPolicy | null;
}

export interface Session {
  idHash: string;
  /** aal2 once a second factor was verified in this session (DESIGN §4.7). */
  aal: 'aal1' | 'aal2';
  aal2At: number | null;
  /** Whether the user has enrolled a second factor. */
  hasFactor: boolean;
  /** A passkey is among the second factors. */
  hasPasskey: boolean;
  /** How this session signed in (null for sessions from before phase 8a). */
  method: SignInMethod | null;
  createdAt: number;
  expiresAt: number;
  user: SessionUser;
}

export type SignInMethod = 'google' | 'email' | 'passkey' | 'saml';

export interface SessionMeta {
  ipPrefix: string | null;
  userAgentHash: string | null;
  /** A coarse device name (src/devices.ts). */
  device?: string | null;
  method?: SignInMethod | null;
  /**
   * A passkey with user verification is phishing-resistant and two factors in one: the session
   * starts at aal2 (DESIGN §4.10).
   */
  aal2?: boolean;
}

async function hashSessionId(pepper: string, cookieValue: string): Promise<string> {
  return hmacHex(pepper, `session:${cookieValue}`);
}

export async function createSession(
  db: D1Database,
  pepper: string,
  now: number,
  userId: string,
  meta: SessionMeta,
): Promise<{ cookieValue: string; expiresAt: number }> {
  const cookieValue = randomToken(32);
  const expiresAt = now + SESSION_ABSOLUTE_SECONDS;
  await db
    .prepare(
      `INSERT INTO sessions (id_hash, user_id, aal, aal2_at, created_at, last_seen_at, expires_at,
                             ip_prefix, user_agent_hash, device, method)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      await hashSessionId(pepper, cookieValue),
      userId,
      meta.aal2 ? 'aal2' : 'aal1',
      meta.aal2 ? now : null,
      now,
      now,
      expiresAt,
      meta.ipPrefix,
      meta.userAgentHash,
      meta.device ?? null,
      meta.method ?? null,
    )
    .run();
  return { cookieValue, expiresAt };
}

/** Returns the active session for this cookie, or null. Expired sessions are deleted. */
export async function getSession(
  db: D1Database,
  pepper: string,
  now: number,
  cookieValue: string | undefined,
): Promise<Session | null> {
  if (!cookieValue) return null;
  const idHash = await hashSessionId(pepper, cookieValue);

  const row = await db
    .prepare(
      `SELECT s.aal, s.aal2_at, s.method, s.created_at, s.last_seen_at, s.expires_at,
              u.id AS user_id, u.status, u.display_name, u.primary_email, u.created_at AS user_created_at,
              u.managed_by,
              EXISTS (SELECT 1 FROM mfa_factors f WHERE f.user_id = u.id) AS has_factor,
              EXISTS (SELECT 1 FROM mfa_factors f WHERE f.user_id = u.id AND f.kind = 'webauthn') AS has_passkey,
              -- The managing organization's rules (DESIGN §4.19); owners are exempt from some.
              p.require_factor, p.passkeys_only, p.session_hours, p.methods, p.ip_ranges,
              po.name AS policy_org_name,
              EXISTS (SELECT 1 FROM org_members m
                      WHERE m.org_id = u.managed_by AND m.user_id = u.id AND m.role = 'owner') AS policy_exempt,
              -- Required SSO (DESIGN §4.18): a session started another way ends.
              (s.method IS NOT 'saml' AND ${SSO_REQUIRED_SQL}) AS sso_violation,
              EXISTS (SELECT 1 FROM identities i
                      JOIN org_domains d ON d.managed_at IS NOT NULL AND d.verified_at IS NOT NULL
                        AND d.domain = substr(i.email, instr(i.email, '@') + 1) COLLATE NOCASE
                      JOIN organizations o ON o.id = d.org_id AND o.status = 'active'
                      WHERE i.user_id = u.id AND i.email_verified = 1
                        AND d.org_id IS NOT u.managed_by) AS must_choose
       FROM sessions s JOIN users u ON u.id = s.user_id
       LEFT JOIN organizations po ON po.id = u.managed_by AND po.status = 'active'
       LEFT JOIN org_policies p ON p.org_id = po.id
       WHERE s.id_hash = ?`,
    )
    .bind(idHash)
    .first<{
      aal: 'aal1' | 'aal2';
      aal2_at: number | null;
      method: SignInMethod | null;
      has_factor: number;
      has_passkey: number;
      require_factor: number | null;
      passkeys_only: number | null;
      session_hours: number | null;
      methods: string | null;
      ip_ranges: string | null;
      policy_org_name: string | null;
      policy_exempt: number;
      created_at: number;
      last_seen_at: number;
      expires_at: number;
      user_id: string;
      status: string;
      display_name: string | null;
      primary_email: string | null;
      user_created_at: number;
      managed_by: string | null;
      sso_violation: number;
      must_choose: number;
    }>();
  if (!row) return null;

  const policy: SessionPolicy | null =
    row.methods !== null && row.managed_by !== null && row.policy_org_name !== null
      ? {
          ...policyFromRow({
            require_factor: row.require_factor ?? 0,
            passkeys_only: row.passkeys_only ?? 0,
            session_hours: row.session_hours,
            methods: row.methods,
            ip_ranges: row.ip_ranges ?? '',
          }),
          orgId: row.managed_by,
          orgName: row.policy_org_name,
          exempt: row.policy_exempt === 1,
        }
      : null;
  const expired =
    row.expires_at <= now ||
    row.last_seen_at + SESSION_IDLE_SECONDS <= now ||
    // The organization's session length (DESIGN §4.19), counted from sign-in.
    (policy?.sessionHours != null && row.created_at + policy.sessionHours * 3600 <= now);
  if (
    expired ||
    row.status !== 'active' ||
    row.sso_violation === 1 ||
    (policy !== null && !methodAllowed(policy, row.method))
  ) {
    await db.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(idHash).run();
    return null;
  }

  if (now - row.last_seen_at >= TOUCH_INTERVAL_SECONDS) {
    await db
      .prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?')
      .bind(now, idHash)
      .run();
  }

  return {
    idHash,
    aal: row.aal,
    aal2At: row.aal2_at,
    hasFactor: row.has_factor === 1,
    hasPasskey: row.has_passkey === 1,
    method: row.method,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    user: {
      id: row.user_id,
      displayName: row.display_name,
      primaryEmail: row.primary_email,
      createdAt: row.user_created_at,
      managedBy: row.managed_by,
      mustChoose: row.must_choose === 1,
      policy,
    },
  };
}

export async function deleteSession(db: D1Database, idHash: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(idHash).run();
}

// ---- Signed-in devices (DESIGN §7) ------------------------------------------------------------

export interface DeviceSession {
  /** An identifier for this list only: not the session's key, and useless as a cookie. */
  ref: string;
  device: string | null;
  method: SignInMethod | null;
  createdAt: number;
  lastSeenAt: number;
  current: boolean;
}

async function sessionRef(pepper: string, idHash: string): Promise<string> {
  return (await hmacHex(pepper, `session-ref:${idHash}`)).slice(0, 24);
}

/** The account's active sessions, most recently used first. */
export async function listSessions(
  db: D1Database,
  pepper: string,
  now: number,
  userId: string,
  currentIdHash: string,
): Promise<DeviceSession[]> {
  const { results } = await db
    .prepare(
      `SELECT id_hash, device, method, created_at, last_seen_at FROM sessions
       WHERE user_id = ? AND expires_at > ? AND last_seen_at > ?
       ORDER BY last_seen_at DESC LIMIT 50`,
    )
    .bind(userId, now, now - SESSION_IDLE_SECONDS)
    .all<{
      id_hash: string;
      device: string | null;
      method: SignInMethod | null;
      created_at: number;
      last_seen_at: number;
    }>();
  return Promise.all(
    results.map(async (row) => ({
      ref: await sessionRef(pepper, row.id_hash),
      device: row.device,
      method: row.method,
      createdAt: row.created_at,
      lastSeenAt: row.last_seen_at,
      current: row.id_hash === currentIdHash,
    })),
  );
}

/** Ends one of the account's other sessions, named by its list reference. */
export async function endSession(
  db: D1Database,
  pepper: string,
  userId: string,
  currentIdHash: string,
  ref: string,
): Promise<boolean> {
  const { results } = await db
    .prepare('SELECT id_hash FROM sessions WHERE user_id = ? AND id_hash <> ?')
    .bind(userId, currentIdHash)
    .all<{ id_hash: string }>();
  for (const row of results) {
    if ((await sessionRef(pepper, row.id_hash)) === ref) {
      await deleteSession(db, row.id_hash);
      return true;
    }
  }
  return false;
}

/** Ends every session of the account except this one; returns how many ended. */
export async function endOtherSessions(
  db: D1Database,
  userId: string,
  currentIdHash: string,
): Promise<number> {
  const result = await db
    .prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?')
    .bind(userId, currentIdHash)
    .run();
  return result.meta.changes;
}
