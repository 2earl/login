import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';
import { SERVICES } from './services';

/**
 * The data-subject rights on /account (docs/DATA_PROTECTION.md §6): a copy of everything the
 * account holds (Art. 15, 20) and deletion (Art. 17, DESIGN §6.3).
 */

export const EXPORT_FORMAT = '2earl-login-export/1';

function iso(unixSeconds: number | null | undefined): string | null {
  return typeof unixSeconds === 'number' ? new Date(unixSeconds * 1000).toISOString() : null;
}

/** Every grant ID of the user. Collected before revoking, so revocation can't skip a page. */
async function grantIds(oauth: OAuthHelpers, userId: string): Promise<string[]> {
  const ids: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await oauth.listUserGrants(userId, { limit: 1000, ...(cursor ? { cursor } : {}) });
    ids.push(...page.items.map((grant) => grant.id));
    cursor = page.cursor;
  } while (cursor);
  return ids;
}

/** Revokes every grant of the user, with its tokens. Returns how many there were. */
export async function revokeAllGrants(oauth: OAuthHelpers, userId: string): Promise<number> {
  const ids = await grantIds(oauth, userId);
  for (const id of ids) await oauth.revokeGrant(id, userId);
  return ids.length;
}

/**
 * Deletes the account (DESIGN §6.3): grants first, so no app keeps access if a later step fails;
 * then, in one D1 transaction, the account rows and the invitation, with the user's audit events
 * re-keyed to a random correlation ID, and a deletion notice for every service; then a second sweep for any grant created in between.
 */
export async function deleteAccount(
  db: D1Database,
  oauth: OAuthHelpers,
  userId: string,
  now: number,
  ipPrefix: string | null,
): Promise<void> {
  const revoked = await revokeAllGrants(oauth, userId);
  const correlationId = `deleted:${crypto.randomUUID()}`;

  await db.batch([
    db
      .prepare('UPDATE audit_events SET actor_user_id = ? WHERE actor_user_id = ?')
      .bind(correlationId, userId),
    db.prepare('DELETE FROM login_tx WHERE user_id = ?').bind(userId),
    // Codes sent to the account's addresses, used or not: they hold the address.
    db
      .prepare(
        `DELETE FROM email_codes WHERE user_id = ?1
            OR email IN (SELECT subject FROM identities WHERE user_id = ?1 AND provider = 'email')`,
      )
      .bind(userId),
    // The invitation goes too: while sign-up is closed, signing in again needs a new one.
    db
      .prepare(
        `DELETE FROM allowlist
         WHERE (kind = 'google_sub'
                AND value IN (SELECT subject FROM identities WHERE user_id = ? AND provider = 'google'))
            OR (kind = 'email' AND value = (SELECT primary_email FROM users WHERE id = ?))
            OR (kind = 'email'
                AND value IN (SELECT subject FROM identities WHERE user_id = ? AND provider = 'email'))`,
      )
      .bind(userId, userId, userId),
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(userId),
    db.prepare('DELETE FROM mfa_factors WHERE user_id = ?').bind(userId),
    db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId),
    db.prepare('DELETE FROM identities WHERE user_id = ?').bind(userId),
    db.prepare('DELETE FROM users WHERE id = ?').bind(userId),
    db
      .prepare(
        `INSERT INTO audit_events (id, at, event, actor_user_id, client_id, ip_prefix, detail)
         VALUES (?, ?, 'user.deleted', ?, NULL, ?, ?)`,
      )
      .bind(crypto.randomUUID(), now, correlationId, ipPrefix, JSON.stringify({ grants: revoked })),
    // Every service is told to delete its data too (deletion-notices.ts delivers these).
    ...SERVICES.map((service) =>
      db
        .prepare(
          `INSERT INTO deletion_notices (service, user_id, created_at) VALUES (?, ?, ?)
           ON CONFLICT (service, user_id) DO NOTHING`,
        )
        .bind(service.id, userId, now),
    ),
  ]);

  await revokeAllGrants(oauth, userId);
}

/** What the account holds, as a JSON document the user downloads (DATA_PROTECTION §6). */
export async function exportAccount(
  db: D1Database,
  oauth: OAuthHelpers,
  userId: string,
  currentSessionHash: string,
  now: number,
): Promise<Record<string, unknown>> {
  const [user, identities, sessions, invitation, events, factors, codes] = await db.batch<
    Record<string, unknown>
  >([
    db
      .prepare(
        'SELECT id, status, display_name, primary_email, created_at, updated_at FROM users WHERE id = ?',
      )
      .bind(userId),
    db
      .prepare(
        `SELECT provider, subject, email, email_verified, created_at, last_login_at
         FROM identities WHERE user_id = ? ORDER BY created_at`,
      )
      .bind(userId),
    db
      .prepare(
        `SELECT id_hash, aal, created_at, last_seen_at, expires_at, ip_prefix, user_agent_hash
         FROM sessions WHERE user_id = ? ORDER BY created_at`,
      )
      .bind(userId),
    db
      .prepare(
        `SELECT a.added_by, a.created_at FROM allowlist a
         JOIN identities i ON i.provider = 'google' AND a.kind = 'google_sub' AND a.value = i.subject
         WHERE i.user_id = ?`,
      )
      .bind(userId),
    db
      .prepare(
        `SELECT at, event, client_id, ip_prefix, detail FROM audit_events
         WHERE actor_user_id = ? ORDER BY at`,
      )
      .bind(userId),
    db
      .prepare(
        `SELECT kind, label, created_at, last_used_at FROM mfa_factors
         WHERE user_id = ? ORDER BY created_at`,
      )
      .bind(userId),
    db
      .prepare(
        'SELECT COUNT(*) AS unused FROM recovery_codes WHERE user_id = ? AND used_at IS NULL',
      )
      .bind(userId),
  ]);

  const account = user?.results[0];
  const apps = [];
  let cursor: string | undefined;
  do {
    const page = await oauth.listUserGrants(userId, { limit: 1000, ...(cursor ? { cursor } : {}) });
    for (const grant of page.items) {
      let name: string | null = null;
      try {
        name = (await oauth.lookupClient(grant.clientId))?.clientName ?? null;
      } catch {
        // A client metadata document that can't be fetched now: export the grant without it.
      }
      apps.push({
        clientId: grant.clientId,
        name,
        permissions: grant.scope,
        redirectUri: grant.redirectUri ?? null,
        allowedAt: iso(grant.createdAt),
        expiresAt: iso(grant.expiresAt),
      });
    }
    cursor = page.cursor;
  } while (cursor);

  return {
    format: EXPORT_FORMAT,
    exportedAt: iso(now),
    service: 'https://login.2earl.com',
    privacyPolicy: 'https://2earl.com/privacy',
    account: account
      ? {
          id: account.id,
          status: account.status,
          name: account.display_name,
          email: account.primary_email,
          createdAt: iso(account.created_at as number),
          updatedAt: iso(account.updated_at as number),
        }
      : null,
    signInMethods: (identities?.results ?? []).map((row) => ({
      provider: row.provider,
      accountId: row.subject,
      email: row.email,
      emailVerified: row.email_verified === 1,
      linkedAt: iso(row.created_at as number),
      lastSignInAt: iso(row.last_login_at as number),
    })),
    sessions: (sessions?.results ?? []).map((row) => ({
      thisBrowser: row.id_hash === currentSessionHash,
      assurance: row.aal,
      createdAt: iso(row.created_at as number),
      lastActiveAt: iso(row.last_seen_at as number),
      expiresAt: iso(row.expires_at as number),
      networkPrefix: row.ip_prefix,
      browserFingerprint: row.user_agent_hash,
    })),
    connectedApps: apps,
    secondFactor: {
      factors: (factors?.results ?? []).map((row) => ({
        type: row.kind === 'webauthn' ? 'passkey' : 'authenticator app',
        name: row.label,
        addedAt: iso(row.created_at as number),
        lastUsedAt: iso(row.last_used_at as number | null),
      })),
      recoveryCodesUnused: codes?.results[0]?.unused ?? 0,
    },
    invitation: invitation?.results[0]
      ? {
          addedBy: invitation.results[0].added_by,
          createdAt: iso(invitation.results[0].created_at as number),
        }
      : null,
    securityLog: (events?.results ?? []).map((row) => ({
      at: iso(row.at as number),
      event: row.event,
      clientId: row.client_id,
      networkPrefix: row.ip_prefix,
      detail: typeof row.detail === 'string' ? (JSON.parse(row.detail) as unknown) : null,
    })),
    notes: [
      'Network prefixes are shortened IP addresses (/24 for IPv4, /48 for IPv6). Full IP addresses are never stored.',
      'browserFingerprint is a shortened SHA-256 hash of the browser’s user-agent string, not the string itself.',
      'Session cookies, access tokens, refresh tokens and authorization codes are stored only as hashes and are not included.',
      'Second-factor secrets are not included: passkey public keys, the encrypted authenticator-app secret and hashed recovery codes.',
      'services lists what each other 2earl service (such as the MCP gateway) holds about you, as that service reports it.',
      'Security log entries are kept for 90 days. Sign-in attempts made before you were signed in are not linked to your account and are not included.',
    ],
  };
}
