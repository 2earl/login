import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import { hmacHex, randomToken } from './crypto';
import {
  clearCookie,
  clientIp,
  isSameOrigin,
  readCookie,
  setCookie,
  underRateLimit,
  type AppContext,
  type AppEnv,
} from './http';
import { listPasskeys } from './mfa';
import { fromBase64url, relyingParty } from './mfa-routes';
import { MESSAGES, sessionsPage } from './pages';
import { safeReturnTo } from './return-to';
import { endOtherSessions, endSession, listSessions } from './sessions';
import { openSession, signInRefusal } from './sign-in';

/**
 * Phase 8a (DESIGN §4.10, §7): signing in with a passkey as the first and only step, and the
 * list of signed-in devices.
 *
 * A passkey sign-in asks for user verification (a fingerprint, face or device PIN), so one
 * gesture proves possession and the person: the session starts at aal2. The challenge is bound
 * to this browser by the __Host-passkey_tx cookie and kept for 5 minutes, used once.
 */

export const PASSKEY_TX_COOKIE = '__Host-passkey_tx';
const CHALLENGE_TTL_SECONDS = 5 * 60;

async function challengeKey(c: AppContext, cookie: string): Promise<string> {
  return hmacHex(c.env.SESSION_PEPPER, `passkey-tx:${cookie}`);
}

interface CredentialRow {
  id: string;
  user_id: string;
  webauthn_credential_id: string;
  webauthn_public_key: string;
  webauthn_sign_count: number | null;
  webauthn_transports: string | null;
  status: string;
}

export function registerPasskeyRoutes(app: Hono<AppEnv>, deps: Deps): void {
  /**
   * A fresh challenge for this browser. `reauth` (someone signed in confirming it's them) limits
   * it to that account's own passkeys; otherwise the browser offers any passkey it has for
   * login.2earl.com, and the account follows from the passkey.
   */
  app.post('/login/passkey/options', async (c) => {
    if (!isSameOrigin(c)) return c.json({ message: 'Forbidden.' }, 403);
    if (!(await underRateLimit(c, 'passkey'))) {
      return c.json({ message: 'Too many attempts from this network. Wait a minute.' }, 429);
    }
    const body: { reauth?: unknown } = await c.req.json<{ reauth?: unknown }>().catch(() => ({}));
    const session = c.get('session');
    const forUser = body.reauth === true && session ? session.user.id : null;
    const now = deps.now();

    const own = forUser ? await listPasskeys(c.env.DB, forUser) : [];
    if (forUser && own.length === 0) {
      return c.json({ message: 'There’s no passkey on this account.' }, 400);
    }
    const options = await generateAuthenticationOptions({
      rpID: relyingParty(c.env).rpID,
      allowCredentials: own.map((p) => ({ id: p.credentialId, transports: p.transports })),
      userVerification: 'required',
      timeout: 120_000,
    });

    const cookie = randomToken(32);
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM passkey_challenges WHERE expires_at <= ?').bind(now),
      c.env.DB.prepare(
        `INSERT INTO passkey_challenges (id_hash, challenge, user_id, expires_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(
        await challengeKey(c, cookie),
        options.challenge,
        forUser,
        now + CHALLENGE_TTL_SECONDS,
      ),
    ]);
    setCookie(c, PASSKEY_TX_COOKIE, cookie, CHALLENGE_TTL_SECONDS);
    return c.json(options);
  });

  app.post('/login/passkey', async (c) => {
    if (!isSameOrigin(c)) return c.json({ message: 'Forbidden.' }, 403);
    if (!(await underRateLimit(c, 'passkey'))) {
      return c.json({ message: 'Too many attempts from this network. Wait a minute.' }, 429);
    }
    const now = deps.now();
    const ip = clientIp(c);
    const body = await c.req.json<{ returnTo?: unknown; response?: unknown }>().catch(() => null);
    const cookie = readCookie(c.req.header('Cookie'), PASSKEY_TX_COOKIE);
    clearCookie(c, PASSKEY_TX_COOKIE);

    // Used up whatever happens next: one answer per challenge.
    const pending = cookie
      ? await c.env.DB.prepare(
          `DELETE FROM passkey_challenges WHERE id_hash = ? AND expires_at > ?
           RETURNING challenge, user_id`,
        )
          .bind(await challengeKey(c, cookie), now)
          .first<{ challenge: string; user_id: string | null }>()
      : null;
    if (!body || !pending) {
      return c.json({ message: 'This request expired. Try again.' }, 400);
    }

    const response = body.response as AuthenticationResponseJSON | undefined;
    const row =
      response && typeof response.id === 'string'
        ? await c.env.DB.prepare(
            `SELECT f.id, f.user_id, f.webauthn_credential_id, f.webauthn_public_key,
                    f.webauthn_sign_count, f.webauthn_transports, u.status
             FROM mfa_factors f JOIN users u ON u.id = f.user_id
             WHERE f.kind = 'webauthn' AND f.webauthn_credential_id = ?`,
          )
            .bind(response.id)
            .first<CredentialRow>()
        : null;

    let newCounter = 0;
    let ok = false;
    if (row && response && (pending.user_id === null || pending.user_id === row.user_id)) {
      try {
        const { rpID, origin } = relyingParty(c.env);
        const result = await verifyAuthenticationResponse({
          response,
          expectedChallenge: pending.challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          credential: {
            id: row.webauthn_credential_id,
            publicKey: fromBase64url(row.webauthn_public_key),
            counter: row.webauthn_sign_count ?? 0,
            transports: row.webauthn_transports
              ? (JSON.parse(row.webauthn_transports) as NonNullable<
                  Parameters<typeof verifyAuthenticationResponse>[0]['credential']['transports']
                >)
              : [],
          },
          requireUserVerification: true,
        });
        ok = result.verified;
        newCounter = result.authenticationInfo.newCounter;
      } catch {
        ok = false;
      }
    }
    if (!ok || !row) {
      await audit(c.env.DB, now, 'login.failed', {
        ipPrefix: ip,
        detail: { method: 'passkey', reason: row ? 'not_verified' : 'unknown_passkey' },
      });
      return c.json(
        {
          message: row
            ? 'That passkey didn’t work. Try again.'
            : 'This passkey isn’t on a 2earl account. Sign in another way, then add it under Security.',
        },
        400,
      );
    }
    if (row.status !== 'active') {
      await audit(c.env.DB, now, 'login.denied', {
        actorUserId: row.user_id,
        ipPrefix: ip,
        detail: { reason: 'user_suspended', method: 'passkey' },
      });
      return c.json({ message: MESSAGES.accountSuspended.body }, 403);
    }
    const refusal = await signInRefusal(c, row.user_id, 'passkey');
    if (refusal) {
      await audit(c.env.DB, now, 'login.denied', {
        actorUserId: row.user_id,
        ipPrefix: ip,
        detail: { reason: 'sso_required', method: 'passkey' },
      });
      return c.json({ message: refusal.body }, 403);
    }

    await c.env.DB.prepare(
      'UPDATE mfa_factors SET webauthn_sign_count = ?, last_used_at = ? WHERE id = ?',
    )
      .bind(newCounter, now, row.id)
      .run();
    await openSession(c, now, row.user_id, { method: 'passkey', aal2: true });
    return c.json({
      redirect: safeReturnTo(typeof body.returnTo === 'string' ? body.returnTo : null),
    });
  });

  // ---- Signed-in devices ------------------------------------------------------------------------

  app.get('/account/sessions', async (c) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsessions', 303);
    const now = deps.now();
    const sessions = await listSessions(
      c.env.DB,
      c.env.SESSION_PEPPER,
      now,
      session.user.id,
      session.idHash,
    );
    const ended = c.req.query('ended');
    return c.html(
      sessionsPage({
        sessions,
        now,
        notice:
          ended === 'one'
            ? 'That device is signed out.'
            : ended === 'others'
              ? 'Every other device is signed out.'
              : null,
      }),
    );
  });

  app.post('/account/sessions/end', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsessions', 303);
    const form = await c.req.raw.formData();
    const ref = form.get('session');
    const now = deps.now();
    if (typeof ref === 'string' && ref.length > 0) {
      const done = await endSession(
        c.env.DB,
        c.env.SESSION_PEPPER,
        session.user.id,
        session.idHash,
        ref,
      );
      if (done) {
        await audit(c.env.DB, now, 'session.ended', {
          actorUserId: session.user.id,
          ipPrefix: clientIp(c),
          detail: { count: 1 },
        });
      }
    }
    return c.redirect('/account/sessions?ended=one', 303);
  });

  app.post('/account/sessions/end-others', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsessions', 303);
    const count = await endOtherSessions(c.env.DB, session.user.id, session.idHash);
    await audit(c.env.DB, deps.now(), 'session.ended', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
      detail: { count },
    });
    return c.redirect('/account/sessions?ended=others', 303);
  });
}
