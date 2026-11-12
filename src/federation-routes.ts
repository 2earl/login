import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import { hmacHex, pkceChallenge, randomToken } from './crypto';
import {
  LOGIN_TX_COOKIE,
  clearCookie,
  clientIp,
  isSameOrigin,
  readCookie,
  setCookie,
  underRateLimit,
  type AppContext,
  type AppEnv,
} from './http';
import { LOGIN_TX_TTL_SECONDS, consumeLoginTx, createLoginTx, type LoginPurpose } from './login-tx';
import { changeCheck } from './mfa-routes';
import { MESSAGES, messagePage, methodHasAccount, methodTaken, type Message } from './pages';
import {
  PROVIDER_NAMES,
  ProviderSignInError,
  appleName,
  authorizationUrl,
  identityFromCode,
  isFederatedProvider,
  providerEnabled,
  type FederatedProvider,
  type ProviderDeps,
} from './providers';
import { safeReturnTo } from './return-to';
import { signupMode } from './settings';
import { finishDeletion, notifyLater, startSession } from './sign-in';
import {
  accountWithEmail,
  addFederatedIdentity,
  emailInvited,
  isUserActive,
  upsertFederatedUser,
  userForProvider,
} from './users';

/**
 * Sign in, sign up, add a method, or confirm a deletion with Microsoft, GitHub or Apple (DESIGN
 * §4.14). The same rules as Google (§4.2, §4.9): a single-use transaction bound to this browser
 * by the __Host-login_tx cookie, state, PKCE (Microsoft, GitHub) and nonce (Microsoft, Apple);
 * accounts keyed on the provider's account ID; never joined by email address (THREAT_MODEL B3).
 */

const APPLE_TICKET_TTL_SECONDS = 5 * 60;

export interface FederationDeps extends Deps, ProviderDeps {}

/** Sends the browser to the provider, with a fresh transaction bound to it. */
export async function startProviderTrip(
  c: AppContext,
  now: number,
  provider: FederatedProvider,
  options: {
    purpose: LoginPurpose;
    returnTo: string | null;
    userId?: string;
    loginHint?: string | null;
  },
): Promise<Response> {
  const tx = await createLoginTx(c.env.DB, c.env.SESSION_PEPPER, now, options.returnTo, {
    purpose: options.purpose,
    provider,
    ...(options.userId ? { userId: options.userId } : {}),
  });
  setCookie(c, LOGIN_TX_COOKIE, tx.cookieValue, LOGIN_TX_TTL_SECONDS);
  return c.redirect(
    authorizationUrl(c.env, provider, {
      state: tx.state,
      nonce: tx.nonce,
      codeChallenge: await pkceChallenge(tx.pkceVerifier),
      loginHint: options.loginHint ?? null,
    }),
    302,
  );
}

export function registerFederationRoutes(app: Hono<AppEnv>, deps: FederationDeps): void {
  const providerOf = (c: AppContext): FederatedProvider | null => {
    const value = c.req.param('provider');
    return isFederatedProvider(value) && providerEnabled(c.env, value) ? value : null;
  };

  app.get('/login/:provider{microsoft|github|apple}', async (c) => {
    const provider = providerOf(c);
    if (!provider) return c.notFound();
    if (!(await underRateLimit(c, 'login'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const now = deps.now();
    const returnTo = safeReturnTo(c.req.query('return_to'));
    if (c.get('session') && c.req.query('reauth') !== '1') return c.redirect(returnTo, 303);
    await audit(c.env.DB, now, 'login.started', {
      ipPrefix: clientIp(c),
      detail: { provider },
    });
    return startProviderTrip(c, now, provider, { purpose: 'sign_in', returnTo });
  });

  // Adding a provider to the signed-in account, after a recent proof it's them (DESIGN §4.9).
  app.post('/account/methods/:provider{microsoft|github|apple}', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const provider = providerOf(c);
    if (!provider) return c.notFound();
    if (!(await underRateLimit(c, 'login'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount', 303);
    const now = deps.now();
    const redirect = changeCheck(session, now, '/account');
    if (redirect) return c.redirect(redirect, 303);
    return startProviderTrip(c, now, provider, {
      purpose: 'link',
      returnTo: '/account',
      userId: session.user.id,
    });
  });

  // Apple answers with a cross-site POST that carries no SameSite=Lax cookie. Keep its answer
  // for a few minutes under a random ticket and continue with a same-site GET, which has it.
  app.post('/callback/apple', async (c) => {
    if (!(await underRateLimit(c, 'callback'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const form = await c.req.raw.formData().catch(() => null);
    const field = (name: string) => {
      const value = form?.get(name);
      return typeof value === 'string' && value.length <= 4096 ? value : null;
    };
    const state = field('state');
    if (!state) return c.html(messagePage(MESSAGES.signInFailed), 400);
    const now = deps.now();
    const ticket = randomToken(32);
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM callback_tickets WHERE expires_at <= ?').bind(now),
      c.env.DB.prepare(
        `INSERT INTO callback_tickets (id_hash, provider, state, code, error, name, expires_at)
         VALUES (?, 'apple', ?, ?, ?, ?, ?)`,
      ).bind(
        await hmacHex(c.env.SESSION_PEPPER, `callback-ticket:${ticket}`),
        state,
        field('code'),
        field('error'),
        appleName(field('user')),
        now + APPLE_TICKET_TTL_SECONDS,
      ),
    ]);
    return c.redirect(`/callback/apple?ticket=${ticket}`, 303);
  });

  app.get('/callback/:provider{microsoft|github|apple}', async (c) => {
    const provider = providerOf(c);
    if (!provider) return c.notFound();
    if (!(await underRateLimit(c, 'callback'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const now = deps.now();
    const ip = clientIp(c);

    // What the provider answered: from the query, or for Apple from the ticket.
    let answer: {
      state: string | null;
      code: string | null;
      error: string | null;
      name: string | null;
    };
    if (provider === 'apple') {
      const ticket = c.req.query('ticket');
      const row = ticket
        ? await c.env.DB.prepare(
            `DELETE FROM callback_tickets WHERE id_hash = ? AND expires_at > ?
             RETURNING state, code, error, name`,
          )
            .bind(await hmacHex(c.env.SESSION_PEPPER, `callback-ticket:${ticket}`), now)
            .first<{
              state: string;
              code: string | null;
              error: string | null;
              name: string | null;
            }>()
        : null;
      answer = row ?? { state: null, code: null, error: 'ticket_invalid', name: null };
    } else {
      answer = {
        state: c.req.query('state') ?? null,
        code: c.req.query('code') ?? null,
        error: c.req.query('error') ?? null,
        name: null,
      };
    }

    const tx = await consumeLoginTx(
      c.env.DB,
      c.env.SESSION_PEPPER,
      now,
      readCookie(c.req.header('Cookie'), LOGIN_TX_COOKIE),
      answer.state ?? undefined,
    );
    clearCookie(c, LOGIN_TX_COOKIE);

    const fail = async (
      reason: string,
      message: Message = MESSAGES.signInFailed,
      status: 400 | 403 | 409 = 400,
    ) => {
      await audit(c.env.DB, now, status === 400 ? 'login.failed' : 'login.denied', {
        ipPrefix: ip,
        detail: { reason, provider },
      });
      return c.html(messagePage(message), status);
    };
    // The transaction must be for this provider: a code from one can't finish a trip to another.
    if (!tx || tx.provider !== provider) return fail('transaction_invalid');

    const deleting = tx.purpose === 'delete_account';
    const stop = async (
      reason: string,
      message: Message = MESSAGES.deletionNotConfirmed,
      status: 400 | 403 | 500 = 400,
    ) => {
      await audit(c.env.DB, now, 'account.deletion_stopped', {
        actorUserId: tx.userId,
        ipPrefix: ip,
        detail: { reason, provider },
      });
      return c.html(messagePage(message, 'Deletion stopped'), status);
    };
    if (answer.error || !answer.code) {
      const reason = answer.error ? 'provider_error' : 'code_missing';
      return deleting ? stop(reason) : fail(reason);
    }

    let identity;
    try {
      identity = await identityFromCode(c.env, deps, provider, {
        code: answer.code,
        codeVerifier: tx.pkceVerifier,
        nonce: tx.nonce,
        now,
        name: answer.name,
      });
    } catch (error) {
      const reason = error instanceof ProviderSignInError ? error.reason : 'unexpected';
      if (deleting) return stop(reason);
      return fail(
        reason,
        reason === 'email_not_verified' ? MESSAGES.providerEmailNotVerified : MESSAGES.signInFailed,
      );
    }
    const name = PROVIDER_NAMES[provider];

    if (deleting) {
      const session = c.get('session');
      if (!session || session.user.id !== tx.userId) return stop('session_changed');
      if ((await userForProvider(c.env.DB, provider, identity.subject)) !== session.user.id) {
        return stop('different_account', MESSAGES.deletionWrongAccount, 403);
      }
      return finishDeletion(c, now, session.user.id, stop);
    }

    if (tx.purpose === 'link') {
      const session = c.get('session');
      if (!session || session.user.id !== tx.userId) {
        return c.html(messagePage(MESSAGES.linkNotConfirmed, 'Nothing changed'), 400);
      }
      const owner = await userForProvider(c.env.DB, provider, identity.subject);
      if (owner && owner !== session.user.id) {
        return c.html(messagePage(methodTaken(name), 'Nothing changed'), 409);
      }
      if (!owner) {
        // An address another account signs in with stays that account's (B3).
        const clash = await accountWithEmail(c.env.DB, identity.email, session.user.id);
        if (clash) return c.html(messagePage(MESSAGES.emailTaken, 'Nothing changed'), 409);
        await addFederatedIdentity(c.env.DB, now, session.user.id, identity);
        await audit(c.env.DB, now, 'identity.added', {
          actorUserId: session.user.id,
          ipPrefix: ip,
          detail: { provider },
        });
        notifyLater(c, session.user.id, {
          kind: 'method_added',
          method: `the ${name} account ${identity.email}`,
        });
      }
      return c.redirect(`/account?added=${provider}`, 303);
    }

    // Sign in or sign up.
    const known = await userForProvider(c.env.DB, provider, identity.subject);
    if (!known) {
      const clash = await accountWithEmail(c.env.DB, identity.email);
      if (clash) return fail('email_has_account', methodHasAccount(clash.provider), 409);
      if (
        (await signupMode(c.env)) === 'invite' &&
        !(await emailInvited(c.env.DB, identity.email))
      ) {
        return fail('not_allowlisted', MESSAGES.notInvited, 403);
      }
    }
    const { userId, created } = await upsertFederatedUser(c.env.DB, now, identity);
    if (created) await audit(c.env.DB, now, 'user.created', { actorUserId: userId, ipPrefix: ip });
    if (!(await isUserActive(c.env.DB, userId)))
      return fail('user_suspended', MESSAGES.accountSuspended, 403);
    return startSession(c, now, userId, tx.returnTo, { welcome: created, method: provider });
  });
}
