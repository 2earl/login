import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import { normaliseEmail } from './directory';
import {
  EMAIL_CODE_COOKIE,
  EMAIL_CODE_TTL_SECONDS,
  checkEmailCode,
  checkEmailLink,
  createEmailCode,
  discardEmailCode,
  pendingEmailCode,
  sendLimit,
  type CodeCheck,
  type EmailCodeRow,
} from './email-codes';
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
import { codeMail, sendMail, type CodePurpose } from './mail';
import { mfaHtml } from './mfa-routes';
import {
  MESSAGES,
  emailCodePage,
  emailLinkPage,
  messagePage,
  signInPage,
  ssoFirstPage,
  welcomePage,
  type Message,
} from './pages';
import { safeReturnTo } from './return-to';
import { signupMode } from './settings';
import { finishDeletion, notifyLater, signInRefusal, startSession } from './sign-in';
import { adoptNewAccount, ssoRequiredAtDomain } from './managed';
import {
  accountWithEmail,
  addEmailIdentity,
  createEmailUser,
  emailInvited,
  isUserActive,
  setDisplayName,
  touchEmailIdentity,
  userForEmail,
} from './users';

/**
 * Sign-in with a code sent by email (DESIGN §4.9), and everything else a code confirms: deleting
 * an account that signs in that way, and adding an address to an account.
 */

/** Creates a code, emails it, and sends the browser to the page where it's typed. */
export async function sendCode(
  c: AppContext,
  now: number,
  input: { email: string; purpose: CodePurpose; userId?: string | null; returnTo?: string | null },
  page: { resent?: boolean } = {},
): Promise<Response> {
  const ip = clientIp(c);
  const limit = await sendLimit(c.env.DB, now, input.email, ip);
  if (limit) {
    await audit(c.env.DB, now, 'login.code_refused', {
      actorUserId: input.userId ?? null,
      ipPrefix: ip,
      detail: { limit },
    });
    return c.html(messagePage(MESSAGES.tooManyCodes, 'No code sent'), 429);
  }
  const code = await createEmailCode(c.env.DB, c.env.SESSION_PEPPER, now, {
    ...input,
    ipPrefix: ip,
  });
  const mail = codeMail(
    input.purpose,
    code.code,
    `${c.env.ISSUER}/login/email/link?token=${encodeURIComponent(code.linkToken)}`,
  );
  if (!(await sendMail(c.env, input.email, mail))) {
    await discardEmailCode(c.env.DB, c.env.SESSION_PEPPER, code.cookieValue);
    return c.html(messagePage(MESSAGES.emailNotSent, 'No code sent'), 502);
  }
  await audit(c.env.DB, now, 'login.code_sent', {
    actorUserId: input.userId ?? null,
    ipPrefix: ip,
    detail: { purpose: input.purpose },
  });
  setCookie(c, EMAIL_CODE_COOKIE, code.cookieValue, EMAIL_CODE_TTL_SECONDS);
  return c.redirect(page.resent ? '/login/email/code?resent=1' : '/login/email/code', 303);
}

export function registerEmailRoutes(app: Hono<AppEnv>, deps: Deps): void {
  const cookieOf = (c: AppContext) => readCookie(c.req.header('Cookie'), EMAIL_CODE_COOKIE);

  app.post('/login/email', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'email'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const form = await c.req.raw.formData();
    const rawReturn = form.get('return_to');
    const returnTo = typeof rawReturn === 'string' && rawReturn ? safeReturnTo(rawReturn) : null;
    const session = c.get('session');
    if (session && form.get('reauth') !== '1') return c.redirect(safeReturnTo(returnTo), 303);
    const typed = typeof form.get('email') === 'string' ? (form.get('email') as string) : '';
    const email = normaliseEmail(typed);
    if (!email) {
      return mfaHtml(
        signInPage({
          returnTo,
          mode: await signupMode(c.env),
          error: 'Enter an email address like name@example.com.',
          email: typed.slice(0, 254),
        }),
        400,
      );
    }
    // A domain whose organization requires single sign-on: its sign-in first (DESIGN §4.25).
    if (form.get('code') !== '1' && (await ssoRequiredAtDomain(c.env.DB, email))) {
      return c.html(ssoFirstPage({ email, returnTo }));
    }
    // The same answer whether or not the address has an account: nothing is revealed here.
    return sendCode(c, deps.now(), { email, purpose: 'sign_in', returnTo });
  });

  app.get('/login/email/code', async (c) => {
    const pending = await pendingEmailCode(c.env.DB, c.env.SESSION_PEPPER, deps.now(), cookieOf(c));
    if (!pending) return c.html(messagePage(MESSAGES.codeExpired), 400);
    return c.html(
      emailCodePage({
        email: pending.email,
        purpose: pending.purpose,
        resent: c.req.query('resent') === '1',
      }),
    );
  });

  app.post('/login/email/resend', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'email'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const now = deps.now();
    const cookie = cookieOf(c);
    const pending = await pendingEmailCode(c.env.DB, c.env.SESSION_PEPPER, now, cookie);
    if (!pending) return c.html(messagePage(MESSAGES.codeExpired), 400);
    // The earlier code stops working: one live code per browser.
    if (cookie) await discardEmailCode(c.env.DB, c.env.SESSION_PEPPER, cookie);
    return sendCode(
      c,
      now,
      {
        email: pending.email,
        purpose: pending.purpose,
        userId: pending.userId,
        returnTo: pending.returnTo,
      },
      { resent: true },
    );
  });

  app.post('/login/email/code', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'email-code'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const now = deps.now();
    const cookie = cookieOf(c);
    const pending = await pendingEmailCode(c.env.DB, c.env.SESSION_PEPPER, now, cookie);
    const form = await c.req.raw.formData();
    const typed = typeof form.get('code') === 'string' ? (form.get('code') as string) : '';
    const result = await checkEmailCode(c.env.DB, c.env.SESSION_PEPPER, now, cookie, typed);
    if (!result.ok && result.reason === 'wrong' && pending) {
      await audit(c.env.DB, now, 'login.code_failed', {
        actorUserId: pending.userId,
        ipPrefix: clientIp(c),
      });
      return c.html(
        emailCodePage({
          email: pending.email,
          purpose: pending.purpose,
          error: `That code isn’t right. ${String(result.triesLeft)} ${result.triesLeft === 1 ? 'try' : 'tries'} left.`,
        }),
        400,
      );
    }
    return complete(c, now, result);
  });

  // The link from the email. Mail scanners open links, so opening it only shows a button.
  app.get('/login/email/link', async (c) => {
    const token = c.req.query('token') ?? '';
    const pending = await pendingEmailCode(c.env.DB, c.env.SESSION_PEPPER, deps.now(), cookieOf(c));
    if (!pending) return c.html(messagePage(MESSAGES.linkOtherBrowser, 'Not signed in'), 400);
    return c.html(emailLinkPage(token, pending.purpose));
  });

  app.post('/login/email/link', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'email-code'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const now = deps.now();
    const form = await c.req.raw.formData();
    const token = typeof form.get('token') === 'string' ? (form.get('token') as string) : '';
    return complete(
      c,
      now,
      await checkEmailLink(c.env.DB, c.env.SESSION_PEPPER, now, cookieOf(c), token),
    );
  });

  /** What a confirmed code does, by why it was sent. */
  async function complete(c: AppContext, now: number, result: CodeCheck): Promise<Response> {
    clearCookie(c, EMAIL_CODE_COOKIE);
    const ip = clientIp(c);
    if (!result.ok) {
      await audit(c.env.DB, now, 'login.failed', {
        ipPrefix: ip,
        detail: { reason: 'code_expired' },
      });
      return c.html(messagePage(MESSAGES.codeExpired), 400);
    }
    const row = result.row;
    if (row.purpose === 'delete_account') return completeDeletion(c, now, row);
    if (row.purpose === 'link_email') return completeLink(c, now, row);

    let userId = await userForEmail(c.env.DB, row.email);
    let created = false;
    if (!userId) {
      // No joining by address (THREAT_MODEL B3): an address a Google account already uses
      // stays that account's.
      if (await accountWithEmail(c.env.DB, row.email)) {
        await audit(c.env.DB, now, 'login.denied', {
          ipPrefix: ip,
          detail: { reason: 'google_has_account' },
        });
        return c.html(messagePage(MESSAGES.googleHasAccount), 409);
      }
      if ((await signupMode(c.env)) === 'invite' && !(await emailInvited(c.env.DB, row.email))) {
        await audit(c.env.DB, now, 'login.denied', {
          ipPrefix: ip,
          detail: { reason: 'not_allowlisted' },
        });
        return c.html(messagePage(MESSAGES.notInvited), 403);
      }
      userId = await createEmailUser(c.env.DB, now, row.email);
      created = true;
      await audit(c.env.DB, now, 'user.created', { actorUserId: userId, ipPrefix: ip });
      await adoptNewAccount(c.env.DB, now, userId, row.email);
    } else {
      await touchEmailIdentity(c.env.DB, now, row.email);
    }
    if (!(await isUserActive(c.env.DB, userId))) {
      await audit(c.env.DB, now, 'login.denied', {
        ipPrefix: ip,
        detail: { reason: 'user_suspended' },
      });
      return c.html(messagePage(MESSAGES.notInvited), 403);
    }
    const refusal = await signInRefusal(c, userId, 'email');
    if (refusal) {
      await audit(c.env.DB, now, 'login.denied', {
        actorUserId: userId,
        ipPrefix: ip,
        detail: { reason: 'sso_required', method: 'email' },
      });
      return c.html(messagePage(refusal), 403);
    }
    return startSession(c, now, userId, row.returnTo, { welcome: created, method: 'email' });
  }

  async function completeDeletion(c: AppContext, now: number, row: EmailCodeRow) {
    const ip = clientIp(c);
    const stop = async (
      reason: string,
      message: Message = MESSAGES.deletionNotConfirmed,
      status: 400 | 403 | 500 = 400,
    ) => {
      await audit(c.env.DB, now, 'account.deletion_stopped', {
        actorUserId: row.userId,
        ipPrefix: ip,
        detail: { reason },
      });
      return c.html(messagePage(message, 'Deletion stopped'), status);
    };
    const session = c.get('session');
    if (!session || session.user.id !== row.userId) return stop('session_changed');
    if ((await userForEmail(c.env.DB, row.email)) !== session.user.id) {
      return stop('different_account', MESSAGES.deletionWrongAccount, 403);
    }
    return finishDeletion(c, now, session.user.id, stop);
  }

  async function completeLink(c: AppContext, now: number, row: EmailCodeRow) {
    const session = c.get('session');
    if (!session || session.user.id !== row.userId) {
      return c.html(messagePage(MESSAGES.linkNotConfirmed, 'Nothing changed'), 400);
    }
    const other = await accountWithEmail(c.env.DB, row.email, session.user.id);
    if (other) return c.html(messagePage(MESSAGES.emailTaken, 'Nothing changed'), 409);
    if ((await userForEmail(c.env.DB, row.email)) === null) {
      await addEmailIdentity(c.env.DB, now, session.user.id, row.email);
      await audit(c.env.DB, now, 'identity.added', {
        actorUserId: session.user.id,
        ipPrefix: clientIp(c),
        detail: { provider: 'email' },
      });
      notifyLater(c, session.user.id, {
        kind: 'method_added',
        method: `codes sent to ${row.email}`,
      });
    }
    return c.redirect('/account?added=email', 303);
  }

  // ---- After sign-up -------------------------------------------------------------------------

  app.get('/welcome', (c) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login', 303);
    const rawReturn = c.req.query('return_to');
    return c.html(
      welcomePage({
        email: session.user.primaryEmail,
        returnTo: rawReturn ? safeReturnTo(rawReturn) : null,
      }),
    );
  });

  app.post('/welcome', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (!session) return c.redirect('/login', 303);
    const form = await c.req.raw.formData();
    const name = form.get('name');
    if (typeof name === 'string' && name.trim()) {
      await setDisplayName(c.env.DB, deps.now(), session.user.id, name);
    }
    const rawReturn = form.get('return_to');
    return c.redirect(safeReturnTo(typeof rawReturn === 'string' ? rawReturn : null), 303);
  });
}
