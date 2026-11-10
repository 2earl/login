import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import { pkceChallenge } from './crypto';
import { normaliseEmail } from './directory';
import { sendCode } from './email-routes';
import { buildGoogleAuthUrl } from './google';
import {
  LOGIN_TX_COOKIE,
  clientIp,
  isSameOrigin,
  setCookie,
  underRateLimit,
  type AppContext,
  type AppEnv,
} from './http';
import { LOGIN_TX_TTL_SECONDS, createLoginTx } from './login-tx';
import { changeCheck } from './mfa-routes';
import { MESSAGES, addEmailPage, messagePage, namePage } from './pages';
import type { Session } from './sessions';
import { notifyLater } from './sign-in';
import { listIdentities, removeIdentity, setDisplayName } from './users';

/**
 * Sign-in methods on the account page (DESIGN §4.9): add Google, add an address, remove one
 * (never the last, never the owner's Google account), and the account's name. Adding or removing
 * a method needs a recent proof that it's the user, as for second factors (THREAT_MODEL R9).
 */
export function registerMethodRoutes(app: Hono<AppEnv>, deps: Deps): void {
  /** The session, or where to send the browser first. */
  const ready = (c: AppContext, returnTo: string): Session | Response => {
    const session = c.get('session');
    if (!session) return c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`, 303);
    const redirect = changeCheck(session, deps.now(), returnTo);
    return redirect ? c.redirect(redirect, 303) : session;
  };

  app.post('/account/methods/google', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'login'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const session = ready(c, '/account');
    if (session instanceof Response) return session;
    const now = deps.now();
    const tx = await createLoginTx(c.env.DB, c.env.SESSION_PEPPER, now, '/account', {
      purpose: 'link_google',
      userId: session.user.id,
    });
    setCookie(c, LOGIN_TX_COOKIE, tx.cookieValue, LOGIN_TX_TTL_SECONDS);
    return c.redirect(
      buildGoogleAuthUrl({
        clientId: c.env.GOOGLE_CLIENT_ID,
        redirectUri: `${c.env.ISSUER}/callback/google`,
        state: tx.state,
        nonce: tx.nonce,
        codeChallenge: await pkceChallenge(tx.pkceVerifier),
      }),
      302,
    );
  });

  app.get('/account/methods/email', (c) => {
    const session = ready(c, '/account/methods/email');
    if (session instanceof Response) return session;
    return c.html(addEmailPage({}));
  });

  app.post('/account/methods/email', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'email'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const session = ready(c, '/account/methods/email');
    if (session instanceof Response) return session;
    const form = await c.req.raw.formData();
    const typed = typeof form.get('email') === 'string' ? (form.get('email') as string) : '';
    const email = normaliseEmail(typed);
    if (!email) {
      return c.html(
        addEmailPage({
          error: 'Enter an email address like name@example.com.',
          email: typed.slice(0, 254),
        }),
        400,
      );
    }
    const mine = await listIdentities(c.env, session.user.id);
    if (mine.some((m) => m.provider === 'email' && m.email === email)) {
      return c.redirect('/account', 303);
    }
    // Whether another account has it is told only after the code proves it's this user's.
    return sendCode(c, deps.now(), { email, purpose: 'link_email', userId: session.user.id });
  });

  app.post('/account/methods/remove', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = ready(c, '/account');
    if (session instanceof Response) return session;
    const form = await c.req.raw.formData();
    const id = form.get('identity');
    const methods = await listIdentities(c.env, session.user.id);
    const target = methods.find((m) => m.id === id);
    if (!target || target.isOwner || methods.length < 2) return c.redirect('/account', 303);
    const now = deps.now();
    const removed = await removeIdentity(c.env.DB, now, session.user.id, target.id);
    if (removed) {
      await audit(c.env.DB, now, 'identity.removed', {
        actorUserId: session.user.id,
        ipPrefix: clientIp(c),
        detail: { provider: removed },
      });
      notifyLater(c, session.user.id, {
        kind: 'method_removed',
        method:
          target.provider === 'google'
            ? `the Google account ${target.email ?? ''}`.trim()
            : `codes sent to ${target.email ?? 'that address'}`,
      });
    }
    return c.redirect('/account?removed=1', 303);
  });

  app.get('/account/name', (c) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fname', 303);
    return c.html(namePage(session.user.displayName));
  });

  app.post('/account/name', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fname', 303);
    const form = await c.req.raw.formData();
    const name = form.get('name');
    await setDisplayName(
      c.env.DB,
      deps.now(),
      session.user.id,
      typeof name === 'string' ? name : '',
    );
    return c.redirect('/account?saved=name', 303);
  });
}
