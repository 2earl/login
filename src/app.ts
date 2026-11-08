import { Hono, type Context } from 'hono';
import type { JWTVerifyGetKey } from 'jose';
import { audit } from './audit';
import { pkceChallenge, sha256Hex } from './crypto';
import { GoogleSignInError, buildGoogleAuthUrl, exchangeCode, verifyGoogleIdToken } from './google';
import { LOGIN_TX_TTL_SECONDS, consumeLoginTx, createLoginTx } from './login-tx';
import { ipPrefix } from './net';
import { APP_CSS, accountPage, homePage, messagePage } from './pages';
import { safeReturnTo } from './return-to';
import { applySecurityHeaders } from './security-headers';
import { createSession, deleteSession, getSession, type Session } from './sessions';
import { allowlistMatch, isUserActive, pinAllowlistToSubject, upsertGoogleUser } from './users';

/** External dependencies, injectable so tests can stand in for Google. */
export interface Deps {
  fetch: typeof fetch;
  googleJwks: JWTVerifyGetKey;
  /** Current time in Unix seconds. */
  now: () => number;
}

type AppEnv = { Bindings: Env; Variables: { session: Session | null } };
type AppContext = Context<AppEnv>;

const SESSION_COOKIE = '__Host-session';
const LOGIN_TX_COOKIE = '__Host-login_tx';

function setCookie(c: AppContext, name: string, value: string, maxAge: number): void {
  c.header(
    'Set-Cookie',
    `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${String(maxAge)}`,
    { append: true },
  );
}

function clearCookie(c: AppContext, name: string): void {
  setCookie(c, name, '', 0);
}

function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

function clientIp(c: AppContext): string | null {
  return ipPrefix(c.req.header('CF-Connecting-IP'));
}

/**
 * Requests that change state must come from our own pages (DESIGN §7). The Origin header must
 * match, and if the browser reports Sec-Fetch-Site it must say same-origin.
 */
function isSameOrigin(c: AppContext): boolean {
  const fetchSite = c.req.header('Sec-Fetch-Site');
  if (fetchSite !== undefined && fetchSite !== 'same-origin') return false;
  return c.req.header('Origin') === new URL(c.env.ISSUER).origin;
}

async function underRateLimit(c: AppContext, route: string): Promise<boolean> {
  const { success } = await c.env.AUTH_RATE_LIMITER.limit({
    key: `${route}:${clientIp(c) ?? 'unknown'}`,
  });
  return success;
}

export function createApp(deps: Deps): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  app.use('*', async (c, next) => {
    await next();
    applySecurityHeaders(c.res.headers);
  });

  // Resolve the session once per request.
  app.use('*', async (c, next) => {
    c.set(
      'session',
      await getSession(
        c.env.DB,
        c.env.SESSION_PEPPER,
        deps.now(),
        readCookie(c.req.header('Cookie'), SESSION_COOKIE),
      ),
    );
    await next();
  });

  app.get('/', (c) => c.html(homePage(c.get('session')?.user.primaryEmail ?? null)));

  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  app.get('/app.css', (c) => {
    c.header('Cache-Control', 'public, max-age=3600');
    return c.body(APP_CSS, 200, { 'Content-Type': 'text/css; charset=utf-8' });
  });

  app.get('/login', async (c) => {
    if (!(await underRateLimit(c, 'login'))) {
      return c.html(messagePage('Too many attempts', 'Please wait a minute and try again.'), 429);
    }
    const now = deps.now();
    const returnTo = safeReturnTo(c.req.query('return_to'));
    if (c.get('session')) return c.redirect(returnTo, 303);

    const tx = await createLoginTx(c.env.DB, c.env.SESSION_PEPPER, now, returnTo);
    setCookie(c, LOGIN_TX_COOKIE, tx.cookieValue, LOGIN_TX_TTL_SECONDS);
    await audit(c.env.DB, now, 'login.started', { ipPrefix: clientIp(c) });

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

  app.get('/callback/google', async (c) => {
    if (!(await underRateLimit(c, 'callback'))) {
      return c.html(messagePage('Too many attempts', 'Please wait a minute and try again.'), 429);
    }
    const now = deps.now();
    const ip = clientIp(c);
    const fail = async (reason: string, status: 400 | 403 = 400) => {
      await audit(c.env.DB, now, status === 403 ? 'login.denied' : 'login.failed', {
        ipPrefix: ip,
        detail: { reason },
      });
      return status === 403
        ? c.html(
            messagePage(
              'Access not available',
              'This Google account cannot sign in to 2earl yet.',
              false,
            ),
            403,
          )
        : c.html(messagePage('Sign-in failed', 'Your sign-in could not be completed.'), 400);
    };

    // The transaction is single-use and bound to this browser by its cookie.
    const tx = await consumeLoginTx(
      c.env.DB,
      c.env.SESSION_PEPPER,
      now,
      readCookie(c.req.header('Cookie'), LOGIN_TX_COOKIE),
      c.req.query('state'),
    );
    clearCookie(c, LOGIN_TX_COOKIE);
    if (!tx) return fail('transaction_invalid');

    if (c.req.query('error')) return fail('google_error');
    const code = c.req.query('code');
    if (!code) return fail('code_missing');

    let identity;
    try {
      const idToken = await exchangeCode(deps.fetch, {
        clientId: c.env.GOOGLE_CLIENT_ID,
        clientSecret: c.env.GOOGLE_CLIENT_SECRET,
        code,
        codeVerifier: tx.pkceVerifier,
        redirectUri: `${c.env.ISSUER}/callback/google`,
      });
      identity = await verifyGoogleIdToken(idToken, {
        jwks: deps.googleJwks,
        clientId: c.env.GOOGLE_CLIENT_ID,
        nonce: tx.nonce,
        now,
      });
    } catch (error) {
      return fail(error instanceof GoogleSignInError ? error.reason : 'unexpected');
    }

    // Locked launch: check before any account is created.
    const locked: string = c.env.LOGIN_LOCKED;
    if (locked !== 'false') {
      const match = await allowlistMatch(c.env.DB, identity);
      if (!match) return fail('not_allowlisted', 403);
      if (match === 'email') {
        await pinAllowlistToSubject(c.env.DB, now, identity);
        await audit(c.env.DB, now, 'allowlist.pinned', { ipPrefix: ip });
      }
    }

    const { userId, created } = await upsertGoogleUser(c.env.DB, now, identity);
    if (created) await audit(c.env.DB, now, 'user.created', { actorUserId: userId, ipPrefix: ip });

    if (!(await isUserActive(c.env.DB, userId))) return fail('user_suspended', 403);

    // A fresh session on every sign-in; any session the browser already had is ended.
    const previous = c.get('session');
    if (previous) await deleteSession(c.env.DB, previous.idHash);
    const userAgent = c.req.header('User-Agent');
    const session = await createSession(c.env.DB, c.env.SESSION_PEPPER, now, userId, {
      ipPrefix: ip,
      userAgentHash: userAgent ? (await sha256Hex(userAgent)).slice(0, 16) : null,
    });
    setCookie(c, SESSION_COOKIE, session.cookieValue, session.expiresAt - now);
    await audit(c.env.DB, now, 'login.succeeded', { actorUserId: userId, ipPrefix: ip });

    return c.redirect(safeReturnTo(tx.returnTo), 303);
  });

  app.post('/logout', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (session) {
      await deleteSession(c.env.DB, session.idHash);
      await audit(c.env.DB, deps.now(), 'logout', {
        actorUserId: session.user.id,
        ipPrefix: clientIp(c),
      });
    }
    clearCookie(c, SESSION_COOKIE);
    return c.redirect('/', 303);
  });

  app.get('/account', (c) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount', 303);
    return c.html(
      accountPage({
        email: session.user.primaryEmail,
        name: session.user.displayName,
        memberSince: session.user.createdAt,
      }),
    );
  });

  app.notFound((c) => c.json({ error: 'not_found' }, 404));

  app.onError((err, c) => {
    // Never echo error details to the client; they may contain request data.
    console.error('unhandled error', err.name);
    return c.json({ error: 'server_error' }, 500);
  });

  return app;
}
