import {
  AuthorizationError,
  CimdFetchError,
  authorizationErrorRedirect,
  type AuthRequest,
  type OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { Hono, type Context } from 'hono';
import type { JWTVerifyGetKey } from 'jose';
import { audit } from './audit';
import { pkceChallenge, sha256Hex } from './crypto';
import { GoogleSignInError, buildGoogleAuthUrl, exchangeCode, verifyGoogleIdToken } from './google';
import { LOGIN_TX_TTL_SECONDS, consumeLoginTx, createLoginTx } from './login-tx';
import { ipPrefix } from './net';
import { SCOPES, authorizationServer, scopeLabel, type GrantProps } from './oauth';
import {
  MESSAGES,
  accountPage,
  consentPage,
  messagePage,
  notFoundPage,
  signInPage,
  type ConnectedApp,
} from './pages';
import { safeReturnTo } from './return-to';
import { CONSENT_CSP, applySecurityHeaders } from './security-headers';
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

/** Hono types its context more narrowly than the Workers runtime provides it. */
function workerCtx(c: AppContext): ExecutionContext {
  return c.executionCtx as unknown as ExecutionContext;
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

/** How a resource reads on the consent page: what it is, then the host it lives on. */
function resourceLabel(resource: string): string {
  try {
    return `2earl MCP gateway (${new URL(resource).host})`;
  } catch {
    return resource;
  }
}

/**
 * Errors from /authorize (docs/consent-page.md in the library): redirect to the client only when
 * the library validated the client and its exact redirect URI; otherwise render locally.
 */
function authorizeError(c: AppContext, error: unknown): Response {
  if (error instanceof AuthorizationError && error.redirectTo) {
    return c.redirect(error.redirectTo, 302);
  }
  if (error instanceof AuthorizationError) {
    return c.html(messagePage(MESSAGES.authorizeInvalid, 'Connection stopped'), 400);
  }
  if (error instanceof CimdFetchError) {
    return c.html(messagePage(MESSAGES.appUnverifiable, 'Connection stopped'), 400);
  }
  throw error;
}

async function connectedApps(oauth: OAuthHelpers, userId: string): Promise<ConnectedApp[]> {
  const { items } = await oauth.listUserGrants(userId);
  return Promise.all(
    items.map(async (grant) => {
      let name = 'Unknown app';
      try {
        name = (await oauth.lookupClient(grant.clientId))?.clientName ?? name;
      } catch {
        // A CIMD document that can't be fetched right now: still list the grant so it can be
        // disconnected.
      }
      let domain: string | null = null;
      if (grant.clientId.startsWith('https://')) {
        try {
          domain = new URL(grant.clientId).host;
        } catch {
          domain = null;
        }
      }
      return {
        grantId: grant.id,
        name,
        domain,
        scopes: grant.scope.map(scopeLabel),
        allowedAt: grant.createdAt,
      };
    }),
  );
}

export function createApp(deps: Deps): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  app.use('*', async (c, next) => {
    await next();
    applySecurityHeaders(c.res.headers);
  });

  // Resolve the session once per request. OAuth protocol endpoints never use it.
  app.use('*', async (c, next) => {
    if (c.req.path.startsWith('/oauth/') || c.req.path.startsWith('/.well-known/')) {
      c.set('session', null);
      await next();
      return;
    }
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

  app.get('/', (c) => (c.get('session') ? c.redirect('/account', 303) : c.html(signInPage())));

  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  app.get('/login', async (c) => {
    if (!(await underRateLimit(c, 'login'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
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
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const now = deps.now();
    const ip = clientIp(c);
    const fail = async (reason: string, status: 400 | 403 = 400) => {
      await audit(c.env.DB, now, status === 403 ? 'login.denied' : 'login.failed', {
        ipPrefix: ip,
        detail: { reason },
      });
      return c.html(
        messagePage(status === 403 ? MESSAGES.notInvited : MESSAGES.signInFailed),
        status,
      );
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

  app.get('/account', async (c) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount', 303);
    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    const notice = c.req.query('disconnected') === '1' ? 'App disconnected.' : undefined;
    return c.html(
      accountPage({
        email: session.user.primaryEmail,
        name: session.user.displayName,
        memberSince: session.user.createdAt,
        apps: await connectedApps(oauth, session.user.id),
        ...(notice ? { notice } : {}),
      }),
    );
  });

  app.post('/account/apps/disconnect', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount', 303);
    const form = await c.req.raw.formData();
    const grantId = form.get('grant');
    if (typeof grantId !== 'string' || grantId.length === 0) {
      return c.redirect('/account', 303);
    }
    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    // revokeGrant is scoped to this user: another user's grant ID does nothing.
    await oauth.revokeGrant(grantId, session.user.id);
    await audit(c.env.DB, deps.now(), 'grant.revoked', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
    });
    return c.redirect('/account?disconnected=1', 303);
  });

  // ---- OAuth authorization server (DESIGN §4.1, §4.3) ------------------------------------

  app.get('/authorize', async (c) => {
    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    let request: AuthRequest;
    try {
      request = await oauth.parseAuthRequest(c.req.raw);
    } catch (error) {
      return authorizeError(c, error);
    }

    // Stricter than the library for all clients, confidential ones included: PKCE with S256,
    // and an explicit resource indicator (RFC 8707), as MCP requires.
    if (!request.codeChallenge || request.codeChallengeMethod !== 'S256') {
      return c.redirect(
        authorizationErrorRedirect(request, 'invalid_request', 'PKCE with S256 is required'),
        302,
      );
    }
    if (!new URL(c.req.url).searchParams.has('resource')) {
      return c.redirect(
        authorizationErrorRedirect(request, 'invalid_target', 'The resource parameter is required'),
        302,
      );
    }

    const session = c.get('session');
    if (!session) {
      const url = new URL(c.req.url);
      return c.redirect(`/login?return_to=${encodeURIComponent(url.pathname + url.search)}`, 303);
    }

    const remember = { secret: c.env.CONSENT_REMEMBER_SECRET, subject: session.user.id };
    if (await oauth.isConsentRemembered(c.req.raw, request, remember)) {
      const { redirectTo } = await oauth.completeAuthorization({
        request,
        userId: session.user.id,
        metadata: {},
        scope: request.scope.filter((s) => s in SCOPES),
        props: { uid: session.user.id, authTime: deps.now() } satisfies GrantProps,
      });
      await audit(c.env.DB, deps.now(), 'consent.reused', {
        actorUserId: session.user.id,
        clientId: request.clientId,
        ipPrefix: clientIp(c),
      });
      return c.redirect(redirectTo, 302);
    }

    let details;
    try {
      details = await oauth.describeConsent(request); // before beginConsent: a failed lookup stores nothing
    } catch (error) {
      return authorizeError(c, error);
    }
    const consent = await oauth.beginConsent(request);
    const trusted = await c.env.DB.prepare('SELECT 1 AS t FROM trusted_clients WHERE client_id = ?')
      .bind(request.clientId)
      .first<{ t: number }>();

    const html = consentPage({
      handle: consent.handle,
      clientName: details.clientName,
      clientDomain: details.clientDomain ?? null,
      trusted: Boolean(trusted),
      redirectHost: details.redirectHost,
      redirectIsLoopback: details.redirectIsLoopback,
      resource: resourceLabel(request.resource ?? c.env.MCP_RESOURCE),
      scopes: details.scope
        .filter((s) => s in SCOPES)
        .map((scope) => ({ scope, label: scopeLabel(scope) })),
      unavailable: details.scope.filter((s) => !(s in SCOPES)),
    });

    // The library's headers bind the consent form to this browser and forbid framing.
    const response = new Response(html, { status: 200, headers: consent.headers });
    response.headers.set('Content-Type', 'text/html; charset=utf-8');
    // No form-action: approving redirects to the client's redirect URI (DESIGN §7).
    response.headers.set('Content-Security-Policy', CONSENT_CSP);
    return response;
  });

  app.post('/authorize', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (!session) return c.html(messagePage(MESSAGES.consentExpired, 'Approval stopped'), 401);

    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    const form = await c.req.raw.clone().formData();
    const handle = form.get('handle');
    if (typeof handle !== 'string') {
      return c.html(messagePage(MESSAGES.consentExpired, 'Approval stopped'), 400);
    }
    const scope = form
      .getAll('scope')
      .filter((s): s is string => typeof s === 'string' && s in SCOPES);

    try {
      if (form.get('decision') !== 'approve' || scope.length === 0) {
        const denied = await oauth.denyConsent(c.req.raw, handle);
        await audit(c.env.DB, deps.now(), 'consent.denied', {
          actorUserId: session.user.id,
          clientId: denied.request.clientId,
          ipPrefix: clientIp(c),
        });
        return new Response(null, { status: 302, headers: denied.headers });
      }

      const remember =
        form.get('remember') === 'on'
          ? { secret: c.env.CONSENT_REMEMBER_SECRET, subject: session.user.id }
          : undefined;
      const approved = await oauth.approveConsent(c.req.raw, handle, {
        scope,
        ...(remember ? { remember } : {}),
      });
      const { redirectTo } = await oauth.completeAuthorization({
        request: approved.request, // from server-side storage, not from the form
        userId: session.user.id,
        metadata: {},
        scope: approved.request.scope,
        props: { uid: session.user.id, authTime: deps.now() } satisfies GrantProps,
      });
      await audit(c.env.DB, deps.now(), 'consent.approved', {
        actorUserId: session.user.id,
        clientId: approved.request.clientId,
        ipPrefix: clientIp(c),
        detail: { scope: approved.request.scope.join(' ') },
      });
      approved.headers.set('Location', redirectTo);
      return new Response(null, { status: 302, headers: approved.headers });
    } catch (error) {
      if (error instanceof AuthorizationError) {
        return c.html(messagePage(MESSAGES.consentExpired, 'Approval stopped'), 400);
      }
      throw error;
    }
  });

  // Metadata, token endpoint and revocation belong to the library.
  app.all('/oauth/*', (c) => authorizationServer(c.env).fetch(c.req.raw, c.env, workerCtx(c)));
  app.get('/.well-known/*', (c) =>
    authorizationServer(c.env).fetch(c.req.raw, c.env, workerCtx(c)),
  );

  app.notFound((c) =>
    (c.req.header('Accept') ?? '').includes('text/html')
      ? c.html(notFoundPage(), 404)
      : c.json({ error: 'not_found' }, 404),
  );

  app.onError((err, c) => {
    // Never echo error details to the client; they may contain request data.
    console.error('unhandled error', err.name);
    return c.json({ error: 'server_error' }, 500);
  });

  return app;
}
