import {
  AuthorizationError,
  CimdFetchError,
  authorizationErrorRedirect,
  type AuthRequest,
  type OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { Hono } from 'hono';
import type { JWTVerifyGetKey } from 'jose';
import { deleteAccount, exportAccount } from './account';
import { deliverDeletionNotices } from './deletion-notices';
import { exportFromServices } from './service-exports';
import { audit } from './audit';
import { hmacHex, pkceChallenge, sha256Hex, timingSafeEqual } from './crypto';
import { GoogleSignInError, buildGoogleAuthUrl, exchangeCode, verifyGoogleIdToken } from './google';
import { LOGIN_TX_TTL_SECONDS, consumeLoginTx, createLoginTx } from './login-tx';
import { isStepUpFresh, listFactors, mfaGate, type MfaGate } from './mfa';
import { registerMfaRoutes } from './mfa-routes';
import { registerAdminRoutes } from './admin';
import { ACR_AAL2, authorizationServer, type GrantProps } from './oauth';
import { ALL_SCOPES, scopeLabel, scopesFor, serviceForResource, type Service } from './services';
import {
  MESSAGES,
  accountDeletedPage,
  accountPage,
  consentPage,
  deleteAccountPage,
  messagePage,
  notFoundPage,
  signInPage,
  type ConnectedApp,
  type Message,
} from './pages';
import {
  CONSENT_APPROVALS_COOKIE,
  LOGIN_TX_COOKIE,
  SESSION_COOKIE,
  clearCookie,
  clientIp,
  isSameOrigin,
  readCookie,
  setCookie,
  underRateLimit,
  workerCtx,
  type AppEnv,
  type AppContext,
} from './http';
import { safeReturnTo } from './return-to';
import { CONSENT_CSP, applySecurityHeaders } from './security-headers';
import { createSession, deleteSession, getSession } from './sessions';
import { allowlistMatch, isUserActive, pinAllowlistToSubject, upsertGoogleUser } from './users';

/** External dependencies, injectable so tests can stand in for Google. */
export interface Deps {
  fetch: typeof fetch;
  googleJwks: JWTVerifyGetKey;
  /** Current time in Unix seconds. */
  now: () => number;
}

/** Paths a session may use before its second-factor gate is passed (DESIGN §4.7). */
function gateAllows(gate: Exclude<MfaGate, null>, path: string): boolean {
  const always = ['/mfa', '/logout', '/login', '/callback/google', '/healthz', '/account/deleted'];
  if (always.includes(path) || path.startsWith('/mfa/')) return true;
  if (path.startsWith('/oauth/') || path.startsWith('/.well-known/')) return true;
  if (gate === 'enrol') {
    // Enrolling, and the data-protection rights, stay available without a factor.
    return (
      path === '/account/security' ||
      path.startsWith('/account/security/') ||
      path === '/account/export' ||
      path === '/account/delete'
    );
  }
  return false;
}

/**
 * The library grants whatever supported scopes the consent form submits. The page therefore
 * carries the scopes it offered, keyed to its single-use handle, and only those can be approved:
 * never more than the app asked for, never another service's.
 */
function offeredScopesMac(env: Env, handle: string, offered: readonly string[]): Promise<string> {
  return hmacHex(env.SESSION_PEPPER, `consent-offered:${handle}:${offered.join(' ')}`);
}

/** How a service reads on the consent page: what it is, then the host it lives on. */
function resourceLabel(service: Service, resource: string): string {
  return `${service.name} (${new URL(resource).host})`;
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

  // Second factor: a session that must pass a challenge, or enrol first, can do nothing else.
  app.use('*', async (c, next) => {
    const session = c.get('session');
    const gate = session ? mfaGate(c.env, session) : null;
    if (!gate || gateAllows(gate, c.req.path)) {
      await next();
      return;
    }
    if (c.req.method !== 'GET') return c.json({ error: 'second_factor_required' }, 403);
    const url = new URL(c.req.url);
    const target = gate === 'challenge' ? '/mfa' : '/account/security';
    return c.redirect(`${target}?return_to=${encodeURIComponent(url.pathname + url.search)}`, 303);
  });

  app.get('/', (c) => (c.get('session') ? c.redirect('/account', 303) : c.html(signInPage())));

  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  app.get('/login', async (c) => {
    if (!(await underRateLimit(c, 'login'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    }
    const now = deps.now();
    const returnTo = safeReturnTo(c.req.query('return_to'));
    // reauth=1: sign in with Google again even though signed in (before adding a first factor).
    if (c.get('session') && c.req.query('reauth') !== '1') return c.redirect(returnTo, 303);

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

    // Re-authentication before deletion ends differently from a sign-in (DESIGN §6.3).
    const deleting = tx.purpose === 'delete_account';
    const stop = async (
      reason: string,
      message: Message = MESSAGES.deletionNotConfirmed,
      status: 400 | 403 | 500 = 400,
    ) => {
      await audit(c.env.DB, now, 'account.deletion_stopped', {
        actorUserId: tx.userId,
        ipPrefix: ip,
        detail: { reason },
      });
      return c.html(messagePage(message, 'Deletion stopped'), status);
    };

    if (c.req.query('error')) return deleting ? stop('google_error') : fail('google_error');
    const code = c.req.query('code');
    if (!code) return deleting ? stop('code_missing') : fail('code_missing');

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
      const reason = error instanceof GoogleSignInError ? error.reason : 'unexpected';
      return deleting ? stop(reason) : fail(reason);
    }

    if (deleting) {
      // The same browser session that asked, and the Google account linked to it.
      const session = c.get('session');
      if (!session || session.user.id !== tx.userId) return stop('session_changed');
      const linked = await c.env.DB.prepare(
        "SELECT 1 AS ok FROM identities WHERE user_id = ? AND provider = 'google' AND subject = ?",
      )
        .bind(session.user.id, identity.subject)
        .first<{ ok: number }>();
      if (!linked) return stop('different_account', MESSAGES.deletionWrongAccount, 403);

      const oauth = authorizationServer(c.env).getOAuthApi(c.env);
      try {
        await deleteAccount(c.env.DB, oauth, session.user.id, now, ip);
        // Tell every service now; the cron retries whatever doesn't go through.
        workerCtx(c).waitUntil(deliverDeletionNotices(c.env, now));
      } catch (error) {
        console.error('account deletion failed', error instanceof Error ? error.name : 'unknown');
        return stop('deletion_error', MESSAGES.deletionFailed, 500);
      }
      clearCookie(c, SESSION_COOKIE);
      clearCookie(c, CONSENT_APPROVALS_COOKIE);
      return c.redirect('/account/deleted', 303);
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
        factors: await listFactors(c.env.DB, session.user.id),
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

  // ---- Data-subject rights (DATA_PROTECTION §6, DESIGN §4.5) ------------------------------

  app.get('/account/export', async (c) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fexport', 303);
    const now = deps.now();
    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    const [account, services] = await Promise.all([
      exportAccount(c.env.DB, oauth, session.user.id, session.idHash, now),
      exportFromServices(c.env, session.user.id),
    ]);
    const data = { ...account, services };
    await audit(c.env.DB, now, 'account.exported', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
    });
    const date = new Date(now * 1000).toISOString().slice(0, 10);
    return new Response(`${JSON.stringify(data, null, 2)}\n`, {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="2earl-account-${date}.json"`,
      },
    });
  });

  app.get('/account/delete', async (c) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fdelete', 303);
    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    const { items } = await oauth.listUserGrants(session.user.id, { limit: 1000 });
    const invited = await c.env.DB.prepare(
      `SELECT 1 AS ok FROM allowlist a JOIN identities i
         ON i.provider = 'google' AND a.kind = 'google_sub' AND a.value = i.subject
       WHERE i.user_id = ?`,
    )
      .bind(session.user.id)
      .first<{ ok: number }>();
    return c.html(
      deleteAccountPage({
        email: session.user.primaryEmail,
        appCount: items.length,
        invited: Boolean(invited),
      }),
    );
  });

  app.post('/account/delete', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'delete'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts, 'Deletion stopped'), 429);
    }
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fdelete', 303);
    const form = await c.req.raw.formData();
    if (form.get('confirm') !== 'on') return c.redirect('/account/delete', 303);
    // With a second factor, deletion also needs it, used in the last 5 minutes (THREAT_MODEL R9).
    if (session.hasFactor && !isStepUpFresh(session, deps.now())) {
      return c.redirect('/mfa?step_up=1&return_to=%2Faccount%2Fdelete', 303);
    }

    // Deletion happens only after Google confirms the linked account in this browser.
    const now = deps.now();
    const tx = await createLoginTx(c.env.DB, c.env.SESSION_PEPPER, now, null, {
      purpose: 'delete_account',
      userId: session.user.id,
    });
    setCookie(c, LOGIN_TX_COOKIE, tx.cookieValue, LOGIN_TX_TTL_SECONDS);
    await audit(c.env.DB, now, 'account.deletion_started', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
    });
    return c.redirect(
      buildGoogleAuthUrl({
        clientId: c.env.GOOGLE_CLIENT_ID,
        redirectUri: `${c.env.ISSUER}/callback/google`,
        state: tx.state,
        nonce: tx.nonce,
        codeChallenge: await pkceChallenge(tx.pkceVerifier),
        loginHint: session.user.primaryEmail,
      }),
      302,
    );
  });

  app.get('/account/deleted', (c) =>
    c.get('session') ? c.redirect('/account', 303) : c.html(accountDeletedPage()),
  );

  registerMfaRoutes(app, deps);
  registerAdminRoutes(app, deps);

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
    // Each service has its own permissions (src/services.ts): only that service's scopes count.
    const service = serviceForResource(c.env, request.resource);
    if (!service || request.resource === undefined) {
      return c.redirect(
        authorizationErrorRedirect(request, 'invalid_target', 'Unknown resource'),
        302,
      );
    }

    const session = c.get('session');
    if (!session) {
      const url = new URL(c.req.url);
      return c.redirect(`/login?return_to=${encodeURIComponent(url.pathname + url.search)}`, 303);
    }

    // An app can require a recent second factor, e.g. for its admin area. login asks for it
    // first; the app checks `aal2At` in the grant's props, so this step is for the user, not the
    // only check.
    const requested = new URL(c.req.url);
    const acr = (requested.searchParams.get('acr_values') ?? '').split(' ');
    if (acr.includes(ACR_AAL2) && !isStepUpFresh(session, deps.now())) {
      const back = encodeURIComponent(requested.pathname + requested.search);
      return c.redirect(
        session.hasFactor
          ? `/mfa?step_up=1&return_to=${back}`
          : `/account/security?return_to=${back}`,
        303,
      );
    }

    const remember = { secret: c.env.CONSENT_REMEMBER_SECRET, subject: session.user.id };
    if (await oauth.isConsentRemembered(c.req.raw, request, remember)) {
      const { redirectTo } = await oauth.completeAuthorization({
        request,
        userId: session.user.id,
        metadata: {},
        scope: scopesFor(service, request.scope),
        props: {
          uid: session.user.id,
          authTime: deps.now(),
          aal2At: session.aal === 'aal2' ? session.aal2At : null,
        } satisfies GrantProps,
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

    const offered = scopesFor(service, details.scope);
    const html = consentPage({
      handle: consent.handle,
      offeredMac: await offeredScopesMac(c.env, consent.handle, offered),
      clientName: details.clientName,
      clientDomain: details.clientDomain ?? null,
      trusted: Boolean(trusted),
      redirectHost: details.redirectHost,
      redirectIsLoopback: details.redirectIsLoopback,
      resource: resourceLabel(service, request.resource),
      scopes: scopesFor(service, details.scope).map((scope) => ({
        scope,
        label: scopeLabel(scope),
      })),
      unavailable: details.scope.filter((s) => !Object.hasOwn(service.scopes, s)),
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
    const offeredField = form.get('offered');
    const offered = typeof offeredField === 'string' ? offeredField.split(' ').filter(Boolean) : [];
    const mac = form.get('offered_mac');
    if (
      typeof mac !== 'string' ||
      !timingSafeEqual(mac, await offeredScopesMac(c.env, handle, offered))
    ) {
      return c.html(messagePage(MESSAGES.consentExpired, 'Approval stopped'), 400);
    }
    const scope = form
      .getAll('scope')
      .filter(
        (s): s is string =>
          typeof s === 'string' && Object.hasOwn(ALL_SCOPES, s) && offered.includes(s),
      );

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
      // The resource comes from server-side storage; a scope of another service never passes.
      const approvedService = serviceForResource(c.env, approved.request.resource);
      const approvedScope = approvedService
        ? scopesFor(approvedService, approved.request.scope)
        : [];
      if (approvedScope.length === 0) {
        return c.html(messagePage(MESSAGES.consentExpired, 'Approval stopped'), 400);
      }
      const { redirectTo } = await oauth.completeAuthorization({
        request: approved.request, // from server-side storage, not from the form
        userId: session.user.id,
        metadata: {},
        scope: approvedScope,
        props: {
          uid: session.user.id,
          authTime: deps.now(),
          aal2At: session.aal === 'aal2' ? session.aal2At : null,
        } satisfies GrantProps,
      });
      await audit(c.env.DB, deps.now(), 'consent.approved', {
        actorUserId: session.user.id,
        clientId: approved.request.clientId,
        ipPrefix: clientIp(c),
        detail: { scope: approvedScope.join(' ') },
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
