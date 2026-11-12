import {
  AuthorizationError,
  CimdFetchError,
  authorizationErrorRedirect,
  type AuthRequest,
  type OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { Hono } from 'hono';
import type { JWTVerifyGetKey } from 'jose';
import { exportAccount } from './account';
import { exportFromServices } from './service-exports';
import { registerOrgRoutes } from './org-routes';
import { registerScimRoutes } from './scim-routes';
import { registerSamlRoutes } from './saml-routes';
import { DpopError, dpopOf, verifyDpopProof, withDpop } from './dpop';
import { pushedRequestUrl, registerParRoute } from './par';
import { membershipsOf, ownershipPlan } from './orgs';
import { audit } from './audit';
import { hmacHex, pkceChallenge, timingSafeEqual } from './crypto';
import { GoogleSignInError, buildGoogleAuthUrl, exchangeCode, verifyGoogleIdToken } from './google';
import { LOGIN_TX_TTL_SECONDS, consumeLoginTx, createLoginTx } from './login-tx';
import { isStepUpFresh, listFactors, listPasskeys, mfaGate, type MfaGate } from './mfa';
import { mfaHtml, registerMfaRoutes } from './mfa-routes';
import { isOwnerUser, registerAdminRoutes } from './admin';
import { ACR_AAL2, authorizationServer, type GrantProps } from './oauth';
import { pairwiseSubject, sectorFor } from './oidc';
import { registerOidcRoutes, withIdToken } from './oidc-routes';
import { registerIntrospection } from './introspection';
import { DEVICE_GRANT, deviceTokenResponse, registerDeviceRoutes } from './device';
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
import { deleteSession, getSession, type Session } from './sessions';
import { registerEmailRoutes, sendCode } from './email-routes';
import { registerMethodRoutes } from './method-routes';
import { registerPasskeyRoutes } from './passkey-routes';
import { signupMode } from './settings';
import { finishDeletion, notifyLater, startSession } from './sign-in';
import {
  accountWithEmail,
  addGoogleIdentity,
  allowlistMatch,
  isUserActive,
  listIdentities,
  pinAllowlistToSubject,
  upsertGoogleUser,
  userForGoogle,
} from './users';

/** A token response for a DPoP-bound access token says so (RFC 9449 §5). */
async function asDpopTokenType(response: Response): Promise<Response> {
  if (!response.ok) return response;
  const body = await response.json<Record<string, unknown>>();
  const headers = new Headers(response.headers);
  headers.delete('Content-Length');
  return new Response(JSON.stringify({ ...body, token_type: 'DPoP' }), {
    status: response.status,
    headers,
  });
}

/** External dependencies, injectable so tests can stand in for Google. */
export interface Deps {
  fetch: typeof fetch;
  googleJwks: JWTVerifyGetKey;
  /** Current time in Unix seconds. */
  now: () => number;
}

/** Paths a session may use before its second-factor gate is passed (DESIGN §4.7). */
function gateAllows(gate: Exclude<MfaGate, null>, path: string): boolean {
  const always = [
    '/mfa',
    '/logout',
    '/oidc/logout',
    '/userinfo',
    '/login',
    '/callback/google',
    '/healthz',
    '/account/deleted',
  ];
  if (always.includes(path) || path.startsWith('/mfa/') || path.startsWith('/login/')) return true;
  // SAML sign-in replies (DESIGN §4.17) start a new session, like /callback/google.
  if (path.startsWith('/saml/')) return true;
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

/**
 * OpenID Connect's own authorization errors (OIDC Core §3.1.2.6), for `prompt=none`. The
 * library's helper knows only OAuth's codes; this adds `iss` and `state` the same way.
 */
function oidcErrorRedirect(
  request: AuthRequest,
  code: 'login_required' | 'consent_required' | 'interaction_required',
): string {
  const url = new URL(request.redirectUri);
  url.searchParams.set('error', code);
  if (request.state) url.searchParams.set('state', request.state);
  if (request.issuer) url.searchParams.set('iss', request.issuer);
  return url.toString();
}

/**
 * The OpenID Connect `nonce` travels through the consent form like the offered scopes: bound to
 * the single-use handle, so a form can't swap in another value.
 */
function nonceMac(env: Env, handle: string, nonce: string): Promise<string> {
  return hmacHex(env.SESSION_PEPPER, `consent-nonce:${handle}:${nonce}`);
}

/** Grant properties: the account, when, and for OpenID Connect what the ID token needs. */
async function grantProps(
  c: AppContext,
  now: number,
  session: Session,
  request: AuthRequest,
  scope: readonly string[],
  nonce: string | null,
): Promise<GrantProps> {
  const props: GrantProps = {
    uid: session.user.id,
    authTime: now,
    aal2At: session.aal === 'aal2' ? session.aal2At : null,
    signedInAt: session.createdAt,
    method: session.method,
  };
  if (scope.includes('openid')) {
    props.oidc = {
      sub: await pairwiseSubject(
        c.env.DB,
        now,
        session.user.id,
        sectorFor(request.clientId, request.redirectUri),
      ),
      nonce,
    };
  }
  return props;
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
    if (
      c.req.path.startsWith('/oauth/') ||
      c.req.path.startsWith('/.well-known/') ||
      c.req.path === '/userinfo'
    ) {
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

  app.get('/', async (c) =>
    c.get('session')
      ? c.redirect('/account', 303)
      : mfaHtml(signInPage({ mode: await signupMode(c.env) })),
  );

  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  // Sign in or sign up: Google, or a code by email (DESIGN §4.9). reauth=1: a signed-in user
  // proves it's them again, with the methods their account has.
  app.get('/login', async (c) => {
    const returnTo = c.req.query('return_to') ? safeReturnTo(c.req.query('return_to')) : null;
    const session = c.get('session');
    const reauth = c.req.query('reauth') === '1';
    if (session && !reauth) return c.redirect(safeReturnTo(returnTo), 303);
    let methods: { google: boolean; email: string | null; passkey: boolean } | null = null;
    if (session && reauth) {
      const identities = await listIdentities(c.env, session.user.id);
      methods = {
        google: identities.some((i) => i.provider === 'google'),
        email: identities.find((i) => i.provider === 'email')?.email ?? null,
        passkey: (await listPasskeys(c.env.DB, session.user.id)).length > 0,
      };
    }
    return mfaHtml(signInPage({ returnTo, mode: await signupMode(c.env), reauth: methods }));
  });

  app.get('/login/google', async (c) => {
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
      return finishDeletion(c, now, session.user.id, stop);
    }

    // Adding Google to the signed-in account (DESIGN §4.9): the same browser session that asked.
    if (tx.purpose === 'link_google') {
      const session = c.get('session');
      if (!session || session.user.id !== tx.userId) {
        return c.html(messagePage(MESSAGES.linkNotConfirmed, 'Nothing changed'), 400);
      }
      const owner = await userForGoogle(c.env.DB, identity.subject);
      if (owner && owner !== session.user.id) {
        return c.html(messagePage(MESSAGES.googleTaken, 'Nothing changed'), 409);
      }
      // An address that signs in to another account by email code stays that account's (B3).
      const clash = owner
        ? null
        : await accountWithEmail(c.env.DB, identity.email, session.user.id);
      if (clash?.provider === 'email') {
        return c.html(messagePage(MESSAGES.emailTaken, 'Nothing changed'), 409);
      }
      if (!owner) {
        await addGoogleIdentity(c.env.DB, now, session.user.id, identity);
        await audit(c.env.DB, now, 'identity.added', {
          actorUserId: session.user.id,
          ipPrefix: ip,
          detail: { provider: 'google' },
        });
        notifyLater(c, session.user.id, {
          kind: 'method_added',
          method: `the Google account ${identity.email}`,
        });
      }
      return c.redirect('/account?added=google', 303);
    }

    // A new account: sign-up must be open, or the account invited; and an address that already
    // signs in with an email code stays that account's (no joining by address, THREAT_MODEL B3).
    const known = await userForGoogle(c.env.DB, identity.subject);
    if (!known) {
      const clash = await accountWithEmail(c.env.DB, identity.email);
      if (clash?.provider === 'email') {
        await audit(c.env.DB, now, 'login.denied', {
          ipPrefix: ip,
          detail: { reason: 'email_has_account' },
        });
        return c.html(messagePage(MESSAGES.emailHasAccount), 409);
      }
    }
    if ((await signupMode(c.env)) === 'invite') {
      const match = await allowlistMatch(c.env.DB, identity);
      if (!match && !known) return fail('not_allowlisted', 403);
      if (!match && known) {
        // An account made while sign-up was open keeps working after it closes.
      } else if (match === 'email') {
        await pinAllowlistToSubject(c.env.DB, now, identity);
        await audit(c.env.DB, now, 'allowlist.pinned', { ipPrefix: ip });
      }
    }

    const { userId, created } = await upsertGoogleUser(c.env.DB, now, identity);
    if (created) await audit(c.env.DB, now, 'user.created', { actorUserId: userId, ipPrefix: ip });

    if (!(await isUserActive(c.env.DB, userId))) return fail('user_suspended', 403);

    return startSession(c, now, userId, tx.returnTo, { welcome: created, method: 'google' });
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
    const notices: Record<string, string> = {
      disconnected: 'App disconnected.',
      google: 'You can now sign in with Google too.',
      email: 'You can now sign in with a code sent to that address too.',
      removed: 'Sign-in method removed.',
      name: 'Name saved.',
      left: 'You left the organization.',
      org_deleted: 'Organization deleted.',
      declined: 'Invitation declined.',
    };
    const key =
      c.req.query('disconnected') === '1'
        ? 'disconnected'
        : (c.req.query('added') ??
          (c.req.query('removed') === '1' ? 'removed' : c.req.query('saved')));
    const notice = key ? notices[key] : undefined;
    return c.html(
      accountPage({
        email: session.user.primaryEmail,
        name: session.user.displayName,
        memberSince: session.user.createdAt,
        apps: await connectedApps(oauth, session.user.id),
        factors: await listFactors(c.env.DB, session.user.id),
        isOwner: await isOwnerUser(c.env, session.user.id),
        methods: await listIdentities(c.env, session.user.id),
        orgs: await membershipsOf(c.env.DB, session.user.id),
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
    const identities = await listIdentities(c.env, session.user.id);
    return c.html(
      deleteAccountPage({
        email: session.user.primaryEmail,
        appCount: items.length,
        invited: Boolean(invited),
        confirmWith: {
          google: identities.some((i) => i.provider === 'google'),
          email: identities.find((i) => i.provider === 'email')?.email ?? null,
        },
        organizations: await ownershipPlan(c.env.DB, session.user.id),
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

    const now = deps.now();
    const identities = await listIdentities(c.env, session.user.id);
    const emailMethod = identities.find((i) => i.provider === 'email')?.email ?? null;
    const hasGoogle = identities.some((i) => i.provider === 'google');
    // With a code to the account's own address, when that's how it signs in (DESIGN §4.9).
    if (emailMethod && (form.get('method') === 'email' || !hasGoogle)) {
      await audit(c.env.DB, now, 'account.deletion_started', {
        actorUserId: session.user.id,
        ipPrefix: clientIp(c),
      });
      return sendCode(c, now, {
        email: emailMethod,
        purpose: 'delete_account',
        userId: session.user.id,
      });
    }

    // Deletion happens only after Google confirms the linked account in this browser.
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

  registerEmailRoutes(app, deps);
  registerMethodRoutes(app, deps);
  registerMfaRoutes(app, deps);
  registerPasskeyRoutes(app, deps);
  registerAdminRoutes(app, deps);
  registerOrgRoutes(app, deps);
  registerScimRoutes(app, deps);
  registerSamlRoutes(app, deps);

  // ---- OAuth authorization server (DESIGN §4.1, §4.3) ------------------------------------

  app.get('/authorize', async (c) => {
    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    // A pushed request (RFC 9126, DESIGN §4.15): the parameters come from what the client pushed,
    // never from the browser's URL. Redirects to sign in keep the short URL with `request_uri`.
    const original = new URL(c.req.url);
    const pushed = await pushedRequestUrl(c.env, deps.now(), original);
    if (pushed === 'invalid') return c.html(messagePage(MESSAGES.authorizeInvalid), 400);
    const effective = pushed ?? original;
    let request: AuthRequest;
    try {
      request = await oauth.parseAuthRequest(pushed ? new Request(pushed, c.req.raw) : c.req.raw);
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
    const query = effective.searchParams;
    const openid = request.scope.includes('openid');
    // An OpenID Connect sign-in may leave out `resource`: its token is for UserInfo (DESIGN
    // §4.11). Every other request must name its resource (RFC 8707), as MCP requires.
    if (!query.has('resource') && !openid) {
      return c.redirect(
        authorizationErrorRedirect(request, 'invalid_target', 'The resource parameter is required'),
        302,
      );
    }
    const nonce = query.get('nonce');
    if (nonce !== null && (nonce.length === 0 || nonce.length > 255)) {
      return c.redirect(
        authorizationErrorRedirect(request, 'invalid_request', 'nonce must be 1 to 255 characters'),
        302,
      );
    }
    const prompt = new Set((query.get('prompt') ?? '').split(' ').filter(Boolean));
    if (prompt.has('none') && prompt.size > 1) {
      return c.redirect(
        authorizationErrorRedirect(request, 'invalid_request', 'prompt=none stands alone'),
        302,
      );
    }
    const maxAgeText = query.get('max_age');
    const maxAge = maxAgeText === null ? null : Number(maxAgeText);
    if (maxAge !== null && (!Number.isInteger(maxAge) || maxAge < 0)) {
      return c.redirect(
        authorizationErrorRedirect(request, 'invalid_request', 'max_age must be a whole number'),
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

    if (openid && !request.scope.every((s) => Object.hasOwn(service.scopes, s))) {
      // An OpenID Connect request is for the account alone: never mixed with a service's scopes.
      return c.redirect(
        authorizationErrorRedirect(
          request,
          'invalid_scope',
          'openid can’t be combined with service scopes',
        ),
        302,
      );
    }
    if (service.id === 'login' && !openid) {
      return c.redirect(
        authorizationErrorRedirect(request, 'invalid_scope', 'The openid scope is required'),
        302,
      );
    }

    const session = c.get('session');
    if (!session) {
      if (prompt.has('none')) {
        return c.redirect(oidcErrorRedirect(request, 'login_required'), 302);
      }
      return c.redirect(
        `/login?return_to=${encodeURIComponent(original.pathname + original.search)}`,
        303,
      );
    }

    // prompt=login, or a sign-in older than max_age: the person signs in again first. The
    // request comes back without `login` in prompt, so it doesn't ask twice.
    const now = deps.now();
    if (prompt.has('login') || (maxAge !== null && now - session.createdAt > maxAge)) {
      if (prompt.has('none')) {
        return c.redirect(oidcErrorRedirect(request, 'login_required'), 302);
      }
      // A pushed request comes back as a plain one here: its prompt has to change.
      const back = new URL(effective);
      prompt.delete('login');
      if (prompt.size > 0) back.searchParams.set('prompt', [...prompt].join(' '));
      else back.searchParams.delete('prompt');
      back.searchParams.delete('max_age');
      return c.redirect(
        `/login?reauth=1&return_to=${encodeURIComponent(back.pathname + back.search)}`,
        303,
      );
    }

    // An app can require a recent second factor, e.g. for its admin area. login asks for it
    // first; the app checks `aal2At` in the grant's props, so this step is for the user, not the
    // only check.
    const acr = (query.get('acr_values') ?? '').split(' ');
    if (acr.includes(ACR_AAL2) && !isStepUpFresh(session, deps.now())) {
      if (prompt.has('none')) {
        return c.redirect(oidcErrorRedirect(request, 'interaction_required'), 302);
      }
      const back = encodeURIComponent(original.pathname + original.search);
      return c.redirect(
        session.hasFactor
          ? `/mfa?step_up=1&return_to=${back}`
          : `/account/security?return_to=${back}`,
        303,
      );
    }

    const remember = { secret: c.env.CONSENT_REMEMBER_SECRET, subject: session.user.id };
    if (!prompt.has('consent') && (await oauth.isConsentRemembered(c.req.raw, request, remember))) {
      const scope = scopesFor(service, request.scope);
      const { redirectTo } = await oauth.completeAuthorization({
        request,
        userId: session.user.id,
        metadata: {},
        scope,
        props: await grantProps(c, deps.now(), session, request, scope, nonce),
      });
      await audit(c.env.DB, deps.now(), 'consent.reused', {
        actorUserId: session.user.id,
        clientId: request.clientId,
        ipPrefix: clientIp(c),
      });
      return c.redirect(redirectTo, 302);
    }

    if (prompt.has('none')) {
      return c.redirect(oidcErrorRedirect(request, 'consent_required'), 302);
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
      nonce:
        nonce === null ? null : { value: nonce, mac: await nonceMac(c.env, consent.handle, nonce) },
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
    // Signing in is what an OpenID Connect app asked for: `openid` can't be left out, only the
    // name and address can.
    if (offered.includes('openid') && scope.length > 0 && !scope.includes('openid')) {
      scope.unshift('openid');
    }
    const nonceField = form.get('nonce');
    const nonceMacField = form.get('nonce_mac');
    let nonce: string | null = null;
    if (typeof nonceField === 'string') {
      if (
        typeof nonceMacField !== 'string' ||
        !timingSafeEqual(nonceMacField, await nonceMac(c.env, handle, nonceField))
      ) {
        return c.html(messagePage(MESSAGES.consentExpired, 'Approval stopped'), 400);
      }
      nonce = nonceField;
    }

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
      // A notice by email the first time an app is allowed, not on every later sign-in with it.
      const earlier = await oauth.listUserGrants(session.user.id, { limit: 1000 });
      const firstTime = !earlier.items.some((g) => g.clientId === approved.request.clientId);
      const { redirectTo } = await oauth.completeAuthorization({
        request: approved.request, // from server-side storage, not from the form
        userId: session.user.id,
        metadata: {},
        scope: approvedScope,
        props: await grantProps(c, deps.now(), session, approved.request, approvedScope, nonce),
      });
      await audit(c.env.DB, deps.now(), 'consent.approved', {
        actorUserId: session.user.id,
        clientId: approved.request.clientId,
        ipPrefix: clientIp(c),
        detail: { scope: approvedScope.join(' ') },
      });
      if (firstTime) {
        let app = 'An app';
        try {
          app = (await oauth.lookupClient(approved.request.clientId))?.clientName ?? app;
        } catch {
          // The app's details can't be loaded now; the notice still goes out.
        }
        notifyLater(c, session.user.id, { kind: 'app_connected', app });
      }
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
  // The token endpoint's limit lives here, not in the zone's per-address rule: every Claude user
  // refreshes from the same few Anthropic addresses (access tokens last 15 minutes), so a coarse
  // per-address limit would lock them all out together. Guessing is not possible here (a code
  // needs its PKCE verifier; refresh tokens are long and random), so this only bounds load.
  app.post('/oauth/token', async (c) => {
    const { success } = await c.env.TOKEN_RATE_LIMITER.limit({ key: clientIp(c) ?? 'unknown' });
    if (!success) {
      return c.json(
        { error: 'temporarily_unavailable', error_description: 'Too many requests; retry shortly' },
        429,
        { 'Retry-After': '10' },
      );
    }
    const form = await c.req.raw
      .clone()
      .formData()
      .catch(() => null);
    const grantType = form?.get('grant_type');
    const now = deps.now();
    // DPoP (RFC 9449, DESIGN §4.15): a proof binds what this request issues to the client's key.
    let exchangeEnv: Env = c.env;
    const proof = c.req.header('DPoP');
    if (proof !== undefined) {
      try {
        const { jkt } = await verifyDpopProof(c.env.DB, now, {
          proof,
          method: 'POST',
          url: `${c.env.ISSUER}/oauth/token`,
        });
        exchangeEnv = withDpop(c.env, jkt);
      } catch (error) {
        if (!(error instanceof DpopError)) throw error;
        return c.json({ error: 'invalid_dpop_proof', error_description: error.description }, 400, {
          'Cache-Control': 'no-store',
        });
      }
    }
    // The device grant (RFC 8628) is login's own, around the library's code flow (§4.13).
    const response =
      grantType === DEVICE_GRANT && form
        ? await deviceTokenResponse(c, now, form, exchangeEnv)
        : await withIdToken(
            c.env,
            now,
            typeof grantType === 'string' ? grantType : null,
            // OpenID Connect: an ID token beside the access token when the grant includes `openid`.
            await authorizationServer(c.env).fetch(c.req.raw, exchangeEnv, workerCtx(c)),
          );
    return dpopOf(exchangeEnv)?.accessTokenBound ? asDpopTokenType(response) : response;
  });
  registerIntrospection(app, deps);
  registerParRoute(app, deps);
  registerDeviceRoutes(app, deps);
  app.all('/oauth/*', (c) => authorizationServer(c.env).fetch(c.req.raw, c.env, workerCtx(c)));
  registerOidcRoutes(app, deps);
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
