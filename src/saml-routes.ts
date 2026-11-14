import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import { hmacHex, randomToken } from './crypto';
import { normaliseEmail } from './directory';
import {
  clearCookie,
  clientIp,
  readCookie,
  setCookie,
  underRateLimit,
  type AppContext,
  type AppEnv,
} from './http';
import { addressAtVerifiedDomain } from './org-domains';
import { MESSAGES, messagePage, notFoundPage, ssoPage, type Message } from './pages';
import { safeReturnTo } from './return-to';
import {
  MAX_RESPONSE_LENGTH,
  SAML_REQUEST_TTL_SECONDS,
  assertedEmail,
  samlConfig,
  samlFor,
  ssoOrgForEmail,
} from './saml';
import { accountFor } from './scim';
import { signupMode } from './settings';
import { signInRefusal, startSession } from './sign-in';
import {
  OIDC_REQUEST_TTL_SECONDS,
  authorizeRequest,
  discover,
  finishOidc,
  oidcConfig,
  oidcRedirectUri,
  type OrgOidc,
} from './sso-oidc';
import { adoptNewAccount, managingOrgFor } from './managed';
import { createEmailUser, emailInvited, isUserActive } from './users';

/**
 * SAML sign-in routes (DESIGN §4.17). The IdP answers with a cross-site POST, which carries no
 * SameSite=Lax cookie: the response is parked under its RelayState and the sign-in finishes on a
 * same-site GET, where the browser's `__Host-saml_tx` cookie proves it is the browser that started.
 */

const SAML_TX_COOKIE = '__Host-saml_tx';
const OIDC_TX_COOKIE = '__Host-oidc_tx';
const RELAY_STATE = /^[A-Za-z0-9_-]{40,64}$/;

const stateHash = (env: Env, relayState: string) =>
  hmacHex(env.SESSION_PEPPER, `saml-state:${relayState}`);
const browserHash = (env: Env, cookie: string) =>
  hmacHex(env.SESSION_PEPPER, `saml-browser:${cookie}`);

export function registerSamlRoutes(app: Hono<AppEnv>, deps: Deps): void {
  const nowMs = () => deps.now() * 1000;

  const fail = async (
    c: AppContext,
    reason: string,
    orgId: string | null,
    message: Message = MESSAGES.signInFailed,
    status: 400 | 403 = 400,
    provider: 'saml' | 'oidc' = 'saml',
  ) => {
    await audit(c.env.DB, deps.now(), status === 400 ? 'login.failed' : 'login.denied', {
      ipPrefix: clientIp(c),
      detail: { reason, provider, org: orgId },
    });
    return c.html(messagePage(message), status);
  };

  app.get('/login/sso', (c) =>
    c.html(
      ssoPage({
        returnTo: c.req.query('return_to') ? safeReturnTo(c.req.query('return_to')) : null,
      }),
    ),
  );

  app.post('/login/sso', async (c) => {
    if (!(await underRateLimit(c, 'login')))
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    const form = await c.req.raw.formData();
    const raw = form.get('email');
    const returnTo =
      typeof form.get('return_to') === 'string'
        ? safeReturnTo(form.get('return_to') as string)
        : null;
    const email = typeof raw === 'string' ? normaliseEmail(raw) : null;
    if (!email)
      return c.html(
        ssoPage({
          returnTo,
          email: typeof raw === 'string' ? raw : '',
          error: 'Enter your work email address.',
        }),
        400,
      );
    const orgId = await ssoOrgForEmail(c.env.DB, email);
    // OpenID Connect, when that's how the organization signs in (DESIGN §4.20).
    const oidc = orgId ? await oidcConfig(c.env.DB, orgId) : null;
    if (orgId && oidc?.enabled) return startOidc(c, orgId, oidc, email, returnTo);
    const config = orgId ? await samlConfig(c.env.DB, orgId) : null;
    if (!orgId || !config?.enabled) {
      return c.html(
        ssoPage({
          returnTo,
          email,
          error: 'No organization signs in this address with single sign-on. Sign in another way.',
        }),
        404,
      );
    }
    const now = deps.now();
    const relayState = randomToken(32);
    const browser = randomToken(32);
    const flow = await stateHash(c.env, relayState);
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM saml_states WHERE expires_at <= ?').bind(now),
      c.env.DB.prepare('DELETE FROM saml_cache WHERE expires_at <= ?').bind(now),
      c.env.DB.prepare(
        'INSERT INTO saml_states (state_hash, org_id, browser_hash, return_to, expires_at) VALUES (?, ?, ?, ?, ?)',
      ).bind(
        flow,
        orgId,
        await browserHash(c.env, browser),
        returnTo,
        now + SAML_REQUEST_TTL_SECONDS,
      ),
    ]);
    setCookie(c, SAML_TX_COOKIE, browser, SAML_REQUEST_TTL_SECONDS);
    const url = await samlFor(c.env, config, nowMs, flow).getAuthorizeUrlAsync(
      relayState,
      undefined,
      {},
    );
    await audit(c.env.DB, now, 'login.started', {
      ipPrefix: clientIp(c),
      detail: { provider: 'saml', org: orgId },
    });
    return c.redirect(url, 302);
  });

  // The IdP's cross-site POST: park the response, continue same-site.
  app.post('/saml/:org/acs', async (c) => {
    if (!(await underRateLimit(c, 'callback')))
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    const orgId = c.req.param('org');
    const form = await c.req.raw.formData().catch(() => null);
    const response = form?.get('SAMLResponse');
    const relayState = form?.get('RelayState');
    if (
      typeof response !== 'string' ||
      response.length > MAX_RESPONSE_LENGTH ||
      typeof relayState !== 'string' ||
      !RELAY_STATE.test(relayState)
    ) {
      // No RelayState: an IdP-initiated sign-in, which login doesn't accept (THREAT_MODEL L3).
      return fail(c, 'request_invalid', orgId);
    }
    const parked = await c.env.DB.prepare(
      'UPDATE saml_states SET response = ? WHERE state_hash = ? AND org_id = ? AND response IS NULL AND expires_at > ?',
    )
      .bind(response, await stateHash(c.env, relayState), orgId, deps.now())
      .run();
    if (parked.meta.changes === 0) return fail(c, 'transaction_invalid', orgId);
    return c.redirect(`/saml/${encodeURIComponent(orgId)}/acs?rs=${relayState}`, 303);
  });

  app.get('/saml/:org/acs', async (c) => {
    if (!(await underRateLimit(c, 'callback')))
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    const orgId = c.req.param('org');
    const relayState = c.req.query('rs') ?? '';
    const browser = readCookie(c.req.header('Cookie'), SAML_TX_COOKIE);
    clearCookie(c, SAML_TX_COOKIE);
    const now = deps.now();
    const flow = RELAY_STATE.test(relayState) ? await stateHash(c.env, relayState) : null;
    const state =
      flow && browser
        ? await c.env.DB.prepare(
            `DELETE FROM saml_states
             WHERE state_hash = ? AND org_id = ? AND browser_hash = ? AND expires_at > ? AND response IS NOT NULL
             RETURNING response, return_to`,
          )
            .bind(flow, orgId, await browserHash(c.env, browser), now)
            .first<{ response: string; return_to: string | null }>()
        : null;
    if (!state) return fail(c, 'transaction_invalid', orgId);
    const config = await samlConfig(c.env.DB, orgId);
    if (!config?.enabled) return fail(c, 'sso_disabled', orgId);

    let profile;
    try {
      ({ profile } = await samlFor(c.env, config, nowMs, flow ?? '').validatePostResponseAsync({
        SAMLResponse: state.response,
      }));
    } catch (error) {
      console.warn(
        'saml response refused',
        error instanceof Error ? error.message.slice(0, 120) : 'unknown',
      );
      return fail(c, 'assertion_invalid', orgId);
    }
    const email = profile ? assertedEmail(profile) : null;
    return finishSso(c, orgId, email, state.return_to, 'saml');
  });

  /**
   * The end of every single sign-on, SAML or OpenID Connect: the address the organization's
   * provider asserts must be at one of its verified domains (THREAT_MODEL L1); then the account
   * that signs in with it, or a new one.
   */
  async function finishSso(
    c: AppContext,
    orgId: string,
    email: string | null,
    returnTo: string | null,
    method: 'saml' | 'oidc',
  ): Promise<Response> {
    const now = deps.now();
    if (!email || !(await addressAtVerifiedDomain(c.env.DB, orgId, email))) {
      return fail(c, 'address_outside_domain', orgId, MESSAGES.signInFailed, 400, method);
    }

    let userId = await accountFor(c.env.DB, email);
    let created = false;
    if (!userId) {
      // At a domain the organization manages, it vouches for its own people: the sign-up switch
      // doesn't apply (DESIGN §4.18).
      const managing = await managingOrgFor(c.env.DB, email);
      if (
        managing?.orgId !== orgId &&
        (await signupMode(c.env)) === 'invite' &&
        !(await emailInvited(c.env.DB, email))
      ) {
        return fail(c, 'not_allowlisted', orgId, MESSAGES.notInvited, 403, method);
      }
      userId = await createEmailUser(c.env.DB, now, email);
      created = true;
      await audit(c.env.DB, now, 'user.created', { actorUserId: userId, ipPrefix: clientIp(c) });
      await adoptNewAccount(c.env.DB, now, userId, email);
    }
    if (!(await isUserActive(c.env.DB, userId)))
      return fail(c, 'user_suspended', orgId, MESSAGES.accountSuspended, 403, method);
    // The organization's networks (DESIGN §4.19) apply to single sign-on too.
    const refusal = await signInRefusal(c, userId, method);
    if (refusal) {
      await audit(c.env.DB, now, 'login.denied', {
        actorUserId: userId,
        ipPrefix: clientIp(c),
        detail: { reason: 'policy', method, org: orgId },
      });
      return c.html(messagePage(refusal), 403);
    }
    return startSession(c, now, userId, returnTo, { welcome: created, method });
  }

  // ---- OpenID Connect (DESIGN §4.20) ------------------------------------------------------------

  async function startOidc(
    c: AppContext,
    orgId: string,
    config: OrgOidc,
    email: string,
    returnTo: string | null,
  ): Promise<Response> {
    const now = deps.now();
    let discovery;
    try {
      discovery = await discover(deps.fetch, config.issuer);
    } catch (error) {
      console.warn('oidc discovery failed', error instanceof Error ? error.message : 'unknown');
      return fail(c, 'provider_unreachable', orgId, MESSAGES.signInFailed, 400, 'oidc');
    }
    const request = await authorizeRequest(discovery, config, oidcRedirectUri(c.env, orgId), email);
    const browser = randomToken(32);
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM oidc_states WHERE expires_at <= ?').bind(now),
      c.env.DB.prepare(
        `INSERT INTO oidc_states (state_hash, org_id, browser_hash, nonce, verifier, return_to, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        await stateHash(c.env, request.state),
        orgId,
        await browserHash(c.env, browser),
        request.nonce,
        request.verifier,
        returnTo,
        now + OIDC_REQUEST_TTL_SECONDS,
      ),
    ]);
    setCookie(c, OIDC_TX_COOKIE, browser, OIDC_REQUEST_TTL_SECONDS);
    await audit(c.env.DB, now, 'login.started', {
      ipPrefix: clientIp(c),
      detail: { provider: 'oidc', org: orgId },
    });
    return c.redirect(request.url, 302);
  }

  // The provider sends the person back here (a top-level GET, so the Lax cookie comes along).
  app.get('/sso/:org/oidc', async (c) => {
    if (!(await underRateLimit(c, 'callback')))
      return c.html(messagePage(MESSAGES.tooManyAttempts), 429);
    const orgId = c.req.param('org');
    const state = c.req.query('state') ?? '';
    const code = c.req.query('code');
    const browser = readCookie(c.req.header('Cookie'), OIDC_TX_COOKIE);
    clearCookie(c, OIDC_TX_COOKIE);
    const now = deps.now();
    const flow =
      RELAY_STATE.test(state) && browser
        ? await c.env.DB.prepare(
            `DELETE FROM oidc_states
             WHERE state_hash = ? AND org_id = ? AND browser_hash = ? AND expires_at > ?
             RETURNING nonce, verifier, return_to`,
          )
            .bind(await stateHash(c.env, state), orgId, await browserHash(c.env, browser), now)
            .first<{ nonce: string; verifier: string; return_to: string | null }>()
        : null;
    if (!flow) return fail(c, 'transaction_invalid', orgId, MESSAGES.signInFailed, 400, 'oidc');
    // The person cancelled, or the provider refused.
    if (!code) return fail(c, 'provider_denied', orgId, MESSAGES.signInFailed, 400, 'oidc');
    const config = await oidcConfig(c.env.DB, orgId);
    if (!config?.enabled) return fail(c, 'sso_disabled', orgId, MESSAGES.signInFailed, 400, 'oidc');
    let email: string | null;
    try {
      ({ email } = await finishOidc(c.env, deps.fetch, config, {
        code,
        verifier: flow.verifier,
        nonce: flow.nonce,
        redirectUri: oidcRedirectUri(c.env, orgId),
        now,
      }));
    } catch (error) {
      console.warn(
        'oidc response refused',
        error instanceof Error ? error.message.slice(0, 120) : 'unknown',
      );
      return fail(c, 'assertion_invalid', orgId, MESSAGES.signInFailed, 400, 'oidc');
    }
    return finishSso(c, orgId, email, flow.return_to, 'oidc');
  });

  // What the organization's owner gives their IdP.
  app.get('/saml/:org/metadata', async (c) => {
    const config = await samlConfig(c.env.DB, c.req.param('org'));
    if (!config) return c.html(notFoundPage(), 404);
    const xml = samlFor(c.env, config, nowMs).generateServiceProviderMetadata(null, null);
    return c.body(xml, 200, { 'Content-Type': 'application/samlmetadata+xml; charset=utf-8' });
  });
}
