import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit } from './audit';
import { hmacHex, pkceChallenge, randomToken } from './crypto';
import {
  clientIp,
  isSameOrigin,
  underRateLimit,
  workerCtx,
  type AppContext,
  type AppEnv,
} from './http';
import { authorizationServer } from './oauth';
import { withIdToken } from './oidc-routes';
import { deviceDonePage, devicePage } from './pages';
import { scopesFor, serviceForResource } from './services';

/**
 * The device authorization grant, RFC 8628 (DESIGN §4.13): sign in on a device without a browser,
 * such as the 2earl CLI, by approving a short code on a phone or computer.
 *
 * The OAuth library has no device grant, so login builds it around the ordinary code flow and
 * never mints tokens itself:
 * 1. `POST /oauth/device_authorization` stores a pending request: the HMAC of a device code, a
 *    short user code, the client, scopes and resource.
 * 2. The person opens `/device`, enters the user code, and goes through the ordinary
 *    `/authorize` page (sign-in, second factor, consent) with redirect URI `/device/callback`.
 * 3. The callback stores the authorization code against the request.
 * 4. The device polls `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`;
 *    once approved, login exchanges the code with the library, with a PKCE verifier derived from
 *    the device code, and returns the library's token response.
 *
 * Only clients that registered `${ISSUER}/device/callback` as a redirect URI may use it.
 */

export const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
export const DEVICE_CODE_TTL_SECONDS = 10 * 60;
export const DEVICE_POLL_INTERVAL_SECONDS = 5;
/** Consonants only: no vowels (no words), none that look alike (B/8, S/5 are fine in caps). */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

export function deviceCallback(env: Env): string {
  return `${env.ISSUER}/device/callback`;
}

function newUserCode(): string {
  const chars: string[] = [];
  while (chars.length < 8) {
    for (const byte of crypto.getRandomValues(new Uint8Array(16))) {
      // 240 = 12 × 20: rejection sampling keeps every letter equally likely.
      if (byte < 240 && chars.length < 8) chars.push(USER_CODE_ALPHABET[byte % 20] ?? 'B');
    }
  }
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
}

/** What people type: any case, with or without the dash or spaces. */
export function normaliseUserCode(typed: string): string | null {
  const letters = typed.toUpperCase().replace(/[\s-]/g, '');
  if (!new RegExp(`^[${USER_CODE_ALPHABET}]{8}$`).test(letters)) return null;
  return `${letters.slice(0, 4)}-${letters.slice(4)}`;
}

const deviceHash = (env: Env, deviceCode: string) =>
  hmacHex(env.SESSION_PEPPER, `device-code:${deviceCode}`);

/** The PKCE verifier for a request: derived, never stored. 64 hex characters. */
const verifierFor = (env: Env, idHash: string) =>
  hmacHex(env.SESSION_PEPPER, `device-pkce:${idHash}`);

const NO_STORE = { 'Cache-Control': 'no-store' };

function oauthError(c: AppContext, error: string, description?: string, status: 400 | 401 = 400) {
  return c.json(
    { error, ...(description ? { error_description: description } : {}) },
    status,
    NO_STORE,
  );
}

interface DeviceRow {
  id_hash: string;
  user_code: string;
  state: string;
  client_id: string;
  scope: string;
  resource: string | null;
  status: 'pending' | 'approved' | 'denied';
  code: string | null;
  interval: number;
  last_polled_at: number | null;
  expires_at: number;
}

/**
 * The token endpoint's answer for the device grant. Called from app.ts for that grant type
 * only; every other grant goes to the library unchanged.
 */
export async function deviceTokenResponse(
  c: AppContext,
  now: number,
  form: FormData,
  /** The env for the code exchange: with the DPoP context when the poll carried a proof. */
  exchangeEnv: Env = c.env,
): Promise<Response> {
  const deviceCode = form.get('device_code');
  const clientId = form.get('client_id');
  if (typeof deviceCode !== 'string' || typeof clientId !== 'string') {
    return oauthError(c, 'invalid_request', 'device_code and client_id are required');
  }
  const idHash = await deviceHash(c.env, deviceCode);
  const row = await c.env.DB.prepare('SELECT * FROM device_codes WHERE id_hash = ?')
    .bind(idHash)
    .first<DeviceRow>();
  if (!row || row.client_id !== clientId) return oauthError(c, 'invalid_grant');
  if (row.expires_at <= now) {
    await c.env.DB.prepare('DELETE FROM device_codes WHERE id_hash = ?').bind(idHash).run();
    return oauthError(c, 'expired_token');
  }
  if (row.status === 'denied') {
    await c.env.DB.prepare('DELETE FROM device_codes WHERE id_hash = ?').bind(idHash).run();
    return oauthError(c, 'access_denied');
  }
  if (row.status === 'pending') {
    // Polling faster than the interval earns 5 more seconds (RFC 8628 §3.5).
    const tooSoon = row.last_polled_at !== null && now - row.last_polled_at < row.interval;
    await c.env.DB.prepare(
      'UPDATE device_codes SET last_polled_at = ?, interval = interval + ? WHERE id_hash = ?',
    )
      .bind(now, tooSoon ? 5 : 0, idHash)
      .run();
    return oauthError(c, tooSoon ? 'slow_down' : 'authorization_pending');
  }

  // Approved: take the code once, then exchange it like any app would.
  const taken = await c.env.DB.prepare(
    `DELETE FROM device_codes WHERE id_hash = ? AND status = 'approved' RETURNING code`,
  )
    .bind(idHash)
    .first<{ code: string | null }>();
  if (!taken?.code) return oauthError(c, 'invalid_grant');
  const exchange = new URLSearchParams({
    grant_type: 'authorization_code',
    code: taken.code,
    redirect_uri: deviceCallback(c.env),
    client_id: row.client_id,
    code_verifier: await verifierFor(c.env, idHash),
  });
  if (row.resource) exchange.set('resource', row.resource);
  const response = await authorizationServer(c.env).fetch(
    new Request(`${c.env.ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: exchange,
    }),
    exchangeEnv,
    workerCtx(c),
  );
  return withIdToken(c.env, now, 'authorization_code', response);
}

export function registerDeviceRoutes(app: Hono<AppEnv>, deps: Deps): void {
  app.post('/oauth/device_authorization', async (c) => {
    const { success } = await c.env.TOKEN_RATE_LIMITER.limit({ key: clientIp(c) ?? 'unknown' });
    if (!success) return c.json({ error: 'slow_down' }, 429, NO_STORE);
    const form = await c.req.raw.formData().catch(() => null);
    const clientId = form?.get('client_id');
    const scopeText = form?.get('scope');
    const resourceField = form?.get('resource');
    if (typeof clientId !== 'string' || !clientId) {
      return oauthError(c, 'invalid_request', 'client_id is required');
    }
    let client;
    try {
      client = await authorizationServer(c.env).getOAuthApi(c.env).lookupClient(clientId);
    } catch {
      client = null;
    }
    if (!client) return oauthError(c, 'invalid_client', undefined, 401);
    if (!client.redirectUris.includes(deviceCallback(c.env))) {
      return oauthError(
        c,
        'unauthorized_client',
        `Register ${deviceCallback(c.env)} as a redirect URI to use the device grant`,
      );
    }

    const requested = (typeof scopeText === 'string' ? scopeText : '').split(' ').filter(Boolean);
    const openid = requested.includes('openid');
    const resource = typeof resourceField === 'string' && resourceField ? resourceField : undefined;
    if (!resource && !openid) {
      return oauthError(c, 'invalid_target', 'The resource parameter is required');
    }
    const service = serviceForResource(c.env, resource ?? `${c.env.ISSUER}/userinfo`);
    if (!service) return oauthError(c, 'invalid_target', 'Unknown resource');
    const scope = scopesFor(service, requested);
    if (scope.length === 0 || scope.length !== requested.length) {
      return oauthError(c, 'invalid_scope', 'Ask for scopes of one resource');
    }

    const now = deps.now();
    const deviceCode = randomToken(32);
    const userCode = newUserCode();
    await c.env.DB.prepare(
      `INSERT INTO device_codes (id_hash, user_code, state, client_id, scope, resource, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        await deviceHash(c.env, deviceCode),
        userCode,
        randomToken(24),
        clientId,
        scope.join(' '),
        resource ?? null,
        now,
        now + DEVICE_CODE_TTL_SECONDS,
      )
      .run();
    return c.json(
      {
        device_code: deviceCode,
        user_code: userCode,
        verification_uri: `${c.env.ISSUER}/device`,
        verification_uri_complete: `${c.env.ISSUER}/device?user_code=${userCode}`,
        expires_in: DEVICE_CODE_TTL_SECONDS,
        interval: DEVICE_POLL_INTERVAL_SECONDS,
      },
      200,
      NO_STORE,
    );
  });

  // The person's side: enter the code, then the ordinary authorization page.
  app.get('/device', (c) => {
    const typed = c.req.query('user_code') ?? '';
    if (!c.get('session')) {
      const back = `/device${typed ? `?user_code=${encodeURIComponent(typed)}` : ''}`;
      return c.redirect(`/login?return_to=${encodeURIComponent(back)}`, 303);
    }
    // A prefilled code is only shown: the person still checks it and presses Continue, so a
    // link alone never approves anything.
    return c.html(devicePage({ userCode: normaliseUserCode(typed) ?? '' }));
  });

  app.post('/device', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!c.get('session')) return c.redirect('/login?return_to=%2Fdevice', 303);
    if (!(await underRateLimit(c, 'device'))) {
      return c.html(devicePage({ userCode: '', error: 'Too many tries. Wait a minute.' }), 429);
    }
    const form = await c.req.raw.formData();
    const typed = form.get('user_code');
    const userCode = typeof typed === 'string' ? normaliseUserCode(typed) : null;
    const now = deps.now();
    const row = userCode
      ? await c.env.DB.prepare(
          "SELECT * FROM device_codes WHERE user_code = ? AND status = 'pending' AND expires_at > ?",
        )
          .bind(userCode, now)
          .first<DeviceRow>()
      : null;
    if (!row) {
      return c.html(
        devicePage({
          userCode: typeof typed === 'string' ? typed.slice(0, 20) : '',
          error:
            'That code isn’t valid or has expired. Check it on your device, or start again there.',
        }),
        400,
      );
    }
    const authorize = new URLSearchParams({
      response_type: 'code',
      client_id: row.client_id,
      redirect_uri: deviceCallback(c.env),
      scope: row.scope,
      state: row.state,
      code_challenge: await pkceChallenge(await verifierFor(c.env, row.id_hash)),
      code_challenge_method: 'S256',
    });
    if (row.resource) authorize.set('resource', row.resource);
    return c.redirect(`/authorize?${authorize.toString()}`, 303);
  });

  app.get('/device/callback', async (c) => {
    const state = c.req.query('state') ?? '';
    const code = c.req.query('code');
    const now = deps.now();
    const session = c.get('session');
    const row = state
      ? await c.env.DB.prepare(
          "SELECT * FROM device_codes WHERE state = ? AND status = 'pending' AND expires_at > ?",
        )
          .bind(state, now)
          .first<DeviceRow>()
      : null;
    if (!row) return c.html(deviceDonePage('expired'), 400);
    if (!code) {
      await c.env.DB.prepare("UPDATE device_codes SET status = 'denied' WHERE id_hash = ?")
        .bind(row.id_hash)
        .run();
      return c.html(deviceDonePage('denied'));
    }
    await c.env.DB.prepare(
      "UPDATE device_codes SET status = 'approved', code = ? WHERE id_hash = ? AND status = 'pending'",
    )
      .bind(code, row.id_hash)
      .run();
    await audit(c.env.DB, now, 'device.approved', {
      actorUserId: session?.user.id ?? null,
      clientId: row.client_id,
      ipPrefix: clientIp(c),
    });
    return c.html(deviceDonePage('approved'));
  });
}
