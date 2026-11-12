import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWTPayload } from 'jose';
import { createApp } from '../src/app';
import { GOOGLE_TOKEN_URL } from '../src/google';

export const ORIGIN = 'https://login.2earl.com';
export const NOW = 1_762_700_000;
export const OWNER_EMAIL = 'ffrhtd@gmail.com';

const signing = await generateKeyPair('RS256');
const publicJwk = { ...(await exportJWK(signing.publicKey)), kid: 'test-key', alg: 'RS256' };
export const testJwks = createLocalJWKSet({ keys: [publicJwk] });

/** Another key, unknown to the JWKS, to forge tokens with. */
export const foreignKey = (await generateKeyPair('RS256')).privateKey;

export async function signIdToken(
  claims: JWTPayload,
  options: { key?: CryptoKey; now?: number } = {},
): Promise<string> {
  const iat = options.now ?? NOW;
  return new SignJWT({
    iss: 'https://accounts.google.com',
    aud: env.GOOGLE_CLIENT_ID,
    sub: 'google-sub-owner',
    email: OWNER_EMAIL,
    email_verified: true,
    name: 'Owner Example',
    iat,
    exp: iat + 3600,
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .sign(options.key ?? signing.privateKey);
}

/** Stands in for Google's token endpoint. */
export class FakeGoogle {
  readonly tokenRequests: URLSearchParams[] = [];
  nextIdToken: string | null = null;
  tokenStatus = 200;

  readonly fetch: typeof fetch = (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url !== GOOGLE_TOKEN_URL) throw new Error(`unexpected outbound fetch to ${url}`);
    if (!(init?.body instanceof URLSearchParams)) throw new Error('expected a form body');
    this.tokenRequests.push(init.body);
    if (this.tokenStatus !== 200) {
      return Promise.resolve(new Response('{}', { status: this.tokenStatus }));
    }
    return Promise.resolve(
      Response.json({ access_token: 'google-access-token', id_token: this.nextIdToken }),
    );
  };
}

export function makeApp(google: FakeGoogle, now: () => number = () => NOW) {
  return createApp({ fetch: google.fetch, googleJwks: testJwks, now });
}

type App = ReturnType<typeof makeApp>;

let ipCounter = 0;
/** A distinct client IP per test keeps the per-IP rate limiter out of the way. */
export function freshIp(): string {
  ipCounter += 1;
  return `10.${String(Math.floor(ipCounter / 250) % 250)}.${String(ipCounter % 250)}.7`;
}

export async function call(
  app: App,
  path: string,
  init: RequestInit & {
    cookies?: Record<string, string>;
    ip?: string;
    /** Worker variables to override for this request, e.g. { MFA_REQUIRED: 'true' }. */
    vars?: Partial<Record<keyof Env, unknown>>;
  } = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.cookies) {
    headers.set(
      'Cookie',
      Object.entries(init.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; '),
    );
  }
  headers.set('CF-Connecting-IP', init.ip ?? '192.0.2.1');
  const ctx = createExecutionContext();
  const requestEnv = init.vars ? envOverride(init.vars) : env;
  const response = await app.fetch(
    new Request(`${ORIGIN}${path}`, { ...init, headers }),
    requestEnv,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
}

export function setCookies(response: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const header of response.headers.getSetCookie()) {
    const [pair] = header.split(';');
    const index = pair?.indexOf('=') ?? -1;
    if (pair && index > 0) out[pair.slice(0, index)] = pair.slice(index + 1);
  }
  return out;
}

export function rawSetCookie(response: Response, name: string): string | undefined {
  return response.headers.getSetCookie().find((h) => h.startsWith(`${name}=`));
}

/** Starts a sign-in and returns what the browser would hold on the way back from Google. */
export async function startLogin(app: App, ip: string, query = '') {
  const response = await call(app, `/login/google${query}`, { ip });
  const location = new URL(response.headers.get('Location') ?? 'about:blank');
  return {
    response,
    location,
    state: location.searchParams.get('state') ?? '',
    nonce: location.searchParams.get('nonce') ?? '',
    txCookie: setCookies(response)['__Host-login_tx'] ?? '',
  };
}

/** Runs a complete sign-in. `claims` override the ID token Google returns. */
export async function signIn(
  app: App,
  google: FakeGoogle,
  options: { ip?: string; claims?: JWTPayload; query?: string; userAgent?: string } = {},
) {
  const ip = options.ip ?? freshIp();
  const login = await startLogin(app, ip, options.query);
  google.nextIdToken = await signIdToken({ nonce: login.nonce, ...options.claims });
  const callback = await call(
    app,
    `/callback/google?code=auth-code&state=${encodeURIComponent(login.state)}`,
    {
      ip,
      cookies: { '__Host-login_tx': login.txCookie },
      ...(options.userAgent ? { headers: { 'User-Agent': options.userAgent } } : {}),
    },
  );
  return { login, callback, session: setCookies(callback)['__Host-session'] };
}

export async function resetDatabase(): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM deletion_notices'),
    env.DB.prepare('DELETE FROM mfa_pending'),
    env.DB.prepare('DELETE FROM passkey_challenges'),
    env.DB.prepare('DELETE FROM recovery_codes'),
    env.DB.prepare('DELETE FROM mfa_factors'),
    env.DB.prepare('DELETE FROM sessions'),
    env.DB.prepare('DELETE FROM identities'),
    env.DB.prepare('DELETE FROM users'),
    env.DB.prepare('DELETE FROM login_tx'),
    env.DB.prepare('DELETE FROM audit_events'),
    env.DB.prepare('DELETE FROM allowlist'),
    env.DB.prepare(
      "INSERT INTO allowlist (id, kind, value, added_by, created_at) VALUES ('owner-initial', 'email', ?, 'test', 0)",
    ).bind(OWNER_EMAIL),
  ]);
}

export async function count(table: string, where = '1 = 1', ...bind: unknown[]): Promise<number> {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${where}`)
    .bind(...bind)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

/**
 * The test env with some values replaced, for one call. The overrides are own properties of a new
 * object whose prototype is the real env, so bindings stay reachable. `defineProperty`, not
 * assignment: assigning would run the env proxy's setter and change the shared env for every
 * later test.
 */
export function envOverride(values: Record<string, unknown>): Env {
  const overridden = Object.create(env) as object;
  for (const [key, value] of Object.entries(values)) {
    Object.defineProperty(overridden, key, { value, enumerable: true });
  }
  return overridden as Env;
}

/** Hidden fields of consent pages opened in this test run, by handle. */
const consentHiddenFields = new Map<string, Record<string, string>>();

/**
 * Reads a consent page as a browser would: returns its handle and remembers every hidden field
 * (handle, offered scopes and their signature), so a test can submit the form like the browser.
 */
export function parseConsent(html: string): string {
  const fields: Record<string, string> = {};
  for (const [, name, value] of html.matchAll(
    /<input type="hidden" name="([^"]+)" value="([^"]*)">/g,
  )) {
    if (name !== undefined && value !== undefined) fields[name] = value.replace(/&amp;/g, '&');
  }
  const handle = fields.handle ?? '';
  consentHiddenFields.set(handle, fields);
  return handle;
}

/** The consent form's hidden fields for `handle`, plus `extra`, as the browser would post them. */
export function consentBody(handle: string, extra: Record<string, string> = {}): URLSearchParams {
  return new URLSearchParams({ ...(consentHiddenFields.get(handle) ?? { handle }), ...extra });
}
