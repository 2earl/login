import type { Context } from 'hono';
import { ipPrefix } from './net';
import type { Session } from './sessions';

/** Request plumbing shared by the route modules. */

export type AppEnv = { Bindings: Env; Variables: { session: Session | null } };
export type AppContext = Context<AppEnv>;

export const SESSION_COOKIE = '__Host-session';
export const LOGIN_TX_COOKIE = '__Host-login_tx';
/** The OAuth library's remembered-consent cookie (default `cookiePrefix`). */
export const CONSENT_APPROVALS_COOKIE = '__Host-oauth-approvals';

export function setCookie(c: AppContext, name: string, value: string, maxAge: number): void {
  c.header(
    'Set-Cookie',
    `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${String(maxAge)}`,
    { append: true },
  );
}

export function clearCookie(c: AppContext, name: string): void {
  setCookie(c, name, '', 0);
}

export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

/** Hono types its context more narrowly than the Workers runtime provides it. */
export function workerCtx(c: AppContext): ExecutionContext {
  return c.executionCtx as unknown as ExecutionContext;
}

export function clientIp(c: AppContext): string | null {
  return ipPrefix(c.req.header('CF-Connecting-IP'));
}

/**
 * Requests that change state must come from our own pages (DESIGN §7). The Origin header must
 * match, and if the browser reports Sec-Fetch-Site it must say same-origin.
 */
export function isSameOrigin(c: AppContext): boolean {
  const fetchSite = c.req.header('Sec-Fetch-Site');
  if (fetchSite !== undefined && fetchSite !== 'same-origin') return false;
  return c.req.header('Origin') === new URL(c.env.ISSUER).origin;
}

export async function underRateLimit(c: AppContext, route: string): Promise<boolean> {
  const { success } = await c.env.AUTH_RATE_LIMITER.limit({
    key: `${route}:${clientIp(c) ?? 'unknown'}`,
  });
  return success;
}
