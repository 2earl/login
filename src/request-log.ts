import type { Context } from 'hono';
import { routePath } from 'hono/route';
import type { AppEnv } from './http';
import { ipPrefix } from './net';

/**
 * What the Worker writes to Workers Logs (DESIGN §9.4). Cloudflare's own per-request logs stay
 * off: they record full URLs, which carry authorization codes and state. These lines name the
 * route pattern, never the path or query, and the network prefix, never the address.
 */

/** The request's Cloudflare Ray ID: shown on error pages, so a person can quote it. */
export const rayId = (request: Request): string | null => request.headers.get('CF-Ray');

/** Without addresses, digits runs or tokens that an error message might carry. */
export function redact(text: string): string {
  return text
    .replace(/[^\s@]+@[^\s@]+/g, '[address]')
    .replace(/[A-Za-z0-9_-]{24,}/g, '[token]')
    .slice(0, 300);
}

function line(c: Context<AppEnv, string>, fields: Record<string, unknown>) {
  const cf = (c.req.raw as { cf?: { colo?: string; country?: string } }).cf;
  return JSON.stringify({
    method: c.req.method,
    // The pattern of the route that answered, e.g. /orgs/:org/saml.
    route: routePath(c, -1),
    ray: rayId(c.req.raw),
    colo: cf?.colo ?? null,
    country: cf?.country ?? null,
    ip_prefix: ipPrefix(c.req.header('CF-Connecting-IP')),
    ...fields,
  });
}

/** A request login refused or failed: 4xx (not 404) and 5xx. */
export function logResponse(c: Context<AppEnv, string>, status: number, ms: number): void {
  if (status < 400 || status === 404) return;
  const text = line(c, { event: 'response', status, ms });
  if (status >= 500) console.error(text);
  else console.warn(text);
}

/** An exception the route didn't handle. */
export function logError(c: Context<AppEnv, string>, error: unknown): void {
  const err = error instanceof Error ? error : new Error(String(error));
  console.error(line(c, { event: 'error', name: err.name, message: redact(err.message) }));
}
