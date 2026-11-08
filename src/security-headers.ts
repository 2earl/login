/**
 * Response headers applied to every response from login.2earl.com.
 * See docs/DESIGN.md §7 and docs/THREAT_MODEL.md (B1).
 */

/** Strict default CSP: no scripts, no framing, forms post only to this origin. */
export const DEFAULT_CSP = [
  "default-src 'none'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
].join('; ');

/**
 * CSP for the consent page. It omits `form-action` because some browsers apply it to the
 * redirect that follows submission, and approving consent redirects to the client's
 * redirect URI (already restricted by exact matching).
 */
export const CONSENT_CSP = [
  "default-src 'none'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
].join('; ');

export const BASE_HEADERS: Readonly<Record<string, string>> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  // same-origin, not no-referrer: under no-referrer browsers send `Origin: null` on same-site
  // form posts, which breaks the Origin check on state-changing requests. same-origin still
  // sends nothing to other sites, so codes and state in our URLs cannot leak there.
  'Referrer-Policy': 'same-origin',
  'X-Content-Type-Options': 'nosniff',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cache-Control': 'no-store',
};

/**
 * Applies the security headers to a response. Headers already set by a handler (for example a
 * page-specific CSP, or the OAuth library's own consent headers) are left untouched.
 */
export function applySecurityHeaders(headers: Headers, csp: string = DEFAULT_CSP): void {
  for (const [name, value] of Object.entries(BASE_HEADERS)) {
    if (!headers.has(name)) headers.set(name, value);
  }
  if (!headers.has('Content-Security-Policy')) headers.set('Content-Security-Policy', csp);
}
