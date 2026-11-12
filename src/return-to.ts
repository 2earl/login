/** Local pages a sign-in may return to. Anything else falls back to the default. */
const ALLOWED_PREFIXES = ['/account', '/authorize', '/admin', '/orgs', '/invite'];
const DEFAULT_RETURN_TO = '/account';

/**
 * Validates a post-sign-in return path. Only same-origin paths under an allowed prefix pass, so
 * `return_to` can never be used as an open redirect.
 */
export function safeReturnTo(value: string | null | undefined): string {
  if (!value) return DEFAULT_RETURN_TO;
  if (!value.startsWith('/') || value.startsWith('//')) return DEFAULT_RETURN_TO;
  // Backslashes and control characters are never part of a legitimate local path.
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f\u007f]/.test(value)) return DEFAULT_RETURN_TO;

  const base = 'https://return-to.invalid';
  let url: URL;
  try {
    url = new URL(value, base);
  } catch {
    return DEFAULT_RETURN_TO;
  }
  if (url.origin !== base) return DEFAULT_RETURN_TO;

  const allowed = ALLOWED_PREFIXES.some(
    (prefix) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`),
  );
  return allowed ? `${url.pathname}${url.search}` : DEFAULT_RETURN_TO;
}
