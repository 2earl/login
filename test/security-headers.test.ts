import { describe, expect, it } from 'vitest';
import { CONSENT_CSP, DEFAULT_CSP, applySecurityHeaders } from '../src/security-headers';

describe('applySecurityHeaders', () => {
  it('keeps a header a handler already set', () => {
    const headers = new Headers({ 'Cache-Control': 'private, max-age=60' });
    applySecurityHeaders(headers);
    expect(headers.get('Cache-Control')).toBe('private, max-age=60');
  });

  it('keeps a page-specific CSP', () => {
    const headers = new Headers({ 'Content-Security-Policy': CONSENT_CSP });
    applySecurityHeaders(headers);
    expect(headers.get('Content-Security-Policy')).toBe(CONSENT_CSP);
  });

  it('uses the given CSP when none is set', () => {
    const headers = new Headers();
    applySecurityHeaders(headers, CONSENT_CSP);
    expect(headers.get('Content-Security-Policy')).toBe(CONSENT_CSP);
  });
});

describe('Referrer-Policy', () => {
  // Regression: under no-referrer, browsers send `Origin: null` on same-site form posts, which
  // made POST /logout fail its Origin check in production.
  it('is same-origin, so same-site form posts keep their Origin header', async () => {
    const { BASE_HEADERS } = await import('../src/security-headers');
    expect(BASE_HEADERS['Referrer-Policy']).toBe('same-origin');
  });
});

describe('CSP values', () => {
  it('default CSP restricts form targets to this origin', () => {
    expect(DEFAULT_CSP).toContain("form-action 'self'");
  });

  it('consent CSP omits form-action but still forbids framing', () => {
    expect(CONSENT_CSP).not.toContain('form-action');
    expect(CONSENT_CSP).toContain("frame-ancestors 'none'");
  });
});
