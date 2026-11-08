import { exports } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { BASE_HEADERS, DEFAULT_CSP } from '../src/security-headers';

const ORIGIN = 'https://login.2earl.com';

function get(path: string, init?: RequestInit): Promise<Response> {
  return exports.default.fetch(new Request(`${ORIGIN}${path}`, init));
}

describe('placeholder worker', () => {
  it('serves the holding page', async () => {
    const res = await get('/');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toMatch(/^text\/html/);
    expect(await res.text()).toContain('Sign-up isn’t open yet');
  });

  it('answers the health check', async () => {
    const res = await get('/healthz');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok' });
  });

  it('returns a JSON 404 for unknown paths', async () => {
    const res = await get('/no-such-page');
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'not_found' });
  });
});

describe('security headers', () => {
  for (const path of ['/', '/healthz', '/does-not-exist']) {
    it(`are set on ${path}`, async () => {
      const res = await get(path);
      for (const [name, value] of Object.entries(BASE_HEADERS)) {
        expect(res.headers.get(name), name).toBe(value);
      }
      expect(res.headers.get('Content-Security-Policy')).toBe(DEFAULT_CSP);
    });
  }

  it('forbid framing', async () => {
    const res = await get('/');
    expect(res.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
  });
});

describe('static asset references', () => {
  // Regression: an unversioned /app.css cached by browsers for an hour made the redesigned pages
  // render with the old stylesheet after deploy.
  it('carry a content fingerprint, so a changed file always gets a new URL', async () => {
    const html = await (await get('/')).text();
    expect(html).toMatch(/href="\/app\.css\?v=[0-9a-f]{12}"/);
    expect(html).toMatch(/href="\/fonts\/readex-pro-latin\.woff2\?v=[0-9a-f]{12}"/);
    expect(html).toMatch(/href="\/favicon\.svg\?v=[0-9a-f]{12}"/);
    expect(html).not.toMatch(/href="\/app\.css"/);
  });
});
