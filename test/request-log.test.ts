import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app';
import { redact } from '../src/request-log';
import { FakeGoogle, NOW, call, testJwks } from './helpers';

/** Logs and error pages (DESIGN §9.4). */

function appWith() {
  const google = new FakeGoogle();
  const app = createApp({
    fetch: (input, init) => google.fetch(input, init),
    googleJwks: testJwks,
    now: () => NOW,
  });
  app.get('/boom', () => {
    throw new Error(
      'D1_ERROR: storage reset for ada@example.com token abcdefghijklmnopqrstuvwxyz0123',
    );
  });
  return app;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('a failure on our side', () => {
  it('gives a browser a page with the reference, and logs a redacted line', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const response = await call(appWith(), '/boom', {
      headers: { Accept: 'text/html', 'CF-Ray': '8f00aa11bb22cc33-FRA' },
    });
    expect(response.status).toBe(500);
    const page = await response.text();
    expect(page).toContain('Something went wrong on our side');
    expect(page).toContain('8f00aa11bb22cc33-FRA');
    expect(page).not.toContain('D1_ERROR');
    const logged = errors.mock.calls.map((args) => String(args[0])).join('\n');
    expect(logged).toContain('"event":"error"');
    expect(logged).toContain('"route":"/boom"');
    expect(logged).toContain('8f00aa11bb22cc33-FRA');
    expect(logged).not.toContain('ada@example.com');
    expect(logged).not.toContain('abcdefghijklmnopqrstuvwxyz0123');
    // And the failed response itself.
    expect(logged).toContain('"status":500');
  });

  it('gives an API client JSON with the reference', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const response = await call(appWith(), '/boom', { headers: { 'CF-Ray': 'r-1' } });
    expect(await response.json()).toEqual({ error: 'server_error', reference: 'r-1' });
  });
});

describe('refusals', () => {
  it('are logged by route pattern, never the path or query', async () => {
    const warnings = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const response = await call(appWith(), '/orgs/org_secret/saml?code=xyz', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: '',
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
    const logged = warnings.mock.calls.map((args) => String(args[0])).join('\n');
    expect(logged).toContain('"route":"/orgs/:org/saml"');
    expect(logged).not.toContain('org_secret');
    expect(logged).not.toContain('xyz');
  });

  it('404s are not logged (scanners)', async () => {
    const warnings = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    await call(appWith(), '/wp-login.php');
    expect(warnings).not.toHaveBeenCalled();
  });
});

describe('the health check', () => {
  it('says which store is down', async () => {
    const broken = {
      ...env,
      DB: {
        prepare: () => {
          throw new Error('down');
        },
      },
    } as unknown as Env;
    const response = await appWith().fetch(new Request('https://login.2earl.com/healthz'), broken);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ status: 'degraded', d1: false, kv: true });
  });
});

it('redacts addresses and long tokens', () => {
  expect(redact('no row for bob@example.com with abcdefghijklmnopqrstuvwxyz')).toBe(
    'no row for [address] with [token]',
  );
});
