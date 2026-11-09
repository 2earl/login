import { env, exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken } from '../src/crypto';
import { deliverDeletionNotices, type AccountEventsBinding } from '../src/deletion-notices';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import { SERVICES, serviceForResource } from '../src/services';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  count,
  envOverride,
  freshIp,
  makeApp,
  resetDatabase,
  setCookies,
  signIdToken,
  signIn,
  consentBody,
  parseConsent,
} from './helpers';

const REDIRECT_URI = 'https://client.example/callback';
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };

let google: FakeGoogle;
let app: ReturnType<typeof makeApp>;
let session: string;
let userId: string;

/** The test env with a service's deletion binding in front of the real bindings. */
function envWith(bindings: Record<string, AccountEventsBinding>): Env {
  return envOverride(bindings);
}

/** A recording stand-in for a service's AccountEvents entrypoint. */
function fakeService(fail = false) {
  const deleted: string[] = [];
  const binding: AccountEventsBinding = {
    deleteUser: (id) => {
      if (fail) return Promise.reject(new TypeError('service down'));
      deleted.push(id);
      return Promise.resolve();
    },
  };
  return { deleted, binding };
}

async function deleteOwnAccount(): Promise<void> {
  const ip = freshIp();
  const start = await call(app, '/account/delete', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body: new URLSearchParams({ confirm: 'on' }),
    cookies: { '__Host-session': session },
    ip,
  });
  const location = new URL(start.headers.get('Location') ?? 'about:blank');
  google.nextIdToken = await signIdToken({ nonce: location.searchParams.get('nonce') ?? '' });
  const done = await call(
    app,
    `/callback/google?code=c&state=${encodeURIComponent(location.searchParams.get('state') ?? '')}`,
    {
      ip,
      cookies: {
        '__Host-session': session,
        '__Host-login_tx': setCookies(start)['__Host-login_tx'] ?? '',
      },
    },
  );
  expect(done.headers.get('Location')).toBe('/account/deleted');
}

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  google = new FakeGoogle();
  app = makeApp(google);
  session = (await signIn(app, google)).session ?? '';
  userId = (await env.DB.prepare('SELECT id FROM users').first<{ id: string }>())?.id ?? '';
});

describe('service registry', () => {
  it('keeps each service’s scopes under its own prefix, with unique ids, resources and bindings', () => {
    const ids = SERVICES.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(SERVICES.map((s) => s.resource(env))).size).toBe(SERVICES.length);
    expect(new Set(SERVICES.map((s) => s.deletionBinding)).size).toBe(SERVICES.length);
    for (const service of SERVICES) {
      expect(Object.keys(service.scopes).length).toBeGreaterThan(0);
      for (const scope of Object.keys(service.scopes)) expect(scope).toMatch(`${service.id}:`);
    }
  });

  it('finds the MCP gateway by its resource, and nothing for other URLs', () => {
    expect(serviceForResource(env, 'https://mcp.2earl.com/mcp')?.id).toBe('mcp');
    expect(serviceForResource(env, 'https://mcp.2earl.com/mcp/')).toBeUndefined();
    expect(serviceForResource(env, 'https://other.2earl.com')).toBeUndefined();
  });
});

describe('per-service permissions', () => {
  async function consentFor(scope: string): Promise<{ html: string; response: Response }> {
    const clientId = (
      await authorizationServer(env)
        .getOAuthApi(env)
        .createClient({ redirectUris: [REDIRECT_URI], tokenEndpointAuthMethod: 'none' })
    ).clientId;
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      scope,
      state: 's',
      code_challenge: await pkceChallenge(randomToken(48)),
      code_challenge_method: 'S256',
      resource: env.MCP_RESOURCE,
    });
    const response = await call(app, `/authorize?${query.toString()}`, {
      cookies: { '__Host-session': session },
    });
    return { html: await response.clone().text(), response };
  }

  it('names the service on the consent page and offers only its scopes', async () => {
    const { html } = await consentFor('mcp:tools.read other:files.write');
    expect(html).toContain('2earl MCP gateway (mcp.2earl.com)');
    expect(html).toContain('value="mcp:tools.read"');
    expect(html).not.toContain('value="other:files.write"');
  });

  it('never grants a scope the service doesn’t have, even if the form is altered', async () => {
    const { html, response } = await consentFor('mcp:tools.read');
    const handle = parseConsent(html);
    const body = consentBody(handle, { decision: 'approve' });
    body.append('scope', 'mcp:tools.read');
    body.append('scope', 'mcp:tools.invoke'); // not requested
    body.append('scope', 'other:files.write'); // not this service's
    const approved = await call(app, '/authorize', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body,
      cookies: { '__Host-session': session, ...setCookies(response) },
    });
    expect(approved.status).toBe(302);
    const grants = await authorizationServer(env).getOAuthApi(env).listUserGrants(userId);
    expect(grants.items[0]?.scope).toEqual(['mcp:tools.read']);
  });
});

describe('signed offered scopes', () => {
  it('refuses a consent form whose offered scopes were changed', async () => {
    const clientId = (
      await authorizationServer(env)
        .getOAuthApi(env)
        .createClient({ redirectUris: [REDIRECT_URI], tokenEndpointAuthMethod: 'none' })
    ).clientId;
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      scope: 'mcp:tools.read',
      state: 's',
      code_challenge: await pkceChallenge(randomToken(48)),
      code_challenge_method: 'S256',
      resource: env.MCP_RESOURCE,
    });
    const page = await call(app, `/authorize?${query.toString()}`, {
      cookies: { '__Host-session': session },
    });
    const handle = parseConsent(await page.text());
    const body = consentBody(handle, {
      decision: 'approve',
      offered: 'mcp:tools.read mcp:tools.invoke',
    });
    body.append('scope', 'mcp:tools.invoke');
    const response = await call(app, '/authorize', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body,
      cookies: { '__Host-session': session, ...setCookies(page) },
    });
    expect(response.status).toBe(400);
    expect((await authorizationServer(env).getOAuthApi(env).listUserGrants(userId)).items).toEqual(
      [],
    );
  });
});

describe('account-deletion notices', () => {
  it('records one notice per service in the same step as the deletion', async () => {
    await deleteOwnAccount();
    expect(await count('users')).toBe(0);
    expect(await count('deletion_notices', 'user_id = ?', userId)).toBe(SERVICES.length);
  });

  it('keeps notices for a service that has no binding yet', async () => {
    await deleteOwnAccount();
    const result = await deliverDeletionNotices(env, NOW);
    expect(result).toEqual({ delivered: 0, failed: 0, waiting: SERVICES.length });
    expect(await count('deletion_notices')).toBe(SERVICES.length);
  });

  it('delivers to the service, then forgets the account ID', async () => {
    await deleteOwnAccount();
    const gateway = fakeService();
    const result = await deliverDeletionNotices(
      envWith({ MCP_GATEWAY_EVENTS: gateway.binding }),
      NOW,
    );
    expect(result.delivered).toBe(1);
    expect(gateway.deleted).toEqual([userId]);
    expect(await count('deletion_notices')).toBe(0);
    expect(await count('audit_events', "event = 'user.deletion_delivered'")).toBe(1);
    // The audit entry names the service, not the account.
    expect(await count('audit_events', 'detail LIKE ?', `%${userId}%`)).toBe(0);
  });

  it('keeps a notice the service didn’t confirm, and retries it later', async () => {
    await deleteOwnAccount();
    const down = fakeService(true);
    const first = await deliverDeletionNotices(envWith({ MCP_GATEWAY_EVENTS: down.binding }), NOW);
    expect(first.failed).toBe(1);
    const row = await env.DB.prepare('SELECT attempts, last_error FROM deletion_notices').first<{
      attempts: number;
      last_error: string;
    }>();
    expect(row).toEqual({ attempts: 1, last_error: 'TypeError' });

    const up = fakeService();
    await deliverDeletionNotices(envWith({ MCP_GATEWAY_EVENTS: up.binding }), NOW + 900);
    expect(up.deleted).toEqual([userId]);
    expect(await count('deletion_notices')).toBe(0);
  });

  it('runs on the 15-minute cron trigger', async () => {
    await env.DB.prepare(
      "INSERT INTO deletion_notices (service, user_id, created_at) VALUES ('mcp', 'gone-user', 0)",
    ).run();
    await exports.default.scheduled({
      cron: '*/15 * * * *',
      scheduledTime: Date.now(),
      noRetry: () => undefined,
    });
    // No binding in the test Worker: the notice waits, untouched, for the service to exist.
    const row = await env.DB.prepare('SELECT attempts FROM deletion_notices').first<{
      attempts: number;
    }>();
    expect(row?.attempts).toBe(0);
  });
});
