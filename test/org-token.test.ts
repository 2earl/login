import { env, exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { makeStaff } from './staff-helpers';
import { pkceChallenge, randomToken } from '../src/crypto';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  consentBody,
  count,
  makeApp,
  parseConsent,
  resetDatabase,
  setCookies,
  signIn,
} from './helpers';

/** DESIGN §4.32: an app asks to act for one of the person's organizations. */

const REDIRECT_URI = 'https://client.example/callback';
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const SAME_ORIGIN = { ...FORM, Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };

let app: ReturnType<typeof makeApp>;
let session: string;
let userId: string;
let clientId: string;
let orgId: string;

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  const google = new FakeGoogle();
  app = makeApp(google);
  session = (await signIn(app, google)).session ?? '';
  userId = (await env.DB.prepare('SELECT id FROM users').first<{ id: string }>())?.id ?? '';
  await makeStaff(session);
  const created = await call(app, '/orgs', {
    method: 'POST',
    headers: SAME_ORIGIN,
    body: new URLSearchParams({ name: 'Acme Bank' }),
    cookies: { '__Host-session': session },
  });
  orgId = /\/orgs\/([^?/]+)/.exec(created.headers.get('Location') ?? '')?.[1] ?? '';
  clientId = (
    await authorizationServer(env)
      .getOAuthApi(env)
      .createClient({ redirectUris: [REDIRECT_URI], tokenEndpointAuthMethod: 'none' })
  ).clientId;
});

async function authorize(organization: string | null, verifier: string) {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'mcp:tools.read',
    state: 's',
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    resource: env.MCP_RESOURCE,
    ...(organization ? { organization } : {}),
  });
  return call(app, `/authorize?${query.toString()}`, { cookies: { '__Host-session': session } });
}

async function approve(page: Response, extra: Record<string, string> = {}) {
  const handle = parseConsent(await page.clone().text());
  const body = consentBody(handle, { decision: 'approve', ...extra });
  body.append('scope', 'mcp:tools.read');
  return call(app, '/authorize', {
    method: 'POST',
    headers: SAME_ORIGIN,
    body,
    cookies: { '__Host-session': session, ...setCookies(page) },
  });
}

async function exchange(code: string, verifier: string) {
  const response = await call(app, '/oauth/token', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
      resource: env.MCP_RESOURCE,
    }),
  });
  return response.json<{ access_token: string; refresh_token: string }>();
}

describe('a token for one of the person’s organizations', () => {
  it('names the organization on the consent page and carries it in the token', async () => {
    const verifier = randomToken(48);
    const page = await authorize(orgId, verifier);
    expect(page.status).toBe(200);
    const html = await page.clone().text();
    expect(html).toContain('On behalf of');
    expect(html).toContain('Acme Bank');
    const approved = await approve(page);
    const code = new URL(approved.headers.get('Location') ?? 'about:blank').searchParams.get(
      'code',
    );
    const tokens = await exchange(code ?? '', verifier);
    const validated = await exports.default.validateToken(env.MCP_RESOURCE, tokens.access_token);
    expect(validated?.props).toMatchObject({ uid: userId, org: orgId });
  });

  it('ends at the next refresh once the person leaves the organization', async () => {
    const verifier = randomToken(48);
    const approved = await approve(await authorize(orgId, verifier));
    const code = new URL(approved.headers.get('Location') ?? 'about:blank').searchParams.get(
      'code',
    );
    const tokens = await exchange(code ?? '', verifier);
    await env.DB.prepare('DELETE FROM org_members WHERE org_id = ?').bind(orgId).run();
    const refreshed = await call(app, '/oauth/token', {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
        client_id: clientId,
        resource: env.MCP_RESOURCE,
      }),
    });
    expect((await refreshed.json<{ error: string }>()).error).toBe('invalid_grant');
    expect(
      await count('audit_events', "event = 'grant.refused' AND detail LIKE '%not_a_member%'"),
    ).toBe(1);
  });

  it('is refused for an organization the person isn’t in, or a malformed one', async () => {
    for (const organization of ['org_someoneelses', 'acme']) {
      const response = await authorize(organization, randomToken(48));
      expect(response.status).toBe(302);
      const error = new URL(response.headers.get('Location') ?? 'about:blank').searchParams.get(
        'error',
      );
      expect(['access_denied', 'invalid_request']).toContain(error);
    }
  });

  it('can’t be changed in the consent form', async () => {
    const page = await authorize(orgId, randomToken(48));
    const response = await approve(page, { organization: 'org_other' });
    expect(response.status).toBe(400);
  });

  it('leaves tokens without one as they were', async () => {
    const verifier = randomToken(48);
    const page = await authorize(null, verifier);
    expect(await page.clone().text()).not.toContain('On behalf of');
    const approved = await approve(page);
    const code = new URL(approved.headers.get('Location') ?? 'about:blank').searchParams.get(
      'code',
    );
    const tokens = await exchange(code ?? '', verifier);
    const validated = await exports.default.validateToken(env.MCP_RESOURCE, tokens.access_token);
    expect(validated?.props.org).toBeUndefined();
  });
});
