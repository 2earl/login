import { env, exports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { pkceChallenge, randomToken } from '../src/crypto';
import { ACCESS_TOKEN_TTL_SECONDS, authorizationServer, setOAuthClock } from '../src/oauth';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  call,
  makeApp,
  resetDatabase,
  setCookies,
  signIn,
  consentBody,
  parseConsent,
} from './helpers';

/**
 * The contract the MCP gateway relies on (docs/GATEWAY_INTEGRATION.md): `validateToken` called
 * on the Worker's real entry point, as a Service Binding calls it.
 */

const REDIRECT_URI = 'https://client.example/callback';
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };

let app: ReturnType<typeof makeApp>;
let session: string;
let userId: string;
let clientId: string;

/** authorize → consent (with the given scopes) → token. */
async function accessToken(scopes: string[]): Promise<string> {
  const verifier = randomToken(48);
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'mcp:tools.read mcp:promptshare.read',
    state: 's',
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    resource: env.MCP_RESOURCE,
  });
  const consent = await call(app, `/authorize?${query.toString()}`, {
    cookies: { '__Host-session': session },
  });
  const handle = parseConsent(await consent.text());
  const body = consentBody(handle, { decision: 'approve' });
  for (const scope of scopes) body.append('scope', scope);
  const approved = await call(app, '/authorize', {
    method: 'POST',
    headers: { ...FORM, ...SAME_ORIGIN },
    body,
    cookies: { '__Host-session': session, ...setCookies(consent) },
  });
  const code = new URL(approved.headers.get('Location') ?? 'about:blank').searchParams.get('code');
  const token = await call(app, '/oauth/token', {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code ?? '',
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
      resource: env.MCP_RESOURCE,
    }),
  });
  return (await token.json<{ access_token: string }>()).access_token;
}

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  const google = new FakeGoogle();
  app = makeApp(google);
  session = (await signIn(app, google)).session ?? '';
  userId = (await env.DB.prepare('SELECT id FROM users').first<{ id: string }>())?.id ?? '';
  clientId = (
    await authorizationServer(env)
      .getOAuthApi(env)
      .createClient({
        redirectUris: [REDIRECT_URI],
        clientName: 'Gateway contract client',
        tokenEndpointAuthMethod: 'none',
      })
  ).clientId;
});

describe('validateToken over the Worker entry point (Service Binding)', () => {
  it('returns the user, client, scopes, audience and expiry for a valid token', async () => {
    const token = await accessToken(['mcp:tools.read', 'mcp:promptshare.read']);
    const before = Math.floor(Date.now() / 1000);
    const result = await exports.default.validateToken(env.MCP_RESOURCE, token);

    expect(result).toMatchObject({
      audience: env.MCP_RESOURCE,
      userId,
      clientId,
      scope: ['mcp:tools.read', 'mcp:promptshare.read'],
      props: { uid: userId, authTime: NOW },
    });
    // Only an internal ID and a time: no email or name crosses to the gateway.
    expect(Object.keys(result?.props ?? {}).sort()).toEqual(['authTime', 'uid']);
    expect(result?.expiresAt).toBeGreaterThanOrEqual(before + ACCESS_TOKEN_TTL_SECONDS - 5);
    expect(result?.expiresAt).toBeLessThanOrEqual(before + ACCESS_TOKEN_TTL_SECONDS + 5);
  });

  it('reports only the scopes the user approved', async () => {
    const token = await accessToken(['mcp:tools.read']);
    const result = await exports.default.validateToken(env.MCP_RESOURCE, token);
    expect(result?.scope).toEqual(['mcp:tools.read']);
  });

  it('throws for a resource it does not serve: a misconfigured gateway fails closed', async () => {
    const token = await accessToken(['mcp:tools.read']);
    for (const resource of ['https://other.2earl.com/mcp', `${env.MCP_RESOURCE}/`]) {
      // Handled on the RPC promise itself: Vitest's `.rejects` leaves the runtime reporting it.
      const outcome = await exports.default.validateToken(resource, token).then(
        () => 'resolved',
        (error: unknown) => (error instanceof Error ? error.message : 'non-error'),
      );
      expect(outcome).toBe('resource must name one registered protected resource');
    }
  });

  it('returns null for a malformed token or a revoked grant', async () => {
    const token = await accessToken(['mcp:tools.read']);
    expect(await exports.default.validateToken(env.MCP_RESOURCE, 'not-a-token')).toBeNull();

    const oauth = authorizationServer(env).getOAuthApi(env);
    const { items } = await oauth.listUserGrants(userId);
    await oauth.revokeGrant(items[0]?.id ?? '', userId);
    expect(await exports.default.validateToken(env.MCP_RESOURCE, token)).toBeNull();
  });
});
