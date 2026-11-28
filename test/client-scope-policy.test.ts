import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { refusedScopes, setClientScopePolicy } from '../src/authz/client-policy';
import { pkceChallenge, randomToken } from '../src/crypto';
import { authorizationServer, setOAuthClock } from '../src/oauth';
import { serviceById, serviceForResource } from '../src/services';
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

/** DESIGN §4.32: an app's own sign-in scope is for that app only. */

const REDIRECT_URI = 'https://client.example/callback';
const SAME_ORIGIN = { Origin: ORIGIN, 'Sec-Fetch-Site': 'same-origin' };
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };

let app: ReturnType<typeof makeApp>;
let session: string;
let clientId: string;

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  await env.DB.prepare("DELETE FROM settings WHERE key = 'client_scope_policy'").run();
  const google = new FakeGoogle();
  app = makeApp(google);
  session = (await signIn(app, google)).session ?? '';
  clientId = (
    await authorizationServer(env)
      .getOAuthApi(env)
      .createClient({ redirectUris: [REDIRECT_URI], tokenEndpointAuthMethod: 'none' })
  ).clientId;
});

async function authorize(scope: string, resource: string, verifier = randomToken(48)) {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope,
    state: 's',
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: 'S256',
    resource,
  });
  return call(app, `/authorize?${query.toString()}`, { cookies: { '__Host-session': session } });
}

describe('which client may ask for which scope', () => {
  it('names each Emanet app and Prompt share’s website as the only client of its scope', () => {
    const emanet = serviceById('emanet');
    const promptshare = serviceById('promptshare');
    if (!emanet || !promptshare) throw new Error('missing service');
    const kurumsal = `${env.EMANET_KURUMSAL_RESOURCE}/oauth/client.json`;
    const merkez = `${env.EMANET_MERKEZ_RESOURCE}/oauth/client.json`;
    expect(refusedScopes(env, emanet, kurumsal, ['emanet:partner'])).toEqual([]);
    expect(refusedScopes(env, emanet, merkez, ['emanet:control'])).toEqual([]);
    expect(refusedScopes(env, emanet, kurumsal, ['emanet:control'])).toEqual(['emanet:control']);
    expect(
      refusedScopes(env, emanet, 'https://evil.example/client.json', ['emanet:field']),
    ).toEqual(['emanet:field']);
    expect(
      refusedScopes(env, promptshare, `${env.PROMPTSHARE_RESOURCE}/oauth/client.json`, [
        'promptshare:account',
      ]),
    ).toEqual([]);
    const kyc = serviceById('kyc');
    if (!kyc) throw new Error('missing service');
    expect(
      refusedScopes(env, kyc, `${env.KYC_RESOURCE}/console/client.json`, ['kyc:console']),
    ).toEqual([]);
    expect(refusedScopes(env, kyc, kurumsal, ['kyc:console', 'kyc:usage.read'])).toEqual([
      'kyc:console',
    ]);
    // Scopes no rule names are for any app, after consent.
    const mcp = serviceById('mcp');
    if (!mcp) throw new Error('missing service');
    expect(refusedScopes(env, mcp, 'https://any.example/c.json', ['mcp:tools.read'])).toEqual([]);
  });

  it('only reports another app’s scope at first, and records it', async () => {
    const response = await authorize('emanet:control', env.EMANET_MERKEZ_RESOURCE);
    expect(response.status).toBe(200);
    expect(
      await count(
        'audit_events',
        "event = 'authz.scope_policy_would_refuse' AND client_id = ?",
        clientId,
      ),
    ).toBe(1);
  });

  it('refuses it at /authorize once enforced', async () => {
    await setClientScopePolicy(env.DB, NOW, 'enforce');
    const response = await authorize('emanet:control', env.EMANET_MERKEZ_RESOURCE);
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location') ?? 'about:blank');
    expect(location.searchParams.get('error')).toBe('invalid_scope');
    expect(await count('audit_events', "event = 'authz.scope_policy_refused'")).toBe(1);
  });

  it('refuses a grant made while reporting, at its next exchange once enforced', async () => {
    const verifier = randomToken(48);
    const page = await authorize('emanet:control', env.EMANET_MERKEZ_RESOURCE, verifier);
    const handle = parseConsent(await page.text());
    const body = consentBody(handle, { decision: 'approve' });
    body.append('scope', 'emanet:control');
    const approved = await call(app, '/authorize', {
      method: 'POST',
      headers: { ...FORM, ...SAME_ORIGIN },
      body,
      cookies: { '__Host-session': session, ...setCookies(page) },
    });
    const code = new URL(approved.headers.get('Location') ?? 'about:blank').searchParams.get(
      'code',
    );
    expect(code).toBeTruthy();
    await setClientScopePolicy(env.DB, NOW, 'enforce');
    const token = await call(app, '/oauth/token', {
      method: 'POST',
      headers: FORM,
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code ?? '',
        redirect_uri: REDIRECT_URI,
        client_id: clientId,
        code_verifier: verifier,
        resource: env.EMANET_MERKEZ_RESOURCE,
      }),
    });
    expect(token.status).toBe(400);
    expect((await token.json<{ error: string }>()).error).toBe('invalid_grant');
    expect(
      await count(
        'audit_events',
        "event = 'grant.refused' AND detail LIKE '%scope_not_for_client%'",
      ),
    ).toBe(1);
  });

  it('leaves the gateway’s scopes alone', async () => {
    await setClientScopePolicy(env.DB, NOW, 'enforce');
    expect((await authorize('mcp:tools.read', env.MCP_RESOURCE)).status).toBe(200);
    expect(serviceForResource(env, env.MCP_RESOURCE)?.firstPartyClients).toBeUndefined();
  });
});
