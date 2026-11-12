import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose';
import { createApp } from '../../src/app';
import { pkceChallenge } from '../../src/crypto';
import { GOOGLE_TOKEN_URL } from '../../src/google';

/**
 * Browser tests only (e2e/wrangler.jsonc, `wrangler dev`, never deployed). The real app, with
 * Google's token endpoint and signing keys replaced: the browser's trip to accounts.google.com is
 * intercepted by Playwright, which sends back a `code` carrying the identity to sign in as; the
 * token request below turns it into an ID token signed with a key generated at startup.
 */

interface FakeCode {
  sub: string;
  email: string;
  name: string;
  nonce: string;
  codeChallenge: string;
}

const keys = await generateKeyPair('RS256');
const jwks = createLocalJWKSet({
  keys: [{ ...(await exportJWK(keys.publicKey)), kid: 'e2e', alg: 'RS256' }],
});

function decodeCode(code: string): FakeCode {
  const b64 = code.replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))) as FakeCode;
}

function fakeGoogle(env: Env): typeof fetch {
  return async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url !== GOOGLE_TOKEN_URL || !(init?.body instanceof URLSearchParams)) {
      return new Response('unexpected outbound request in e2e', { status: 500 });
    }
    const code = decodeCode(init.body.get('code') ?? '');
    // The app must send the PKCE verifier matching the challenge it sent to "Google".
    if ((await pkceChallenge(init.body.get('code_verifier') ?? '')) !== code.codeChallenge) {
      return Response.json({ error: 'invalid_grant' }, { status: 400 });
    }
    const now = Math.floor(Date.now() / 1000);
    const idToken = await new SignJWT({
      iss: 'https://accounts.google.com',
      aud: env.GOOGLE_CLIENT_ID,
      sub: code.sub,
      email: code.email,
      email_verified: true,
      name: code.name,
      nonce: code.nonce,
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'e2e' })
      .sign(keys.privateKey);
    return Response.json({ access_token: 'e2e', id_token: idToken });
  };
}

let app: ReturnType<typeof createApp> | null = null;

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Response | Promise<Response> {
    app ??= createApp({
      fetch: fakeGoogle(env),
      googleJwks: jwks,
      // Microsoft, GitHub and Apple are off in the journey (no client IDs set).
      microsoftJwks: jwks,
      appleJwks: jwks,
      now: () => Math.floor(Date.now() / 1000),
    });
    return app.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
