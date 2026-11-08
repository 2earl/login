import { createRemoteJWKSet } from 'jose';
import { createApp } from './app';
import { GOOGLE_JWKS_URL } from './google';

/**
 * Production entry point. Google's signing keys are fetched on demand and cached by jose.
 * The OAuth authorization server (for MCP clients) is added in phase 4c (docs/DESIGN.md §12).
 */
const app = createApp({
  fetch: (input, init) => fetch(input, init),
  googleJwks: createRemoteJWKSet(new URL(GOOGLE_JWKS_URL)),
  now: () => Math.floor(Date.now() / 1000),
});

export default app satisfies ExportedHandler<Env>;
