import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';
import { newSigningKey } from './scripts/oidc-key.mjs';

/**
 * A stand-in for a service's AccountEvents entrypoint (wrangler.jsonc "services"), so its binding
 * is a real RPC binding in tests. Tests that need other behaviour override the binding per call.
 */
function standIn(name: string, service: string) {
  return {
    name,
    modules: true,
    compatibilityDate: '2026-11-01',
    script: `
      import { WorkerEntrypoint } from 'cloudflare:workers';
      export class AccountEvents extends WorkerEntrypoint {
        async deleteUser(userId) {}
        async exportUser(userId) {
          return { service: ${JSON.stringify(service)}, securityLog: [], stand_in_for: userId };
        }
      }
      export default { fetch: () => new Response('stand-in', { status: 404 }) };
    `,
  };
}

export default defineConfig(async () => {
  // Read the real migrations so tests run against exactly the schema that production gets.
  // The path is relative to the repository root, where pnpm runs vitest.
  const migrations = await readD1Migrations('./migrations');
  // A fresh ID-token signing key for every test run (DESIGN §4.11).
  const oidcSigningKey = await newSigningKey();

  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            // Test-only values for the Worker secrets declared in wrangler.jsonc.
            GOOGLE_CLIENT_SECRET: 'test-google-client-secret',
            SESSION_PEPPER: 'test-session-pepper',
            CONSENT_REMEMBER_SECRET: 'test-consent-remember-secret-at-least-32-chars',
            MFA_ENCRYPTION_KEY: 'test-mfa-encryption-key',
            OWNER_GOOGLE_SUB: 'google-sub-owner',
            OIDC_SIGNING_KEY: oidcSigningKey,
            // Tests start invite-only, as the service launched; open sign-up is tested by
            // switching it (the settings table or a per-call override).
            LOGIN_LOCKED: 'true',
          },
          workers: [standIn('mcp', '2earl MCP gateway'), standIn('promptshare', 'Prompt share')],
        },
      }),
    ],
    test: {
      setupFiles: ['./test/apply-migrations.ts'],
    },
  };
});
