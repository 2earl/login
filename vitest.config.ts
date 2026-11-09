import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig(async () => {
  // Read the real migrations so tests run against exactly the schema that production gets.
  // The path is relative to the repository root, where pnpm runs vitest.
  const migrations = await readD1Migrations('./migrations');

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
          },
          // A stand-in for the MCP gateway's AccountEvents entrypoint (wrangler.jsonc "services"),
          // so the binding is a real RPC binding in tests. Tests that need other behaviour
          // override MCP_GATEWAY_EVENTS per call.
          workers: [
            {
              name: 'mcp',
              modules: true,
              compatibilityDate: '2026-11-01',
              script: `
                import { WorkerEntrypoint } from 'cloudflare:workers';
                export class AccountEvents extends WorkerEntrypoint {
                  async deleteUser(userId) {}
                  async exportUser(userId) {
                    return { service: '2earl MCP gateway', securityLog: [], stand_in_for: userId };
                  }
                }
                export default { fetch: () => new Response('stand-in', { status: 404 }) };
              `,
            },
          ],
        },
      }),
    ],
    test: {
      setupFiles: ['./test/apply-migrations.ts'],
    },
  };
});
