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
        },
      }),
    ],
    test: {
      setupFiles: ['./test/apply-migrations.ts'],
    },
  };
});
