import { applyD1Migrations, type D1Migration } from 'cloudflare:test';
import { env } from 'cloudflare:workers';

// Test-only binding injected by vitest.config.ts. Not part of the Worker's Env.
const { TEST_MIGRATIONS } = env as unknown as { TEST_MIGRATIONS: D1Migration[] };

// Setup files run before each test file; applyD1Migrations skips migrations already applied.
await applyD1Migrations(env.DB, TEST_MIGRATIONS);
