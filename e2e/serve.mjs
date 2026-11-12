// Starts the e2e Worker for Playwright (e2e/playwright.config.ts): a fresh local database with
// all migrations, then `wrangler dev` on port 8788 with test-only secrets.
import { spawn, spawnSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { newSigningKey } from '../scripts/oidc-key.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const config = join(here, 'wrangler.jsonc');
const persist = join(here, '..', '.wrangler', 'e2e-state');
const wrangler = join(here, '..', 'node_modules', '.bin', 'wrangler');

export const E2E_OWNER_SUB = 'e2e-owner-sub';

const secrets = {
  GOOGLE_CLIENT_SECRET: 'e2e-google-client-secret',
  SESSION_PEPPER: 'e2e-session-pepper-at-least-32-characters',
  CONSENT_REMEMBER_SECRET: 'e2e-consent-remember-secret-at-least-32-chars',
  MFA_ENCRYPTION_KEY: 'e2e-mfa-encryption-key',
  OWNER_GOOGLE_SUB: E2E_OWNER_SUB,
  OIDC_SIGNING_KEY: await newSigningKey(),
};

rmSync(persist, { recursive: true, force: true });
const migrate = spawnSync(
  wrangler,
  ['d1', 'migrations', 'apply', 'DB', '--local', '--config', config, '--persist-to', persist],
  { stdio: 'inherit', env: { ...process.env, CI: 'true' } },
);
if (migrate.status !== 0) process.exit(migrate.status ?? 1);

const dev = spawn(
  wrangler,
  [
    'dev',
    '--config',
    config,
    '--persist-to',
    persist,
    '--port',
    '8788',
    '--ip',
    'localhost',
    '--show-interactive-dev-session=false',
    ...Object.entries(secrets).flatMap(([key, value]) => ['--var', `${key}:${value}`]),
  ],
  { stdio: 'inherit', env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } },
);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => dev.kill(signal));
dev.on('exit', (code) => process.exit(code ?? 0));
