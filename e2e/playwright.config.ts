import { defineConfig, devices } from '@playwright/test';

/** Browser tests against the real app in `wrangler dev` (e2e/serve.mjs). Run: `pnpm test:e2e`. */
export default defineConfig({
  testDir: '.',
  testMatch: '*.e2e.ts',
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 60_000,
  reporter: process.env.CI ? [['list'], ['github']] : 'list',
  use: {
    baseURL: 'http://localhost:8788',
    trace: 'retain-on-failure',
    // Same rendering as the screenshots reviewed in PRs.
    ...devices['Desktop Chrome'],
  },
  webServer: {
    command: 'node e2e/serve.mjs',
    cwd: '..',
    url: 'http://localhost:8788/healthz',
    timeout: 120_000,
    reuseExistingServer: false,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
