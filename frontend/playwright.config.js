import { defineConfig, devices } from '@playwright/test';

/**
 * E2E config.
 *
 * The Django API is expected to already be running on :8011 with a seeded
 * analyst account — see e2e/README.md. Only the Vite dev server is started
 * here, because the backend needs a database and demo capture that the test
 * runner should not be silently creating.
 */
export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup.js',
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:5199',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'npm run dev -- --port 5199 --strictPort',
    env: { VITE_API_BASE: 'http://127.0.0.1:8011/api' },
    url: 'http://127.0.0.1:5199',
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
