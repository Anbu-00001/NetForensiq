import { chromium } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const API = process.env.VITE_API_BASE ?? 'http://127.0.0.1:8011/api';
const USER = { username: 'analyst', password: 'demo-pass-1234' };
const STATE = path.join('e2e', '.auth', 'tokens.json');

/**
 * Authenticate once for the whole run.
 *
 * The login endpoint is deliberately throttled to 8/hour (a brute-force
 * control on a police system), so logging in per-test exhausts the budget and
 * the suite starts failing with 429s for reasons unrelated to the code. One
 * login per run keeps the throttle meaningful and the suite repeatable.
 */
export default async function globalSetup(config) {
  const baseURL = config.projects[0].use.baseURL;
  const browser = await chromium.launch();
  const page = await browser.newPage({ baseURL });

  // Navigate first: a fetch from about:blank has no origin, so CORS blocks it.
  await page.goto('/login');

  const tokens = await page.evaluate(async ({ api, user }) => {
    const res = await fetch(`${api}/auth/login/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(user),
    });
    if (!res.ok) return { error: `${res.status} ${await res.text()}` };
    return res.json();
  }, { api: API, user: USER });

  if (tokens.error || !tokens.access) {
    await browser.close();
    throw new Error(
      `Global setup could not authenticate (${tokens.error ?? 'no token'}). ` +
      `Is the backend running on ${API} with the seeded analyst account? ` +
      `A 429 means the login throttle is exhausted — wait for the window to reset.`,
    );
  }

  // The app keeps tokens in sessionStorage, which Playwright's storageState
  // does not capture (it persists cookies and localStorage). So the tokens are
  // written to disk and injected per-page by the auth fixture instead.
  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  fs.writeFileSync(STATE, JSON.stringify(tokens, null, 2));
  await browser.close();
}
