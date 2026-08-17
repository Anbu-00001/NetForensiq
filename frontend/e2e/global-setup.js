import { chromium } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const API = process.env.VITE_API_BASE ?? 'http://127.0.0.1:8011/api';
const USER = { username: 'analyst', password: 'demo-pass-1234' };
const STATE = path.join('e2e', '.auth', 'tokens.json');

/**
 * Authenticate once, and only when the cached token has actually expired.
 *
 * The login endpoint is throttled to 8/hour — a brute-force control on a
 * police system, and one worth keeping. But a suite that burns one login per
 * run becomes unrunnable after eight runs, which during active development is
 * an afternoon. The first version of this file logged in every time and did
 * exactly that.
 *
 * Access tokens last 30 minutes, so the cached one is reused whenever it still
 * works. That is verified by making a real authenticated request rather than
 * by decoding the expiry: a token can also be invalid because the database was
 * rebuilt underneath it, and only the server knows.
 */
async function tokenStillWorks(page, access) {
  return page.evaluate(async ({ api, token }) => {
    try {
      const res = await fetch(`${api}/sessions/`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return res.ok;
    } catch {
      return false;
    }
  }, { api: API, token: access });
}

export default async function globalSetup(config) {
  const baseURL = config.projects[0].use.baseURL;
  const browser = await chromium.launch();
  const page = await browser.newPage({ baseURL });

  // Navigate first: a fetch from about:blank has no origin, so CORS blocks it.
  await page.goto('/login');

  let tokens = null;
  if (fs.existsSync(STATE)) {
    try {
      const cached = JSON.parse(fs.readFileSync(STATE, 'utf-8'));
      if (cached?.access && await tokenStillWorks(page, cached.access)) {
        tokens = cached;
      }
    } catch {
      tokens = null;   // unreadable cache is the same as no cache
    }
  }

  if (!tokens) {
    tokens = await page.evaluate(async ({ api, user }) => {
      const res = await fetch(`${api}/auth/login/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(user),
      });
      if (!res.ok) return { error: `${res.status} ${await res.text()}` };
      return res.json();
    }, { api: API, user: USER });
  }

  if (tokens.error || !tokens.access) {
    await browser.close();
    throw new Error(
      `Global setup could not authenticate (${tokens.error ?? 'no token'}). ` +
      `Is the backend running on ${API} with the seeded analyst account? ` +
      `A 429 means the login throttle is exhausted — the cached token has also ` +
      `expired or been invalidated. Either wait for the window to reset, or ` +
      `clear the throttle for local runs:\n` +
      `  cd backend && ./.venv/bin/python manage.py shell -c ` +
      `"from django.core.cache import cache; cache.clear()"`,
    );
  }

  // The app keeps tokens in sessionStorage, which Playwright's storageState
  // does not capture (it persists cookies and localStorage). So the tokens are
  // written to disk and injected per-page by the auth fixture instead.
  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  fs.writeFileSync(STATE, JSON.stringify(tokens, null, 2));
  await browser.close();
}
