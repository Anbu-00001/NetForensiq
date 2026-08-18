import { test as base, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const TOKENS = path.join('e2e', '.auth', 'tokens.json');

/**
 * The API the suite talks to directly.
 *
 * Assertions compare what is on screen against what the API returns, so they
 * fetch it themselves. That address was written out seven times across the
 * spec; change the port and the two anti-fabrication guards would have gone on
 * passing while testing nothing. Playwright's webServer passes VITE_API_BASE,
 * so this is the same value the app itself uses.
 */
export const API_BASE = process.env.VITE_API_BASE ?? 'http://127.0.0.1:8011/api';

/**
 * Test fixtures.
 *
 * `page` arrives already authenticated. The app stores JWTs in sessionStorage,
 * which Playwright's storageState does not persist, so the tokens obtained
 * once in global setup are injected via addInitScript — that runs before any
 * page script, so the app boots already signed in and never hits the
 * throttled login endpoint.
 *
 * `anonymousPage` is a clean context for testing that guards actually guard.
 */
export function tokensFor(role) {
  const all = JSON.parse(fs.readFileSync(TOKENS, 'utf-8'));
  const tokens = all[role];
  if (!tokens?.access) {
    throw new Error(`No cached tokens for '${role}' — re-run global setup.`);
  }
  return tokens;
}

async function signedIn(page, role) {
  await page.addInitScript(({ access, refresh }) => {
    sessionStorage.setItem('access_token', access);
    sessionStorage.setItem('refresh_token', refresh);
  }, tokensFor(role));
  return page;
}

export const test = base.extend({
  page: async ({ page }, use) => {
    await use(await signedIn(page, 'analyst'));
  },

  /** A signed-in administrator — the only role that may approve accounts. */
  adminPage: async ({ browser, baseURL }, use) => {
    const context = await browser.newContext({ baseURL });
    const page = await context.newPage();
    await signedIn(page, 'commander');
    await use(page);
    await context.close();
  },

  /**
   * A signed-in account holding Viewer clearance.
   *
   * The role model is enforced on the server, and every test until now ran as
   * an investigator — so nothing checked that the interface stops offering
   * actions a viewer cannot take. Rendering a Confirm button that always
   * returns 403 is a fake affordance.
   */
  viewerPage: async ({ browser, baseURL }, use) => {
    const context = await browser.newContext({ baseURL });
    const page = await context.newPage();
    await signedIn(page, 'viewer');
    await use(page);
    await context.close();
  },

  // baseURL is threaded through so specs can use relative paths here too.
  // Without it every anonymous navigation needed an absolute URL, which is
  // how three assertions ended up pinned to a port the config also defines.
  anonymousPage: async ({ browser, baseURL }, use) => {
    const context = await browser.newContext({ baseURL });
    const page = await context.newPage();
    await use(page);
    await context.close();
  },
});

export { expect };

/**
 * Call the API from inside the page, with the page's own access token.
 *
 * The address has to cross into the browser context as an argument: a
 * `page.evaluate` closure is serialised and run in the page, where Node's
 * module scope does not exist. Five call sites each inlined the URL instead,
 * which is how the port ended up written out seven times.
 */
/**
 * The evaluate calls below read sessionStorage, which `about:blank` refuses —
 * an opaque origin has no storage. A test that calls the API before its first
 * navigation would otherwise fail with a SecurityError that says nothing about
 * what it was testing.
 */
async function onAppOrigin(page) {
  if (!page.url().startsWith('http')) {
    await page.goto('/');
  }
}

export async function apiGet(page, path) {
  await onAppOrigin(page);
  return page.evaluate(async ({ base, p }) => {
    const token = sessionStorage.getItem('access_token');
    const response = await fetch(`${base}/${p}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return response.json();
  }, { base: API_BASE, p: path });
}

export async function apiPost(page, path, payload) {
  await onAppOrigin(page);
  return page.evaluate(async ({ base, p, body }) => {
    const token = sessionStorage.getItem('access_token');
    const response = await fetch(`${base}/${p}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    return response.json();
  }, { base: API_BASE, p: path, body: payload });
}

/** DRF paginates; plain lists come back bare. */
export const rows = (data) => (Array.isArray(data) ? data : data?.results ?? []);
