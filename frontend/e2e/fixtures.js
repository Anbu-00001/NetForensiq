import { test as base, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const TOKENS = path.join('e2e', '.auth', 'tokens.json');

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
export const test = base.extend({
  page: async ({ page }, use) => {
    const tokens = JSON.parse(fs.readFileSync(TOKENS, 'utf-8'));
    await page.addInitScript(({ access, refresh }) => {
      sessionStorage.setItem('access_token', access);
      sessionStorage.setItem('refresh_token', refresh);
    }, tokens);
    await use(page);
  },

  anonymousPage: async ({ browser }, use) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    await use(page);
    await context.close();
  },
});

export { expect };
