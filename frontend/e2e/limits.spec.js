// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import { test, expect } from './fixtures';

/**
 * The page that says what the tool cannot establish.
 *
 * The check that matters is not "a page renders" but "the numbers on it are the
 * measured ones": the same figures the validation report derives, read from the
 * API, not typed into the page. An earlier version of this information, in the
 * investigation report, said "thirty-five thresholds" and "ten rules" after both
 * had changed.
 */
const API = process.env.VITE_API_BASE ?? 'http://127.0.0.1:8011/api';

test.describe('limits of this tool', () => {
  test('is public, and states the measured miss rate before anyone signs in', async ({ anonymousPage }) => {
    const limits = await (await anonymousPage.request.get(`${API}/engine/limits/`)).json();
    const u = limits.validation.apk.unseen;

    await anonymousPage.goto('/limits');
    await expect(anonymousPage.getByText('If the tool finds nothing')).toBeVisible();
    // The sentence an officer should use, carrying the numbers the API carries.
    await expect(anonymousPage.getByText(`reached none on ${u.missed}`)).toBeVisible();
    await expect(anonymousPage.getByText(`On ${u.n} malware samples`).first()).toBeVisible();
    // No navigation shell for someone who is not signed in.
    await expect(anonymousPage.getByText('Examine sample')).toHaveCount(0);
  });

  test('says where a standard was read and where only a summary was', async ({ anonymousPage }) => {
    await anonymousPage.goto('/limits');
    await expect(anonymousPage.getByText(/NIST SP 800-86/).first()).toBeVisible();
    await expect(anonymousPage.getByText(/text read/)).toBeVisible();
    await expect(anonymousPage.getByText(/secondary source: text not read/)).toBeVisible();
    // The page must not *claim* compliance. It does say, in so many words, that
    // it does not — "nothing below says this tool complies with them" — so the
    // check is for positive claims, not for the words.
    const text = await anonymousPage.locator('body').innerText();
    expect(text).not.toMatch(/\b(complies|conforms)\s+with\s+(NIST|ISO)/i);
    expect(text).not.toMatch(/\b(is|are)\s+(compliant|certified|accredited)\b/i);
    expect(text).toMatch(/not accredited/);
  });

  test('counts on the page are the code\'s counts', async ({ anonymousPage }) => {
    const limits = await (await anonymousPage.request.get(`${API}/engine/limits/`)).json();
    await anonymousPage.goto('/limits');
    const { thresholds, heuristic_thresholds: heuristic } = limits.counts;
    await expect(anonymousPage.getByText(`${heuristic} of the ${thresholds} thresholds`)).toBeVisible();
  });

  test('a signed-in officer reaches it from the navigation and keeps the shell', async ({ page }) => {
    await page.goto('/dashboard');
    await page.getByText('Limits of this tool').first().click();
    await expect(page).toHaveURL(/\/limits$/);
    await expect(page.getByText('What was measured')).toBeVisible();
    await expect(page.getByText('Dashboard').first()).toBeVisible(); // the sidebar is still there
  });

  test('it asks nothing of the network beyond this machine', async ({ anonymousPage }) => {
    const external = [];
    anonymousPage.on('request', (r) => {
      const host = new URL(r.url()).hostname;
      if (!['127.0.0.1', 'localhost'].includes(host) && r.url().startsWith('http')) external.push(r.url());
    });
    await anonymousPage.goto('/limits');
    await expect(anonymousPage.getByRole('heading', { name: 'What it cannot establish' })).toBeVisible();
    expect(external).toEqual([]);
  });
});
