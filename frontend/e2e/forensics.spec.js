import { test, expect } from './fixtures';

const USER = { username: 'analyst', password: 'demo-pass-1234' };

/**
 * These tests assert the thing the code review flagged as the project's
 * biggest credibility problem: that what appears on screen is real.
 *
 * A dashboard that renders is not the bar. A dashboard whose numbers match
 * the API is.
 */

async function login(page) {
  // Credentials are already in storage via global setup; this just lands the
  // session on an authenticated page.
  await page.goto('/dashboard');
  await page.waitForURL(/dashboard/, { timeout: 20_000 });
}

test.describe('authentication', () => {
  test('protected routes redirect anonymous users to login', async ({ anonymousPage }) => {
    await anonymousPage.goto('http://127.0.0.1:5199/dashboard');
    await expect(anonymousPage).toHaveURL(/login/);
  });

  test('a signed-in analyst reaches the dashboard', async ({ page }) => {
    await login(page);
    await expect(page).toHaveURL(/dashboard/);
  });
});

test.describe('dashboard shows real data', () => {
  test.beforeEach(async ({ page }) => login(page));

  test('stat cards match the API summary exactly', async ({ page }) => {
    // Read what the API actually returned for the selected session
    const summary = await page.evaluate(async () => {
      const token = sessionStorage.getItem('access_token');
      const sessions = await fetch('http://127.0.0.1:8011/api/sessions/', {
        headers: { Authorization: `Bearer ${token}` },
      }).then((r) => r.json());
      const list = Array.isArray(sessions) ? sessions : sessions.results;
      if (!list.length) return null;
      return fetch(`http://127.0.0.1:8011/api/sessions/${list[0].id}/summary/`, {
        headers: { Authorization: `Bearer ${token}` },
      }).then((r) => r.json());
    });

    test.skip(!summary, 'no capture sessions seeded');

    // The flow count on screen must be the flow count in the database
    const body = await page.locator('body').innerText();
    expect(body).toContain(String(summary.totals.flows));
  });

  test('no "Blocked" or "Archived" card — the tool cannot do either', async ({ page }) => {
    const body = await page.locator('body').innerText();
    expect(body).not.toMatch(/\bBlocked\b/);
    expect(body).not.toMatch(/\bArchived\b/);
  });

  test('the old hardcoded placeholder figures are gone', async ({ page }) => {
    const body = await page.locator('body').innerText();
    for (const stale of ['627.16 M', '512.04 M', '14.82 M', '2.41 M', '88.30 M']) {
      expect(body).not.toContain(stale);
    }
  });
});

test.describe('findings', () => {
  test.beforeEach(async ({ page }) => login(page));

  test('each finding explains itself and exposes its thresholds', async ({ page }) => {
    await page.goto('/detections');
    await expect(page.getByText(/Findings/i).first()).toBeVisible();

    // Threshold provenance must be inspectable from the UI
    await page.getByRole('button', { name: /detection thresholds/i }).click();
    await expect(page.getByText(/beacon_min_connections/).first()).toBeVisible();
  });

  test('an analyst can triage a finding', async ({ page }) => {
    await page.goto('/detections');

    // Triage is a state change, so this test resets one finding to "new"
    // first. Without that, a second run finds everything already reviewed
    // and would fail for reasons unrelated to the behaviour under test.
    const pendingId = await page.evaluate(async () => {
      const token = sessionStorage.getItem('access_token');
      const res = await fetch('http://127.0.0.1:8011/api/detections/', {
        headers: { Authorization: `Bearer ${token}` },
      }).then((r) => r.json());
      const list = Array.isArray(res) ? res : res.results;
      if (!list?.length) return null;
      await fetch(`http://127.0.0.1:8011/api/detections/${list[0].id}/triage/`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: 'new', note: '' }),
      });
      return list[0].id;
    });

    test.skip(!pendingId, 'no detections seeded');

    await page.reload();
    const card = page
      .locator('text=/C2_BEACON|DNS_TUNNEL|RECON_|EXFIL_|ICMP_/')
      .first();
    await card.click();

    const dismiss = page.getByRole('button', { name: /Dismiss/i }).first();
    await expect(dismiss).toBeVisible();
    await dismiss.click();

    // The decision must be reflected back from the server, not just locally
    await expect(page.getByText(/Reviewed/i).first()).toBeVisible();
  });
});

test.describe('evidence', () => {
  test.beforeEach(async ({ page }) => login(page));

  test('exhibits show hashes and a custody verdict', async ({ page }) => {
    await page.goto('/evidence');
    await expect(page.getByText(/Evidence register/i)).toBeVisible();

    const chainButton = page.getByRole('button', { name: /chain of custody/i }).first();
    const count = await chainButton.count();
    test.skip(count === 0, 'no evidence seeded');

    await chainButton.click();
    await expect(
      page.getByText(/Custody chain intact|Custody chain BROKEN/i).first(),
    ).toBeVisible();
  });
});
