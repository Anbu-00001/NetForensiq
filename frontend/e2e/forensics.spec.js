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

/**
 * How many rows the API holds for an endpoint.
 *
 * Skips must be decided from server state, never from `locator.count()`.
 * `count()` returns 0 for "not rendered yet" as readily as for "does not
 * exist", so a skip guarded that way turns a real UI regression into a green
 * run — which is exactly what happened here before this helper existed.
 */
async function apiCount(page, path) {
  return page.evaluate(async (p) => {
    const token = sessionStorage.getItem('access_token');
    const r = await fetch(`http://127.0.0.1:8011/api/${p}`, {
      headers: { Authorization: `Bearer ${token}` },
    }).then((x) => x.json());
    const list = Array.isArray(r) ? r : r.results;
    return list?.length ?? 0;
  }, path);
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

    test.skip(await apiCount(page, 'evidence/') === 0, 'no evidence seeded');

    // Auto-waiting locator, so a slow render fails loudly instead of skipping
    const chainButton = page.getByRole('button', { name: /chain of custody/i }).first();
    await expect(chainButton).toBeVisible();
    await chainButton.click();
    await expect(
      page.getByText(/Custody chain intact|Custody chain BROKEN/i).first(),
    ).toBeVisible();
  });
});

test.describe('section 63 certificate', () => {
  test.beforeEach(async ({ page }) => login(page));

  test('an exhibit exposes its certificates and their completeness', async ({ page }) => {
    await page.goto('/evidence');
    await expect(page.getByText(/Section 63 certificates/i).first()).toBeVisible();

    // s.63(4) needs both parts, so a half-signed certificate must say so
    // rather than presenting itself as valid.
    const badge = page.getByText(/Both parts signed|DRAFT — Part B unsigned/).first();
    await expect(badge).toBeVisible();
  });

  test('the certificate downloads as a real PDF', async ({ page }) => {
    await page.goto('/evidence');

    test.skip(
      await apiCount(page, 'certificates/') === 0,
      'no certificate issued for any exhibit',
    );

    const button = page.getByRole('button', { name: /Download PDF/i }).first();
    await expect(button).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent('download'),
      button.click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^S63-.*\.pdf$/);

    // Assert it is actually a PDF, not an error page saved with a .pdf name
    const path = await download.path();
    const fs = await import('node:fs');
    const header = fs.readFileSync(path).subarray(0, 5).toString();
    expect(header).toBe('%PDF-');
  });
});

test.describe('air-gapped operation', () => {
  /**
   * The venue may have no usable internet. A page that quietly depends on a
   * CDN font or a remote script looks fine on a developer laptop and falls
   * apart on the day, so this proves the app needs nothing beyond localhost.
   *
   * Every request to any other host is aborted, and any attempt is recorded
   * and asserted against — a failed background fetch that the UI swallows
   * would otherwise pass unnoticed.
   */
  test('the app works with every non-local request blocked', async ({ page }) => {
    const blocked = [];

    await page.route('**', (route) => {
      const url = new URL(route.request().url());
      const local = ['127.0.0.1', 'localhost', '::1'].includes(url.hostname);
      if (local || url.protocol === 'data:' || url.protocol === 'blob:') {
        return route.continue();
      }
      blocked.push(url.href);
      return route.abort();
    });

    await page.goto('/dashboard');
    await page.waitForURL(/dashboard/, { timeout: 20_000 });

    // Wait for data to actually arrive, rather than asserting against a
    // half-rendered shell — the sidebar alone would satisfy a loose match.
    await expect(page.getByText(/Packets/i).first()).toBeVisible({ timeout: 20_000 });

    expect(
      blocked,
      `the app reached for external hosts: ${blocked.join(', ')}`,
    ).toEqual([]);
  });

  test('findings and evidence pages need no external hosts either', async ({ page }) => {
    const blocked = [];
    await page.route('**', (route) => {
      const url = new URL(route.request().url());
      const local = ['127.0.0.1', 'localhost', '::1'].includes(url.hostname);
      if (local || url.protocol === 'data:' || url.protocol === 'blob:') {
        return route.continue();
      }
      blocked.push(url.href);
      return route.abort();
    });

    await page.goto('/detections');
    await expect(page.getByText(/Findings/i).first()).toBeVisible();

    await page.goto('/evidence');
    await expect(page.getByText(/Evidence register/i)).toBeVisible();

    expect(blocked, `external hosts requested: ${blocked.join(', ')}`).toEqual([]);
  });
});

test.describe('the interface claims nothing it cannot do', () => {
  test.beforeEach(async ({ page }) => login(page));

  test('no controls for actions this tool cannot perform', async ({ page }) => {
    // These were live-looking buttons wired to nothing. On a tool whose whole
    // claim is evidentiary integrity, an inert "Purge buffer" control next to
    // the evidence register is worse than useless.
    const body = await page.locator('body').innerText();
    for (const phantom of ['Purge buffer', 'Rotate storage']) {
      expect(body).not.toContain(phantom);
    }
  });

  test('the sidebar capture window reflects the real session', async ({ page }) => {
    const session = await page.evaluate(async () => {
      const token = sessionStorage.getItem('access_token');
      const r = await fetch('http://127.0.0.1:8011/api/sessions/', {
        headers: { Authorization: `Bearer ${token}` },
      }).then((x) => x.json());
      const list = Array.isArray(r) ? r : r.results;
      return list?.length ? list[0] : null;
    });

    test.skip(!session?.capture_start, 'no capture session seeded');

    // The old build showed a hardcoded 2026-08-02 09:14:07 and "2d 04h 11m"
    const body = await page.locator('body').innerText();
    expect(body).not.toContain('2d 04h 11m');

    const year = new Date(session.capture_start).getFullYear();
    expect(body).toContain(String(year));
  });

  test('search filters findings instead of doing nothing', async ({ page }) => {
    await page.goto('/detections');

    const subject = await page.evaluate(async () => {
      const token = sessionStorage.getItem('access_token');
      const r = await fetch('http://127.0.0.1:8011/api/detections/', {
        headers: { Authorization: `Bearer ${token}` },
      }).then((x) => x.json());
      const list = Array.isArray(r) ? r : r.results;
      return list?.length ? list[0].subject_ip : null;
    });

    test.skip(!subject, 'no detections seeded');

    await page.goto(`/detections?q=${encodeURIComponent(subject)}`);
    await expect(page.getByText(/filtered:/i)).toBeVisible();

    // A filter that matches nothing would also show a chip; assert findings survived
    await expect(
      page.locator('text=/C2_BEACON|DNS_TUNNEL|RECON_|EXFIL_|ICMP_|COVERT_/').first(),
    ).toBeVisible();
  });
});

test.describe('public pages make no false claims', () => {
  /**
   * The landing page escaped every earlier check because the suite only ever
   * visited authenticated routes. It was still rendering "Evidence sealed
   * 2,417", "Packets / sec 84.2 K" and "UPTIME 2d 04h" over Math.sin
   * sparklines — months after PROGRESS.md recorded removing exactly those.
   * These run anonymously, which is how a judge first sees the product.
   */
  const PUBLIC = ['/', '/login', '/register'];

  const FABRICATED = [
    '2,417', '84.2 K', '512.0 M', '1,482',   // invented telemetry figures
    '2d 04h',                                 // invented uptime
    'ISOLATION FOREST',                       // no model exists in the codebase
    'D3 GRAPH ENGINE',                        // no flow-graph page exists
    'LIVE CAPTURE PREVIEW',                   // nothing is capturing live
    'LIVE SYSTEM TELEMETRY',                  // pre-auth, nothing could back it
    'AUTHORIZED DEPLOYMENT',                  // no authority deployed this
    'TLS 1.3 CHANNEL',                        // demo stack runs over plain HTTP
  ];

  for (const path of PUBLIC) {
    test(`${path} shows no fabricated figures or capabilities`, async ({ anonymousPage }) => {
      await anonymousPage.goto(`http://127.0.0.1:5199${path}`);
      await anonymousPage.waitForLoadState('networkidle');
      const body = await anonymousPage.locator('body').innerText();

      for (const phrase of FABRICATED) {
        expect(body, `${path} still shows "${phrase}"`).not.toContain(phrase);
      }
    });
  }

  test('the landing page does not claim to be tamper-proof', async ({ anonymousPage }) => {
    // The custody model's own docstring says tamper-EVIDENT, "which is the
    // honest claim to make about a database table". The marketing copy must
    // not promise more than the code is willing to.
    await anonymousPage.goto('http://127.0.0.1:5199/');
    const body = await anonymousPage.locator('body').innerText();
    expect(body.toLowerCase()).not.toContain('tamper-proof');
  });
});
