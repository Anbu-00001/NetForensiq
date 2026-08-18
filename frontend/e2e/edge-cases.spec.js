import { test, expect, apiGet, apiPost, rows, API_BASE, tokensFor } from './fixtures';

/**
 * Edge cases and corners.
 *
 * The main suite covers the paths a demo takes. This one covers the paths a
 * judge takes when they try to break it: an expired session, a viewer clicking
 * things they are not cleared for, a deep link into a filter, a certificate
 * signed twice by one account, the API falling over mid-page.
 *
 * Everything here asserts a *requirement*, not merely that nothing threw. A
 * test that only proves the page did not crash would pass over a page showing
 * nothing at all.
 */

const RULE_ID = /^(C2_BEACON|COVERT_CHANNEL|DNS_TUNNEL|RECON_|EXFIL_|ICMP_|HOST_)/;

// ── authentication and session ──────────────────────────────────────────

test.describe('sessions end when they should', () => {
  test('an invalid token lands on login rather than a blank page', async ({ browser, baseURL }) => {
    const context = await browser.newContext({ baseURL });
    const page = await context.newPage();
    await page.addInitScript(() => {
      sessionStorage.setItem('access_token', 'not.a.real.token');
      sessionStorage.setItem('refresh_token', 'also.not.real');
    });

    await page.goto('/dashboard');
    await expect(page).toHaveURL(/login/, { timeout: 20_000 });
    await context.close();
  });

  test('signing out invalidates the refresh token on the server', async ({ request }) => {
    // Logout used to be client-side only: the browser dropped its storage and
    // the refresh token stayed valid for a full day.
    const { refresh } = tokensFor('analyst');

    // A throwaway session, so the suite's own cached token survives.
    const fresh = await (await request.post(`${API_BASE}/auth/login/`, {
      data: { username: 'analyst', password: process.env.NETFORENSIQ_DEMO_PASSWORD ?? 'demo-pass-1234' },
      failOnStatusCode: false,
    })).json().catch(() => ({}));

    test.skip(!fresh?.refresh, 'login throttled; cannot test blacklisting this run');
    expect(fresh.refresh).not.toBe(refresh);

    const before = await request.post(`${API_BASE}/auth/login/refresh/`, {
      data: { refresh: fresh.refresh }, failOnStatusCode: false,
    });
    expect(before.status(), 'a fresh refresh token should work').toBe(200);

    await request.post(`${API_BASE}/auth/logout/`, {
      headers: { Authorization: `Bearer ${fresh.access}` },
      data: { refresh: fresh.refresh },
    });

    const after = await request.post(`${API_BASE}/auth/login/refresh/`, {
      data: { refresh: fresh.refresh }, failOnStatusCode: false,
    });
    expect(after.status(), 'the token must be dead after signing out').not.toBe(200);
  });

  test('tokens are never written to localStorage', async ({ page }) => {
    // sessionStorage dies with the tab; localStorage survives it. On a shared
    // machine in a police station that difference matters.
    await page.goto('/dashboard');
    await expect(page.getByText(/Packets/i).first()).toBeVisible({ timeout: 20_000 });

    const leaked = await page.evaluate(() => Object.keys(localStorage));
    expect(leaked, `tokens leaked into localStorage: ${leaked}`).toEqual([]);
  });
});

// ── clearance ───────────────────────────────────────────────────────────

test.describe('viewer clearance is honoured by the interface', () => {
  test('a viewer sees findings but is not offered triage controls', async ({ viewerPage }) => {
    await viewerPage.goto('/detections');
    await expect(viewerPage.getByText(/Findings/i).first()).toBeVisible();

    const card = viewerPage.getByRole('button', { name: RULE_ID }).first();
    await expect(card, 'a viewer must still be able to read findings').toBeVisible();
    await card.click();

    // Rendering a control that always returns 403 is a fake affordance.
    await expect(
      viewerPage.getByRole('button', { name: /^Confirm$/ }),
    ).toHaveCount(0);
    await expect(
      viewerPage.getByRole('button', { name: /Dismiss \(false positive\)/ }),
    ).toHaveCount(0);
  });

  test('a viewer is not offered evidence actions', async ({ viewerPage }) => {
    await viewerPage.goto('/evidence');
    await expect(viewerPage.getByText(/Evidence register/i)).toBeVisible();

    await expect(viewerPage.getByRole('button', { name: /Re-verify integrity/i })).toHaveCount(0);
    await expect(viewerPage.getByRole('button', { name: /Issue certificate/i })).toHaveCount(0);
    await expect(viewerPage.getByRole('button', { name: /Countersign Part B/i })).toHaveCount(0);
  });

  test('the server refuses a viewer even if the request is made directly', async ({ request }) => {
    // The UI hiding a button is a courtesy. The guard is on the server.
    const { access } = tokensFor('viewer');
    const findings = await (await request.get(`${API_BASE}/detections/`, {
      headers: { Authorization: `Bearer ${access}` },
    })).json();
    const first = (Array.isArray(findings) ? findings : findings.results ?? [])[0];
    test.skip(!first, 'no findings seeded');

    const refused = await request.post(`${API_BASE}/detections/${first.id}/triage/`, {
      headers: { Authorization: `Bearer ${access}` },
      data: { status: 'confirmed', note: 'viewer should not be able to do this' },
      failOnStatusCode: false,
    });
    expect(refused.status()).toBe(403);
  });
});

// ── findings ────────────────────────────────────────────────────────────

test.describe('the findings list is the whole findings list', () => {
  test('every finding is loaded, not just the first page', async ({ page }) => {
    // The page once rendered data.results — the first 50 rows of every session
    // pooled — while the "awaiting review" chip counted only what had loaded.
    const total = await page.evaluate(async (base) => {
      const token = sessionStorage.getItem('access_token');
      const r = await fetch(`${base}/detections/`, {
        headers: { Authorization: `Bearer ${token}` },
      }).then((x) => x.json());
      return r.count ?? (Array.isArray(r) ? r.length : r.results.length);
    }, API_BASE);

    test.skip(total <= 50, 'fewer than one page of findings; nothing to prove');

    await page.goto('/detections');
    await expect(page.getByRole('button', { name: RULE_ID }).first()).toBeVisible();

    // Wait for paging to finish, then count rendered rows.
    await expect
      .poll(async () => page.getByRole('button', { name: RULE_ID }).count(),
            { timeout: 40_000 })
      .toBe(total);
  });

  test('a search that matches nothing says so instead of showing everything', async ({ page }) => {
    await page.goto('/detections?q=zzz-no-such-host-zzz');
    await expect(page.getByText(/No findings match/i)).toBeVisible();
    await expect(page.getByRole('button', { name: RULE_ID })).toHaveCount(0);
  });

  test('a search with regex metacharacters is treated as text', async ({ page }) => {
    // The filter is a substring match; if it ever became a regex, ".*" would
    // silently match everything and the "filtered" chip would lie.
    await page.goto('/detections?q=.*');
    await expect(page.getByText(/No findings match/i)).toBeVisible();
  });

  test('a finding row opens from the keyboard', async ({ page }) => {
    await page.goto('/detections');
    const card = page.getByRole('button', { name: RULE_ID }).first();
    await expect(card).toBeVisible();

    await card.focus();
    await expect(card).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('Enter');
    await expect(card).toHaveAttribute('aria-expanded', 'true');
  });

  test('every published threshold is listed, not a sample of them', async ({ page, request }) => {
    const published = await (await request.get(`${API_BASE}/detections/thresholds/`, {
      headers: { Authorization: `Bearer ${tokensFor('analyst').access}` },
    })).json();

    await page.goto('/detections');
    await page.getByRole('button', { name: /detection thresholds/i }).click();

    const body = await page.locator('body').innerText();
    for (const threshold of published) {
      expect(body, `threshold ${threshold.key} is published but not shown`)
        .toContain(threshold.key);
    }
  });

  test('finding text is rendered as text, never as markup', async ({ page }) => {
    // Rationale and evidence are attacker-influenced: they carry hostnames and
    // DNS query names lifted straight out of the capture. Counting inline
    // scripts would only measure the dev server's own preamble, so this asks
    // the question that matters — did any capture-derived string end up
    // *inside* a script rather than in the page's text?
    await page.goto('/detections');
    const card = page.getByRole('button', { name: RULE_ID }).first();
    await expect(card).toBeVisible();
    await card.click();

    const findings = rows(await apiGet(page, 'detections/'));
    const strings = findings
      .slice(0, 20)
      .flatMap((f) => [f.subject_ip, f.rule_id, f.title])
      .filter(Boolean);

    const contaminated = await page.evaluate((needles) => {
      const scripts = [...document.querySelectorAll('script')];
      return needles.filter((n) => scripts.some((s) => s.textContent.includes(n)));
    }, strings);

    expect(contaminated, 'capture-derived text reached a <script> element')
      .toEqual([]);
  });
});

// ── evidence and certificates ───────────────────────────────────────────

test.describe('certificates refuse what section 63 refuses', () => {
  test('one account cannot sign both parts', async ({ request }) => {
    const { access } = tokensFor('analyst');
    const exhibits = await (await request.get(`${API_BASE}/evidence/`, {
      headers: { Authorization: `Bearer ${access}` },
    })).json();
    const exhibit = (Array.isArray(exhibits) ? exhibits : exhibits.results ?? [])[0];
    test.skip(!exhibit, 'no evidence seeded');

    const issued = await request.post(`${API_BASE}/evidence/${exhibit.id}/certificate/`, {
      headers: { Authorization: `Bearer ${access}` },
      data: { part_a_name: 'analyst', part_a_designation: 'IO' },
      failOnStatusCode: false,
    });
    test.skip(issued.status() !== 201, `could not issue a certificate (${issued.status()})`);
    const certificate = await issued.json();

    // s.63(4) contemplates the person in charge of the device AND an expert.
    const countersigned = await request.post(`${API_BASE}/certificates/${certificate.id}/sign/`, {
      headers: { Authorization: `Bearer ${access}` },
      data: { part_b_name: 'analyst', part_b_qualification: 'expert' },
      failOnStatusCode: false,
    });
    expect(countersigned.status(), 'the same account signed both parts').toBe(409);
    expect(await countersigned.text()).toMatch(/different people/i);
  });

  test('a half-signed certificate presents itself as a draft', async ({ page, request }) => {
    const certificates = rows(await apiGet(page, 'certificates/'));
    const draft = certificates.find((c) => !c.is_complete);
    test.skip(!draft, 'no incomplete certificate to check');

    const pdf = await request.get(`${API_BASE}/certificates/${draft.id}/pdf/`, {
      headers: { Authorization: `Bearer ${tokensFor('analyst').access}` },
    });
    expect(pdf.status()).toBe(200);

    await page.goto('/evidence');
    await expect(page.getByText(/DRAFT — Part B unsigned/).first()).toBeVisible();
  });

  test('re-verifying an exhibit reports a verdict either way', async ({ page }) => {
    await page.goto('/evidence');
    const exhibits = rows(await apiGet(page, 'evidence/'));
    test.skip(exhibits.length === 0, 'no evidence seeded');

    const result = await apiPost(page, `evidence/${exhibits[0].id}/verify/`, {});
    expect(result).toHaveProperty('verified');
    expect(result.expected_sha256).toBe(exhibits[0].sha256_hash);
    // A pass must compute the same digest, not merely decline to complain.
    if (result.verified) {
      expect(result.computed_sha256).toBe(result.expected_sha256);
    }
  });

  test('the custody chain reports its own integrity', async ({ page }) => {
    const exhibits = rows(await apiGet(page, 'evidence/'));
    test.skip(exhibits.length === 0, 'no evidence seeded');

    const chain = await apiGet(page, `evidence/${exhibits[0].id}/custody/`);
    expect(chain.chain_intact, `custody chain broken: ${chain.problems}`).toBe(true);
    expect(chain.events.length).toBeGreaterThan(0);

    // Each entry must digest its predecessor, or the chain proves nothing.
    for (let i = 1; i < chain.events.length; i += 1) {
      expect(chain.events[i].previous_hash).toBe(chain.events[i - 1].entry_hash);
    }
    expect(chain.events[0].previous_hash).toBe('');
  });
});

// ── resilience ──────────────────────────────────────────────────────────

test.describe('failures are visible, not silent', () => {
  test('an unreachable API shows an error instead of an empty dashboard', async ({ page }) => {
    await page.route(`${API_BASE}/sessions/**`, (route) => route.abort());
    await page.goto('/dashboard');

    await expect(page.getByText(/Could not reach the API|Failed to load/i).first())
      .toBeVisible({ timeout: 20_000 });
  });

  test('a failing findings request does not empty the threshold panel', async ({ page }) => {
    // These used to share a Promise.all, so one failure blanked both — on the
    // page whose whole purpose is publishing thresholds.
    await page.route(`${API_BASE}/detections/?**`, (route) => route.abort());
    await page.route(`${API_BASE}/detections/`, (route) => route.abort());

    await page.goto('/detections');
    await page.getByRole('button', { name: /detection thresholds/i }).click();
    await expect(page.getByText(/beacon_min_connections/).first()).toBeVisible();
  });

  test('a deep link into a filtered view works on first load', async ({ page }) => {
    const findings = rows(await apiGet(page, 'detections/'));
    test.skip(findings.length === 0, 'no findings seeded');
    const subject = findings[0].subject_ip;

    await page.goto(`/detections?q=${encodeURIComponent(subject)}`);
    await expect(page.getByText(/filtered:/i)).toBeVisible();
    await expect(page.getByRole('button', { name: RULE_ID }).first()).toBeVisible();
  });

  test('the app is usable on a phone-sized viewport', async ({ page }) => {
    // Officers carry phones, and a demo on a projector is not the only screen
    // this will be opened on.
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/dashboard');
    await expect(page.getByText(/Packets/i).first()).toBeVisible({ timeout: 20_000 });

    const overflow = await page.evaluate(() =>
      document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, 'the page scrolls sideways on a phone').toBeLessThanOrEqual(1);
  });
});
