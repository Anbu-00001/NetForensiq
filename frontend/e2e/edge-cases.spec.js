import { test, expect, apiGet, apiPost, rows, API_BASE, tokensFor } from './fixtures';
import { GUJARATI } from '../src/i18n/gujarati';

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
    const { refresh } = tokensFor('investigator');

    // A throwaway session, so the suite's own cached token survives.
    const fresh = await (await request.post(`${API_BASE}/auth/login/`, {
      data: { username: 'investigator', password: process.env.NETFORENSIQ_DEMO_PASSWORD ?? 'Netforensiq@2026' },
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
    await page.goto('/detections');
    const firstPage = await apiGet(page, 'detections/');
    const total = firstPage.count
      ?? (Array.isArray(firstPage) ? firstPage.length : firstPage.results.length);

    test.skip(total <= 50, 'fewer than one page of findings; nothing to prove');

    await expect(page.getByRole('button', { name: RULE_ID }).first())
      .toBeVisible({ timeout: 30_000 });

    // Every finding is loaded and counted; the list renders in batches because
    // putting hundreds of expandable cards in the DOM at once takes seconds.
    // What must never happen is the page implying it holds fewer than it does,
    // so the true total has to be on screen.
    await expect(page.getByText(new RegExp(`of ${total} findings`)))
      .toBeVisible({ timeout: 30_000 });

    const before = await page.getByRole('button', { name: RULE_ID }).count();
    await page.getByRole('button', { name: /Show \d+ more/ }).click();
    await expect
      .poll(async () => page.getByRole('button', { name: RULE_ID }).count())
      .toBeGreaterThan(before);
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
      headers: { Authorization: `Bearer ${tokensFor('investigator').access}` },
    })).json();

    await page.goto('/detections');
    await page.getByRole('button', { name: /detection thresholds/i }).click();

    // The panel opens behind a Collapse transition, so the keys are not in the
    // rendered text the instant the click resolves. Waiting for the first one
    // is the difference between a test and a coin toss.
    await expect(page.getByText(published[0].key, { exact: false }).first())
      .toBeVisible({ timeout: 20_000 });

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
    // Section 63(4) contemplates the person in charge of the device AND an
    // expert. Checked against a certificate that already exists: an earlier
    // version of this test issued a fresh one on every run, which left seven
    // orphan DRAFT certificates in the demonstration database — a test writing
    // statutory documents into the data a judge is shown.
    const { access } = tokensFor('investigator');
    const certificates = await (await request.get(`${API_BASE}/certificates/`, {
      headers: { Authorization: `Bearer ${access}` },
    })).json();
    const list = Array.isArray(certificates) ? certificates : certificates.results ?? [];
    const signedByAnalyst = list.find((c) => c.part_a_name === 'investigator');
    test.skip(!signedByAnalyst, 'no certificate whose Part A was signed by this account');

    const refused = await request.post(
      `${API_BASE}/certificates/${signedByAnalyst.id}/sign/`,
      {
        headers: { Authorization: `Bearer ${access}` },
        data: { part_b_name: 'investigator', part_b_qualification: 'expert' },
        failOnStatusCode: false,
      },
    );
    expect(refused.status(), 'the same account signed both parts').toBe(409);
    expect(await refused.text()).toMatch(/different people/i);
  });

  test('each certificate shows the completeness the API reports', async ({ page }) => {
    // s.63(4) requires both parts, so a half-signed certificate must say so
    // rather than presenting itself as valid. Asserted against every
    // certificate rather than skipping when none happens to be incomplete —
    // a suite that skips its way to green is worse than one that fails.
    await page.goto('/evidence');
    const certificates = rows(await apiGet(page, 'certificates/'));
    test.skip(certificates.length === 0, 'no certificates issued');

    await expect(page.getByText(/Section 63 certificates/i).first()).toBeVisible();
    const body = await page.locator('body').innerText();

    for (const certificate of certificates) {
      expect(body, `${certificate.reference} is not listed`)
        .toContain(certificate.reference);
    }

    const complete = certificates.filter((c) => c.is_complete).length;
    const drafts = certificates.length - complete;

    const shownComplete = (body.match(/Both parts signed/g) ?? []).length;
    const shownDraft = (body.match(/DRAFT — Part B unsigned/g) ?? []).length;

    expect(shownComplete, 'complete certificates shown').toBe(complete);
    expect(shownDraft, 'draft certificates shown').toBe(drafts);
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

// ── reading the artefacts in Gujarati ───────────────────────────────────

test.describe('the legal terms are readable in Gujarati', () => {
  test('the evidence register carries a Gujarati gloss', async ({ page }) => {
    await page.goto('/evidence');
    const gloss = page.locator('[lang="gu"]').first();
    await expect(gloss).toBeVisible();

    const text = await gloss.innerText();
    // મુદ્દામાલ is the word Gujarat Police's own case-property registers use
    // for a seized exhibit, and it is the term a magistrate would look for.
    expect(text).toContain('મુદ્દામાલ');
    expect(text).toContain('ભારતીય સાક્ષ્ય અધિનિયમ');
  });

  test('the working pages carry the gloss too, not just the register', async ({ page }) => {
    // A single translated page reads as a gesture. The terms an officer meets
    // while working — findings, severity — carry it as well.
    await page.goto('/detections');
    await expect(page.getByText(GUJARATI.findings).first()).toBeVisible();

    await page.goto('/dashboard');
    await expect(page.getByText(/Packets/i).first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(GUJARATI.severity).first()).toBeVisible();
  });

  test('no deprecated MUI prop reaches the DOM', async ({ page }) => {
    // React logs "does not recognize the PaperProps prop on a DOM element" and
    // the attribute is actually emitted. A console error on a page an officer
    // uses is small; a console error nobody is watching for is how the next
    // one hides.
    const complaints = [];
    page.on('console', (message) => {
      if (message.type() === 'error') complaints.push(message.text());
    });

    for (const route of ['/', '/register', '/login', '/dashboard', '/detections', '/evidence']) {
      await page.goto(route);
      await page.waitForLoadState('networkidle');
    }

    const reactWarnings = complaints.filter((text) =>
      /React does not recognize|Warning:.*prop on a DOM element/i.test(text));
    expect(reactWarnings, reactWarnings.join('\n')).toEqual([]);
  });

  test('Gujarati is marked as Gujarati for assistive technology', async ({ page }) => {
    // Without lang="gu" a screen reader pronounces the script with an English
    // voice, which is worse than not offering it.
    await page.goto('/evidence');
    const count = await page.locator('[lang="gu"]').count();
    expect(count).toBeGreaterThan(0);
  });
});

// ── account approval ────────────────────────────────────────────────────

test.describe('approving an account happens inside the application', () => {
  test('an administrator sees the queue and can act on it', async ({ adminPage }) => {
    await adminPage.goto('/approvals');
    await expect(adminPage.getByText(/Account approvals/i)).toBeVisible();

    const queue = await apiGet(adminPage, 'auth/accounts/pending/');
    test.skip(!queue?.pending?.length, 'no applications waiting');

    for (const account of queue.pending) {
      await expect(adminPage.getByText(account.username, { exact: false }).first())
        .toBeVisible();
    }
    await expect(adminPage.getByRole('button', { name: /^Approve$/ }).first())
      .toBeVisible();
  });

  test('an investigator is told plainly that this is not theirs', async ({ page }) => {
    await page.goto('/approvals');
    await expect(page.getByText(/requires Administrator clearance/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /^Approve$/ })).toHaveCount(0);
  });

  test('the navigation offers approvals only to administrators', async ({ page, adminPage }) => {
    // A link leading to "you are not cleared for this" is a worse answer than
    // no link.
    await adminPage.goto('/dashboard');
    await expect(adminPage.getByText('Approvals').first()).toBeVisible();

    await page.goto('/dashboard');
    await expect(page.getByText(/Packets/i).first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText('Approvals')).toHaveCount(0);
  });
});

// ── the applicant's journey ─────────────────────────────────────────────

test.describe('an applicant can enrol and find out what happened', () => {
  /**
   * The only journey a user takes before they have an account, and the one
   * with no signed-in tester to fall back on. Registration is throttled to
   * 5/hour, so this creates exactly one account per run; verify.sh clears the
   * throttle counter before the suite starts.
   */
  test('registering leaves an application an administrator can see', async ({
    anonymousPage, adminPage,
  }) => {
    const suffix = Date.now().toString(36).slice(-6);
    const username = `applicant-${suffix}`;
    const badge = `E2E-${suffix.toUpperCase()}`;

    await anonymousPage.goto('/register');
    await anonymousPage.getByPlaceholder('as per service record').fill('E2E Applicant');
    await anonymousPage.getByPlaceholder('e.g. INV-0042').fill(badge);
    await anonymousPage.getByPlaceholder('name@dept.gov.in').fill(`${username}@dept.gov.in`);
    await anonymousPage.getByPlaceholder('e.g. Cyber Crime Unit A').fill('Cyber Crime Branch');
    await anonymousPage.getByPlaceholder('lowercase, no spaces').fill(username);
    await anonymousPage.getByPlaceholder('min. 8 characters').fill('e2e-enrolment-pass');
    await anonymousPage.getByPlaceholder('re-enter').fill('e2e-enrolment-pass');

    // Clearance is a select with no default. The form refuses to submit
    // without it, which is correct — an applicant must choose what they are
    // asking for — and is why this journey had no coverage until now.
    await anonymousPage.getByText('select clearance…').click();
    await anonymousPage.getByRole('option', { name: /investigator/i }).click();

    const submitted = anonymousPage.waitForResponse(
      (r) => r.url().includes('/auth/register/') && r.request().method() === 'POST',
    );
    await anonymousPage.getByRole('button', { name: /submit for authorization/i }).click();
    const response = await submitted;

    // Assert on the response, not on text that happens to be on the page:
    // the register form's own stage list contains the word "submitted", so a
    // loose text match passed while the request was failing.
    expect(
      response.status(),
      `registration rejected: ${await response.text()}`,
    ).toBe(201);

    // The application reached the queue an administrator actually works.
    const queue = await apiGet(adminPage, 'auth/accounts/pending/');
    expect(
      queue.pending.map((a) => a.username),
      'the application did not reach the approval queue',
    ).toContain(username);

    // And the applicant, checking by badge, is told the truth: pending.
    await anonymousPage.goto('/status');
    await anonymousPage.getByPlaceholder('as registered').fill(username);
    await anonymousPage.getByPlaceholder('e.g. INV-0042').fill(badge);
    await anonymousPage.getByRole('button', { name: /check|status|verify/i }).first().click();
    await expect(
      anonymousPage.getByText(/Administrator review/i).first(),
    ).toBeVisible({ timeout: 15_000 });
  });

  test('an unknown applicant is not told which half was wrong', async ({ anonymousPage }) => {
    // The status check is public, so it must not become a username oracle.
    await anonymousPage.goto('/status');
    await anonymousPage.getByPlaceholder('as registered').fill('no-such-person');
    await anonymousPage.getByPlaceholder('e.g. INV-0042').fill('NOPE-1');
    await anonymousPage.getByRole('button', { name: /check|status/i }).first().click();

    await expect(
      anonymousPage.getByText(/No enrollment record matches those details/i),
    ).toBeVisible({ timeout: 15_000 });
  });
});

// ── accessibility ───────────────────────────────────────────────────────

/**
 * GIGW 3.0 — the Guidelines for Indian Government Websites, which state and
 * central departments are expected to meet as a condition of digital service
 * delivery — takes WCAG 2.1 AA as its baseline. AA requires 4.5:1 contrast for
 * normal text.
 *
 * This probe has caught the same class of mistake on both palettes. On the
 * old dark ground the muted greys sat at alpha 0.35–0.45 and measured
 * 2.8–3.9:1; on the white ground the trap is the accent, because the cyan
 * that reads at 10.5:1 on ink measures 1.77:1 on paper. Reasoning about
 * either by eye is how they got shipped.
 */
const CONTRAST_PROBE = () => {
  const luminance = ([r, g, b]) => {
    const f = (c) => {
      const v = c / 255;
      return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const parse = (colour) => {
    const m = colour.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const parts = m[1].split(',').map((n) => parseFloat(n));
    return { rgb: parts.slice(0, 3), a: parts.length > 3 ? parts[3] : 1 };
  };
  const backdrop = (el) => {
    let node = el;
    while (node && node !== document.documentElement) {
      const c = parse(getComputedStyle(node).backgroundColor);
      if (c && c.a > 0.9) return c.rgb;
      node = node.parentElement;
    }
    return [255, 255, 255];
  };

  const bad = [];
  for (const el of document.querySelectorAll('p, span, h1, h2, h3, h4, li, td, th, label, button, a')) {
    const text = (el.textContent || '').trim();
    if (!text || el.children.length) continue;

    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') continue;
    const box = el.getBoundingClientRect();
    if (box.width === 0 || box.height === 0) continue;

    const fg = parse(style.color);
    if (!fg) continue;
    const bg = backdrop(el);
    const blended = fg.rgb.map((c, i) => fg.a * c + (1 - fg.a) * bg[i]);

    const size = parseFloat(style.fontSize);
    const weight = parseInt(style.fontWeight, 10) || 400;
    // WCAG "large text": >=18.66px bold, or >=24px.
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const required = large ? 3 : 4.5;

    const l1 = luminance(blended);
    const l2 = luminance(bg);
    const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);

    if (ratio < required) {
      bad.push(`"${text.slice(0, 40)}" ${ratio.toFixed(2)}:1 (needs ${required})`);
    }
  }
  return bad;
};

test.describe('text meets WCAG 2.1 AA contrast', () => {
  for (const route of ['/dashboard', '/detections', '/evidence']) {
    test(`${route} has no unreadable text`, async ({ page }) => {
      await page.goto(route);
      await expect(page.getByText(/Dashboard/i).first()).toBeVisible({ timeout: 20_000 });
      await page.waitForTimeout(1500);

      const failures = await page.evaluate(CONTRAST_PROBE);
      expect(failures, `${route}: ${failures.join(' | ')}`).toEqual([]);
    });
  }

  test('the public landing page is readable too', async ({ anonymousPage }) => {
    await anonymousPage.goto('/');
    await anonymousPage.waitForLoadState('networkidle');

    const failures = await anonymousPage.evaluate(CONTRAST_PROBE);
    expect(failures, `landing: ${failures.join(' | ')}`).toEqual([]);
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
