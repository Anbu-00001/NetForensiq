import { test, expect, apiGet, rows } from './fixtures';

/**
 * The air-gap claim, enforced.
 *
 * This platform is meant to run in a police room with no route to the
 * internet. Today that happens to be true: the fonts are bundled through
 * @fontsource, there is no CDN link in index.html, and no rule consults a
 * threat feed. None of that is guaranteed by anything. One `<link>` to Google
 * Fonts, one analytics snippet, one "just fetch the latest IOC list" and the
 * product stops working on the machine it was built for — and it would still
 * pass every other test in this suite, because a developer's laptop has
 * internet.
 *
 * So these tests take the internet away and then check the interesting thing.
 * The interesting thing is not "the app survived being offline" — a page can
 * survive a failed request by silently rendering less. It is that the app
 * never asked. Every request the browser makes is inspected, anything not
 * addressed to this machine is aborted, and the list of aborted requests must
 * be empty at the end.
 */

/** Any rule the engine can emit — the accessible name of a finding card. */
const RULE_ID = /^(C2_BEACON|COVERT_CHANNEL|DNS_TUNNEL|RECON_|EXFIL_|ICMP_|HOST_)/;

/**
 * Hosts that are this machine.
 *
 * The interface and the API deliberately sit on different ports (5199 and
 * 8011 under test), so "same origin" is the wrong test — it would abort the
 * app's own API calls. The line that actually matters for an air-gapped
 * workstation is whether a packet would leave the box, so the check is on the
 * host, not the origin.
 */
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

function isLocal(url) {
  // data: and blob: never touch the network — the bytes are already in the
  // page. Their URLs also do not parse into a useful hostname, so they are
  // settled before the URL parser is asked.
  if (url.startsWith('data:') || url.startsWith('blob:')) return true;
  try {
    return LOOPBACK.has(new URL(url).hostname);
  } catch {
    // An unparseable URL is not something this test can vouch for, so it
    // counts as external and shows up in the failure message.
    return false;
  }
}

/**
 * Cut the page off from everything except this machine.
 *
 * Returns the two lists the assertions are made against: `external` is every
 * request that was refused, and `requested` is every URL the page asked for
 * at all — which is how the font check below can tell "served locally" from
 * "never fetched".
 *
 * Must be called before the first navigation, or the documents and assets of
 * that navigation escape the interceptor.
 */
async function airgap(page) {
  const external = [];
  const requested = [];

  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = request.url();
    requested.push(url);

    try {
      if (isLocal(url)) {
        await route.continue();
      } else {
        external.push(`${request.method()} ${url}`);
        await route.abort('blockedbyclient');
      }
    } catch {
      // A route handler races the page: if a navigation discards the request
      // before it is answered, continue()/abort() throws. The URL is already
      // recorded above, so the assertions still see it; swallowing the throw
      // only stops an unrelated teardown error from masking the real result.
    }
  });

  // WebSockets bypass page.route entirely, so an HMR-style long-lived
  // connection to somewhere else would not appear in `external` unless it is
  // watched separately. The Vite dev server opens one, to this machine.
  page.on('websocket', (socket) => {
    if (!isLocal(socket.url())) external.push(`WS ${socket.url()}`);
  });

  return { external, requested };
}

/** Console errors and uncaught exceptions, in the order they happened. */
function watchConsole(page) {
  const problems = [];
  page.on('console', (message) => {
    if (message.type() === 'error') problems.push(message.text());
  });
  page.on('pageerror', (error) => problems.push(`uncaught: ${error.message}`));
  return problems;
}

test.describe('the platform works with no route off this machine', () => {
  test('the core journey makes no request that leaves the box', async ({ page }) => {
    const { external, requested } = await airgap(page);
    const problems = watchConsole(page);

    // The login page first. It is the first thing an officer sees and the
    // most likely place for a stray font or icon CDN to be added, and it is
    // the one page in the journey that renders before any token exists.
    await page.goto('/login');
    await expect(page.getByText('SECURE ACCESS TERMINAL')).toBeVisible();
    await expect(page.getByText('OPERATOR ID')).toBeVisible();
    await expect(page.getByRole('button', { name: /AUTHENTICATE/i })).toBeVisible();

    // Signed in — the session fixture puts the tokens in sessionStorage
    // before any page script runs, which is how the rest of this suite signs
    // in without spending one of the eight logins the throttle allows per
    // hour.
    await page.goto('/dashboard');
    await expect(page.getByText(/Packets/i).first()).toBeVisible({ timeout: 20_000 });

    // "The page loaded" is not the assertion. A dashboard cut off from its
    // API renders its frame and a row of dashes, and would pass a check that
    // only looked for headings. So the figure on screen is compared against
    // the figure the API returned.
    const sessions = rows(await apiGet(page, 'sessions/'));
    expect(
      sessions.length,
      'no capture sessions in the demonstration database, so this test could ' +
      'not tell a working dashboard from an empty one',
    ).toBeGreaterThan(0);
    const summary = await apiGet(page, `sessions/${sessions[0].id}/summary/`);
    expect(await page.locator('body').innerText())
      .toContain(String(summary.totals.flows));

    // Findings.
    await page.goto('/detections');
    await expect(page.getByText(/Findings/i).first()).toBeVisible();
    const findings = rows(await apiGet(page, 'detections/'));
    expect(findings.length, 'no findings seeded').toBeGreaterThan(0);
    await expect(page.getByRole('button', { name: RULE_ID }).first())
      .toBeVisible({ timeout: 20_000 });

    // Evidence. Every exhibit the API holds has to be named on screen; a
    // register that quietly shows none of them is the failure mode being
    // guarded against.
    await page.goto('/evidence');
    await expect(page.getByText(/Evidence register/i)).toBeVisible();
    const exhibits = rows(await apiGet(page, 'evidence/'));
    expect(exhibits.length, 'no exhibits seeded').toBeGreaterThan(0);
    const register = await page.locator('body').innerText();
    for (const exhibit of exhibits) {
      expect(register, `${exhibit.exhibit_number} is not on the register`)
        .toContain(exhibit.exhibit_number);
    }

    // The assertion this file exists for. Not "it coped", but "it never
    // tried" — every URL that would have left this machine, with the method,
    // so a failure says which line of code to go and look at.
    expect(
      external,
      `the application reached for ${external.length} external resource(s):\n` +
      `  ${external.join('\n  ')}`,
    ).toEqual([]);

    // A page that silently swallowed a blocked request would still show an
    // error here, and so would anything else broken along the way.
    expect(problems, problems.join('\n')).toEqual([]);

    // Sanity: the interceptor saw traffic at all. Without this, a routing
    // pattern that matched nothing would produce an empty `external` list and
    // a green test that had checked nothing.
    expect(requested.length, 'the interceptor observed no requests at all')
      .toBeGreaterThan(0);
  });

  test('web fonts are served from this machine, not from a font CDN', async ({ page }) => {
    const { external, requested } = await airgap(page);

    await page.goto('/login');
    await expect(page.getByText('SECURE ACCESS TERMINAL')).toBeVisible();

    // Wait for the faces the page actually uses to finish loading, rather
    // than for a fixed delay. document.fonts.ready settles once every
    // font-face required by the current layout has resolved.
    await page.evaluate(() => document.fonts.ready);

    // The bundled fonts have to have been fetched from somewhere. If nothing
    // was fetched, this test proves nothing about where fonts come from, so
    // that case fails rather than passing quietly.
    const fontRequests = requested.filter((url) => /\.woff2?(\?|#|$)/i.test(url));
    expect(
      fontRequests.length,
      'no web font was requested, so this test could not check where fonts ' +
      'come from — has the app stopped using @fontsource?',
    ).toBeGreaterThan(0);

    // Fonts are stricter than the rest of the suite: the API may live on
    // another port, but a font is a static asset and must come from the
    // interface's own origin.
    const origin = new URL(page.url()).origin;
    const offsite = fontRequests.filter((url) => !url.startsWith(`${origin}/`));
    expect(offsite, `fonts fetched from another origin:\n  ${offsite.join('\n  ')}`)
      .toEqual([]);

    // And they rendered. A blocked font still leaves a request in the list
    // above, so the browser is asked which faces it actually has.
    const loaded = await page.evaluate(() =>
      [...document.fonts]
        .filter((face) => face.status === 'loaded')
        .map((face) => face.family));
    expect(
      loaded.some((family) => /inter|jetbrains/i.test(family)),
      `no bundled face finished loading; document.fonts holds: ${loaded.join(', ')}`,
    ).toBe(true);

    expect(external, external.join('\n')).toEqual([]);
  });

  test('signing in through the form talks only to the local API', async ({ anonymousPage }) => {
    // The journey above starts from an injected session, which skips the one
    // request an officer's day actually begins with. This runs the real form.
    const { external } = await airgap(anonymousPage);
    const problems = watchConsole(anonymousPage);

    await anonymousPage.goto('/login');
    await anonymousPage.getByPlaceholder('username').fill('analyst');
    // Addressed by autocomplete rather than by placeholder: the placeholder is
    // a run of bullet characters, which is a brittle thing to match on.
    await anonymousPage.locator('input[autocomplete="current-password"]')
      .fill(process.env.NETFORENSIQ_DEMO_PASSWORD ?? 'demo-pass-1234');

    const answered = anonymousPage.waitForResponse(
      (r) => r.url().includes('/auth/login/') && r.request().method() === 'POST',
    );
    await anonymousPage.getByRole('button', { name: /AUTHENTICATE/i }).click();
    const response = await answered;

    // Checked before the throttle guard below, because it holds either way:
    // whether the credentials were accepted or refused, nothing should have
    // been sent off the machine.
    expect(external, external.join('\n')).toEqual([]);

    // The login endpoint allows eight attempts an hour — a brute-force
    // control worth keeping, and one this suite already spends most of during
    // setup. A run that hits the ceiling has not found a defect, so it says so
    // rather than reporting a failure it cannot distinguish from one.
    test.skip(response.status() === 429, 'login throttle exhausted this run');
    expect(response.status(), `sign-in rejected: ${await response.text()}`).toBe(200);

    await expect(anonymousPage).toHaveURL(/dashboard/, { timeout: 20_000 });
    await expect(anonymousPage.getByText(/Packets/i).first())
      .toBeVisible({ timeout: 20_000 });
    expect(problems, problems.join('\n')).toEqual([]);
  });

  test('the interception has teeth', async ({ page }) => {
    // Everything above rests on an empty list meaning "nothing was blocked".
    // An empty list also results from an interceptor that is not running, a
    // pattern that matches nothing, or a typo in the host check — all of which
    // would turn this whole file green while testing nothing. So the page is
    // made to reach for a real external host, and the block is verified.
    const { external } = await airgap(page);
    await page.goto('/login');

    // The URL crosses into the browser as an argument: an evaluate callback is
    // serialised and run in the page, where this module's scope does not exist.
    const reached = await page.evaluate(async (url) => {
      try {
        await fetch(url, { mode: 'no-cors' });
        return true;
      } catch {
        return false;
      }
    }, 'https://fonts.googleapis.com/css2?family=Inter');

    expect(reached, 'a request to an external host was allowed through').toBe(false);
    expect(external.join('\n')).toContain('fonts.googleapis.com');
  });
});
