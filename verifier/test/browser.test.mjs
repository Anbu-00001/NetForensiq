// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
// The page, in a real browser (Chromium via the Playwright already used by the
// frontend's end-to-end tests), opened from file:// the way it will be used.
//
// Skipped, with the reason printed, when Playwright's browser is not installed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { load } from '../lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const page_url = pathToFileURL(resolve(here, '..', 'dist', 'nfverify.html')).href;
const fixtures = resolve(here, 'fixtures');
const fp = (name) => join(fixtures, name);

let chromium = null;
try {
  chromium = createRequire(import.meta.url)(resolve(here, '..', '..', 'frontend', 'node_modules', 'playwright')).chromium;
} catch { /* reported by the skip reason below */ }

let browser;
let skipReason = chromium ? '' : 'Playwright is not installed (frontend/node_modules)';

before(async () => {
  if (!chromium) return;
  try { browser = await chromium.launch(); }
  catch (e) { skipReason = `Chromium could not start: ${e.message.split('\n')[0]}`; }
});
after(async () => { if (browser) await browser.close(); });

async function open() {
  const page = await browser.newPage();
  const violations = [];
  page.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) violations.push(m.text()); });
  await page.goto(page_url);
  return { page, violations };
}
const text = (page, sel) => page.locator(sel).innerText();

const opts = () => ({ skip: skipReason || false });

test('a good package is intact but not yet confirmed; the right fingerprint confirms it', opts(), async () => {
  const { page } = await open();
  await page.setInputFiles('#pkg', fp('good.nfcase.json'));
  await page.waitForSelector('#result .banner');
  assert.match(await text(page, '#result .banner'), /Intact — but not yet confirmed/);
  assert.match(await text(page, '#result'), /custody chain intact/);

  await page.fill('#fp', (await import('node:fs')).readFileSync(fp('fingerprint.txt'), 'utf8').trim());
  assert.match(await text(page, '#result .banner'), /Verified, and signed by the key you named/);

  await page.fill('#fp', 'ab'.repeat(32));
  assert.match(await text(page, '#result .banner'), /does not verify/);
  await page.close();
});

test('an edited package does not verify and shows none of its contents', opts(), async () => {
  const { page } = await open();
  await page.setInputFiles('#pkg', fp('tampered.nfcase.json'));
  await page.waitForSelector('#result .banner.bad');
  assert.equal(await page.locator('#result .exhibit').count(), 0, 'an unverified manifest must not be rendered');
  assert.equal(await page.locator('#filesection').isHidden(), true);
  await page.close();
});

test('a package with an entry removed does not verify', opts(), async () => {
  const { page } = await open();
  await page.setInputFiles('#pkg', fp('forged-removed-entry.nfcase.json'));
  await page.waitForSelector('#result .banner.bad');
  assert.match(await text(page, '#result'), /missing or reordered|previous_hash|entries/);
  await page.close();
});

test('the exhibit file is recognised, and a different file is not', opts(), async () => {
  const { page } = await open();
  await page.setInputFiles('#pkg', fp('good.nfcase.json'));
  await page.waitForSelector('#filesection:not([hidden])');
  await page.setInputFiles('#file', fp('exhibit.bin'));
  await page.waitForFunction(() => /This is exhibit EX-PKG-1/.test(document.getElementById('fileresults').innerText));
  await page.setInputFiles('#file', fp('fingerprint.txt'));
  await page.waitForFunction(() => /does NOT match any exhibit/.test(document.getElementById('fileresults').innerText));
  await page.close();
});

test('text from a hostile package is shown as text, never as markup', opts(), async () => {
  const { V, noble } = load();
  const seed = Uint8Array.from(Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'));
  const hostile = '<img src=x onerror="window.__owned=1"><script>window.__owned=2</script>';
  const entry = { sequence: 1, action: 'acquired', actor_badge: hostile, actor_ip: '', detail: hostile,
                  timestamp: '2026-10-02T09:30:00+00:00', previous_hash: '' };
  entry.entry_hash = V.entryHash(1, entry);
  const manifest = {
    schema: 'netforensiq.case-manifest/1', generated_at: 'x', tool: { name: hostile, version: hostile },
    case: { case_number: hostile, title: hostile },
    exhibits: [{ evidence_id: 1, exhibit_number: hostile, original_filename: hostile, sha256: 'a'.repeat(64),
      content_check: { intact: true }, certificates: [],
      custody: { event_count: 1, head_hash: entry.entry_hash, events: [entry] } }],
  };
  const manifest_json = JSON.stringify(manifest);
  const msg = Buffer.concat([Buffer.from('netforensiq.case-package/1\n'), Buffer.from(manifest_json)]);
  const pub = noble.ed25519.getPublicKey(seed);
  const envelope = { format: 'netforensiq.case-package/1', manifest_json, signature: {
    algorithm: 'ed25519', public_key: Buffer.from(pub).toString('base64'),
    value: Buffer.from(noble.ed25519.sign(msg, seed)).toString('base64') } };
  const dir = (await import('node:fs')).mkdtempSync(join((await import('node:os')).tmpdir(), 'nfh-'));
  const file = join(dir, 'hostile.json');
  (await import('node:fs')).writeFileSync(file, JSON.stringify(envelope));

  const { page } = await open();
  await page.setInputFiles('#pkg', file);
  await page.waitForSelector('#result .exhibit');
  assert.equal(await page.locator('#result img, #result script').count(), 0, 'markup was injected');
  assert.equal(await page.evaluate(() => window.__owned), undefined, 'injected script ran');
  assert.ok((await text(page, '#result')).includes('<img src=x'), 'the text should appear literally');
  await page.close();
});

test('the page cannot make a network request by any ordinary route', opts(), async () => {
  const hits = [];
  const server = createServer((req, res) => { hits.push(req.url); res.writeHead(200, { 'access-control-allow-origin': '*' }); res.end('x'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  const { page, violations } = await open();
  const outcome = await page.evaluate(async (base) => {
    const attempt = async (name, fn) => { try { return [name, await fn()]; } catch (e) { return [name, 'blocked: ' + (e && e.name)]; } };
    return Object.fromEntries(await Promise.all([
      attempt('fetch', () => fetch(base + '/fetch').then(() => 'SENT')),
      attempt('xhr', () => new Promise((res) => { const x = new XMLHttpRequest(); x.onerror = () => res('blocked'); x.onload = () => res('SENT'); try { x.open('GET', base + '/xhr'); x.send(); } catch { res('blocked'); } })),
      attempt('image', () => new Promise((res) => { const i = new Image(); i.onerror = () => res('blocked'); i.onload = () => res('SENT'); i.src = base + '/img'; })),
      attempt('beacon', () => (navigator.sendBeacon(base + '/beacon', 'x') ? 'queued' : 'blocked')),
      attempt('websocket', () => new Promise((res) => { try { const w = new WebSocket(base.replace('http', 'ws') + '/ws'); w.onerror = () => res('blocked'); w.onopen = () => res('SENT'); } catch { res('blocked'); } })),
      attempt('script-element', () => new Promise((res) => { const s = document.createElement('script'); s.onerror = () => res('blocked'); s.onload = () => res('SENT'); s.src = base + '/script.js'; document.head.appendChild(s); })),
      attempt('iframe', () => new Promise((res) => { const f = document.createElement('iframe'); f.onload = () => res('loaded?'); f.onerror = () => res('blocked'); f.src = base + '/frame'; document.body.appendChild(f); setTimeout(() => res('blocked (no load)'), 800); })),
    ]));
  }, base);
  await new Promise((r) => setTimeout(r, 400));
  server.close();
  await page.close();

  assert.deepEqual(hits, [], `the server saw requests: ${JSON.stringify(hits)} (outcomes ${JSON.stringify(outcome)})`);
  assert.ok(violations.length >= 3, `expected the browser to report policy violations, got ${violations.length}`);
});

test('the page ships its own security policy, with no unsafe directives', () => {
  const html = (() => { const { readFileSync } = createRequire(import.meta.url)('node:fs'); return readFileSync(resolve(here, '..', 'dist', 'nfverify.html'), 'utf8'); })();
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /connect-src 'none'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|\*|https?:/);
});

test('skip reason, when there is one, is stated', { skip: !skipReason }, () => {
  console.log('browser tests skipped:', skipReason);
});
