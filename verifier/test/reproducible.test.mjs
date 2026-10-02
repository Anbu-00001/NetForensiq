// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
// "Check the checker": rebuilding from the committed sources with the pinned
// dependencies must give exactly the committed page, so its published SHA-256 is
// something a reader can reproduce rather than take on trust.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const have = existsSync(join(root, 'node_modules', 'esbuild'));

test('rebuilding reproduces the committed page and the committed noble bundle',
  { skip: have ? false : 'run `npm install` in verifier/ to enable' }, async () => {
    const { assemble } = await import('../build.mjs');
    const { html, noble } = await assemble();
    assert.equal(html, readFileSync(join(root, 'dist', 'nfverify.html'), 'utf8'),
      'dist/nfverify.html is out of date: run `npm run build`');
    assert.equal(noble, readFileSync(join(root, 'vendor', 'noble.iife.js'), 'utf8'),
      'vendor/noble.iife.js is out of date: run `npm run build`');
  });

test('the published digest matches the page', () => {
  const html = readFileSync(join(root, 'dist', 'nfverify.html'), 'utf8');
  const published = readFileSync(join(root, 'dist', 'nfverify.html.sha256'), 'utf8').split(/\s+/)[0];
  assert.equal(createHash('sha256').update(html, 'utf8').digest('hex'), published);
});

test('the CSP hashes are the hashes of the script and style blocks actually in the page', () => {
  const html = readFileSync(join(root, 'dist', 'nfverify.html'), 'utf8');
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const style = html.match(/<style>([\s\S]*?)<\/style>/)[1];
  const b64 = (t) => createHash('sha256').update(t, 'utf8').digest('base64');
  assert.ok(csp.includes(`'sha256-${b64(script)}'`), 'script hash does not match');
  assert.ok(csp.includes(`'sha256-${b64(style)}'`), 'style hash does not match');
  assert.equal((html.match(/<script/g) || []).length, 1, 'exactly one script block');
});
