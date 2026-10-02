// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
// Build dist/nfverify.html: one file, no network, and a security policy that
// forbids network requests outright.
//
//   node build.mjs
//
// Deterministic: the same sources and the same pinned dependency versions give
// the same bytes, so dist/nfverify.html.sha256 can be checked by anyone who
// rebuilds (test/reproducible.test.mjs does exactly that).
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(join(here, p), 'utf8');
const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest();

export async function assemble() {
  // 1. The only third-party code: noble's hashes and ed25519, bundled unminified
  //    so it can be read, with its licence comments kept.
  const bundled = await build({
    entryPoints: [join(here, 'vendor-entry.js')],
    bundle: true, format: 'iife', globalName: 'NobleNF', target: 'es2020',
    minify: false, legalComments: 'inline', write: false, logLevel: 'silent',
  });
  const noble = bundled.outputFiles[0].text;

  const core = read('src/verify-core.js');
  const ui = read('src/ui.js');
  const style = read('src/style.css');
  const template = read('src/index.template.html');
  const version = JSON.parse(read('package.json')).version;

  const script = [noble, core, ui].join('\n');
  // A closing script tag inside the bundle would end the block early and let
  // whatever follows run outside the hash.
  if (/<\/script/i.test(script)) throw new Error('script text contains </script');

  // 2. The policy. Scripts and styles only by hash; no connections, images,
  //    forms, frames or base URL of any kind.
  const hash = (text) => `'sha256-${sha256(text).toString('base64')}'`;
  const csp = [
    "default-src 'none'",
    `script-src ${hash(script)}`,
    `style-src ${hash(style)}`,
    "connect-src 'none'", "img-src 'none'", "form-action 'none'",
    "base-uri 'none'", "frame-src 'none'",
  ].join('; ');

  const html = template
    .replace('__CSP__', csp)
    .replace('__STYLE__', () => style)
    .replace('__VERSION__', version)
    .replace('__SCRIPT__', () => script);
  return { html, noble, csp };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { html, noble } = await assemble();
  mkdirSync(join(here, 'dist'), { recursive: true });
  writeFileSync(join(here, 'vendor', 'noble.iife.js'), noble);
  writeFileSync(join(here, 'dist', 'nfverify.html'), html);
  // The product serves the same file itself, at /nfverify.html, so an officer
  // can hand a recipient a link or a USB copy without a second download.
  writeFileSync(join(here, '..', 'frontend', 'public', 'nfverify.html'), html);
  const digest = createHash('sha256').update(html, 'utf8').digest('hex');
  writeFileSync(join(here, 'dist', 'nfverify.html.sha256'), `${digest}  nfverify.html\n`);
  console.log(`dist/nfverify.html  ${html.length} bytes  sha256 ${digest}`);
}
