#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
// Verify a NetForensiq case package from the command line, with the same checks
// as the page (it loads the same code). For machines that have Node and no
// browser, or for scripts.
//
//   node nfverify.mjs package.nfcase.json
//   node nfverify.mjs package.nfcase.json --fingerprint "a1b2c3d4 e5f6..." exhibit.pcap cert.pdf
//
// Exit status: 0 verified, 1 does not verify (or a file does not match), 2 usage.
import { readFileSync } from 'node:fs';
import { fileLike, load } from './lib.mjs';

const args = process.argv.slice(2);
let fingerprint = '';
const paths = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--fingerprint') fingerprint = args[++i] || '';
  else paths.push(args[i]);
}
if (!paths.length) {
  console.error('usage: node nfverify.mjs PACKAGE [--fingerprint FP] [FILE ...]');
  process.exit(2);
}

const { V } = load();
const [packagePath, ...files] = paths;
const result = V.verifyPackage(readFileSync(packagePath, 'utf8'), fingerprint);
for (const c of result.checks) console.log(`[${c.level.toUpperCase()}] ${c.text}`);
if (result.fingerprint) console.log(`\nSigning key fingerprint: ${V.displayFingerprint(result.fingerprint)}`);

let allMatch = true;
for (const file of files) {
  if (!result.manifest) { console.log(`\n${file}: not checked (the package does not verify)`); allMatch = false; continue; }
  const digests = await V.hashFile(fileLike(file));
  const match = V.matchFile(result.manifest, digests);
  const what = !match ? 'does NOT match any exhibit or certificate in the package'
    : match.kind === 'exhibit' ? `is exhibit ${match.exhibit.exhibit_number}`
    : `is the certificate PDF ${match.certificate.reference}`;
  if (!match) allMatch = false;
  console.log(`\n${file}: ${what}\n  sha256 ${digests.sha256}`);
}
console.log(`\nResult: ${result.ok && allMatch ? 'verified' : 'DOES NOT VERIFY'}`);
process.exit(result.ok && allMatch ? 0 : 1);
