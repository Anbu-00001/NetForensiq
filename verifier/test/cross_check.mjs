// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
// Run by evidence/tests_case_package_js.py. For every <name>.json in the
// directory, verify it here and require the result to equal what the Python
// verifier recorded in <name>.expected.json: same ok, same fingerprint, and the
// same checks in the same order with the same level and text. Then sign a
// package with noble (JavaScript) and write it for Python to verify, so the
// signature agreement is tested in both directions.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { load } from '../lib.mjs';

const dir = process.argv[2];
const { V, noble } = load();
let compared = 0;
const failures = [];

for (const name of readdirSync(dir).filter((f) => f.endsWith('.json') && !f.endsWith('.expected.json'))) {
  const base = name.replace(/\.json$/, '');
  let expected;
  try { expected = JSON.parse(readFileSync(join(dir, `${base}.expected.json`), 'utf8')); }
  catch { continue; }
  let fp = '';
  try { fp = readFileSync(join(dir, `${base}.fp`), 'utf8').trim(); } catch { /* none */ }

  const got = V.verifyPackage(readFileSync(join(dir, name), 'utf8'), fp);
  const mine = { ok: got.ok, fingerprint: got.fingerprint, checks: got.checks };
  const theirs = { ok: expected.ok, fingerprint: expected.fingerprint, checks: expected.checks };
  compared++;
  if (JSON.stringify(mine) !== JSON.stringify(theirs)) {
    failures.push(`${base}\n  python: ${JSON.stringify(theirs)}\n  js:     ${JSON.stringify(mine)}`);
  }
}

// JavaScript signs, Python verifies.
const good = JSON.parse(readFileSync(join(dir, 'good.json'), 'utf8'));
const seed = Uint8Array.from(Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'));
const pub = noble.ed25519.getPublicKey(seed);
const message = Buffer.concat([Buffer.from('netforensiq.case-package/1\n', 'utf8'), Buffer.from(good.manifest_json, 'utf8')]);
const sig = noble.ed25519.sign(message, seed);
const fingerprint = Buffer.from(noble.sha256(pub)).toString('hex');
good.signature = {
  algorithm: 'ed25519', public_key: Buffer.from(pub).toString('base64'),
  key_fingerprint: fingerprint, value: Buffer.from(sig).toString('base64'),
};
writeFileSync(join(dir, 'js-signed.out'), JSON.stringify(good));
writeFileSync(join(dir, 'js-signed.fingerprint'), fingerprint);

if (failures.length) {
  console.error(`JS and Python disagree on ${failures.length} of ${compared} cases:\n` + failures.join('\n'));
  process.exit(1);
}
console.log(`OK ${compared} cases identical`);
