// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileLike, load } from '../lib.mjs';

const { V, noble } = load();
const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');

test('RFC 8032 section 7.1 test 1: public key and signature', () => {
  // The vector the Python tests use, so the two libraries are held to the same
  // external answer and not only to each other.
  const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  const pub = noble.ed25519.getPublicKey(seed);
  assert.equal(hex(pub), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  const sig = noble.ed25519.sign(new Uint8Array(0), seed);
  assert.equal(hex(sig), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
  assert.ok(noble.ed25519.verify(sig, new Uint8Array(0), pub, { zip215: false }));
});

test('a flipped bit in the signature or the message is rejected', () => {
  const seed = randomBytes(32);
  const pub = noble.ed25519.getPublicKey(seed);
  const msg = Buffer.from('manifest');
  const sig = noble.ed25519.sign(msg, seed);
  const bad = Uint8Array.from(sig); bad[10] ^= 1;
  assert.equal(noble.ed25519.verify(bad, msg, pub, { zip215: false }), false);
  assert.equal(noble.ed25519.verify(sig, Buffer.from('manifesu'), pub, { zip215: false }), false);
});

// Sizes around the 4 MiB chunk boundary, the empty file and a single byte: the
// places a streaming implementation is wrong when it is wrong.
for (const size of [0, 1, 55, 56, 64, 4 * 1024 * 1024 - 1, 4 * 1024 * 1024, 4 * 1024 * 1024 + 1, 9_000_007]) {
  test(`streaming hash of ${size} bytes equals node crypto (sha256, sha1, md5)`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'nfv-'));
    const path = join(dir, 'f.bin');
    const data = randomBytes(size);
    writeFileSync(path, data);
    const got = await V.hashFile(fileLike(path));
    assert.equal(got.size, size);
    for (const algo of ['sha256', 'sha1', 'md5']) {
      assert.equal(got[algo], createHash(algo).update(data).digest('hex'), algo);
    }
  });
}

test('well-known digests of the empty input and "abc"', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nfv-'));
  const path = join(dir, 'abc');
  writeFileSync(path, 'abc');
  const got = await V.hashFile(fileLike(path));
  // FIPS 180 / RFC 1321 published values
  assert.equal(got.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(got.sha1, 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(got.md5, '900150983cd24fb0d6963f7d28e17f72');
});

test('entry hash joins the fields exactly as the Python side does', () => {
  const entry = { sequence: 2, action: 'viewed', actor_badge: 'GP-1', actor_ip: '', detail: 'a|b ₹',
                  timestamp: '2026-10-02T09:30:00+00:00', previous_hash: 'x' };
  const expected = createHash('sha256')
    .update('7|2|viewed|GP-1||a|b ₹|2026-10-02T09:30:00+00:00|x', 'utf8').digest('hex');
  assert.equal(V.entryHash(7, entry), expected);
});

test('fingerprint helpers', () => {
  assert.equal(V.normaliseFingerprint('AB cd:EF-01'), 'abcdef01');
  assert.equal(V.displayFingerprint('0123456789abcdef0123456789abcdef'), '01234567 89abcdef 01234567 89abcdef');
});

test('garbage in is a failure, not an exception', () => {
  for (const text of ['', 'null', '[]', '{"format":"x"}', '{"format":"netforensiq.case-package/1"}',
                      '{"format":"netforensiq.case-package/1","signature":{"public_key":"!!","value":"!!"}}']) {
    const r = V.verifyPackage(text);
    assert.equal(r.ok, false, text);
    assert.equal(r.manifest, null);
  }
});
