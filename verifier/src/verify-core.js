// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
/*
 * NetForensiq case package verifier — the checks, with no DOM.
 *
 * Written as a classic script, not an ES module: a module cannot be loaded from
 * a file:// page in Chrome, and this page is meant to be opened from a USB
 * stick. The same file runs in Node for the tests and the command-line tool.
 *
 * It mirrors evidence/case_package.py:verify_package. Two implementations that
 * must agree catch what one cannot; verifier/test/ builds packages with the
 * Python one and verifies them with this one, and runs the tamper cases through
 * both.
 *
 * What a pass means, and does not, is in verifier/README.md and on the page.
 */
(function (root, factory) {
  'use strict';
  var api = { create: factory };
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  else { root.NFVerify = api; }
})(typeof self !== 'undefined' ? self : this, function (noble) {
  'use strict';

  var FORMAT = 'netforensiq.case-package/1';
  var MANIFEST_SCHEMA = 'netforensiq.case-manifest/1';
  // Prepended to what is signed, so a signature over a case package cannot be
  // replayed as one over a different document type.
  var CONTEXT = 'netforensiq.case-package/1\n';
  var HEX64 = /^[0-9a-f]{64}$/;
  var CHUNK = 4 * 1024 * 1024;

  var encoder = new TextEncoder();

  function utf8(text) { return encoder.encode(text); }

  function toHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
  }

  // Strict: padding and alphabet checked, because atob() is lenient about both.
  function fromBase64(text) {
    if (typeof text !== 'string' || text.length % 4 !== 0 ||
        !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) { return null; }
    var binary = atob(text);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
    return bytes;
  }

  function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }

  function normaliseFingerprint(text) {
    return String(text || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  }

  function displayFingerprint(hex) {
    var groups = [];
    for (var i = 0; i < hex.length; i += 8) { groups.push(hex.slice(i, i + 8)); }
    return groups.join(' ');
  }

  // sha256 over the UTF-8 of: evidence_id|sequence|action|actor_badge|actor_ip|
  // detail|timestamp|previous_hash — the strings exactly as the package gives
  // them. The timestamp is never reformatted here: Python's isoformat() drops
  // the fractional part when it is zero, and a verifier that formats dates
  // itself would report tampering on exactly those entries.
  function entryHash(evidenceId, entry) {
    var payload = [
      String(evidenceId), String(entry.sequence), entry.action, entry.actor_badge,
      entry.actor_ip, entry.detail, entry.timestamp, entry.previous_hash
    ].join('|');
    return toHex(noble.sha256(utf8(payload)));
  }

  // Fields that must not contain '|'. With these free of it the hashed text has
  // one reading; a package where one holds '|' could have had its fields
  // re-split without changing any hash. Mirrors NO_PIPE_FIELDS in case_package.py.
  var NO_PIPE_FIELDS = ['action', 'actor_badge', 'actor_ip', 'timestamp', 'previous_hash'];

  function chainProblems(evidenceId, custody) {
    var events = (custody && custody.events) || [];
    var problems = [];
    if (!events.length) { return ['the custody log is empty']; }
    var previous = '';
    for (var i = 0; i < events.length; i++) {
      var entry = events[i];
      var n = entry.sequence;
      if (n !== i + 1) {
        problems.push('entry ' + (i + 1) + ' is numbered ' + n +
          ': an entry is missing or reordered');
      }
      if (entry.previous_hash !== previous) {
        problems.push('entry #' + n + ': previous_hash does not match the entry before it');
      }
      for (var f = 0; f < NO_PIPE_FIELDS.length; f++) {
        if (String(entry[NO_PIPE_FIELDS[f]] || '').indexOf('|') !== -1) {
          problems.push('entry #' + n + ': ' + NO_PIPE_FIELDS[f] + " contains '|', so the " +
            "entry's hash does not fix which text belongs to which field");
        }
      }
      if (!HEX64.test(String(entry.entry_hash))) {
        problems.push('entry #' + n + ': entry_hash is not a SHA-256 digest');
      } else if (entryHash(evidenceId, entry) !== entry.entry_hash) {
        problems.push('entry #' + n + ': content has been altered');
      }
      previous = entry.entry_hash;
    }
    if (custody.event_count !== events.length) {
      problems.push('the package says ' + custody.event_count + ' entries, it carries ' +
        events.length);
    }
    if (custody.head_hash !== previous) {
      problems.push("the package head_hash is not the last entry's hash");
    }
    return problems;
  }

  /*
   * Verify a package. Returns { ok, checks, fingerprint, manifest }.
   * `checks` is [{ id, level: 'pass'|'fail'|'info', text }]. A package whose
   * signature does not verify returns no manifest: its contents are not shown
   * as though they could be trusted.
   */
  function verifyPackage(text, expectedFingerprint) {
    var checks = [];
    function add(id, level, message) { checks.push({ id: id, level: level, text: message }); }
    var result = { ok: false, checks: checks, fingerprint: null, manifest: null };

    var envelope;
    try { envelope = JSON.parse(text); }
    catch (e) { add('envelope', 'fail', 'not valid JSON'); return result; }
    if (!envelope || typeof envelope !== 'object' || envelope.format !== FORMAT) {
      add('envelope', 'fail', 'not a ' + FORMAT + ' file');
      return result;
    }
    add('envelope', 'pass', 'format ' + FORMAT);

    var sig = envelope.signature || {};
    var manifestJson = envelope.manifest_json;
    var publicKey = fromBase64(sig.public_key);
    var value = fromBase64(sig.value);
    if (!publicKey || !value) {
      add('signature', 'fail', 'the signature or public key is not valid base64');
      return result;
    }
    if (sig.algorithm !== 'ed25519' || typeof manifestJson !== 'string') {
      add('signature', 'fail', 'unsupported or missing signature');
      return result;
    }

    var fingerprint = toHex(noble.sha256(publicKey));
    result.fingerprint = fingerprint;

    var valid = false;
    try {
      // zip215:false asks for strict RFC 8032 verification. noble's default is
      // the more permissive ZIP215 rule set; Python's OpenSSL is the strict one.
      valid = publicKey.length === 32 && value.length === 64 &&
        noble.ed25519.verify(value, concat(utf8(CONTEXT), utf8(manifestJson)), publicKey,
                             { zip215: false });
    } catch (e) { valid = false; }
    if (!valid) {
      add('signature', 'fail',
        'the signature does not match the manifest: the file has been altered since it ' +
        'was signed, or was not signed by this key');
      return result;
    }
    add('signature', 'pass', 'the manifest is exactly as it was signed');

    if (sig.key_fingerprint && sig.key_fingerprint !== fingerprint) {
      add('fingerprint', 'fail',
        'the fingerprint written in the file is not the fingerprint of its key');
    } else if (expectedFingerprint) {
      if (normaliseFingerprint(expectedFingerprint) === fingerprint) {
        add('fingerprint', 'pass', 'the signing key matches the fingerprint you supplied');
      } else {
        add('fingerprint', 'fail', 'the signing key does NOT match the fingerprint you supplied');
      }
    } else {
      add('fingerprint', 'info',
        'signed by key ' + displayFingerprint(fingerprint) + '. A valid signature shows the ' +
        "file is unaltered and came from the holder of this key; it does not show the key is " +
        "the laboratory's. Compare the fingerprint with one you obtained separately.");
    }

    var manifest;
    try { manifest = JSON.parse(manifestJson); }
    catch (e) { add('manifest', 'fail', 'the signed manifest is not valid JSON'); return result; }
    if (manifest.schema !== MANIFEST_SCHEMA) {
      add('manifest', 'fail', 'unsupported manifest schema ' + JSON.stringify(manifest.schema));
      return result;
    }
    result.manifest = manifest;

    (manifest.exhibits || []).forEach(function (exhibit) {
      var number = exhibit.exhibit_number || '?';
      var problems = chainProblems(exhibit.evidence_id, exhibit.custody || {});
      if (problems.length) {
        problems.forEach(function (p) { add('chain:' + number, 'fail', number + ': ' + p); });
      } else {
        add('chain:' + number, 'pass', number + ': custody chain intact (' +
          exhibit.custody.event_count + ' entries, every hash recomputed)');
      }
      if (!HEX64.test(String(exhibit.sha256))) {
        add('hash:' + number, 'fail', number + ': sha256 is not a SHA-256 digest');
      }
      var check = exhibit.content_check || {};
      if (check.intact) {
        add('content:' + number, 'info', number + ': the laboratory re-hashed the stored file ' +
          'at export and it matched. This is the laboratory\'s statement; hash your own copy ' +
          'to check it yourself.');
      } else {
        add('content:' + number, 'fail', number + ': the stored file did NOT match its sealed ' +
          'hash when the package was made');
      }
      (exhibit.certificates || []).forEach(function (cert) {
        if (cert.certified_sha256 !== exhibit.sha256) {
          add('certificate:' + cert.reference, 'fail', 'certificate ' + cert.reference +
            ' certifies a different hash from the exhibit it is filed against');
        }
      });
    });

    result.ok = !checks.some(function (c) { return c.level === 'fail'; });
    return result;
  }

  /*
   * Hash a file in 4 MB pieces, all three digests in one pass. `file` needs only
   * `size` and `slice(start, end).arrayBuffer()` (a browser File, or a small
   * adapter in Node). WebCrypto cannot hash incrementally, so a 500 MB capture
   * would have to be held in memory whole; the pure-JS hashes can stream.
   * SHA-256 is the decisive digest. SHA-1 and MD5 are computed because the
   * statutory schedule names them, and are never relied upon.
   */
  async function hashFile(file, onProgress) {
    var h256 = noble.sha256.create();
    var h1 = noble.sha1.create();
    var h5 = noble.md5.create();
    for (var offset = 0; offset < file.size; offset += CHUNK) {
      var buffer = await file.slice(offset, Math.min(offset + CHUNK, file.size)).arrayBuffer();
      var bytes = new Uint8Array(buffer);
      h256.update(bytes); h1.update(bytes); h5.update(bytes);
      if (onProgress) { onProgress(Math.min(offset + CHUNK, file.size), file.size); }
    }
    return {
      size: file.size,
      sha256: toHex(h256.digest()),
      sha1: toHex(h1.digest()),
      md5: toHex(h5.digest())
    };
  }

  // Which exhibit, or which certificate PDF, does a file with these digests belong to?
  function matchFile(manifest, digests) {
    var exhibits = (manifest && manifest.exhibits) || [];
    for (var i = 0; i < exhibits.length; i++) {
      var exhibit = exhibits[i];
      if (exhibit.sha256 === digests.sha256) {
        return {
          kind: 'exhibit', exhibit: exhibit,
          sizeMatches: exhibit.file_size_bytes === digests.size,
          sha1Matches: !exhibit.sha1 || exhibit.sha1 === digests.sha1,
          md5Matches: !exhibit.md5 || exhibit.md5 === digests.md5
        };
      }
      var certs = exhibit.certificates || [];
      for (var j = 0; j < certs.length; j++) {
        if (certs[j].pdf_sha256 && certs[j].pdf_sha256 === digests.sha256) {
          return { kind: 'certificate', exhibit: exhibit, certificate: certs[j] };
        }
      }
    }
    return null;
  }

  return {
    FORMAT: FORMAT, MANIFEST_SCHEMA: MANIFEST_SCHEMA,
    verifyPackage: verifyPackage, hashFile: hashFile, matchFile: matchFile,
    chainProblems: chainProblems, entryHash: entryHash,
    displayFingerprint: displayFingerprint, normaliseFingerprint: normaliseFingerprint
  };
});
