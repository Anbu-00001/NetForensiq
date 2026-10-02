# 162 — A package the other side can check, on their own machine

**Question.** A Section 63 certificate asserts that a file has a particular hash. The
person who most needs to test that — defence counsel, a magistrate, a second laboratory —
has no way to do it except to ask the investigating agency's own system, which is taking
the investigator's word for the investigator's own exhibit. Can the lab hand over one file
that the recipient can verify without our software, an account or a network?

Built: a signed case package (`evidence/case_package.py`), an Ed25519 signing key
(`evidence/signing.py`), and a single-file browser verifier (`verifier/`).

## What a package is, and the choices that were not obvious

* **A JSON file, not a ZIP.** A ZIP needs a decompression library in the verifier and
  invites zip-bomb handling on the recipient's side. The package carries hashes and the
  custody log, not the evidence bytes, so it is small and readable.
* **The manifest is a string inside the envelope.** The signature covers its exact bytes.
  Signing a parsed object would need both sides to serialise identically — key order,
  whitespace, number formatting, unicode escaping — and the first mismatch looks exactly
  like tampering.
* **Every field that goes into an entry hash is carried, as the string that was hashed.**
  `timestamp` is `datetime.isoformat()`, which *omits the fractional part when the
  microsecond is zero*. A verifier that formatted dates itself would report tampering on
  exactly those entries; a test fixes a zero-microsecond event and requires it to verify.
* **A document-type prefix on what is signed** (`netforensiq.case-package/1\n`), so this
  signature cannot be replayed as one over a different kind of document.
* **Re-hash at export.** The package records whether the stored file still matched its
  sealed hash *when exported*. A package that said "intact" because the file was intact
  when sealed could never report that it had since changed.
* **Export appends a custody entry first**, so the export is in the package. It is a POST
  and needs investigator clearance, like every other call that writes to the log.

## What a signature adds to a hash chain — and the limit it does not remove

A hash chain proves a log is internally consistent. It cannot prove nobody rebuilt it:
whoever holds the data can recompute every hash from the first entry. A signature stops
that for someone who does not hold the key. It stops nothing for a recipient who has no
independent record of whose key it is, which is why the verifier shows the fingerprint and
says so. A test builds a forged package with an attacker's own key: it **verifies**, and
only the fingerprint comparison exposes it. That is the honest claim, and the page makes it.

## Two implementations, forced to agree

The checks exist twice — `case_package.verify_package` and `verifier/src/verify-core.js`
— because two implementations that must agree catch what one cannot. Python builds 19
packages — a good one (without a fingerprint, with the right one, with a wrong one); not
JSON; the wrong format; an empty array; edited signed text; a swapped signature; a forgery
re-signed with another key (as it stands, and checked against the real fingerprint); an
altered entry; a truncated end; reordered entries; a wrong head hash; a bad digest; a
longer log containing a zero-microsecond entry, a detail with `|` and non-ASCII text, and
a certificate; a removed middle entry; a certificate for another hash; content marked not
intact — and records what its verifier says. The JavaScript must produce the same verdict, the
same checks in the same order, the same wording. Then JavaScript signs and Python verifies.

The first run found one disagreement in 19: each language's own JSON-parser error text.
Both now say "not valid JSON". Mutating either side — a different field separator, no
previous-hash check, no certificate comparison — fails the test, which was checked.

## The page cannot phone home

The verifier is one HTML file with `default-src 'none'`, scripts and styles allowed by
hash only, and `connect-src 'none'`. A browser test points `fetch`, XHR, an image, a
beacon, a WebSocket, a script element and an iframe at a local server. With the policy,
the server receives nothing. With the policy removed it receives all seven and the test
fails. *Limit stated on the page:* a content policy cannot stop a script navigating the
window to a URL; no input is ever executed (package text is inserted as text only, and a
test loads a package full of markup), so that route needs a script that cannot get in.

Hashing runs in 4 MiB pieces. WebCrypto cannot hash incrementally, so a 500 MB capture
would have to be held in memory whole; noble's pure-JS hashes stream. Measured in Node:
200 MB through SHA-256, SHA-1 and MD5 together in 3.2 s (about 62 MB/s); SHA-256 alone is
several times faster. Streaming results equal Node's own at 0, 1, 55, 56, 64 bytes and
either side of the chunk boundary, and the published digests of "abc" match.

Ed25519 verification is strict RFC 8032 (`zip215: false`); noble's default is the more
permissive ZIP215. RFC 8032 test 1 (public key and signature) is checked in both languages.

## Found on the way

* **The real `.evidence.key` was inside every Docker image built from a working
  checkout.** `.dockerignore` excluded databases and the evidence store but not keys.
  Fixed (`**/*.key`, `**/*.pem`, `**/.signing.key`), with tests, and confirmed against a
  rebuilt image: no key file under `/app`. Images built before this are affected; do not
  distribute them, and rebuild. The key was never tracked in git.
* **A test run wrote into the real evidence store** (`backend/evidence_store/` had
  collected 1,946 files, about 780 MB, beside real demo exhibits), and a root-owned
  leftover from one run made a later run fail with `PermissionError`. Test runs now get a
  disposable store; the real one is untouched across a full run (1,946 files before and
  after).

## Measured end to end

On the isolated network of research/161, through the real interface: log in, press
"Export signed package", download a 6.4 KB package; the page then shows the signing key's
fingerprint; the verifier the app serves at `/nfverify.html` reports "Intact — but not yet
confirmed" without it and "Verified, and signed by the key you named" with it. The
browser made no request off the machine.

## Not done, and not claimed

* The certificate PDF does not print the signing key's fingerprint. It would let a
  recipient confirm the signer from the document they already hold; it was left because it
  changes a court-facing layout and needs its own review.
* The signing key sits on the data volume beside the evidence key unless supplied through
  `PACKAGE_SIGNING_KEY`; a lab that cares keeps it on removable media.
* No timestamping authority: nothing external shows *when* a package was signed.
* Verification of the Python side by anyone other than its author, and of the page by a
  second browser engine (Firefox, WebKit): only Chromium was run.
