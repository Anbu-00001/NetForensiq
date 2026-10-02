# NetForensiq package verifier

One HTML file that checks a signed NetForensiq case package on the recipient's own
machine. No install, no account, no network. Open `dist/nfverify.html` in a browser,
choose the package, and (optionally) choose the exhibit file you were given.

The product serves the same file at `/nfverify.html`, and it can be mailed or
carried on a USB stick. It also runs from the command line:

```bash
node nfverify.mjs package.nfcase.json --fingerprint "a1b2c3d4 e5f6a7b8 ..." exhibit.pcap
```

## What the recipient is told

| Check | Shown by |
|---|---|
| The package has not been changed since it was signed | Ed25519 signature over the exact manifest text |
| Every custody entry still hashes to what is recorded | each of the entry hashes is recomputed |
| No entry was removed from the middle, reordered, or cut off the end | numbering, `previous_hash` links, entry count and head hash |
| A certificate does not certify a different hash from its exhibit | compared per certificate |
| The file in the recipient's hand is the exhibit, or the certificate PDF, the package describes | the file is hashed in the page (SHA-256, SHA-1, MD5) and matched |

## What it cannot tell them

* **That the key is the laboratory's.** Anyone can sign a package with their own key
  and it will verify. The page shows the key's fingerprint; the recipient has to
  compare it with one obtained *another way* — a printed certificate, a phone call, a
  notice from the laboratory. Entering it in the box turns "intact" into "verified".
  A test builds a forgery that verifies, and shows only the fingerprint exposes it.
* **That the log was never rebuilt before signing.** A hash chain proves a log is
  consistent. Whoever holds the data can recompute every hash from the first entry. Only
  an external anchor could show otherwise.
* **That the evidence is genuine or the findings are correct.** It checks the record of
  custody, not the conclusions drawn from the file.

## Why it can be trusted to stay in the page

* **A security policy that forbids network access.** The page carries
  `default-src 'none'` with scripts and styles allowed only by hash, and
  `connect-src 'none'`. A browser test points `fetch`, `XMLHttpRequest`, an image, a
  beacon, a WebSocket, a script element and an iframe at a local server and requires it
  to receive nothing. With the policy removed it receives all seven and the test fails.
  *Limit:* a content policy cannot stop a script from navigating the whole window to a
  URL. No input is ever run as script — text from a package goes into the page only as
  text, and a test loads a package full of markup and checks none of it became an element
  — but that is a defence by construction, not by policy.
* **One reproducible file.** `npm run build` produces `dist/nfverify.html` and its
  SHA-256 from pinned dependencies; a test rebuilds it and requires the same bytes. A
  recipient who wants to check the checker can rebuild and compare.
* **Read in place.** The only third-party code is `@noble/hashes` and `@noble/curves`
  (MIT, Paul Miller), bundled unminified into `vendor/noble.iife.js` with their licence
  comments, so it can be read. Versions are pinned in `package.json`.

## Format

A package is a JSON file:

```json
{
  "format": "netforensiq.case-package/1",
  "manifest_json": "<the manifest, as a string>",
  "signature": { "algorithm": "ed25519", "public_key": "<base64>",
                 "key_fingerprint": "<hex>", "value": "<base64>" }
}
```

The signature covers the UTF-8 bytes of `"netforensiq.case-package/1\n" + manifest_json`.
The manifest is a string inside the envelope so that nobody has to agree on how to
serialise JSON: the bytes that were signed are the bytes you have. The fingerprint is the
SHA-256 of the raw 32-byte public key.

Each custody entry hash is `sha256` of the UTF-8 text made by joining these fields with
`|`: `evidence_id, sequence, action, actor_badge, actor_ip, detail, timestamp,
previous_hash` — the strings exactly as the manifest gives them. The timestamp is never
reformatted: Python's `isoformat()` drops the fractional part when it is zero, and a
verifier that formatted dates itself would report tampering on exactly those entries (a
test pins this). Anyone can reproduce it with `sha256sum`.

Signatures are strict RFC 8032. noble's default is the more permissive ZIP215 rule set,
so the page asks for `zip215: false`; Python's `cryptography` (OpenSSL) is strict
already.

## Tests

```bash
cd verifier && npm install && npm test          # core, boundary and known-answer tests,
                                                # real-browser tests, reproducibility
cd backend && python manage.py test evidence.tests_case_package evidence.tests_case_package_js
```

* **Known answers.** RFC 8032 test 1 (key and signature), and the published digests of
  `"abc"` for SHA-256, SHA-1 and MD5.
* **Streaming.** Hashes of 0, 1, 55, 56, 64 bytes and either side of the 4 MiB chunk
  boundary equal Node's own.
* **Two implementations that must agree.** Python builds 19 packages — good, edited,
  re-signed, forged, truncated, reordered, with a removed middle entry, with a mismatched
  certificate — and runs its verifier; the page's JavaScript must give the same verdict,
  the same checks, in the same order, with the same wording. Then JavaScript signs and
  Python verifies. Mutating either implementation makes this test fail.
* **A real browser**, opened from `file://`: verdicts, file matching, hostile input, and
  the network test above.

Regenerating the committed fixtures (synthetic data, signed with the public RFC 8032 test
key — not a real key, not evidence):

```bash
NF_VERIFIER_FIXTURES=$PWD/verifier/test/fixtures \
  python backend/manage.py test evidence.tests_case_package_js.FixtureWriter
```

## Hosting it publicly

Because it never receives a file, a copy on a static host (a Hugging Face *Static* Space,
GitHub Pages) holds no evidence, accepts no upload and stores nothing: the case for not
running the product on the internet does not apply to this page. Publish `dist/nfverify.html`
together with `dist/nfverify.html.sha256`.
