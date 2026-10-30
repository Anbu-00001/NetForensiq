# 167 — An outside review, checked point by point

An outside review of the repository (October 2026) listed what is still weak. Each point was
checked against the code before anything was changed, because a review can be wrong and a
fix for a problem that does not exist is still a change. Dated 30 Oct 2026.

| Point raised | Checked | Outcome |
|---|---|---|
| Network rules are noisy; detection is not competitive | Confirmed from `capture/data/rule_base_rates.json` | Open. Stated in the README's Honest Limitations with the figures |
| Signing key on the same disk as the data, no external anchor | Confirmed: `SIGNING_KEY_FILE` defaults beside the database | Open. Already stated; `PACKAGE_SIGNING_KEY` lets a lab keep it elsewhere |
| Nothing independently reviewed; corpora not like seized devices | Confirmed | Open. Stated |
| Custody hash joins fields with `|`, unescaped | **Confirmed, and exploitable in a narrow way** | **Fixed** |
| Throttles of 10,000/hour, effectively off for sign-in | **Confirmed, and the documents said 8/hour** | **Fixed** |
| JWTs in browser storage | Partly: `sessionStorage`, not `localStorage`; no CSP existed | **Mitigated** with a measured CSP; cookies not done |
| MIT project with GPL-2.0-only scapy in the web process | Scapy/androguard was already handled; a second pairing was found | Open question, stated |
| `grok.d` and `deep-research-report.md` in the root | They are cited inputs to research/95, not junk | **Moved** to `research/sources/` |

## The `|` join

`CustodyEvent.compute_hash` joins evidence id, sequence, action, badge, IP, detail, timestamp
and previous hash with `|`. Unescaped joining is sound when the text splits one way. Here the
integers, the action (a fixed choice), the IP address, the ISO timestamp and the hex digest
cannot contain `|`, so with one free-text field the split would be unique. There were two:
`actor_badge` had no restriction. A badge `GJ-1|` with no IP and detail `x` gives
`GJ-1|||x`; badge `GJ-1` with detail `|x` gives the same. Text can move between fields with
every hash unchanged.

That matters when a chain's head hash has been recorded somewhere outside the database, which
is the reason to keep a hash chain at all. It does not affect a signed package, whose signature
covers the fields separately.

**Fix.** A database `CheckConstraint` on `User.badge_id` and on `CustodyEvent.actor_badge`
(migrations accounts 0006, evidence 0010), a validator for a readable message, and a check in
both verifiers that rejects an entry where any field but `detail` contains `|`. No stored chain
changes: the live database held 24 users and 133 custody entries, none with `|` in a badge
(checked read-only before the migration was written).

**Tests.** The hashed text decodes back to exactly its fields; a re-split entry keeps its hash
and is rejected; the database refuses a badge with `|`; a form says why. The cross-language
check gained a 20th case, the re-split forgery, on which Python and JavaScript must agree and
must both fail.

## Rate limits

`settings.py` defaulted every scope to 10,000/hour outside tests from commit `bd22d94`
(21 Aug 2026), raised so that demonstrations would not lock anyone out. `.env.example` and
PROGRESS.md kept saying eight sign-ins an hour. The throttle tests did not notice, because
under test hard-coded values were used and nothing compared the documents with the code.

**Fix.** The rates live in `netforensiq_backend/throttles.py` with their reasons; the previous
documented values are the defaults again (sign-in 8/hour, anonymous 30/hour, and so on), and
`docker-compose.yml` defaults match. A demonstration raises one value deliberately
(`LOGIN_THROTTLE_RATE=200/hour`). Tests: no default above 1,000/hour, an empty variable counts
as unset, the running configuration uses these rates, and `docker-compose.yml` and
`.env.example` state the same numbers.

Found on the way: `User.account_locked_until` is a field nothing reads or writes.

## Tokens and the Content-Security-Policy

The interface keeps its tokens in `sessionStorage`: per tab, cleared when the tab closes, and
readable by any script in the page. There was no Content-Security-Policy, so an injected
script could have read them and sent them anywhere.

**Mitigation.** The app shell is served with `default-src 'self'; script-src 'self'; style-src
'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self';
object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. Inline styles
are allowed because MUI injects `<style>` elements and the D3 graph sets style attributes. The
header goes on the shell only: the offline verifier is served from the same directory with its
own policy that allows its inline scripts by hash, and a browser enforces every policy it
receives, so the shell's header on that file would stop it running.

**Measured** in Chromium against the built app served by Django on a throwaway database with
demonstration data: signed in, eight screens visited, no policy violations and no page errors;
the dashboard graph renders. Two controls show the policy is enforced rather than absent: an
injected inline script did not run, and a `fetch` to another origin was refused. The verifier
page loaded from the same server with no header policy and worked.

Not done: tokens in `HttpOnly` cookies. Not covered: the Vite development server, which does not
send the header.

## Licences

Scapy (GPL-2.0-only) and androguard/apkInspector (Apache-2.0) were already kept in separate
processes. Listing the declared licence of every installed dependency found one more pairing:
`psycopg2` is LGPL-3.0-or-later with an OpenSSL exception (its own `LICENSE`), and under
`docker-compose.yml` it is loaded in the same process as scapy. Whether an image containing both
may be redistributed as one program was not settled: the FSF's compatibility table could not be
read (four requests, each refused with HTTP 429), and its verdict is not stated here from
memory. The air-gapped compose uses SQLite and never loads `psycopg2`. `tzdata` (Apache-2.0) is
in the development environment but required by nothing on Linux, so it is not in the image.

## Not done

* Network detection. The useful next step is more attack captures, especially beacons, and a
  re-measurement; retuning against the same 30 captures would fit the rules to the test.
* The signing key's default location, a timestamp authority, and printing the key
  fingerprint on the Section 63 certificate.
* The open licence question above.
