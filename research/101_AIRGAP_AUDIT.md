# 101 — Air-gap work: hardcode audit

Audited 19 Aug 2026, after the air-gap deployment path was built. Scope is the
code written that day: `spa.py`, `timesource.py`, the two bundle scripts, the
certificate change, and the documentation claims made about all of it.

**Verdict**: eleven findings, all resolved. Two were real defects that would
have been felt by a user; the rest were claims that outran the code. The most
serious was found by the browser suite rather than by reading, and the second
most serious by the agent that tried to actually install the bundle — neither
was visible on inspection, which is the point.

---

## CRITICAL

**1. The offline bundle shipped the developer's live case database.**
`scripts/build_offline_bundle.sh` excluded `db.sqlite3`. This project's database
is `netforensiq.sqlite3` (`settings.py`, `SQLITE_NAME`), so the exclusion never
matched anything and every installer carried a populated 52 MB database: ten
user accounts with password hashes, 197 audit-log rows, 166,972 flows, three
sealed evidence records, two §63 certificates and 61 live JWTs. Three lines
below the broken exclusion, a comment claimed the opposite.

*Resolved*: excluded by glob (`*.sqlite3`, `-wal`, `-shm`) rather than by one
literal filename, plus a post-copy assertion that fails the build if any
database, `.env` or evidence store reached the staging tree. The assertion was
negative-tested against a planted file. A fresh install now creates a 348 KB
database from migrations.

## HIGH

**2. A missing script or font was served as HTML.** `spa.py` decided the
SPA-fallback question from the `Accept` header and treated a bare `*/*` as
"wants HTML". Chrome sends exactly that for `<script src>` and `@font-face`, and
`fetch()` sends it by default — so `GET /assets/missing.js` returned index.html
with status 200. The module docstring specifically claimed this could not
happen. Measured against a running server before the fix: `.js`, `.woff2` and an
unknown `/apiv2/` path all returned `200 text/html`.

*Resolved*: the rule now comes from the path (does the last segment name a
file?) and from whether the request is a navigation, not from a header that
does not carry the distinction. Regression tests cover the exact headers Chrome
sends for scripts, stylesheets, images and fonts.

**3. `python3 -m venv` is a separate package on Debian and Ubuntu.** The
installer assumed it was present. On a machine with no network, `apt-get
install python3-venv` is not available, so the install would have failed with
advice that could not be followed.

*Resolved*: falls back to `venv --without-pip` and bootstraps pip from the
bundled wheel by putting it on `PYTHONPATH` — verified end to end, not assumed.
If venv is missing entirely it now says so in terms the operator can act on.

**4. With `DEBUG=False` nothing served the Django admin's own CSS.** The
deployment mode this work exists to support runs with `DEBUG` off and has no
reverse proxy, so the admin would have rendered as unstyled HTML with nothing
to explain why.

*Resolved*: `STATIC_ROOT` added, a route mounted over it, `collectstatic` added
to the installer, and two tests. Verified live: `/static/admin/css/base.css`
returns 200 `text/css` with `DEBUG=False`.

## MEDIUM

**5. `SECRET_KEY` regenerated on every restart.** `settings.py` falls back to a
random key when none is configured, which keeps a clone runnable — but the
bundle deliberately excludes `.env`, so every offline install inherited that
fallback. Restarting the workstation between shifts would have signed every
officer out with no explanation.

*Resolved*: the installer generates a key once, on the machine that will use it,
mode 600. It is never carried in the bundle, because a key shared across every
install is not a secret.

**6. The air-gap check could pass having read nothing.** `grep` over a glob
matching zero files returns success, so the step that certifies the build makes
no external references would have certified an empty directory.

*Resolved*: counts files first and reports the count. Also extended to the
952 KB JS bundle, which was previously unchecked — deliberately matching only
load-bearing forms (`url(`, `fetch(`, `src=`, `href=`) rather than bare
hostnames, because React and MUI embed documentation URLs in minified error
strings that are never fetched.

**7. The bundle's checksum file was unverifiable anywhere but the build
machine.** `sha256sum -c` recorded an absolute build path, so it failed on the
receiving side — where verifying the bundle is the entire point.

*Resolved*: records the bare filename; `sha256sum -c` now passes from the
unpack directory.

**8. `--help` printed a truncated sentence.** A hardcoded `sed -n '2,30p'` line
range that the header had already outgrown.

*Resolved*: reads the comment block until the first non-comment line, so it
stays correct however the header changes.

## LOW

**9. "The air-gapped machine needs Python and nothing else."** Not true as
stated — the scripts also use `tar`, `sha256sum`, `grep` and `find`. All are
present on any Linux install, which is why the claim looked harmless, but it is
still a claim the code does not support.
*Resolved*: "Python 3 and the POSIX utilities any Linux install already has",
in README.md, PROGRESS.md and the module docstring.

**10. Unexplained literals.** `ASSET_CACHE_CONTROL` carried a bare `31536000`,
and `timesource._QUERY_TIMEOUT_SECONDS` a bare `5`.
*Resolved*: the first is now `365 * 24 * 60 * 60`; the second carries the
reason for its value and for what the timeout path returns.

**11. "Two guards prevent it", followed by three bullets.** The docstring had
been edited without its own summary being reread.
*Resolved*.

## Deliberate, not findings

- **`django.views.static.serve` in a deployment.** Django's documentation calls
  it "inefficient and insecure" and says not to use it in production. It is
  used anyway, bound to loopback on a machine with no network — the case the
  warning does not describe. The module now states this outright rather than
  paraphrasing the warning into something softer.
- **Third-party reference captures are excluded by default.** 70 MB of malware
  traffic from malware-traffic-analysis.net is roughly half the bundle, and
  silently redistributing another party's corpus inside an installer is not a
  sensible default. `--with-reference-captures` includes them for a demo, and
  the script says which way it went and why.

## Verified clean

- No unexplained numeric literal remains in either new module.
- No new constant duplicates an existing one; nothing shadows `THRESHOLDS`.
- `timesource` makes no network call — asserted by a test that fails if a
  socket is opened, because a module written for an offline machine that
  reached for a time server would hang on exactly that machine.
- Every failure path in `timesource` resolves to `UNKNOWN`; an unrecognised
  value from systemd is never guessed into a confident answer.
- Fonts are genuinely local: `@fontsource/inter` and `@fontsource/jetbrains-mono`
  are npm packages compiled into the build, and the built CSS references only
  `/assets/…`. Confirmed by grep over `dist` and by the browser suite.
- The Gujarat High Court citation now in PROGRESS.md was verified by opening the
  judgment, not by trusting the two models that found it. See
  [research/104](104_DOSHI_CITATION_PROMPT.md).

## Final state

| | |
|---|---|
| Backend tests | **151 pass** |
| Playwright E2E | **61 pass** |
| ESLint | clean |
| Vite build | succeeds |
| `check_docs.py` | all documented counts match the code |
