# 170 — The small fixes from the second review and the field audit

Dated 9 Nov 2026. A second outside review (an AI, 1 Nov) and a field audit by a separate AI
agent (9 Nov) each listed faults. This note is the set that could be fixed without changing
what the software decides: configuration, wording, pinned versions and checks. Each was
looked at in the code first. The faults that change behaviour are not here; they are listed
at the end.

| Point | Checked | Outcome |
|---|---|---|
| `docker-compose.yml` mounts no volume at `/app/data` (audit F-02/F-03) | Confirmed: the Dockerfile puts the evidence key, signing key and update trust list there; the main compose file mounted only the evidence store and the database | **Fixed.** `data:/app/data` added. The air-gapped compose already had it. A test holds it there |
| Key regenerated silently when its file is missing (F-02) | Confirmed in `crypto.load_key(create=True)` | **Open**, behaviour change: see below |
| `.env.example` sets `DEBUG=True`; the code defaults to `False` | Confirmed | **Fixed.** Example says `False`; a test holds it there |
| Four `check --deploy` warnings (HSTS, SSL redirect, secure session and CSRF cookie) | Confirmed: five warnings on the shipped settings | **Fixed behind one switch.** `HTTPS_ONLY`, off by default because the default deployment is plain HTTP on loopback. With it on, two warnings remain (`SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_HSTS_PRELOAD`), left unset because each commits a whole domain |
| No way to remove Django's `/admin/` | Confirmed | **Fixed.** `ADMIN_ENABLED=false` removes the route. Default unchanged |
| Pinned dependencies with advisories | Checked against the OSV database (`api.osv.dev`) for each pin: Django 6.0.7 (4, all GeoDjango), DRF 3.17.1 (7), PyJWT 2.13.0 (29), sqlparse 0.5.5 (10), pyzipper 0.3.6 (2), pytest 8.4.2 (2) | **Bumped** to Django 6.0.10, DRF 3.18.3, PyJWT 2.15.1, sqlparse 0.6.1, pyzipper 0.4.0, pytest 9.2.0, each the newest release of its series on PyPI that day; full suite re-run. One PyJWT advisory (GHSA-gvp8-978c-rx2q) lists no fixed release |
| No CI, no Dependabot | Confirmed: no `.github/workflows` | **Added**, not yet run on GitHub (see below) |
| Verifier lockfile not tracked (blind audit L9) | `verifier/package-lock.json` existed but `.gitignore` excluded all lockfiles | **Fixed.** Un-ignored; `npm ci` against it was run in a clean copy; the verifier tests pass |
| Badge reads "§63 certified" | The README itself says no lawyer or laboratory has reviewed the certificate | **Reworded** to "certificate form, not legally reviewed" |
| Internal-scan bar of 250 ports is not in the README | Confirmed: `scan_unique_ports_local` is 250 against 25 for an outside source | **Stated** in Honest Limitations. The rule itself is unchanged |

## Which of the advisories apply here

Not tested for exploitability. Reading the titles: Django's four are GeoDjango and this project
does not enable it; most of PyJWT's concern JWKS and asymmetric keys, which `simplejwt` with an
HMAC secret does not use, though a few (`jwt.decode` recursion on a deeply nested header,
non-canonical signatures) concern code that the token-refresh endpoint, which anyone can call,
plausibly runs; DRF's CPU and parser items concern any endpoint that parses a body or an `Accept`
header. Neither reading was tried against this application. They were bumped because a fixed release exists and the cost was one test run, not because
each was shown to be exploitable.

## The continuous-integration file

`.github/workflows/ci.yml` runs the backend suite, the migration check, the documentation and
publish-safety checks, and the verifier's known-answer and reproducible-build tests; a separate
job runs `pip-audit` and is informational, because a blocking audit would fail from the first run
on the PyJWT advisory above. The three actions' versions were read from their releases, and the
`v7` tag of each was confirmed to exist. **The workflow has not run on GitHub.** The commands it
holds were run by hand; the YAML was parsed; whether the runner has everything (for example
`poppler-utils`, which it installs, and the right Python packages from `requirements-nodeps.txt`)
is found out on the first push. The verifier's browser test is left out of it: it needs a browser
runtime.

## Not in this note: the faults that change behaviour

* Reusing an exhibit number overwrites the sealed file before the database refuses it (F-01).
* A missing evidence or signing key is regenerated silently, and every older exhibit then reads
  as altered (F-02).
* The certificate ticks "Computer/Storage Media" and "Operated by me" from fixed defaults (F-04).
* Findings an officer dismissed still appear in the report and the SIEM export (F-05).
* Per-case access control, the severity cap for network rules, and running the APK engine as a
  separate user.

Each changes what an officer sees or what a deployment does, so each wants a decision first.
