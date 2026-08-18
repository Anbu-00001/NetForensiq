# 100 — Final hardcoded-value audit

*18 August 2026. Performed directly rather than delegated: the agent tasked with
it hit a session limit mid-run. Scope and method are the same as
[research/97](97_HARDCODE_AUDIT.md), which this pass re-checks.*

**Verdict: one finding, fixed. Everything CRITICAL/HIGH/MEDIUM from 97 verified
resolved.**

---

## Re-check of research/97

| # | Finding | State |
|---|---|---|
| C-1 | Risk-score table defined twice, second copy uncited literals | **Fixed.** `Detection.severity_rank_for()` reads `SEVERITY_WEIGHT`; `SeverityRankHasOneDefinitionTests` pins the two together. Fixing it also restored three `Meta.indexes` that had been written inside `save()` and therefore never existed. |
| C-2 | Invented FIR number `I-CR-2026-0042` written onto real §63 certificates | **Fixed.** Seeding is `seed_demo`, whose case reference is `DEMO-NOT-A-REAL-CASE`; `SeedDemoSafetyTests` asserts the string cannot read as an FIR. |
| C-3 | Three contradictory backend test counts across the docs | **Fixed.** `scripts/check_docs.py` measures them and `verify.sh` runs it every phase. |
| H-1 | 27 tests failed on a machine that had run the app (shared throttle cache) | **Fixed.** `IsolatedCacheRunner` gives the suite its own file-based cache. Verified by poisoning the shared cache and re-running: still green. |
| H-2 | `score_beacon()` dead code with two uncited thresholds and a false evidence claim | **Fixed.** Deleted, with the reason recorded where it stood. |
| H-3 | `ALLOWED_HOSTS` the only setting not environment-driven | **Fixed.** |
| M-1 | `LOW` and `CRITICAL` severities published but unreachable | **Fixed.** `HOST_CORROBORATED` earns CRITICAL; the exfiltration rule emits LOW for a bulk HTTPS upload with unremarkable entropy. A test scans the engine source and fails if any published tier has no emitter. |
| M-2 | Entropy sampling policy uncited but decides a cited threshold | **Fixed.** Both constants published as informational thresholds; every finding that rests on entropy states how many samples backed it. |
| M-3 | "15 minutes" restated as prose beside the interpolated threshold | **Fixed.** |
| M-4 | `system` printed as an officer name in the custody annexure | **Fixed.** Prints an em dash. |
| M-5 | Synthetic captures sealed indistinguishably from real evidence | **Fixed** — see section F. |
| M-6 | Fallbacks rendering as fact (`'Operator'`, `STATUS_STYLE.archived`, `?? 0`) | **Fixed**, and one more of the same class found this pass — see below. |
| M-7 | E2E specs bypassing `baseURL` with a hardcoded host:port | **Fixed.** One `API_BASE`, one `baseURL`. |

---

## A. Fabricated or placeholder data reaching a user

**One finding, fixed during this pass.**

`frontend/src/pages/DashboardPage.jsx:177` rendered

```jsx
secondary={`${formatCount(totals?.detections_pending ?? 0)} awaiting triage`}
```

`formatCount` already returns an em dash for a missing value — that is its
whole purpose — and the `?? 0` overrode it, printing **"0 awaiting triage"** as
a measured claim when the figure had simply not arrived. Same class as M-6, on
the card an officer looks at first. The coercion is removed.

Everything else in `frontend/src` is clean. The remaining `||` and `??`
fallbacks are error strings (`'Authentication failed…'`), an avatar's initials,
or explicitly honest (`'Origin not recorded'`, ``Unrecognised status: ${…}``).
The only `Math.random` is a decorative particle canvas; no value derived from it
is rendered as data.

## B. Magic numbers in the detection engine

**Clean, and enforced by tests rather than by inspection.**

- `ThresholdsAreActuallyAppliedTests` fails the build if a published threshold
  is read by no rule.
- `ThresholdProvenanceTests` fails if a threshold carries no source string.
- `RuleRegistryTests` fails if `RULE_IDS` and the emitted `rule_id`s diverge.
- `check_docs.py` fails if the engine emits a rule `SPEC_02` does not document.

Remaining numeric literals in comparison positions were read individually:
`len(sorted_values) < 3` (a quartile needs three points), `median <= 0` (a
degenerate guard), and the TLS wire-format offsets in `tls_fingerprint.py`.
All structural, all commented.

## C. Configuration baked in

**Clean.** Every value a deployment must change reads the environment:
`SECRET_KEY`, `DEBUG`, `ALLOWED_HOSTS`, the database block, `CACHE_*`,
`MEDIA_ROOT`, `HOME_NET`, `EXHIBIT_PREFIX`, `CERTIFICATE_PREFIX`,
`ISSUING_ORGANISATION`, `CORS_EXTRA_ORIGINS`, `VITE_API_BASE`. What remains
hardcoded is Django's own structure (`INSTALLED_APPS`, `MIDDLEWARE`,
`ROOT_URLCONF`) plus `TIME_ZONE = 'UTC'`, which is a deliberate evidential
decision with its reasoning in the file.

## D. Comments claiming more than the code does

**Clean at the points previously flagged.** The two overstatements found earlier
are gone: the entropy sampling comment no longer asserts the bound is free, and
"a demonstration must not be able to pass itself off as a case" now reads
"…by accident", with the limits of the mechanism stated in
`capture/provenance.py` and in the README.

## E. Documentation figures

`python3 scripts/check_docs.py` passes: 127 backend tests, 57 E2E, 9 rule IDs,
7 rule functions, 35 thresholds. The checker now also fails when the engine
emits a rule the specification does not document — added after an outside
reviewer, not us, noticed that `COVERT_CHANNEL_UNKNOWN_PORT` and
`HOST_CORROBORATED` appeared nowhere in `SPEC_02`.

Its regex table covers the counts that appear in prose. It does not attempt to
police every number in the documents — the real-traffic figures in
`PROGRESS.md` are historical measurements, not claims about the current code,
and rewriting them automatically would erase the record.

## F. Can a demonstration capture be mistaken for evidence?

Every path was walked:

| Path | Outcome |
|---|---|
| Manifest missing | `unattested` — never `seized` |
| Manifest unreadable or malformed | `unattested` |
| Manifest detached and reattached to another file | Digest mismatch, manifest ignored, `unattested` |
| Officer declares `--provenance seized` over a synthetic manifest | Recorded as declared **and** the contradiction written into `provenance_detail` |
| `--no-seal` | No exhibit at all; findings render `not in evidence` |
| Re-import of the sealed copy from the evidence store | **Was a gap** — the manifest stayed with the original, so a synthetic capture came back `unattested`, quieter than the truth. Fixed: `ingest_evidence` copies the manifest into the store beside the sealed file. Covered by `ProvenanceSurvivesResealingTests`. |
| `EvidenceRecord` created outside `ingest_evidence` (admin, shell) | Field defaults to `unattested` — fails in the alarming direction |

The manifest is **not a security control** and the code now says so. Anyone who
can write to the capture directory can write one. What it makes impossible is an
*accident*: losing track of which file is which cannot silently produce an
exhibit, because every failure mode resolves to "origin not declared" and both
the register and the certificate print that.
