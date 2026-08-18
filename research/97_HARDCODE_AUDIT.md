# 97 — Hardcoded Value Audit

**Scope:** `backend/**/*.py`, `frontend/src/**`, `frontend/e2e/*.js`, `scripts/*.sh`,
`README.md`, `PROGRESS.md`. Excludes `node_modules`, `.venv`, `frontend/dist`,
`graphify-out`, `.codegraph`, migrations.

**Audited for one thing only:** hardcoded values that contradict the project's central
claim — *"no fabricated data — every figure traces to the database, every threshold
carries a citation."*

**Method.** `detection.py` read in full and every `THRESHOLDS` key cross-checked against
its read sites; every numeric comparison in `detection.py`/`processor.py`/`features.py`
traced to a published threshold or classified structural; backend suite executed twice
(dirty and clean cache) for the real test count; `npx playwright test --list` executed
for the real E2E count; rule count taken from the `RULES` registry and from `rule_id=`
literals.

**Headline.** The detection engine's provenance contract is in genuinely good shape —
all 32 published thresholds are read, a test enforces it, and the frontend has clearly
already been through a fabrication purge. The exposure is now concentrated in four
places: a **second, uncited copy of the risk-score table** in `models.py`, an **invented
FIR number** that the seed script writes onto real Section 63 certificates, **three
mutually contradictory test counts** in the docs, and a **shared throttle cache that
makes 27 tests fail** on a reviewer's machine.

---

## Verified counts (claimed vs actual)

| Claim | Where | Claimed | **Actual** | Verified by |
|---|---|---|---|---|
| Backend tests | `README.md:137`, `README.md:375` | **61** | **79** | `manage.py test` → `Ran 79 tests` |
| Backend tests | `PROGRESS.md:7` | **74** | **79** | same |
| Playwright E2E | `README.md:140`, `README.md:378` | **15** | **19** | `npx playwright test --list` → `Total: 19 tests` |
| Playwright E2E | `PROGRESS.md:7` | **19** | **19** | ✅ correct |
| Detection rules | `README.md:59`, `README.md:315`, `LandingPage.jsx:15`, `LandingPage.jsx:285`, `LoginPage.jsx:381` | **7** | **7 functions / 8 `rule_id`s** | `RULES` registry = 7; `grep -c "rule_id='"` = 8 |
| Real-traffic defects | `README.md:347`, `PROGRESS.md:61`, `PROGRESS.md:172` | **six** | **six** | consistent with `research/96` ✅ |
| Suite status | `PROGRESS.md:7` "all green, zero skips" | green | **27 errors** on a used machine | see C-1 |

---

# CRITICAL

### C-1 · The risk-score table exists twice, and the second copy is uncited literals
**`backend/capture/models.py:198-203`** and **`backend/capture/detection.py:1075-1081`**

`detection.py` publishes the 0–100 risk score through `THRESHOLDS` and states it is the
only source:

```
detection.py:1073   # Single source of truth, shared with Detection.Meta ordering. Published in
detection.py:1074   # THRESHOLDS so the 0-100 risk_score shown on the dashboard is not an
detection.py:1075   # unexplained number.
```

```
models.py:198       SEVERITY_RANK = {
models.py:199           Severity.LOW: 10,
models.py:200           Severity.MEDIUM: 35,
models.py:201           Severity.HIGH: 70,
models.py:202           Severity.CRITICAL: 95,
```

Both are live, on different write paths:
- `detection.py:1131` — `finding.severity_rank = SEVERITY_WEIGHT.get(...)` (bulk_create path, threshold-derived)
- `models.py:272` — `self.severity_rank = self.SEVERITY_RANK.get(...)` (`Model.save()` path, bare literals)

**Why it matters:** the "Flagged flows" card and the default sort order of the Findings
table are driven by a number that has two independent definitions. They agree today by
coincidence. Change `risk_score_high` in `THRESHOLDS` and the provenance panel will
publish 70→X while any finding written through `save()` still ranks at 70 — the exact
"unexplained number on the dashboard" the comment claims to have eliminated. This is the
single finding most likely to be fatal if a judge greps for the constants behind the
risk score.

### C-2 · An invented FIR/case number is written onto real Section 63 certificates
**`scripts/verify.sh:68`**

```bash
&& "$PY" manage.py import_pcap synthetic_captures/demo_storyline.pcap --name demo \
     --case "I-CR-2026-0042" --seized-from "Switch SPAN port" >/dev/null \
```

`I-CR-2026-0042` is a fabricated Gujarat-format crime register number and
`Switch SPAN port` a fabricated seizure location. These are not test fixtures — they go
through `ingest_evidence()` into `EvidenceRecord.case_reference` / `seized_from`, and are
then rendered:
- into the certificate PDF's statutory hash report — `certificate_pdf.py:363`
  `['Case reference', evidence.case_reference or '—']`
- onto the Evidence page — `EvidencePage.jsx:259` `` `· case ${record.case_reference}` ``

`verify.sh` writes into the same SQLite database the dev server serves, and seeds
whenever `Detection`/`EvidenceRecord` are empty (`verify.sh:57-70`). A judge demoing the
product downloads a BSA 2023 statutory declaration bearing an invented FIR number — on
the one document in the project whose entire premise is that nothing on it is invented.
`certificate_pdf.py`'s own docstring rule 1 is *"Statutory blanks stay blank… Filling it
with a plausible value would be forging a statutory declaration."*

### C-3 · Documentation states three different, all-wrong backend test counts
**`README.md:137`**, **`README.md:375`**, **`PROGRESS.md:7`**

```
README.md:137     # Backend: 61 tests
PROGRESS.md:7     ## Status: Phases 0–12 complete · **74 backend tests + 19 Playwright E2E, all green, zero skips**
```
Actual: **79**. Three documents, three numbers (61 / 74 / 79), none matching.

**Why it matters:** this is the cheapest possible thing for a judge to check —
`manage.py test` prints `Ran 79 tests` in 45 seconds. A project whose pitch is "every
figure traces to the database" cannot miscount its own test suite in two files, by two
different amounts.

---

# HIGH

### H-1 · The default cache location makes 27 tests fail on a reviewer's machine
**`backend/netforensiq_backend/settings.py:138`**

```python
'LOCATION': os.getenv('CACHE_LOCATION', str(BASE_DIR / '.cache')),
```

DRF's login throttle (`'login': '8/hour'`, `settings.py:232`) stores counters in this
cache. The test database is created fresh per run, but **the cache is not** — the test
runner shares `backend/.cache` with the dev server.

Measured on the current tree:
- With the existing cache: `Ran 79 tests … FAILED (errors=27)` — 27 tests error on
  `self.assertEqual(response.status_code, 200)` in `accounts/tests.py:87` (`_tokens()`),
  cascading into every `evidence.tests` class that authenticates.
- After `cache.clear()`: `Ran 79 tests … OK`

**Why it matters:** `PROGRESS.md:7` claims *"all green, zero skips"*. Anyone who runs the
app and then runs `manage.py test` — the obvious order for a judge — sees 27 errors.
`verify.sh:110-114` papers over this by clearing the cache first, so the harness is green
while the documented command is not. Note the workaround already exists there, meaning
the failure mode was known and left in the default path.

### H-2 · `score_beacon()` is dead code carrying two unpublished thresholds and a false evidence claim
**`backend/capture/detection.py:429-463`**

Never called. `grep -rn "score_beacon" backend --include=*.py` returns only the
definition at `detection.py:429`; `rule_beaconing` uses `score_connection_beacon`
(`detection.py:512`). It contains:

- `detection.py:449` `if duration_hours < 6:` and `detection.py:451` `if duration_hours < 11:`
  — two decision thresholds that appear in no `THRESHOLDS` entry and carry no source
  string, in the file whose docstring says *"Where no citable value exists the constant
  is tagged OUR_HEURISTIC."*
- A misstatement of what was computed. Only `ts` is ever scored:
  ```
  detection.py:447       components = {'ts': ts_score}
  detection.py:458       'renormalised': bool(omitted),
  ```
  For a flow lasting ≥11 h, `omitted` is empty and the evidence reports
  `renormalised: False` with `omitted_subscores: []` — asserting the full RITA composite
  was computed when three of its four subscores never were. The `ds` subscore is never
  computed and never declared omitted, at any duration.

**Why it matters:** it is dead so the harm is latent, but a judge reading the engine sees
uncited magic numbers and an evidence dict that would lie, inside the one file that is
the project's provenance contract. Either delete it or publish `6`/`11` as
`beacon_duration_subscore_hours` / `beacon_histogram_subscore_hours` with the RITA
citation that `score_connection_beacon:405-406` already gives them.

### H-3 · `ALLOWED_HOSTS` is the only setting in the file not environment-driven
**`backend/netforensiq_backend/settings.py:38`**

```python
ALLOWED_HOSTS = ['localhost', '127.0.0.1']
```

Every neighbouring setting reads from the environment — `SECRET_KEY` (`:33`), `DEBUG`
(`:36`), the whole database block (`:97-116`), `CACHE_*` (`:135-138`), `MEDIA_ROOT`
(`:181`), `HOME_NET` (`:195-199`), even `CORS_EXTRA_ORIGINS` (`:210`). `ALLOWED_HOSTS`
alone is baked in.

**Why it matters:** the platform cannot be deployed to any hostname without a source
edit. For a police-deployment pitch, "it only runs on localhost" is a demoware tell.

---

# MEDIUM

### M-1 · `LOW` and `CRITICAL` severities are published but unreachable
**`backend/capture/detection.py:210-213`**

`THRESHOLDS` publishes `risk_score_low: (10, …)` and `risk_score_critical: (95, …)`, and
`views.py:230-246` renders both to the user in the provenance panel. But no rule ever
emits either severity — all eleven `severity=` assignments in `detection.py` (lines 524,
526, 585, 651, 746, 790, 894, 896, 973, 974, 1033) use only `HIGH` and `MEDIUM`.

The guard test at `capture/tests.py:493` passes because `_t('risk_score_critical')` *is*
called (inside `SEVERITY_WEIGHT`, `detection.py:1080`) — it checks that a key is read, not
that its branch is reachable.

**Why it matters:** `SeverityBreakdown.jsx:4` renders `ORDER = ['critical', 'high',
'medium', 'low']`, so the dashboard advertises four severity tiers of which two can never
populate. A judge asking "show me a critical finding" cannot be shown one.

### M-2 · Entropy sampling policy is uncited but decides a cited threshold's outcome
**`backend/capture/processor.py:25-26`**

```python
MAX_ENTROPY_SAMPLES = 40
ENTROPY_SAMPLE_BYTES = 512
```

`payload_entropy` is the mean of at most 40 samples of at most 512 bytes each
(`processor.py:186-189`). That value is then compared against `exfil_entropy_high` = 7.6,
which carries a full binwalk citation (`detection.py:168`).

**Why it matters:** the threshold is sourced; the measurement it judges is not. On a
100 MB flow the "entropy" is computed from ≤20 KB chosen by arrival order. The comment
calls this a memory bound and asserts it is "without materially changing the entropy
estimate" — an unsupported claim on which a HIGH-severity exfiltration finding rests.
Neither constant appears in `THRESHOLDS` or in any finding's `evidence`.

### M-3 · A hardcoded "15 minutes" in user-visible rationale prose
**`backend/capture/detection.py:911`**

```
'state for only 15 minutes would not have reported.' if slow else '')
```

The value it describes is `scan_inactivity_timeout` = 900 s (`detection.py:191`), read
into `timeout` at `detection.py:847` and interpolated correctly two lines earlier
(`detection.py:903`, `gaps of more than {timeout:.0f}s`). This one restates it as a
literal in English.

**Why it matters:** it is rendered verbatim in the Findings panel
(`DetectionsPage.jsx:74`) and copied into chargesheets. Retune the threshold and the
finding's own explanation of itself becomes false, while the sentence beside it stays
correct — the most confusing possible failure.

### M-4 · `'system'` is printed as an officer name in the custody annexure
**`backend/evidence/certificate_pdf.py:420`**

```python
(event.actor.username if event.actor else 'system')
```

Under the column header `'Officer'` (`certificate_pdf.py:411`). `CustodyEvent.actor` is
nullable and is null for every event created by `import_pcap`, which never passes
`collected_by` (`import_pcap.py:53-58`) — so on the demo path *every* custody row in
ANNEXURE 2 names an officer called "system" who does not exist in the user table.

**Why it matters:** it is a placeholder identity in the chain-of-custody exhibit of a
court document, printed in the same column as real badge-carrying officers. Consistent
with `certificate_pdf.py`'s own rule ("statutory blanks stay blank"), this should be a
blank or "—", not a name.

### M-5 · Synthetic captures are sealed as evidence with no marker distinguishing them
**`backend/capture/models.py:19`** + **`scripts/verify.sh:66-69`**

`generate_traffic` writes a synthetic PCAP; `import_pcap` seals it via `ingest_evidence`
with a real SHA-256, a real custody chain and `source_type='pcap'` — identical in every
field to a genuine imported capture. `grep -rn "source_type" frontend/src/` returns
nothing: the field is serialised (`capture/serializers.py:101`) but never rendered.

**Why it matters:** nothing in the UI or the certificate PDF distinguishes a
machine-generated demo capture from seized evidence. Combined with C-2, the demo produces
a sealed exhibit with a fabricated FIR number and no indication it is synthetic.

### M-6 · Fallback values that render as fact
- **`frontend/src/components/layout/TopBar.jsx:107`** — `{user?.role || 'Operator'}`.
  "Operator" is not one of the backend's roles (`accounts/models.py:6-9` — admin /
  investigator / viewer). A user whose role fails to load is displayed as holding a role
  that does not exist. Neighbouring fields use `'—'` (`:110`, `:135`) — this one should too.
- **`frontend/src/pages/EvidencePage.jsx:210`** — `STATUS_STYLE[record.status] ?? STATUS_STYLE.archived`.
  An unrecognised integrity status renders as the definite label "Archived". Currently
  unreachable (the three keys at `EvidencePage.jsx:13-15` exactly match
  `evidence/models.py:83-85`), but the failure mode is silent mislabelling of an exhibit's
  integrity state — it should fall through to an explicit unknown.
- **`frontend/src/pages/DashboardPage.jsx:122`** — `(summary.session.capture_duration_seconds ?? 0)`
  renders "0 min" for an absent duration. `forensics.js:109` and `:117` deliberately
  return `'—'` for null precisely so a missing value is not shown as a measured zero;
  this line breaks that convention.

### M-7 · E2E specs bypass `baseURL` with a hardcoded host:port
**`frontend/e2e/forensics.spec.js:41, 337, 351`**

```js
await anonymousPage.goto('http://127.0.0.1:5199/dashboard');
```

`playwright.config.js:20` already defines `baseURL: 'http://127.0.0.1:5199'`, and the
rest of the suite uses relative paths. Change the port in the config and these three
assertions — including both anti-fabrication guards, the ones that exist to stop exactly
this class of defect from regressing — silently stop testing the app.

---

# LOW

| # | Location | Finding | Why it matters |
|---|---|---|---|
| L-1 | `frontend/src/pages/LandingPage.jsx:15`, `:285`; `LoginPage.jsx:381` | Rule count hardcoded in UI prose ("Seven deterministic rules", "seven cited rules", "7 RULES, SOURCED OR TAGGED"). Correct against `RULES` (7) but no test pins it, and the engine emits **8** distinct `rule_id`s. | Pre-auth marketing copy is the first thing a judge reads; add an 8th rule and three strings become wrong with nothing to catch it. Ambiguous today (7 functions vs 8 rule ids). |
| L-2 | `backend/netforensiq_backend/settings.py:167` | `TIME_ZONE = 'UTC'` hardcoded, not env-driven. | Defensible for forensics, but it means storage is UTC, the PDF converts to IST (`certificate_pdf.py:82`), and the UI renders in browser locale (`EvidencePage.jsx:303`, `DetectionsPage.jsx:130`) — three different zones for the same instant, none labelled in the UI. |
| L-3 | `backend/evidence/certificate_pdf.py:82` | `IST = ZoneInfo('Asia/Kolkata')` hardcoded. | Correct and arguably mandatory (the statutory form's label reads "Time (IST)"), but it is a baked-in locale assumption. Flagged for completeness only — **do not "fix" this**; the surrounding comment explains why it must not be configurable. |
| L-4 | `backend/netforensiq_backend/settings.py:204-209` | `CORS_ALLOWED_ORIGINS` hardcodes four loopback origins (:5173, :5199). | Mitigated by `CORS_EXTRA_ORIGINS` (`:210`), but the baked-in list includes the Playwright port, so test config leaks into the deployed allowlist. |
| L-5 | `frontend/src/services/api.js:5` | `import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8000/api'` | Correct env-first pattern, but a production build with `VITE_API_BASE` unset silently ships a bundle that calls the viewer's own localhost. Should fail loudly instead. |
| L-6 | `frontend/e2e/global-setup.js:6`, `frontend/e2e/forensics.spec.js:3` | `{ username: 'analyst', password: 'demo-pass-1234' }` | Legitimate test fixture — no seed command creates this account (verified: no `create_user` outside `tests.py`). But it is a weak credential committed in plaintext, and any demo machine where the account was created by hand is reachable with it. |
| L-7 | `backend/scripts/fetch_reference_captures.sh:187` | `unzip -o -P "infected_${datestamp}"` — archive password in source. | Publicly documented scheme for a public research corpus, and the comment at `:148-153` explains it honestly. Noted only because it is a literal credential. |
| L-8 | `backend/capture/processor.py:43-46` | `SRC_ZEEK_TIMEOUT` defined and referenced nowhere. `detection.py:132` defines its own `SRC_ZEEK_IDLE` for the same citation. | Dead citation constant; two strings for one source is how they drift apart. |
| L-9 | `backend/capture/processor.py:16-21` | `WELL_KNOWN_PORTS` maps port→protocol name, assigned to `app_protocol` at `:180-183` from the port number alone. | "Application protocols" on the dashboard (`ProtocolRanking.jsx:32`) reports e.g. "SSH" purely because the port was 22, with no dissection. Real detection (HTTP Host, TLS SNI) does overwrite it at `:332`/`:344`, but the unverified port-guess is what is displayed otherwise. Same identifier name as the unrelated curated frozenset at `detection.py:147`. |
| L-10 | `backend/capture/views.py:109` | `buckets = 30` — timeline bucket count, uncited. | Presentation, not detection — but it sets the resolution of the only chart on the dashboard and is invisible to the provenance panel. |
| L-11 | `backend/capture/features.py:74`, `:80`, `:114` | `len(timestamps) < 3`, `len(gaps) < 2`, `duration > 0.1` | Minimum-sample gates and a rate-measurability floor. `0.1` in particular is a decision threshold with a justifying comment but no source and no `OUR_HEURISTIC` tag, in a file feeding the cited beacon thresholds. |
| L-12 | `backend/capture/detection.py:737`, `:738`, `:805` | `samples < 3`, `query_name[:120]`, `sorted(names)[:5]` | Evidence-sample caps. Presentation, but they decide how much of the observed data an officer is shown, and are not declared in the evidence dict. |
| L-13 | `frontend/src/pages/StatusPage.jsx:26` + `:275` | `stageIndex('approved')` returns `2`, and `done = i < activeIdx` — so stage 3 "Access granted" renders **IN PROGRESS** for an already-approved account, directly above the "PROCEED TO TERMINAL" button (`:283-295`). | Status text contradicts the account's real state and the button beside it. |
| L-14 | `frontend/src/pages/LandingPage.jsx:423` | `NETFORENSIQ v1.0` — hardcoded version string. | Will not track releases; no single source of version truth in the repo. |
| L-15 | `scripts/verify.sh:23`; `playwright.config.js:20,28-30`; `global-setup.js:39` | Ports 8011 / 5199 repeated across four files with no shared source. | Harness-only, acceptable — but changing one requires finding all four. |
| L-16 | `backend/evidence/service.py:96`, `:159` | Exhibit/certificate prefixes `NF-` and `S63-` baked into identifiers. | Organisation-specific identifier scheme in a police deployment; should be configurable per unit. |

---

## Checked and found clean

Recording these so the same ground is not re-walked:

- **`THRESHOLDS` completeness.** All 32 keys are read by a rule. The 4 exempt keys
  (`flow_idle_timeout_*`) are explicitly listed in `INFORMATIONAL_THRESHOLDS`
  (`detection.py:294-299`), surfaced to the user as *"aggregation, not a rule"*
  (`DetectionsPage.jsx:230`), and enforced by `capture/tests.py:493-513`. **No unused
  published thresholds.** This is the strongest part of the codebase.
- **`Math.random` in `LandingPage.jsx:52-55`** drives a decorative canvas particle field
  only. No number derived from it is rendered as data. Not a finding.
- **No `Math.sin` sparklines, no `?? 42`-style fallbacks, no demo arrays** anywhere in
  `frontend/src`. `StatCard.jsx:7` explicitly refuses to draw a sparkline without real
  series data. The earlier fabrication purge held.
- **Login-attempt claim is true.** `LoginPage.jsx:249-250` ("recorded with timestamp,
  username and source address") is backed by `accounts/views.py:56-67` →
  `accounts/utils.py:11-19`, which stores `username_attempted`, `ip_address` and
  `user_agent` on both success and failure.
- **PDF chunk-size claim is true.** `certificate_pdf.py:380` ("1 MiB chunks") matches
  `evidence/models.py:50` `chunk_size=1024 * 1024`.
- **Evidence status labels are true.** `EvidencePage.jsx:13-15` matches
  `evidence/models.py:82-85` exactly, including wording. Status is `SEALED` only after
  `hash_file()` has run (`service.py:103-121`), so "Sealed — hash verified" is accurate
  at the moment it is first displayed.
- **Dashboard figures.** Every card in `DashboardPage.jsx:150-160` maps to a field
  computed by `capture/views.py:80-99` from stored rows. No authored constants.
- **Six-defect claim is self-consistent** across `README.md:347`, `PROGRESS.md:61`,
  `PROGRESS.md:172` and `research/96`.
- **`capture_live.py:14-19`** — the old hardcoded `--iface 9` default is gone and
  `required=True`, with the reasoning recorded.
- **No seeded production credentials.** No `create_user`/`create_superuser` outside
  `tests.py`; the E2E `analyst` account must be created by hand.

---

## Ranked remediation order

1. **C-1** — collapse `models.py:SEVERITY_RANK` into `detection.py:SEVERITY_WEIGHT`
   (import it, or have `save()` call through). One definition, threshold-derived.
2. **C-2** — drop `--case` / `--seized-from` from `verify.sh:68`, or replace with an
   unmistakable non-value (`DEMO-NOT-A-REAL-CASE`).
3. **C-3** — correct the four count claims to 79 / 19, and add an assertion or CI step
   so they cannot drift again.
4. **H-1** — point `CACHE_LOCATION` at a temp path under `manage.py test`, so the
   documented command is green without `verify.sh`'s workaround.
5. **H-2** — delete `score_beacon`, or publish `6`/`11` and fix the `omitted_subscores`
   claim.
6. **H-3** — `ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')`.
7. **M-1** — either emit `CRITICAL`/`LOW` from some rule, or remove the unreachable tiers
   from `SeverityBreakdown.jsx:4` and mark the thresholds informational.
8. **M-2 … M-7**, then LOW.

*Nothing in this audit was modified. Report only.*

---

# Resolution log — 18 Aug 2026

Every finding above was worked through. What was done, and where the fix is
pinned by a test.

## CRITICAL

| # | Resolution | Pinned by |
|---|---|---|
| C-1 | `Detection.SEVERITY_RANK` deleted; `Detection.severity_rank_for()` reads `detection.SEVERITY_WEIGHT`, itself derived from `THRESHOLDS`. **A second defect surfaced while fixing it:** the `Meta.indexes` list had been written *inside* `save()`, so none of the three indexes existed. | `capture.tests.SeverityRankHasOneDefinitionTests` |
| C-2 | Seeding moved into `manage.py seed_demo`, whose case reference is `DEMO-NOT-A-REAL-CASE` and whose seizure location says no seizure took place. It refuses to run at all when `ALLOWED_HOSTS` names anything beyond loopback. | `capture.tests.SeedDemoSafetyTests` |
| C-3 | `scripts/check_docs.py` measures the counts and compares them against every claim in README.md and PROGRESS.md; `verify.sh` runs it on every phase. | the harness itself |

## HIGH

| # | Resolution |
|---|---|
| H-1 | `netforensiq_backend/test_runner.IsolatedCacheRunner` gives the suite its own cache directory — still file-based, so throttling behaves as it does in a deployment. Verified by poisoning the shared cache with exhausted counters and re-running: green. |
| H-2 | `score_beacon()` deleted, with a comment recording what it was and why a per-flow beacon scorer was wrong in the first place. |
| H-3 | `ALLOWED_HOSTS` reads the environment. |

## MEDIUM

| # | Resolution |
|---|---|
| M-1 | `HOST_CORROBORATED` makes `CRITICAL` reachable — it restates findings rather than measuring anything, which is why it is the only rule allowed to say it. `LOW` is emitted by the exfiltration rule for a bulk upload over HTTPS with unremarkable entropy. A test scans the engine source and fails if any published severity is emitted by nothing. The synthetic corpus gained a `compromised_host` scenario, because every other scenario gave its behaviour to a different address — realistic for testing one rule, unrealistic as a model of a compromise. |
| M-2 | `entropy_max_samples` and `entropy_sample_bytes` are published as informational thresholds, and every finding that rests on entropy states how many samples backed it. The comment claiming the bound was "without materially changing the entropy estimate" is gone — nothing established that. |
| M-3 | The rationale interpolates `scan_inactivity_timeout` instead of restating it as "15 minutes". |
| M-4 | The custody annexure prints `—` where no officer is attached, and `import_pcap --officer` attributes custody entries to a real account. |
| M-5 | Provenance manifests. See the README section; four states, default `unattested`, `SYNTHETIC DATA — NOT EVIDENCE` banded across the certificate. |
| M-6 | `'Operator'` → `'—'`; unrecognised evidence status renders as unrecognised rather than "Archived"; an absent capture duration renders `—` rather than "0 min". |
| M-7 | `baseURL` threaded into the anonymous context; `API_BASE`, `apiGet`, `apiPost` and `rows` live in `e2e/fixtures.js`. The address appeared seven times; it now appears once. |

## LOW

Resolved: L-1 (`GET /api/engine/` serves the rule count and version to the
pre-auth pages, with an E2E test comparing screen against engine), L-4
(Playwright's origin comes from the harness, not from `settings.py`), L-5
(`services/apiBase.js`; a production build with no `VITE_API_BASE` falls back to
same-origin and says so), L-8 (duplicate Zeek citation removed), L-9
(`app_protocol_source` distinguishes a protocol read off the wire from one
guessed from the port — 94% of labels on the reference captures are guesses),
L-10 (timeline resolution is a query parameter and the chart states what each
point covers), L-11 and L-12 (measurability floors and evidence sample caps
named, explained and reported in the findings that use them), L-13 (an approved
application no longer shows its final stage as IN PROGRESS), L-14 (`VERSION`
file, served through `/api/engine/`), L-16 (identifier prefixes come from
settings).

Judgement calls, unchanged and deliberately so:

- **L-3 — `IST` in the certificate renderer.** The statutory form's field reads
  "Time (IST)". Making it configurable would let a certificate print a time
  under a label that is not the one the Schedule prescribes.
- **L-2 — `TIME_ZONE = 'UTC'`.** Storage stays UTC: an evidential timestamp has
  to mean the same instant wherever the file is opened. Presentation converts.
- **L-6 / L-7 — known credentials.** The demo password is now created by a
  command that refuses to run on anything reachable beyond loopback. The
  archive password is a publicly documented scheme for a public research corpus.
- **L-15 — ports repeated across harness files.** Harness-only; centralising
  them would add indirection to four lines that change together or not at all.

## Found while fixing, not in the original report

- **`Meta.indexes` written inside `save()`** — see C-1. Three indexes the API
  queries against did not exist.
- **Re-sealing an exhibit lost its provenance.** The manifest sat beside the
  *original* file, so re-importing the sealed copy — what someone does when
  reprocessing an exhibit — produced a record marked `unattested`. A synthetic
  capture downgraded to "origin unknown", quieter than the truth, which is the
  direction a provenance system must never fail. The manifest is now copied
  into the evidence store.
- **Exhibit numbers became filenames unvalidated.** `../` in an exhibit number
  would have written the sealed copy outside the evidence store while the
  record claimed it was in custody.
- **An N+1 query on the findings list.** Reporting each finding's exhibit added
  two queries per row; over seven pages of 343 findings the page stopped
  responding. `select_related('session__evidence')`, and the threshold panel no
  longer shares a `Promise.all` with the findings request.
- **Finding rows were clickable `div`s.** An officer working a long list with a
  keyboard could not open any of them, and a screen reader announced nothing.
