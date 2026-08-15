# NetForensiq — Build Progress

**Target:** KANAD S.H.I.E.L.D. 2026 · Category 2, Problem Statement #8 —
*Network & Packet Forensics Platform (Cyber Crime Investigation System)*
**Event:** ~20 Aug 2026 · i-Hub Gujarat, Navrangpura, Ahmedabad
**Positioning:** not "another packet analyser" — **the chain-of-custody layer that makes
network evidence stand up in an Indian court.** Arkime/Zeek/Suricata show you packets;
none of them produce a BSA §63 certificate.

Code review that set this plan: [research/93_NETFORENSIQ_CODE_REVIEW.md](research/93_NETFORENSIQ_CODE_REVIEW.md)

---

## Status: Phases 0–6 complete · 36 backend tests + 8 Playwright E2E, all green

### Quick start

```bash
# backend  (SQLite by default — no database server needed)
cd backend && python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/python manage.py migrate
./.venv/bin/python manage.py generate_traffic --scenario mixed --seed 7
./.venv/bin/python manage.py import_pcap synthetic_captures/demo_storyline.pcap --name demo
./.venv/bin/python manage.py analyze_session
./.venv/bin/python manage.py runserver 127.0.0.1:8011

# frontend
cd frontend && npm install && npm run dev

# tests
cd backend && ./.venv/bin/python manage.py test          # 36 tests
cd frontend && npx playwright test                        # 8 E2E
```

---

## Phase 0 — Repo & environment ✅

- `research/` consolidated into the repo; external LLM reports under `research/external_reports/`
- `requirements.txt` was **UTF-16 encoded**, which silently breaks `pip install -r`. Rewritten
- **SQLite fallback** — the project hard-required PostgreSQL with no server installed, so it
  could not run at all. `DB_NAME` selects PostgreSQL; SQLite otherwise
- `SECRET_KEY` falls back to an ephemeral key so a fresh clone runs; `.env.example` added
- DRF now **denies by default** (`IsAuthenticated`) — previously every future endpoint was public
- Removed stray root `package.json` declaring `psql@^0.0.1`, an abandoned package pulling
  2013-era transitive deps
- `.vscode/settings.json` excludes `node_modules` (60,755 files) and `.venv` (14,911) from the
  file watcher

## Phase 1 — Critical correctness ✅

- **Packet timestamps.** `processor.py` used `time.time()` at parse time, so every imported PCAP
  was stamped with the import moment and all timing was destroyed. Now reads `pkt.time`.
  *Verified:* the planted 30 s C2 beacon round-trips as `interval_median = 29.997 s`,
  `dispersion = 0.026`
- **Flow direction.** "Forward" was decided by lexicographic IP ordering, making `bytes_ratio`
  (the exfiltration feature) meaningless. Direction is now anchored to the connection
  **initiator**, confirmed by TCP SYN where available
- **Beacon periodicity measured on the outbound leg only** — measuring across both directions
  alternates a ~0.2 s reply gap with the real ~30 s period and hides the beacon entirely.
  *Caught by testing, not inspection*
- IPv6 no longer silently dropped · `PcapReader` streaming replaces `rdpcap`
- `capture_start` / `capture_end` recorded separately from processing time

## Phase 2 — Evidence integrity ✅

- SHA-256 **+ MD5** at ingest, streamed in one pass, re-verified on export
- **Part A / Part B is statutory**, not commentary: it is THE SCHEDULE to the BSA 2023,
  cross-referenced by §63(4)(c), verified against indiacode.nic.in. The Schedule names
  SHA1/SHA256/MD5 explicitly — which is why MD5 is computed despite being weak, and never
  relied on alone
- Field provenance tagged `[STATUTORY]` / `[STANDARD]` / `[GOOD PRACTICE]` in the model, so we
  never claim legal backing we do not have
- `CustodyEvent` is hash-chained; each entry digests its predecessor
- *Verified:* one appended byte flips status to `tampered`; editing custody entry #2 reports
  `entry #2: content has been altered`

## Phase 3 — Detection engine ✅

Rules first (explainable), model second.

- Five rules: C2 beaconing · DNS tunnelling · port scan · exfiltration · ICMP tunnel
- **Every threshold carries its source**, published at `GET /api/detections/thresholds/`.
  Values we invented are tagged `[OUR HEURISTIC]` and that tag travels into each finding
- Beaconing follows RITA's *current* `analyzer.go` (MADM ÷ median interval); RITA's own README
  documents a fixed divisor of 30 and is stale
- DNS findings aggregate per (source, parent domain) — one alert per query produced 54
  near-identical rows for a single tunnel
- Exfiltration volume is relative to the capture (p95 outbound, floored at 100 KB); a fixed byte
  threshold cannot work across capture scales
- Human-in-the-loop triage: new / confirmed / dismissed / escalated, with reviewer and note
- *Verified:* all five planted attack types detected from 2,623 packets / 621 flows, as
  7 findings — no alert fatigue

## Phase 4 — API layer ✅

The capture app previously had **no HTTP surface at all**. Now:

| Endpoint | Purpose |
|---|---|
| `POST /api/sessions/{id}/analyse/` | run the detection rules |
| `GET /api/sessions/{id}/summary/` | dashboard aggregates, computed from rows |
| `GET /api/sessions/{id}/timeline/` | activity bucketed from packet timestamps |
| `POST /api/detections/{id}/triage/` | analyst confirm / dismiss / escalate |
| `GET /api/detections/thresholds/` | every threshold with its provenance |
| `POST /api/evidence/{id}/verify/` | re-hash and compare, logged either way |
| `POST /api/evidence/{id}/certificate/` | issue a BSA §63 certificate |
| `GET /api/evidence/{id}/custody/` | chain of custody + integrity verdict |

## Phase 5 — Frontend ✅

- Dashboard was **entirely hardcoded** — `Math.sin` sparklines, literal `"627.16 M"` strings.
  Every figure now traces to `services/forensics.js`
- **Deleted the "Blocked" and "Archived" cards** — this is a passive tool that can do neither
- Protocol bubbles sized by √count so *area* is proportional; the old fixed percentages summed
  to 145%
- New **Findings** page: rationale, full evidence JSON, triage controls, threshold provenance
  panel with a badge on our own heuristics
- New **Evidence** page: hashes, re-verify, hash-chained custody with intact/broken verdict
- Sidebar linked to six routes that did not exist; only real routes remain
- Removed fabricated telemetry from the login splash ("Evidence sealed 2,417", "1.24 Gb/s")

## Phase 6 — Test & verify ✅

- **36 backend tests** over the labeled synthetic corpus — feature maths, timestamp fidelity,
  each attack type, a **benign-traffic false-positive guard**, DNS aggregation, threshold
  provenance, IPv6, hashing, tamper detection, custody-chain breakage, certificate refusal on
  failed integrity
- **8 Playwright E2E** — auth guard, dashboard figures matching the API exactly, absence of the
  old placeholder strings, threshold inspection, triage round-trip, custody verdict
- Deleted the teammate's root `test_capture.py` (hardcoded interface index 9, machine-specific)

### Bugs the tests caught

1. Beacon period read as 0.3 s instead of 30 s — intervals were measured across both directions
2. `triage_status` missing from the serializer, so triage controls never rendered
3. CORS allowed only `localhost:5173`, so the browser blocked every API call from the test origin
4. The E2E suite exhausted the 8/hour login throttle; now one login per run via a fixture
   injecting tokens into sessionStorage (which Playwright's `storageState` does not persist)

---

## Ground rules for this build

1. **No hardcoded demo data.** Every number on screen comes from the database.
2. **No invented thresholds.** Detection parameters carry a citation or are explicitly labelled
   `[OUR HEURISTIC]`.
3. **No overclaiming.** Synthetic-data performance is reported as such.
4. Test at the end of every phase.

## Research backing this build

| File | Content |
|---|---|
| `research/SPEC_01_EVIDENCE_INTEGRITY.md` | BSA §63 verbatim, THE SCHEDULE field list, schema |
| `research/SPEC_02_DETECTION_ALGORITHMS.md` | RITA/Snort/binwalk/JA3 parameters with sources |
| `research/SPEC_03_CONNECTORS_AND_MCP.md` | Open feeds worth wiring in; Indian gov APIs that do not exist |
| `research/93_NETFORENSIQ_CODE_REVIEW.md` | The end-to-end review that produced this plan |

---

## Next up (not started)

- [ ] Certificate **PDF rendering** (reportlab installed; model and issue flow done)
- [ ] Threat-intel enrichment — abuse.ch SSLBL JA3 list, Tranco whitelist, Public Suffix List
      (see SPEC_03; all offline-capable)
- [ ] JA3 fingerprint computation (spec verified in SPEC_02, field not yet populated)
- [ ] Live-capture UI (management command exists; no HTTP trigger)
- [ ] IsolationForest as a clearly-labelled secondary signal
