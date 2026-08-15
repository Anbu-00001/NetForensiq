# NetForensiq — Build Progress

**Target:** KANAD S.H.I.E.L.D. 2026 · Category 2, Problem Statement #8 —
*Network & Packet Forensics Platform (Cyber Crime Investigation System)*
**Event:** ~20 Aug 2026 · i-Hub Gujarat, Navrangpura, Ahmedabad
**Positioning:** not "another packet analyser" — **the chain-of-custody layer that makes
network evidence stand up in an Indian court.** Arkime/Zeek/Suricata show you packets;
none of them produce a BSA §63 certificate.

Full code review that set this plan: [research/93_NETFORENSIQ_CODE_REVIEW.md](research/93_NETFORENSIQ_CODE_REVIEW.md)

---

## Phase 0 — Repo & environment ✅

- [x] `research/` consolidated into the repo (was a sibling directory)
- [x] External LLM reports moved to `research/external_reports/`
- [x] `requirements.txt` rewritten — it was **UTF-16 encoded**, which breaks `pip install -r`
- [x] Added numpy, scikit-learn, reportlab, pytest, pytest-django
- [x] `.venv` created, all dependencies installed and verified
- [x] **SQLite fallback** — project had a hard PostgreSQL dependency and no server is
      installed; it now runs with zero database setup. PostgreSQL still used when `DB_NAME` is set
- [x] `SECRET_KEY` falls back to an ephemeral generated key so a fresh clone runs
- [x] `.env.example` added
- [x] DRF now **denies by default** (`IsAuthenticated`); previously every future endpoint
      would have been public
- [x] `MEDIA_ROOT` / `EVIDENCE_ROOT` / `CERTIFICATE_ROOT` configured
- [x] `.gitignore` extended (venv, sqlite, evidence, captures, playwright artefacts)

## Phase 1 — Critical correctness ✅

- [x] **Packet timestamps.** `processor.py` used `time.time()` at parse time, so every
      imported PCAP was stamped with the import moment and all timing was destroyed.
      Now reads `pkt.time`. *Verified:* the synthetic 30 s C2 beacon round-trips as
      `interval_median = 29.997 s`, `dispersion = 0.026`
- [x] **Flow direction.** "Forward" was decided by lexicographic IP ordering, making
      `bytes_ratio` (the exfiltration feature) meaningless. Direction is now anchored to the
      connection **initiator**, confirmed by TCP SYN where available
- [x] **Beacon periodicity measured on the outbound leg only.** Measuring across both
      directions alternates a ~0.2 s reply gap with the real ~30 s period and hides the beacon
      *(caught by testing, not by inspection)*
- [x] **IPv6** no longer silently dropped
- [x] **Streaming ingest** — `PcapReader` replaces `rdpcap`, so memory scales with distinct
      conversations rather than file size
- [x] Interval statistics (mean/median/stddev/MAD/dispersion) computed per flow
- [x] `capture_start` / `capture_end` recorded separately from processing time
- [x] `Detection` model added — every finding carries rule id, rationale, observed value,
      threshold and citation, so "why was this flagged?" is answerable from the record

## Phase 2 — Evidence integrity 🔜

- [ ] SHA-256 of the original PCAP at ingest, re-verified on export
- [ ] `EvidenceRecord`, `CustodyEvent`, hash-chained audit trail
- [ ] BSA §63 certificate generation (structure pending research spec)
- [ ] Emit the `VIEW_EVIDENCE` / `EXPORT_EVIDENCE` audit actions that already exist unused

## Phase 3 — Detection engine 🔜

Rules first (explainable), model second. Thresholds must be **cited**, not invented.

- [ ] C2 beaconing · DNS tunnelling · port scan · exfiltration · ICMP tunnel
- [ ] IsolationForest as a secondary, clearly-labelled signal
- [ ] Benign whitelist to control false positives

## Phase 4 — API layer 🔜

- [ ] Serializers + viewsets for sessions / flows / DNS / detections / evidence
- [ ] Wire into `urls.py` (capture app currently has **no HTTP surface at all**)

## Phase 5 — Frontend 🔜

- [ ] Replace hardcoded dashboard with live data
- [ ] **Delete the "Blocked" and "Archived" stat cards** — the system cannot do either
- [ ] Session / flow / detection / evidence views

## Phase 6 — Test & verify 🔜

- [ ] pytest suite over the labeled synthetic corpus
- [ ] Playwright end-to-end
- [ ] Independent audit agent pass

---

## Ground rules for this build

1. **No hardcoded demo data.** Every number on screen comes from the database.
2. **No invented thresholds.** Detection parameters carry a citation or are explicitly
   labelled `[OUR HEURISTIC]`.
3. **No overclaiming.** Synthetic-data performance is reported as such.
4. Test at the end of every phase.
