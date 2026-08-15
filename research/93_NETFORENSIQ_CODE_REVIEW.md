# NetForensiq — End-to-End Code Review

> **Reviewed:** 2026-08-15 · Commit `120ccd9` (single commit) · ~4,873 LOC
> **Target problem statement:** Category 2 #8 — *Network & Packet Forensics Platform
> (Cyber Crime Investigation System)*
> **Stack:** Django 6.0.7 + DRF + SimpleJWT + PostgreSQL + Scapy 2.7 · React 19 + Vite + MUI + Recharts

## Verdict — **CONTINUE**

The hard, unglamorous parts are built and built well: a real Scapy flow-assembly engine, a
forensically literate schema, police-grade auth, and a labeled synthetic attack generator.
What's missing — API layer, detection, UI wiring — is *additive*, not a rewrite. Restarting
would discard the two hardest components to rebuild the same thing.

**But be clear-eyed: the demo today is a facade.** The dashboard is 100% hardcoded, the capture
engine has no HTTP surface, and the "AI-driven anomaly detection" the problem statement
requires does not exist in any form.

---

## Scorecard

| Dimension | Score | Note |
|---|---|---|
| Data model / schema design | 8.5/10 | Genuinely forensics-literate |
| Packet processing engine | 6/10 | Good structure, one critical bug, two broken features |
| Synthetic data generation | 9/10 | Best part of the project |
| Auth & access control | 7.5/10 | Well-matched to police deployment; some dead code |
| API layer | **1/10** | Does not exist for capture |
| Detection / AI | **0/10** | Not started |
| Frontend ↔ backend integration | **1/10** | Auth only; dashboard is fake |
| Testing | **0/10** | Zero tests |
| Docs / reproducibility | 2/10 | No README, no `.env.example` |
| **Evidence integrity (BSA §63)** | **0/10** | Scored explicitly by the rubric |

---

## 🔴 Critical

### 1. The parser destroys packet timestamps — `capture/processor.py:57`

```python
now = time.time()          # ← wall clock at parse time
```

`pkt.time` is **never read**. Every packet in an imported PCAP is stamped with the moment of
import.

Consequences: `first_seen ≈ last_seen` for every flow → `duration_seconds ≈ 0` →
`packets_per_second` silently falls into the `else float(total_packets)` branch in
`features.py:59` → all timing features are garbage.

**The irony is severe.** `synthetic.py:242` builds C2 beaconing with a deliberate 30-second
interval and sets `pkt.time = t` on every packet — the interval *is* the beaconing signature.
`processor.py` throws it away on import. **The project's own demo data is destroyed by its own
parser.** Timeline reconstruction — the core of network forensics — is currently impossible.

*Fix:* use `float(pkt.time)` when present, fall back to `time.time()` only for live capture.
Small change, unlocks everything downstream.

### 2. The capture engine has no HTTP surface

`capture/views.py` is the untouched Django stub (`# Create your views here.`), and
`netforensiq_backend/urls.py` routes only `admin/` and `api/auth/`.

The entire engine is reachable **only** via management commands. The React app cannot see a
single flow. No serializers exist for `CaptureSession`, `Flow`, or `DNSRecord`.

### 3. The dashboard is entirely fabricated

`DashboardPage.jsx:13-22` — sparklines are `Math.sin`, chart data is `Math.sin`/`Math.cos`.
StatCards are literal strings: `"627.16 M"`, `"512.04 M"`. `ProtocolBubbles`, `ProtocolRanking`
and `HexHeatmap` are hardcoded arrays / a seeded LCG.

Two of the five StatCards claim capabilities **the system does not have in any form**:
- **"Blocked — 2.41 M"** — NetForensiq is a passive capture tool. It cannot block anything.
- **"Archived — 88.30 M"** — no archival feature exists.

A judge asking "show me a blocked packet" ends the demo. Delete these two cards.

Also `ProtocolBubbles.jsx:3-8` is internally incoherent: TCP `value: 80` → `54%`, TLS
`value: 162` → `27%`. The percentages don't follow the values and sum to **145%**.

### 4. No detection layer — the thing the PS actually asks for

`models.py:90-92` declares `is_analyzed`, `anomaly_score`, `risk_score`, and even indexes
`risk_score` — but **nothing anywhere writes them**. `requirements.txt` contains no numpy,
pandas, scikit-learn, or torch.

The problem statement requires *"signature-based detection, AI-driven anomaly detection"*.
Current completion: **0%**. The features to feed a model are computed correctly; the model
is absent.

---

## 🟠 High — correctness

### 5. Flow direction is arbitrary, so exfiltration detection can't work

`processor.py:25-35` defines "forward" by **lexicographic ordering of `(ip, port)`**, not by who
initiated the connection:

```python
if a <= b: return (...), True
```

So `packets_sent` / `bytes_sent` mean "from the lower-sorted endpoint", not "client → server".
`bytes_ratio` — explicitly the exfiltration feature — is therefore semantically arbitrary, and
its meaning flips depending on IP string ordering.

*Fix:* set direction from the first packet seen (or TCP SYN), and store an explicit
`initiator_ip`.

### 6. `unique_dst_ports` is structurally incapable of detecting port scans

Port is part of the flow key, so a scan across 1,000 ports creates **1,000 separate flows**,
each with `unique_dst_ports` of 1–2. The counter can never exceed 2.

`synthetic.py:220` generates port-scan traffic that this feature can **never** detect. Port-scan
detection must aggregate per *source IP* across flows, not within a flow.

### 7. IPv6 is silently dropped

`processor.py:51` — `if IP not in pkt: return`. `IPv6` is never imported. Any IPv6 PCAP yields
zero flows with no warning.

### 8. Memory is unbounded

`rdpcap()` (`service.py:111`) loads the entire PCAP into RAM, and `FlowAggregator.flows` grows
without limit. The `FlowAggregator` docstring claims it *"flushes completed flows to the
database in batches"* — **it does not**; `finalize()` returns everything at once. A multi-GB
police PCAP will OOM. Use `PcapReader` for streaming.

---

## 🟡 Medium — security

### 9. Unauthenticated enrollment enumeration — `accounts/views.py:75`

`ApprovalStatusView` is `AllowAny` and, given a username + badge_id, returns `department`,
`requested_role`, and timestamps. That lets anyone confirm whether a named officer is enrolled
and in which department, rate-limited only by `AnonRateThrottle` at 30/hour. On a police system
that's real information disclosure.

### 10. Account lockout is security theatre

`User.failed_login_attempts` and `account_locked_until` exist and migrate, but **nothing ever
increments or enforces them** — `failed_login_attempts` is only ever reset to 0 on success
(`views.py:63`). Either implement lockout or drop the fields.

### 11. DRF defaults to `AllowAny`

`settings.py` sets no `DEFAULT_PERMISSION_CLASSES`. Every endpoint added later is public
unless the author remembers to lock it. Set `IsAuthenticated` as the default now.

### 12. Audit actions declared but never emitted

`VIEW_EVIDENCE`, `EXPORT_EVIDENCE`, `LOGOUT`, `APPROVE_USER` are defined in `AuditLog.Action`
and never used. The *instinct* is exactly right — see below.

---

## 🟡 Medium — hackathon fit

### 13. No evidence integrity — and the rubric scores it explicitly

Every Category 2 problem statement lists **"Quality and admissibility of digital evidence"** as
a criterion. NetForensiq currently has: no SHA-256 hashing of ingested PCAPs, no chain of
custody, no BSA §63 certificate export, no write-once guarantees.

This is the **highest-leverage gap in the project** — it is cheap to build, directly scored, and
the `VIEW_EVIDENCE`/`EXPORT_EVIDENCE` audit enum shows the author already saw it coming.
See [PS_03_LEGAL_AND_DATA_REALITY.md](PS_03_LEGAL_AND_DATA_REALITY.md) for the two-part
(Part A operator / Part B expert) certificate structure and the `§63(4)(c)` hash-algorithm
requirement.

### 14. Zero tests

Both `tests.py` files are untouched stubs. `test_capture.py` is a manual script that hardcodes
`conf.ifaces.dev_from_index(9)` — machine-specific, not a test. The synthetic generator makes
this *painfully* easy to fix: generate a labeled PCAP, import it, assert the flows.

### 15. Reproducibility

No project README, no `.env.example`. PostgreSQL is required with no SQLite fallback, and
`SECRET_KEY`/`DB_*` come from an uncommitted `.env` — a teammate cloning this cannot run it
without asking. On demo day that's an avoidable risk.

---

## ✅ What is genuinely good

**Don't rebuild these.**

- **`models.py` schema** — separating `CaptureSession` / `Flow` / `DNSRecord` is correct.
  Including `ja3_hash`, `tls_sni`, `payload_entropy`, `longest_dns_label` and `tcp_flags_seen`
  shows real domain literacy. Indexes are sensibly chosen.
- **TLS SNI extraction** (`processor.py:193`) — the hand-rolled ClientHello parser is
  *correct*: offset 43 properly accounts for the 5-byte record header, 4-byte handshake header,
  2-byte version and 32-byte random. This delivers destination domains from encrypted sessions
  without decryption — a genuinely strong demo beat.
- **`features.py`** — Shannon entropy and the DNS subdomain features are the right signals,
  correctly implemented, and the comments explain *why* each matters.
- **`synthetic.py`** — the standout. Five labeled attack scenarios (DNS tunneling, exfiltration,
  port scan, C2 beaconing, ICMP tunnel) plus a benign baseline, seedable for reproducibility.
  Given that no real police PCAP is obtainable, generating labeled ground truth is exactly the
  right instinct — and it hands you a train/test set for the missing ML layer for free.
- **`accounts` app** — role + `badge_id` + `department` + admin approval + audit log is a
  genuinely well-matched model for police deployment, and better than most hackathon auth.
- **Persistence** — `bulk_create(batch_size=500)` inside `@transaction.atomic`, with DNS records
  correctly linked back to flows.
- **Comment quality** — explains rationale, not mechanics.

**Minor nits:** duplicate imports (`accounts/views.py:8-12`), duplicated comment line
(`api.js:19-20`), `from datetime import timedelta` stranded mid-file at `settings.py:154`.

---

## Recommended order of work

1. **Fix `pkt.time`** — one-line class of change, unlocks every timing feature *(critical)*
2. **Fix flow direction** — makes `bytes_ratio` mean something *(critical for exfil)*
3. **Build the API layer** — serializers + viewsets for sessions/flows/DNS *(unblocks the UI)*
4. **Wire the dashboard to real data; delete the "Blocked" and "Archived" cards**
5. **Add evidence integrity** — SHA-256 on ingest, chain of custody, §63 certificate export
   *(highest score-per-hour in the whole project)*
6. **Add detection** — start with explainable rules (entropy + DNS label length + beacon
   periodicity + per-source port fan-out), *then* IsolationForest on top. Rules first: a police
   panel will ask "why did it flag this", and a rule answers, a black box doesn't
7. **Re-scope `unique_dst_ports`** to per-source aggregation so port scans are detectable
8. **Tests** — import a generated PCAP, assert detections. The generator makes this trivial
9. **README + `.env.example` + SQLite fallback**

Items 1, 2 and 7 are small. Items 3, 5 and 6 are where the remaining value is.
