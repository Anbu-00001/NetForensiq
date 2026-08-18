# NetForensiq — Build Progress

**Target:** KANAD S.H.I.E.L.D. 2026 · Category 2, Problem Statement #8 —
*Network & Packet Forensics Platform (Cyber Crime Investigation System)*
**Event:** ~20 Aug 2026 · i-Hub Gujarat, Navrangpura, Ahmedabad

## Status: Phases 0–13 complete · **106 backend tests + 22 Playwright E2E, all green, zero skips**

The demonstration dataset is **real traffic**: two published captures with
written ground truth, plus — only when asked for with `--include-synthetic` —
one generated capture sealed and labelled `SYNTHETIC`.

```bash
./scripts/verify.sh      # runs everything: backend suite, seeding, API, E2E
```

---

## What this is, stated precisely

Arkime, Zeek and Suricata all analyse packets, and all of them are better at it
than we are. The gap this fills is narrower and further downstream.

**eSakshya** — NIC's app, mandatory under BNSS §105 — seals *scene video* and
issues a §63 certificate for it. **CCTNS Property Registers** track *physical
objects* through the malkhana. A packet capture is neither: it has no scene to
videograph and no object to book into an evidence room. It falls between the
two systems, and nothing currently covers it.

So: **not "another packet analyser" — the chain-of-custody layer for network
evidence, in the shape Gujarat's judiciary is already being trained to expect.**

⚠️ **Do not say "nobody else issues a §63 certificate."** eSakshya does, for its
own recordings — verified in
[research/95](research/95_ESAKSHYA_VERIFIED_FINDINGS.md). The claim only holds
for network evidence.

---

## The detection engine

Nine rule IDs, from seven rule functions plus one post-pass. Every threshold
carries its source; values we invented are tagged `[OUR HEURISTIC]` and that tag
travels into each finding's stored evidence. Published at
`GET /api/detections/thresholds/`.

**35 thresholds: 12 externally cited, 23 ours.** The claim was never that all of
them are sourced — it is that each one says which it is.

| Rule | Detects |
|---|---|
| `C2_BEACON_PERIODIC` | Repeated connections at a regular period (RITA's model) |
| `C2_BEACON_KEEPALIVE` | Periodicity *inside* one persistent session — RITA counts connections and sees only one |
| `COVERT_CHANNEL_UNKNOWN_PORT` | Sustained egress to an unrecognised port with no SNI |
| `DNS_TUNNEL_LONG_LABEL` | Labels at both tunnel length and encoded-payload entropy |
| `DNS_TUNNEL_SUBDOMAIN_VOLUME` | Many unique subdomains under one parent |
| `RECON_PORT_SCAN` | One source probing many host+port combinations |
| `EXFIL_VOLUME_ASYMMETRY` | Outbound volume past the capture's own p95 |
| `ICMP_TUNNEL_OVERSIZED` | Sustained oversized ICMP *echo* — errors excluded |
| `HOST_CORROBORATED` | One address that three or more independent rules keep naming |

`HOST_CORROBORATED` takes no measurement. It restates what the other rules
found, which is why it is the only thing allowed to say CRITICAL — and why the
CRITICAL tier on the dashboard could previously never populate at all.

**`$HOME_NET` is per capture, not per install.** An office capture is RFC 1918;
a capture of a public-facing server is not. One global setting means the second
case loaded is analysed against the wrong network and every egress rule
inverts. `manage.py suggest_home_net` reads a proposal off the traffic and shows
its working — it deliberately does not apply it.

---

## Validation against real traffic — the part that matters

Everything was synthetic until 15 Aug: a detector finding attacks the same
codebase planted proves only that the two agree. Two real captures from
malware-traffic-analysis.net, with published ground truth, changed that.

**It found six defects. Every one was invisible to the synthetic corpus.**

| | Before | After |
|---|---|---|
| Real AsyncRAT C2 detected | **0** | **5** — all on the documented C2 host |
| Alerts on a week of real server traffic | **7,052** | **307** — each a distinct scanning host |
| Longest flow | 22,736 s carrying 148 bytes | 201 s |

Full account: [research/96](research/96_REAL_TRAFFIC_VALIDATION.md). The
defects, briefly:

1. **The beacon rule counted packets where RITA counts connections** — and cited
   RITA for it. It agreed with our corpus only because the generator reused one
   source port, so packets happened to equal beacons.
2. **Nothing detected a persistent covert channel.** AsyncRAT holds one
   connection open, which RITA cannot see even implemented correctly.
3. **The rule read the wrong port** — the client's ephemeral port, not the
   service. 5,853 findings on inbound scans.
4. **No `$HOME_NET`.** All 172 "C2 beacons" on the server capture were external
   hosts probing *in*.
5. **ICMP errors flagged as tunnels.** They quote the original header (RFC 792),
   so they are large by design. 795 of 799 findings named the monitored server
   as their subject; filtering to echo types removed 338 and a minimum packet
   count removed 238 more, taking the rule from 799 findings to 25.
6. **A 5-tuple was treated as a connection.** Reused ephemeral ports merged
   conversations hours apart.

**A seventh came from the entropy gate.** Widening the DNS rule with entropy
immediately flagged `sunshine-bizrate-inc-software.trycloudflare.com` as
tunnelling. That host *is* the campaign's payload infrastructure — but it is a
Cloudflare hostname of dictionary words, not encoded payload. Right host, wrong
reason. Entropy now narrows the rule instead of widening it.

**Where we deliberately diverge from a cited source.** bro-simple-scan is a
streaming detector: its 15-minute timeout means a slow sweep never trips it.
Applied faithfully, that reported 100 episodes from 16 sources and discarded
291 hosts that scanned the same server slowly. We hold the whole capture, so
the count is cumulative and **291 slow scanners are recovered** — one probed 161
combinations over 5.1 days in 263 episodes, the largest just 4. The departure
and its reason are stated in the rule and in every finding's evidence.

---

## The audit

An agent swept the codebase for anything shown to a user that is not true.
**44 findings.** The worst: the landing page still carried every fabricated
figure this document once claimed had been removed — `Evidence sealed 2,417`,
`Packets / sec 84.2 K`, `Math.sin` sparklines — because the E2E suite only ever
visited authenticated routes. **The page a judge sees first was the one page
never tested.**

Also removed or fixed: an "ISOLATION FOREST" feature card for a model that does
not exist; a "D3 GRAPH ENGINE" for a page that does not exist; a
**"tamper-proof"** claim the custody model's own docstring refuses to make; a
`LIVE SYSTEM TELEMETRY` panel of hardcoded statuses rendered before login; and
`Purge buffer` / `Rotate storage` buttons wired to nothing, offering destructive
operations on evidence.

**Real defects behind the cosmetics:**

- **The §63 two-person rule was described in a comment and not enforced.** One
  account could sign both parts and get a complete certificate. Now refused.
- **Part A was signed by a click sending `{}`** — recording an officer as having
  made a statutory declaration they were never shown. It now displays the
  declaration and collects the Schedule's fields.
- **"Clearance level" governed nothing.** A viewer could triage, verify
  evidence and sign certificates. Now enforced, with approval checked too.
- **Logout was client-side only** — the refresh token stayed valid for a day and
  nothing recorded the session ending. Now blacklisted and audited.
- **The login throttle was per-process.** No `CACHES` was configured, so Django
  defaulted to LocMemCache: the 8/hour limit was really 8 × workers, and reset
  on every restart.
- **An invented "Identity verification" stage** told applicants their identity
  had been verified. Nothing verifies it; the backend has three states.
- **Eight thresholds were published to users but applied by nothing.**

---

## The hardcode audit

A second agent swept only for hardcoded values — anything shown to a user, or
used as a decision threshold, that does not trace to the database or to a cited
source. **Three critical, three high, seven medium, sixteen low.** All resolved.
Full report: [research/97](research/97_HARDCODE_AUDIT.md).

The four that mattered:

- **The risk-score table existed twice.** `detection.py` derived it from the
  published thresholds and called itself "the single source of truth" while
  `models.py` held the same four numbers as bare literals — both live, on
  different write paths (`bulk_create` vs `save()`), agreeing only by
  coincidence. Retuning a published threshold would have left the dashboard
  ranking findings by a number the provenance panel no longer matched.

  Fixing it uncovered a second defect: the `Meta.indexes` list had been written
  *inside* `save()`, so none of the three indexes existed.

- **An invented FIR number reached real Section 63 certificates.** The seed
  script wrote `I-CR-2026-0042` and `Switch SPAN port` through the real ingest
  path into the same database the dev server serves, and the certificate
  renderer printed it — on the one document whose own rule is *"filling a
  statutory blank with a plausible value would be forging a statutory
  declaration."* Seeding now uses `DEMO-NOT-A-REAL-CASE`.

- **The test suite failed 27 times on a reviewer's machine.** DRF's login
  throttle stores counters in the Django cache; the test *database* is fresh
  each run but the cache is not, so running the app and then running
  `manage.py test` — the obvious order — exhausted the limit. `verify.sh`
  cleared the cache first, so the harness was green while the documented command
  was not. The suite now gets its own cache directory, still file-based so
  throttling behaves as it does in a deployment.

- **A synthetic capture sealed as evidence was indistinguishable from a seized
  one.** Same hash, same custody chain, same certificate. Every capture now
  carries a provenance manifest, and a generated one is stamped
  `SYNTHETIC DATA — NOT EVIDENCE` across the top of its certificate.

Also resolved: `ALLOWED_HOSTS` was the only setting not environment-driven;
`score_beacon()` was dead code carrying two uncited thresholds and an evidence
dict that would have misreported which RITA subscores were computed; the custody
annexure printed `system` in the Officer column of a court exhibit; a finding's
own prose restated a threshold as "15 minutes" instead of interpolating it;
`AuditLog` filed triage decisions, detection runs and certificate signatures all
as `VIEW_EVIDENCE`, and `APPROVE_USER` — the one act that decides who may touch
evidence — was defined and never written.

---

## What the numbers say about themselves

`scripts/check_docs.py` measures the test counts, rule count and threshold count
and compares them against every claim in this file and in the README.
`verify.sh` runs it on every phase. It exists because three documents once gave
three different backend test counts, none of them right — the cheapest possible
claim for a reviewer to check.

---

## Ground rules

1. **No fabricated data.** Every figure traces to the database. Guarded by E2E
   on both public and authenticated pages.
2. **No fake affordances.** If a control is rendered, it does something.
3. **No invented thresholds.** Cited, or tagged `[OUR HEURISTIC]`. A test fails
   the build if a published threshold is read by no rule.
4. **No overclaiming.** Synthetic results are labelled synthetic; no precision
   or recall is claimed from two captures.
5. `./scripts/verify.sh` at the end of every phase.

---

## Known gaps — say these before a judge finds them

- **Two captures is not an evaluation.** No precision or recall is measured.
- Two of seven C2 flows were missed — 7 s and 13 s, below the sustained floor.
- **No beacon periodicity was detected on real malware.** 3.5 minutes is not
  enough for RITA's model, and thresholds were not tuned until it passed.
- The 308 scan findings are consistent with the capture's description but have
  not been individually confirmed.
- **Import is slow** — ~110 s for 362k packets, nearly all inside scapy.
- **No `LOW`-severity finding appears in the demonstration data.** The tier is
  reachable — the exfiltration rule emits it for a bulk upload over HTTPS whose
  payload entropy is unremarkable — but none of the three captures contains one.
- **`HOST_CORROBORATED` fires only on the synthetic capture.** Neither reference
  capture has a host implicated by three rules: one is a single-victim infection
  and the other is a server being scanned by hundreds of distinct sources.
- **JA4 is computed only for TLS over TCP on port 443.** QUIC and DTLS
  ClientHellos are not parsed, and a handshake split across TCP segments is
  skipped rather than guessed at. The fingerprint is simply absent for those.
- **`payload_entropy` is an estimate**, taken from at most 40 samples of at most
  512 bytes. Every finding that rests on it says how many samples backed it.
- **`suggest_home_net` is a heuristic** with no published algorithm behind it.
  It is a proposal an officer confirms, never applied on its own.
- No live-capture HTTP trigger; the management command exists.
- No Indian government system has a public API — Sanchar Saathi, CEIR, I4C,
  NCRP, CCTNS are web-form or police-network only
  ([SPEC_03](research/SPEC_03_CONNECTORS_AND_MCP.md)). Any integration claim
  must be framed as "designed to accept", not "integrated with".

## Research backing this build

| File | Content |
|---|---|
| [95](research/95_ESAKSHYA_VERIFIED_FINDINGS.md) | eSakshya verified claim-by-claim; what it does and does not do |
| [96](research/96_REAL_TRAFFIC_VALIDATION.md) | The real-traffic run and all six defects |
| [SPEC_01](research/SPEC_01_EVIDENCE_INTEGRITY.md) | BSA §63 verbatim, THE SCHEDULE |
| [SPEC_02](research/SPEC_02_DETECTION_ALGORITHMS.md) | Detection parameters with sources |
| [SPEC_03](research/SPEC_03_CONNECTORS_AND_MCP.md) | Open feeds; Indian gov APIs that do not exist |
