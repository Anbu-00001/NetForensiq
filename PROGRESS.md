# NetForensiq — Build Progress

**Target:** KANAD S.H.I.E.L.D. 2026 · Category 2, Problem Statement #8 —
*Network & Packet Forensics Platform (Cyber Crime Investigation System)*
**Event:** ~20 Aug 2026 · i-Hub Gujarat, Navrangpura, Ahmedabad

## Status: Phases 0–12 complete · **74 backend tests + 19 Playwright E2E, all green, zero skips**

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

Seven rules. Every threshold carries its source; values we invented are tagged
`[OUR HEURISTIC]` and that tag travels into each finding's stored evidence.
Published at `GET /api/detections/thresholds/`.

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
   so they are large by design. 795 of 799 findings were the server's own replies.
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
- The 307 scan findings are consistent with the capture's description but have
  not been individually confirmed.
- **Import is slow** — ~110 s for 362k packets, nearly all inside scapy.
- `ja3_hash` is exposed on the API and never populated.
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
