# 155 — Real captures through the real upload path

**Question:** at the hackathon a PCAP upload "kept loading and never finished". The demo
runs look perfect. What happens with real captures, through the same web path an officer
uses — how long, how accurate, and do the dashboards hold up?

**Method.** The production server command from the Dockerfile (gunicorn, 3 workers,
1800 s timeout, `DEBUG=False`), run against an isolated copy of every stateful thing —
database, evidence store, encryption key — so nothing touched the real ones. Captures
uploaded through `POST /api/capture/upload/` exactly as the Import page sends them, then
the four calls the dashboard makes on open, then a headless Chromium signing in as the
investigator, picking each session from the dashboard's own dropdown and photographing
it. Server memory sampled throughout, every worker capped at 5 GB so a runaway import
fails instead of taking the machine down.

**Captures** — real traffic neither the demo nor earlier benchmarks had used, from
malware-traffic-analysis.net (each post carries a written analysis, which is the ground
truth), plus one large capture already on disk:

| | capture | size | why |
|---|---|---|---|
| A | 2026-09-08 XWorm post-infection traffic | 13 KB | accuracy: published C2 `43.228.157.141:7007` |
| B | 2025-12-17 Mirai botnet test VM (+ 7 KB in-the-wild scans) | 10 MB | IoT botnet; published IOC `158.94.210.88` |
| C | 2026-08-07 seven days of scans hitting a web server | 46 MB | scan traffic — huge flow counts |
| D | 4SICS GeekLounge ICS capture | 209 MB | near the 512 MB upload ceiling |

Only traffic archives were downloaded — never the `-files` or `-malware-samples`
archives that hold binaries — into `26_class/mal/pcaps/`.

---

## 1. What an officer waits for

| capture | packets | flows | upload request | worker peak RAM | result |
|---|---|---|---|---|---|
| A XWorm | 146 | 1 | 0.06 s | small | ✅ |
| B Mirai (wild) | 42 | 5 | 0.05 s | small | ✅ |
| B Mirai (VM) | 118,105 | 107,035 | **46.3 s** | 894 MB | ✅ |
| C 7-day scans | 500,923 | 223,120 | **102.0 s** | 1,691 MB | ✅ |
| D 4SICS | 2,274,747 | 940,733 | 62.7 s → **failed** | **4,523 MB** | ❌ HTTP 422 |

Where the 102 s goes on capture C, measured stage by stage outside the server:

| stage | time | memory added |
|---|---|---|
| parse + aggregate | 6.6 s | +430 MB |
| finalize | 2.1 s | +256 MB |
| **persist (Django ORM → SQLite)** | **55.8 s** | **+527 MB** |
| **detection** | **42.8 s** | held at ~1.1 GB |

Parsing is no longer the cost (`fastparse`/`fastdns`, research/153). **Time and memory
both scale with the number of distinct conversations, not with file size**, and every
flow is held three times at the peak — aggregator state, finalised dicts, ORM objects —
about 5.7 KB per flow. Capture D's 940,733 flows (a scan later in the file; the first
150,000 packets hold only 2,038) would need ~5.4 GB. It hit the 5 GB cap and failed.

## 2. Accuracy against ground truth

- **A — XWorm: correct.** One finding, *"Unidentified 292s channel to
  43.228.157.141:7007"* from infected host `10.9.8.128` — the published C2 exactly.
- **B — Mirai: correct, and was noisy.** The published IOC is found (*"Unidentified 118s
  channel to 158.94.210.88:56999"*), the sweep is one high-severity finding (*"Port scan:
  10.12.17.101 probed 106,689 host+port combinations on 106,688 hosts"*), the DNS panel
  surfaces `cnc.304.su`, and 57,735 TELNET flows are shown as "from port only" — Mirai
  scans Telnet. But the same host also carried **3,768 false covert-channel findings**
  (§3.2).
- **C — scanners hitting a web server:** 663 findings (613 `RECON_PORT_SCAN`); DNS panel
  shows `version.bind` probes and `dnsscan.shadowserver.org`.

## 3. Defects found and fixed

Each was reproduced before being fixed, and each fix was measured against the defect.
583 backend tests and 87 engine tests pass after all of them.

### 3.1 The dashboard showed one capture's figures under another's name

`DashboardPage.jsx` set `loading` only on first page load. Switching sessions left the
previous capture's cards, graph and timeline on screen, **under the newly selected
capture's name, with no spinner**, until the slowest of four requests returned.
Photographed: the dropdown reading session #9 (500.9 K packets) above session #6's
146 packets and its XWorm diagram. In an evidence tool that is a misattribution.

Fix: the loaded data carries the session it belongs to; anything that does not match the
selection is not drawn, and a spinner reads "Loading session #N…". A failed switch clears
rather than leaving the previous figures under the error. Re-photographed: all six
sessions show the session picked (dropdown and Packets card agree).

### 3.2 A covert-channel rule reported refused connections as channels

`COVERT_CHANNEL_UNKNOWN_PORT` rejected one-directional flows by *frame* bytes, so a bare
54-byte RST/ACK counted as "received". On capture B, Mirai's sweep of TCP/37215 (the
Huawei HG532 exploit port) left 3,768 SYN→RST flows — 1 packet each way — reported as
3,768 channels against one host, 1.1 MB of scenario JSON.

Fix: require at least two packets each way, the minimum for a TCP connection that
completed its handshake (RFC 9293 s.3.5). Measured across all nine sessions, demo and
real: the only change is capture B going from 3,769 findings to 1; every known true
positive is kept (AsyncRAT demo 5, storyline demo 2, XWorm 1, Mirai C2 1).

### 3.3 The attack-story panel froze the page

The scenario panel rendered every finding in a stage. Capture B's 3,769 rows made the
page too heavy for a headless browser to photograph within 30 s — an officer's tab would
have stopped responding. Fix: at most 12 rows per stage, then "…and N more — every one is
listed on the Findings page". Counts stay exact; only the drawing is capped.

### 3.4 The timeline built a model object per flow

`timeline` walked `session.flows.all()` to read four fields — the defect the graph
endpoint had already been fixed for. **7.1–7.5× faster, byte-identical on all six
sessions** (223,120 flows: 6.68 s → 0.90 s), and since the dashboard waited on it,
every panel now appears sooner.

### 3.5 Re-analysis left stale risk scores

Flows were reset only if never analysed before, so after a re-analysis 3,820 flows on
capture B still scored as risky with findings against 52. The Flagged-flows card, the
timeline's flagged band and the graph's red edges all read that column. It also issued one
UPDATE per flagged flow. Fix: reset once, then raise flagged flows in at most one batched
statement per severity. After: flagged flows equal flows with findings (52/52, 663/663, 1/1).

### 3.6 Running out of memory was reported as a bad file

`MemoryError` is an `Exception` with an empty message, so capture D came back as *"could
not be parsed: . It may be truncated or use an unsupported link type"* — sending the
officer to look for a fault in a good file. It is now reported as what it is (HTTP 413),
with the remedy: split the capture (`editcap -c`) or use a machine with more memory.

## 4. Not fixed — needs a design decision

### 4.1 Nobody can sign in while a large capture imports

Reproduced: a login during capture C's import returned **HTTP 500 after 42.4 s**; the same
login a moment later took 0.5 s. SQLite in WAL mode allows "only one writer at a time"
(sqlite.org/wal.html), the import holds the write lock through ~100 s of persistence and
detection, and a login writes (last-login, sign-in audit), waits out the 30 s busy
timeout and fails. So does any triage, sealing or signing by any other user.

### 4.2 The upload is one synchronous request

Hash, seal, parse, aggregate, persist and detect all happen inside the HTTP request, and
the frontend waits with `timeout: 0` and no progress. Anything that drops the connection
— a proxy's read timeout, sleep, Wi-Fi — leaves the browser spinning forever even when the
server finishes. This, with §4.1 and §1's memory profile, is the most likely explanation
of what happened at the hackathon.

### 4.3 One design fixes all three

A background import that **streams flows to the database in batches** as they expire:

- short transactions → other users' writes interleave (§4.1);
- the request returns as soon as the file is sealed, and the Import page polls a progress
  figure (§4.2);
- flows leave memory as they are written, instead of being held three times (§1) —
  expiring idle flows by capture time is the same rule `_starts_new_flow` already applies,
  so the records produced are unchanged.

For deployments with several concurrent users, the supported PostgreSQL backend removes
§4.1 on its own.

### 4.4 The graph can fold away the victim

On capture C, 60 external scanners fill the graph's 60-node limit, so the web server they
were all attacking is folded into "18,377 other hosts" — the one node an officer most wants
to see. Reserving slots for peers shared by many implicated hosts would fix it; not changed
here because it alters what the diagram shows by design.

## 5. Limits

- Five captures, one machine. Timings on a slower laptop will be longer; the flow counts
  and memory-per-flow are properties of the code and transfer.
- The e2e Playwright suite in `frontend/e2e/` was not run; the dashboard change was
  verified by lint, a production build, and the screenshot run described above.
- `home_net` was left blank, as an officer who does not know the network would; on capture
  C the server has a public address, so the graph cannot separate inside from outside.

*Measured 19 Sep 2026. Harness, logs, screenshots and report in
`GujaratPolice_Hackathon/pcap_realtest/` (outside the repository).*
