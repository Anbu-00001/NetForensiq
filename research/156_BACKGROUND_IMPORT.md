# 156 — Taking the import out of the request

**Question:** research/155 ended on three defects that shared one cause — the whole
import happened inside the HTTP upload, in one database transaction. Nobody could sign
in while a capture was being read (§4.1), the browser waited with no progress and no way
to survive a dropped connection (§4.2), and a 209 MB capture exhausted the worker
because every flow was held in memory until the last packet was read (§1).

This is the redesign, and what it measured.

**The bar it had to clear.** The findings this tool produces are evidence. A faster
import that changes a duration, splits a conversation in two or moves a finding is not
an improvement, it is a different answer. So the gate is the one `tests_equivalence.py`
sets for parsers: the new path may ship only if it reproduces the old path's output
exactly, on real captures, compared column by column.

---

## 1. What changed

### 1.1 Flows are written as they finish, not at the end

`FlowAggregator.drain()` hands over the flows that can no longer change and removes them
from memory. Two groups qualify: flows already retired onto `completed` by a fresh SYN
or an idle gap, and flows whose last packet is further behind the newest packet read
than their inactivity timeout **plus a 300-second margin**.

The margin is what makes it safe. `_starts_new_flow` attaches a packet to an existing
flow only if it arrives within that protocol's timeout of the flow's last packet, so a
flow dropped under this rule could only be dropped wrongly by a packet arriving more
than 300 seconds behind the watermark. That is a property of a file, so it is measured:
`max_reordering` records the largest backward step in every import, and
`tests_streaming.py` asserts it against the margin rather than assuming captures are
ordered. Expiring idle state to bound memory is what Zeek's inactivity timers do — the
timeout values here are already Zeek's.

DNS records are the exception and are still held to the end, because a reply is only
seen after the record for its query exists. Their flows' primary keys are remembered as
each batch is written — only for the flows that carried a query, which is thousands, not
hundreds of thousands.

### 1.2 Each batch is its own transaction

2,000 flows per transaction. SQLite permits "only one writer at a time"
([sqlite.org/wal.html](https://www.sqlite.org/wal.html) §2.2) and Django is configured
to `BEGIN IMMEDIATE`, so a transaction holds the write lock from the moment it opens.
One transaction for a 223,120-flow capture meant ~100 seconds of held lock; a sign-in
waits out its 30-second `busy_timeout` and fails.

`BEGIN IMMEDIATE` also matters for *why* waiting works at all: SQLite returns
`SQLITE_BUSY` without calling the busy handler when retrying could deadlock — the
classic case being a reader promoting to a writer
([busy_handler](https://www.sqlite.org/c3ref/busy_handler.html)). Taking the write lock
up front avoids that promotion, so a blocked writer really does retry.

### 1.3 The rules no longer hold the write lock while they read

`analyse_session` was wrapped whole in `transaction.atomic`. The rules read flows for
~43 seconds and write nothing; the writes are one `bulk_create` and a handful of grouped
`UPDATE`s. The transaction now opens after the last rule has run and covers exactly the
writes, so the findings are still all-or-nothing.

### 1.4 The reading happens in a separate process

`capture/importer.py` starts `manage.py run_import --session N` detached, and the upload
returns **HTTP 202** as soon as the exhibit is sealed and hashed — the part the officer
is waiting to be told. A child was chosen over a thread for two reasons: an import's
peak memory is set by the number of conversations in the capture, and in a thread that
peak is inside the web worker; and gunicorn recycles workers, which would kill a thread
mid-import and leave a session reading "running" for ever.

Progress is written to the session row every 50,000 packets — the same boundary
`capture/monitor.py` crosses for the live monitor, and for the same reason: no broker,
nothing extra to install on a machine with no network. The Import page polls it. A
session that stops reporting for ten minutes is recorded as failed when the API notices,
rather than being shown as running for ever.

### 1.5 A session is no longer called finished before it is analysed

Found by measuring, not by reading. `persist_results` marked the session COMPLETED as
soon as the flows were written, and detection ran after. For the ~43 seconds that took,
a 500,923-packet capture was on the dashboard as a finished analysis with **zero
findings** — indistinguishable from a capture in which nothing was found. The totals are
still recorded as soon as they are true; the verdict waits for the rules.

---

## 2. Measured

Same harness as research/155, same isolated server (gunicorn, 3 workers, `DEBUG=False`,
5 GB address-space cap), same machine, same captures.

| | capture | upload request | to a fully analysed session | peak RSS | sign-in during import |
|---|---|---:|---:|---:|---|
| A | XWorm, 13 KB, 146 pkts | 0.06 s → **0.03 s** | — → **1.0 s** | small | — |
| B | Mirai VM, 10 MB, 118,105 pkts | 46.3 s → **0.15 s** | — → **46.2 s** | 894 → **976 MB** | **200 in 5.91 s** |
| C | 7-day scans, 46 MB, 500,923 pkts | 102.0 s → **0.44 s** | 102.0 s → **89.3 s** | 1,691 → **1,469 MB** | **500 after 42.4 s → 200 in 1.63 s** |

"Peak RSS" is every process together — the three gunicorn workers *and* the import
child. The child's own peak was 555 MB on B and 994 MB on C.

**What the officer waits for at the form went from 46–102 seconds to under half a
second.** The total time to a finished analysis is modestly better (102.0 s → 89.3 s);
the point was never that reading a capture would become instant, it was that it stops
being a request.

The sign-in figure is the one that was a defect. It was HTTP 500 after 42.4 s on capture
C; it is now HTTP 200 in 1.63 s. On capture B the same sign-in took 5.91 s — slower,
because that capture produces 107,035 flows from 10 MB and the batches come fast — so
"nobody is locked out" is accurate and "sign-in is unaffected" would not be.

## 3. Equivalence

The same three files were imported by the old code and the new code into the same
database, and every stored row compared:

| capture | flows | 36 columns identical | findings | identical |
|---|---:|---|---:|---|
| XWorm | 1 | ✅ | 1 | ✅ |
| Mirai VM | 107,035 | ✅ | 53 | ✅ |
| 7-day scans | 223,120 | ✅ | 663 | ✅ |

**330,156 flow rows and 717 findings, byte for byte the same.** Capture A's finding is
still *"Unidentified 292s channel to 43.228.157.141:7007"* from `10.9.8.128` — the
published XWorm C2.

`tests_streaming.py` holds the same bar in the suite, on generated captures that put the
margin under pressure from both sides: a late packet inside the margin must still find
its flow, a reused port must still start a new one, and a DNS reply arriving after its
query's flow was written must still link to it.

## 4. Still open

- **The 209 MB capture has not been re-run.** research/155 §1 recorded it failing at
  4,523 MB. The three copies of each flow at the peak are now down to one plus a batch,
  which should be the difference — but that is an expectation, not a measurement, and it
  is not claimed as one here.
- **A fast scan burst still cannot be drained.** Eviction is by idle time, so a capture
  whose 107,035 conversations all happen inside a minute has nothing to write out early.
  Capture B is exactly that case, and its memory did not improve.
- **The graph can still fold away the victim** (research/155 §4.4), unchanged.
- **DNS records are still held whole.** A capture that is mostly DNS has no equivalent
  of `drain` for them.

*Measured 19 Sep 2026. Harness and logs in `GujaratPolice_Hackathon/pcap_realtest/`
(outside the repository); `run_background_test.py` is the script.*
