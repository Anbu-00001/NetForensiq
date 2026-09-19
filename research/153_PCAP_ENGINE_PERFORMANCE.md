# 153 — Making the PCAP layer faster: where the time actually goes

**Question asked:** can a Rust / Go / C++ library replace scapy (and Django) to make
PCAP scanning faster and more accurate? Is there a unique framework in here?

**Short answer:** scapy was worth replacing, Django mostly is not, and neither needed a
new language. The measured bottlenecks were not where either of us expected: the
biggest wins came from a two-word change and a 200-line pure-Python parser, and the
import is now **6.7× faster end to end** with every finding unchanged.

The replacement also turned up two defects in recorded evidence that had nothing to do
with speed — an ICMP payload that varied with Python import order, and a DNS query the
old path invented out of a truncated packet. See §3A; those are arguably worth more
than the 6.7×.

Every number below is a wall-clock measurement taken on this machine (Linux 6.17,
Python 3.12.3, scapy 2.7.0) over real captures in this repository. Nothing is
projected, quoted from a vendor, or estimated. Where a measurement is noisy or a claim
is untested, it says so.

---

## 1. Baseline: where the time went before any change

Method: `profile_stages.py` runs the import pipeline in cumulative stages, each a
superset of the last, so a stage's marginal cost is its time minus the previous one's.
Measured on `RealAttacksPCAP/4SICS-GeekLounge-151022.pcap`, 400,000 packets.

| Stage | Wall clock | Marginal |
|---|---|---|
| 0 — read the file's bytes, parse nothing | 0.18 s | (1,183 MB/s — the disk floor) |
| 1 — scapy `RawPcapReader` frames | 0.97 s | +0.79 s |
| 2 — + timestamp and link type | 1.03 s | +0.07 s |
| 3 — + `fastparse.parse` (struct headers) | 1.88 s | +0.84 s |
| 4 — + `FlowAggregator` | 19.98 s | **+18.10 s** |

Share of total: frame reading **5.2%**, header parsing **4.2%**, flow aggregation
**90.6%**.

**The first thing this kills:** replacing scapy *as a pcap file reader* — which is what
"a faster pcap library in Rust" usually means — is capped at 5.2%. An infinitely fast
reader saves about one second in twenty. `fastparse.py` already did the work that
mattered there in 2025, and the 465-second figure in its docstring is history.

So the interesting question moved to: what is the aggregator doing for 18 seconds?

### 1.1 It was still scapy — as a dissector, not a reader

`cProfile` over the aggregator put `scapy.packet.Packet.__init__` at 17.35 s cumulative
of 31.57 s, with `do_dissect`, `__setattr__`, `fields.getfield` and 105,934 calls to
`__build_class__` underneath it. Two call sites are responsible, both of which use
scapy to answer a small question:

- `processor._dns_layer` — builds a full scapy `DNS` object to read six fields.
- `processor._icmp_payload` — builds a scapy `ICMP` object to find where a header ends.

Measured by removing each in turn (`scapy_share.py`, no profiler overhead, 150,000
packets per file):

| Capture | full | no scapy DNS | no scapy ICMP | neither | **scapy share** |
|---|---|---|---|---|---|
| 4SICS-GeekLounge-151022 | 10.51 s | 2.82 s | 8.39 s | 1.20 s | **88.6%** |
| wrccdc-2018-cyber-defence | 9.14 s | 6.16 s | 4.94 s | 2.13 s | **76.7%** |
| 2024-12-18-server-scans | 4.66 s | — | 3.20 s | 3.18 s | **43–60%** |

The third file was re-run three times because one pass reported "no DNS" as *slower*
than full — run-to-run variance on this machine is roughly ±15%, which is why the row
gives a range and not a single figure. The conclusion survives the variance: scapy is
**43–89% of flow aggregation**, and aggregation is ~90% of import.

### 1.2 But the largest single phase was detection, not parsing

Splitting the whole import into its three real phases (`e2e.py`, 150,000 packets):

| Phase | 4SICS | wrccdc |
|---|---|---|
| parse + aggregate | 8.98 s (36.0%) | 10.13 s (46.2%) |
| persist (Django ORM + SQLite) | 2.63 s (10.6%) | 2.88 s (13.2%) |
| **detection rules (our own Python)** | **13.33 s (53.5%)** | **8.90 s (40.6%)** |

Neither scapy nor Django. The biggest phase in the pipeline was code we wrote.

---

## 2. Fix already applied: an N+1 in IOC matching

`cProfile` on the detection phase: `rule_ioc_feed_match` → `ioc.match_session` was
20.28 s of 26.12 s, issuing **9,000 SQL queries** — but only 0.12 s of that was inside
the SQLite driver. The cost was Python, around the queries.

Instrumenting `Model.refresh_from_db` named the culprit exactly: 14,015 calls, one per
row, all to load one deferred field — `session_id`.

The cause is a Django trap rather than a Django flaw. `session.flows` and
`session.dns_records` are reverse-FK managers, and Django populates each returned
object's `.session` from the parent it was reached through. Doing so reads the FK
column — and a column left out of `.only()` is deferred, so reading it fires a
`refresh_from_db` for that single row. The `.only()` list was written to be frugal and
was paying per row to re-fetch what a wider list would have loaded once.

Naming `session_id` in both `.only()` calls ([capture/ioc.py:290](../backend/capture/ioc.py#L290),
[:315](../backend/capture/ioc.py#L315)):

| | time | queries | hits |
|---|---|---|---|
| as written | 7.11 s | 9,000 | 12,045 |
| with `session_id` | 0.57 s | 5 | 12,045 |

**12.5× faster, 9,000 queries to 5, byte-identical hits** (compared as sorted tuples of
every field each hit carries, over indicators seeded from the capture's own addresses
and domains so the count is non-zero). 142 existing tests pass.

End-to-end effect: 4SICS import 24.94 s → 16.75 s, **33% faster**, findings unchanged
at 40. The wrccdc capture improved far less (21.91 s → 21.32 s) because it has fewer
DNS records for the N+1 to multiply over — a reminder that a single capture is a poor
benchmark.

**This is the headline lesson for the language question.** The worst bottleneck in the
pipeline was a two-word omission. Rewriting `ioc.py` in Rust would have made a
9,000-query algorithm run its 9,000 queries faster.

`evidence/posture.py:112` and `:334` are the only other `.only()` call sites. Both were
audited with the same `refresh_from_db` instrument that found this one
(`scripts/pcap_benchmarks/posture_audit.py`) and both are clean: **0 deferred-field
reloads, 6 queries total**. `:112` is a plain manager rather than a related manager, so
no FK is populated behind it; `:334` pairs `.only()` with `select_related('case')` and
names every field it then reads. Reasoning said they were probably fine; the instrument
is what makes that a finding rather than a guess.

---

## 3. The scapy answer: replace the dissection, keep the discipline

The codebase's own rule (`fastparse.py` docstring) is that equivalence with scapy *is
not asserted, it is tested*. I held the prototypes to that.

### 3.1 DNS — a clean win

`fastdns_proto.py`, ~120 lines, reads exactly what `_process_dns` consumes: transaction
id, QR bit, `ancount`, QNAME (with compression pointers, bounded against pointer
loops), QTYPE, and A/AAAA rdata from the answer section. Bounds-checked throughout,
returns `None` rather than guessing.

| Capture | messages | scapy | prototype | speedup | identical |
|---|---|---|---|---|---|
| 4SICS | 40,000 | 9.157 s | 0.166 s | **55×** | 40,000 / 40,000 |
| wrccdc | 4,780 | 2.769 s | 0.029 s | **96×** | 4,780 / 4,780 |

**44,780 real DNS messages, zero differences**, comparing the full tuple
`(id, qr, qname, qtype-as-string, [A/AAAA rdata])`.

### 3.2 ICMP — where the test earned its keep

My first attempt was a constant-offset table (8 bytes, 20 for timestamp, 12 for address
mask). It ran 629–807× faster and was **wrong**: 123 mismatches of 9,415 messages, all
on types 3 and 11 — the error messages that quote the original packet.

Investigating: scapy returned exactly 128 bytes where a raw slice returned 255 or 328.
My first hypothesis was RFC 4884's `length` octet (original datagram in 32-bit words) —
**disproved**, that octet is 0 in all 6,675 samples. The actual rule is a flat 128-byte
cap on the quoted packet for error types. Adding it:

```
identical 73,935 / 73,935  (100.000%)
```

across both captures. So ICMP is replaceable too — but only because the test caught a
wrong answer that was 800× faster than the right one. Note what this implies: the
128-byte cut is a scapy dissection detail, not a protocol rule, and the findings
recorded to date have it baked in. Reproducing it is therefore the *correct* choice for
continuity, and it is the sort of thing no amount of reading the RFC would have told us.

### 3.3 Shipped, and what it cost

Both readers are now in the product: [`capture/fastdns.py`](../backend/capture/fastdns.py)
and `fastparse.icmp_payload`, consumed through `processor._dns_layer` and
`processor._icmp_payload`. The aggregator now sees one normalised
`fastdns.DnsMessage` whichever path fed it, so the live and import paths have a
single reading to keep in step rather than one each.

End to end, 150,000 packets per file, after §2 and §3 together:

| Capture | before | after | | findings |
|---|---|---|---|---|
| 4SICS-GeekLounge | 24.94 s | **3.71 s** | **6.7×** | 40 → 40 |
| wrccdc-2018 | 21.91 s | **4.58 s** | **4.8×** | 54 → 54 |

Flows and DNS records identical too (2038/11977 and 6905/2110). **564 backend
tests pass**, including 24 new ones in `capture/tests_equivalence.py`.

No new language, no build toolchain, no new dependency — and two fewer scapy
call sites, which matters separately because scapy is GPL-2.0-only and this
project is MIT.

---

## 3A. Two things the equivalence harness found that nobody was looking for

Both were discovered by diffing against scapy rather than by reading code, and
both are corrections to recorded evidence, not performance work. They are the
reason §7 is worth building rather than just worth describing.

### 3A.1 The ICMP payload depended on Python import order

`bytes(ICMP(m).payload)` does not return bytes from the capture. It returns the
re-serialisation of whatever scapy dissected the quoted packet into. For an
ICMP error quoting a datagram scapy recognises — CLDAP and SNMP both appear in
the reference captures — the ASN.1 is re-encoded with different length forms,
producing a different byte string of a different length.

Which messages that happened to depended on **which scapy layers were
imported**. Measured on `2024-12-18-one-week-of-server-scans…`, 13,511 ICMP
messages:

| scapy layers loaded | divergent from the wire bytes |
|---|---|
| `scapy.layers.inet` only | 0 |
| `scapy.all` (what `capture.service` imports) | **94** |

`payload_entropy` is derived from that payload, and the ICMP tunnelling rule
reads `payload_entropy`. So a finding could turn on an import statement. That
is not a property evidence can have.

`fastparse.icmp_payload` returns a contiguous slice of the message, always.
Impact of the change on that capture: **450 of 94,811 stored entropy values
moved (0.47%), and no finding changed at all — 184 before, 184 after.**

### 3A.2 The old path invented a DNS query that was never sent

scapy builds a `DNS` object out of whatever it is handed; given fewer than 12
octets it leaves every field at its class default and reports a question for
`www.example.com.`, scapy's default qname. The old `_dns_layer` passed that
straight through and `_process_dns` wrote it to `DNSRecord`.

Across 65,342 DNS messages in the corpus this happens **once** — a DNS-over-TCP
length prefix with no message after it — so the practical impact is one
fabricated row. The principle is not small: a forensic tool that invents a
query name under truncation is producing evidence of a lookup that did not
occur. `fastdns.parse` returns None instead.

Both divergences are deliberate, both are asserted in `tests_equivalence.py`
with ceilings so they stay exceptional, and both are cases where matching
scapy exactly would have meant preserving a defect.

---

## 4. The library survey you asked for

Licences matter here for a reason already established in this project: NetForensiq is
MIT, and scapy is **GPL-2.0-only**, which is why GPL-3.0 was rejected for our own code.
Every scapy call we remove reduces our exposure to that dependency — a second,
non-performance argument for §3 that a Rust rewrite would not improve on.

| Library | Language | Licence | What it would replace | Verdict |
|---|---|---|---|---|
| [rusticata/pcap-parser](https://github.com/rusticata/pcap-parser) | Rust | MIT/Apache-2.0 | file reading — **5.2% of import** | Amdahl-capped. Not worth a PyO3 build chain. |
| [etherparse](https://github.com/JulianSchmid/etherparse) | Rust | MIT/Apache-2.0 | `fastparse` headers — **4.2%** | Same cap. `fastparse` already costs 2 µs/packet. |
| [pcarp](https://lib.rs/crates/pcarp) | Rust | — | pcapng reading | "performance similar to libpcap", pcapng-only, no dissection. Nothing to gain. |
| [gopacket](https://github.com/gopacket/gopacket) | Go | BSD-3-Clause | reading + dissection | Actively maintained (community fork; last publish Aug 2026). Would mean a second runtime and an IPC boundary for ~30% of one phase. |
| [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus) | C++ | **Unlicense** (public domain) | reading + dissection | Fast and permissive; **no official Python bindings** — we would write and maintain the binding ourselves. |
| [nDPI](https://github.com/ntop/nDPI) | C | **LGPLv3** | protocol identification (*accuracy*, not speed) | The only entry that offers something we do not have. See §5. |
| [dpkt](https://github.com/kbandla/dpkt) | Python | BSD-3-Clause | DNS/ICMP dissection | ~17× scapy in a third-party benchmark. Our prototype measured **55–96×** here, with zero dependencies. |

**Conclusion on language:** every native candidate targets the 9% of the pipeline that
is already fast, or targets the 40% that pure Python just made 55–96× faster. The
crossover where Rust or C++ would pay is a pipeline whose Python parts are already
tight — which is only now becoming true, and even then the next bottleneck (§1.2) is
algorithmic.

I did not benchmark any of these libraries myself. The rows above describe what they
are and what they would replace; the speed claims in them are the projects' own or
third-party, and are marked as such. The only speed numbers I stand behind in this
document are the ones I measured.

---

## 5. Accuracy is a separate question from speed

You asked for "faster **and** more accurate", and nothing above makes the tool more
accurate — it makes identical findings arrive sooner, which was the point of testing
for byte-equality.

The one genuine accuracy candidate in the survey is **nDPI**: it identifies application
protocols by inspection rather than by port number. Today `processor._ingest` guesses
from `WELL_KNOWN_PORTS` and records `app_protocol_source = 'port'`, overwriting it only
when an HTTP Host header, TLS ClientHello or DNS message gives a real observation. A
tunnel on port 443 that is not TLS is exactly what that guess gets wrong, and it is
exactly what nDPI is built to catch.

Cost: LGPLv3 (workable for an MIT project via dynamic linking, but it constrains
distribution), a C dependency, and a new source of claims that would each need the
citation discipline the APK engine already follows. **Not scored above 7.5 — it is a
research item, not an implementation item**, and it should be evaluated on a labelled
corpus before anything is wired in.

---

## 6. Django

Persist is 10.6–16.7% of import — the smallest phase. But the ORM overhead inside it is
real. Like-for-like (`orm_fair.py`: same source dicts, same `Flow()` construction and
field coercion, same table, 6,905 rows):

| | time |
|---|---|
| `Flow()` + `bulk_create(batch_size=500)` | 2.00 s |
| `Flow()` + `executemany` on the raw driver | 0.50 s (**4.0×**) |

Both wrote 6,905 verified rows. For reference, the raw driver inserting
already-prepared tuples took 0.03 s, so nearly all of the remaining 0.50 s is Python
building values, not SQLite.

**This does not argue for replacing Django.** It argues for bypassing the ORM on the
one hot write path and keeping Django for everything it is actually good at here:
migrations, auth, the admin, DRF serialisers, and the evidence chain in `evidence/`.
A 4× on 13% of import is ~10% end-to-end; rewriting the backend in Go or Rust would
risk the Section 63 certificate handling, the custody model and the role system to
chase it. That trade is not close.

If Django ever *is* the bottleneck, the first move is Postgres (already supported via
`DB_ENGINE`) and `COPY`, not a new language.

---

## 7. The framework idea

The reusable thing produced today is not a parser. It is the method that made swapping
one safe, and it generalises into something this project has a specific claim to.

**Differential dissection gating.** Take the reference dissector (scapy) as an oracle,
run it and the fast path over every message in the real corpus, and require *byte
equality of the derived values* — not of intermediate objects — before the fast path is
allowed to ship. `tests_fastparse.py` already does this for IP/TCP/UDP. Today it
generalised to DNS (44,780 messages) and ICMP (73,935 messages), and it **rejected a
wrong implementation that was 800× faster** before it could change a single finding.

Why this is worth naming in a forensics tool specifically: the output is evidence. "We
replaced the parser and it got faster" is an engineering claim. "We replaced the parser
and the findings are provably identical across 118,715 real messages from named
captures" is a claim that survives cross-examination. Most network tools cannot say it
because they never had a slow, correct oracle to diff against — we do, and we were
about to throw it away.

Concretely this would become `capture/tests_equivalence.py`: a corpus-driven harness
that any future fast path must pass, with the message counts recorded in the test so a
regression in coverage is visible.

This is the honest version of "revolutionise". It is not a new protocol engine; it is a
safety property, cheap to build because the oracle already exists, and it is the reason
the ICMP shortcut did not ship.

---

## 8. Scoreboard

Scored on measured benefit × confidence ÷ risk, same bar as before: implement above 7.5.

| # | Item | Measured benefit | Score | Status |
|---|---|---|---|---|
| 1 | `.only()` N+1 fix in `ioc.py` | 12.5× on IOC matching; 33% end-to-end | **9.6** | ✅ **shipped** |
| 2 | `fastdns` replacing scapy DNS | 55–96×; 44,780 messages identical | **9.2** | ✅ **shipped** |
| 3 | Differential equivalence harness | caught a wrong 800× shortcut and two evidence defects | **8.7** | ✅ **shipped** (24 tests) |
| 4 | `icmp_payload` replacing scapy ICMP | 629–807×; deterministic bytes | **8.4** | ✅ **shipped** |
| 6 | Audit remaining `.only()` uses | 0 deferred reloads, 6 queries | **7.6** | ✅ **clean**, see below |
| 5 | `executemany` on the flow write path | 4.0× on persist | **7.8** → **6.0** | ⚠️ **blocked**, see below |
| 7 | nDPI for protocol identification | accuracy, unquantified | **6.1** | research only (§5) |
| 8 | Rust/C++ pcap reader (any of them) | ≤5.2% by measurement | **2.4** | ❌ rejected |
| 9 | Replace Django | ≤13–17%, high evidential risk | **1.8** | ❌ rejected |

**Why #5 was demoted rather than built.** `persist_results` links each DNS
record to its flow through the primary keys `bulk_create` hands back, and on
SQLite 3.35+ Django gets those via `RETURNING` for every row (verified: 71,832
of 71,832). A raw `executemany` does not return them, so taking the 4× means
inventing a scheme to recover the key mapping on the one write path that
carries the evidence chain. Tuning the existing call instead does nothing —
measured on 71,832 flow rows, the current `batch_size=500` is already the
fastest setting:

| batch_size | 500 | 2000 | 5000 | None |
|---|---|---|---|---|
| time | **10.76 s** | 14.60 s | 14.25 s | 15.48 s |

So the cost is the ORM's per-object machinery, not batching, and the cheap
version of this item does not exist. It stays open with the obstacle named.

Note that persist is now the *largest* phase on a flow-heavy capture — 52.3% of
27.30 s on `2024-12-18-one-week-of-server-scans…`, which produces 71,832 flows
from 150,000 packets. That is where the next real work is, and it is an ORM
question rather than a language one.

---

## 9. Limits of this study

- **Three captures, one machine.** 4SICS is ICS traffic (unusually DNS-heavy at 8% of
  packets), wrccdc is a defence exercise (ICMP-heavy), the 2024-12-18 file is server
  scans. Run-to-run variance is ~±15%. A fourth capture could move the percentages.
- **Equivalence was tested on values the aggregator consumes**, not on every field
  scapy exposes. That is the right scope — but it means the fast paths are equivalent
  *for this application*, and would need re-testing if a rule started reading a new
  field.
- **The 128-byte ICMP cap is now explained**, and the first rule for it was wrong.
  scapy implements RFC 4884 s.5.2 in `_ICMPExtensionField.getfield`: extensions start
  at octet 137, but only when the message reaches 144 octets, and only for types 3, 11
  and 12. A flat "cut error types at 128" rule matched scapy on all 73,935 ICMP
  messages in the corpus and was still wrong on **113 of 375** generated messages —
  types 3/11/12 between 137 and 143 octets, and types 4 and 5 at any length. Corpus
  agreement is not proof; those cases are now generated in `IcmpBoundaryTests`.
- **`fastdns` matches scapy's quirks deliberately**, including treating any label with
  either high bit set as a pointer (`cur & 0xc0`, not `== 0xc0`) and following forward
  pointers, which RFC 1035 s.4.1.4 forbids and [RFC 9267](https://www.rfc-editor.org/rfc/rfc9267.html)
  s.3 names as an anti-pattern. Work is bounded by scapy's own limits — a visited-set
  and 20 jumps — rather than by stricter ones, because a stricter limit would reject
  names scapy accepted and move findings.
- **Two divergences are intentional** (§3A) and capped in the tests. They correct
  fabricated and non-deterministic evidence respectively; neither changed a finding on
  this corpus, but both change stored column values, so a re-import of an old capture
  will differ in `payload_entropy` on ~0.5% of flows.
- **No library in §4 was benchmarked here.** Their rows describe capability and
  licence, not measured speed.
- **Three captures, and the third behaves differently from the other two.** The
  server-scan capture is flow-heavy rather than packet-heavy (71,832 flows from 150,000
  packets), and on it persistence dominates. Conclusions drawn from 4SICS and wrccdc
  alone would have missed that entirely.

*Measured 19 Sep 2026. Scripts in the session scratchpad; reproduce with
`profile_stages.py`, `scapy_share.py`, `e2e.py`, `dns_compare.py`, `icmp_rule.py`,
`combined.py`, `orm_fair.py`.*
