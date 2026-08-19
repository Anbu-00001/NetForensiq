# 120 — Compliance against the official problem statement

Category 2, Problem Statement 8 — *Network & Packet Forensics Platform*, Cyber
Crime Branch, Ahmedabad City Police.

Ten functional requirement groups are specified. This tracks each sub-item
against what the code actually does, with the file that does it. It is updated
as things land, and an item is only marked ✅ when something in the test suite
holds it there.

**Legend** — ✅ done and tested · 🟡 partial · ❌ not built

---

## 1. Packet Capture & Ingestion

| Sub-item | State | Where |
|---|---|---|
| Capture live network traffic (PCAP) | ✅ | `capture_live.py`, `service.run_live_capture` |
| Import and analyse stored capture files | ✅ | `import_pcap.py`, and now **through the browser** — `capture/upload.py` |
| High-throughput packet processing | 🟡 | 166,093 flows from a week-long capture parse and analyse; no formal throughput benchmark |
| Filtering by IP, protocol, port | ✅ | `FlowViewSet.get_queryset`, BPF filter on live capture |

**Added this pass**: browser upload with signature checking (not extension),
512 MB cap, required provenance declaration, and sealing before parsing.
Nine tests in `CaptureUploadTests`. Plus `capture_phone.py` — capture a
tethered phone's traffic, or pull a PCAPdroid capture over adb.

## 2. Deep Packet Inspection

| Sub-item | State | Where |
|---|---|---|
| Protocol decoding (HTTP, HTTPS, DNS, …) | ✅ | DNS, TLS/SNI, HTTP host at capture time; **full FTP, SMTP and HTTP transcripts** on demand — `capture/protocols.py` |
| Payload inspection for hidden data | ✅ | Shannon entropy sampling, `features.shannon_entropy` |
| Encrypted / obfuscated traffic patterns | ✅ | **JA4** TLS client fingerprinting, `tls_fingerprint.py` — verified against FoxIO's published reference values |
| Session reconstruction | ✅ | `capture/reassembly.py` — TCP stream reassembly with gap, retransmission and **overlap-conflict** reporting; `/api/flows/{id}/transcript/` |

**Honest note**: 94% of protocol labels on the server capture are port
inference, not observation (1,281 observed vs 21,034 inferred of 166,972). The
UI states which is which rather than presenting a guess as a reading.

**Added this pass**: real TCP reassembly, and the design decision behind it.
Ptacek & Newsham (1998) showed operating systems resolve overlapping segments
differently, so a reconstructed stream depends on an assumption about the
receiving host. Snort resolves this by guessing the destination OS —
appropriate for a sensor predicting what a victim saw, wrong for an examiner
who is testifying. So this keeps the first arrival, **names that policy**, and
reports the reconstruction as *ambiguous* whenever a later segment contradicts
an earlier one. Gaps end a run rather than being closed up: a capture that
missed the middle of a transfer must not yield a file that looks complete.
28 tests in `capture/tests_reassembly.py`. TLS is reported as *encrypted,
contents not recoverable* — materially different from an empty transcript.
Reading a transcript needs Investigator clearance even though it is a GET, and
is written to the exhibit's chain of custody.

## 3. Threat Detection

| Sub-item | State | Where |
|---|---|---|
| Signature-based detection | 🟡 | Nine deterministic rules with cited thresholds; **no external IOC feed** (abuse.ch, SSLBL) wired in |
| Malware communication and botnets | ✅ | `C2_BEACON_PERIODIC`, `C2_BEACON_KEEPALIVE` — RITA methodology |
| Data exfiltration | ✅ | `EXFIL_VOLUME_ASYMMETRY` |
| Covert channels and tunnelling | ✅ | `DNS_TUNNEL_*`, `ICMP_TUNNEL_OVERSIZED`, `COVERT_CHANNEL_UNKNOWN_PORT` |

## 4. AI-Based Anomaly Detection

| Sub-item | State | Where |
|---|---|---|
| Behavioural analysis of traffic | ✅ | `capture/anomaly.py` — IsolationForest over 13 flow features |
| Unusual traffic spikes and patterns | ✅ | same |
| Insider threat detection | 🟡 | Covered indirectly: an internal host behaving unlike its peers is flagged; no dedicated user-behaviour model |
| Zero-day / unknown attacks | ✅ | The point of the unsupervised signal — finds what no rule describes |

**Built this pass, on conditions.** The previous position was that an isolation
score cannot be testified to. That objection was to the *black box*, not the
method, so the implementation is bound by it: capped at MEDIUM, always names
the features that made a flow stand out with signed z-scores, and a flow the
model isolates but cannot explain is **dropped rather than reported**. Fitted
per capture, `random_state` pinned so the same evidence gives the same answer.
Shortlist capped at 50 with the number held back stated. Seven tests.

On the synthetic storyline it independently flagged `10.45.57.44` — the same
host the deterministic rules corroborate.

## 5. Traffic Flow Visualization

| Sub-item | State | Where |
|---|---|---|
| Graph-based visualization | ✅ | `components/graph/NetworkGraph.jsx`, `/api/sessions/{id}/graph/` |
| Flow diagrams (source → destination) | ✅ | same — directed edges, weighted by volume |
| Timeline-based activity tracking | ✅ | `timeline` action, bucket width published |
| Highlighting suspicious nodes and connections | ✅ | Nodes ringed and coloured by worst finding; edges carrying a flagged flow drawn red |

**Built this pass.** The design constraint was explainability: a legend is a
lookup table the reader must hold in their head, so instead every node carries
a full sentence — *"Inside the monitored network. Exchanged 438 KB across 179
conversations with 4 machines. 9 findings recorded against it."* Colour is
never the only signal; flagged hosts are also ringed and enlarged, so it
survives a colour-blind reader and a dim projector.

## 6. Forensic Investigation Module

| Sub-item | State | Where |
|---|---|---|
| Search and filter historical traffic | ✅ | Flow/detection/DNS filters, findings search |
| Reconstruction of attack scenarios | 🟡 | `HOST_CORROBORATED` assembles multi-rule host stories; no explicit kill-chain view |
| Timeline correlation of events | 🟡 | Per-session timeline exists; a Case now groups exhibits, but there is no cross-session correlation view |
| Case management for investigators | ✅ | `evidence.models.Case` + `CaseAssignment`, `/api/cases/` — exhibits, officers and status on one record |

## 7. Evidence Collection & Reporting

| Sub-item | State | Where |
|---|---|---|
| Export of forensic data | ✅ | Certificate PDF, sealed capture, custody chain |
| Tamper-**evident** storage with timestamps | ✅ | SHA-256 + MD5 + SHA-1, hash-chained custody log |
| Chain-of-custody tracking | ✅ | `evidence/service.py`, verified on every read |
| Automated report generation | ✅ | **Forensic examination report** — `evidence/investigation_report.py`, `/api/sessions/{id}/report/`. Cover sheet, findings by machine with reasoning and plain-language glosses, and a limits section that is never omitted |

**Note on wording**: the statement says "tamper-proof". This system is
tamper-**evident** — the hash chain reveals alteration, it does not prevent it.
Saying otherwise would be the single easiest claim for a judge to break.

**Added this pass**: `/api/verify/{exhibit}/` — open, unauthenticated
verification so defence counsel or a magistrate can test a certificate's
SHA-256 without credentials to the investigating agency's own system. Discloses
integrity, custody-chain state and provenance; never the case, the FIR, the
filename or the content. Seven tests.

## 8. Integration with Cyber Crime Systems

| Sub-item | State | Where |
|---|---|---|
| Integration with CCB databases | ❌ | No such integration; none is publicly documented to build against |
| **SIEM integration** (bonus) | ✅ | `capture/siem.py`, `/api/sessions/{id}/siem/?fmt=` — ECS, CEF and RFC 5424, streamed |
| Linking network evidence with reported cases | 🟡 | FIR number + police station recorded on the exhibit and printed on the certificate |
| Support for digital forensic workflows | ✅ | Seize → seal → analyse → triage → certify |
| API-based integration | ✅ | Full DRF API, JWT, documented |

**Do not overclaim here.** CCTNS/ICJS integration requires authorisation this
project does not have. The honest claim is that the API exists and the FIR
number is carried end to end.

## 9. Dashboard & Analytics

| Sub-item | State | Where |
|---|---|---|
| Real-time monitoring dashboard | 🟡 | Live capture writes flows as it runs; the dashboard does not yet stream |
| Alerts for suspicious activities | ✅ | Findings with severity, triage queue |
| Traffic statistics and trends | ✅ | Summary, timeline, protocol mix |
| Investigator-friendly UI | 🟡 | **The known weakness.** See below |

## 10. Data Security & Compliance

| Sub-item | State | Where |
|---|---|---|
| Encryption of captured data | ❌ | Evidence store is on the filesystem, unencrypted; relies on disk encryption |
| Role-based access control | ✅ | Four roles, enforced server-side, tested |
| Secure storage and access logs | ✅ | `AuditLog` — every read, verify, export and sign-in attempt, including rate-limited ones |
| Compliance with digital evidence standards | ✅ | BSA 2023 §63(4) two-part certificate, THE SCHEDULE Parts A/B |

---

## What is left, ranked

1. **Investigator-friendly UI** (obj. 9). All four roles render an almost
   identical dashboard; the new palette is defined but components still use
   hardcoded colours. This is the gap most likely to cost the pitch.
2. **Case management** (obj. 6). A Case object grouping exhibits, officers and
   status. Also unlocks "linking evidence with reported cases" (obj. 8).
3. **Encryption at rest** (obj. 10). Straightforward and currently absent.
4. **Session reconstruction** (obj. 2) and **FTP/SMTP decoding**.
5. **External IOC feed** (obj. 3) — abuse.ch SSLBL is offline-downloadable and
   fits the air-gapped model.
6. **Live dashboard streaming** (obj. 9).


---

## Bonus points

| Bonus item | State | Where |
|---|---|---|
| Real-time alerting for active threats | 🟡 | Live capture writes flows as it runs and rules can be run against a running session; no push/webhook delivery yet |
| Integration with SIEM systems | ✅ | `capture/siem.py` — **ECS**, **CEF 0** and **RFC 5424**, streamed line-by-line so a session with thousands of findings does not have to be held in memory. Nine tests, including one asserting the CEF header keeps exactly seven fields and one asserting the FIR number never leaves the case file |
| Encrypted traffic analysis without decryption | ✅ | **JA4** TLS client fingerprinting — `capture/tls_fingerprint.py`, verified against FoxIO's published reference values. Plus SNI, timing, volume and DNS. Nothing is decrypted and nothing claims to be |
| Automated attack classification | 🟡 | Findings carry rule, category and severity; **MITRE ATT&CK technique mapping is the missing piece** and is being researched before any identifier goes on a slide |
| Multi-language support for reports | 🟡 | Gujarati glossary renders in the interface. The PDF path cannot yet shape Gujarati correctly — ReportLab places glyphs in codepoint order, which mangles the script. Documented in `i18n/gujarati.js`; a real fix needs a shaping engine |
| Cloud-based scalable deployment | ✅ | `Dockerfile` + `docker-compose.yml` — multi-stage build, non-root uid 10001, healthcheck, tini as PID 1, Postgres with a real readiness probe, named volumes, port bound to loopback. **Image builds and runs; verified healthy and serving.** Coexists with the air-gapped path via `docker save`/`docker load` |

## Deliverables

| Deliverable | State | Where |
|---|---|---|
| Working prototype/demo (live or simulated) | ✅ | Both — `capture_live.py`, `capture_phone.py`, `import_pcap`, browser upload, and two real malware captures |
| Packet analysis and visualization dashboard | ✅ | Dashboard, findings queue, evidence register, and the network diagram |
| Threat detection demonstration | ✅ | Ten rules on real AsyncRAT/XWorm traffic; the synthetic storyline exercises every rule including host corroboration |
| Forensic report generation sample | ✅ | `/api/sessions/{id}/report/` — rendered and read end to end |
| Documentation (architecture, workflows, detection methods) | ✅ | `README.md`, `PROGRESS.md`, and 20+ research documents including SPEC_01/02/03 |
| Deployment setup (containerised/cloud-ready) | ✅ | Docker image built and smoke-tested; compose file with Postgres |


---

## Added after the first compliance pass

### Case management (objective 6)

`Case` carries the identifiers a court uses — case number, FIR, police station,
district, offence sections, status — entered **once** and read from there by
every exhibit, certificate and forwarding letter. ICJS names the principle:
*ONE DATA ONCE ENTRY*. Twelve exhibits from one raid previously meant the same
FIR typed twelve times, and one of the twelve will be wrong.

Two refusals are the interesting part:

- Linking a sealed exhibit to a case **never rewrites** the `case_reference` it
  was sealed with. If they disagree, the disagreement is recorded in the
  custody log for the officer to see. Editing an exhibit's stated provenance so
  it matches newer software is altering the record to fit the tool.
- An exhibit already on another case cannot be silently reassigned.

`CaseAssignment` enforces one capacity per officer per case, which is what makes
BSA s.63(4)'s two-different-people requirement checkable *before* a certificate
is drafted rather than at signing.

### The custody register (objectives 6 and 8)

Two requirements landed within a year of each other and describe a document
this system can already produce:

- **BNSS 2023 s.193(3)(i)** — the report filed on completion of investigation
  must state *"the sequence of custody in case of electronic device"*. Chain of
  custody is not good practice here; it is enumerated content of the charge
  sheet.
- **Kattavellai @ Devakar v. State of Tamil Nadu, 2025 INSC 845** (15 Jul 2025)
  — a Chain of Custody Register recording *"each and every movement of the
  evidence … with counter sign at each end thereof stating also the reason
  therefor"*, kept to conviction or acquittal and placed on the trial court
  record. Those directions were issued on DNA evidence and we do not claim they
  govern packet captures; what they settle is what a court now expects such a
  register to contain.

`evidence/custody_register.py` produces it. The signature column is **printed
empty** — the direction asks for a counter-signature from the person who made
the movement, and a row saying who was logged in is not that.

### Encryption at rest (objective 10)

AES-256-GCM in 1 MiB chunks, each with its own nonce and tag; the final chunk
carries a flag no other chunk carries, so truncation is detectable rather than
silently returning a shorter capture. `evidence/crypto.py`.

The constraint that shaped it: **the digest on the certificate stays a digest of
the plaintext.** A hash of ciphertext cannot be reproduced by anyone handed the
same capture, so it would be useless as evidence. Everything that reads an
exhibit decrypts first.

Switched on by default. When it is not on, the system says so — including how
many exhibits are ciphertext on disk versus how many are not, because
"encryption: on" beside forty exhibits in the clear is the failure worth seeing.
`manage.py encrypt_evidence_store` migrates an existing store and refuses to
encrypt any artefact that fails its hash first.

Losing the key destroys the evidence. There is no recovery path and there is not
meant to be one.

### Real-time alert delivery (bonus 1)

`capture/alerting.py` — RFC 5424 syslog over UDP or TCP, and JSON webhooks in
Elastic Common Schema. Fires at the end of each detection pass, after findings
are written, so an alert never describes a finding that failed to persist.

Every attempt is recorded with its outcome, because **an alert nobody received
that the system believes it sent is worse than no alerting at all** — the
operator stops watching the console. Delivery failures never propagate into
analysis: a SIEM that is down must not roll back a detection run.

Empty by default. An air-gapped workstation with no configured sink must not
open outbound connections, and silence there is correct behaviour rather than a
misconfiguration to warn about. Batches are capped at 100 and the receiver is
told the count withheld.


### Reading it back: what the demo capture actually contained

Reconstruction was run against the real server capture rather than the
synthetic one, and it decoded a live exploitation attempt that no rule had
flagged:

```
POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
HTTP/1.1  →  404 Not Found
```

That is **CVE-2024-4577**, the PHP-CGI argument injection: the `%AD` soft
hyphen survives the CGI handler's escaping and PHP's "best fit" Unicode mapping
turns it back into a real hyphen, so `-d allow_url_include=1 -d
auto_prepend_file=php://input` reaches the interpreter as command-line
arguments. The server answered 404, so the attempt failed.

Two things worth taking from it. The metadata layer saw a 33 KB HTTP flow and
nothing more; the content layer named the attack. And the tool found it without
a signature for it — which is the honest argument for why session
reconstruction earns its place beside the rules rather than duplicating them.

### Two defects the work surfaced

**Orientation.** A flow's `src_ip` is whichever address the capture saw first,
which for traffic recorded at the server is the server. The first
reconstruction returned an empty HTTP request because it had parsed the
*server's* stream looking for a request line. It failed silently — a transcript
with the sides swapped looks like a transcript. Fixed by orienting on the
recorded initiator (`reassembly.conversation_endpoints`), with three tests
holding it.

**Speed.** Finding one conversation means walking the whole capture, and
dissecting every layer of every packet through scapy took **39.7 seconds** on a
28 MB exhibit — long enough that nobody would use the feature twice. Replaced
with a direct header parser reading only the eight fields reassembly needs:
**0.9 seconds**, a 44× improvement. Correctness is held by tests that run the
same captures through both paths and compare the recovered runs byte for byte,
plus one that checks trailing Ethernet padding is not appended to the stream —
the frame is padded to 60 bytes, so payload length has to come from the IP
header's total length, never from the captured frame.
