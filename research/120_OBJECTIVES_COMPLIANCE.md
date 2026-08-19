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
| Protocol decoding (HTTP, HTTPS, DNS, …) | 🟡 | DNS, TLS/SNI, HTTP host decoded; FTP and SMTP are **port-inferred only** |
| Payload inspection for hidden data | ✅ | Shannon entropy sampling, `features.shannon_entropy` |
| Encrypted / obfuscated traffic patterns | ✅ | **JA4** TLS client fingerprinting, `tls_fingerprint.py` — verified against FoxIO's published reference values |
| Session reconstruction | ❌ | Flows are aggregated, not reassembled into streams |

**Honest note**: 94% of protocol labels on the server capture are port
inference, not observation (1,281 observed vs 21,034 inferred of 166,972). The
UI states which is which rather than presenting a guess as a reading.

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
| Timeline correlation of events | 🟡 | Per-session timeline exists; no cross-session correlation |
| Case management for investigators | ❌ | FIR number and police station are fields on an exhibit; there is no Case object grouping exhibits, officers and status |

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
