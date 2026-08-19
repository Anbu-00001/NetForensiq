# 114 — PS-69EEFE2B677F3 objective coverage

The official requirement text is in
[PS_00](PS_00_OFFICIAL_PROBLEM_STATEMENTS.md#L2485). This file tracks, honestly,
what is built against it. It is a checklist to close, not a claim.

Status: ✅ built and tested · 🟡 partial · ❌ absent

## The eight Key Objectives

| # | Objective | Status | Where it stands |
|---|---|---|---|
| 1 | Capture and analyse live **and** stored network traffic | 🟡 | Both exist — `capture_live.py` and `import_pcap`, plus browser upload. **Live capture has no interface**, so from the outside the product looks import-only. Fix: expose it. |
| 2 | Detect anomalies including APTs, exfiltration, hidden tunnels | ✅ | 9 rules, 35 published thresholds, validated against two real malware captures. |
| 3 | Deep packet inspection and protocol decoding | 🟡 | DNS fully decoded, TLS ClientHello parsed to JA4, HTTP Host, SNI. **No FTP/SMTP decode, no session reconstruction.** |
| 4 | Signature-based **and AI-based** threat detection | 🟡 | Rules are strong. **AI/ML is documented as NOT IMPLEMENTED** — an explicit objective with a hole in it. |
| 5 | Visualize network flows and suspicious activities | 🟡 | Charts exist. **No graph-based visualisation of communication**, which the functional requirements name explicitly. |
| 6 | Support forensic investigation and evidence generation | ✅ | Custody chain, SHA-256/MD5/SHA-1, BSA §63 two-part certificate, provenance, public verification. The strongest area. |
| 7 | **Integrate with cybercrime investigation systems** | ❌ | FIR number and police station are stored as text. **No case entity, no linking of evidence to a case, no integration API.** The weakest area. |
| 8 | Secure and legally compliant data handling | 🟡 | RBAC, hash-chained audit log, throttling, air-gapped deployment. **No encryption at rest.** |

## Functional requirements not yet met

| Requirement | Status | Note |
|---|---|---|
| Session reconstruction | ❌ | Named under DPI. |
| Case management for investigators | ❌ | Named twice — under Forensic Investigation and under Integration. |
| Linking network evidence with reported cases | ❌ | The FIR field is a string, not a relationship. |
| Graph visualisation, source → destination mapping | ❌ | Named under Traffic Flow Visualization. |
| Highlighting suspicious nodes and connections | 🟡 | Findings name a `subject_ip`; nothing draws it. |
| Timeline correlation of events | 🟡 | An activity chart exists; events are not correlated on it. |
| Reconstruction of attack scenarios | 🟡 | `HOST_CORROBORATED` does this numerically, not narratively. |
| Automated report generation for legal use | 🟡 | The §63 certificate is generated. A full investigation report is not. |
| Alerts for suspicious activities | 🟡 | Findings are listed; nothing alerts. |
| API-based integration with other tools | 🟡 | A REST API exists and is documented; no integration is demonstrated. |
| Encryption of captured data | ❌ | Evidence is hashed and sealed, not encrypted. |
| Insider threat detection | 🟡 | Exfiltration and covert-channel rules cover part of it; it is not framed that way. |
| Filtering by IP, protocol, port | ✅ | Present on the flows endpoint. |
| High-throughput packet processing | ✅ | 166,972 flows from a one-week capture. |

## Order of work

Ranked by (a) named as a Key Objective, (b) what a judge sees in a demo.

1. **Graph visualisation of communication** — objective 5, named explicitly, and
   the single change that most improves whether a non-technical officer
   understands the screen. The per-host data it needs now exists
   (`capture/hosts.py`).
2. **Case management + evidence linking** — objective 7, currently the only ❌
   among the eight, and the thing that connects this to how a station works.
3. **AI-based anomaly detection** — objective 4, named explicitly. Must ship as
   a clearly-labelled secondary signal, never overriding a cited rule, or it
   contradicts the "explainable, not a black box" position.
4. **Live capture in the interface** — objective 1. The capability exists; only
   the surface is missing.
5. **Session reconstruction and further protocol decode** — objective 3.
6. **Automated investigation report** — beyond the §63 certificate.
7. **Encryption at rest** — objective 8.

## What must not be claimed

- That the ML component finds zero-days. It flags statistical outliers. The
  requirement says "identification of zero-day or unknown attacks"; the honest
  translation is "surfaces traffic that does not resemble the rest of this
  capture", and it must be labelled as a lead, not a finding.
- That evidence is tamper-proof. It is tamper-evident.
- That we integrate with CCTNS or ICJS. We can accept and record an FIR number
  and expose an API; no integration has been tested against a real system.
