<div align="center">

# 🛡️ NetForensiq

### Network & Packet Forensics Platform — built to survive a courtroom, not just a dashboard

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Django](https://img.shields.io/badge/Django-6.0-092E20?style=flat-square&logo=django&logoColor=white)](https://djangoproject.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Scapy](https://img.shields.io/badge/Scapy-2.7-F7931E?style=flat-square)](https://scapy.net)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![Tests](https://img.shields.io/badge/tests-447_passing-1B6E3C?style=flat-square)](#-tests)
[![Air-gapped](https://img.shields.io/badge/Runtime-air--gapped-1B6E3C?style=flat-square)](#-air-gapped-by-construction)
[![BSA §63](https://img.shields.io/badge/BSA_2023-§63_certified-6B3FA0?style=flat-square)](#-bsa-section-63-certificates)

**🥈 2nd Place — KANAD S.H.I.E.L.D. 2026**
Cyber Crime Branch, Ahmedabad City Police × i-Hub Gujarat
*Category 2 · Problem Statement #8 — Network & Packet Forensics Platform*

</div>

---

## 🎯 The Problem

Arkime, Zeek and Suricata will show you packets. **None of them will hand an investigating officer a document a magistrate can accept.**

Indian digital evidence lives or dies on the **Bharatiya Sakshya Adhiniyam (BSA) 2023, Section 63**. Physical seizure already has its rails — eSakshya videographs the scene, CCTNS logs the hard drive into the malkhana. Network evidence falls straight through the gap between them.

```mermaid
graph LR
    subgraph SCENE["🎥 Physical Scene"]
        A["eSakshya<br/><i>videographs seizure</i>"]
    end
    subgraph STORE["📦 Police Malkhana"]
        B["CCTNS Register<br/><i>logs the hard drive</i>"]
    end
    subgraph GAP["⚠️ The Gap"]
        C["PCAP · SPAN taps · volatile flows<br/><b>no scene video · no physical log</b>"]
    end
    subgraph NF["🛡️ NetForensiq"]
        D["Seal &amp; Hash"] --> E["Hash-Chained Custody"] --> F["Detect &amp; Attribute"] --> G["BSA §63 Certificate"]
    end

    C -.->|"cannot be videographed"| A
    C -.->|"cannot be shelved"| B
    C ==>|"sealed, tracked, certified"| D

    classDef scene fill:#E8F0FE,stroke:#1A73E8,stroke-width:2px,color:#0B2545
    classDef store fill:#FFF4E5,stroke:#B35C00,stroke-width:2px,color:#3D2200
    classDef gap fill:#FDECEA,stroke:#B3261E,stroke-width:3px,color:#5C0F0A
    classDef nf fill:#E6F4EA,stroke:#1B6E3C,stroke-width:2px,color:#0B3D1F
    class A scene
    class B store
    class C gap
    class D,E,F,G nf
```

> **NetForensiq is not another packet analyser.** It is the *legal admissibility and chain-of-custody layer* for network evidence.

---

## ⚡ Quick Start

```bash
git clone https://github.com/Anbu-00001/NetForensiq.git
cd NetForensiq

docker build -t netforensiq:latest .

docker run -d --name netforensiq --restart unless-stopped \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 127.0.0.1:8000:8000 \
  -v netforensiq_db:/app/data \
  -v netforensiq_evidence:/app/evidence_store \
  -e SECRET_KEY="change-me-before-real-use" \
  -e ALLOWED_HOSTS=127.0.0.1,localhost \
  -e SQLITE_NAME=/app/data/netforensiq.sqlite3 \
  netforensiq:latest
```

Open **http://127.0.0.1:8000** · seed the demo data with:

```bash
docker exec netforensiq python manage.py seed_demo
```

| Account | Role | Can do |
|---|---|---|
| `investigator` | Investigator | Import captures, triage findings, seal exhibits, sign Part A |
| `expert` | FSL / Examiner | **Countersign Part B**, examine APK samples |
| `commander` | Administrator | Approve accounts, read the sign-in log, examine samples |
| `viewer` | Viewer | Read-only |

<sub>Demo password for all four: `Netforensiq@2026`. `pending-applicant` fails by design — it demonstrates the approval gate.</sub>

> ⚠️ Bound to **loopback**, not `0.0.0.0`. A forensic tool that appears on the station LAN the moment it starts is not a decision anyone made.

---

## 🔄 The Evidence Lifecycle

Everything in NetForensiq flows through one pipeline. **The hash is taken before anything reads the file** — so the artefact the digest describes is the artefact the findings came from.

```mermaid
flowchart TD
    U["📥 <b>Officer uploads a capture</b><br/>browser or manage.py import_pcap"]
    P{"Declare provenance<br/><i>required · no default</i>"}
    S["🔒 <b>SEAL</b><br/>SHA-256 + SHA-1 + MD5<br/>copied into evidence store"]
    C1["⛓️ Custody event 1<br/><i>SEIZED · officer · timestamp</i>"]
    A["⚙️ <b>ANALYSE the sealed copy</b><br/>never the upload"]
    F["🌊 Flow assembly<br/><i>Zeek-sourced idle timeouts</i>"]
    D["🎯 11 detection rules<br/>+ statistical anomaly"]
    M["🗺️ MITRE ATT&amp;CK mapping"]
    C2["⛓️ Custody event 2<br/><i>ANALYSED</i>"]
    R["📊 Findings + attack scenario"]
    CERT["📜 <b>BSA §63 Certificate</b><br/>Part A + Part B · two people"]

    U --> P
    P -->|seized / reference / synthetic| S
    S --> C1 --> A
    A --> F --> D --> M --> C2 --> R
    R --> CERT

    classDef intake fill:#E8F0FE,stroke:#1A73E8,stroke-width:2px,color:#0B2545
    classDef seal fill:#E6F4EA,stroke:#1B6E3C,stroke-width:3px,color:#0B3D1F
    classDef chain fill:#FFF9E6,stroke:#B38600,stroke-width:2px,color:#3D2E00
    classDef analyse fill:#E8F6F8,stroke:#0891A6,stroke-width:2px,color:#04353D
    classDef legal fill:#F3E8FD,stroke:#6B3FA0,stroke-width:3px,color:#2E1550
    class U,P intake
    class S seal
    class C1,C2 chain
    class A,F,D,M,R analyse
    class CERT legal
```

### Why provenance has no default

A default would mean the system deciding, on an officer's behalf, **what a file is** — and the only safe default makes the feature useless. Three declarations, each printed on the certificate:

```mermaid
graph LR
    SZ["🔴 <b>SEIZED</b><br/>captured from a network<br/>under investigation<br/><i>→ this is evidence</i>"]
    RF["🟠 <b>REFERENCE</b><br/>real traffic from a<br/>published corpus<br/><i>→ real, but not evidence</i>"]
    SY["🔵 <b>SYNTHETIC</b><br/>generated for demonstration<br/><i>→ never presentable</i>"]

    classDef sz fill:#FDECEA,stroke:#B3261E,stroke-width:3px,color:#5C0F0A
    classDef rf fill:#FFF4E5,stroke:#B35C00,stroke-width:2px,color:#3D2200
    classDef sy fill:#EEF2F7,stroke:#4A5568,stroke-width:2px,color:#1A202C
    class SZ sz
    class RF rf
    class SY sy
```

---

## ⛓️ Chain of Custody — Hash-Chained, Not Just Logged

An audit table anyone can `UPDATE` is not a chain of custody. Every custody event carries the hash of the one before it, so **removing or editing any link breaks every link after it**.

```mermaid
graph LR
    G["🌱 GENESIS<br/><code>prev = 0000…</code>"]
    E1["① SEIZED<br/><code>H(genesis + event)</code>"]
    E2["② ANALYSED<br/><code>H(prev + event)</code>"]
    E3["③ CERTIFICATE ISSUED<br/><code>H(prev + event)</code>"]
    E4["④ COUNTERSIGNED<br/><code>H(prev + event)</code>"]
    V{"🔍 verify()"}
    OK["✅ INTACT<br/>every link recomputes"]
    BAD["❌ BROKEN<br/><i>names the exact link</i>"]

    G --> E1 --> E2 --> E3 --> E4 --> V
    V -->|chain recomputes| OK
    V -->|mismatch| BAD

    classDef genesis fill:#EEF2F7,stroke:#4A5568,stroke-width:2px,color:#1A202C
    classDef link fill:#FFF9E6,stroke:#B38600,stroke-width:2px,color:#3D2E00
    classDef good fill:#E6F4EA,stroke:#1B6E3C,stroke-width:3px,color:#0B3D1F
    classDef bad fill:#FDECEA,stroke:#B3261E,stroke-width:3px,color:#5C0F0A
    class G genesis
    class E1,E2,E3,E4,V link
    class OK good
    class BAD bad
```

Tampering is reported as *"the chain breaks at event 3"* — not a silent boolean.

---

## 🎯 Detection Engine

Eleven rules, every one **deterministic and citable**. No black-box score decides whether someone is prosecuted.

```mermaid
flowchart LR
    FLOWS["🌊 Assembled flows"] --> ENGINE{"Detection engine"}

    ENGINE --> BEACON["📡 <b>C2 Beaconing</b><br/>PERIODIC · KEEPALIVE"]
    ENGINE --> TUNNEL["🕳️ <b>Tunnelling</b><br/>DNS long-label · subdomain volume<br/>ICMP oversized"]
    ENGINE --> EXFIL["📤 <b>Exfiltration</b><br/>volume asymmetry"]
    ENGINE --> RECON["🔍 <b>Reconnaissance</b><br/>port scan"]
    ENGINE --> COVERT["🎭 <b>Covert channel</b><br/>unknown service on open port"]
    ENGINE --> IOC["🧾 <b>IOC feed match</b><br/><i>only if a feed was imported</i>"]
    ENGINE --> ANOM["📈 <b>Statistical anomaly</b><br/><i>capped MEDIUM · not a rule</i>"]

    BEACON & TUNNEL & EXFIL & RECON & COVERT & IOC --> CORR["🔗 <b>HOST_CORROBORATED</b><br/><i>same host, multiple independent rules</i>"]
    CORR --> ATT["🗺️ MITRE ATT&amp;CK v19.2"]
    ANOM -.->|never corroborates alone| CORR

    classDef flow fill:#E8F6F8,stroke:#0891A6,stroke-width:2px,color:#04353D
    classDef rule fill:#FFF4E5,stroke:#B35C00,stroke-width:2px,color:#3D2200
    classDef crit fill:#FDECEA,stroke:#B3261E,stroke-width:3px,color:#5C0F0A
    classDef soft fill:#EEF2F7,stroke:#4A5568,stroke-width:1px,color:#1A202C
    class FLOWS,ENGINE,ATT flow
    class BEACON,TUNNEL,EXFIL,RECON,COVERT,IOC rule
    class CORR crit
    class ANOM soft
```

| Rule ID | Detects | Threshold source |
|---|---|---|
| `C2_BEACON_PERIODIC` | Regular callback intervals | Published, with interval statistics shown |
| `C2_BEACON_KEEPALIVE` | Long-lived low-byte channels | Published |
| `DNS_TUNNEL_LONG_LABEL` | Oversized DNS labels | RFC 1035 label limits |
| `DNS_TUNNEL_SUBDOMAIN_VOLUME` | High unique-subdomain counts | Published |
| `ICMP_TUNNEL_OVERSIZED` | ICMP payloads carrying data | Published |
| `EXFIL_VOLUME_ASYMMETRY` | Outbound ≫ inbound | Published + entropy sample count |
| `RECON_PORT_SCAN` | Fan-out across ports | Published |
| `COVERT_CHANNEL_UNKNOWN_PORT` | Unrecognised service on a permitted port | Published |
| `IOC_FEED_MATCH` | Endpoint on an imported feed | Feed's own retrieval date |
| `HOST_CORROBORATED` | One host implicated by **several independent rules** | Derived |
| `ANOMALY_STATISTICAL` | Unsupervised outlier | ⚠️ Cites nothing — capped MEDIUM by design |

> Every threshold is served live at `GET /api/detections/thresholds/` — **35 thresholds**, each tagged as sourced or heuristic. A number an officer cannot decompose is a number they cannot testify to.

---

## 📱 APK Examination — and the part a scanner cannot do

Submitted samples are sealed like any other exhibit, then examined **statically** — never executed, never sent to a cloud scanner.

```mermaid
flowchart TD
    Z["📦 .apk or .zip<br/><i>ZipCrypto / WinZip-AES supported</i>"]
    UZ["🔓 Unwrap one archive layer<br/><i>conventional passwords auto-tried</i>"]
    SEAL["🔒 Seal the file as received<br/><i>the ZIP, not the extracted APK</i>"]
    MAN["📄 AndroidManifest.xml<br/><i>binary AXML parser</i>"]
    RAW["🧬 <b>Byte-level fallback</b><br/>declared compression ignored<br/><i>verified against AXML magic</i>"]
    PERM["🔑 Permission risk model"]
    DEX["🧾 DEX string indicators"]
    CORROB{"Manifest corroborates<br/>the code reference?"}
    SCORE["📊 Additive score<br/><i>every point traceable</i>"]
    FAM["🏷️ 6 behavioural families"]
    NET["🔗 <b>Correlate with sealed captures</b>"]

    Z --> UZ --> SEAL --> MAN
    MAN -->|"unreadable"| RAW --> PERM
    MAN -->|"parsed"| PERM
    PERM --> DEX --> CORROB
    CORROB -->|"yes → scores"| SCORE
    CORROB -->|"no → shown, greyed, 0 pts"| SCORE
    SCORE --> FAM --> NET

    classDef intake fill:#E8F0FE,stroke:#1A73E8,stroke-width:2px,color:#0B2545
    classDef seal fill:#E6F4EA,stroke:#1B6E3C,stroke-width:3px,color:#0B3D1F
    classDef parse fill:#E8F6F8,stroke:#0891A6,stroke-width:2px,color:#04353D
    classDef evade fill:#FDECEA,stroke:#B3261E,stroke-width:3px,color:#5C0F0A
    classDef out fill:#F3E8FD,stroke:#6B3FA0,stroke-width:2px,color:#2E1550
    class Z,UZ intake
    class SEAL seal
    class MAN,PERM,DEX,CORROB,SCORE parse
    class RAW evade
    class FAM,NET out
```

**Six families**, each assigned only when every capability it *mechanically requires* is present — and each returned with the evidence that qualified it:

`Banking trojan / OTP interceptor` · `Stalkerware / covert surveillance` · `SMS fraud / premium-rate abuse` · `Dropper / stager` · `Remote access trojan (RAT)` · `Device-admin abuse / lockout`

### Two design decisions worth reading

**① A DEX string alone proves nothing.** Nearly every APK statically links AndroidX or Flutter, and those libraries *contain* references to `AccessibilityService` and `DevicePolicyManager` whether or not the app calls them. Scoring on the string alone classified a benign alarm clock as stalkerware. So a code reference only scores if the manifest **declares the matching permission** — the library can carry the code; only the app can ask for the capability.

**② An unreadable manifest is a finding, not an absence of one.** If Android installs a package, its manifest is well-formed by the only definition that matters. A manifest the platform reads and every analysis tool refuses is not damaged — it is *built to be unreadable*. Scored as absence of evidence, the most evasive samples would score lowest. It is scored as evasion instead.

### The correlation nobody else can produce

```mermaid
graph LR
    APK["📱 APK embeds<br/><code>cdn-analytics.example</code>"]
    PCAP["📼 Sealed exhibit NF-2026…<br/><code>10.3.14.101</code> resolved it<br/><i>14:22:07 IST</i>"]
    OUT["⚖️ <b>A capability becomes an event</b><br/>with a timestamp and an exhibit number"]
    APK --> OUT
    PCAP --> OUT

    classDef a fill:#F3E8FD,stroke:#6B3FA0,stroke-width:2px,color:#2E1550
    classDef b fill:#E8F6F8,stroke:#0891A6,stroke-width:2px,color:#04353D
    classDef c fill:#E6F4EA,stroke:#1B6E3C,stroke-width:3px,color:#0B3D1F
    class APK a
    class PCAP b
    class OUT c
```

---

## 📜 BSA Section 63 Certificates

Section 63(4) requires **the person in charge of the device and an expert** — two different people. A two-part form that one account can sign twice guarantees nothing.

```mermaid
sequenceDiagram
    autonumber
    participant IO as 👮 Investigating Officer
    participant SYS as 🛡️ NetForensiq
    participant EX as 🔬 FSL Examiner

    IO->>SYS: Issue certificate (Part A)
    SYS->>SYS: Re-verify exhibit hash
    SYS-->>IO: DRAFT — Part B unsigned
    Note over SYS: Same account cannot sign both parts
    EX->>SYS: Countersign Part B
    SYS->>SYS: Check examiner standing<br/>(role, or EXPERT on this case)
    SYS->>SYS: Re-verify hash before attesting
    SYS-->>EX: ✅ COMPLETE — PDF rendered
    Note over SYS: Custody event appended to the chain
```

The renderer reproduces **THE SCHEDULE** to the Act — Part A and Part B — and the custody register prints its signature column **empty**, because a signature this system never witnessed is not one it will print.

---

## ⚡ Performance

Measured on a real **200 MB / 2,274,747-packet** ICS capture (4SICS Geek Lounge):

| Stage | Before | After | Gain |
|---|---:|---:|---:|
| Packet parse + flow assembly | 377.8 s | **34.0 s** | **11.1×** |
| Browser upload → sealed → analysed | 11 m 55 s | **3 m 12 s** | **3.7×** |
| Graph aggregation endpoint (117k flows) | 34.03 s | **1.28 s** | **27×** |

The parse win comes from `capture/fastparse.py`, which reads header fields straight out of the frame with `struct` instead of building a Scapy object per packet.

**Equivalence is tested, not assumed.** `tests_fastparse.py` runs both readers over real captures and requires *identical* flows, DNS records, byte counts and timestamps. It found two genuine defects the fast path would otherwise have introduced:

- One frame in 2,274,747 declared a TCP `dataofs` of 0 — malformed, and the dissector keeps it. Refusing it lost 1 packet, 1 flow and 62 bytes.
- UDP payloads must **not** be clamped to the length field, because the dissector folds trailing bytes into `Padding` and returns them.

---

## 🔌 SIEM & Alerting

```mermaid
graph LR
    F["🎯 New finding"] --> SIEM{"Export"}
    SIEM --> ECS["📘 <b>ECS 8.11</b><br/>ndjson · Elastic"]
    SIEM --> CEF["📕 <b>CEF 0</b><br/>ArcSight lineage"]
    SIEM --> SYS["📗 <b>RFC 5424</b><br/>syslog · RFC 6587 framing"]
    SYS --> WAZ["🐺 <b>Wazuh</b><br/>decoders + rules 100200–100222"]
    F --> WH["🪝 Webhook"]

    classDef src fill:#FDECEA,stroke:#B3261E,stroke-width:2px,color:#5C0F0A
    classDef exp fill:#E8F6F8,stroke:#0891A6,stroke-width:2px,color:#04353D
    classDef sink fill:#E6F4EA,stroke:#1B6E3C,stroke-width:2px,color:#0B3D1F
    class F src
    class SIEM,ECS,CEF,SYS exp
    class WAZ,WH sink
```

`integrations/wazuh/` ships decoders, a ruleset and `sample-events.log` so the pipeline can be proved with `wazuh-logtest` **before** NetForensiq is running. The test suite parses the shipped XML and runs its regex against live `to_syslog` output — a decoder drifted from its emitter installs cleanly, matches nothing, and reports zero alerts, which is indistinguishable from a quiet network.

> **Honest framing:** syslog is a real integration. The webhook and pull API are *export in an ingestible format*. A SOC engineer knows the difference, so the compliance doc states it.

---

## 🏗️ Architecture

```mermaid
graph TB
    subgraph FE["🖥️ React 19 + Vite + MUI"]
        UI["Dashboard · Findings · Evidence<br/>Import · Examine Sample · Approvals"]
        D3["Deterministic D3 topology<br/><i>no force simulation</i>"]
    end
    subgraph API["⚙️ Django 6 + DRF · gunicorn ×3"]
        AUTH["accounts/<br/><i>JWT · roles · audit log</i>"]
        CAP["capture/<br/><i>parse · detect · monitor · APK</i>"]
        EV["evidence/<br/><i>seal · custody · §63 · posture</i>"]
    end
    subgraph DATA["💾 Storage"]
        DB[("SQLite WAL / PostgreSQL")]
        ES["🔒 Evidence store<br/><i>AES-256-GCM at rest</i>"]
    end
    subgraph WIRE["🌐 Capture"]
        PCAP["PCAP / pcapng"]
        LIVE["Live NIC<br/><i>CAP_NET_RAW</i>"]
    end

    UI --> AUTH & CAP & EV
    D3 --> CAP
    PCAP & LIVE --> CAP
    CAP --> DB
    EV --> ES & DB

    classDef fe fill:#E8F0FE,stroke:#1A73E8,stroke-width:2px,color:#0B2545
    classDef api fill:#E8F6F8,stroke:#0891A6,stroke-width:2px,color:#04353D
    classDef data fill:#E6F4EA,stroke:#1B6E3C,stroke-width:2px,color:#0B3D1F
    classDef wire fill:#FFF4E5,stroke:#B35C00,stroke-width:2px,color:#3D2200
    class UI,D3 fe
    class AUTH,CAP,EV api
    class DB,ES data
    class PCAP,LIVE wire
```

**Why the topology graph is deterministic:** a force simulation draws the same capture differently every time it runs. Reproducibility is an evidence property, so the layout is a two-column ledger — inside the monitored network on the left, outside on the right, arrowheads pointing at whoever answered.

---

## ✈️ Air-Gapped by Construction

The running container needs **no network**. Verified under `--network none`: a socket to `1.1.1.1` fails with *Network is unreachable*, and the platform still seals a capture, analyses it and issues a §63 certificate.

- 🚫 No cloud scanner, no VirusTotal, no telemetry
- 🔑 Raw-socket capability baked into the image, not applied by hand
- 📦 `scripts/save_airgap_images.sh` / `load_airgap_images.sh` for transfer
- 🗄️ SQLite WAL + 30 s busy timeout, so long analyses don't lock out sign-in

<sub>Building requires a network. The build happens on a connected machine and the image is carried across.</sub>

---

## 🧪 Tests

```bash
docker exec netforensiq python manage.py test    # 447 backend tests
cd frontend && npx playwright test               # Playwright E2E
```

<div align="center">

**`Ran 447 tests — OK`**

</div>

The tests that earned their keep:

| Test | Defect it caught |
|---|---|
| `tests_wazuh.py` | Shipped XML was **malformed** — `--` inside a comment. Wazuh would have loaded nothing, silently. |
| `tests_fastparse.py` | Two byte-level divergences between the fast and reference parsers. |
| `HomeNetIsDescribedAsApplied` | Graph caption described the deployment default while classification used a `/32`. |
| `tests_monitor.py` | Module-level state broke under 3 gunicorn workers — `start` and `status` hit different processes. |

---

## 📁 Layout

```
NetForensiq/
├── backend/
│   ├── accounts/          Auth · roles · audit log · sign-in log · approvals
│   ├── capture/
│   │   ├── fastparse.py     struct-based frame reader (11× faster)
│   │   ├── processor.py     flow assembly · TLS/DNS/HTTP decode
│   │   ├── detection.py     11 rules + published threshold registry
│   │   ├── apk.py           AXML parser · risk model · family classifier
│   │   ├── monitor.py       DB-backed live monitor (multi-worker safe)
│   │   ├── siem.py          ECS · CEF · RFC 5424
│   │   ├── ioc.py           threat-feed import & matching
│   │   └── scenario.py      ATT&CK-ordered attack reconstruction
│   └── evidence/
│       ├── service.py       seal · custody · verify · §63 signing
│       ├── certificate_pdf.py   renders THE SCHEDULE, Parts A & B
│       ├── crypto.py        AES-256-GCM at rest
│       └── posture.py       statutory compliance posture
├── frontend/src/pages/    Dashboard · Detections · Evidence · Import · Sample
├── integrations/wazuh/    decoders · rules · sample events
├── research/              legal, technical and literature research
└── scripts/               verification · offline bundle · air-gap transfer
```

---

## ⚠️ Honest Limitations

This project was built for a hackathon and it is **not finished**. Stated plainly, because a forensics tool that oversells itself is worse than none:

- **The APK classifier produces false positives.** A Play Store application has scored far higher than it should. The permission and DEX weights need real calibration against a labelled corpus.
- **Static analysis only.** No detonation, no decompilation, no emulation. It reads the manifest, the certificate and DEX strings — nothing more is claimed.
- **Ten of the fourteen ATT&CK tactics cannot be evidenced from network capture at all**, and `scenario.py` names them rather than quietly leaving them out.
- **`ANOMALY_STATISTICAL` cites no threshold.** It is capped at MEDIUM and always ships the features that made a flow stand out.
- **JA4+ variants (JA4S/JA4H/JA4T…) are not shipped** — FoxIO License 1.1 makes them non-commercial. Only core JA4 (BSD-3-Clause) is used.
- **CERT-In's 6-hour rule is a reporting deadline, not a detection mandate**, and is deliberately *not* cited as justification for real-time alerting.

---

## 📄 License

Built for KANAD S.H.I.E.L.D. 2026. Licensing terms to be determined.

<div align="center">
<sub>Reference captures from Netresec, malware-traffic-analysis.net and WRCCDC are used under their published terms and are marked <b>REFERENCE</b> — real traffic, never evidence.</sub>
</div>
