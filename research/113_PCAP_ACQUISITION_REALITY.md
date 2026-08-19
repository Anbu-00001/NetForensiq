# 113 — PCAP Acquisition Reality: Answering "Where Does the PCAP Come From?"

> **Compiled:** 19 Aug 2026. Research only — no code touched. Answers a specific reviewer
> critique of NetForensiq: *"the application depends on a pcap file — without one it is just a
> scanner and a certificate generator. How does a police station actually GET a pcap? How is
> this useful in an air-gapped room where it cannot see live traffic? Could we bridge it to
> capture from a phone?"*
>
> Cross-referenced against this project's own prior legal research
> ([PS_03_LEGAL_AND_DATA_REALITY.md](PS_03_LEGAL_AND_DATA_REALITY.md),
> [SPEC_01_EVIDENCE_INTEGRITY.md](SPEC_01_EVIDENCE_INTEGRITY.md)) so section numbers stay
> consistent across the research folder rather than introducing a second, possibly-conflicting
> set of citations. Where this file needed a number PS_03 hadn't already verified, that is
> flagged `⚠️ UNVERIFIED` rather than asserted.
>
> Also cross-referenced against the actual backend code (`backend/capture/`), because two of
> the reviewer's implied gaps — a live-capture mode, and TLS metadata fingerprinting — turned
> out to already be built, not merely proposed. That materially changes the honest answer.

---

## Verdict

**"It depends on a pcap" is a fair limitation stated in an unfair frame, and about a third of it
is simply factually wrong about the current codebase.** A pcap-analysis tool is not "just a
scanner and a certificate generator" any more than a fingerprint-matching system is "just a
database lookup" — the pcap is the evidentiary artefact, exactly as a seized hard drive is the
artefact for disk forensics or a blood sample is the artefact for a DNA lab. No forensic
analysis tool acquires its own evidence; EnCase does not raid premises, Cellebrite UFED does not
serve the production summons that gets it a phone. Acquisition and analysis are different
functions with different legal authorities in every real forensic regime (SWGDE, NIST SP
800-86, ACPO — see §4), and conflating them is the actual misunderstanding, not the tool's
architecture.

That said, three things ARE fair criticism and are addressed honestly below rather than
argued away:

1. **The demo currently only shows the "receive a pcap and analyse it" half of the story.**
   The acquisition half — where a real station would source one — is not narrated anywhere in
   the pitch. That is a presentation gap, not an architecture gap (see §6 for what to add).
2. **The product already has a live-capture mode** (`backend/capture/management/commands/capture_live.py`,
   `CaptureSession.Source.LIVE` in `backend/capture/models.py`) that answers "can it see live
   traffic" with "yes, on whichever machine you run it on" — but this is not exposed in the web
   UI or mentioned in any pitch material found in this repo, so the reviewer's question is
   understandable: from the outside, the product looks upload-only.
3. **A phone-capture bridge is real and is a 2-day-achievable demo** (PCAPdroid, no root, no
   Mac needed) but nobody has built or rehearsed it yet. It is the single highest-value,
   lowest-effort addition identified in this research (§6, item 1).

The honest one-line answer to the reviewer: *"A pcap in a real investigation comes from a
lawful production order to an ISP/enterprise, a seized device's own capture, a malware sandbox,
or — yes — a phone we can bridge live; our tool's job starts the moment one lawfully exists, the
same division of labour every acquisition/analysis pair in forensics uses, and we can show you
the phone-bridge live in under two minutes."*

---

## 1. How network evidence is actually acquired in law enforcement

Real investigative pcaps come from one of six places. None of them is "the investigating
officer runs Wireshark on the internet backbone" — that specific fantasy is what the reviewer
is (correctly) pushing back on, and it's worth being explicit that nobody is claiming it.

### 1.1 ISP / telecom lawful-interception handoff — the "live content" route

This is the most tightly gated route and the one most often confused with the others.

- **Legal basis (content interception):** Historically **Section 5(2), Indian Telegraph Act,
  1885** with procedure under **Rule 419A, Indian Telegraph (Amendment) Rules, 2007** — orders
  issued by the Union/State Home Secretary, valid up to 60 days and renewable to a 180-day
  ceiling, reviewed by a Central/State Review Committee.
  ([Telegraph Act interception overview — SupremeToday](https://supremetoday.ai/issue/telephonic-interception-under-indian-telegraph-act);
  [Rule 419A — CIS India](https://cis-india.org/internet-governance/resources/rule-419-a-indian-telegraph-rules-1951))
  This project's own PS_03 (§B.12) has already established that this framework has been
  **replaced by Section 20 of the Telecommunications Act, 2023** — same public-emergency/
  public-safety/national-security gating, new Central/State Review Committees, and a
  post-hoc power to order destruction of copies that don't meet the statutory conditions.
- **Legal basis (electronic information broadly, i.e. non-telecom computer resources):**
  **Section 69, Information Technology Act, 2000** (interception/monitoring/decryption "in the
  interest of" sovereignty, security, friendly relations, public order, or prevention/
  investigation of an offence), procedure under the **IT (Procedure and Safeguards for
  Interception, Monitoring and Decryption of Information) Rules, 2009** — orders by a Home
  Secretary-level authority at Centre/State, IG-level at state field level, with 3-day/7-day
  approval clocks and 180-day destruction of records.
  ([Section 69 — Indian Kanoon](https://indiankanoon.org/doc/1439440/);
  [Interception Rules 2009 — CIS India](https://cis-india.org/internet-governance/resources/it-procedure-and-safeguards-for-interception-monitoring-and-decryption-of-information-rules-2009))
- **Section 69B, IT Act, 2000** — a separate power to **monitor and collect traffic data** (not
  content) from any computer resource, for cyber security purposes. Confirmed to exist and be
  live post-BNSS (PS_03 §B.9). ⚠️ **UNVERIFIED in this pass**: the exact title/number of the
  distinct procedural rules implementing §69B specifically (as opposed to the §69 Interception
  Rules 2009, which govern §69 not §69B) was not independently confirmed against a primary
  source in this research session — flag before citing a specific rules title for §69B.
- **What actually gets handed over:** the output at the LEA-facing interfaces is standardised
  as **HI2 (Intercept Related Information — signalling: numbers, IP/MAC, timing, duration)** and
  **HI3 (Call Content)**, per the DoT/TEC Lawful Interception System framework — this is *not*
  a generic pcap dump of a backbone link; it's a mediated, per-target feed keyed to a specific
  interception order.
  ([TEC LIS study paper](https://tec.gov.in/public/pdf/Studypaper/Final%20Approved%20LIS%20Study%20paper%20aug%202015.pdf))
- **Bottom line for a hackathon tool:** this route produces a pcap-shaped or RTP-shaped
  artefact **only after** an interception order exists and only for the targeted subscriber —
  it is not a bulk-traffic source and a police-station-level tool cannot self-serve it. It is
  the correct answer to "how would call content ever end up as a pcap," but it is a slow,
  high-authority path, not a routine one.

### 1.2 Production summons to a victim/enterprise organisation — the routine route

The overwhelmingly common real-world path for a *station-level* investigation is not
interception at all — it's asking the entity that already has the logs.

- **Legal basis:** **Section 94, Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023** (replacing
  CrPC Section 91) — a court or investigating-officer summons to produce "any document or thing"
  including, per BNSS's explicit modernisation, electronic communications and communication
  devices. Already fully documented with primary-source detail in this project's
  [PS_03_LEGAL_AND_DATA_REALITY.md §A](PS_03_LEGAL_AND_DATA_REALITY.md), which this file defers
  to rather than re-deriving.
  ([Section 94 BNSS explained — ILMS Academy](https://www.ilms.academy/blog/section-91-crpc-section-94-bnss-explained-scope-validity-judicial-interpretation))
- **What is realistically obtainable this way:** an enterprise victim's own SIEM/firewall
  export, NetFlow, or **an actual pcap** if the victim organisation runs a network TAP or IDS
  that stores raw captures (many SOC-equipped enterprises, banks, and data centres do, precisely
  because CERT-In requires it — see below). This is the single most realistic "how does a real
  pcap end up on an investigator's desk" answer for a cybercrime-branch case: **the victim
  organisation already had a TAP/SPAN capture running for its own security monitoring, and
  the police obtain a copy of it under a §94 BNSS summons.**
- **CERT-In 2022 Directions** independently make this more likely to exist: issued
  **28 April 2022 under Section 70B(6), IT Act 2000**, they mandate all "service providers,
  intermediaries, data centres, body corporate and Government organisations" to **enable and
  securely retain logs of all ICT systems for a rolling 180 days, stored within Indian
  jurisdiction**, and to furnish them to CERT-In (and, by extension, to law enforcement acting
  under §94 BNSS) on request. Non-compliance carries penalties up to ₹1 lakh / 1 year under
  §70B(7). This is exactly the "an org was already logging, so a pcap-shaped artefact exists to
  be summoned" mechanism.
  ([Lexology overview](https://www.lexology.com/library/detail.aspx?g=899f3b94-c31f-4983-868f-5ee5abbf78c8);
  [CERT-In Directions PDF, primary source](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf))
  — note the Directions mandate **logs**, not necessarily full packet captures; whether a given
  organisation's compliance takes the form of raw pcap, flow logs, or application logs is
  organisation-specific and should not be overclaimed as "every CERT-In-compliant org has a
  180-day pcap archive." Most will have flow/application logs; a minority (banks, larger SOCs)
  will have raw captures.

### 1.3 ISP session metadata — IPDR (not content, and not literally a pcap, but close cousin)

- DoT mandated ISPs to retain **Internet Protocol Detail Records (IPDR)** — source/destination
  IP:port, timestamps, session duration, data volume, APN — with retention **revised to 2
  years** per a December 2021 DoT circular. This is metadata-only, not packet content, but it
  is genuinely useful for correlating a suspect's known session window against a pcap's
  timestamps, and is exactly what real cybercrime cells (e.g., Delhi Police's August 2026 IPDR
  SOP) use for tracing internet activity.
  ([Innefu Labs IPDR guide](https://innefu.com/the-complete-guide-to-ipdr-internet-protocol-detail-records/);
  [Delhi Police IPDR SOP — MediaNama](https://www.medianama.com/2026/08/223-delhi-police-guidelines-internet-activity-ipdr/))
  This is already documented in more depth in this project's PS_03 §A.2, including the CGNAT
  caveat (IPDR is nearly useless without the private-IP↔public-IP:port NAT mapping logged
  alongside it).

### 1.4 Seized devices

A seized computer, router, or NAS may already hold pcap files, browser/app caches, or router
NAT/connection-tracking logs (`conntrack`, DHCP leases, syslog). Extraction is standard digital
forensics (imaging + write-blocking, see §5), not network capture — the pcap, if any exists on
the device, is simply a file to recover, hash, and ingest.

### 1.5 Honeypots

An organisation (including a police cyber cell) operating a **honeypot** on infrastructure it
owns can lawfully capture everything that touches it, under ordinary computer-owner rights —
no India-specific honeypot statute was found in this research, and none appears necessary
because the honeypot operator is the network owner, not an interceptor of someone else's
traffic. Common honeypot platforms (T-Pot, Cowrie) natively emit pcap. This is a legitimate,
low-friction pcap source for a demo dataset or for a genuine "police-operated bait
infrastructure" capability, but it only ever captures attackers who touch the honeypot — it is
not a general evidence-acquisition mechanism.

### 1.6 Malware sandbox detonation

Automated malware-analysis sandboxes (Cuckoo Sandbox and its actively-maintained fork **CAPE**)
execute a suspicious binary in an isolated VM and record **all its network activity as a pcap**
— DNS, HTTP/HTTPS, C2 callbacks — downloadable directly from the sandbox run.
([Cuckoo Sandbox overview](https://cuckoosandbox.org/); malware-detonation pcap workflow
summarised across multiple sources in the search above)
This is a genuinely strong, low-friction, entirely-lawful pcap source for a hackathon demo: **a
seized malware sample recovered from a device, detonated in a sandbox, pcap ingested into
NetForensiq** is a complete, realistic, self-contained investigative story that needs no
external network access and no consent questions at all.

---

## 2. Capturing traffic from a mobile phone — what is actually possible

This is the reviewer's specific question, and the honest answer is: **yes, on Android, cheaply,
without root, and it should be demoed live; on iOS it's real but needs a Mac and is not worth
building for a 2-day hackathon.**

### 2.1 Android — no root required

- **PCAPdroid** (open source, GPLv3) — `github.com/emanuele-f/PCAPdroid`. Uses Android's
  `VpnService` API to route the device's own traffic through a **local, on-device loopback
  "VPN"** (nothing leaves the phone to an external server; the app simulates a VPN purely to get
  OS-level packet visibility). Exports standard **.pcap**, extracts SNI/DNS/HTTP URLs per
  connection, and can decrypt HTTPS **only for apps that trust a user-added CA certificate** —
  i.e. it does not defeat certificate pinning (see §2.3).
  ([GitHub](https://github.com/emanuele-f/PCAPdroid); [F-Droid listing](https://f-droid.org/en/packages/com.emanuelef.remote_capture/);
  [Quick start docs](https://emanuele-f.github.io/PCAPdroid/quick_start.html))
- **tPacketCapture** — same `VpnService` technique, no root, exports .pcap for later analysis
  in Wireshark, has a paid "Pro" per-app filter.
  ([Taosoftware product page](https://www.taosoftware.co.jp/en/android/packetcapture/))
- **Practical demo workflow (achievable inside a 2-day hackathon):** install PCAPdroid on any
  Android phone/emulator from F-Droid, tap Start, generate some traffic (browse, open a
  messaging app), tap Stop, export the .pcap, transfer it (USB/email/ADB pull) to the NetForensiq
  ingest endpoint. This is a genuine live phone→pcap→analysis pipeline and costs essentially
  nothing to rehearse.

### 2.2 iOS — needs a Mac, no jailbreak required

- **rvictl (Remote Virtual Interface Tool)** — ships with Xcode at
  `/Library/Apple/usr/bin/rvictl`. Pair the iPhone to a Mac, get its UDID, run
  `rvictl -s <UDID>` to create a virtual `rvi0` network interface that mirrors the device's
  traffic, then capture on `rvi0` in Wireshark exactly like any other interface. Requires a
  device reboot the first time (to load the `rpmuxd` daemon) and a Lightning/USB-C cable —
  it is not wireless.
  ([Tutorial — Medium/d3adw0k](https://medium.com/meetcyber/wireshark-packet-capture-on-ios-using-rvictl-2ac93c31c6fd);
  [gh2o/rvi_capture — Linux/Windows port](https://github.com/gh2o/rvi_capture))
- This gives full packet-level visibility (headers + encrypted payloads) exactly like any wired
  capture — same TLS limitation as everywhere else (§2.3). A Linux/Windows reimplementation
  (`rvi_capture`) exists for teams without a Mac, but is less battle-tested.
- **iOS `sysdiagnose`** is **not** a packet-capture mechanism — it's a system diagnostics log
  bundle (crash logs, some network state snapshots). Do not describe it as equivalent to a
  pcap; it was named in the research brief but does not actually produce network packet data in
  a usable pcap sense. Correcting this expectation here rather than silently omitting it.

### 2.3 What TLS does to any of this — the load-bearing technical honesty point

On an un-instrumented phone (no root/jailbreak, no user-trusted MITM certificate), a capture —
by PCAPdroid, tPacketCapture, or rvictl — gives you:

- **TLS ClientHello metadata**: negotiated version, cipher suites, extensions, ALPN, and
  crucially **SNI** (the plaintext hostname the client is connecting to — still unencrypted in
  the overwhelming majority of TLS 1.3 deployments as of 2026, since Encrypted Client Hello
  adoption remains partial).
- **JA4 fingerprinting** of the TLS client — this project's codebase already implements this
  (`backend/capture/tls_fingerprint.py`), correctly using JA4 rather than the retired JA3 (JA3
  stopped reliably identifying clients once Chrome 110+ began randomising ClientHello extension
  order). JA4 sorts before hashing specifically to survive that.
  ([JA4 technical spec — FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4);
  [Salesforce JA3 origin/retirement context](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/))
- **Connection metadata**: source/destination IP:port, timing, packet sizes, flow duration,
  data volume.
- **DNS queries** (if not using DoH/DoT — increasingly these ARE encrypted on modern phones,
  which narrows this further).
- **NOT the decrypted application content** of any TLS 1.2+/1.3 connection — that requires the
  device to trust an interception certificate the operator installs, AND the target app to not
  pin its own certificate. WhatsApp, Signal, most banking apps, and increasingly most
  security-conscious apps pin certificates specifically to defeat this. Traffic-pattern research
  (packet-size/timing fingerprinting of Signal and WhatsApp Web) can infer *activity type*
  (chat vs. voice call vs. video call vs. idle) from metadata alone without decryption, but this
  is a research technique, not a shipped, court-ready capability, and should not be presented as
  one.
  ([Signal traffic-pattern study — MDPI](https://www.mdpi.com/2076-3417/11/17/7789);
  [WhatsApp Web signature-identification study — ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0141933123000029))

### 2.4 Rooted/jailbroken options — real, but not a police-field capability

On a **rooted** Android device or **jailbroken** iPhone: `tcpdump` can run directly on-device
(full raw capture, no VpnService indirection), and **Frida** + **objection**/`frida-interception-and-unpinning`
can dynamically patch an app's TLS-pinning checks at runtime so a **mitmproxy** MITM certificate
is accepted, exposing decrypted HTTPS content.
([Frida SSL-pinning bypass guide](https://approov.io/blog/how-to-bypass-certificate-pinning-with-frida-on-an-android-app);
[httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning))
This is genuine, working technique — but it requires (a) root/jailbreak, which most suspect
devices won't have and rooting them yourself is itself an evidence-altering act; (b) per-app,
per-version engineering effort that breaks on app updates; and (c) running attacker-style
dynamic instrumentation against evidence, which cuts directly against forensic
non-alteration principle (§4). It belongs in a controlled malware-analysis/red-team context
(e.g., a devices the department owns for testing), never presented as something a police
officer would do to a seized suspect phone.

### 2.5 Legal position in India for capturing FROM a phone

There is a sharp, underexplored distinction the reviewer's question glosses over, and it matters:

- **A victim's own phone, with the victim's consent**: legally straightforward. This is
  routine in cybercrime-branch practice already — victims are asked to preserve/submit
  screenshots and screen recordings as evidence under IT Act/BNS provisions
  ([ApniLaw — screen recording as evidence](https://www.apnilaw.com/uncategorized/is-screen-recording-legal-evidence-in-cybercrime-cases-in-india/)).
  Asking a scam victim to install PCAPdroid and capture the next contact from a fraudster is a
  natural, low-friction extension of that existing practice — no warrant, no production order,
  just informed consent, exactly like asking them to hand over a screenshot.
- **A suspect's seized device**: this is where the naive "just install a capture app and let it
  run" idea breaks down. BNSS's seizure framework (**Section 105**, mandatory audio-video
  recording of the search/seizure act itself, per this project's PS_03 §B.2) and the
  internationally-standard **ACPO Principle 1** ("no action... should change data held on a
  digital device... that may subsequently be relied upon as evidence") both point the same
  direction: **installing, running, or configuring anything on a seized device — a VPN profile,
  a capture app, a trusted root CA — actively modifies and executes code on the evidence.** That
  is precisely the class of action forensic doctrine tells you not to take. Indian law
  enforcement's actual practice on seized phones is **static extraction** (Cellebrite UFED and
  equivalents, imaging the device without powering it onto a live network) — not live network
  capture.
  ([Indian police use of Cellebrite/UFED — MediaNama](https://www.medianama.com/2022/03/223-how-indian-law-enforcement-uses-phone-cracking-tools-2/))
  A phone-capture bridge is therefore honestly pitched as: **acquisition tool for a
  consenting victim/informant's own device, or for a department-owned test/demo device — not
  a technique to run against a seized suspect device.**

---

## 3. What metadata is genuinely extractable from a pcap

### 3.1 "Can we get call records / CDR-equivalent data from a pcap?" — No, plainly.

**No.** A Call Detail Record is produced by the telecom operator's own switching/billing
infrastructure and lives entirely inside the telecom's systems — it is never observable on a
network link a third party could capture, because it's generated *after* the call, from
internal signalling and billing state, not by inspecting packets in flight. There is no
technique, however clever, that derives a real CDR from a pcap. This project's own PS_03 already
states this distinction precisely and should be the canonical framing: CDR/IPDR come from the
telecom operator under a §94 BNSS summons; a pcap comes from wherever traffic was actually
captured. They are different artefact classes from different custodians, full stop.
([CDR definition and scope — Wikipedia](https://en.wikipedia.org/wiki/Call_detail_record))

### 3.2 What a pcap CAN genuinely give you

| Signal | Real? | Notes |
|---|---|---|
| VoIP/SIP call signalling (who/when/duration) | **Yes, if SIP runs unencrypted** | Common on legacy PBX/enterprise trunks; consumer apps (WhatsApp calls) do not use SIP and are not exposed this way. |
| RTP audio stream reconstruction/playback | **Yes, if RTP is unencrypted (no SRTP)** | Wireshark's **Telephony → VoIP Calls** menu follows SIP dialogs (INVITE/RINGING/OK/BYE) and can play back supported codecs (G.711 etc). |
| DNS queries | **Yes** | Unless the device uses DoH/DoT, increasingly common. |
| TLS SNI | **Yes, usually** | Plaintext hostname in ClientHello; narrows with Encrypted Client Hello adoption. |
| HTTP Host headers / URLs | **Yes, only for cleartext HTTP** | Rare now; most traffic is HTTPS. |
| JA4 TLS client fingerprint | **Yes — already implemented in this codebase** | `backend/capture/tls_fingerprint.py`. |
| DHCP hostnames | **Yes** | Devices often broadcast a human-chosen name ("Anbus-iPhone") in the DHCP request — a real, well-known identity leak. |
| mDNS/Bonjour device/service names | **Yes** | AirPlay/HomeKit/printer/NAS advertisements carry device names in cleartext multicast. |
| User-Agent strings | **Only for cleartext HTTP** | Not visible over HTTPS without decryption. |
| WhatsApp/Signal/Telegram content | **No** | End-to-end encrypted; only connection metadata and coarse activity-type inference from traffic patterns (§2.3) is possible, and that is a research technique, not a reliable operational one. |
| Call content generally | **No, unless RTP is unencrypted** | Modern VoIP overwhelmingly uses SRTP or a proprietary encrypted media path. |

### 3.3 Is call-detail reconstruction from SIP/RTP a real technique? Yes — with caveats on the tools

- **Wireshark → Telephony → VoIP Calls** is a real, built-in feature: it groups SIP dialogs into
  calls, shows a flow-sequence diagram of the signalling handshake, and can play back the
  audio for supported codecs.
  ([OneUptime SIP/VoIP Wireshark guide](https://oneuptime.com/blog/post/2026-03-20-analyze-sip-voip-wireshark/view))
- **rtpbreak** is a genuine, purpose-built RTP-session detector/reconstructor: it does not need
  RTCP and works independent of the signalling protocol used (SIP, H.323, SCCP), emitting output
  files consumable by Wireshark/tshark/sox for playback or further processing. This is the
  correct tool to cite for "reconstruct the call from raw RTP even if you don't have clean SIP."
- **SIPp is not a reconstruction tool** — it is a **SIP traffic *generator*/load-tester**, used
  to script and replay SIP/RTP call scenarios for performance testing. Its genuine forensic
  relevance is the reverse of what a casual read of the tool name suggests: it's excellent for
  **synthesising realistic SIP+RTP demo pcaps** to test a call-reconstruction feature against,
  not for reconstructing calls from captured evidence. Citing it as a reconstruction tool would
  be a factual error; flagging that correction here.
  ([SIPp+Wireshark for RTP extraction, Asterisk docs](https://www.asterisk.org/debugging-rtp-with-sipp-and-wireshark/))

---

## 4. Live capture vs. air-gapped analysis — how real forensic shops reconcile this

Yes, this is completely standard, not a contradiction the reviewer should hold against the
architecture — it is in fact the textbook pattern, and (see the note below) this project's own
codebase already implements exactly this split.

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response*,
  formalises a four-stage process — **Collection → Examination → Analysis → Reporting** —
  explicitly treating network traffic as one of its named data-source categories, collected
  under procedures that preserve integrity, then examined/analysed separately.
  ([NIST SP 800-86, primary source PDF](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf))
- **ACPO Good Practice Guide for Computer-Based Electronic Evidence** (UK, widely referenced
  internationally including in Indian digital-forensics training material) states **Principle
  1**: no action should change data on a device that may later be relied on as evidence — the
  entire justification for doing capture on one machine (exposed to the network, disposable in
  evidentiary terms once the pcap is hashed off it) and analysis on a separate, isolated machine
  (never touches the network under investigation, so it cannot alter or leak the evidence, and
  its own integrity is easier to defend in court).
  ([ACPO guide, primary text mirror](https://cryptome.org/acpo-guide.htm))
- **SWGDE Best Practices for Computer Forensic Acquisitions** likewise separates acquisition
  (done in a "safe and controlled environment," hashed at the point of collection) from
  examination, and explicitly calls out network traffic logging via "packet analyzers, packet
  sniffers, or web proxies" as a distinct collection activity from the analysis that follows.
  ([SWGDE 17-F-002, NIST OSAC listing](https://www.nist.gov/osac/standards-library/swgde-17-f-002-20))
- **The standard mechanism for getting the pcap from the capture point to the isolated analysis
  machine is literally "sneakernet"** — copying via removable media by hand — which is the
  accepted, named term of art in air-gapped forensic lab design, not an improvised workaround.
  ([Air-gapped forensic lab discussion — ForensicFocus](https://www.forensicfocus.com/forums/general/forensic-lab-connected-to-internet/))

**This project already has both halves of this pattern built, not just theorised:**
`backend/capture/management/commands/capture_live.py` runs on a network-attached machine and
produces a hashed `CaptureSession` (source type `live`), and separately, the
[101_AIRGAP_AUDIT.md](101_AIRGAP_AUDIT.md) research documents an already-shipped **offline
installer bundle** designed specifically to run the analysis stack on a machine with no network
access at all. The reviewer's implicit worry — "surely a tool architected around air-gapped
analysis can never see live traffic" — describes a real, common failure mode in other tools, but
not this one: the two-machine pattern is already the shape of the code, it's just never been
narrated to a reviewer as the deliberate SOP match it is.

**One more real, citable technical detail for how the capture machine itself should be wired
into a real network (not just the phone case)**: a genuinely forensic-grade capture is taken
from a **network TAP**, not a switch's SPAN/mirror port. This is not a pedantic distinction —
SPAN ports can silently drop packets under load and their output is not treated as reliably
complete, whereas dedicated TAP hardware forwards every bit at line rate and is the
evidentially-preferred source for anything that will end up in court.
([TAP vs SPAN, evidentiary framing](https://www.niagaranetworks.com/solutions/tap-versus-span))

---

## 5. Verifying a pcap's integrity — realistic without a full PKI

- **Hash at capture, immediately.** SHA-256 (and optionally MD5, since it's still a checkbox
  option in the relevant certificate schedule — see below) computed the moment the file is
  written, before it moves anywhere. This is already the design in
  [SPEC_01_EVIDENCE_INTEGRITY.md](SPEC_01_EVIDENCE_INTEGRITY.md) for this project, tied to the
  **Bharatiya Sakshya Adhiniyam (BSA) 2023, Section 63** certificate — that document's own close
  reading is worth restating here since it's a genuinely subtle point: **the word "hash" appears
  only in the certificate's prescribed Schedule form, not in the operative admissibility
  sub-sections of §63 itself.** Hashing is how you *attest* integrity on the certificate, not a
  separately-named statutory admissibility test — practically the same outcome, but the correct
  legal framing.
- **Write-blockers** are a storage-media concept — they matter when a machine holding
  already-captured pcap files is seized and imaged (protecting the source disk from
  modification during that imaging), not to a live network capture in progress, which has no
  "source media" to write-block in that sense.
  ([Write-blocker fundamentals](https://medium.com/@aasthathakker/write-blockers-47f3618f80fb))
- **WORM media / dual-hash** — burning the hashed pcap to a WORM-class medium (or a
  write-once storage tier) after capture is a realistic, low-tech way to get tamper-evidence
  without any PKI at all: a second hash computed independently at the analysis end either
  matches the capture-end hash or it doesn't.
- **RFC 3161 timestamping** is real and realistic to add without standing up your own PKI: a
  client submits a **hash** (not the file itself) to a Time-Stamp Authority, which returns a
  signed token binding that hash to a moment in time. Public/free TSAs exist (e.g., FreeTSA.org)
  specifically so a project doesn't need to operate its own CA to get a legally-recognised
  timestamp token bound to an evidence hash.
  ([RFC 3161 mechanics](https://www.metaspike.com/trusted-timestamping-rfc-3161-digital-forensics/))
  — but per the SPEC_01 finding above, **BSA §63 does not actually require RFC 3161
  timestamping**; it is a genuinely useful courtroom-readiness enhancement, not a compliance
  gap. Don't claim it's legally mandated; it isn't, per this project's own prior reading of the
  statute.
- **Signed capture appliances** (commercial network-forensics appliances that sign captures at
  the hardware level) exist in the enterprise market but are out of reach for a hackathon build
  and not necessary — a hash-at-capture + optional public-TSA-timestamp combination gets
  functionally the same tamper-evidence property without needing that hardware.

---

## 6. Acquisition-route reality table

| Acquisition route | Who can do it | Legal basis in India | Realistic for our demo? | Effort |
|---|---|---|---|---|
| Phone capture via PCAPdroid/tPacketCapture (Android, no root) | Anyone with the device (consenting victim, or dept-owned test phone) | Consent-based; no warrant needed for a consenting party's own device | **Yes — build and rehearse this** | Low |
| iOS capture via rvictl | Team member with a Mac + Xcode | Same consent basis as above | Possible, but needs a Mac and a cable; awkward on a live demo stage | Medium |
| Live capture on a 2nd (network-attached) machine, transferred sneakernet to the air-gapped analysis box | The team, using the already-built `capture_live.py` | N/A — this is the team's own test network, not evidence acquisition from a third party | **Yes — already coded, just needs UI exposure + a rehearsed 2-machine demo** | Low (mostly packaging, not new capability) |
| Victim's screen recording / own-device pcap submitted with a complaint | The victim, voluntarily | Ordinary evidentiary submission alongside IT Act/BNS complaint provisions | Yes, as a narrated scenario | Low (no new code — it's the same ingest path) |
| Malware sandbox detonation (Cuckoo/CAPE) of a recovered sample | Analyst, on a machine they own | No special authority needed — it's the analyst's own sandbox VM | Yes — clean, self-contained, no consent questions | Medium (stand up a sandbox, or pre-record one run) |
| Honeypot capture | Police cyber cell, on infrastructure it owns | Ordinary computer-owner rights; no India-specific honeypot statute identified | Plausible as a described capability; not worth building live | Medium |
| Victim organisation's existing TAP/SPAN/SIEM export, obtained via summons | Investigating officer | **Section 94, BNSS 2023** production summons | Realistic to *narrate*, not to demo live (no real org to summon) | N/A — narrative only |
| ISP IPDR (session metadata, not pcap) | Investigating officer | §94 BNSS summons; DoT 2-year retention mandate | Narrative-only; correlate against a demo pcap's timestamps to show the *concept* | Low, if only illustrating the correlation idea |
| Lawful interception (live content) | Only the authorised agency/TSP under an interception order | Telecommunications Act 2023 §20 (content); IT Act §69/§69B (electronic info/traffic data) | **No — do not attempt to demo or imply this** | N/A |
| Seized device static extraction (Cellebrite/UFED) | Trained forensic examiner | BNSS search/seizure provisions (§105 etc.); standard mobile-forensics practice | Out of scope — this is a different tool category entirely, feeding *files* (not live capture) into the same evidence pipeline | N/A |

---

## 7. Things we could truthfully add — ranked by value/effort

1. **A rehearsed phone-capture demo (PCAPdroid → export → ingest).** Highest value, lowest
   effort. Directly answers the reviewer's exact question, live, in under two minutes, using an
   already-existing open-source Android app and the product's existing pcap-ingest path. No new
   backend code required — this is a demo-script and README addition, not an engineering task.
2. **Expose the existing live-capture mode in the web UI and narrate it as the "capture
   station."** The capability (`capture_live.py`, `CaptureSession.Source.LIVE`) already exists;
   it is currently a management command, invisible to a reviewer looking at the product surface.
   Packaging it as a visible "Live Capture" screen, paired with the already-built air-gapped
   analysis bundle, turns the two-machine SOP pattern from an invisible implementation detail
   into the headline answer to "how does this work in an air-gapped room." Low-medium effort
   because the hard part (the capture pipeline itself) is done.
3. **DHCP hostname / mDNS device-name extraction into flow records.** Real forensic value
   (device attribution — "Anbus-iPhone" connected from this MAC at this time) and low
   incremental effort given the packet-parsing infrastructure (`home_net.py`, `features.py`,
   the JA4 parser as a working example of TLS-record-level extraction) already exists in the
   codebase to extend from.
4. **JA4 fingerprinting is already shipped — say so explicitly in the pitch.** This is not a
   "could add" item; it's evidence the "device/session fingerprinting from metadata" claim is
   real and implemented today, correctly using JA4 over the retired JA3. Worth stating plainly
   to a reviewer who may assume metadata-fingerprinting claims are aspirational.
5. **SIP/VoIP call reconstruction (Wireshark-VoIP-Calls-equivalent + rtpbreak-style RTP
   extraction).** Real, valuable, directly answers "what about call records" — but only for
   unencrypted SIP/RTP (legacy PBX/enterprise trunks), not for consumer mobile VoIP. Medium-high
   effort (SIP dialog parsing, RTP stream reassembly, codec identification). Worth building only
   if a VoIP-fraud or PBX-abuse scenario is actually part of the pitch; otherwise it's effort
   spent on a narrow case.
6. **RFC 3161 timestamp token via a public TSA, bound to the capture hash.** Low effort, modest
   but real courtroom-readiness value; correctly framed as an enhancement, not a §63 compliance
   requirement (see §5).
7. **iOS rvictl support.** Real capability, but needs a Mac and a cable and is friction-heavy
   for a 2-day hackathon demo. Lowest priority of this list; mention as "supported in principle"
   rather than building it.

---

## 8. Things we must NOT claim

- **We do not decrypt TLS/HTTPS content from a captured phone or network stream by default.**
  Metadata, SNI, JA4, timing, and volume only — full stop, unless the device has been
  separately, deliberately instrumented with a trusted interception certificate, and even then
  pinned apps (WhatsApp, Signal, most banking apps) defeat it.
- **A pcap never produces a CDR.** CDRs come from the telecom operator's own systems and are
  obtained via a §94 BNSS production summons to the TSP — never say "we extract call records
  from the pcap."
- **We do not perform lawful interception, and the tool must never be described in a way that
  implies live wiretap capability.** Interception (live call/message content) requires an order
  under the Telecommunications Act 2023 §20 (or the IT Act §69/§69B electronic-information
  analogue) issued to/by an authorised agency or TSP — a hackathon tool ingesting a pcap someone
  else lawfully captured is categorically different from performing interception itself, and
  that distinction must stay sharp in every pitch sentence.
- **We do not claim the tool acquires evidence from a suspect's seized device.** That remains
  standard mobile forensics (Cellebrite/UFED-class static extraction, done by a trained
  examiner) — this tool's job starts once a pcap exists, exactly like a DNA lab's job starts once
  a swab exists.
- **Do not present installing a capture app / trusted CA on a seized suspect phone as a sound
  forensic technique.** It actively modifies and executes code on evidence, contrary to ACPO
  Principle 1 and the spirit of BNSS §105's evidence-integrity intent. The phone-capture bridge
  is honestly a **consenting-party or department-owned-device** capability, not a
  seized-evidence one — keep that line explicit in the demo narration.
- **Do not cite SIPp as a call-reconstruction/forensic-analysis tool.** It is a SIP traffic
  generator/load-tester; its correct role here is generating realistic demo pcaps, not
  reconstructing evidentiary calls. Wireshark's VoIP Calls feature and rtpbreak are the
  reconstruction tools.
- **Do not claim JA3 fingerprinting** — it is retired and unreliable since Chrome 110+; the
  codebase already correctly uses JA4 only. Don't regress this in any future marketing copy.
- **Do not claim RFC 3161 timestamping (or any specific timestamping mechanism) is legally
  required by BSA §63.** Per this project's own SPEC_01 close reading, §63's operative
  sub-sections require a hash-based certificate in the prescribed Schedule form; timestamping
  beyond that is a genuine enhancement, not a compliance gap to imply exists.
- **Do not claim CERT-In's 180-day retention mandate means "every organisation has a pcap
  archive we can obtain."** The Directions mandate logs; whether a given organisation's
  compliance is raw packet capture, flow logs, or application logs varies, and only a minority
  (banks, larger SOCs) will hold true raw captures.
