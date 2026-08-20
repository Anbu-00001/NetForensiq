# 145 — Metadata: encrypted-traffic analysis without decryption, and what to record at seizure

**Status:** Research, verified against primary sources on 20 Aug 2026.
**Rule applied, same as [95_ESAKSHYA_VERIFIED_FINDINGS.md](95_ESAKSHYA_VERIFIED_FINDINGS.md):** a claim is marked
✅ only if the primary source was fetched directly. Everything else is ⚠️ (secondary source only) or
explicitly **UNVERIFIED**, regardless of how confident it sounds.

Two independent questions, both about metadata:

- **Part A** — what else is extractable from encrypted traffic without decrypting it, that
  NetForensiq does not already do (current baseline: JA4 client fingerprinting, SNI, DNS names,
  interval/timing statistics, volume asymmetry, Shannon entropy — see
  `backend/capture/tls_fingerprint.py` and `backend/capture/features.py`).
- **Part B** — what metadata should be recorded *at the moment of sealing* an exhibit
  (`evidence.service.ingest_evidence`) to make it defensible in an Indian court, beyond the
  hashes and case fields already captured.

---

## PART A — Encrypted traffic analysis without decryption

### A.0 What we already have, and why it matters here

`backend/capture/tls_fingerprint.py` implements **JA4** (not JA3 — JA3 is retired; Chrome 110's
2023 extension-order randomisation broke it). The implementation was read line-by-line before this
research began: it parses a ClientHello, strips GREASE (RFC 8701) from ciphers/extensions/versions,
and builds `t{ver}{sni}{ncipher}{next}{alpn}_{sha256(sorted ciphers)[:12]}_{sha256(sorted exts_sigalgs)[:12]}`.
Comparing this byte-for-byte against FoxIO's own reference implementation (fetched below, §A.1),
**our JA4 construction matches the spec exactly**, including the GREASE table, the cipher/extension
sort-before-hash design, and the SNI/ALPN exclusion from the extension hash. One thing the module's
own docstring states and this research confirms is now **out of date**: it says QUIC ClientHellos are
"not parsed... we do not reassemble QUIC initial packets." §A.4 below shows this is fixable — QUIC
Initial packets are not actually encrypted in any meaningful sense (RFC 9001 §5.2), and JA4's own
format already has a `q` prefix for exactly this case.

### A.1 The JA4+ suite — verified against the FoxIO repo and its canonical implementation

**Source of truth used:** github.com/FoxIO-LLC/ja4 — the README (`README.md`), the technical-details
directory (only `JA4.md` and `JA4H.md` exist as prose; the other variants are documented only as PNG
infographics, so the **canonical spec for JA4S/JA4T/JA4L/JA4X/JA4SSH is the reference Rust
implementation** in `rust/ja4/src/{tls,tcp,ssh,time/tcp,time/udp}.rs`, which is what was read to get
exact field construction — quoted below, not paraphrased from marketing copy). ✅

| Method | What it hashes / measures | Input required from a passive PCAP | Present in a passive PCAP? |
|---|---|---|---|
| **JA4** | TLS ClientHello: version, cipher list (sorted), extension list (sorted) + sig-algs, ALPN marker | One ClientHello record | ✅ Yes (TLS 1.2 and 1.3 alike — ClientHello is always cleartext) |
| **JA4S** | TLS ServerHello: version, extension count + list **in original order**, negotiated cipher, ALPN | One ServerHello record | ✅ Yes — **ServerHello itself is cleartext in TLS 1.3 too** (only what follows it is encrypted; see §A.2) |
| **JA4H** | HTTP request: method, HTTP version, cookie/referer flags, header count, primary `Accept-Language`, sha256 of header names (sorted), sha256 of cookie names/values (sorted) | A parsed HTTP/1.x or HTTP/2 request | Only for **cleartext HTTP** — useless against HTTPS unless TLS is terminated or the app is plaintext (common for malware C2, IoT, legacy devices) |
| **JA4L / JA4LS** | Not a hash — a **latency + TTL** pair, `{rtt_half}_{ttl}`, derived from the TCP 3-way handshake timestamps (`ja4l_c = (t_ACK − t_SYNACK)/2`, `ja4l_s = (t_SYNACK − t_SYN)/2`) or, for QUIC, the Initial/Handshake packet timestamps | SYN, SYN-ACK, ACK timestamps + TTL from IP header | ✅ Yes — pure TCP/IP metadata, works on **any** TCP or QUIC flow regardless of what's inside |
| **JA4X** | X.509 certificate: `{sha256(issuer RDN OIDs)[:12]}_{sha256(subject RDN OIDs)[:12]}_{sha256(cert extension OIDs)[:12]}` | Raw DER certificate bytes off the wire | ✅ **TLS 1.2 only** — TLS 1.3 encrypts the Certificate message (see §A.2); no plaintext cert, no JA4X |
| **JA4T / JA4TS** | TCP fingerprint from the client/server SYN: `{window_size}_{tcp_option_kinds}_{mss}_{window_scale}` | One SYN (client) or SYN-ACK (server) packet, TCP layer only | ✅ Yes — no TLS involved at all; works even on non-TLS TCP |
| **JA4TScan** | Active TCP scanner variant of JA4T (sends probes) | N/A — active, not passive | ❌ Not applicable — NetForensiq is a passive-capture tool by design |
| **JA4SSH** | Traffic-shape fingerprint of an SSH session: modal TCP payload length per direction over rolling windows of `sample_size` packets, formatted `c{mode_len}s{mode_len}_c{...}s{...}...`, plus (separately) **HASSH**/HASSH-server from the SSH KEX algorithm-negotiation string | TCP payload lengths + direction, no decryption | ✅ Yes — this is the FoxIO team's own production implementation of exactly the "packet-size/direction sequence" technique discussed academically in §A.5, which is useful corroboration that the technique is real and deployed, not just a paper result |
| **JA4D / JA4D6** | DHCP / DHCPv6 fingerprint from option ordering | DHCP broadcast packets | ✅ Yes, when DHCP is visible on the captured segment (see also `research/113_PCAP_ACQUISITION_REALITY.md` line ~328 on DHCP hostname leakage, already noted there) |

**Licence — verified, and it matters:**

- **JA4 core is BSD-3-Clause** (`LICENSE-JA4` in the repo). ✅ No restriction; this is what
  `tls_fingerprint.py` already implements.
- **Everything else — JA4S, JA4H, JA4L/JA4LS, JA4X, JA4SSH, JA4T/JA4TS/JA4TScan, JA4D/JA4D6 — is
  under the "FoxIO License 1.1"**, quoted verbatim from `LICENSE` in the repo: ✅
  > *"'Non-commercial purposes' include personal use by an individual, academic research and
  > development, and testing and evaluation of the software for your own internal use... Using
  > software 'for your own internal business purposes in a manner where you do not directly
  > monetize the software' is a non-commercial purpose."*
  > *"Providing the software on a hosted or managed service basis to others"* and *"providing
  > maintenance, support or development services for the software to others"* are explicitly
  > **excluded** from non-commercial use.
  > The README states this directly: *"If, for example, a company would like to use JA4+ internally
  > to help secure their own company, that is permitted. If... a vendor would like to sell JA4+
  > fingerprinting as part of their product offering, they would need to request an OEM license."*
  - **Reading for NetForensiq (our interpretation, not a legal opinion from FoxIO):** a police
    department computing JA4S/JA4T/JA4L/JA4X/JA4SSH internally, for its own investigations, and not
    selling, hosting, or monetising the tool, reads as "non-commercial internal use" under this
    definition. It should still be disclosed on an "acknowledgements/licences" page precisely
    because JA4+ is **patent-pending and a registered trademark** — a certificate or report that
    prints a `JA4S=...` or `JA4X=...` value is using FoxIO's marks and methods, and the licence's
    own §1.2 requires that "anyone who gets a copy... also gets a copy of these license terms."
  - **This is the one thing to flag loudly to the team before building JA4S/JA4T/JA4X/JA4L/JA4SSH**:
    it is a different licence from what `tls_fingerprint.py`'s docstring currently implies ("same
    as JA3... BSD 3-Clause" — true for JA4 core, **not** true for the rest of the suite). A code
    comment analogous to the existing JA4-vs-JA3 docstring should say so when any JA4+ variant is
    added, so nobody later assumes the whole suite is BSD.

### A.2 TLS certificate metadata — verified per version

✅ Verified against RFC 8446 (TLS 1.3) and corroborating sources: **in TLS 1.2, the server's
Certificate handshake message is sent in the clear** — a passive observer with no decryption can read
issuer, subject, validity dates, self-signed status, SAN list, and full extension OIDs directly off
the wire (this is exactly the input JA4X needs, §A.1). **In TLS 1.3, the Certificate message (along
with EncryptedExtensions, CertificateVerify, and Finished) is encrypted** under handshake traffic
secrets derived from the (EC)DHE key exchange — a passive observer sees only the cleartext ClientHello
and ServerHello, and everything from Certificate onward is opaque without the private key or a
key-log file. This is a **privacy improvement by design** in TLS 1.3, not an oversight.

**What is extractable per version, concretely:**

| Field | TLS 1.2 (passive) | TLS 1.3 (passive) |
|---|---|---|
| Negotiated version, cipher, extensions (JA4/JA4S) | ✅ | ✅ |
| SNI (ClientHello) | ✅ (unless ECH — §A.3) | ✅ (unless ECH) |
| Certificate: issuer, subject, validity, SAN, self-signed | ✅ | ❌ (encrypted) |
| Certificate transparency SCT list (often a cert extension) | ✅ | ❌ (encrypted) |

**Fraction of real traffic still on TLS 1.2 — UNVERIFIED at a precise figure.** Multiple searches
were made for a live traffic-volume split (not server-support-capability, which is a different and
much less useful number). Cloudflare Radar's TLS-version report and the Cloudflare Radar API both
require an authenticated API key and returned `403`/an auth-error to this research's fetch attempts;
Qualys SSL Labs' SSL Pulse dashboard is JS-rendered and did not yield numbers to a text fetch. What
could be sourced: ⚠️ secondary reporting cites Qualys SSL Pulse showing **100% of ~150,000 monitored
websites still support TLS 1.2 as a fallback** (as of a June 2025 snapshot) even as **75.3% now also
support TLS 1.3**, and an unsourced figure claims "~90% of browser negotiations use TLS 1.3." Neither
number answers "what fraction of packets we actually capture will be TLS 1.2" — that depends heavily
on what's on the network (server support ≠ what a given client negotiates; IoT devices, older
Android/Windows builds, embedded and industrial equipment, and malware families frequently pin TLS 1.2
or SSLv3 and will not negotiate up even when the peer offers 1.3). **Practical implication for
NetForensiq:** do not assume TLS 1.3 has made certificate-based analysis (JA4X) obsolete on the kind
of traffic this tool is likely to see (mixed corporate/residential networks, older or unmanaged
devices) — treat the "TLS 1.2 fraction" as unknown-but-non-trivial and keep JA4X buildable rather than
skip it as legacy-only.

### A.3 Encrypted Client Hello (ECH)

✅ RFC 9849 finalised the current ECH design (March 2026, per search results — not independently
fetched from the RFC itself in this pass, flagged accordingly). Firefox has supported ECH since
version 118 (enabled by default from 119), Chrome since October 2023; ⚠️ one source states "59% of
browsers including Chrome, Edge, Firefox and Safari actively use ECH out-of-the-box" on the client
side. **Server-side deployment is the bottleneck**: ⚠️ secondary sources cite **4.2% of the top 10K
websites and 9.2% of the top 1M websites** supporting ECH, largely because Cloudflare turned it on by
default for its customers in late 2023 — ECH deployment today is close to "wherever Cloudflare is,"
not general.

**What breaks and what survives, concretely:** ECH replaces the cleartext SNI in the ClientHello with
an encrypted payload (the real ClientHello is wrapped inside an "outer" ClientHello whose SNI, if
present at all, names the ECH-serving CDN, e.g. `cloudflare-ech.com`). This defeats SNI-based domain
attribution for ECH-enabled sites specifically. **What still works even with ECH on:**
- JA4 itself — the outer ClientHello still has a real, fingerprintable cipher/extension list (ECH
  support is itself an extension that shows up in the extension count).
- JA4T, JA4L — TCP/IP layer metadata is untouched by ECH.
- The destination IP address and ASN (unless further hidden behind a CDN or VPN this tool can't see
  past — a separate, orthogonal problem).
- **DNS**: the client typically has to look up an `HTTPS`/`SVCB` DNS record to learn the ECH config
  before it can even send an ECH ClientHello — an unencrypted DNS query for that record (if DNS itself
  isn't encrypted via DoH/DoT, which is common but not universal) still names the domain.
- JA4X, JA4S — moot either way once TLS 1.3 is in play (§A.2).

**Practical read for a 2026 Indian-network capture:** ECH is realistically still a minority case
outside Cloudflare-fronted sites, and even where present it does not blind the tool to JA4/JA4T/JA4L
or, usually, to plaintext DNS. It is a real and growing gap, not yet a dominant one.

### A.4 QUIC / HTTP/3

✅ **QUIC Initial packets are not actually confidential.** RFC 9001 §5.2 defines Initial-packet
protection keys as derived via HKDF-Extract from **a fixed, published salt**
(`0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`) and the connection's Destination Connection ID, which
is itself carried in the cleartext packet header. The RFC states this directly: *"as it is trivial to
determine the keys used for Initial packets, these packets are not considered to have confidentiality
or integrity protection"* against an on-path or passive observer. **The TLS ClientHello inside a
QUIC Initial packet's CRYPTO frame is therefore recoverable by anyone who can compute the same public
key derivation** — SNI, cipher list, ALPN, QUIC transport parameters, all of it. This "encryption" is
about resisting middlebox interference and ossification, not about hiding anything from an analyst.

✅ FoxIO's own JA4 format already anticipates this: the format's first character is `q` for QUIC
(`t`=TCP, `d`=DTLS, `q`=QUIC), confirmed directly from `technical_details/JA4.md`: *"QUIC is the
protocol which the new HTTP/3 standard utilizes, encapsulating TLS 1.3 into UDP packets... If the
hello packet uses QUIC protocol, the fingerprint begins with 'q'."* The README's own example table
shows Chrome producing both `JA4=t13d1516h2..._` (TCP) and `JA4=q13d0312h3..._` (QUIC) fingerprints.
**This directly contradicts the current claim in `tls_fingerprint.py`'s docstring that QUIC support
would require work we haven't done — the ClientHello is available, it just needs the Initial-packet
unwrap (a fixed HKDF derivation, not a decryption in any meaningful sense) before the existing
`parse_client_hello` logic can run on it.**

✅ FoxIO also computes JA4L over QUIC (see `rust/ja4/src/time/udp.rs`, read directly): using the
Initial/Handshake packet timestamps from both directions instead of TCP's SYN/SYN-ACK/ACK, the same
latency+TTL pair is derivable.

**What's visible in QUIC/HTTP-3 traffic overall:** SNI, JA4-equivalent client fingerprint (once the
Initial unwrap is implemented), packet sizes and timing (always visible — QUIC's payload is genuinely
encrypted post-handshake, but sizes/timing are metadata regardless of transport), and the UDP 5-tuple.
**What's lost relative to TCP+TLS**: no visible TCP handshake (so no JA4T/JA4L via the TCP path — must
use the QUIC-native timestamp path instead), and post-handshake QUIC frames (stream data) are
genuinely encrypted with no equivalent to JA4X (no cleartext certificate path exists in QUIC at all —
QUIC always runs over TLS 1.3 semantics).

### A.5 Packet size and direction sequences — website/traffic fingerprinting

This is real, deployed technique (JA4SSH is FoxIO's own production instance of it, §A.1), and also a
heavily academic literature with a well-known gap between lab results and field reliability. Searches
this pass found: ⚠️ **"Beyond a Single Perspective: Towards a Realistic Evaluation of Website
Fingerprinting Attacks"** (arXiv 2510.14283, fetched — abstract only, paywalled full text) states
plainly that while classifiers report **"over 90% accuracy in controlled experimental settings," many
"degrade significantly"** once evaluated against realistic conditions simultaneously — traffic drift
over time, multi-tab browsing, early-stage/incomplete sessions, open-world (unknown-site) settings,
and active defenses. ⚠️ A parallel body of work on **encrypted traffic *classification*** (as opposed
to website fingerprinting specifically) reports the same honest finding under a different name:
**concept drift** — application updates change traffic shape fast enough that a classifier trained on
one snapshot degrades within weeks to months, and production deployment requires either frequent
retraining (expensive, needs fresh labelled data) or accepting declining accuracy.

**Honest read for NetForensiq:** website/app fingerprinting from size+direction sequences is a real
signal (this is essentially what `interval_features`/`payload_entropy` already lean on, at the
flow-statistics level) but should **never be presented as an identification** in a forensic product —
only as a corroborating behavioural signal alongside JA4/SNI/DNS, exactly the way `Detection.evidence`
already requires a threshold + source citation rather than a bare score. A closed-world claim ("this
flow is Telegram") built purely from packet-size sequences would not survive a defence challenge citing
this literature, and should not be built as a headline feature. It is buildable as an **auxiliary**
score (e.g., "traffic shape consistent with interactive chat, inconsistent with bulk transfer") in a
day or two using existing flow features, but a per-app classifier trained on public traces is not — it
would need a labelled corpus this tool has no legitimate way to acquire on an air-gapped, evidence-only
deployment, and would immediately be subject to the drift problem above with no way to retrain safely
against unvetted new traffic.

### A.6 Certificate Transparency / passive DNS correlation

**Both are fundamentally online services** — CT log queries (crt.sh, Google's CT log list) and passive
DNS databases (Farsight/DNSDB and similar) are live lookups against third-party infrastructure, which
directly conflicts with the air-gap requirement already established for this platform (see
`research/113_PCAP_ACQUISITION_REALITY.md` and the existing `IOCFeed` design in
`backend/capture/models.py`, whose docstring states explicitly: *"the examination workstation is
air-gapped, so it cannot [fetch]... an evidence machine that opens outbound connections while a
capture is loaded has just introduced traffic of its own into an environment whose whole purpose is
establishing what traffic existed"*).

**What IS usable offline:** a **periodically-downloaded, dated snapshot** of CT log data or a curated
domain/certificate-fingerprint mapping, carried into the air-gapped environment exactly the way
`IOCFeed` already handles abuse.ch blocklists — imported with a stated `retrieved_on` date (not a file
mtime), licence, and source. This is directly buildable as **a new `IOCFeed.Format` choice** (e.g.
`ct_log_snapshot`) reusing the exact provenance-and-staleness pattern `IOCIndicator`/`ioc.py` already
implement for blocklists, including the staleness-gap disclosure `capture/ioc.py` already computes on
every match — a JA4X-derived certificate fingerprint (§A.1, TLS 1.2 only) or a SAN/issuer string
extracted from a cleartext cert could be checked against such a snapshot the same way an IP is checked
against Feodo Tracker today. This is genuinely low-effort (a day, mostly the CSV/JSON import path,
which is a near-copy of the existing `IOCFeed` importer) **but only useful on TLS 1.2 traffic** — see
§A.2 — since TLS 1.3 hides the certificate a passive observer would otherwise fingerprint.

### A.7 Ranked, buildable list

Ranked by (forensic value it concretely adds) × (buildability in 1–2 days) × (honesty about failure
modes), highest first:

1. **JA4T (TCP client fingerprint).** ★★★★★ buildability — single SYN packet, no TLS parsing at all,
   format is three fields joined by underscores (`window_size_options_mss_wscale`), confirmed exactly
   from FoxIO's Rust source (§A.1). **Forensic value:** distinguishes OS/stack even on non-TLS
   traffic, complements JA4 rather than duplicating it, works when TLS is absent entirely (raw TCP
   malware, plaintext protocols). **Licence:** FoxIO License 1.1, non-commercial-use case likely
   applies (§A.1) — disclose it. **Effort: well under a day.**

2. **QUIC support for the existing JA4 parser (the `q` prefix).** ★★★★☆ — requires unwrapping the
   Initial packet's AEAD protection using the fixed public salt (RFC 9001 §5.2, quoted above) before
   feeding the resulting ClientHello bytes into the *already-correct* `parse_client_hello`. **Forensic
   value:** HTTP/3 is now Chrome's/most browsers' default transport to many major sites; without this,
   an increasing slice of "TLS-looking" traffic (actually QUIC over UDP/443) is invisible to
   fingerprinting entirely today. **Licence:** BSD-3 (this stays inside JA4 core, not JA4+).
   **Effort: 1–2 days** — the AEAD unwrap is a known, fixed derivation (HKDF-Extract/Expand with a
   published salt, no key material to obtain), the risk is QUIC's variable-length integer encoding and
   packet-number decoding, not cryptography.

3. **JA4S (TLS server response fingerprint).** ★★★★☆ — format confirmed exactly from FoxIO's Rust
   source (§A.1): `{quic_or_t}{ver}{ext_count}{alpn}_{cipher}_{sha256(exts, original order)[:12]}`.
   **Forensic value:** fingerprints the *server*, not the client — useful for identifying C2
   infrastructure or malicious servers reused across cases, independent of which client library talked
   to them, and works on TLS 1.3 too (ServerHello is cleartext, §A.2). **Licence:** FoxIO License 1.1.
   **Effort: under a day** given the ClientHello parser already exists as a template for ServerHello.

4. **JA4L / JA4LS (latency + TTL from the handshake).** ★★★☆☆ — needs SYN/SYN-ACK/ACK timestamps
   (already captured — see `interval_features` reasoning in `features.py`) plus TTL from the IP
   header (currently discarded). **Forensic value:** rough network-distance and hop-count estimate per
   flow, which is a genuinely different signal from anything currently computed — a beacon that's
   "0.3ms away" is very unlikely to be the same infrastructure as one "180ms away" even if both share a
   JA4 fingerprint, which is a useful disambiguator for grouping C2 by physical/network location.
   **Licence:** FoxIO License 1.1. **Effort: about a day**, mostly plumbing TTL through the existing
   flow-state accumulator.

5. **pcapng SHB/IDB provenance extraction (§B.4 below — cross-referenced here because it is also an
   "extract more from what's already there" item).** Not encrypted-traffic analysis, but same spirit:
   free metadata already in the file that the current ingestion path discards. See Part B.

6. **CT-log offline snapshot correlation (§A.6).** ★★★☆☆ — reuses the existing `IOCFeed` pattern
   almost verbatim. **Forensic value:** ties a cleartext certificate (TLS 1.2 only) to a
   publicly-logged issuance record, useful for flagging freshly-issued certs (a strong phishing/C2
   signal — "this cert was issued 6 hours before this traffic was captured") the same way `IOCFeed`
   already flags stale blocklist matches. **Licence:** CT logs themselves are public infrastructure;
   no licence issue, only the staleness-disclosure discipline the codebase already applies elsewhere.
   **Effort: about a day.**

7. **JA4X (certificate fingerprint).** ★★★☆☆ — construction fully confirmed from FoxIO's Python
   source (§A.1): issuer/subject RDN-OID hashes plus extension-OID hash. **Forensic value:** groups
   traffic by certificate authority/subject pattern (many malware families reuse self-signed cert
   templates — the README's own examples show `JA4X` values for Sliver, SoftEther, Qakbot, Pikabot).
   **Caveat, stated honestly:** only computable on TLS 1.2 traffic (§A.2), and the "fraction of traffic
   still on TLS 1.2" figure is UNVERIFIED (§A.2) — this feature's real-world hit rate on 2026 traffic
   is genuinely unknown, not just conservatively estimated. Build it, but do not promise it will fire
   often. **Licence:** FoxIO License 1.1. **Effort: 1–2 days**, X.509 DER parsing is more fiddly than
   the fixed-format TLS records above.

8. **JA4SSH (SSH traffic-shape fingerprint).** ★★☆☆☆ — narrow but real: SSH is common on
   investigation-relevant traffic (lateral movement, reverse shells — the README's own example is
   literally `JA4SSH=c76s76_c71s59_c0s70` labelled "Reverse SSH Shell"). **Forensic value:** detects
   interactive-shell vs. bulk-transfer SSH usage from size patterns alone, without touching the
   encrypted payload. **Licence:** FoxIO License 1.1. **Effort: about a day**, but lower priority than
   the TLS-focused items above given how much less SSH appears than TLS in typical captures.

9. **Auxiliary traffic-shape scoring from size/direction sequences (§A.5), NOT a per-app
   classifier.** ★★☆☆☆ — buildable in a day from data the flow accumulator already has
   (`packets_sent`/`packets_received`, `avg_packet_size`, `interval_*`), but must be presented as a
   corroborating behavioural note, never an identification, given the literature's own honesty about
   lab-vs-field accuracy gaps (§A.5). Low priority precisely because overstating it is worse than not
   building it.

10. **JA4H (HTTP client fingerprint).** ★☆☆☆☆ for *this* tool specifically — fully specified and
    trivial to build (Python source read directly, §A.1), but its entire input (HTTP headers, cookies)
    is exactly what TLS is encrypting in the traffic this tool is meant to analyse. Real value only
    for plaintext-HTTP malware/IoT traffic, which is a narrower slice than everything above. Build it
    last, if at all, and only when a plaintext-HTTP-heavy case shows up.

**Not recommended to build:** JA4TScan (active scanning — contradicts the passive-capture design
entirely); a per-application ML classifier from packet sequences (§A.5's drift problem, no legitimate
training-data source on an air-gapped deployment); live CT-log or passive-DNS *queries* (both require
the exact online connectivity the platform is designed not to have).

---

## PART B — Acquisition metadata to record at sealing

### B.0 What `ingest_evidence` records today

Read directly from `backend/evidence/service.py` and `backend/evidence/models.py`: exhibit number,
original filename, stored path, file size, SHA-256/SHA-1/MD5, encryption-at-rest state, acquisition
timestamp, device type/make-model/serial/identifier, custodian relationship, case/FIR/police-station
linkage, seized-from, acquisition notes, provenance (seized/reference/synthetic/unattested) with a
manifest-vs-declaration reconciliation, and `collected_by`. Separately, `CustodyEvent` hash-chains
every subsequent action, and `evidence/timesource.py` **already records the workstation's own clock
state** (NTP-sync yes/no/unknown, timezone, RTC-in-local-time flag) and prints it on the Section 63
certificate's custody annexure — this is a genuine, already-built answer to part of §B.5 below, not a
gap.

### B.1 What the standards actually name

**NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — fetched
directly (`nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf`), converted with
`pdftotext -layout`, and read at source. ✅ §3 ("Data Collection"), p.3-4, states — quoted verbatim:

> *"This involves keeping a log of every person who had physical custody of the evidence, documenting
> the actions that they performed on the evidence and at what time, storing the evidence in a secure
> location when it is not being used, making a copy of the evidence and performing examination and
> analysis using only the copied evidence, and verifying the integrity of the original and copied
> evidence... Throughout the process, a detailed log should be kept of every step that was taken to
> collect the data, **including information about each tool used in the process**... one person on the
> scene should be designated the evidence custodian... and record every action that was taken along
> with **who** performed the action, **where** it was performed, and **at what time**."*

§4.4/§5 (p.4-14 onward) separately covers system-clock reliability, quoted:

> *"analysts should be aware of the value of using system times and file times... this may seem like a
> simple task, it is often complicated by unintentional or intentional discrepancies in time settings
> among systems... The Network Time Protocol (NTP) synchronizes the time on a computer with an atomic
> clock... [and] The computer's clock does not have the correct time [is listed as a named reason file
> times may be inaccurate]."*

**SWGDE, "Best Practices for Computer Forensic Acquisitions," 17-F-002, version 2.1 (5 Aug 2025)** —
fetched directly from swgde.org and converted with `pdftotext`. ✅ Its §9 "Documentation" gives the
single most directly usable field list found in this research, quoted verbatim:

> *"Examiners should document digital evidence acquisitions per organizational policy. The
> documentation should include a description detailed enough to allow the definitive identification of
> the items to the exclusion of all others. This information may include:*
> - *Unique identifiers (e.g., make, model, serial number, and asset tag);*
> - *Source of digital evidence (e.g., a description of its location when discovered);*
> - *Unique investigation identifiers (e.g., investigation name, case number);*
> - *Acquisition details (e.g., type of acquisition, imaging tool and version number);*
> - *Hash value(s) of the acquired data;*
> - *Any photographs of the evidence that were taken, either at the time of collection or before the
>   acquisition;*
> - *Acquiring person's name and title;*
> - *Acquisition date and time (including time zone);*
> - *Errors encountered during acquisition;*
> - *Any additional documentation as required by the examiner's organization."*

And, on chain of custody specifically:

> *"When digital evidence is transferred from one person to another, the chain of custody should note
> at a minimum... Unique identification of the item; Name of transferring individual; Name of receiving
> individual or facility; Date and time of receipt and transfer; Purpose of transfer."*

**ISO/IEC 27037:2012**, *Guidelines for identification, collection, acquisition and preservation of
digital evidence* — the full standard is paywalled (iso.org sells it; no free mirror located). ⚠️
Secondary summaries (not independently checked against the paywalled clause text, flagged
accordingly) consistently describe **Clause 6** as covering identification/collection/acquisition
documentation, listing items such as: type of incident, date/time of incident, an investigation plan,
tools needed to acquire evidence, and — per one summary — **Clause 6.3** on "handling without
modification, with integrity documented." **This document should be treated as directionally correct
but not quotable at the clause-and-sentence level** the way NIST SP 800-86 and SWGDE are above; if
ISO 27037 needs to be cited with a specific clause number in a certificate or spec document, the
standard itself (or a licensed copy) needs to be obtained — this was not possible in this research
pass. **ISO/IEC 27042** (analysis/interpretation) was searched for but no usable summary of its
specific field-level content was found this pass; also flag as **UNVERIFIED / not researched to
clause level**.

**ACPO Good Practice Guide for Digital Evidence** — already verified in this repo at
`research/113_PCAP_ACQUISITION_REALITY.md` (line ~289), citing ACPO Principle 1 ("no action... should
change data held on a [device]...") via the cryptome.org primary-text mirror. Not re-fetched here;
that existing verification is reused rather than duplicated.

**SWGDE more broadly** — already cited in `113_PCAP_ACQUISITION_REALITY.md` for the
acquisition/analysis machine-separation principle (SWGDE 17-F-002 listing at
nist.gov/osac/standards-library). This research pass adds the §9 field list above, which that earlier
document did not yet quote.

### B.2 India-specific: BSA 2023 Schedule, and eSakshya

**Already fully verified in this repository** — `research/SPEC_01_EVIDENCE_INTEGRITY.md` §1.2
reproduces THE SCHEDULE to BSA 2023 §63(4)(c) verbatim from the indiacode.nic.in bare-act PDF
(pp.51–53), not re-fetched here to avoid duplicating work already done to the same standard. The
Schedule's own Part A/Part B form asks for, about the device and the process: device type (tick-box:
Computer/Storage Media, DVR, Mobile, Flash Drive, CD/DVD, Server, Cloud, Other), Make & Model, Colour,
Serial Number, IMEI/UIN/UID/MAC/Cloud ID, custodian relationship (Owned/Maintained/Managed/Operated),
hash value(s) and algorithm (SHA1/SHA256/MD5/Other, all as tick-boxes with a value field), and
Date/Time(IST)/Place of signing — all of which `EvidenceRecord` and `certificate_pdf.py` already
mirror field-for-field, confirmed by direct reading of both files for this task (§B.0 above).

**eSakshya** — already verified in `research/95_ESAKSHYA_VERIFIED_FINDINGS.md`: it generates a BSA
§63(4)(c) Part A certificate, eSigned via Aadhaar, computing SHA-256 at "freeze" time (✅, sourced to
the Maharashtra eSakshya Rules 2025 and corroborated screen-by-screen). **eSakshya does not track
post-seizure custody** — that finding stands and is directly relevant here: NetForensiq's
hash-chained `CustodyEvent` log is doing something the officially-deployed government tool does not,
which is worth keeping rather than trimming for "over-collection."

**CFSL/DFSL SOP** — searched this pass; **no publicly-published SOP document specific to network/PCAP
seizure was located.** CFSL Hyderabad and the regional FSLs were identified as the relevant bodies but
no public procedure document exists to cite. Marked **UNVERIFIED / not publicly available** rather
than invented.

### B.3 The acquiring workstation — what to record, and the over-collection line

Cross-referencing what NIST SP 800-86 and SWGDE actually name (§B.1) against what the prompt asked
about (hostname, OS+version, tool version, capture-tool identity, interface name, NTP-sync state,
operator's account/badge):

| Item | Named by a standard? | Verdict |
|---|---|---|
| **Tool name + version used for acquisition** | ✅ SWGDE §9: "imaging tool and version number" | **REQUIRED** |
| **Acquiring person's name/title** | ✅ SWGDE §9 explicitly; NIST 800-86 "who performed the action" | **REQUIRED** — already captured as `collected_by` |
| **Acquisition date/time incl. timezone** | ✅ SWGDE §9 explicitly | **REQUIRED** — already captured, and rendered in IST via `certificate_pdf.ist()` |
| **Errors encountered during acquisition** | ✅ SWGDE §9 explicitly | **RECOMMENDED** — not currently a distinct field; `acquisition_notes` is free text and could carry it, but SWGDE names it as its own item |
| **Clock synchronisation state (NTP yes/no/unknown)** | ✅ NIST 800-86 §4.4/§5 (see quote, §B.1) | **REQUIRED** — **already built** (`evidence/timesource.py`), confirmed by direct reading |
| **Capture interface name** (e.g. `eth0`, a SPAN port label) | Not named by NIST/SWGDE directly, but is exactly "type of acquisition" (SWGDE §9) applied to a live network capture rather than a disk image, and is already a first-class field on `CaptureSession.interface` in `capture/models.py` | **RECOMMENDED** — already exists on `CaptureSession`, not currently surfaced onto the sealed `EvidenceRecord` itself when the source was a live interface rather than an uploaded PCAP |
| **Hostname of the capturing/acquiring machine** | Not directly named by NIST/SWGDE (they name "make, model, serial number, asset tag" for the *evidence device*, not the analyst's own workstation) — but is a reasonable proxy for "which machine performed this," analogous to what SWGDE asks about the imaging tool's environment | **RECOMMENDED**, not required — a single fixed lab workstation makes this low-value; a fleet of field-capture laptops makes it worth having |
| **Capture tool's OS and version** (the machine running scapy/tcpdump/Wireshark) | Not directly named — closest analogue is SWGDE's "imaging tool and version number," which is about the *forensic* tool, not the underlying OS | **RECOMMENDED**, lower priority than the tool version itself |
| **Operator's account name / login** | Not named — SWGDE asks for the person's **name and title**, a human-readable attestation, not a system account identifier | **OVER-COLLECTION if it duplicates `collected_by`'s badge/name** — a Django username is not what any standard asks for; only worth recording if it differs meaningfully from the named officer (e.g., a shared kiosk account), and even then belongs in the custody log's `actor` field, which already exists |
| **Operator's badge number** | Not named by NIST/SWGDE, but is the standard Indian police identification format and is exactly the kind of detail an FIR-linked chargesheet would already expect | **RECOMMENDED** — **already built**: `CustodyEvent.actor_badge` exists and is populated from `actor.badge_id` |
| **MAC address / hardware serial of the capturing machine's NIC** | Not named by any standard reviewed | **OVER-COLLECTION** — this identifies police equipment in unnecessary detail for a use case the standards don't ask for; if ever needed for a specific chain-of-custody dispute, it belongs in free-text `acquisition_notes`, not a first-class field |
| **Operator's personal device details** (a hypothetical officer's own phone/laptop used off-book) | Not applicable if only official evidence-store equipment is used | **OVER-COLLECTION / out of scope** — see DPDP note below |

**DPDP Act 2023 and officer data — UNVERIFIED at the level of a specific bearing provision.**
Section 17 was located (fetched via search, not the bare act itself this pass) and its subsection
17(1)(c) provides a **law-enforcement processing exemption**: personal data may be processed "in the
interest of prevention, detection, investigation or prosecution of any offence," relaxing Chapter II,
III and §16 obligations for *that* processing. This is about processing **suspects'/third parties'**
data for an investigation, not a direct statement about **an officer's own** workstation/device
metadata being collected by their own department's tooling — no specific DPDP provision addressing
*that* narrower question was found this pass. The practical guidance above (badge number yes, MAC
address/personal device no) is this research's own reasoned judgement — flagged as [GOOD PRACTICE],
not as a DPDP-mandated position — consistent with the general data-minimisation instinct DPDP
expresses elsewhere (though not fetched to a specific section for this narrower point). **Recommend
treating any future workstation-metadata field addition against a simple test: does a named standard
(§B.1) ask for it, and does it help establish the acquisition's integrity or the chain of custody? If
neither, it's over-collection regardless of DPDP.**

### B.4 PCAP-specific metadata — verified option codes, and a real gap

✅ **pcapng is still an IETF Internet-Draft, not yet an RFC** — confirmed from datatracker.ietf.org:
the current version is `draft-ietf-opsawg-pcapng-05`, published 17 March 2026, Intended Status
"Informational," expiring 18 September 2026. (For contrast, the sibling classic-pcap format has its
own parallel draft, `draft-ietf-opsawg-pcap`.) The option codes below were fetched from
**draft-03 and cross-checked against draft-05**; they are identical across both, and match the
long-standing Wireshark wiki reference that every real-world pcapng writer (Wireshark, dumpcap,
tshark, tcpdump with `-w` in some builds) already implements — these numbers have been stable for a
decade of de-facto use even while the IETF document itself is still in draft. ✅

**Block type codes:**

| Block | Type code |
|---|---|
| Section Header Block (SHB) | `0x0A0D0D0A` |
| Interface Description Block (IDB) | `0x00000001` |
| Enhanced Packet Block (EPB) | `0x00000006` |

**Section Header Block options** (per-file provenance — who/what wrote this capture):

| Option | Code | Length | What it carries |
|---|---|---|---|
| `opt_endofopt` | 0 | 0 | terminator |
| `opt_comment` | 1 | variable | free-text comment |
| **`shb_hardware`** | **2** | variable | the hardware the capture was taken on |
| **`shb_os`** | **3** | variable | the OS the capture was taken on |
| **`shb_userappl`** | **4** | variable | the application that wrote the file (e.g. `"Wireshark 4.2.0"`) |

**Interface Description Block options** (per-interface capture configuration):

| Option | Code | Length | What it carries |
|---|---|---|---|
| **`if_name`** | **2** | variable | interface name (e.g. `eth0`) |
| **`if_description`** | **3** | variable | free-text interface description |
| `if_IPv4addr` | 4 | 8 | interface's IPv4 address + netmask |
| `if_IPv6addr` | 5 | 17 | interface's IPv6 address + prefix length |
| `if_MACaddr` | 6 | 6 | interface's MAC address |
| `if_EUIaddr` | 7 | 8 | interface's EUI-64 address |
| `if_speed` | 8 | 8 | interface speed, bits/second |
| **`if_tsresol`** | **9** | 1 | timestamp resolution — see encoding below |
| **`if_tzone`** | **10** | 4 | timezone of the interface's clock |
| **`if_filter`** | **11** | variable, min. 1 | the capture filter that was applied (e.g. a BPF string) |
| **`if_os`** | **12** | variable | the OS on which this particular interface's packets were captured |
| `if_fcslen` | 13 | 1 | frame-check-sequence length, if present |
| **`if_tsoffset`** | **14** | 8 | offset to add to packet timestamps |
| `if_hardware` | 15 | variable | interface hardware description |
| `if_txspeed` | 16 | 8 | interface TX speed |
| `if_rxspeed` | 17 | 8 | interface RX speed |
| `if_iana_tzname` | 18 | variable | IANA timezone name (newer addition — present in draft-05, worth checking a given writer's draft-support level before relying on it) |

**`if_tsresol` encoding, quoted from the fetched spec text:** *"If the Most Significant Bit is equal
to zero, the remaining bits indicates the resolution of the timestamp as a negative power of 10 (e.g.
6 means microsecond resolution). If the Most Significant Bit is equal to one, the remaining bits
indicates the resolution as negative power of 2."* — i.e. a single byte tells you exactly how precise
the packet timestamps in this file are, which is directly relevant to any claim this tool makes about
sub-millisecond beacon timing (`interval_features` in `features.py`).

**Do we extract these today? No — verified by reading the ingestion path.** `capture/upload.py`
checks the pcap/pcapng magic bytes (`0x0a0d0d0a` for pcapng) only to validate the file format at
upload; it does not read block options. Packet iteration goes through `scapy.utils.PcapReader`
(confirmed by grep across `capture/service.py`, `capture/home_net.py`, `capture/reassembly.py` — all
three call `PcapReader`/`RawPcapReader`). Scapy's pcapng reader parses the SHB/IDB **internally**
(it has to, to get byte order and per-interface link type/timestamp resolution right for the packets
it hands back) but **does not expose those options through its packet-iteration API** — the
`shb_hardware`/`shb_os`/`shb_userappl`/`if_name`/`if_filter`/`if_tsresol` values are read by scapy and
then silently discarded before `ingest_evidence` ever sees the file.

**This is the single most concretely useful, cheapest addition in this whole document.** A capturing
tool that wrote `shb_userappl = "tcpdump 4.99.4"` or `shb_os = "Linux 6.1.0-glibc2.36"` into the file
is handing NetForensiq exactly the kind of tool-and-environment provenance NIST SP 800-86 and SWGDE
both ask be documented (§B.1) — **for free, already inside the evidence file, written by whatever
tool did the actual seizure** (which may not even be this platform — an uploaded PCAP from a field
laptop's tcpdump run carries this). Recording it does not require trusting the claim (a hostile actor
could forge `shb_os`), but as a *disclosed, quoted* field on the certificate — "the file's own header
declares it was written by X" — it is exactly the same epistemic status as the SHA-1/MD5 values
already printed "for the form's sake, not relied upon alone" in `certificate_pdf._hash_block`, and
costs nothing to add since scapy already parses these blocks and just needs to be asked to keep the
values instead of discarding them (or, more robustly, read once at ingest with a small ~50-line direct
block/option parser independent of scapy's internals, so a scapy version change can't silently start
dropping this). **Effort: well under a day.** Store as a JSON blob on `EvidenceRecord`
(`pcap_metadata = models.JSONField(default=dict, blank=True)`) with keys matching the option names
above, printed as an additional annexure on the certificate the same way the custody chain already is.

### B.5 Time — what should be recorded about the clock

Already substantially built (§B.0), confirmed by direct reading of `evidence/timesource.py`: NTP
synchronisation state (`synchronised`/`unsynchronised`/`unknown`, read from `timedatectl show`'s
`NTPSynchronized` field), system timezone, and whether the hardware RTC is kept in local time rather
than UTC (which matters across a daylight-saving boundary — though India, notably, has no DST, so this
specific flag is lower-stakes for an India-only deployment than the code comment's general framing
suggests, worth noting but not worth removing since the platform's design already anticipates
non-Indian reference captures per `EvidenceRecord.Provenance.REFERENCE`).

**What this covers vs. what §B.4's pcapng metadata would add:** `timesource.describe()` records the
clock state of the **analysis/certification workstation, at the moment the certificate is rendered** —
it says nothing about the clock of the **machine that actually captured the packets**, which may be a
different machine entirely (a field laptop, a SPAN-port collector) and may have captured the traffic
hours, days, or months before ingestion. `if_tsresol` and `if_tzone` (§B.4) are the *capturing*
machine's declarations about its own clock, embedded in the file itself — genuinely complementary to,
not redundant with, `timesource.py`. **Recommendation: record both, and print them side by side on the
certificate's time-basis note** — "this certificate was rendered on a workstation whose clock was
[state]; the capture file itself declares a timestamp resolution of [X] and was written by [tool]" is
a materially stronger statement than either alone, and is assemblable from two features that already
almost entirely exist (`timesource.py`) or are a well-under-a-day addition (§B.4's pcapng parse).

---

## Summary tables for quick reference

### Part A — buildable ranking (see §A.7 for full reasoning)

| Rank | Feature | Effort | Licence | Value |
|---|---|---|---|---|
| 1 | JA4T | <1 day | FoxIO 1.1 | High — works without any TLS |
| 2 | QUIC unwrap for existing JA4 | 1–2 days | BSD-3 | High — growing traffic share |
| 3 | JA4S | <1 day | FoxIO 1.1 | High — server-side, survives TLS 1.3 |
| 4 | JA4L/JA4LS | ~1 day | FoxIO 1.1 | Medium — geo/hop disambiguator |
| 5 | pcapng SHB/IDB extraction | <1 day | none (spec is public) | High — see Part B.4 |
| 6 | CT-log offline snapshot | ~1 day | none (public logs) | Medium — TLS 1.2 only |
| 7 | JA4X | 1–2 days | FoxIO 1.1 | Medium — TLS 1.2 only, hit-rate UNVERIFIED |
| 8 | JA4SSH | ~1 day | FoxIO 1.1 | Low-medium — narrow protocol |
| 9 | Auxiliary shape scoring | ~1 day | none | Low — must not overclaim |
| 10 | JA4H | <1 day | FoxIO 1.1 | Low for this tool — needs cleartext HTTP |
| — | JA4TScan, ML site classifier, live CT/pDNS | N/A | — | **Not recommended** — see §A.7 |

### Part B — field list, standard + tag

REQUIRED = a named standard asks for it. RECOMMENDED = good practice / partially named / already
built. OVER-COLLECTION = not asked for by any standard reviewed, and privacy cost exceeds evidentiary
value.

| Field | Standard (verified) | Tag | Status in NetForensiq today |
|---|---|---|---|
| Hash value(s) + algorithm | SWGDE §9; BSA Schedule (verbatim) | REQUIRED | ✅ built |
| Acquiring person's name/title | SWGDE §9; NIST 800-86 §3 | REQUIRED | ✅ built (`collected_by`) |
| Acquisition date/time + timezone | SWGDE §9 | REQUIRED | ✅ built, IST-rendered |
| Imaging/capture tool name + version | SWGDE §9 | REQUIRED | ❌ gap — not on `EvidenceRecord`; recoverable from pcapng `shb_userappl` (§B.4) |
| Unique device identifiers (make/model/serial/asset tag) | SWGDE §9; BSA Schedule | REQUIRED | ✅ built |
| Source/location of evidence | SWGDE §9; BSA Schedule (`seized_from`) | REQUIRED | ✅ built |
| Investigation identifiers (case, FIR) | SWGDE §9; BNSS (via `Case` model) | REQUIRED | ✅ built |
| Chain-of-custody transfer log (who/when/why) | SWGDE §9 (custody sub-list); NIST 800-86 §3 | REQUIRED | ✅ built, hash-chained (`CustodyEvent`) — exceeds what eSakshya does (§B.2) |
| Errors encountered during acquisition | SWGDE §9 | RECOMMENDED | ❌ gap — foldable into `acquisition_notes` or a new field |
| Clock NTP-sync state | NIST 800-86 §4.4/§5 | REQUIRED | ✅ built (`timesource.py`) |
| Capturing interface name | SWGDE §9 (as "type of acquisition") | RECOMMENDED | ⚠️ exists on `CaptureSession.interface`, not surfaced onto sealed `EvidenceRecord` |
| pcapng `shb_hardware`/`shb_os`/`shb_userappl` | No standard names this exactly; directly serves SWGDE's "tool and version" ask | RECOMMENDED | ❌ gap — see §B.4, cheapest fix in this document |
| pcapng `if_tsresol`/`if_tzone`/`if_tsoffset` | Serves NIST 800-86's clock-reliability concern | RECOMMENDED | ❌ gap — see §B.4 |
| Officer's badge number | Not named by NIST/SWGDE; standard Indian policing practice | RECOMMENDED | ✅ built (`CustodyEvent.actor_badge`) |
| Operator's Django account/login (beyond badge) | Not named | OVER-COLLECTION if duplicative | N/A — not a field, correctly |
| Capturing machine's hostname | Not directly named | RECOMMENDED, low priority | ❌ not built; low value on a fixed lab machine |
| Capturing machine's NIC MAC/hardware serial | Not named by any standard reviewed | **OVER-COLLECTION** | N/A — correctly not built |
| Officer's personal device details | Not applicable / DPDP data-minimisation instinct (UNVERIFIED at specific-section level) | **OVER-COLLECTION** | N/A — correctly not built |

---

## Sources fetched directly in this research pass (✅ primary)

- github.com/FoxIO-LLC/ja4 — README.md, LICENSE, LICENSE-JA4, technical_details/JA4.md,
  technical_details/JA4H.md, technical_details/README.md, python/ja4h.py, python/ja4x.py,
  rust/ja4/src/tls.rs, rust/ja4/src/tcp.rs, rust/ja4/src/ssh.rs, rust/ja4/src/time/tcp.rs,
  rust/ja4/src/time/udp.rs
- RFC 9001 (datatracker.ietf.org), §5.2 — QUIC Initial-packet salt and confidentiality statement
- draft-ietf-opsawg-pcapng-03 and -05 (ietf.org / datatracker.ietf.org) — option code tables,
  block-type codes, `if_tsresol` encoding
- NIST SP 800-86 (nvlpubs.nist.gov) — §3 (Data Collection), §4.4/§5 (clock reliability)
- SWGDE 17-F-002-2.1, "Best Practices for Computer Forensic Acquisitions" (swgde.org, 5 Aug 2025) —
  §9 Documentation, in full
- This repository: `backend/capture/tls_fingerprint.py`, `features.py`, `models.py`;
  `backend/evidence/models.py`, `service.py`, `certificate_pdf.py`, `timesource.py`;
  `backend/capture/upload.py`, `service.py`, `home_net.py`, `reassembly.py` (grepped for the
  pcap-reading path)

## Sources used only secondarily (⚠️) or left UNVERIFIED

- TLS 1.2 live-traffic-volume fraction — UNVERIFIED at a precise figure (§A.2)
- ECH deployment percentages — ⚠️ secondary only, RFC 9849 not independently fetched
- ISO/IEC 27037 and 27042 clause-level content — ⚠️/UNVERIFIED, standard is paywalled
- CFSL/DFSL public SOP for network evidence — UNVERIFIED, not located
- DPDP Act 2023 §17 — ⚠️ fetched via search summary, not the bare act itself this pass; no specific
  provision found addressing officer-workstation-metadata collection directly
