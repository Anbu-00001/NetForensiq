# SPEC 02 — Detection Algorithms

NetForensiq (KANAD S.H.I.E.L.D. 2026) — explainable, rule-first detection logic for bidirectional
flow records with sourced parameter values. Every threshold below is either (a) quoted/derived
directly from a primary source (RFC, tool source code, vendor doc, paper), with a citation, or
(b) explicitly marked **[OUR HEURISTIC]** when no citable value exists. Where two sources conflict
(e.g. a tool's own docs vs. its current source code), both are shown and the one we implement is
stated explicitly.

Flow schema assumed (from NetForensiq's aggregator): `packets_sent/recv`, `bytes_sent/recv`,
`duration`, `avg_pkt_size`, `pkts_per_sec`, `bytes_ratio`, `payload_entropy` (sampled Shannon
entropy, bits/byte), `tcp_flags_seen`, `app_protocol`, `dns_query_count`, `longest_dns_label`,
`http_host`, `tls_sni`.

---

## 1. C2 Beaconing / Periodic Callback Detection

### Signal
An internal host repeatedly contacts the same external host/port at intervals that are more
*regular* (low jitter, symmetric distribution) than human- or application-driven traffic, often
with similar-sized payloads each time (a heartbeat "check-in").

### Algorithm — RITA's beacon score (verified against primary source, not just docs)

We read RITA's (Active Countermeasures) actual current source, not just its marketing docs,
because the two disagree — see note below. Primary sources fetched and inspected directly:

- `pkg/beacon/Readme.md` (documented spec) — https://github.com/activecm/rita-legacy/blob/main/pkg/beacon/Readme.md
- `pkg/beacon/analyzer.go` (actual running code) — https://github.com/activecm/rita-legacy/blob/main/pkg/beacon/analyzer.go
- `etc/rita.yaml` (shipped defaults) — https://github.com/activecm/rita-legacy/blob/main/etc/rita.yaml

**What RITA actually computes (4 independent subscores, weighted average):**

1. **Timestamp (TS) score** — regularity of inter-arrival intervals.
   - Compute inter-arrival deltas between consecutive connections, sort them.
   - **Bowley skewness**: `tsSkew = (Q1 + Q3 − 2·Q2) / (Q3 − Q1)` over the interval distribution
     (Q1/Q2/Q3 = 25th/50th/75th percentile of intervals). Only computed if `Q3−Q1 ≥ 10` (seconds)
     and `Q2 ≠ Q1` and `Q2 ≠ Q3` (Bowley skew is undefined/unreliable otherwise); else skew = 0.
     A beacon's intervals should be symmetric around the median → skew ≈ 0.
   - `tsSkewScore = 1 − |tsSkew|`
   - **Dispersion**: Median Absolute Deviation about the median (MADM) of intervals.
     `tsMadmScore = max(0, 1 − tsMadm / tsMid)` (`tsMid` = median interval, in the *current*
     code — see discrepancy note below).
   - `tsScore = ceil(((tsSkewScore + tsMadmScore) / 2) × 1000) / 1000`

2. **Data-size (DS) score** — regularity of per-connection byte counts (originating bytes).
   - Same Bowley skew and MADM treatment applied to the sorted list of per-connection sent-byte
     values.
   - `dsSkewScore = 1 − |dsSkew|`
   - `dsMadmScore = max(0, 1 − dsMadm / dsMid)`
   - **Smallness**: `dsSmallnessScore = max(0, 1 − dsMode / 65535)` — rewards beacons whose modal
     payload size is small (C2 heartbeats are typically small; 65535 = max TCP window/packet size
     used as the normalizing ceiling).
   - `dsScore = ceil(((dsSkewScore + dsMadmScore + dsSmallnessScore) / 3) × 1000) / 1000`

3. **Duration score** — how much of the observation window the beacon activity actually spans.
   - `coverageScore = (last_conn_ts − first_conn_ts) / (dataset_max_ts − dataset_min_ts)`, capped
     at 1.0.
   - `consistencyScore = longestConsecutiveHourRun / DurationConsistencyIdealHoursSeen`, capped at
     1.0 (rewards a beacon that fires in *every* hour for a long consecutive stretch).
   - `durScore = max(coverageScore, consistencyScore)`, only computed once
     `DurationMinHoursSeen` (default **6** hours) of activity is seen.

4. **Histogram score** — shape of the per-hour connection-count histogram.
   - `cvScore = 1 − CoefficientOfVariation(hourly connection counts)` (rewards a flat, uniform
     rate of connections per hour — classic 24/7 beacon behavior).
   - `bimodalFitScore` rewards histograms with 2–3 distinct flat "plateau" sections (e.g. a
     beacon that only runs during business hours), computed once
     `HistogramBimodalMinHoursSeen` (default **11** hours) of activity is seen.
   - `histScore = max(cvScore, bimodalFitScore)`

**Final score:**
```
score = ceil((tsScore·W_ts + dsScore·W_ds + durScore·W_dur + histScore·W_hist) × 1000) / 1000
```
Default weights `W_ts = W_ds = W_dur = W_hist = 0.25` (must sum to 1.0; RITA lets an analyst
re-weight, e.g. drop `W_dur`/`W_hist` to 0 for a pure timing/size score).

**Important discrepancy we found and are flagging honestly:** RITA's own `Readme.md`
(documented 2022-05-24) states `ts.score = (1/3)·[(1−|skew|) + max(1−MADM/30,0) + connCountScore]`
— i.e. a *fixed* 30-second MADM divisor and a third "connection density" subscore
(`connections / (duration_seconds/90)`, capped at 1.0). The **current `analyzer.go` code no
longer does this** — it divides MADM by the *median interval itself* (`tsMid`), not a fixed 30,
and has folded connection density out of `tsScore` (duration/histogram are now separate
top-level subscores instead). **We implement the code's current 2-component TS score / 3-component
DS score / weighted-4-way final score, not the stale README formula**, and note this for the
judges as evidence we read the source rather than trusting the docs.

**Alternative/complementary approaches (Fourier/autocorrelation).** Frequency-domain methods
(FFT on the inter-arrival histogram, or autocorrelation of a binned time series looking for a
strong peak at the beacon period) are described in vendor blogs (Palo Alto, Cisco Cognitive
Threat Analytics) and some academic work, but **we could not find a primary source that
publishes concrete, reproducible parameter values** (peak-prominence threshold, FFT window
size) the way RITA's GitHub source publishes its constants. We therefore do **not** specify FFT
as a first-class rule; if implemented, treat peak-prominence thresholds as
**[OUR HEURISTIC]** and keep RITA's statistical score as the primary, defensible method.

### Parameters table

| Parameter | Value | Source |
|---|---|---|
| Minimum connections to score a pair | **23** (`DefaultConnectionThresh`, hard floor enforced by RITA — cannot be set lower) | `etc/rita.yaml` — reasoning given in-file: "hosts that have fewer than at least one connection per hour could significantly increase both the analysis time and the number of false positives" — https://github.com/activecm/rita-legacy/blob/main/etc/rita.yaml |
| Subscore weights | 0.25 / 0.25 / 0.25 / 0.25 (TS/DS/Duration/Histogram), must sum to 1.0 | `etc/rita.yaml`, same file |
| Bowley skew reliability floor | `Q3 − Q1 ≥ 10` (else skew forced to 0) | `pkg/beacon/analyzer.go` line ~123, 127 |
| Duration min hours before duration score computed | 6 hours (`DurationMinHoursSeen`) | `etc/rita.yaml` |
| Duration "ideal" consistency window | 12 hours (`DurationConsistencyIdealHoursSeen`, half a day) | `etc/rita.yaml` |
| Histogram bimodal min hours | 11 hours (`HistogramBimodalMinHoursSeen`) | `etc/rita.yaml` |
| DS smallness normalizer | 65535 bytes | `pkg/beacon/analyzer.go` |
| Practitioner alert threshold on final score | **> 0.8**, prioritize **≥ 0.85** for triage | Community/practitioner guidance (Black Hills InfoSec blog; Cyb3r-Monk's KQL reimplementation uses `ScoreThreshold = 0.85`), **not** a RITA-shipped default — RITA itself just ranks/sorts, it does not hard-cut. Label this row **[OUR HEURISTIC, informed by practitioner sources]**. |
| TRW connections-to-decide (statistical validity floor, general SPRT reasoning, cross-reference §3) | 4–5 | Jung, Paxson, Berger, Balakrishnan (2004) — see §3 |

### False positives
- **Legitimate polling software**: NTP, monitoring/heartbeat agents (Nagios, Zabbix, SNMP
  polling), software update checkers, cloud SDK keep-alives, Slack/Teams/Zoom presence pings —
  all produce genuinely regular, low-jitter, small-payload connections and will score *high* on
  RITA's formula. This is a well-known, acknowledged limitation of interval-regularity scoring,
  not a flaw unique to our implementation.
- **CDN/anycast infrastructure**: repeated connections to the same *logical* CDN endpoint may
  actually hit different backend IPs, breaking the "unique connection pair" grouping and hiding
  real regularity, or conversely a busy shared destination IP can look like many hosts beaconing
  to it.
- Mitigation used by RITA itself: `CompromisedDeviceCountMax` (Cyb3r-Monk KQL reimplementation
  default 5) — de-prioritize a destination if too many distinct internal hosts beacon to it
  (mass-adoption legitimate service, e.g. Windows Update, rather than targeted C2).
- **Known-jitter evasion**: malware authors have read RITA's source (it's open-source) and add
  randomized sleep jitter specifically to defeat MADM/skew scoring — a beacon score alone should
  never be treated as ground truth; combine with destination reputation, JA3, and rarity
  (how many other internal hosts talk to this destination).

### Implementation notes
- Group by (internal IP, external IP, external port, protocol) — RITA's "unique connection pair."
- Exclude zero-length intervals (repeat/retransmit noise) before computing skew/MADM — RITA does
  this explicitly (`diffNonZeroIdx`).
- Round percentile index as `round(p × (n−1))`, 0-indexed, matching RITA's Go implementation
  (`util.Round(.25*float64(diffLength-1))`), not the "official" NIST/Excel percentile methods —
  this specific interpolation choice materially changes skew/MADM values at low `n`.

---

## 2. DNS Tunneling Detection

### Signal
A tunneling channel (iodine, dnscat2, dns2tcp, custom) encodes application data into the
subdomain/labels of DNS queries against a domain the attacker controls, producing queries that
are longer, higher-entropy, more frequent, and more type-skewed (TXT/NULL) than normal.

### Algorithm & thresholds

**Structural ceiling (hard RFC limit, not itself a signal — but bounds what "abnormal" means):**
RFC 1035 §2.3.4/§3.1: a DNS **label** is limited to **63 octets**, a full **name** to **255
octets**. Source (primary, fetched and quoted directly):
https://www.rfc-editor.org/rfc/rfc1035 — "the remaining six bits of the length field limit the
label to 63 octets or less" / "the total length of a domain name … is restricted to 255 octets
or less." Tunneling tools that want throughput push labels toward this 63-octet ceiling
repeatedly, which ordinary hostnames essentially never do.

**Label length threshold**: Farnham & Atlasis, *Detecting DNS Tunneling* (SANS/GIAC, 2013),
using time-interval, request-size, record-type, and subdomain-entropy features, is the paper
most frequently cited by later tools/papers for this problem
(https://www.sans.org/white-papers/34152/, GIAC record
https://www.giac.org/paper/gcia/1116/detecting-dns-tunneling/108367). Multiple secondary
sources attribute a **>52-character hostname** flag to this paper. **We were not able to fetch
the original PDF text directly to re-verify this number against primary text** (SANS reading-room
PDFs returned 403/were not retrievable in this session) — treat the 52-char figure as
**moderate-confidence, secondary-sourced**, not independently verified. We recommend implementing
it but logging it as `farnham_2013_unverified` in code comments so a reviewer knows to re-check
if precision matters.

**Query-type distribution**: normal client traffic is dominated by A/AAAA queries. Tunneling
tools default to record types chosen for larger response payloads:
- **iodine** — defaults to **NULL** records, auto-negotiates up to TXT/SRV/MX/CNAME/A if NULL is
  filtered. Source: iodine project documentation / widely-replicated tool behavior description.
- **dnscat2** — defaults to **TXT, CNAME, MX** (adds A/AAAA only for client→server direction).
- **dns2tcp** — uses **TXT** records.

A host issuing an elevated share of TXT/NULL queries to one destination domain, especially
combined with high query *rate* to that single domain, is the actionable multi-feature signal —
no single authoritative "normal TXT %" baseline was found in the literature, so the **exact
ratio threshold is [OUR HEURISTIC]** (see table).

**Unique-subdomain-count per parent domain**: heavy, DGA-style random-subdomain attacks are
sometimes described with thresholds in the thousands of unique subdomains/domain/day range in
patent literature (USPTO filings on DNS-tunneling detection cite figures like 10,000), which we
treat as **weak/non-academic sourcing** — flagged **[OUR HEURISTIC]** with a much lower,
flow-forensics-appropriate number since NetForensiq operates on a single capture/session, not a
resolver's daily aggregate.

**NXDOMAIN ratio — important scoping correction.** NXDOMAIN-ratio is primarily a signal for
**DGA-based malware C2** (the malware guesses many candidate domains, most of which are
unregistered → NXDOMAIN), **not** classic DNS tunneling. In DNS tunneling the attacker owns the
authoritative zone, so tunneling queries almost always resolve successfully (NOERROR) — a high
NXDOMAIN ratio on its own should not be presented as a tunneling indicator; keep it as a
*separate* DGA-oriented signal so the tool's explanations to a panel remain technically accurate.

**Entropy of subdomain labels**: information-theoretic ceilings are exact and citable —
Base64 alphabet (64 symbols) → max entropy `log2(64) = 6.0` bits/char; Base32 (32 symbols) →
`log2(32) = 5.0` bits/char; hex (16 symbols) → `log2(16) = 4.0` bits/char. Ordinary
English-word-based hostnames measured over the DNS label alphabet typically sit well below
their alphabet's ceiling (structured language has heavy redundancy). The academic treatment
closest to this (Springer book chapter, "Information-Entropy-Based DNS Tunnel Prediction," 2018,
https://link.springer.com/chapter/10.1007/978-3-319-99277-8_8) is paywalled — **we could not
verify its exact numeric cutoff from primary text**, so the specific bits/char cutoff we
implement is **[OUR HEURISTIC]**, but it is grounded in the exact alphabet-size math above
(not arbitrary).

### Parameters table

| Parameter | Value | Source |
|---|---|---|
| Max DNS label length | 63 octets (hard ceiling) | RFC 1035 §2.3.4/§3.1 (primary, fetched) |
| Max DNS name length | 255 octets (hard ceiling) | RFC 1035 §2.3.4/§3.1 (primary, fetched) |
| Suspicious label length | **> 52 characters** | Farnham & Atlasis 2013 (SANS/GIAC) — attribution via secondary sources, **not independently verified against primary PDF**; flag as moderate confidence |
| Suspicious label entropy | **[OUR HEURISTIC]** mean label entropy > 3.5 bits/char, over labels ≥ 20 chars | Grounded in Base32/64/hex alphabet-entropy ceilings (exact math above); no single cited universal cutoff found |
| TXT+NULL query-type share (per source→domain, rolling window) | **[OUR HEURISTIC]** > 30% | No cited "normal baseline %" found; grounded in iodine/dnscat2/dns2tcp defaulting to these types |
| Unique subdomains per parent domain (per session) | **[OUR HEURISTIC]** > 50 unique subdomains under one registrable domain within the capture window | Weakly informed by USPTO filing figures (10,000/day at resolver scale); scaled down for session-level flow analysis |
| Query rate to single domain | **[OUR HEURISTIC]** > 5 queries/sec sustained for 30s to one registrable domain | No authoritative source found |
| NXDOMAIN ratio | Track separately as a **DGA/C2 domain-generation** signal, not a tunneling signal | Reasoning above (attacker owns tunneling zone) |

### False positives (MUST be whitelisted — this is what makes a demo credible)
- **CDN edge hostnames**: Akamai (`*.akamai.net`, edge hostnames with long hashed labels),
  Amazon **CloudFront** (`d111111abcdef8.cloudfront.net` — random 13-char distribution IDs),
  Fastly, Azure (`*.blob.core.windows.net`, `*.azureedge.net`), Google Cloud CDN — all produce
  long, high-entropy-looking subdomains as a matter of normal operation.
- **AV/reputation cloud lookups**: McAfee GTI (queries encode a file-hash-derived subdomain
  against `*.avqs.mcafee.com`), Sophos SXL (`*.sophosxl.net` / `sophosxl.com`), Trend Micro
  reputation services (`ipas.trendmicro.com` and related), Symantec/Broadcom IP reputation. These
  legitimately look identical in *shape* to tunneling: long pseudo-random subdomain, high query
  rate, TXT/A lookups.
- **DNSBLs (RBL/DNSWL lookups)**: reversed-IP queries against `zen.spamhaus.org` and similar zones
  are structurally "a label built from encoded data" and must be allow-listed by suffix.
- **SPF/DKIM mail-auth lookups**: RFC 7208 caps SPF evaluation at **10 DNS mechanism lookups**
  and **2 "void" lookups** per check (RFC 7208 §4.6.4) — a mail server doing SPF/DKIM checks
  against `_spf.google.com`, `_spf.salesforce.com`, `selector1._domainkey.*` etc. generates
  bursts of subdomain-heavy queries that are entirely legitimate.
- **Cloud telemetry**: Microsoft/Office 365 (`*.events.data.microsoft.com`), Dropbox client
  sync/telemetry, Windows Update / Delivery Optimization — all issue frequent queries with long
  or opaque-looking subdomains.
- **Implementation note**: ship a suffix allow-list (`*.akamai.net`, `*.cloudfront.net`,
  `*.akamaiedge.net`, `*.sophosxl.net`, `*.avqs.mcafee.com`, `*.spamhaus.org`,
  `*.events.data.microsoft.com`, `*.blob.core.windows.net`, `_spf.*`, `*.domainkey.*`) checked
  **before** scoring, and log what was suppressed for auditability.

### Implementation notes
- Score at the (source host, registrable parent domain) granularity, not per-query.
- Compute entropy over the full label string using the standard Shannon formula on a per-character
  frequency table (matches what NetForensiq already does for payload entropy — reuse the same
  function for consistency).
- Present NXDOMAIN-ratio and tunneling-signal scores as **separate, clearly labeled** outputs in
  the UI so an investigator doesn't conflate DGA malware with DNS tunneling.

---

## 3. Port Scan Detection

### Algorithms

**A. TRW — Threshold Random Walk** (Jung, Paxson, Berger, Balakrishnan, *Fast Portscan Detection
Using Sequential Hypothesis Testing*, IEEE Symposium on Security & Privacy, Oakland, 2004).
Primary source fetched and read in full: https://www.icir.org/vern/papers/portscan-oak04.pdf

TRW models each connection attempt from a remote host as a Bernoulli trial `Y_i` coding whether
the target address/port behaves like a "used" (responsive) destination or not, and runs a
**sequential probability ratio test (Wald's SPRT)** between two hypotheses:
- `H0` (benign remote host): `Pr[Y_i | H0]` parameterized by `θ0`
- `H1` (scanner): `Pr[Y_i | H1]` parameterized by `θ1`, with `θ0 > θ1` (a scanner hits far more
  unused/non-responsive addresses than a benign host, which targets real services it already
  knows about).

After each observation, the running likelihood ratio `Λ(Y)` is compared against two thresholds
`η0` (accept H0) and `η1` (accept H1), derived from user-chosen false-positive/false-negative
targets `α`, `β` via Wald's classical bounds:
```
η1 ≤ β / α         η0 ≥ (1 − β) / (1 − α)
```
The paper's own worked example (quoted directly from the paper, §4.4): with **α = 0.01**,
**β = 0.99**, **θ0 = 0.8**, **θ1 = 0.2**, the expected number of connection attempts needed to
reach a decision under H1 is **E[N|H1] = 5.4** — this is the paper's own basis for its abstract's
claim of detecting a scanner in **"4 or 5 connection attempts in practice."**

**B. Threshold/count-based detection** — the simpler, far more widely deployed method, used by
Zeek and Snort/Suricata's rule engines: count distinct ports (vertical) or distinct destination
hosts (horizontal) touched by one source within a sliding time window, alert past a threshold.

### Real tool defaults (all fetched directly from primary source repos)

**Zeek — legacy `scan.zeek`** (https://github.com/zeek/zeek — fetched
`scripts/policy/misc/scan.zeek` at tag v6.0.9/v6.1):
- `port_scan_threshold = 15.0` distinct ports with **failed** connections to one victim host
- `addr_scan_threshold = 25.0` distinct victim hosts with failed connections on one port
- both tracked over a **5-minute** (`port_scan_interval` / `addr_scan_interval`) sliding window
- **This script is `@deprecated`, unmaintained since 2013**, and Zeek's own source explicitly
  tells operators to install the community package instead: *"Remove in v6.1. Use the external
  github.com/ncsa/bro-simple-scan package instead… The misc/scan.zeek script hasn't been
  maintained since 2013."* (quoted directly from the script's own deprecation annotation).

**Zeek — current recommended package, `ncsa/bro-simple-scan`**
(https://github.com/ncsa/bro-simple-scan, fetched `scripts/scan.zeek`):
- `scan_threshold = 25` — unique host+port combinations with failed connections, for a
  **remote**-sourced scanner
- `local_scan_threshold = 250` — same, for a **local** (internal)-sourced scanner (higher because
  internal hosts legitimately touch many services, e.g. backup/monitoring agents)
- `scan_timeout = 15min` — a rolling "not seen again for this long → expire" window (not a fixed
  bucket)
- `dark_host_threshold = 3` — hits on unused/"darknet" address space; once exceeded, the bar for
  full scan detection drops sharply: `scan_threshold_with_darknet_hits = 10` (remote),
  `local_scan_threshold_with_darknet_hits = 100` (local)
- `knockknock_threshold = 20` — unique **hosts** probed on a **single port** from one source
  (a horizontal single-port sweep variant), or **3** if darknet hits are involved

**Snort 3 — `port_scan` inspector** (Cisco Talos, actively maintained; the modern successor to
legacy Snort 2's `sfPortscan` preprocessor; fetched `src/network_inspectors/port_scan/ps_module.cc`
from https://github.com/snort3/snort3):
- Four canonical scan-type categories, matching the standard vertical/horizontal taxonomy —
  quoted directly from the source's own parameter descriptions:
  - **`portscan`** — "one-to-one" — many ports, one host → **vertical scan**
  - **`portsweep`** — "one-to-many" — one port, many hosts → **horizontal scan**
  - **`decoy_portscan`** — "one-to-one decoy" — vertical scan with spoofed decoy sources mixed in
  - **`distributed_portscan`** — "many-to-one" — many sources hitting one target
- Default per-scan-type thresholds (all from `scan_params` defaults in `ps_module.cc`):
  `scans = 100` (total attempts), `rejects = 15` (attempts with a negative/failed response),
  `nets = 25` (distinct target-IP changes seen), `ports = 25` (distinct port/protocol changes
  seen).
- Time windows (`tcp_window`, `udp_window`, `ip_window`, `icmp_window`) default to **0**, meaning
  no fixed expiry — tracking is adaptive/connection-count-driven rather than a fixed clock window
  by default.

**Suricata** — confirmed it has **no dedicated sfPortscan-equivalent preprocessor**; Suricata does
port-scan detection through ordinary signatures plus its generic `threshold.config` /
`detection_filter` keyword mechanism (`type both|threshold|limit`, `track by_src|by_dst`,
`count N`, `seconds T`). Illustrative community rules (ET Open-style, from search-derived
examples, **not independently re-verified against a live ruleset fetch — moderate confidence**):
an Nmap `-sS` SYN-scan signature keyed on TCP window size 2048, thresholded `type both, track
by_src, count 1, seconds 60`; a custom SYN-flood-style rule alerting at 20 SYNs from one source
within 70 seconds. Because Suricata ships no single authoritative default the way Zeek/Snort 3
do, **treat any specific Suricata count/seconds pair as [OUR HEURISTIC] unless pulled from a
live, version-pinned ET-Open `emerging-scan.rules` file.**

### Parameters table

| Parameter | Value | Source |
|---|---|---|
| TRW target FP rate α | 0.01 | Jung et al. 2004, worked example |
| TRW target detection rate β | 0.99 | Jung et al. 2004, worked example |
| TRW θ0 (benign "used-address" hit rate) | 0.8 | Jung et al. 2004, worked example |
| TRW θ1 (scanner "used-address" hit rate) | 0.2 | Jung et al. 2004, worked example |
| TRW expected attempts to decide | **5.4** (≈ "4 or 5") | Jung et al. 2004, Eq. 14 worked example |
| Zeek legacy vertical scan | 15 distinct ports / 5 min (failed conns) | `scan.zeek` v6.0.9 (deprecated) |
| Zeek legacy horizontal scan | 25 distinct hosts / 5 min (failed conns) | `scan.zeek` v6.0.9 (deprecated) |
| Zeek current (bro-simple-scan) remote scanner | 25 unique host+port combos / 15-min rolling | `ncsa/bro-simple-scan` `scan.zeek` |
| Zeek current (bro-simple-scan) local scanner | 250 unique host+port combos / 15-min rolling | `ncsa/bro-simple-scan` `scan.zeek` |
| Zeek darknet-hit accelerant | 3 dark-IP hits → threshold drops to 10 (remote) / 100 (local) | `ncsa/bro-simple-scan` `scan.zeek` |
| Snort 3 vertical/horizontal default | scans=100, rejects=15, nets=25, ports=25 | `snort3` `ps_module.cc` (Cisco Talos) |
| Suricata scan-window example | count 1–20 / 60–70 sec | Community ET-style rules, **[unverified, moderate confidence]** |

### False positives
- **Vertical**: application servers that legitimately open many ports to one client (media/RTP
  negotiation, FTP passive mode, game servers) — allow-list known multi-port protocols.
- **Horizontal**: load balancers/health-checkers, vulnerability scanners run *by the org itself*
  (Nessus/Qualys/internal red team), monitoring systems (Nagios, Zabbix, SNMP walks), and
  peer-to-peer/BitTorrent DHT traffic all look like horizontal sweeps.
- **Both**: NAT'd networks where many real users share one source IP; treat the reject-rate signal
  (Snort 3's `rejects`, Zeek's "failed connections only" tracking) as important — a busy NAT gateway
  making many *successful* connections should score very differently from one making many
  *failed* ones.
- TRW's own framing is explicitly designed to reduce this class of FP: because it conditions on
  the ratio of failed-vs-successful attempts rather than raw connection count, a NAT'd host making
  hundreds of successful connections to real, popular services does not trigger it the way a
  fixed-count rule would.

### Implementation notes
- Distinguish "failed" from "successful" using TCP flags already captured in the flow schema
  (`tcp_flags_seen`): SYN-only / SYN+RST / SYN-no-ACK-response = half-open/failed;
  SYN+SYN-ACK+ACK = established. This directly implements Zeek's and Snort's "track failed
  connections" behavior without needing raw packet replay.
- Implement both a **vertical** (ports-per-host) and **horizontal** (hosts-per-port) counter keyed
  by source IP, matching Snort 3's `portscan`/`portsweep` split, since they have different FP
  profiles and should be surfaced as different alert types to the investigator.

---

## 4. Data Exfiltration Detection

### Signal
Large or sustained outbound-heavy transfers, especially with encrypted/compressed-looking payload
and/or occurring at anomalous times relative to a host's own baseline.

### Volume asymmetry
No single authoritative fixed outbound:inbound ratio was found in the literature — real practice
is highly deployment-dependent. Practitioner guidance (Fidelis Security) notes many
organizations alert on absolute outbound volume around **1 GB or higher** per session/day as a
starting point, explicitly acknowledging attacker rate-limiting (e.g. ~50 MB/hour chunking to
stay under such caps) as a known evasion. This is a coarse operational figure, not a research
result — **treat as [OUR HEURISTIC], informed by practitioner reporting, not derived**. Our flow
schema already carries `bytes_ratio`; the concrete implementable rule we propose:
**[OUR HEURISTIC]** flag when `bytes_sent : bytes_received > 10 : 1` **and** `bytes_sent` exceeds
an absolute floor (e.g. 50 MB) — the ratio alone over-fires on tiny flows (a single large upload
button click).

For the **DNS-channel-specific** case of exfiltration, one academic result is concretely citable:
"Information-Based Heavy Hitters for Real-Time DNS Data Exfiltration Detection and Prevention"
(arXiv:2307.02614) reports their method (ibHH) detecting exfiltration down to **0.7 bytes/second**
sustained rate at a **1% false-positive rate** — but this figure is specific to their DNS-query
heavy-hitter method and dataset, not a general network-flow rule; cite it only when discussing
the DNS-tunneling/exfil overlap case, not as a general TCP exfiltration threshold.

### Entropy threshold — verified against a real tool's shipped defaults
The commonly repeated claim "entropy ≥ 7.0 bits/byte signals encryption" is folklore-level in
security blogs. We traced it to its most defensible root and its most *precise, implementable*
form:

- **Qualitative origin**: Lyda & Hamrock, *Using Entropy Analysis to Find Encrypted and Packed
  Malware*, IEEE Security & Privacy 5(2), 2007 (DOI: 10.1109/MSP.2007.48) established that
  packed/encrypted binary sections show measurably higher entropy than native code sections. We
  could **not** retrieve the exact numeric cutoff from the primary text in this session (paywalled
  mirrors returned 403) — cite it for the qualitative finding only.
- **Precise, citable, implementable numbers**: **binwalk** (ReFirmLabs; widely used firmware/
  binary forensics tool), source fetched directly
  (https://github.com/ReFirmLabs/binwalk/blob/v2.3.4/src/binwalk/modules/entropy.py):
  ```python
  DEFAULT_BLOCK_SIZE = 1024
  DEFAULT_TRIGGER_HIGH = .95   # normalized entropy, 0-1 scale → 7.6 bits/byte
  DEFAULT_TRIGGER_LOW  = .85   # → 6.8 bits/byte
  ```
  binwalk computes entropy over 1024-byte blocks and reports it on a normalized 0–1 scale
  (`ORDER = 8`, i.e. `entropy_bits_per_byte / 8`). Its shipped "rising edge" trigger for
  "entering a compressed/encrypted region" is **0.95 × 8 = 7.6 bits/byte**; its "falling edge"
  (returning to normal) is **0.85 × 8 = 6.8 bits/byte**. **We recommend implementing these two
  values (7.6 / 6.8 bits/byte on 1024-byte blocks) rather than the folklore "7.0"** — they come
  from an actual, widely-deployed tool's source code, not a blog repetition chain.

### Why entropy alone false-positives badly on TLS/HTTPS — and how we handle it
The overwhelming majority of web traffic is now TLS-encrypted (well above 90% per browser
telemetry from Chrome/Firefox transparency reporting), and **any** TLS record's application-data
payload is, by design, close to maximal entropy (~7.9–8.0 bits/byte) — legitimate banking traffic
and malicious C2/exfiltration are statistically indistinguishable by entropy alone. This is
reinforced by "Reliable Detection of Compressed and Encrypted Data" (arXiv:2103.17059), whose own
ML-based classifier (EnCoD) — built specifically because simple entropy fails — only reaches
82–92% accuracy on the *easier* task of telling compressed from encrypted data at all, and states
plainly that "current approaches consistently fail to distinguish encrypted and compressed data."
**Mitigation**: never gate an exfiltration alert on entropy alone. Combine entropy with (a) volume
asymmetry, (b) destination novelty/rarity (has this internal host talked to this external IP/SNI
before), (c) off-hours timing, and (d) absence of a legitimate TLS SNI/JA3 match to known-good
software. Entropy should demote/promote a score, never gate it standalone.

### Off-hours / baseline-deviation approach
**[OUR HEURISTIC]** — no single cited canonical threshold exists for "off-hours." Recommended
implementable rule: maintain a per-host (or per-subnet-role) rolling baseline of `bytes_sent` by
hour-of-day/day-of-week over a trailing window (e.g. 14 days); flag a flow's volume as anomalous
if it exceeds the baseline mean by **> 3 standard deviations** for that host/hour bucket. This is
standard statistical process control practice, not a security-specific citation — labeled
heuristic accordingly.

### Parameters table

| Parameter | Value | Source |
|---|---|---|
| Entropy rising-edge (flag as compressed/encrypted) | **7.6 bits/byte** (0.95 × 8), 1024-byte blocks | binwalk v2.3.4 `entropy.py`, primary source |
| Entropy falling-edge | **6.8 bits/byte** (0.85 × 8) | binwalk v2.3.4 `entropy.py`, primary source |
| Volume ratio | **[OUR HEURISTIC]** outbound:inbound > 10:1 AND bytes_sent > 50 MB | Loosely informed by Fidelis practitioner guidance (~1 GB absolute alerts common) |
| DNS-exfil sustained rate (DNS channel only) | 0.7 B/s at 1% FPR (their method, their dataset) | arXiv:2307.02614, ibHH |
| Off-hours deviation | **[OUR HEURISTIC]** > 3σ from per-host hourly baseline | Standard SPC practice, not security-specific |

### False positives
- Backups, VPN bulk sync, video-conferencing uploads, CI/CD artifact pushes, and any legitimate
  large HTTPS upload will trip volume+entropy rules; whitelisting by destination reputation
  (known SaaS backup/collab ranges) and requiring the off-hours/novelty co-signal is essential.
- Any already-compressed legitimate file type (zip, jpg, mp4, docx-as-zip) is high-entropy at
  rest and in transit — entropy on its own cannot separate "user uploaded a video" from
  "malware exfiltrated a database dump."

### Implementation notes
- Compute entropy on the same sampled-payload basis NetForensiq already uses; apply the two
  binwalk-derived thresholds as banding (low/medium/high suspicion) rather than a single cutoff.
- Score components (volume, entropy, novelty, off-hours) independently and combine as a
  **weighted, explainable checklist** shown to the investigator (e.g. "3 of 4 exfiltration
  indicators present") rather than a single opaque number — directly supports the explainability
  requirement in §7/§8.

---

## 5. ICMP Tunneling Detection

### Signal
ICMP tunneling tools (ptunnel/ptunnel-ng, icmpsh, icmptunnel) embed arbitrary application data
inside ICMP Echo Request/Reply payloads, which normally carry only small, fixed, low-entropy
filler.

### Normal baseline payloads (verified)
- **Linux** (`iputils` ping): default payload **56 bytes** of data (+8-byte ICMP header +
  20-byte IPv4 header = **84 bytes** total on the wire — the familiar `64(84) bytes` figure
  reported by `ping`).
- **Windows** ping: default payload **32 bytes**, and — unlike Linux's counting-byte pattern —
  Windows uses a **fixed, constant, repeating alphabetic pattern**: `abcdefghijklmnopqrstuvwabcdefghi`
  (hex `61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67
  68 69`). Maximum Windows ping payload (with `-l`) is **65,527 bytes**.
- These are extremely well-established, easily independently verifiable facts (`man ping` /
  Windows `ping /?` behavior); we cross-checked two independent write-ups and they agree exactly
  on both the byte counts and the Windows letter pattern.

### Anomaly signal
1. **Size**: any ICMP echo payload materially larger than the OS-default (56 on Linux, 32 on
   Windows) — especially payloads that **vary in size packet-to-packet within one "ping session"**
   — is anomalous. A normal `ping` run uses one fixed `-s`/`-l` size for the whole run; varying
   sizes indicate data-driven (not diagnostic) payloads.
2. **Content**: Windows's payload is a **constant** 32-byte pattern and Linux's is a
   **predictable, low-variance** filler — real ping traffic should show *near-zero byte-level
   entropy* and should be **byte-for-byte identical** across consecutive packets in a session. A
   session where payload bytes change between packets (beyond the sequence-number field) rules
   out ordinary `ping`.
3. **Entropy**: once size/constancy fails, apply the same entropy framework as §4 — payload
   entropy approaching 7.6–8 bits/byte (binwalk's own rising-edge threshold, reused here for
   consistency across the tool) indicates encoded/compressed tunnel data rather than diagnostic
   filler.
4. **Signature-based detection is explicitly not robust** — worth stating honestly to a panel.
   ptunnel's actively maintained fork, ptunnel-ng, ships a **user-configurable 32-bit magic
   number** (`opts.magic`, default `0xdeadc0de`) precisely to defeat static fingerprinting; its
   own `--magic` help text says outright: *"Set ptunnel magic hexadecimal number… (prevent Cisco
   WSA/IronPort fingerprint scan)"* — quoted directly from
   https://github.com/utoni/ptunnel-ng/blob/master/src/options.c. This is a direct, primary-source
   admission by a tool author that static byte-signature detection is trivially evaded, which is
   exactly why we lead with statistical (size/constancy/entropy) detection rather than magic-byte
   matching.

### Parameters table

| Parameter | Value | Source |
|---|---|---|
| Linux default ICMP payload | 56 bytes (84 bytes total on wire) | `iputils ping` behavior, widely verified |
| Windows default ICMP payload | 32 bytes, fixed pattern `abcdefghijklmnopqrstuvwabcdefghi` | Widely verified Windows `ping` behavior |
| Windows max ICMP payload | 65,527 bytes (`-l`) | Windows `ping` documentation |
| Anomalous payload size | **[OUR HEURISTIC]** > 100 bytes, or any intra-session size variance | No single authoritative cutoff found; grounded in the 32/56-byte OS baselines |
| Entropy flag | 7.6 bits/byte rising / 6.8 falling (reuse §4 binwalk thresholds) | binwalk v2.3.4, cross-referenced from §4 |
| ptunnel-ng default magic (do NOT rely on this as a signature) | `0xdeadc0de`, user-configurable | `ptunnel-ng` `src/options.c`, primary source |

### False positives
- Path-MTU-discovery diagnostics and some enterprise monitoring tools legitimately vary ICMP
  payload size (e.g. `ping -s <size>` sweeps used by network engineers troubleshooting
  fragmentation) — a single scripted sweep should not alone trigger a high-confidence alert;
  require *sustained*, *bidirectional*, *high-entropy* traffic before flagging.
- Some load balancers/health checks use nonstandard ICMP payloads by design.

### Implementation notes
- Track ICMP "sessions" keyed by (src, dst, ICMP id) — the ICMP header's identifier field is the
  natural session key (used by real ping to match request/reply pairs), directly analogous to a
  TCP/UDP flow key.
- Because our flow aggregator already computes payload entropy for other protocols, wire the same
  function to ICMP payloads rather than writing new entropy code.

---

## 6. JA3 / JA3S / JA4 TLS Fingerprinting

### JA3 construction — independently verified, not just quoted
Primary source: Salesforce, https://github.com/salesforce/ja3 (Althouse, Atkinson, Atkins, 2017;
blog: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/).

**Algorithm**: from the TLS ClientHello, gather the **decimal** values of:
`SSLVersion, Cipher, SSLExtension, EllipticCurve, EllipticCurvePointFormat`
— concatenate values **within** a field with `-`, concatenate the **five fields** with `,` (empty
fields stay empty, delimiters still present), then **MD5** the resulting ASCII string → a 32-hex
-character fingerprint. **GREASE values (RFC 8701) are excluded entirely** from every field before
concatenation, specifically so GREASE-emitting clients still produce a stable, comparable hash.

We **independently verified** this is exactly right by recomputing the README's own example
locally (not just trusting the fetched text):
```
$ printf '%s' "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0" | md5sum
ada70206e40642a3e4461f35503241d5   ← matches the README's claimed JA3 hash exactly
```
**JA3S** (server-side): same construction, but only three fields from the ServerHello —
`SSLVersion, Cipher, SSLExtension` — fingerprinting how a *server* responded to a given client,
useful for identifying C2 server software/config independent of domain fronting.

### JA4 — the successor, and why it exists
Primary source: FoxIO, https://github.com/FoxIO-LLC/ja4 (technical spec:
`technical_details/JA4.md`). Format: `t13d1516h2_8daaf6152771_b186095e22b6`
- **JA4_a** (plaintext prefix): protocol (`t`=TLS/TCP, `q`=QUIC, `d`=DTLS) + TLS version (`13`) +
  SNI-presence (`d`=domain SNI present, `i`=IP-only/no SNI) + 2-digit cipher count (GREASE
  excluded) + 2-digit extension count (GREASE excluded) + first/last ALPN characters.
- **JA4_b**: 12-char **truncated SHA256** of ciphers **sorted** in hex order, comma-delimited.
- **JA4_c**: 12-char truncated SHA256 of extensions **sorted** by hex value (SNI 0x0000 and ALPN
  0x0010 excluded from the hash), followed by signature algorithms in original order.
- **Critical fix over JA3**: JA4 **sorts** ciphers/extensions before hashing, so
  extension-*order* no longer changes the fingerprint. This directly targets a real, dated,
  citable event: **Chrome 110** (rolled out ~20 January 2023) began **randomizing ClientHello
  extension order on every connection** as an anti-ossification measure (same motivation as
  GREASE). With ~16 extensions in a typical Chrome ClientHello, that's up to **16! ≈ 2×10¹³**
  possible orderings — meaning **stock JA3 now produces a different hash almost every connection
  for modern Chrome/Chromium**, making it functionally useless for stable client
  identification. (Documented independently by Fastly's engineering blog and Stamus Networks;
  https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild,
  https://www.stamus-networks.com/blog/ja3-fingerprints-fade-browsers-embrace-tls-extension-randomization.)
- Licensing: the core **JA4** spec is BSD-3-Clause (same as JA3, so any JA3 consumer can adopt it
  freely); the broader **JA4+** family (JA4S/JA4H/JA4X/JA4SSH/etc.) is under the **FoxIO License
  1.1**, which is permissive for academic/internal use but **restricts monetization** — relevant
  if NetForensiq is ever commercialized, fine for a police-hackathon prototype.

### Public malicious-JA3 fingerprint sources
- **abuse.ch SSLBL — JA3 Fingerprint Blacklist**: https://sslbl.abuse.ch/ja3-fingerprints/,
  CSV export and ready Suricata rules at
  https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules. Built from analysis of **>25 million
  malware PCAPs**. **abuse.ch's own published caveat, quoted directly from their site: "these
  fingerprints have not been tested against known good traffic yet and may cause a significant
  amount of false positives."** We surface this caveat directly in NetForensiq's UI wherever a
  JA3-blacklist hit is shown.
- **Status note**: SSLBL's separate **IP blacklist** component was deprecated/emptied as of
  January 2025; the **JA3 fingerprint** component remains active and maintained as of this
  research (August 2026) — worth re-checking at demo time since abuse.ch has been actively
  pruning legacy feeds.

### Honest limitations (a police panel will ask about this)
- **TLS 1.3 alone does not defeat JA3/JA4.** The ClientHello/ServerHello are still sent
  unencrypted on the wire in TLS 1.3 (only *later* handshake messages and application data are
  encrypted) — passive fingerprinting continues to work fine against plain TLS 1.3.
- **ECH (Encrypted Client Hello) does defeat us specifically**, and we should be precise about
  *why*, because most public write-ups frame this from the wrong vantage point (the destination
  server's). ECH wraps the real "inner" ClientHello (true SNI, true extension set) inside a
  generic "outer" ClientHello. **The destination server** decrypts the inner hello and can still
  fingerprint the true client — but **NetForensiq is a passive network-level observer, not the
  destination server**, so from our vantage point ECH-protected sessions only ever expose the
  generic, often shared, outer ClientHello. **For us, ECH deployment (increasingly common via
  Cloudflare/Chrome/Firefox) is a real, growing blind spot for JA3/JA4**, and this should be
  disclosed as a known limitation, not glossed over.
- **Extension-order randomization** (Chrome 110+, above) already degrades stock JA3 badly even
  without ECH; JA4 mitigates but does not eliminate this (cipher/extension *counts* and the ALPN
  fields are still somewhat distinguishing, but less uniquely so than full JA3).
- JA3/JA4 fingerprint the **TLS library/stack + its configuration**, not the specific
  application or malware family — a false positive risk in the opposite direction: many
  unrelated programs sharing the same TLS library (e.g. everything built on a common Go/OpenSSL
  version) will share a JA3, and a match should be treated as investigative *lead* evidence, not
  proof.

### Parameters table

| Item | Value | Source |
|---|---|---|
| JA3 field order | SSLVersion,Cipher,Extensions,EllipticCurves,ECPointFormats | Salesforce `ja3` README (primary), independently re-verified via local `md5sum` |
| JA3 hash algorithm | MD5, 32 hex chars | Salesforce `ja3` README (primary) |
| JA3S field order | SSLVersion,Cipher,Extensions (ServerHello only) | Salesforce `ja3` README (primary) |
| GREASE handling | Fully excluded from all fields, both JA3 and JA4 | RFC 8701; Salesforce/FoxIO repos |
| JA4 hash algorithm | SHA256, truncated to 12 hex chars per section | FoxIO `JA4.md` (primary) |
| JA4 sorting | Ciphers and extensions sorted before hashing (order-independent) | FoxIO `JA4.md` (primary) |
| Chrome extension randomization onset | Chrome 110, ~20 Jan 2023 | Fastly/Stamus Networks engineering blogs |
| Public malicious JA3 feed | sslbl.abuse.ch/ja3-fingerprints/ (>25M PCAPs) | abuse.ch, with abuse.ch's own FP caveat |

### False positives
- Shared-library JA3/JA4 collisions across unrelated benign and malicious software (see above).
- Legitimate software that bundles an old/unusual TLS stack (many IoT/embedded devices, older
  enterprise agents) may coincidentally match a blacklist fingerprint generated from malware built
  on the same stack version.

### Implementation notes
- Compute both JA3 (for backward-compat matching against the large existing abuse.ch corpus) and
  JA4 (for forward-looking accuracy against modern Chrome/Firefox); show both in the UI.
- Treat a blacklist hit as **one input to a combined score**, never an auto-block/auto-classify
  decision, consistent with abuse.ch's own stated caveat.

---

## 7. Unsupervised Anomaly Detection on Flow Features (IsolationForest)

### Parameters, verified against sklearn's own docs
Source: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
(fetched directly), original method: Liu, Ting, Zhou, *Isolation Forest*, IEEE ICDM 2008 (DOI
10.1109/ICDM.2008.17) and *Isolation-based Anomaly Detection*, ACM TKDD 6(1), 2012 (DOI
10.1145/2133360.2133363).

| Parameter | sklearn default | Recommendation for network flows |
|---|---|---|
| `n_estimators` | **100** | Keep sklearn's default. The original Liu et al. 2008 paper's own experiments found average path lengths converge well before 100 trees — sklearn's default is not an arbitrary library choice but inherits the paper's own convergence finding. |
| `max_samples` | `'auto'` = `min(256, n_samples)` | Keep default — 256 was the paper's own recommended subsample size, chosen because isolation trees need very few samples to isolate anomalies (a core claim of the method: anomalies are "few and different," so small subsamples suffice and *reduce* swamping/masking effects from large normal clusters). |
| `contamination` | `'auto'` → uses paper's convention: decision offset fixed at **−0.5** (inlier scores near 0, outlier scores near −1) | **[OUR HEURISTIC]**: set explicitly rather than `'auto'` once we know our synthetic generator's attack mix (e.g. 0.02–0.05), since `'auto'` is sklearn's admitted fallback for when you have *no* prior — we do have one from the generator's known label ratio. On real captures where the true ratio is unknown, revert to `'auto'`. |
| `max_features` | 1.0 (all features) | Keep default given our modest (~15) feature count. |
| `bootstrap` | `False` | Keep default (paper's isolation trees are built on samples *without* replacement). |

### Which of our features are actually discriminative
Given our flow schema, the features that are discriminative **by construction** (they are
literally what our synthetic generator manipulates to create each attack class) are:
`bytes_ratio`, `payload_entropy`, `pkts_per_sec`, `dns_query_count`, `longest_dns_label`,
`duration`, `avg_pkt_size`. This is an important **honesty caveat for evaluation** (see §8): good
IsolationForest performance on synthetic data partly reflects that we are detecting the generator's
own parameterization, not necessarily real-world attacker behavior.

**Transformations**: `bytes_sent`/`bytes_received`/`packets_sent`/`packets_received` are heavily
right-skewed (a handful of huge flows, a mass of small ones) — apply `log1p` before feeding to
the model. This is standard preprocessing practice (sklearn's own preprocessing guide notes
log-style transforms are used to reduce skew before distance/scale-sensitive steps —
https://scikit-learn.org/stable/modules/preprocessing.html), and is **doubly important** for
IsolationForest specifically: because its random split thresholds are drawn *uniformly* within
each feature's observed min–max range, extreme skew means most random splits land in the sparse
high-value tail, wasting splitting "budget" and reducing effective resolution among the (far more
numerous) small-value flows — a mechanical consequence of the algorithm's split-selection rule
described in Liu et al. 2008, not an empirical claim we're asserting without basis.
**Categorical features** (`app_protocol`, `tcp_flags_seen`) must be one-hot (not naively integer-
label) encoded — IsolationForest's numeric split comparisons would otherwise impose a false
ordinal relationship between unrelated categories.

### Honest statement of expected performance and failure modes
- IsolationForest detects **statistical outlierness**, not **maliciousness** — a legitimate but
  unusual flow (a one-off large backup, a new but benign application) will score identically to
  genuine attack traffic that happens to be equally rare in the training distribution.
- It will likely **under-perform on "low-and-slow" attacks deliberately shaped to stay within
  normal statistical envelopes** — e.g. exfiltration paced to match typical upload volumes, or a
  C2 beacon with added jitter specifically to avoid regularity-based detection (§1). This is a
  structural limitation of any unsupervised outlier method, not specific to our implementation.
- It is sensitive to **concept drift**: a model trained on one week of traffic will drift stale as
  normal usage patterns change (new software rollouts, seasonal traffic); needs periodic retraining
  and is not a "set and forget" component.
- `contamination` mis-specification directly biases the alert rate — setting it too low silently
  suppresses true positives; too high floods the analyst with false ones. This is exactly why we
  do **not** treat IsolationForest output as a final verdict.

### Why rules-first + model-second is the defensible architecture for law enforcement
A rule like RITA's beacon formula (§1) or Snort 3's `scans/rejects/nets/ports` counters (§3)
produces a **deterministic, reproducible, fully-explainable** verdict: given the same flow data,
the same score comes out every time, and every contributing number can be shown to an
investigator or, ultimately, a court. NIST SP 800-86 (*Guide to Integrating Forensic Techniques
into Incident Response*) grounds forensic tool acceptance explicitly in "consistency in the
examination process and the accuracy and **reproducibility** of results" (§3.1.1, on forensic
tooling generally) — a bar that a documented, formula-based rule satisfies far more directly than
an opaque anomaly score from a model an investigator cannot re-derive by hand. **Practically**:
IsolationForest should surface candidates for human review and can *raise the priority* of a flow
that also matches a rule-based signal, but should never be the sole basis for an alert presented
as "detected: C2 beaconing" — that framing must come from the interpretable rule that actually
explains *why*.

---

## 8. Evaluation

### Metrics
- **Precision, Recall, F1** per attack class (not just macro-averaged) — a police panel will ask
  "how many of your DNS-tunneling alerts are real," which is precision, and "how many real DNS
  tunneling sessions did you catch," which is recall; report both, not just accuracy (accuracy is
  meaningless on imbalanced attack:benign ratios).
- **False Positive Rate** (`FP / (FP + TN)`) computed against the **benign baseline only** —
  report this number explicitly and prominently, since it's what determines whether the tool is
  usable in a real SOC/investigative workflow.
- **PR-AUC over ROC-AUC** for the imbalanced case: Davis & Goadrich, *The Relationship Between
  Precision-Recall and ROC Curves*, ICML 2006 — establishes that ROC curves can look
  misleadingly good on highly imbalanced data (which ours is, benign traffic vastly outweighing
  attacks) while PR curves reveal the same model performing poorly; report PR-AUC as the headline
  imbalanced-data metric, ROC-AUC as a secondary one.
- Report a full **confusion matrix per attack type**, plus a breakdown of which specific
  rule/subscore fired for each true positive (directly supports the explainability framing above).

### The overclaiming trap — cite explicitly, don't just assert
- **McHugh, J. (2000), "Testing Intrusion Detection Systems: A Critique of the 1998 and 1999
  DARPA Intrusion Detection System Evaluations as Performed by Lincoln Laboratory,"** ACM
  Transactions on Information and System Security 3(4), 262–294, DOI 10.1145/382912.382923 — the
  canonical critique establishing that a detector's performance on a *generated/synthetic*
  evaluation corpus (background traffic + injected attacks, methodologically similar to what
  NetForensiq's generator does) does not reliably predict performance on real network traffic,
  because synthetic background traffic lacks the statistical richness and heterogeneity of
  production networks, and injected attacks are typically cleaner/more separable than real
  attacker behavior.
- **Tavallaee, Bagheri, Lu, Ghorbani (2009), "A Detailed Analysis of the KDD CUP 99 Data Set,"**
  IEEE Symposium on Computational Intelligence for Security and Defense Applications — a second,
  independently-arrived-at critique of the most widely used synthetic IDS benchmark, documenting
  specific artifacts (e.g. near-duplicate records making train/test splits leak information) that
  produce inflated reported accuracy. The general lesson — **audit your own synthetic dataset for
  the equivalent artifacts** (near-duplicate flows across our own train/eval split, attack classes
  that are too parametrically "clean" relative to how our own rules define them) — applies
  directly to NetForensiq's synthetic generator and should be stated in any reported numbers.
- **Concrete implication for NetForensiq**: because several of our discriminative features (§7)
  are the *same* parameters the synthetic generator uses to construct each attack class, and
  because our rule thresholds (§1–§6) were partly chosen with knowledge of typical attack-tool
  behavior, any precision/recall we report on our own synthetic set should be presented with an
  explicit caveat: **"measured on synthetic, labeled data generated by our own tool; real-world
  transfer is unverified and expected to be lower, particularly against attackers who deliberately
  evade the specific thresholds published in this document — since this document itself is public
  once released."**

---

## Sources

**C2 Beaconing**
- RITA beacon README (documented spec): https://github.com/activecm/rita-legacy/blob/main/pkg/beacon/Readme.md
- RITA beacon analyzer (actual running code, primary): https://github.com/activecm/rita-legacy/blob/main/pkg/beacon/analyzer.go
- RITA default config: https://github.com/activecm/rita-legacy/blob/main/etc/rita.yaml
- RITA main repo: https://github.com/activecm/rita

**DNS Tunneling**
- RFC 1035, Domain Names — Implementation and Specification: https://www.rfc-editor.org/rfc/rfc1035
- Farnham & Atlasis, "Detecting DNS Tunneling" (SANS/GIAC 2013): https://www.sans.org/white-papers/34152/ ; https://www.giac.org/paper/gcia/1116/detecting-dns-tunneling/108367
- RFC 7208, Sender Policy Framework (SPF), §4.6.4 (10-lookup / 2-void-lookup limits): https://datatracker.ietf.org/doc/html/rfc7208
- "Information-Based Heavy Hitters for Real-Time DNS Data Exfiltration Detection and Prevention": https://arxiv.org/abs/2307.02614

**Port Scan**
- Jung, Paxson, Berger, Balakrishnan, "Fast Portscan Detection Using Sequential Hypothesis Testing," IEEE S&P 2004 (primary PDF, fetched and read in full): https://www.icir.org/vern/papers/portscan-oak04.pdf
- Zeek legacy scan.zeek (deprecated): https://docs.zeek.org/en/v6.0.9/scripts/policy/misc/scan.zeek.html ; source https://github.com/zeek/zeek/blob/v6.0.9/scripts/policy/misc/scan.zeek
- Zeek current recommended package, ncsa/bro-simple-scan: https://github.com/ncsa/bro-simple-scan
- Snort 3 port_scan inspector (Cisco Talos): https://github.com/snort3/snort3/blob/master/src/network_inspectors/port_scan/ps_module.cc

**Data Exfiltration**
- Lyda & Hamrock, "Using Entropy Analysis to Find Encrypted and Packed Malware," IEEE S&P 5(2), 2007, DOI 10.1109/MSP.2007.48
- binwalk entropy module (primary source of implementable thresholds): https://github.com/ReFirmLabs/binwalk/blob/v2.3.4/src/binwalk/modules/entropy.py
- "Reliable Detection of Compressed and Encrypted Data" (EnCoD): https://arxiv.org/abs/2103.17059
- Fidelis Security, "Data Exfiltration Detection Guide for SOC Teams": https://fidelissecurity.com/threatgeek/data-protection/how-to-detect-data-exfiltration/

**ICMP Tunneling**
- ptunnel-ng source (magic-number evasion admission, primary): https://github.com/utoni/ptunnel-ng/blob/master/src/options.c
- Windows/Linux default ping payload behavior: widely-replicated, independently cross-checked technical write-ups (Medium/Gursimar Singh; ittavern.com)

**JA3/JA3S/JA4**
- Salesforce JA3 (primary): https://github.com/salesforce/ja3 ; blog: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/
- FoxIO JA4 spec (primary): https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
- RFC 8701, GREASE: https://datatracker.ietf.org/doc/html/rfc8701
- abuse.ch SSLBL JA3 Fingerprint Blacklist: https://sslbl.abuse.ch/ja3-fingerprints/
- Fastly, "A first look at Chrome's TLS ClientHello permutation in the wild": https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild
- Stamus Networks, "JA3 Fingerprints Fade as Browsers Embrace TLS Extension Randomization": https://www.stamus-networks.com/blog/ja3-fingerprints-fade-browsers-embrace-tls-extension-randomization

**IsolationForest**
- scikit-learn IsolationForest docs (primary): https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- scikit-learn preprocessing guide: https://scikit-learn.org/stable/modules/preprocessing.html
- Liu, Ting, Zhou, "Isolation Forest," IEEE ICDM 2008, DOI 10.1109/ICDM.2008.17
- Liu, Ting, Zhou, "Isolation-based Anomaly Detection," ACM TKDD 6(1), 2012, DOI 10.1145/2133360.2133363
- NIST SP 800-86, "Guide to Integrating Forensic Techniques into Incident Response" (reproducibility framing)

**Evaluation**
- McHugh, "Testing Intrusion Detection Systems…," ACM TISSEC 3(4), 2000, DOI 10.1145/382912.382923
- Tavallaee, Bagheri, Lu, Ghorbani, "A Detailed Analysis of the KDD CUP 99 Data Set," IEEE CISDA 2009
- Davis & Goadrich, "The Relationship Between Precision-Recall and ROC Curves," ICML 2006

---

## [OUR HEURISTIC] values — complete list (no citable source found; use with disclosure)

| # | Heuristic | Proposed value |
|---|---|---|
| 1 | Beacon-score alert threshold | > 0.8 (practitioner-informed, not a RITA default) |
| 2 | DNS label entropy cutoff | mean > 3.5 bits/char over labels ≥ 20 chars |
| 3 | TXT+NULL query-type share (tunneling) | > 30% of a source's queries to one domain |
| 4 | Unique subdomains per parent domain (session-scale) | > 50 within capture window |
| 5 | DNS query rate to one domain | > 5 qps sustained for 30s |
| 6 | Exfiltration volume ratio | outbound:inbound > 10:1 AND bytes_sent > 50 MB |
| 7 | Off-hours volume deviation | > 3σ from per-host hourly baseline |
| 8 | ICMP anomalous payload size | > 100 bytes, or intra-session size variance |
| 9 | IsolationForest `contamination` | set to synthetic generator's known attack ratio (e.g. 0.02–0.05) instead of `'auto'` |
| 10 | Suricata scan count/seconds pair | not adopted as a hard default — implement Snort 3's `scans/rejects/nets/ports` model instead, which is fully sourced |

Every other numeric threshold in this document traces to a quoted primary or strongly-attributed
secondary source, listed inline in its section.
