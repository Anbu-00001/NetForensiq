# 157 — What the detection rules say about traffic that is not an attack

**Question:** the APK engine may not raise a tier on a signal until that signal has been
measured against legitimate software — 201 F-Droid apps, and a signal that fires on any of
them cannot carry a verdict alone. The network rules never had the equivalent. They were
written from published indicators in five malicious captures, and how often each one says
"this host is beaconing" about an ordinary laptop had never been measured.

This measures it.

---

## 1. Method

**Benign corpus.** 16 captures from the CTU Malware Capture Facility's *Normal* set
(Stratosphere Laboratory, CTU Prague): Windows VMs browsing the web, home notebooks,
university machines, each with a README describing what was running. 2.52 GB, 134,739
flows. Downloaded with `apk_corpus/analysis/fetch_benign_captures.sh`, which records each
capture's source URL, size and SHA-256.

**Not CICIDS2017.** The obvious alternative is a labelled IDS benchmark, and it was
rejected on the evidence: Engelen et al. (IEEE SPW 2021) found errors in its traffic
generation, flow construction, feature extraction and labelling; Lanvin et al. (2023)
found packet misordering, duplicate flows, undocumented capture gaps and further label
errors that materially change measured detection performance. A benign base rate taken
from a corpus whose "benign" label is unreliable would look rigorous and mean nothing.

**What "benign" means here.** Captured as ordinary use, by a lab that says so, with no
attack staged. It does *not* mean the traffic is free of scanning, failed connections or
odd software — real networks carry all three, and that is the point. A rule that fires
here fires on real life.

**Malicious corpus.** The 7 captures already in the project: XWorm, Mirai (VM and
in-the-wild), a week of server scans, seven days of scans, the AsyncRAT/XWorm reference
and the wrccdc exercise. 613,788 flows.

**Harness.** `scripts/measure_rule_base_rates.py` — one child process per capture,
sequential, each with an address-space ceiling and its own database. The same shape
`apk_runner` uses, for the same reasons: a capture that exhausts memory kills one child
rather than the machine, and memory is returned between captures.

**A limit stated up front.** The two corpora are not matched. The benign captures are long
browsing sessions; several malicious ones are small and targeted (the XWorm capture is 146
packets). Capture-level firing rates therefore flatter the benign side. That does not
explain away any of §2.

---

## 2. What the measurement found

Every rule that fires at all, fires on ordinary traffic.

| Rule | Benign (16) | Malicious (7) |
|---|---:|---:|
| `ANOMALY_STATISTICAL` | 16 | 4 |
| `C2_BEACON_KEEPALIVE` | 9 — **1,150 findings** | **0** |
| `C2_BEACON_PERIODIC` | 8 | 1 |
| `RECON_PORT_SCAN` | 8 | 4 |
| `HOST_CORROBORATED` | 7 | **0** |
| `EXFIL_VOLUME_ASYMMETRY` | 5 | 1 |
| `COVERT_CHANNEL_UNKNOWN_PORT` | 4 | 3 |
| `DNS_TUNNEL_LONG_LABEL` | 4 | 1 |
| `DNS_TUNNEL_SUBDOMAIN_VOLUME` | 4 | **0** |
| `ICMP_TUNNEL_OVERSIZED` | 2 | 1 |
| `IOC_FEED_MATCH` | 0 | 0 — untested, silent without a feed |

**`HOST_CORROBORATED` — the engine's strongest sentence, *"10.0.2.15 implicated by 5
independent rules"* — fired on 7 of 16 captures of a Windows VM browsing the web**, and on
none of the malicious ones. A rule built to express agreement between rules inherits
whatever they get wrong, and multiplies it into confidence.

`ANOMALY_STATISTICAL` firing everywhere is expected and is not counted as a defect: it is
the unsupervised signal, capped at MEDIUM and documented as a lead rather than a
conclusion. It is listed for completeness.

### 2.1 Four defects, each visible in the evidence

1. **Port scan counted normal browsing.** *"10.0.2.15 probed 806 host+port combinations on
   719 hosts"* — a browser reaching CDNs and ad networks. The rule counted distinct
   destination pairs and never asked whether the connections succeeded.
2. **A "beacon" with a zero-second period.** *"Periodic callback to 161.69.13.21 every
   ~0s"*. A median interval of zero is not a schedule.
3. **Multicast counted as exfiltration.** *"0.1 MB outbound to 239.255.255.250
   (106876:1)"* — SSDP's multicast group. Nothing answers, because there is nobody to
   answer; the ratio is not high, it is undefined.
4. **CDNs counted as DNS tunnelling.** *"66 unique subdomains of amazonaws.com"*, *"111 of
   cern.ch"*, *"59 of akamaiedge.net"*.

---

## 3. The fixes, and what they are taken from

### 3.1 A scan is failed connections, not fan-out

Zeek counts failures and says so: `Scan::addr_scan_threshold` is "the threshold of the
unique number of hosts a scanning host has to have **failed connections** with on a single
port". Snort's `sfportscan` rests on the same observation — "most queries sent by the
attacker will be negative… In the nature of legitimate network communications, negative
responses from hosts are rare".

The distinction is not a refinement; it is the signal. Jung, Paxson, Berger and
Balakrishnan built Threshold Random Walk on it (IEEE S&P 2004) and named the failure mode
of counting destinations instead: such a rule "can erroneously flag a legitimate access
such as that of Web crawlers or proxies" — this project's exact false positive, described
twenty-two years before it was measured here.

**Implemented:** only flows whose peer never completed a handshake count towards the
threshold — fewer than two packets returned, which covers both of Zeek's cases (`S0`, "no
reply", and `REJ`, a single RST). It is the same test the covert-channel rule already uses
(research/155 §3.2). The finding now reads *"failed to connect to N host+port
combinations"*, and the evidence carries both the failed and the attempted count.

### 3.2 A period, not a burst

`beacon_min_period = 1.0s`, applied to both beacon rules. Below one second the flow model
itself does not distinguish gaps — flows are cut on idle timeouts measured in tens of
seconds — so sub-second structure is transport behaviour, not cadence.

Deliberately **not** raised to exclude fast beacons. Real C2 does call home every few
seconds. RITA's own design targets the slower end — a minimum of 23 connections, "Since
analyzing hosts that have fewer than at least one connection per hour could significantly
increase both the analysis time and the number of false positives" — but excluding
everything under a minute here would be tuning against this corpus rather than against a
defect.

### 3.3 Link-scoped destinations cannot receive exfiltration

A categorical exclusion, not a threshold: 224.0.0.0/4 (RFC 5771), 255.255.255.255
(RFC 919, "must not be forwarded"), 169.254.0.0/16 (RFC 3927, "A router MUST NOT forward a
packet with an IPv4 Link-Local source or destination address"), ff00::/8 and fe80::/10
(RFC 4291). Each is defined by its RFC as link-scoped, so "data left the network to this
host" is not a claim that can be true of it.

### 3.4 One phenomenon, one finding

`C2_BEACON_KEEPALIVE` emitted one finding per connection — 340 of them about one host
talking to one AWS address. Zeek's notice framework solves this with an `identifier` and a
suppression interval, and states that without an identifier suppression never happens at
all. Findings are now aggregated per (host, peer, port), with the number of connections
carrying the pattern on the finding. Nothing is hidden; 340 restatements can no longer
bury a real finding further down the list.

---

## 4. Measured again, after

| Rule | Benign before | after | Malicious before → after |
|---|---:|---:|---|
| `RECON_PORT_SCAN` | 8 / 16 | **1 / 16** | 4 / 7 → **4 / 7** |
| `C2_BEACON_PERIODIC` | 8 / 16 | **4 / 16** | 1 / 7 → 0 / 7 |
| `HOST_CORROBORATED` | 7 / 16 | **5 / 16** | 0 / 7 → 0 / 7 |
| `C2_BEACON_KEEPALIVE` | 9 / 16, 1,150 findings | 9 / 16, **597** | 0 / 7 → 0 / 7 |
| `EXFIL_VOLUME_ASYMMETRY` | 5 / 16, 14 | 5 / 16, **12** | 1 / 7 → 1 / 7 |
| **Total findings** | **1,803** | **1,221** | **1,138 → 1,136** |

**The port-scan fix removed seven of eight benign firings and cost nothing at all on the
malicious side.** Mirai's sweep now reads *"failed to connect to 106,688 host+port
combinations"*, wrccdc's *"31,017"*.

**The one malicious finding that disappeared was the defect itself.** `C2_BEACON_PERIODIC`
lost *"Periodic callback to 134.71.3.16 every ~0s"* on the wrccdc capture — the same
zero-interval artefact, made about a malicious capture instead of a benign one. No true
positive was lost; a false statement was withdrawn from both corpora.

319 capture tests pass unchanged.

---

## 5. What is still wrong

- **`C2_BEACON_KEEPALIVE` still fires on 9 of 16 benign captures and 0 of 7 malicious
  ones.** Aggregation cut the noise by half; it did not make the rule discriminate. On
  this evidence the rule has no demonstrated true-positive value. It has not been removed
  on the strength of seven malicious captures, but it must not be read as evidence of C2
  until it earns a better number.
- **DNS tunnelling vs CDN is unfixed.** The right approach is known — group by the Public
  Suffix List's eTLD+1 rather than a parent-domain string, require each generated
  subdomain to be queried about once (tunnels generate, CDNs re-query), and weigh NXDOMAIN
  rate and record type. Elastic's measurement of exactly this problem is blunt: "High
  entropy, a large number of subdomains, and large packet size may seem like reliable
  indicators of a DNS tunnel. But that approach now yields an unmanageable volume of false
  positives." Implementing it needs a PSL snapshot shipped with the engine.
- **`HOST_CORROBORATED` still fires on 5 of 16 benign captures and 0 of 7 malicious.**
  Corroboration between unspecific rules is not evidence, and this rule will not be worth
  anything until the rules under it are.
- **16 captures is a small corpus.** A rule firing on none of them still has a one-sided
  95% upper bound of 17.1% on its true benign rate. That bound is wide and is printed by
  the reporting tool rather than left implied.
- **No rule yet publishes its measured benign rate to the officer reading the finding.**
  That is what the APK engine does — every capability carries its baseline — and it is the
  obvious next step here.

*Measured 19 Sep 2026. Corpus manifest at `mal/benign_pcaps/corpus_manifest.json`;
results in `mal/base_rates_*.json`; tools are `scripts/measure_rule_base_rates.py` and
`scripts/rule_base_rate_report.py`.*
