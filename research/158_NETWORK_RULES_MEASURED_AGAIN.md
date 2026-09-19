# 158 — The four network defects research/157 left open

**Question:** research/157 measured every network rule against 16 captures of ordinary
traffic and closed four defects. It ended on four more, stated as still wrong:

1. `C2_BEACON_KEEPALIVE` fired on 9 of 16 benign captures and 0 of 7 attacks.
2. `HOST_CORROBORATED` — the one finding allowed to say CRITICAL — fired on 5 of 16
   benign captures and 0 of 7 attacks.
3. DNS tunnelling still counted CDN and cloud hostnames.
4. No finding told the officer reading it how often its rule is wrong.

This fixes each, and measures the result on six captures of ordinary traffic that no
rule change was fitted to.

---

## 1. The keepalive rule was counting the transport talking to itself

The benign firings were not scattered. They clustered at **~10 s and ~45 s, on ports 80
and 443** — *"Regular keepalive to 93.184.220.29:80 every ~10.0s (16 connections)"*,
*"… 23.38.83.177:443 every ~45.0s"*. That is not a schedule an application chose.

**Cause.** The per-flow interval statistics counted every outbound packet, and a TCP
connection that is only *receiving* sends nothing but acknowledgements — and, when idle,
keep-alive probes. RFC 1122 §4.2.3.6: *"A keep-alive segment either contains no data or
consists of one octet."* Chromium probes idle sockets every **45 s**
(`kTCPKeepAliveSeconds = 45`, set to keep NAT state from expiring). Counted as sends, an
idle browser tab is a perfectly regular callback.

**Fix.** Only outbound packets that carry data — more than one octet, by the IP header's
own length field — count towards a connection's send intervals. A remote-access trojan's
heartbeat is an application message and carries data, so it is still counted; the
synthetic AsyncRAT-shaped heartbeat still fires, and a new test holds the same
connection with bare probes to *not* firing.

The length has to come from the IP header, not the captured frame: an ACK is padded to
Ethernet's 60-octet minimum, so the frame carries six octets that are not data. Both
readers now report it — `fastparse` from the IPv4 total length / IPv6 payload length,
the dissector by subtracting its `Padding` layer — and they agree on real frames
(`tests_fastparse`). The payload itself, and so every entropy figure, is unchanged.

**Result, same 16 captures:** 9 → **7** captures, **597 → 37** findings (−94%). Still
**0 of 7** attacks.

What is left is real application heartbeats — a web portal's push channel on 443 every
~35 s, a peer-to-peer client on a high port every 5.5 s. Timing cannot separate those
from a RAT's heartbeat, and nothing in this corpus shows the rule catching one. It is
therefore **capped at LOW** under §3's rule, not deleted: an officer can still see it,
with its measured rate beside it.

## 2. DNS tunnelling: grouped by registered domain, counted over "loose ends"

The rule grouped queries by "the last two labels" and counted every distinct name. On
ordinary traffic: *"66 unique subdomains of amazonaws.com"*, *"59 of akamaiedge.net"*,
*"662 of in-addr.arpa"*.

Elastic's analysis of exactly this false positive (*Plight at the end of the tunnel*)
names two tests, both implemented:

- **Group by registered domain.** The Mozilla Public Suffix List draws the boundary
  between a public suffix and what someone registered under it, including the private
  section where cloud and dynamic-DNS providers declare their customers separate
  (`*.compute-1.amazonaws.com`, `akamaiedge.net`, `duckdns.org`, `trycloudflare.com`).
  Shipped as a snapshot (version `2026-09-18_18-42-54_UTC`, SHA-256 `330c1c71…`), read by
  `capture/psl.py`; the version is recorded on every DNS finding. The parser passes all
  64 applicable vectors of the PSL project's own `tests/test_psl.txt`. Reverse lookups
  are grouped by the zone an address holder is actually delegated — a /24 (RFC 1035
  §3.5, RFC 2317) or a /64 (RFC 3596) — not by `in-addr.arpa`, under which the list
  would put 16 million addresses per group.
- **Count only loose ends.** A tunnel *"has no intention to ever make an IP connection
  to the resolved domain name"*; ordinary resolution exists to reach an address. A name
  counts only if the host never went on to talk to anything it returned. Where a
  capture holds no traffic but DNS, that test cannot be made; the finding says so and
  counts every name, rather than silently passing.

**Result, same 16 captures:** `DNS_TUNNEL_SUBDOMAIN_VOLUME` 4 → **1**,
`DNS_TUNNEL_LONG_LABEL` 4 → **1**. The long-label rule's one firing in the attack
corpus is kept, and it should not be read as a detection: it is *"2 oversized DNS labels
under rackcdn.com"* in the wrccdc exercise, a CDN name in a capture that happens to be
an attack. "Fired on an attack capture" is what the table counts; it is not the same as
"caught the attack", and for this rule it was not.

What is left: *"69 unused subdomains of cern.ch"* — names resolved and never connected
to, which is what browser DNS prefetching looks like — and three long `gstatic.com`
labels in a DNS-only capture, where the connection test cannot run.

**A real tunnel is still caught.** The seven-capture attack corpus contains no DNS
tunnel, so until now neither rule had been seen to fire on one. Elastic publishes an
iodine capture with the analysis above (`dns-tunnel-iodine.pcap`, SHA-256 `91fd221e…`).
Both rules fire: *"222 unused subdomains of pirate.sea from 10.0.2.30"* and an
oversized-label finding. It was chosen because it is a tunnel, before it was run, and
the rules were not changed afterwards. It holds only DNS, so the loose-end test was not
exercised on it. It is added to the attack corpus as its eighth capture.

## 3. Publishing each rule's measured rate — and what it may decide

`scripts/rule_base_rate_report.py --emit` now writes
`backend/capture/data/rule_base_rates.json` from measured runs; it is never edited by
hand. `capture/base_rates.py` reads it for three things:

1. **Every finding carries its rule's rate** — in `evidence['measured_base_rate']`, on the
   API as `measured_base_rate`, on the finding card in the UI, and in the investigation
   report once per rule — as a sentence an officer can read aloud, with the exact
   one-sided 95% Clopper–Pearson upper bound. It is frozen into the finding when made,
   so a report printed later states what was known then.
2. **Only rules that fired on no ordinary capture may corroborate** — the APK engine's
   bar, applied to the network side. `HOST_CORROBORATED` counted agreement among rules
   that each fire on innocent traffic; agreement among unspecific rules is not evidence.
3. **A rule that has fired on ordinary traffic and never on an attack is capped at LOW**,
   with the severity it was written at kept in the evidence.

The consequence is stated plainly: **on current measurements only `IOC_FEED_MATCH` may
corroborate**, so `HOST_CORROBORATED` will essentially not fire until the rules beneath
it are specific. That is the correct behaviour for a finding that says CRITICAL, not a
side effect.

---

## 4. Measured on six captures nothing was fitted to

The 16 captures above were used to find these defects and to check the fixes, so a rate
re-measured on them is no longer clean. Six more CTU *Normal* captures were downloaded —
every remaining one with a full pcap, minus Normal-12 and Normal-22, which share a date
and file name with captures already used and may hold the same traffic — chosen by that
rule alone, before any was examined (`apk_corpus/analysis/fetch_benign_heldout_captures.sh`,
SHA-256s in `mal/benign_pcaps_heldout/corpus_manifest.tsv`). 3.9 GB, 247,868 flows,
measured once against the shipped table.

| Rule | Held-out benign (6) | What fired |
|---|---:|---|
| `HOST_CORROBORATED` | **0 / 6** | — |
| `C2_BEACON_PERIODIC` | **0 / 6** | — |
| `DNS_TUNNEL_LONG_LABEL` | **0 / 6** | — |
| `ICMP_TUNNEL_OVERSIZED` | 0 / 6 | — |
| `C2_BEACON_KEEPALIVE` | 3 / 6 | one finding each, all ~60 s on port 80, all at LOW |
| `EXFIL_VOLUME_ASYMMETRY` | 3 / 6 | 0.1–0.7 MB uploads at 11:1 to 23:1 |
| `COVERT_CHANNEL_UNKNOWN_PORT` | 2 / 6 | 8880, 8090 |
| `DNS_TUNNEL_SUBDOMAIN_VOLUME` | 1 / 6 | *"114 unused subdomains of cnki.net"* |
| `RECON_PORT_SCAN` | 1 / 6 | *"failed to connect to 619 host+port combinations on 557 hosts"* |

Predictions logged before the run: `HOST_CORROBORATED` on 0 of 6 (p = 0.93) — held;
keepalive on at least 2 of 6 (p = 0.55) — held.

No "before" figure exists for these six: the old code was never run on them, and
reconstructing it would mean reverting the working tree. The comparison that exists is
§1–2's, on the 16.

## 5. The 209 MB capture (research/156 §4)

The 4SICS ICS capture, which failed at 4,523 MB under a 5 GB cap in research/155, was
re-run through the background import against the production server command, same cap
(`pcap_realtest/run_capture_d.sh`, `results/background.json`). **It completes:** upload
request 1.71 s, sign-in during the import HTTP 200 in 0.52 s, finished in **491.9 s**,
import process peak **3,532 MB**, 108 findings. It stores 2,253,190 packets where the file
holds 2,274,747 frames; counted directly, the other **21,557** are frames with no IP layer
(ARP and similar), which the flow model has never counted. Prediction (p = 0.55) held.

## 6. The APK blind set, and Play Protect

**Blind set.** 100 MalwareBazaar APKs downloaded by excluding both earlier corpora, left
unexamined, and scored **once** on the engine as it ships (image `sandbox-v6`, the shipped
`data/baselines.json`; `apk_corpus/analysis/chain_blind.sh`). No native-code rule was
written in v6, so this is the engine whose held-out score was 64.

| | Result |
|---|---|
| Blind set | **52 / 100** (95% CI 41.8–62.1): tier 4 ×4, tier 3 ×23, tier 2 ×25, tier 1 ×45, tier 0 ×3 |
| Held-out set, for comparison | 64 / 100 (53.8–73.4) |
| Both unseen sets | **116 / 200 = 58.0%** (50.8–64.9) |
| Fresh F-Droid, re-checked on the shipped engine | 0 of 89 examined; 11 could not be examined |

Pre-registered: 80% interval 48–72 — caught it; "≥ 64" at p = 0.40 — wrong. Almost the
whole drop is tier 2 (45 → 25): the blind set is the 600 most recent uploads, and fewer
of them forge their own ZIP headers. The engine's strongest signal is a packaging trick
that newer samples use less.

**Play Protect.** AV-TEST, May 2025: 99.8% of 2,973 new samples, 99.9% of 3,017
reference samples, no false warnings; endurance test Jul–Dec 2025: 99.6% / 99.7% on
~18,000. Different samples from ours, so not a head-to-head — but no reading of 58%
against 99.8% puts this engine ahead, and none is made.

What *could* be run head to head is the one install-time check Google publishes exactly:
India's enhanced fraud protection, which blocks Internet-sideloaded installs declaring
RECEIVE_SMS, READ_SMS, notification-listener or accessibility access.
`scripts/efp_permission_check.py` applies it in the same network-less sandbox, each app
in its own 1 GB child (the first version read them in one process and a blind sample
exhausted it):

| Same samples | Engine | Google's rule | Both | Either |
|---|---:|---:|---:|---:|
| Held-out malware (100) | 64 | 46 | 30 | 80 |
| Blind malware (100) | 52 | 33 of 98 readable | 18 | 67 |
| **All unseen malware (200)** | **116 (58%)** | **79 of 198 (40%, CI 33.0–47.1)** | 48 | 147 |
| Fresh legitimate (100) | 0 of 89 | 3 (two launchers, a notification vault — accessibility) | — | — |

Two blind samples have deliberately corrupted ZIP entries and could not be read by the
rule's parser. This compares against one published rule, not against Play Protect.

## 7. What is still wrong

- **The attack column counts captures a rule fired on, not attacks it caught.**
  `DNS_TUNNEL_LONG_LABEL`'s firing in wrccdc is a CDN name (§2). Eight attack captures,
  one of them a tunnel, is thin.
- **Two rules are now LOW by rule, not by judgement:** `C2_BEACON_KEEPALIVE` (10 / 22
  benign, 0 / 8 attacks) and `C2_BEACON_PERIODIC` (4 / 22, 0 / 8). The second has never
  met a connection-per-callback beacon in the attack corpus; it is untested there rather
  than shown to fail, and the cap treats the two the same. A real beacon capture would
  settle it.
- **`HOST_CORROBORATED` will essentially not fire.** Only `IOC_FEED_MATCH` is measured
  silent on ordinary traffic. That is correct for a CRITICAL finding until the rules
  beneath it are specific.
- **DNS prefetching looks like a loose end** (`cern.ch`, `cnki.net`). Browsers resolve
  links they never follow.
- **22 captures bound a clean rule's benign rate at 12.7%, not lower.**
- **The APK engine's two unseen sets are spent.** The next detection claim needs a new
  capability and newly downloaded samples. 31 samples Google's rule blocks are ones the
  engine misses; that is a lead, not something to fit to.

*Measured 19–20 Sep 2026. Base-rate runs: `mal/base_rates_{benign,malicious}_v158a.json`,
`mal/base_rates_benign_heldout.json`, `mal/base_rates_dns_tunnel.json`. Shipped table:
`backend/capture/data/rule_base_rates.json` (22 benign, 8 attack captures). APK:
`apk_corpus/analysis/blind_v6/`, `apk_corpus/analysis/efp/`.*
