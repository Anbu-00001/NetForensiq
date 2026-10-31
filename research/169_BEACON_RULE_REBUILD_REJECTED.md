# 169 — A beacon rule rebuilt on published methods, measured, and not shipped

Dated 31 Oct 2026. The blind audit (research/168, M7) repeated what the measurements already
said: `C2_BEACON_PERIODIC` fired on 4 of 22 captures of ordinary traffic and on none of 8
attacks. This note records an attempt to replace it with a rule built only from published
methods, the measurement that decided it, and why the old rule is still the one in the code.

## New data

Collected for this, kept outside the repository in `mal/` with a manifest of source, published
date, family, what the source says and SHA-256 per file (every hash re-checked after download):

* **39 attack captures**, 2015–2026, 31 of them from 2022 or later: 26 from
  malware-traffic-analysis.net (Cobalt Strike behind Qakbot, Pikabot, Gozi, Bumblebee, BazarLoader,
  Emotet, SSLoad and others; NetSupport, AsyncRAT, Remcos, DarkGate, Lumma, XWorm, njRAT), 5 DNS
  tunnels (Tu, Liu and Sun, Computers & Security 2023), 4 Sliver captures, 2 from PCAP-ATTACK's
  command-and-control folder, 2 from the Stratosphere MCFP. 18 are marked `c2_expected` because
  their source describes C2 or post-infection traffic; the rest are not assumed either way.
* No captures of Brute Ratel, Havoc or Mythic, and no ICMP tunnels, could be found.

Before any measurement the 39 were split by the last hex digit of each SHA-256: 15 for
development (7 with expected C2), 24 held out (11 with expected C2). The held-out half was
measured once, after the rule was frozen.

## The published methods (survey kept in prep/, not in the repository)

No source read separates scheduled software from C2 by timing alone, and several say so
directly. Elastic: their framework is "not as a means for detection". Fox-IT: "some baselining
is necessary". RITA's composite score, ported and fed synthetic timestamps, gives a Poisson
(non-periodic) flow 74–85 out of 100 on a 30-minute capture and an NTP poll the same 100 as a
default Cobalt Strike beacon: its 24-hour histogram and duration parts saturate on a short capture.

What could be cited:

| Element | Value | Source |
|---|---|---|
| Group | initiator, destination, service port, transport; TLS server name in place of the address when seen | Flare triad; RITA SNI grouping |
| Evidence floor | at least 10 connections over at least 30 s | van der Eijk & Schuijt, OS3 2020 |
| Test 1 | coefficient of variation of the gaps ≤ 0.2 | our choice: admits Cobalt Strike to 50 % jitter (0.19) and Sliver defaults (0.115), computed from vendor documentation; 0.2 also appears in Yilmaz et al. 2026 (secondary) |
| Test 2 | more than 50 % of gaps of 30 s or more in one 2-second window | Flare `configs/elasticsearch.ini` |
| Label | UDP/123 named as an NTP poll and kept LOW | RFC 5905 |

## Development

On the 15 development captures the old rule fired on 2 of the 7 with expected C2, the new one
on 3. The new rule caught a Pikabot channel of 13 connections whose gaps varied by 0.06 %, which
the old rule's 23-connection floor excluded. The same capture showed the limit every source
predicts: Bing and Microsoft telemetry from the same machine were as regular as the controller.

Writing the per-group statistics tool (`scripts/beacon_group_stats.py`) exposed a grouping bug in
the draft: a flow stored server-first holds the client's ephemeral port in `dst_port`, which put
every connection in a group of its own. The rule and the tool both take the service port from
`flow_direction()`.

## Held out, measured once

| | Old rule | New rule |
|---|---|---|
| Held-out attack captures (24) | **6** | 4 |
| of which C2 expected (11) | **5** | 3 |
| Ordinary traffic, the 22 captures of the shipped table | **4** | 6 |

The new rule is worse on both. It lost BazarLoader (callbacks about 5 s apart) and Pikabot
(about 2 s): Flare's test ignores gaps under 30 s, and those beacons were not regular enough for
the CV test. RITA's skew and MAD score, for all its faults on short captures, caught them. The
lower floor of 10 connections let in two more ordinary captures.

Predictions were logged before the held-out run. Four of five were wrong, in the direction of
expecting the rebuild to do better than it did.

## Decision

The old rule stays. Designing a third version now would be fitting it to the held-out half, which
has been seen. The rejected rule is kept as a patch beside the data, not in the code. What this
work does leave in the repository is the group statistics tool, and a larger measurement of the
rules that ship (below).

The lesson for the next attempt: short-cadence beacons (seconds, not minutes) are common in
these captures, a rule built around minute-scale defaults misses them, and any new rule needs
fresh held-out captures, because these are spent for beacon design.

## The rules that ship, measured on 91 captures

The new captures also give a larger measurement of the rules as they are. Ordinary traffic: the
22 captures of the shipped table plus 22 newly collected (IoT-23 device traffic, CTU-IDSEVAL-6,
five i46 `normal` captures, nine University of Malaga captures of scripted agents; all CC BY 4.0,
each file's hash checked against its manifest). Attacks: the 8 of the shipped table plus the 39
above. The shipped code was re-run on the original 30 first and reproduced the shipped table
exactly, rule by rule, so the old and new figures come from the same code.

| Rule | Ordinary (44) | Attacks (47) | One-sided Fisher exact p |
|---|---|---|---|
| `DNS_TUNNEL_LONG_LABEL` | 1 | 7 | 0.036 |
| `DNS_TUNNEL_SUBDOMAIN_VOLUME` | 2 | 6 | 0.16 |
| `COVERT_CHANNEL_UNKNOWN_PORT` | 11 | 15 | 0.31 |
| `ICMP_TUNNEL_OVERSIZED` | 2 | 3 | 0.53 |
| `C2_BEACON_PERIODIC` | 7 | 8 | 0.56 |
| `EXFIL_VOLUME_ASYMMETRY` | 17 | 16 | 0.75 |
| `RECON_PORT_SCAN` | 5 | 4 | 0.79 |
| `C2_BEACON_KEEPALIVE` | 14 | 9 | 0.95 |
| `ANOMALY_STATISTICAL` | 41 | 29 | 1.0 |
| `IOC_FEED_MATCH`, `HOST_CORROBORATED` | 0 | 0 | untested |

The p value is the chance of at least that many attack captures firing if the rule fired equally
often on both kinds; computed exactly from the hypergeometric distribution and checked against
SciPy. One rule clears 0.05. The others do not show that they fire more often on attacks than on
ordinary traffic, and the keepalive rule fires more often on ordinary traffic.

Three things limit this:

* **A count is per capture, not per host.** An attack capture also holds the victim's ordinary
  traffic. The destinations the beacon rules named on attack captures were not checked against the
  sources' indicator lists, which were not downloaded, so some of those firings may be on
  background traffic. The Pikabot development capture shows that this happens.
* **The attack corpus is mostly malware infections.** Few of the 47 contain scanning, so the
  port-scan rule looks worse here than on the 8 of the shipped table, three of which are
  captures of internet-facing machines being scanned. A rule should be judged on the attacks it is written for.
* **The new ordinary traffic is not a laptop or a phone.** It is IoT devices, lab captures labelled
  `normal`, and scripted agents. No benign-labelled phone or current Windows/macOS capture could
  be found under an open licence.

**Not installed.** The engine still reads the 30-capture table. Installed as it is, the larger table
would *raise* the beacon rules' severity, because the current cap applies only to a rule that has
never fired on an attack capture, and both now have. A cap that asks instead whether a rule fires
significantly more often on attacks would put every rule but one at LOW. Either changes what an
officer sees on every capture, so it is left as a decision rather than made here. The table is in
`validation/network_rules_91_captures.json`; the per-capture results and the corpora's manifests
are kept with the captures outside the repository.
