# Validation against real traffic

Until 15 Aug 2026 every detection result in this project came from our own
synthetic generator. That is circular: a detector finding attacks that the same
codebase planted proves only that the two agree with each other.

This document records what happened when the engine was run against two real
captures from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net),
neither produced by us, both with independently published ground truth.

**It found five defects.** Every one of them was invisible to the synthetic corpus.

---

## The captures

| Capture | Size | Packets | Flows | What it is |
|---|---|---|---|---|
| `2024-03-14-AsyncRAT-and-XWorm-infection-traffic.pcap` | 44 MB | 46,304 | 36 | A real Windows host infected with AsyncRAT and XWorm, ~3.5 minutes of post-infection C2 |
| `2024-12-18-one-week-of-server-scans-and-probes-and-web-traffic.pcap` | 28 MB | 361,992 | 141,638 | One week of a real internet-facing server being scanned and probed |

The first tests **true positives** — can we find a documented C2 channel?
The second tests **false positives** — an internet-facing server is the most
hostile possible environment for a noisy rule.

Ground truth for the first, from the analyst's published notes:

```
C2:
- 91.134.150.150:3232 - TLSv1 traffic
- 91.92.252.234:3232  - TLSv1 traffic
- 91.134.150.150:7000 - encoded/encrypted TCP traffic
```

---

## First run: 0 detections on real C2, 7,052 on a real server

| | AsyncRAT (true positives wanted) | Server week (false positives feared) |
|---|---|---|
| **Before** | **0** | **7,052** |
| After | **5** — all on documented C2 | **262** |

Both numbers were wrong in the worst possible direction at once: blind to real
malware, and drowning in alerts on real background traffic.

---

## Defect 1 — the beacon rule counted packets where RITA counts connections

`rule_beaconing` iterated flows and tested `flow.packets_sent >= 23`, citing
RITA's `DefaultConnectionThresh`. **RITA counts connections between a host pair.
We counted packets inside a single connection and cited RITA for it.**

It agreed with the synthetic corpus only because
`generate_c2_beaconing` reused one source port for all 90 beacons, so
packets-per-flow happened to equal beacons. On real traffic a single TCP session
carries thousands of packets, and the intervals measured are TCP segment timing:
the AsyncRAT C2 flow reported `interval_median = 0.0011 s`.

**Fixed** by grouping flows into `(initiator, peer)` pairs and computing
intervals between *connection start times*. Because real inter-connection gaps
are now available, the full Bowley-skew + MADM score can be computed instead of
the dispersion component alone.

**The corpus was also wrong**, so `generate_c2_beaconing_connections` was added —
a beacon that opens a new connection per callback, which is the shape RITA
models. Both shapes are now represented and separately tested, and
`test_connection_beacon_counts_connections_not_packets` guards the regression.

## Defect 2 — nothing detected a persistent covert channel

AsyncRAT holds one connection open rather than reconnecting, so RITA's model
cannot see it *even when implemented correctly*. Two rules now cover the two
shapes:

- `C2_BEACON_PERIODIC` — RITA's model, repeated connections
- `C2_BEACON_KEEPALIVE` — ours, periodicity inside one long-lived session,
  scored with RITA's MADM formula so the alert threshold means the same thing

Neither fired on this capture: **3.5 minutes of AsyncRAT does not contain a
statistically detectable beacon period.** That is the honest result, and the
thresholds were left alone rather than tuned until the sample passed.

What *does* separate it is channel shape. Across the whole capture:

| | C2 flows (7) | Benign flows (12 largest) |
|---|---|---|
| Port | 3232, 7000 | 443 |
| App protocol identified | none | TLS |
| TLS SNI | **absent, all 7** | **present, all 12** |
| Duration | 148–206 s | 0–110 s |

So `COVERT_CHANNEL_UNKNOWN_PORT` fires on a sustained egress connection to a
non-well-known port with no identified protocol and no SNI. It found
**5 of the 7 C2 flows and none of the benign traffic**. The two missed are the
7 s and 13 s connections to `91.92.252.234`, below the 60 s sustained-session
floor — a real limitation, not a rounding error.

## Defect 3 — the rule read the wrong port entirely

On the server capture this rule alone produced **5,853 findings**. Every sampled
one was inbound, and the port it complained about was the *client's ephemeral
port* — 55684, 60806, 42778 — because the responder had been recorded as the
flow's source. Reading `dst_port` is only correct when the capture happens to
record the initiator as the source.

`flow_direction()` now derives `(initiator, peer, service_port)` from the
initiator, so the port tested is always the service being connected to.

## Defect 4 — no notion of which network is being defended

Snort and Suricata both define `$HOME_NET`. Without it, a rule meaning "an
internal host reached out to something odd" also fires on every scanner on the
internet reaching in.

`HOME_NET` is now a setting, defaulting to the RFC 1918 ranges as in Snort's
shipped configuration, and the egress rules require the initiator inside it.

This matters more than a filter: of 155 `C2_BEACON_PERIODIC` and 17
`C2_BEACON_KEEPALIVE` findings on the server capture, **zero** had a subject
inside HOME_NET. All 172 were external hosts probing inward — scanning, already
covered by `RECON_PORT_SCAN`, and actively misleading when labelled C2.

⚠️ **The default is wrong for a capture of a public-facing server**, whose own
addresses are public. Set it explicitly:

```bash
HOME_NET="203.161.44.0/24" python manage.py analyze_session 6
```

Doing exactly that on the server capture surfaced 7 genuine outbound keepalive
channels from the server itself that the default had hidden.

## Defect 5 — ICMP tunnelling flagged the server's own error replies

799 findings, **795 of them with the same subject: the monitored server**.

ICMP error messages quote the offending packet's header and the first 8 bytes of
its payload (RFC 792), so they are large *by design*. A server answering a week
of scans emits hundreds of destination-unreachables, and the rule called every
one a tunnel — because the processor discarded the ICMP type, keeping only the
protocol name.

The processor now packs type and code into the port field as `type*256 + code`,
following the Cisco NetFlow convention for ICMP, and the rule accepts only echo
request (8) and echo reply (0) — the types every real ICMP tunnel uses
(ptunnel, icmpsh, icmptunnel).

That removed 338. Of the 461 that remained, **238 were single-packet flows**: an
echo reply mirrors the request payload, so one large reply to a scanner's large
ping is ordinary. A tunnel carries a stream, so a minimum packet count was added.

**799 → 25.**

---

## Where it stands

| Rule | AsyncRAT (3.5 min, infected host) | Server week (362k packets) |
|---|---|---|
| `COVERT_CHANNEL_UNKNOWN_PORT` | **5** — all documented C2 | 0 |
| `RECON_PORT_SCAN` | 0 | 235 — **235 distinct scanning hosts** |
| `ICMP_TUNNEL_OVERSIZED` | 0 | 25 |
| `EXFIL_VOLUME_ASYMMETRY` | 0 | 2 |
| `C2_BEACON_*` | 0 (see Defect 2) | 0 with correct HOME_NET; 7 when set to the server's own /24 |
| **Total** | **5** | **262** |

The 235 port-scan findings are not noise. The capture is titled *"one week of
server scans and probes"*; finding 235 distinct scanning hosts in it is the rule
working. One alert per scanner, not per probe.

## What this does not show

- Two of seven C2 flows are still missed (too short to qualify as sustained).
- No beacon-periodicity detection succeeded on real malware. The rules are
  implemented correctly and RITA's own thresholds assume far longer windows
  than 3.5 minutes; on this sample they are simply not enough.
- Two captures is not an evaluation. There is no measured precision or recall,
  and none should be claimed.
- A separate defect was found and **not yet fixed**: flow aggregation has no
  idle timeout, so a reused ephemeral port merges conversations hours apart into
  one "flow". The server capture contains flows reporting 22,736 s duration
  carrying 148 bytes. Recorded in PROGRESS.md.

## Reproducing

```bash
# password scheme is infected_YYYYMMDD, per the post date
unzip -P infected_20240314 2024-03-14-AsyncRAT-and-XWorm-infection-traffic.pcap.zip
python manage.py import_pcap <file> --name REAL-AsyncRAT
python manage.py analyze_session <id>
```
