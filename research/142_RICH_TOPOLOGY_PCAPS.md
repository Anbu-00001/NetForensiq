# Rich-Topology PCAP Sources for the "Who Talked to Whom" Diagram

**Date:** 2026-08-20
**Problem:** The three loaded captures (AsyncRAT/XWorm, one-week-of-scans, our synthetic
capture) all draw as a star/fan — one host vs. many. We need publicly downloadable PCAPs
where MANY internal hosts talk to MANY other hosts, including internal↔internal (lateral)
traffic, so the network diagram looks like a real multi-actor investigation.

**Method:** Fetched primary source pages directly (`curl`/WebFetch), decoded Nextcloud share
metadata for exact byte sizes, range-probed one download link to confirm it actually streams
pcap data, and cross-checked scenario/topology claims against the hosting organisation's own
pages wherever possible. Anything not independently confirmed is marked **UNVERIFIED**.

---

## Ranked shortlist (top 5)

Ranking weights: richness of topology (many-to-many, internal↔internal) × downloadable
without registration × redistribution/licence safety × existence of ground truth.

| Rank | Dataset | Topology richness | No registration | Licence safety | Ground truth |
|---|---|---|---|---|---|
| 1 | **MACCDC 2012** (Netresec) | Excellent — full CDX enterprise network under live red-team attack | Yes | Organiser-sanctioned, no formal licence | Extensive third-party analyses, no single canonical answer key |
| 2 | **WRCCDC** (2018–2026, archive.wrccdc.org) | Excellent — same CDX genre, finer-grained files | Yes | **Unverified** — no licence text found anywhere | None found |
| 3 | **MACCDC 2010 / 2011** | Excellent, same as #1 | Yes | Same as #1 | Same as #1 |
| 4 | **CSE-CIC-IDS2018** (S3, `cse-cic-ids2018` bucket) | Very good on paper (420 clients + 30 servers + 50 IoT) but synthetic/AWS | Yes (anonymous S3, no-sign-request) | Cite-only, publicly hosted by UNB/CIC via AWS Open Data | Published paper + labelled flows |
| 5 | **CIC-IDS2017** (UNB/CIC) | Good — 12 victim hosts + up to 5 attacker hosts, real OS mix | **No — request form required** | Cite-only | Published paper + labelled flows, matches pcap timestamps |

CTU-13 and Nitroba are documented in detail below but did **not** make the top 5 — CTU-13
because its downloadable pcap structurally cannot show the rich topology we need (see catch
below), Nitroba because it is a small home-LAN capture, not an enterprise one.

---

## 1. MACCDC 2012 — RECOMMENDED PRIMARY CANDIDATE

- **Name:** PCAP files from the Mid-Atlantic Collegiate Cyber Defense Competition, 2012
- **Landing page:** https://www.netresec.com/?page=MACCDC (fetched directly, verified)
- **Share page:** https://share.netresec.com/s/7qgDSGNGw2NY8ea
- **Direct download (verified reachable):**
  ```
  curl -L -o maccdc2012.zip "https://share.netresec.com/public.php/dav/files/7qgDSGNGw2NY8ea/?accept=zip"
  ```
  I range-probed this exact URL (`curl -r 0-524287`) and confirmed it returns HTTP 200 and
  streams real Zip data (`Zip archive data, at least v4.5 to extract, compression
  method=store`) — this is a live, working link, not a dead page.
- **Size:** **5,668,083,801 bytes ≈ 5.68 GB** — read directly out of the share page's own
  Nextcloud metadata (`"details":"5668083801"` in the decoded `initial-state-core-public-page-menu`
  JSON blob), not an estimate.
- **Format:** pcap, inside a zip of the whole folder. Multiple secondary sources (Security
  Onion docs, Wireshark community, training material) describe it as split into ~10 files
  named `maccdc2012_00000.pcap` … `maccdc2012_00009.pcap` of a few hundred MB each — I could
  **not** get an authenticated WebDAV file listing to confirm the exact per-file breakdown
  (Nextcloud share blocked anonymous PROPFIND), so treat the individual filenames as
  **UNVERIFIED**, but the ~5.68 GB total is confirmed.
- **Topology — the reason this is #1:** MACCDC is a real Collegiate Cyber Defense
  Competition. Per the organiser's own description (quoted from the Netresec page): teams are
  "physically co-located," "each team is given physically identical computer configurations,"
  and teams "ensure the systems supply the specified services while under attack from a
  volunteer Red Team," plus scripted "injects" simulating real business activity. That means:
  several competing teams (each running a full stack — DNS, web, mail, DB) on one scored
  network, all being scanned/exploited by one Red Team, plus internal team-to-team and
  service-to-service chatter, plus green-team "normal user" background traffic. This is
  structurally the many-hosts-talk-to-many-hosts, mixed-protocol, lateral-movement-shaped
  topology the diagram needs — not a single infected box.
- **Licence:** No formal licence text on the Netresec page itself. However, MACCDC's own
  organisation announced the release itself in the past (a Facebook post titled "PCAP files
  from 2010, 2011, and 2012 competitions are available…" linking to Netresec — found via
  search, **UNVERIFIED** that the post is still live, but the existence of an organiser
  announcement is a strong provenance signal). It has been openly hosted for 10+ years, is
  referenced in the Wireshark wiki, Security Onion's own documentation, and multiple academic
  papers, without any takedown. Recommendation: safe for internal contest/demo use with
  attribution to MACCDC/Netresec; do not claim it as our own or bundle for redistribution
  beyond the demo.
- **Ground truth:** No single official "answer key," but it is one of the most-analysed
  public pcaps in the security-training world (referenced in books like *Practical Packet
  Analysis*, SANS coursework, and many independent write-ups), so findings can be
  cross-checked against a large body of public analysis even without one canonical document.
- **Honest catch:** 5.68 GB is well over the "parse in minutes / under 500 MB" target. Do
  **not** try to load the whole zip. Download once, then use `editcap`/`tcpdump -r ... -w`
  to slice out a single one of the ~10 constituent files or a fixed packet-count/time-window
  subset for the demo. 2012 traffic is 13+ years old — a judge could note the age, though it's
  far more recent and far richer than DARPA/Lincoln Labs 1998–99 data.

## 2. WRCCDC (Western Regional CCDC) — richer size granularity, licence unverified

- **Archive root:** https://archive.wrccdc.org/pcaps/ (fetched, confirmed a real Nginx
  directory listing)
- **Years available (confirmed from directory listing):** 2012, 2016, 2017, 2018, 2019,
  2020, 2021, 2024, 2025, 2026.
- **Format/size:** `.pcap.gz` files named `wrccdc.YYYY-MM-DD.[HHMMSS].[microseconds].pcap.gz`.
  For 2018 specifically: 500+ files, individual files ranging **66.8 MiB to 231.8 MiB**
  (confirmed via directory listing), i.e. a single file is comfortably inside the 500 MB
  budget — this is the main practical advantage over MACCDC's monolithic zip.
- **Topology:** Same CDX genre as MACCDC — WRCCDC's own description: "CCDC is the first
  competition that specifically focuses on the operational aspect of managing and protecting
  an existing 'commercial' network infrastructure." Same expectation: multiple teams' full
  enterprise stacks under live red-team attack, i.e. rich many-to-many traffic.
- **Licence:** **UNVERIFIED and this is the deciding weakness.** I checked both
  `archive.wrccdc.org` (the directory-listing root) and `wrccdc.org` (the official competition
  site) directly — neither page states any licence, terms of use, or explicit authorisation
  for redistributing the captures. The directory listing itself is served by a generic Nginx
  fancy-index theme with no accompanying README. Unlike MACCDC (where the organiser's own
  Facebook account announced the Netresec mirror), I found no equivalent public statement of
  WRCCDC endorsing this specific archive's publication. Treat as **lower confidence on
  redistribution safety** than MACCDC until an explicit statement is found — fine to use
  internally for a hackathon demo/analysis, but don't publish it as "cleared" data.
- **Ground truth:** None found.
- **Honest catch:** Total 2018 volume alone is 90+ GB (many files); pick exactly one file.

## 3. MACCDC 2010 / 2011

- **2010:** https://share.netresec.com/s/wC4mqF2HNso4Ten — verified size
  **10,240,538,366 bytes ≈ 10.24 GB** (same Nextcloud metadata technique).
- **2011:** https://share.netresec.com/s/mQaZcBPAN3iqdYH — verified size
  **13,395,732,948 bytes ≈ 13.40 GB**.
- Same topology, provenance, and licence profile as MACCDC 2012, just larger and less
  commonly cited in the literature (2012 is the "canonical" one most write-ups use). Useful
  as a backup/alternate year if 2012 is somehow unsuitable, but no reason to prefer them over
  2012 given the larger download size.

## 4. CSE-CIC-IDS2018 — richest topology on paper, fully synthetic, huge

- **Access (verified, no registration):** public AWS S3 bucket, confirmed via anonymous
  `ListBucketResult` XML request — no `aws` CLI or credentials needed:
  ```
  aws s3 sync --no-sign-request s3://cse-cic-ids2018/ dest-dir
  # or browse via HTTPS:
  curl "https://cse-cic-ids2018.s3.amazonaws.com/?list-type=2&delimiter=/"
  ```
- **Structure (confirmed by listing the bucket):** `Original Network Traffic and Log
  data/` contains 10 day-folders: `Wednesday-14-02-2018` through `Friday-02-03-2018`. Each
  day-folder has a `pcap.zip` and a `logs.zip`. I confirmed the size of one day directly:
  **`Friday-02-03-2018/pcap.zip` = 44,789.8 MB ≈ 44.8 GB** for a single day (`logs.zip` for
  the same day is a much smaller 236.7 MB, but that's logs, not packets).
- **Topology:** Per secondary sources (topology description not independently re-verified
  against a primary CIC document beyond the search-engine summary): a synthetic enterprise
  network built on AWS with **~420 client VMs + ~30 servers (SSH/FTP/HTTP(S)/SMTP/DNS) + ~50
  IoT-style devices**. Numerically this is the richest topology of anything reviewed here —
  by far — because it deliberately simulates a large "LAN."
- **Licence:** Hosted as part of the AWS Open Data Sponsorship Program under UNB/CIC's cite-only
  terms (same citation requirement as the rest of the CIC dataset family). No paywall or
  registration gate on the S3 bucket itself, unlike CIC-IDS2017's request-form gate.
- **Ground truth:** Published paper (Sharafaldin et al.) plus labelled-flow CSVs in the
  "Processed Traffic Data for ML Algorithms" side of the bucket.
- **Honest catches:**
  - This is a **fully synthetic, script-generated AWS environment** — "benign" traffic was
    produced by behaviour-profiling agents (the CIC "B-Profile" system), not organic human
    users. A judge who knows the CIC datasets will recognise this immediately and can
    legitimately call it "simulated," exactly the risk flagged in the brief.
  - 44.8 GB **for one day alone** is wildly over budget. To use this practically you'd need
    to range-fetch just part of one pcap.zip (S3 supports HTTP range requests, so it's
    possible to read the zip's central directory and pull a single member file without
    downloading the whole archive, but this needs custom tooling — not a simple `curl`).

## 5. CIC-IDS2017 — good topology, gated behind a request form

- **Official page:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Download:** now routes through https://cicresearch.ca/CICDataset/CIC-IDS-2017/, which is
  a **request/registration form** ("CIC Dataset Download Form," info used for "internal CIC
  Statistical Purpose") — confirmed via search results describing the current form-gated flow;
  the old direct anonymous directory listing at `205.174.165.80` now 301-redirects to
  `cicresearch.ca` and no longer serves a raw file listing. This **fails the "downloadable
  without registration" criterion** from the brief.
- **Size:** reported elsewhere as 48.4 GB packed / 50 GB unpacked for the full 5-day set —
  **UNVERIFIED directly** (couldn't get a live directory listing to confirm).
- **Topology (from the official UNB page, fetched directly):** internal LAN `192.168.10.0/24`
  with **12 victim machines** (2 Ubuntu servers, 4 Ubuntu workstations, 5 Windows
  Vista/7/8.1/10, 1 Mac) behind a firewall (`172.16.0.1`) to an external network
  `205.174.165.0/24`, plus an attacker network with a Kali box and 3 Windows machines. Real
  many-to-many potential inside the victim LAN.
- **Licence:** cite-only, publicly stated as "publicly available for researchers," but now
  gated by the request form above.
- **Ground truth:** Published ICISSP paper (Sharafaldin et al. 2018) plus labelled flow CSVs
  keyed to pcap timestamps — among the best-documented ground truth of anything reviewed.
- **Honest catch:** the UNB page's own language — "generating realistic background traffic
  was our top priority," achieved via profiling "25 users" into an automated B-Profile system
  — means the benign traffic is **simulated**, not organic. Same synthetic-data objection a
  judge could raise applies here as with CSE-CIC-IDS2018.

---

## Full findings by source (including ones that did NOT make top 5)

### Netresec "Publicly available PCAP files" index (https://www.netresec.com/?page=PcapFiles)

Fetched directly. Confirmed entries relevant to the brief:

- **MACCDC** (2010/2011/2012) — see above, top pick.
- **ISTS** (Information Security Talent Search) — https://www.netresec.com/?page=ISTS.
  Fetched directly: only one dataset listed, **ISTS 12** (March 2015), and both download
  links on the page literally read **"(download temporarily unavailable)"** as of this
  fetch. Same CDX genre and topology promise as MACCDC, but currently **not downloadable** —
  excluded.
- **WRCCDC** — linked from the index to `archive.wrccdc.org/pcaps/` (over 1 TB total across
  all years per the index page's own description) — see above.
- **DEFCON CTF** (`media.defcon.org`) — linked from the index. I spot-checked DEF CON 24's
  CTF directory and found a **real, live file**: `LegitBS DEF CON 24 ctf packet
  captures.rar` at
  `https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20ctf/LegitBS%20DEF%20CON%2024%20ctf%20packet%20captures.rar`
  — confirmed reachable (`HTTP/2 200`), but the server didn't return a `Content-Length`
  header on HEAD, so **exact size is UNVERIFIED** without a full download. CTF "king of the
  hill" traffic is genuinely N-to-N (every team's vulnbox is attacked by every other team, so
  the graph would be a dense mesh), which structurally is the richest topology shape of
  anything on this list — but the *content* is mostly raw exploit/shellcode traffic rather
  than an "investigation" narrative, and no licence statement was found for the DEF CON media
  archive. Flagged as promising but **not fully vetted** given time constraints — worth a
  follow-up look if MACCDC/WRCCDC don't pan out.
- **DEFCON CTF 2018** (oooverflow.io) — linked from the index, not independently checked.
- **CSAW CTF 2011**, **HackEire CTF** — linked from the index, not checked (small/old CTF
  archives, lower priority).

### Stratosphere IPS / CTU-13 (https://www.stratosphereips.org/datasets-ctu13)

Fetched directly (raw HTML, not just search summaries).

- **Structure confirmed:** 13 scenarios, individually downloadable as
  `CTU-Malware-Capture-Botnet-42` through `-54` (URLs confirmed present in the page HTML),
  plus one combined `CTU-13-Dataset.tar.bz2` (1.9 GB).
- **License:** CC-BY 2.0 (confirmed on page) — the *best* licence of anything reviewed here.
  Zip files are password-protected with password `infected`.
- **Citation:** Garcia, Grill, Stiborek, Zunino, "An empirical comparison of botnet detection
  methods," Computers & Security, 2014.
- **THE decisive catch (verbatim quote pulled directly from the page):**
  > "TYPE OF FILES AND DOWNLOAD Each of the scenarios in the dataset was processed to obtain
  > different files. **For privacy issues the complete pcap file containing all the
  > background, normal and botnet data is not available.** However, the rest of the files is
  > available. Each scenario contains: The pcap file for the botnet capture only... The
  > bidirectional NetFlow files (generated with Argus) of all the traffic, including the
  > labels... The original executable file."

  In other words: **the only pcap you can actually download per scenario is the
  botnet-traffic-only capture.** The "normal" and "background" hosts — the ones that would
  give you the rich, many-host, non-infected-looking topology — exist only as anonymised
  NetFlow records (`.biargus`), not as packets. This directly undermines the goal: downloading
  CTU-13's pcap gets you the infected host(s) talking to their C2/victims, which is
  structurally the same star/fan shape we're already stuck with on the AsyncRAT/XWorm
  capture, just relabelled. Some scenarios reportedly have multiple simultaneous infected
  hosts (this varies by scenario; exact per-scenario infected-host counts were **not**
  independently confirmed — the page's Table 3/4 with those numbers are rendered as images I
  could not OCR), which could add a little multi-actor structure to the botnet-only pcap, but
  it will never include the full enterprise background traffic. **Excluded from the top 5 for
  this reason** despite having the best licence and solid ground truth of anything reviewed.

### Digital Corpora (https://digitalcorpora.org/)

Fetched the network-packet-dumps index and several individual scenario pages directly.

- **Nitroba University Harassment Scenario** (2008) —
  https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/
  - **Size:** pcap file "about 60MB" (stated directly on the page) — comfortably inside the
    500 MB budget.
  - **Topology:** a single Ethernet tap in **one dorm room** with a shared Wi-Fi router (no
    password) — "Three women share the dorm room... one of the women's friends installed a
    Wi-Fi router." So the internal side is realistically **a handful of laptops (maybe 3–6
    devices)** behind one NAT'd link, talking outward to Yahoo Mail, a message-self-destruct
    web service, etc. This is a small home-LAN fan-out, not an enterprise many-to-many
    topology — same fundamental shape problem as the current captures, just with a different
    (and genuinely compelling) DFIR narrative (cyber-harassment investigation).
  - **Licence:** page includes published MD5/SHA1/SHA256 hashes and is explicitly maintained
    as a public teaching resource by Digital Corpora (sponsored by the AWS Open Data
    Sponsorship Program per the site's own header).
  - **Ground truth:** yes — a password-protected teacher's solution exists, gated to
    "faculty at accredited educational institutions" (confirmed from page comments/admin
    replies) — we would not qualify for the solution key itself, but the scenario write-up
    and slides are public.
  - Verdict: good as a **secondary, small, narrative-rich supplementary capture**, not a
    primary fix for the topology problem.

- **M57-Patents Scenario** (2009) —
  https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
  - Multi-day network captures ("Network Traffic" organised "by calendar date," spanning
    roughly mid-November through December) of a fictional small company ("M57 Patents") with
    named employees (Jo, Terry, etc.) — potentially a richer, multi-employee office LAN than
    Nitroba.
  - **Access is UNVERIFIED / at risk:** distribution is via torrent trackers (Terasaur,
    formerly torrents.ibiblio), and the page's own comment history (2012–2017) shows repeated
    user reports of broken links and unexplained auth walls, with admins patching links
    reactively over the years. I did not have time to confirm current, working, anonymous
    download links or actual file sizes. Flag as a **possible follow-up**, not confirmed
    usable today.

- **2018 Lone Wolf Scenario** — checked and **excluded**: this is a disk-image/memory-forensics
  scenario (`.E01`–`.E09` EnCase images, `memdump.mem`, `pagefile.sys`), not a network capture
  at all.

- **DEFCON 20 CTF** (`downloads.digitalcorpora.org/corpora/packets/2012-defcon/`) — over 2000
  packet dumps from a competitive event; not independently examined for topology/size given
  time constraints.

- **5GB TCP Connection** pcap — single-connection TCP-reassembly test file, not relevant to a
  multi-host topology.

### malware-traffic-analysis.net multi-host / AD-environment exercises

- Found several 2024–2026 dated "traffic analysis exercise" posts that are explicitly
  Active-Directory environments (not single-infected-host malware captures like the
  AsyncRAT/XWorm one already loaded). Directly fetched **2025-06-13** ("It's a Trap!") as a
  concrete example:
  - Single `/24` LAN (`10.6.13.0/24`) with a named AD domain (`MASSFRICTION`) and a domain
    controller at `10.6.13.3` (`WIN-DQL4WFWJXQ4`), plus at least one infected Windows client
    the exercise asks students to identify (IP/MAC/hostname/user account).
  - **File:** `2025-06-13-traffic-analysis-exercise.pcap.zip`, **39.3 MB** (well within
    budget), password-protected (site-standard password, on the About page).
  - **No answer key published** by the site author ("I'm not going to post any answers, so
    feel free to do what you will with the data") — third-party write-ups (e.g. a Medium post
    titled "2025-06-13 — Traffic Analysis Exercise: It's a Trap!") likely exist and could
    serve as informal ground truth, but I could not fetch that specific article (blocked by
    Cloudflare bot-protection on Medium) so its content is **UNVERIFIED**.
  - **Topology:** genuinely an AD environment (DC + client), but scaled small — one /24
    subnet, likely only a handful of hosts total (DC + a few workstations), not a large
    enterprise. Better than a single-host star, but smaller-scale than MACCDC/WRCCDC/CIC.
  - **Licence:** the site's About page states "Copyright © 2026 | Malware-Traffic-Analysis.net"
    with no explicit redistribution licence — same informal-but-long-standing-public-use
    status as the AsyncRAT/XWorm capture already in the project, so no new legal exposure
    versus what's already accepted for this project.
  - There are other similarly-dated exercises worth a follow-up pass if a small
    multi-host AD capture is wanted as a *supplement* rather than a topology fix: 2024-11-26
    (Nemotodes), 2024-09-04 (Big Fish in a Little Pond), 2024-08-15 (WarmCookie), 2024-07-30
    (You Dirty Rat!) — titles found via search, **not individually fetched/verified**.

### CIC-IDS2017 / CSE-CIC-IDS2018 (CIC, UNB)

See ranked entries #4 and #5 above for full detail.

### Other sources checked and excluded

- **Splunk Boss of the SOC (BOTS v1/v2/v3)** — confirmed via GitHub (`splunk/botsv3`,
  `splunk/botsv2`) that these ship as **pre-indexed Splunk data, not raw pcap**. Excluded —
  fails the "PCAP" requirement outright.
- **LANL Unified Host and Network Dataset** — confirmed via `csr.lanl.gov/data/2017/` and
  secondary sources: **NetFlow (Cisco NetFlow v9) and Windows event logs only, no pcap
  traces**. Excluded.
- **UNSW-NB15** — raw pcap is available (100 GB, per UNSW's own page), but the topology is
  explicitly an **IXIA PerfectStorm traffic-generator rig**: "three virtual servers, two
  routers... Server 1 and 3 generate normal traffic, while server 2 generates malicious
  traffic" — a narrow, explicitly synthetic 3-server topology, not organic many-host traffic.
  Lower priority than CIC datasets which at least simulate a full LAN of distinct machines.
- **MAWI Working Group Traffic Archive** (`mawi.wide.ad.jp`) — real backbone transit traffic
  (Tokyo–US link), anonymised with **Crypto-PAn prefix-preserving anonymisation** (confirmed
  via MAWI's own FAQ) — notably this is the *good* kind of anonymisation the brief warned
  about (prefix-preserving retains relative subnet/topology structure, unlike a naive
  full-randomisation that would collapse everything into one subnet). However it's packet
  **headers only, no payloads**, and — more fundamentally — it's aggregate ISP transit
  traffic between unrelated hosts, not a coherent incident/investigation with an internal
  network. Excluded as not narratively fit for a forensic "investigation" diagram even though
  the anonymisation itself isn't the problem.
- **DARPA/Lincoln Labs 1998–99 datasets** — not independently re-fetched this round (well
  known already); flagged per the brief as carrying an obvious "this traffic is 25+ years
  old" objection a judge could raise. Not recommended regardless of topology richness.
- **SecRepo.com** — confirmed to exist as a curated links index, but did not independently
  verify specific rich multi-host pcap holdings within the time available; treat any
  SecRepo-sourced dataset as needing its own individual verification pass.

---

## On PCAP anonymisation destroying topology (as requested)

Two genuinely different things get called "anonymisation" and they have opposite effects on
a "who talked to whom" diagram:

1. **Prefix-preserving anonymisation** (e.g. Crypto-PAn, used by MAWI) — replaces real IPs
   with fake ones but preserves subnet/prefix relationships, so hosts that were on the same
   subnet before anonymisation are still grouped together after. This **preserves** topology
   shape, just strips real-world identity. Fine for a diagram, bad for attributing to a real
   organisation.
2. **Flat/full randomisation or IP-rewrite-to-one-subnet** (not directly observed in any
   dataset fetched this round, but this is the failure mode the brief warned about) —
   collapses distinct external actors into a narrow synthetic range, or maps everything
   through a small NAT pool, which **destroys** the many-to-many shape entirely and can make
   a genuinely rich capture look artificially star-shaped after anonymisation. None of the
   datasets ranked in the top 5 above are known to do this, but it's worth spot-checking the
   IP diversity (`tshark -q -z endpoints,ip` or similar) on whatever is finally chosen, since
   some published "sanitised" law-enforcement/vendor pcaps do exactly this and it would
   silently reproduce the exact problem we're trying to fix.

---

## Recommended next step

Download MACCDC 2012 (Item #1), slice out a single constituent pcap or a fixed time window
with `editcap`, and check basic host/edge counts (`tshark -q -z endpoints,ip` /
`-z conv,ip`) before committing — confirm empirically that it actually produces a dense
many-to-many graph rather than assuming it from the competition description alone.
