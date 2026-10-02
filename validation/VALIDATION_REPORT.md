# NetForensiq 1.0.0 — tool validation report

Generated 2026-10-02 from `validation/results.json` by
`scripts/build_validation_report.py`. Every figure below is read from that file, which
`scripts/extract_validation_data.py` derived from run logs and corpus manifests; none is typed
into this document. Per-sample verdicts are in `validation/apk_samples.csv`.

## 1. Status of this report

This is **developer-supplied testing information**. It is not a validation of any laboratory's
method, it has **not been reviewed by anyone other than its author**, and it sets no acceptance
criteria, because those belong to the unit that will use the tool.

The UK Forensic Science Regulator's guidance on validating digital forensic methods
(FSR-G-218, Issue 2) defines validation as "The process of providing objective evidence that a
method, process or device is fit for the specific purpose intended" (s.3.3.1), and places the
onus on the user: "The onus is for the organisation using the method (i.e. the forensic unit)
to demonstrate validation, although the developer may greatly assist the end user by providing
information on the testing that has already been performed" (s.1.1.10). This document is that
information, arranged as the guidance asks a record to be: each requirement with its finding,
failures "explicitly highlighted", and "Any limitations of the validation approach and the method
itself should be detailed" (s.7.6.4). It does not claim compliance with the guidance.

## 2. The tool state these results belong to

| | |
|---|---|
| Platform version | 1.0.0 |
| APK examination engine | 2.0.0 |
| Shipped APK baseline table | `backend/apk_engine/data/baselines.json`, SHA-256 `36e6bb24641a93d5ebae0fc5593ccfa426788ebee0765cfa43ce904c7878ec56` |
| Network rule-rate table | `backend/capture/data/rule_base_rates.json`, SHA-256 `9b2777bd3b92ae79acd7ed015db04577b3176a4b13d3afce812608b68123099b` |

**Results are valid for this configuration only.** A change to the engine, the baseline table or
a rule is a change to the method, and the figures below must be re-measured before they are
quoted for it. After a change the guidance asks whether the method "remains fit for the specific
purpose" and whether the change "does not require revalidation of the method" (s.6.3.10b). Each
run below records the engine image and baseline hash it used.

## 3. What is being tested — the requirements

| # | The tool is claimed to… | Tested by |
|---|---|---|
| R1 | assign an Android package an evidence tier, and reach a tier on real malware it was not built from | §5.1: two sets of unseen malware |
| R2 | not raise a tier on legitimate software | §5.2: legitimate apps the engine was not adjusted against |
| R3 | say plainly when it could not examine a package, rather than report it clean | §5.1–5.2, tier 0 |
| R4 | state, for each network detection rule, how often it fires on ordinary traffic | §6 |
| R5 | compute the hashes certificates rely on correctly, including across read-chunk boundaries | known-answer tests, §7 |
| R6 | detect a change to any custody-log entry | §7 |

**Expected outcomes and error margin (s.7.2.1d).** No acceptable error margin has been set by a
forensic unit, so none is stated here as a pass mark. The project did pre-register expectations
before the final measurement (`apk_corpus/analysis/PREREGISTRATION.md`, v6). They were:

| Pre-registered claim | Stated probability | Outcome |
|---|---:|---|
| at least one native-code signal fires on 0 of 201 legitimate apps and on at least 20 of 200 malicious | 70% | **false** — 2 of 16 signals fired on no legitimate app; the best of them, `cap.native_header_damaged`, fired on 1 of 197 examined malicious samples. No rule was built from them. |
| the blind score reaches ≥ 70 / 100 | 35% | **false** — 52 / 100 |
| the blind score reaches the 80 / 100 target | 12% | **false** — 52 / 100 |

## 4. Test data, and how little control there was over it (s.7.2.1c)

The guidance asks that where "there is little or no control of the source data, this should be
explicitly declared in the plan and the subsequent limitation declared", and that validation data
be "representative of the real life use the method will be put to" (s.1.1.9). Neither corpus
below is chosen by the engine's authors to be representative of seized devices.

| Corpus | Kind | n | How it was chosen | Used for |
|---|---|---:|---|---|
| design | malicious APKs | 200 | MalwareBazaar (abuse.ch): file type `apk`, limit 200, acquired 2026-09-18 (its listing returns recent uploads) | the rules were written from these: **in-sample, not a detection claim** |
| held-out | malicious APKs | 100 | MalwareBazaar, selected by *exclusion* of the design set before any was examined; never by what the engine did with them | first unseen measurement |
| blind | malicious APKs | 100 | MalwareBazaar, the 600 most recent uploads, excluding both earlier corpora; downloaded and left unexamined until the engine was frozen; scored once | second unseen measurement |
| baseline | legitimate + malicious | 201 + 194 | F-Droid apps, 23 chosen because they legitimately do what malware does (install packages, create VPNs, handle SMS, run shell commands) plus a random sample | the reference the baseline table was measured on |
| fresh-benign | legitimate APKs | 100 | F-Droid, sampled with a new seed; not used for baselines, rule design or defect-finding | false-positive measurement |
| network, ordinary | captures | 22 | CTU Malware Capture Facility "Normal" set: 16 used to find and fix defects, 6 held out | rule false-alarm rates |
| network, attack | captures | 8 | published malware traffic with written analysis (malware-traffic-analysis.net), a wrccdc defence exercise, and one DNS-tunnel capture published by Elastic | whether rules fire at all on attacks |

**What these data are not.** MalwareBazaar holds what researchers choose to upload. F-Droid is a
cleaner population than the Play Store: its builds carry fewer tracking libraries, and the app
that broke an earlier scoring scheme was a Play build of a payments app, a class F-Droid
under-represents. The CTU "Normal" captures are, per their own READMEs, Windows virtual machines browsing the web,
home notebooks and university machines, recorded between 2013 and 2017. None is a seized phone or
a station network.

MalwareBazaar's terms ask that samples not be redistributed, so the repository carries their
SHA-256 digests only (`validation/apk_samples.csv`).

## 5. Results — the Android examination engine

Definitions: a sample is **detected** if it reached tier 2, 3 or 4. Tier 1 ("no harmful
behaviour established") on a malicious sample is a **miss**. Tier 0 means the package could not
be examined and is never counted as clean. Intervals are exact (Clopper–Pearson).

### 5.1 Malicious samples (R1, R3)

| Run | Corpus | Engine image | n | Tier 4 | Tier 3 | Tier 2 | Tier 1 | Tier 0 | Detected | 95% CI |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| `design-v5` | design | `sandbox-v5` | 200 | 10 | 65 | 88 | 34 | 3 | **163 / 200** (81.5%) | 75.4–86.6% |
| `heldout-v5` | heldout | `sandbox-v5` | 100 | 2 | 17 | 45 | 31 | 5 | **64 / 100** (64.0%) | 53.8–73.4% |
| `heldout-v6` | heldout | `sandbox-v6` | 100 | 2 | 17 | 45 | 31 | 5 | **64 / 100** (64.0%) | 53.8–73.4% |
| `blind-v6` | blind | `sandbox-v6` | 100 | 4 | 23 | 25 | 45 | 3 | **52 / 100** (52.0%) | 41.8–62.1% |


`design-v5` is in-sample and is shown only to be compared with the unseen rows; the gap between it
(163 / 200) and the unseen sets is the
finding. The held-out set was measured twice: by the v5 engine image when it was first scored,
and again by the shipped v6 image, so that both unseen sets describe one configuration.


**Both unseen sets together, on the shipped engine:
116 / 200 = 58.0%** (95% CI 50.8–64.9%). Of the 200 samples, 76 reached no
tier (**38.0% missed**) and 8 could not be examined.

**Engine image check.** Where a corpus was examined by both the v5 and the shipped v6 image (heldout and fresh-benign), 200 of 200 per-sample verdicts were identical. The v6 image adds a native-code survey that no rule uses, so by construction it cannot raise a tier; this is the measured confirmation.

**Failures, highlighted (s.7.6.4).** The engine does not meet an expectation of detecting most
unseen malware, still less the 80% target. The blind set scored below the held-out set
(52 against 64). Almost all of the difference is
tier 2 (integrity indicators — forged archive headers): 45 held-out samples
reached it and 25 blind ones. The likeliest reason, which was **not tested**, is
that the engine's strongest signal is a packaging trick and the blind set, the 600 most recent
uploads, may use it less. Google Play Protect's published 99.8% (AV-TEST, May 2025, on different
samples) is far higher, and nothing here claims otherwise.

### 5.2 Legitimate apps (R2, R3)

| Run | Engine image | Apps | Examined | Could not be examined | Reached a tier | 95% bound on the false-positive rate |
|---|---|---:|---:|---:|---:|---|
| `fresh-benign-v5` | `sandbox-v5` | 100 | 89 | 11 | **0** | ≤ 3.3% (one-sided) |
| `fresh-benign-v6` | `sandbox-v6` | 100 | 89 | 11 | **0** | ≤ 3.3% (one-sided) |

No examined legitimate app reached a tier. **11 of the
100 could not be examined and are not counted as clean**, which is why the bound is
computed over 89 and not 100: an earlier statement of "0 / 100, bound
3.0%" used the wrong denominator and was corrected on 2 Oct 2026 (research/154).

Zero is a count, not a rate. The one-sided 95% bound is the most the true false-positive rate
could plausibly be given zero in 89: ≤ 3.3%. The population is F-Droid
(§4), so the figure does not transfer to Play Store apps.

## 6. Results — the network detection rules (R4)

Each rule was run over 22 captures of ordinary traffic and 8 of attacks.
The rates are published with every finding in the interface and the investigation report.

| Rule | Ordinary-traffic captures it fired on | 95% upper bound on that rate | Attack captures it fired on | Reading |
|---|---:|---:|---:|---|
| `ANOMALY_STATISTICAL` | 22 / 22 | 100% | 4 / 8 | a lead, not a finding; fires on every capture by construction |
| `C2_BEACON_KEEPALIVE` | 10 / 22 | 65% | 0 / 8 | never seen on an attack; shown at LOW |
| `C2_BEACON_PERIODIC` | 4 / 22 | 37% | 0 / 8 | never seen on an attack; shown at LOW |
| `COVERT_CHANNEL_UNKNOWN_PORT` | 6 / 22 | 47% | 3 / 8 | fires on ordinary traffic; a reason to look, not a conclusion |
| `DNS_TUNNEL_LONG_LABEL` | 1 / 22 | 20% | 2 / 8 | fires on ordinary traffic; a reason to look, not a conclusion |
| `DNS_TUNNEL_SUBDOMAIN_VOLUME` | 2 / 22 | 26% | 1 / 8 | fires on ordinary traffic; a reason to look, not a conclusion |
| `EXFIL_VOLUME_ASYMMETRY` | 8 / 22 | 56% | 1 / 8 | fires on ordinary traffic; a reason to look, not a conclusion |
| `HOST_CORROBORATED` | 0 / 22 | 13% | 0 / 8 | untested: needs rules that fire on no ordinary capture to vote |
| `ICMP_TUNNEL_OVERSIZED` | 2 / 22 | 26% | 1 / 8 | fires on ordinary traffic; a reason to look, not a conclusion |
| `IOC_FEED_MATCH` | 0 / 22 | 13% | 0 / 8 | untested: silent without an imported feed |
| `RECON_PORT_SCAN` | 2 / 22 | 26% | 4 / 8 | fires on ordinary traffic; a reason to look, not a conclusion |

**Read these carefully.**

* "Fired on an attack capture" is not "caught the attack". `DNS_TUNNEL_LONG_LABEL`'s firing in the
  wrccdc exercise is a CDN name (`rackcdn.com`) in a capture that happens to be an attack.
* 8 attack captures is thin, and the attack corpus contains no connection-per-callback beacon, so
  `C2_BEACON_PERIODIC` is *untested* on attacks, not shown to fail. Both beacon rules are shown at
  LOW because neither has been seen to fire on one.
* With 22 ordinary captures, a rule that fired on none still has a one-sided 95% upper bound
  of 12.7% on its true rate.
* These runs used the working tree of 19–20 Sep 2026 before it was committed; no image or commit
  identifier was recorded for them. They should be repeated on a tagged build.

Per-capture results:

| Capture | Role | Flows | Findings | Rules fired (findings) |
|---|---|---:|---:|---|
| `CTU-Normal-13__2017-07-03_capture-win2.pcap` | benign · design | 61 | 2 | ANOMALY_STATISTICAL (2) |
| `CTU-Normal-14__2017-07-23_capture-winFull.pcap` | benign · design | 5,578 | 54 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (1), COVERT_CHANNEL_UNKNOWN_PORT (2), EXFIL_VOLUME_ASYMMETRY (1) |
| `CTU-Normal-18__2017-09-05_capture-win4.pcap` | benign · design | 38,147 | 54 | ANOMALY_STATISTICAL (50), EXFIL_VOLUME_ASYMMETRY (4) |
| `CTU-Normal-20__2017-04-30_win-normal.pcap` | benign · design | 18,830 | 57 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (2), C2_BEACON_PERIODIC (1), COVERT_CHANNEL_UNKNOWN_PORT (4) |
| `CTU-Normal-21__2017-05-02_kali-normal.pcap` | benign · design | 10,677 | 79 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (28), EXFIL_VOLUME_ASYMMETRY (1) |
| `CTU-Normal-23__2017-04-18_win-normal.pcap` | benign · design | 16,253 | 51 | ANOMALY_STATISTICAL (50), C2_BEACON_PERIODIC (1) |
| `CTU-Normal-24__2017-04-19_win-normal.pcap` | benign · design | 7,188 | 52 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (1), C2_BEACON_PERIODIC (1) |
| `CTU-Normal-26__2017-04-28_normal.pcap` | benign · design | 15,049 | 54 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (3), DNS_TUNNEL_SUBDOMAIN_VOLUME (1) |
| `CTU-Normal-28__2017-05-01_normal.pcap` | benign · design | 11,967 | 51 | ANOMALY_STATISTICAL (50), RECON_PORT_SCAN (1) |
| `CTU-Normal-33__capture-new-Windows-7-Full.pcap` | benign · design | 4,609 | 56 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (1), COVERT_CHANNEL_UNKNOWN_PORT (1), EXFIL_VOLUME_ASYMMETRY (2), ICMP_TUNNEL_OVERSIZED (2) |
| `CTU-Normal-4-only-DNS__2015-03-24_capture1-only-dns.pcap` | benign · design | 1,787 | 36 | ANOMALY_STATISTICAL (36) |
| `CTU-Normal-6-filtered__2013-10-21_capture-1-only-dns.pcap` | benign · design | 853 | 19 | ANOMALY_STATISTICAL (18), DNS_TUNNEL_LONG_LABEL (1) |
| `CTU-Normal-7__2013-12-17_capture1.pcap` | benign · design | 2,882 | 66 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (1), C2_BEACON_PERIODIC (1), COVERT_CHANNEL_UNKNOWN_PORT (5), EXFIL_VOLUME_ASYMMETRY (4), ICMP_TUNNEL_OVERSIZED (5) |
| `CTU-Normal-8-1__2016-09-13_win16.pcap` | benign · design | 522 | 11 | ANOMALY_STATISTICAL (11) |
| `CTU-Normal-8-2__2016-09-13_win16.pcap` | benign · design | 186 | 4 | ANOMALY_STATISTICAL (4) |
| `CTU-Normal-9__2016-09-13_win16.pcap` | benign · design | 150 | 3 | ANOMALY_STATISTICAL (3) |
| `CTU-Normal-25__2017-04-25_win-normal.pcap` | benign · held-out | 7,297 | 50 | ANOMALY_STATISTICAL (50) |
| `CTU-Normal-27__2017_04_30-normal.pcap` | benign · held-out | 35,331 | 51 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (1) |
| `CTU-Normal-29__2017-05-01_normal.pcap` | benign · held-out | 30,168 | 52 | ANOMALY_STATISTICAL (50), COVERT_CHANNEL_UNKNOWN_PORT (1), EXFIL_VOLUME_ASYMMETRY (1) |
| `CTU-Normal-30__2017-05-01_normal.pcap` | benign · held-out | 48,031 | 50 | ANOMALY_STATISTICAL (50) |
| `CTU-Normal-31__2017-05-01_normal.pcap` | benign · held-out | 53,806 | 59 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (1), COVERT_CHANNEL_UNKNOWN_PORT (7), EXFIL_VOLUME_ASYMMETRY (1) |
| `CTU-Normal-32__2017-05-02_normal.pcap` | benign · held-out | 73,235 | 56 | ANOMALY_STATISTICAL (50), C2_BEACON_KEEPALIVE (1), DNS_TUNNEL_SUBDOMAIN_VOLUME (1), EXFIL_VOLUME_ASYMMETRY (3), RECON_PORT_SCAN (1) |
| `2024-03-14-AsyncRAT-and-XWorm-infection-traffic.pcap` | malicious · attack | 36 | 5 | COVERT_CHANNEL_UNKNOWN_PORT (5) |
| `2024-12-18-one-week-of-server-scans-and-probes-and-web-traffic.pcap` | malicious · attack | 166,093 | 357 | ANOMALY_STATISTICAL (50), RECON_PORT_SCAN (307) |
| `2025-12-01-thru-12-03-in-the-wild-scans.pcap` | malicious · attack | 5 | 0 | none |
| `2025-12-17-testing-the-Mirai-botnet-URL-on-a-VM.pcap` | malicious · attack | 107,035 | 53 | ANOMALY_STATISTICAL (50), COVERT_CHANNEL_UNKNOWN_PORT (1), ICMP_TUNNEL_OVERSIZED (1), RECON_PORT_SCAN (1) |
| `2026-08-07-seven-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap` | malicious · attack | 223,120 | 663 | ANOMALY_STATISTICAL (50), RECON_PORT_SCAN (613) |
| `2026-09-08-XWorm-post-infection-traffic.pcap` | malicious · attack | 1 | 1 | COVERT_CHANNEL_UNKNOWN_PORT (1) |
| `dns-tunnel-iodine.pcap` | malicious · attack | 1 | 2 | DNS_TUNNEL_LONG_LABEL (1), DNS_TUNNEL_SUBDOMAIN_VOLUME (1) |
| `wrccdc-2018-cyber-defence-exercise.pcap` | malicious · attack | 117,498 | 57 | ANOMALY_STATISTICAL (50), DNS_TUNNEL_LONG_LABEL (1), EXFIL_VOLUME_ASYMMETRY (3), RECON_PORT_SCAN (3) |

## 7. Results — hashing, sealing and custody (R5, R6)

* **Known-answer tests** (`backend/evidence/tests_known_answers.py`): `hash_file` returns the
  published SHA-256, SHA-1 and MD5 of the empty input, of "abc" and of one million repetitions of
  "a" (FIPS 180, RFC 1321); the answer does not change with the read-chunk size (1 byte to 2 MB);
  a single flipped bit changes every digest.
* **Custody log:** a test suite alters, removes, reorders and truncates entries and requires each
  to be detected (`backend/evidence/tests_case_package.py`, `tests.py`). A hash chain shows a log
  is internally consistent; it cannot show the whole log was not rebuilt, and the signed case
  package says so (research/162).
* **Independent implementation:** the browser verifier was required to give results identical to
  the Python verifier on 19 packages, including every forged case
  (`backend/evidence/tests_case_package_js.py`).
* **Parser equivalence:** the fast packet reader is compared with the reference dissector over
  real captures and must give identical flows, DNS records, byte counts and timestamps
  (`backend/capture/tests_fastparse.py`, `tests_equivalence.py`).

These test that the code does what it says. They do not establish that Section 63 certificates
will be accepted by any court.

## 8. Limitations

1. **Detection is 58% on unseen malware and 42% is missed.** The sets are small (the interval above
   is wide), and both are now spent: any rule written after looking at them is no longer measured
   by them.
2. **Tier 1 never means "safe".** It means no harmful behaviour was established by static
   examination, which does not execute the sample.
3. **Tier 0 is not a clean result.** 8 of 200 malicious and 11 of 100 legitimate
   samples could not be examined.
4. **The corpora are not representative of seized devices** (§4).
5. **Network rule rates come from 22 + 8 captures** of one lab's collection, and the attack side
   contains no beacon of the kind one rule is built for.
6. **Both unseen sets are reported for the shipped engine; the held-out set was first scored by the v5 image and its verdicts were identical on re-measurement (§5.1).**
7. **Not independently reviewed.** The author wrote the tool, chose the corpora and ran the tests.
8. **No timing or throughput claim is validated here**; see `research/156` for the import measurements.

## 9. Reproducing this

The data come from public sources and nothing needs to be taken on trust:

```bash
# Samples: fetch the digests listed in validation/apk_samples.csv from MalwareBazaar with your
# own key (https://auth.abuse.ch/); they are served as password-protected zips.
python scripts/fetch_malwarebazaar_corpus.py unpack --from <dir> --into <dir>

# Examine them with the shipped engine and compare with apk_samples.csv:
python -m apk_engine evaluate --check --malicious <unpacked dir> --benign <fdroid dir>

# Network rules over a directory of captures; then the table:
python scripts/measure_rule_base_rates.py --captures <dir> --label benign --out benign.json
python scripts/rule_base_rate_report.py --benign benign.json --malicious attack.json
```

The corpora's own manifests (`mal/*/corpus_manifest.json`) record how each was selected. The
ordinary-traffic captures are listed with URL and SHA-256 in `validation/results.json`.

## 10. Where each requirement of the guidance is answered

| FSR-G-218 | This report |
|---|---|
| s.3.3.1 definition of validation | §1 |
| s.1.1.9–1.1.10 representative data; developer-supplied testing | §1, §4 |
| s.7.2.1c control over source data; blind trials | §4, §5.1 |
| s.7.2.1d expected outcomes and error margin | §3 (none set; pre-registered expectations shown) |
| s.7.2.1e limitations of the tests performed | §4, §8 |
| s.7.6.4 requirement vs finding; failures highlighted; limitations detailed | §3–§8 |
| s.6.3.10 change and re-verification | §2 |

