# 154 — Why adding five rules changed nothing, and what actually moved detection

**Question:** the APK engine detected 34.0% of 200 MalwareBazaar samples. Five new
behaviour rules were written on 19 Sep 2026. How far has detection improved?

**The short answer is uncomfortable and worth stating first: adding the rules, on its
own, improved detection by exactly zero.** Not approximately zero — zero. The rules fire,
they fire often, and not one of them moved a single sample's tier. What moved detection
was re-measuring the baselines, and the reason is a design decision this engine makes
deliberately.

---

## 1. The measurement that showed nothing happened

The engine image used for the September corpus run was built on 18 Sep at 18:02, before
the new rules existed. Checked rather than assumed:

```
rules in that image:  5        rules on disk after 19 Sep:  10
```

So the 34.0% figure describes a 5-rule engine. A fresh image was built with all ten, and
the same 200 samples re-examined. On the 93 samples completed before the run was stopped:

| | v1 (5 rules) | v2 (10 rules) |
|---|---|---|
| tier ≥ 2 | 33.8% | **33.8%** |
| samples whose tier changed | — | **0** |

The new rules were not inert. Across those samples they fired 26 times:

| rule | firings |
|---|---|
| `beh.runtime_code_from_network` | 14 |
| `beh.screen_capture_to_network` | 6 |
| `beh.adb_payload_dropper` | 2 |
| `beh.dropper_with_bundled_payload` | 2 |
| `beh.accessibility_types_into_other_apps` | 2 |

29.2% of samples fired at least one new rule, and **no sample's verdict changed.**

### Why that is correct behaviour, not a bug

`verdict.py` will not let a signal raise the evidence tier unless that signal is
*validated*, and `baselines.py` defines validated as: fired on **zero** legitimate apps
in a corpus of at least `MIN_BENIGN = 30`. A rule nobody has measured against legitimate
software has status `unmeasured`, and an unmeasured rule is not evidence — it is a guess
with a citation.

The baselines in force were measured on 31 apps in Sep 2026 and contain 31 signal
entries. The five new rules are not among them. Neither, as it turns out, are five of the
ten integrity indicators.

This is the property the project wanted: **you cannot improve the detection rate by
writing rules.** You improve it by measuring them. The engine enforces that, and it just
enforced it against its own author.

---

## 2. What was actually available, and had been all along

The feature tables from the corpus run carry every signal that fired per sample, so the
benign base rate of each could be measured directly — 200 malicious, 300 F-Droid apps,
all analysed, errors excluded.

| integrity indicator | malicious | benign |
|---|---|---|
| `zip.encryption_flag_on_package` | 73 (36.5%) | **0** |
| `zip.header_mismatch` | 40 (20.0%) | **0** |
| `zip.path_collisions` | 37 (18.5%) | **0** |
| `zip.unknown_compression_method` | 36 (18.0%) | **0** |
| `axml.attribute_size` | 28 (14.0%) | **0** |
| `axml.unknown_chunk` | 24 (12.0%) | **0** |
| `axml.attribute_start` | 17 (8.5%) | **0** |
| `axml.attribute_names` | 11 (5.5%) | **0** |
| `axml.string_count_mismatch` | 11 (5.5%) | **0** |
| `zip.oversized_filename` | 9 (4.5%) | **0** |

**Any integrity indicator: 114 of 200 malicious (57.0%), 0 of 300 legitimate (0.00%)**,
which supports a one-sided 95% bound on the benign firing rate of **0.99%**.

Of those 114, sixty-two were already at tier ≥ 2 by another route. **Fifty-two were being
missed while carrying a signal that fires on no legitimate app in the corpus.**

Five of these ten indicators were absent from `baselines.json` entirely — including
`zip.encryption_flag_on_package`, the highest-coverage signal in the engine — so they
could never raise a tier no matter what they found.

### These are not our invention, and now they cite the primary source

Three reports were re-opened and quoted directly rather than through secondary coverage,
and added to `sources.py` as verified:

- **[Zimperium zLabs, "Konfety Returns", 15 Jul 2025](https://zimperium.com/blog/konfety-returns-classic-mobile-threat-with-new-evasion-techniques)** —
  "The APK contains the bit 00 of the General Purpose Flags enabled. This causes some
  tools to incorrectly identify the APK (ZIP) as encrypted and subsequently request a
  password for decompression." That is `zip.encryption_flag_on_package` exactly. It was
  previously carrying only a news article about this research.
- **[Cyble, "GhostBat RAT", 14 Oct 2025](https://cyble.com/blog/ghostbat-rat-inside-the-resurgence-of-rto-themed-android-malware/)** —
  "modified the central directory and local file headers by altering the compression
  method value to 'STORE', resulting in failed APK decompilation attempts." Same
  indicator as Konfety's false BZIP declaration, seen from the opposite side, which is
  why the rule tests "neither stored nor deflate" rather than a specific value. GhostBat
  is also directly relevant here: it impersonates Indian RTO apps such as mParivahan.
- **[Zimperium zLabs, "Fantasy Hub", 6 Nov 2025](https://zimperium.com/blog/fantasy-hub-another-russian-based-rat-as-m-a-a-s)** —
  "the SMS handler role unifies multiple powerful permissions such as Contacts, Camera,
  Files access into a single authorization step." Supports a proposed capability, §5.

---

## 3. Method: what is being measured against what

`evaluate.py` states the trap plainly — a signal is validated *because* it fired on no
app in the baseline corpus, so re-examining that corpus is guaranteed to show zero false
positives, and that number proves nothing. Three corpora were therefore separated before
anything was measured:

| corpus | contents | role |
|---|---|---|
| benign baseline | 23 original F-Droid + 200 of the 300-app sample | measures benign firing; sets validation |
| benign held-out | the other 100 | the only false-positive number that means anything |
| malicious design | the original 200 MalwareBazaar samples | the rules were written knowing these |
| malicious held-out | **100 newly fetched samples**, never seen | the only detection number that means anything |

The benign split takes every third app by sorted filename rather than a contiguous cut,
because F-Droid names sort by reverse-domain prefix and a contiguous cut would put whole
publishers on one side.

The 100 held-out malicious samples were selected by excluding the existing manifest from
a 500-sample listing — **before** any of them was examined, and never by whether the
engine detects them. `scripts/fetch_malwarebazaar_selection.py` exists so that selection
is a recorded, repeatable step rather than a judgement call.

---

## 4. Candidate rules the corpus suggests (not shipped)

`apk_corpus/analysis/tools/mine_conjunctions.py` searches for capability conjunctions
that fire on malware and on no legitimate app. It is a **candidate generator**: nothing it
finds may ship without a published source behind it, because "it separated our 500
samples" is a statement about 500 samples.

Top candidates, zero benign firings in 300:

| coverage | conjunction |
|---|---|
| 27 (13.5%) | `query_installed_apps + sms_receiver` |
| 25 (12.5%) | `shell_exec + sms_receiver` |
| 18 (9.0%) | `install_packages + vpn_interface` |
| 17 (8.5%) | `notification_listener + sms_receiver` |
| 17 (8.5%) | `accessibility_service + boot_start + device_admin` |

The union of the top 22 covers 62 of 200 malicious samples with no benign firings — but
these were found *in* the corpus they are scored on, so that coverage is an overestimate
of what they would achieve on unseen malware. That is what the held-out corpus is for,
and it is why none of them was shipped into the measured run.

After integrity indicators are activated, 80 of 200 samples are still missed, and mining
against only those returns conjunctions covering 3–6 samples each — fourteen samples in
total across fourteen separate rules. That is a poor trade: fourteen rules, each resting
on a handful of examples, is how a detector learns a corpus instead of a threat.

---

## 5. One sourced capability the engine lacks

Fantasy Hub's primary privilege-escalation route is **asking to become the default SMS
handler**, because that single grant carries Contacts, Camera and Files access with it.
The engine detects `cap.sms_receiver` (an `SMS_RECEIVED`/`SMS_DELIVER` intent filter) but
not the full four-component declaration Android requires for eligibility, which
[Android's own guidance](https://android-developers.googleblog.com/2013/10/getting-your-sms-apps-ready-for-kitkat.html)
specifies exactly:

1. receiver for `android.provider.Telephony.SMS_DELIVER`, requiring `android.permission.BROADCAST_SMS`
2. receiver for `android.provider.Telephony.WAP_PUSH_DELIVER`, requiring `android.permission.BROADCAST_WAP_PUSH`
3. activity for `android.intent.action.SENDTO` on `sms:`/`smsto:`/`mms:`/`mmsto:`
4. service for `android.intent.action.RESPOND_VIA_MESSAGE`, requiring `android.permission.SEND_RESPOND_VIA_MESSAGE`

Declaring all four is what a real messaging app does, so the capability alone cannot raise
a tier — F-Droid ships several legitimate SMS clients. The tell is the conjunction: an app
that takes the SMS handler role while hiding its launcher icon is not a messaging app,
because the user must be able to open a messaging app.

**Disclosure:** the family composition of the held-out corpus was visible (Fantasy Hub is
19 of the 100) *before* this rule was designed. The rule is justified by a published
source rather than by the corpus, but the held-out result would no longer be blind with
respect to it. It was therefore **not** shipped into the measured run, and is recorded
here as work for a next iteration with a fresh held-out set.

---

## 6. Results

### 6.1 The re-baseline (v3)

Measured on 201 benign apps (23 original F-Droid + 200 of the sample; 22 of the 223
could not be examined) and 194 malicious. **25 signals validated**, including all ten
integrity indicators. Of the five rules added on 19 Sep:

| rule | malicious | benign | status |
|---|---|---|---|
| `beh.runtime_code_from_network` | 25 | 0 | validated |
| `beh.accessibility_types_into_other_apps` | 11 | 0 | validated |
| `beh.screen_capture_to_network` | 18 | 1 (Conversations) | experimental |
| `beh.dropper_with_bundled_payload` | 4 | 2 (Orgro, AniVu) | experimental |
| `beh.adb_payload_dropper` | 3 | **4** (incl. K-9 Mail, AdAway) | experimental |

`adb_payload_dropper` fired on more legitimate apps than malicious ones. Its own
lookalikes text had claimed that combining install + shell + boot was "the botnet
dropper profile"; that text now states the measurement instead.

**One regression was caught before it shipped.** `cert.debug_certificate` fired on 6 of
the original 31 benign apps — the locally built ones, no longer on disk — and on 0 of
the new 201, which would have promoted it to validated and made every debug-signed APK
raise a tier. `tools/merge_baselines.py` carries forward benign firings whose evidence
has disappeared; it can only keep a signal out of validated status, never put one in.

### 6.2 Held-out, v3 — the first number on unseen malware

100 malicious samples never examined before, 100 benign apps not used for baselines:

| | |
|---|---|
| **detection (tier ≥ 2)** | **63 / 100 = 63.0%** — 95% CI [52.8, 72.4] |
| false positives (tier ≥ 2) | 1 / 100 = 1.0% — 95% CI [0.0, 5.4] |
| balanced accuracy | 81.0% |
| precision | 63 / 64 = 98.4% |
| could not be examined | 5 malicious, 4 benign |

Tier distribution, malicious: tier 4: 2 · tier 3: 17 · tier 2: 44 · tier 1: 32 · tier 0: 5.

From **34.0%** to **63.0%** on malware the engine had never seen, and the gain came
almost entirely from measuring signals that already existed.

### 6.3 The first held-out false positive, and what it was

`priv.wh201906.serialtest`, a USB serial-port tool from F-Droid, was placed at tier 3
by `beh.runtime_code_from_network`. Reproduced with the same image and baselines, both
conjuncts came from **Qt for Android's framework code**:

- `cap.dynamic_code_loading` ← `org.qtproject.qt5.android.bindings.QtLoader.loadApplication()`
  calling `DexClassLoader` — Qt's standard bootstrap;
- `cap.network_use` ← `QtNative.setClipboardUri()` calling `Uri.parse` — clipboard
  handling, not networking.

`org.qtproject.` was missing from the library table, so Qt's code was unattributed, and
unattributed code counts as the app's own. The same class of defect as the earlier
"NPCI's root check read as Flipkart's". Fixed by adding Qt's namespace — verified in
qtbase's own source tree rather than assumed — with a regression test; the APK then
examines at tier 1.

**This spent the held-out benign set.** It was used to find a defect and the defect was
fixed, so a false-positive rate re-measured on those same 100 apps is no longer blind.
A fresh set of 100 F-Droid apps, sampled with a new seed and excluding every app already
held, is used for the false-positive claim instead (§6.5).

`Uri.parse` being counted as network use is a genuine over-breadth in
`codemap.NETWORK_APIS`, left unchanged: removing it would shift every rule that uses
network as a conjunct, unmeasured, and the attribution fix alone removes this false
positive.

### 6.4 What the misses were, and two more detectors (v4)

Profiling the design-set misses left after the re-baseline (66 of 200) split them into
groups, and only one of them was what was expected:

| group | misses | what it was | outcome |
|---|---|---|---|
| NFC card relay | 24 | "Total Protect" (20 variants, randomised package names) and NGate: `IsoDep` card reads + network, 4–9 permissions | **new rule** |
| packer | 7 | 72–92 KB loader DEX beside a 5–12 MB blob at entropy 8.00, named `.dat`/`.pak`/`.cache` | **new rule** |
| TV-box botnets | ~15 | Mirai/JackSkid: ELF in `assets/`, `libbot.so` | not separable |

**Native/ELF scanning did not close the gap.** An ELF executable outside `lib/` fired on
14 malicious and on 2 legitimate apps — OpenVPN's `pie_openvpn` and BOINC's compute
client — which ship helper binaries in `assets/` and execute them exactly as `assets/lol`
is executed. Statically the technique is identical. Mirai strings (`TSource Engine
Query`, `/dev/watchdog`) separated cleanly but covered 2 samples.

**`beh.nfc_card_relay`** — `IsoDep.transceive` in app code + network use + ≤ 10 declared
permissions: 24 malicious, 0 of 300 benign. CERT Polska found NGate relaying over plain
framed TCP, Cleafy found SuperCard X over mTLS, Total Protect uses WebSocket — the
transport varies, so the rule requires network use rather than any one protocol. The one
legitimate app reading contactless cards over a network, a Bitcoin payment terminal,
declares 17 permissions; the relay samples declared 4–9. **The threshold of 10 was chosen
with both numbers visible and is the rule's weakest part.** Mapped to ATT&CK Mobile T1646
(Exfiltration Over C2 Channel), verified on attack.mitre.org.

**`beh.packed_code_payload`** (tier 2, no PHA category) — DEX under 100 KB beside an
entry of ≥ 1 MB at entropy ≥ 7.99: 38 malicious, 0 benign, and identical counts across
every threshold tried. The first version of this measurement excluded `.dat` and `.pak`
as naturally compressed formats and missed exactly the samples it was meant to find.
Duan et al. (NDSS 2018, p.3) found commercial packers "widely used by many developers to
pack and protect their intellectual property", and F-Droid contains no packed apps, so
the zero benign firings overstate how clean this is on Play Store software.

### 6.5 v4 — the held-out result

*Running at the time of writing: v4 re-baseline, held-out test, design-set re-check, and
the false-positive check on 100 fresh F-Droid apps.*

---

## 7. Limits

- The v2 comparison covers **93 of 200** samples, not all of them; the run was stopped
  once the result was unambiguous (0 tier changes in 93) and the machine was needed for
  the re-baseline. The claim it supports — that new rules alone changed nothing — does not
  depend on the remaining 107.
- Detection on the original 200 is a **design-set** number. Those samples' misses informed
  the rules. Only the 100 held-out samples support a detection claim.
- The held-out malicious corpus is 100 samples: a detection rate from it has a 95%
  interval roughly ±10 points wide. It is a measurement, not a precise one.
- MalwareBazaar is not a random sample of Android malware. It is what researchers
  uploaded, which skews toward families people are currently writing about.
- The benign corpus is F-Droid, which is open-source software. Play Store apps carry more
  advertising SDKs and more obfuscation, and a false-positive rate measured on F-Droid may
  not transfer.
- Integrity indicators detect **tampering with the package container**, which is evidence
  of evasion, not of malice. An app that forges its ZIP headers is hiding something from
  analysis tools; that is what the tier-2 language says, and it is not the same claim as
  "this app is malware".
