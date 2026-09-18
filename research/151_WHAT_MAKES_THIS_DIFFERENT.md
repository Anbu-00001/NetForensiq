# 151 — What makes this different from every other APK scanner, and what must still be built

**Status:** Research, 18 Sep 2026. Written after [150](150_APK_MALWARE_CLASSIFICATION.md) shipped
(`apk_engine` 2.0.0). Every number attributed to *our* engine was measured on this machine today;
every claim about another tool carries a marker.
**Verification rule (same as [150](150_APK_MALWARE_CLASSIFICATION.md)):** ✅ = primary source
(source code, official docs, vendor page) fetched and read. ⚠️ = secondary only (news report,
search summary, issue tracker quoted second-hand).

---

## TL;DR

**Every tool in this space answers "is this malware?" with a number. We answer a different question:
"what can be established about this file, and how strongly?"** That is the only question a forensic
report can survive being asked under cross-examination, and it is the question none of them answer.

Four differences already exist in the code:

1. **A tier, never a sum.** The verdict is the *strongest single established fact*, so adding noise
   to a sample cannot move it. MobSF's score is an *average* of CVSS values — adding a new issue can
   make an app score *better* (§1.1, ⚠️ the maintainers' own issue tracker).
2. **Every behavioural and integrity rule carries a measured benign false-positive count, and may
   only raise a tier if that count is zero.** Nothing shipped in this field does this (§2.2). It
   forced me to demote two rules I had written myself. One deliberate exception: a tier-4
   intelligence *identity* match — file hash or signing certificate — is an identity fact, not a
   statistical one, and is ungated by any baseline.
3. **Findings are attributed to the app's own code or to an SDK.** This is the single defect that
   made our old scorer call a Play Store Flipkart build a remote-access trojan, and it is why
   MobSF and Quark still do (§2.3).
4. **The exhibit never leaves the machine.** VirusTotal states that "the contents of submitted files
   or pages may also be shared with premium VirusTotal customers" ✅; Pithus states that "samples
   detected as malicious are automatically uploaded to MalwareBazaar" ✅. For a seized exhibit that
   is not a feature, it is a disclosure (§2.4).

Four things do **not** yet exist and are what "deployable to the world" actually requires:

**A.** Identity-claim verification — *this file claims to be the pension portal; the real one is not
signed by this key* (§4.1). **B.** Promoting capture correlation from corroboration to evidence
(§4.2). **C.** A Bharatiya Sakshya Adhiniyam §63(4)-shaped expert certificate (§4.3).
**D.** A corpus large enough that "0 of n" means something — today *n* = 31, which bounds a clean
signal's true benign rate only below **9.2%** (§3.2). D is the precondition for the credibility of
everything else.

---

## 1. The landscape, judged by one question

Not "which is most accurate" — nobody can answer that without a shared corpus. The question is:
**hand each tool a file seized from a victim's phone. What comes back, and what does it cost you?**

| Tool | What it returns | Who else gets the exhibit | Can one finding be cross-examined? |
|---|---|---|---|
| **VirusTotal** | Count of engines that flagged it, plus their labels | Shared with examining partners; contents "may also be shared with premium VirusTotal customers" ✅ | No. No evidence path, and the engines disagree on the family |
| **Koodous** | Community YARA rule hits over a shared public sample repository ⚠️ | Public repository by design ⚠️ | Partly — the rule text is visible, but no benign base rate |
| **Pithus** | Aggregated output of androguard, APKiD, Quark, MobSF, exodus-core. **No overall verdict** ✅ | "samples detected as malicious are automatically uploaded to MalwareBazaar" ✅ | The underlying tools' findings, unranked |
| **MobSF** | "Security score" out of 100 = average of per-issue CVSS ✅ | Nobody — self-hosted. This is MobSF's real advantage | Issue-by-issue yes; the score, no |
| **Quark-Engine** | Weighted 5-stage score out of 100 | Nobody — local | Stage-by-stage yes; measured on Flipkart it returned **121** matched behaviours at 100% confidence against the dropper's **41** (measured, [150 §2.2](150_APK_MALWARE_CLASSIFICATION.md)) |
| **APKiD** | Packer / compiler / obfuscator fingerprints. No verdict ✅ | Nobody — local | Yes, and honestly. APKiD is the model to imitate |
| **Commercial MAST** (NowSecure, Appknox, Oversecured) | Vulnerability findings in *your own* app against OWASP MASVS ⚠️ | Vendor cloud ⚠️ | Different problem entirely — they audit apps you own, they do not triage a stranger's APK |
| **ML literature** (Drebin → LAMDA, TESSERACT) | A probability | n/a | No. And the field's own benchmarks now exist mainly to show how fast these decay under drift ⚠️ |

Two observations fall out of that table.

**Every product either gives you a number with no evidence path, or an evidence path with no
ranking.** MobSF, Quark and VirusTotal are in the first group; Pithus and APKiD are in the second.
Nothing occupies the middle, which is exactly where a forensic examiner works.

**The three tools that would tell an investigator the most are the three that publish the exhibit.**
That is a structural conflict, not an oversight: VirusTotal, Koodous and Pithus are *intelligence*
platforms, and intelligence platforms are worth using because everyone contributes samples. A police
examiner cannot contribute the sample. It is evidence, it may contain the victim's harvested data,
and uploading it tells the operator their campaign is burned.

### 1.1 The scoring flaw is documented by the maintainers

MobSF starts every app at 100 and reports the *average* CVSS of the issues found ⚠️. Its own feature
requests point out the consequence: "if an issue is introduced to an app that already has higher
average cvss than that issue, app would actually have higher score than before even though it now
has more issues" ⚠️ ([issue #1069](https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues/1069),
[#1731](https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues/1731)).

This is not a bug in MobSF — MobSF is an appsec tool and has never claimed to classify malware
([150 §2.1](150_APK_MALWARE_CLASSIFICATION.md)). It is a demonstration that **any aggregate over
heterogeneous findings is indefensible**, because the aggregation function is a choice nobody can
justify on the witness stand. Ours has no aggregation function. The tier is a maximum over
established facts, and the report names which fact set it.

---

## 2. What is already different — with the measurements

### 2.1 The verdict cannot be moved by noise

`verdict.py` takes the strongest tier any single established finding reaches. There is no weight to
tune, so there is no weight to attack. A sample with forty capabilities and no established behaviour
sits at tier 1, and the report says so in words: *"No harmful behaviour established."* Not "clean" —
the distinction is the whole point.

### 2.2 Every rule ships with its measured benign base rate

This is the part I could find no precedent for. Academic work measures a false-positive rate for a
*model*; Arp et al. name the base-rate fallacy as one of the field's recurring sins ✅
([150 §3](150_APK_MALWARE_CLASSIFICATION.md)). But no shipped tool attaches a measured benign
count to each individual rule and refuses to let the rule raise severity until that count is zero.
`baselines.py` does, and the numbers are in `data/baselines.json`, measured across 31 legitimate
apps today:

| Signal | Fired on n of 31 legitimate apps |
|---|---|
| `cap.boot_start` | **20** |
| `cap.install_packages` | **13** |
| `cap.shell_exec` | **13** |
| `cap.query_installed_apps` | 10 |
| `cap.accessibility_actions` | 8 |
| `cert.debug_certificate` | 6 |
| `cap.accessibility_service` | 5 |
| `cap.sms_send` | 5 |
| `cap.vpn_interface` | 4 |
| `cap.overlay_window` | 3 |
| `cap.sms_read`, `cap.device_admin`, `cap.notification_listener` | 2 each |
| `cap.vpn_catch_all_route`, `cap.sms_receiver`, `cap.root_detection_strings`, `cap.hides_launcher_icon` | 1 each |
| `cap.dynamic_code_loading`, `cap.telegram_bot_api`, `cap.quick_tunnel_url` | 0 |
| `axml.attribute_names`, `axml.attribute_size`, `axml.string_count_mismatch` | 0 |
| `cert.malformed_country`, `zip.header_mismatch`, `zip.unknown_compression_method` | 0 |
| **`beh.install_under_network_blackout`** | **0** |
| `beh.sms_to_telegram_bot`, `beh.install_from_quick_tunnel` | 0 |
| `beh.hides_launcher_icon` | 1 → demoted to *experimental* |
| `beh.accessibility_control_with_overlay` | 1 → demoted to *experimental* |

That is the complete record — all 31 measured signals, not a selection.

Read the `cap.install_packages` row against the `beh.install_under_network_blackout` row, because
that single comparison is the strongest argument this project has.

**Installing packages fires on 13 of 31 legitimate apps. A catch-all VPN route fires on 1. Doing both
from the app's own code fires on 0.** The conjunction discriminates where neither conjunct does.
Every additive scorer in the field gives Aurora Store points for the first and RethinkDNS points for
the second, and that is precisely how you arrive at "Flipkart is a remote-access trojan". The top row
makes the same point from the other end: starting at boot fires on **20 of 31** — two-thirds of
legitimate apps — and any scorer charging points for it is charging points for being an ordinary
Android app.

The corpus is adversarial on purpose: the 23 F-Droid apps were chosen *because* they legitimately
install packages (Aurora Store, Droid-ify, F-Droid), create VPN interfaces (OpenVPN for Android,
NetGuard, RethinkDNS), handle SMS (Fossify Messages), automate through accessibility (Key Mapper) or
run shell commands (Termux). A benign corpus of ordinary apps would prove nothing.

The two demotions are the honest part. I wrote `beh.hides_launcher_icon` and
`beh.accessibility_control_with_overlay` expecting them to be clean; SheSafe and ConsentLens fired
them. They stay in the report under `not_established`, with their counts visible, and they do not
move the tier. **A system that can demote its author's own rules is falsifiable in a way a tuned
weight can never be.**

### 2.3 App code and SDK code are told apart

The manifest merger copies SDK components into the app's manifest, so a Flipkart build declares
activities under `com.facebook`, `in.juspay` and `org.npci.upi`. Our old scorer read NPCI's root
check as Flipkart's, which is how it reached 100/100. `codemap.py` attributes by organisation
prefix, and `endpoints.extract()` splits hosts into `app` and `sdk` lists before any rule sees them.
For scale: the old regex scorer reported **156** "domains" for Flipkart — recorded in
[150 §1.1](150_APK_MALWARE_CLASSIFICATION.md) and in the `endpoints.py` docstring. The current
pipeline does not start from that list, and its own split for Flipkart is not recorded anywhere in
the repository, so no figure for it is quoted here.

Library detection is a well-studied research problem (LibScout, LibRadar, LibID, LibPecker ⚠️) but it
is not wired into any shipped verdict. Ours is load-bearing, with one limit that matters: **code
evidence attributed to a known SDK namespace cannot satisfy a behaviour rule** — library hits are
kept only as a `library_only_occurrences` count. That guarantee covers code evidence and not manifest
evidence, which is an open defect (§3.5).

### 2.4 The exhibit never leaves the machine — and this is a legal property, not a preference

`apk_runner.py` executes the engine as a separate process with a scrubbed environment (`PATH`,
`PYTHONPATH`, `LANG`, `PYTHONDONTWRITEBYTECODE`, plus `APK_ENGINE_BASELINES` where set), a CPU cap,
a 900-second timeout and a machine-wide `flock` that holds across every gunicorn worker. The memory
cap is applied by the child to itself in `__main__.py` (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_CORE`,
soft == hard), not by the parent, because `preexec_fn` is unsafe from a threaded process.

**No network call exists on the examination path.** `engine.py` and `__main__.py` import nothing
network-capable, and the only `urllib` use in examined code is `urlsplit` for parsing. The package
does contain one outbound-capable module — `refresh_data.py`, which rebuilds `data/` from the Exodus
API, Echap's stalkerware indicators and IANA — but nothing imports it; it runs as its own entry
point, and its docstring states it "runs on a connected build machine, never on the air-gapped
workstation". The resulting snapshot carries provenance and SHA-256 in `sources.json`, and every
report names the snapshot it ran against.

For an Indian police deployment this is the difference between a usable tool and an inadmissible one.

---

## 3. What is *not* different — the honest column

A novelty claim is worth nothing without this section.

### 3.1 We detect far less than an antivirus engine

Five behaviour rules against an AV vendor's millions of signatures. We will miss most malware, and
tier 1 must never be read as safe. The report's `LIMITS` list says exactly that in the output
itself — *"tier 1 must be read as 'not established', never as 'safe'"*. The
correct positioning is **an examination instrument, not a detector** — a microscope, not a metal
detector. Running VirusTotal *in addition*, on a hash only, remains sensible for an examiner who
wants coverage; what we refuse to do is upload the file.

### 3.2 "0 of 31" is a weaker statement than it looks

With 0 events in 31 trials, the exact one-sided 95% upper bound on the true benign rate is
**1 − 0.05^(1/31) = 9.2%**. So "fired on none of 31 legitimate apps" only licenses "fires on fewer
than about 1 in 11 legitimate apps". That is enough to beat a hand-tuned weight and nowhere near
enough to deploy nationally. Getting that bound under 1% needs ~300 benign apps; under 0.1%, ~3,000.
`baselines.py` already prints the bound rather than hiding it, and `status()` will not say
*validated* below `MIN_BENIGN = 30`.

### 3.3 Sensitivity is unmeasured — n = 1

One malicious sample (`com.mrram.loader`). We can state that the engine established a tier-3
behaviour on it; we cannot state a detection rate, and must not imply one.

### 3.4 No dynamic analysis, and limited obfuscation resistance

Everything is static. A packed or heavily reflective dropper will reduce `codemap` to noise. APKiD
detects packers; we do not yet run it (GPL, and it would have to stay out of process).

### 3.5 Manifest-derived capabilities are not attributed — an open defect

§2.3 attributes *code* evidence to the app or to an SDK. Five capability detectors read the manifest
instead and do no attribution at all: `cap.sms_receiver`, `cap.accessibility_service`,
`cap.notification_listener`, `cap.boot_start`, and the receiver half of `cap.device_admin`
(`identity.components_with_action` / `components_with_permission` filter the merged component list
and return a hard-coded library count of zero).

Because the manifest merger copies SDK components into the app's manifest — the same mechanism that
produced the Flipkart false positive — an SDK-declared accessibility service still counts as the
app's own. Two of the five behaviour rules can be reached that way:
`beh.accessibility_control_with_overlay` through `cap.accessibility_service`, and
`beh.sms_to_telegram_bot` through `cap.sms_receiver`.

This is a plausible cause of the ConsentLens demotion, and it is testable. **Fixed on 18 Sep 2026**
(§8.1); measured on the 23 F-Droid apps still on disk, 11 of them declare a boot receiver that
belongs to AndroidX WorkManager rather than to the app. The ConsentLens hypothesis itself remains
untested, because that app is one of the 8 benign samples no longer on this machine (§8.6).

---

## 4. The gap worth building

Ranked by *novel × deployable*, and each stated as a falsifiable capability rather than a feature.

### 4.1 Identity-claim verification — "this file claims to be someone it is not"

**This is the strongest missing piece, and it maps directly onto the Indian threat.**

The dominant fraud in India is not exotic malware. It is impersonation: an APK named
`PENSION CARD VERIFICATION`, a fake PM-Kisan, a fake e-challan, a fake bank app, a fake "8th Pay
Commission salary calculator" ⚠️. For those, the question worth answering in a courtroom is not "does
this call a suspicious API" — it is:

> *This file presents itself as the pension portal. The genuine pension app is signed by certificate
> X. This file is signed by a self-signed certificate generated four days before the complainant
> received it. Those are different keys.*

That is binary, checkable offline, reproducible by the defence, and impossible to argue with. It is
also **tier-4-grade evidence by our own definition** — an identity fact, not a statistical one.

What it needs:

- A signed reference set mapping `package name → authorised signing certificate SHA-256`, built from
  APKs we hold and from a provenance-recorded acquisition, in the same shape as `data/sources.json`.
- A collision rule: same package name, different signer → the package is not what it claims. Zero
  false positives by construction, because it is an identity statement, not a heuristic.
- Certificate-age evidence: `notBefore` of the signing certificate against the offence date. A
  certificate minted days before the campaign is a fact a magistrate understands immediately.
- Rebuild fingerprints: apktool/`zipalign` artifacts that indicate decompile-and-resign, which is
  how a legitimate app becomes a trojanised one.

Prior art check: commercial brand-protection services (CloudSEK and similar) do this at internet
scale as a takedown service ⚠️; the academic work is repackaging detection (FSquaDRA, ViewDroid) ⚠️.
**Neither is an offline, evidence-grade check an examiner can run on one seized file.** That is the
opening.

### 4.2 Promote capture correlation from corroboration to evidence

We are the only project in this list that holds both halves. NetForensiq captures traffic from the
seized device; `apk_engine` names the hosts that appear **only in the app's own code**. Today
`apk_correlation.py` reports `tier_effect: 'none — corroboration only'`, which was the right
conservative default.

The upgrade: if a host present only in the suspect app's own code — in no SDK, and in no app of the
benign corpus — was actually resolved or contacted in the capture taken from that device, that is the
app's behaviour **observed**, not inferred. It is the one finding that closes the gap between "the
program contains this address" and "the phone asked for this address", and it is the sentence an
investigating officer most wants to be able to say.

It must go through the same gate as everything else: measure how often a benign app's own-code host
appears in an unrelated capture before letting it move a tier.

### 4.3 A BSA §63(4)-shaped expert certificate

India replaced Indian Evidence Act §65B with Bharatiya Sakshya Adhiniyam 2023 §63. §63(4) now
requires **dual certification** — by the person in charge of the device *and* by an expert — and the
expert's certificate must state **the hash value of the record and the algorithm used to obtain it** ⚠️.

**Correction to an earlier draft of this section.** This repository already ships the certificate:
`evidence/certificate_pdf.py` renders THE SCHEDULE verbatim — Part A and Part B, the hash report
annexure the Schedule requires, a custody annexure, and a DRAFT stamp across every page when either
part is unsigned. APK samples reach it too, because `capture/apk_views.py` seals them through
`ingest_evidence` like any other exhibit. So the statutory half was not the gap.

The gap was the **expert** half. The certificate proves what the exhibit *is*; nothing recorded what
the examination *did*, so a defence expert had no way to obtain the same report. That is what is
now emitted: engine and tool versions, the SHA-256 of every reference file the examination read, the
baseline snapshot it was judged against, and the command to run it again — with the one field that
legitimately varies between runs (`engine.seconds`) named as such.

That claim is only worth making if it is true, so **determinism is a test**, not a remark
(`tests/test_determinism.py`): the same file examined twice must agree in every field but timing.

### 4.4 Scale the corpus — the precondition for all of the above

§3.2 is the real blocker. 31 benign apps and 1 malicious sample. Two separate needs:

- **Benign, to ~300:** F-Droid's index is the cheap, licence-clean, fully reproducible source, and it
  is adversarial in the right way. This is bounded work and needs no new permissions.
- **Malicious, to a meaningful n:** MalwareBazaar (abuse.ch) is the standard free source and carries
  the ground truth an evaluation needs — family signature, tags and a first-seen date per sample.
  The acquisition and sandbox tooling is built (§8.8); the download itself needs an abuse.ch
  Auth-Key, which is an account only you can create.

Without this, every "0 of n" claim in the README is honest but weak, and a reviewer who knows the
field will say so.

### 4.5 Publish the falsification ledger

Ship `data/baselines.json`'s corpus manifest — the SHA-256 of every sample measured, 31 benign and 1
malicious — with the tool. For the 23 F-Droid apps anyone can re-acquire the exact build and re-run
the measurement; the Flipkart build and the 7 locally built apps are named and hashed but not
redistributable, which is a further argument for §4.4's F-Droid scale-up. A security tool that hands
you the recipe for proving it wrong is rare enough to be a differentiator on its own.

---

## 5. Why this is the right instrument for the Indian threat specifically

On 26 August 2026 the National Cybercrime Threat Analytics Unit (I4C, MHA) issued an advisory on
malicious Android apps distributed through social-media advertising. It describes a six-stage modus
operandi ⚠️:

> "distribution through social media ads, redirection to phishing sites, downloading a secondary
> package as an update, abuse of accessibility permissions to seize control, VPN installation, and
> ultimately, unauthorised financial transactions."

Set that against what the engine already establishes:

| I4C stage | Our signal | Benign base rate |
|---|---|---|
| 3. secondary package downloaded "as an update" | `cap.install_packages` | 13 / 31 — alone, meaningless |
| 5. VPN installation routing traffic to attacker servers | `cap.vpn_catch_all_route` | 1 / 31 — alone, meaningless |
| **3 ∧ 5 in the app's own code** | **`beh.install_under_network_blackout`** | **0 / 31 — tier 3** |
| 4. accessibility abuse to seize control | `beh.accessibility_control_with_overlay` | 1 / 31 — *experimental*, reported, does not move the tier |
| 1–2. ad → phishing site → APK | distribution evidence, **not in the file** | — |

The behaviour rule that fires on the judge's dropper is the conjunction of exactly the two stages the
national advisory names, and it is clean on a corpus deliberately stocked with VPN clients and app
installers. That is the argument, and it is made of measurements rather than adjectives.

Stages 1–2 are worth noticing for a different reason: **they are not in the file.** No static analyser
can establish how an APK reached a victim. That is a `provenance` field an officer fills in, which we
already require at upload — and it is another reason the honest output is an examination, not a score.

---

## 6. What would falsify the novelty claim

Stated so the claim is worth something:

- MobSF, Quark, Koodous or a commercial vendor shipping **per-rule measured benign false-positive
  rates that gate severity**. (Searched 18 Sep 2026; found none. Academic papers report per-model
  FPRs, which is a different thing.)
- Any shipped tool whose verdict **attributes findings to app code vs SDK code**. (Library detection
  exists as research; the verdict wiring does not.)
- An offline, evidence-grade **package-name/signer impersonation check** for a single file.
- A mobile analysis tool emitting a **BSA §63(4)** or equivalent statutory certificate.

If any of these turns up, that pillar goes, and this document should be edited rather than defended.

---

## 7. Build order

| # | Work | Status |
|---|---|---|
| 1 | **Attribute manifest-derived capabilities** (§3.5) | **Built** — `behaviours._manifest` now splits app from library, as code evidence always did |
| 2 | **Identity-claim verification** (§4.1) | **Built** — `reference_set.py`, wired into the verdict with its own vocabulary |
| 3 | **Reproducibility of the examination** (§4.3) | **Built** — `report['reproduction']`, with determinism as a test |
| 4 | Publish the falsification ledger (§4.5) | **Built** — `python -m apk_engine corpus` |
| 5 | **Benign corpus to ~300 from F-Droid** | **Tooling built** (`scripts/fetch_fdroid_corpus.py`); the download and re-measurement are a deliberate, hours-long run |
| 6 | **Capture correlation promoted to evidence** (§4.2) | **Not started** — blocked on a measurement that cannot be made yet (§4.2) |
| 7 | **Malicious corpus** (§4.4) | **Not started** — needs an explicit decision on handling live malware |

---

## 8. What was built (18 Sep 2026)

Scored against novelty × deployability, five of seven items cleared the bar and were built. All 531
backend tests pass, the frontend builds, the palette check passes and the documented counts match
the code.

### 8.1 Manifest components are now attributed (§3.5)

`behaviours._manifest` splits manifest-derived evidence into app and library exactly as code evidence
has always been split, using a new `CodeMap.attribute_component` that resolves a relative component
name (`.SmsRx`) against the package before attributing it. Five capabilities change behaviour:
`cap.sms_receiver`, `cap.accessibility_service`, `cap.notification_listener`, `cap.boot_start` and
the receiver half of `cap.device_admin`.

The test that holds it is `test_a_receiver_the_manifest_merger_copied_in_is_not_the_app_s`: an SMS
receiver declared under a bundled SDK's namespace no longer makes `cap.sms_receiver` present, and
therefore can no longer complete `beh.sms_to_telegram_bot`. Before the fix it did.

**Measured on the 23 F-Droid apps still on disk**, component by component:

| Capability | Components belonging to the app | Belonging to a bundled library |
|---|---|---|
| `cap.boot_start` | 14 (+1 unattributed) | **11** |
| `cap.device_admin` | 2 | 0 |
| `cap.accessibility_service` | 2 | 0 |
| `cap.notification_listener` | 1 | 0 |
| `cap.sms_receiver` | 1 | 0 |

All eleven are the same class — `androidx.work.impl.background.systemalarm.RescheduleReceiver`,
AndroidX WorkManager's boot receiver, present in 11 of 23 apps. Before the fix, every one of them
counted as the application declaring a boot receiver. Two apps (**Aurora Store** and **NewPipe**)
declare *no other* boot receiver, so for them the capability flips from present to absent:
`cap.boot_start` goes from 17/23 to 15/23 on this corpus.

Two apps is a small correction, and it is worth being precise about why it is not the interesting
number. The eleven are all from AndroidX — the toolchain every app carries. A corpus containing
apps with *proprietary* SDKs would contaminate far more: the Flipkart build whose merged manifest
declares components under `com.facebook`, `in.juspay` and `org.npci.upi` is exactly such a case,
and it is one of the 8 benign samples no longer on disk (§8.7). So the measured effect here is a
lower bound on the defect's real size, not an estimate of it.

I predicted before running this that the count would be zero, reasoning about proprietary trackers
and forgetting that library attribution also covers the platform toolchain. It is recorded as a
miss; the measurement is what settled it.

### 8.2 Identity-claim verification (§4.1)

`apk_engine/reference_set.py` answers "is this the package it claims to be?" — a comparison of two
certificate digests, not a detector. Three findings:

| Finding | What it establishes | Effect |
|---|---|---|
| `identity.signer_not_authorised` | The package declares a known name but is not signed by the key on record | Tier 3 if the entry's authority is `publisher`, tier 2 if `distributor` |
| `identity.label_claims_another_package` | The launcher label belongs to a different package in the reference set | Reported only — never moves the tier |
| `cert.expires_before_play_minimum` | The signing certificate expires before 22 Oct 2033, so the file was not distributed through Play under this key | Reported only |

Two design points carry the honesty of this layer. **Authority is per entry**, because the strength
of a mismatch depends entirely on what the reference set actually knows: a key observed on an
F-Droid build licenses "this is not that build", not "this is not the publisher's". And the **tier
gets its own vocabulary** (`report.IDENTITY_TIERS`): reaching tier 3 on an identity finding prints
*"Not the application it claims to be"*, never *"Harmful behaviour demonstrated"*, because no
behaviour was demonstrated. If a real behaviour reaches the same tier, the behavioural wording wins.
`verdict.decide` tracks the two maxima separately for exactly this reason.

Baselines deliberately do not apply, for the same reason they do not apply to an intelligence
identity match — and the TL;DR now names this exception rather than claiming a universal rule.

The shipped `data/known_signers.json` holds the 23 F-Droid builds of the evaluation corpus, recorded
as `distributor`. It is a seed, not a registry; the set is built where it is deployed:

```bash
python -m apk_engine reference --from /path/to/genuine/apks \
    --authority publisher --note "Downloaded from Google Play, 18 Sep 2026"
```

### 8.3 Reproducibility of the examination (§4.3)

Every report now carries `reproduction`: engine and tool versions, the SHA-256 of every file in
`data/` that the examination read, the baseline snapshot it was judged against, and the command.
`tests/test_determinism.py` holds the engine to the claim — two examinations of one file must agree
in every field but `engine.seconds`, which the block names as the one volatile field.

The statutory certificate was already here (`evidence/certificate_pdf.py`, Parts A and B of THE
SCHEDULE, hash-report annexure, DRAFT stamp when unsigned), and APK exhibits already reach it
through `ingest_evidence`. What was missing was the expert's side: what the *examination* did.
Wiring the reproduction block into the PDF as a further annexure is deliberately **not** done — that
document has invariants worth not disturbing on a Friday.

### 8.4 The falsification ledger (§4.5)

```bash
python -m apk_engine corpus
```

prints the corpus behind every base rate, one SHA-256 per sample, so the measurement can be repeated
and contradicted.

### 8.5 Corpus tooling (§4.4)

`scripts/fetch_fdroid_corpus.py` builds a reproducible benign corpus from the F-Droid index:
deterministic sampling from a fixed seed, index-published SHA-256 verified on every download,
resumable, with a manifest recording the index version and the exact selection. Verified against the
live index (4,408 packages available); **the download and re-measurement have not been run** — that
is several gigabytes and an hours-long memory-hungry measurement, and it is a deliberate decision,
not a side effect of this work.

### 8.6 What could not be re-measured

`data/baselines.json` is **unchanged**, and deliberately so. The attribution fix alters what five
capabilities count, so the honest move would be to re-measure the whole corpus — but 8 of the 31
benign samples (the Flipkart build and 7 locally built apps) are no longer on this machine, so the
31-app measurement cannot be reproduced. Re-measuring on the 23 that remain would shrink the corpus
below `MIN_BENIGN = 30` and invalidate every *validated* status.

The stale direction is the safe one: the stored counts can only *overstate* how often a signal fires
on legitimate apps, and overstating that can only hold a tier down, never push one up. No sample can
be raised by a stale baseline.

Two things follow, and both are open. The hypothesis in §3.5 — that manifest contamination is why
`beh.accessibility_control_with_overlay` fired on ConsentLens — is **untested**, because ConsentLens
is one of the missing 8. And re-acquiring those 8 is now a precondition for the corpus scale-up, not
merely desirable.

### 8.8 Acquiring malicious samples safely

`scripts/fetch_malwarebazaar_corpus.py` and `scripts/analyse_untrusted.sh` make a labelled malicious
corpus obtainable without putting a runnable sample on the host.

The threat model is worth stating precisely, because "running malware" is not what happens here.
There is no Android runtime on this machine, so an APK is an inert ZIP and the engine never executes
a line of it. The real exposure is that **androguard, apkInspector, lxml and zlib parse
attacker-chosen bytes**, two of them in C. The likely outcome is a crash or a hang, which
`RLIMIT_AS` and `RLIMIT_CPU` already bound. The container is for the unlikely one, and for the far
more probable accidents — a sample escaping as a runnable file, or reaching the network.

| Rule | How it is enforced |
|---|---|
| Samples stay encrypted at rest | What is written is the password-protected ZIP as abuse.ch served it, named by SHA-256, mode `0400`. No `.apk` ever exists on the host |
| Decryption happens only in the sandbox | `unpack` runs on a `tmpfs` mounted `noexec,nosuid,nodev`, and is discarded with the container |
| Every sample is verified | SHA-256 checked against the manifest after decryption, and the ZIP magic checked — a file that is not the sample recorded is not analysed |
| Nothing reaches a repository | `fetch` refuses to write into a directory with a `.git` above it; `.gitignore` also covers `*.apk`, `apk_corpus/` and `sandbox_results/` |
| The key is never an argument | Read from `MALWAREBAZAAR_AUTH_KEY`, so it stays out of shell history and `ps` |
| The analysis can do nothing else | `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, memory and PID capped |

**Verified end to end on 18 Sep 2026** with a synthetic corpus — a benign F-Droid app wrapped exactly
as MalwareBazaar serves them, plus one deliberately corrupted entry. The corrupt entry was rejected
on digest mismatch, the valid one was examined, and nothing was written to the host but the report.
Labelling a benign app "malicious" did not make the engine agree: it reported tier 1.

The sandbox also corrected a real assumption. The image's main `python3` carries
`cap_net_raw,cap_net_admin` for live capture, and the kernel refuses to exec a file with capabilities
under `no-new-privileges`. That refusal is correct, and the fix was to use
`/usr/local/bin/python3-analysis` — the capability-free copy the Dockerfile already makes, and the
same binary `APK_ENGINE_PYTHON` points at in production. The sandbox and the deployed path now run
the same interpreter.

### 8.9 The first measured detection rate (18 Sep 2026)

200 APK samples were acquired from MalwareBazaar — the 200 most recent as of 18 Sep 2026, first seen
between 8 Jul and 17 Sep 2026, no filtering by family or by what we detect. Labelled families include
Copybara, IRATA, NGate and Herodotus; 168 are unlabelled but confirmed malicious by the source. All
200 unpacked with zero digest rejections and were examined in the sandbox.

| Tier | Samples | |
|---|---:|---|
| 4 — Known harmful software | **10** | indicator identity match |
| 3 — Harmful behaviour demonstrated | **8** | validated behaviour rule |
| 2 — Built to evade inspection | **50** | validated integrity indicator |
| 1 — No harmful behaviour established | **127** | **missed** |
| 0 — Could not be examined | 5 | 4 tier 0, 1 engine crash |

**68 of 200 (34%) reached tier 2 or above. 127 (63.5%) were missed.** That is the first sensitivity
figure this project has ever had, and it is the honest one: five behaviour rules against a broad
sample of current Android malware. It is stated here rather than buried because the alternative —
no figure at all — is what every scoring tool in §1 offers.

Two samples are worth naming. `com.transport.gov.in` reached tier 4 and `com.Sam.RtoEchallan`
reached tier 3: a package impersonating the Indian transport ministry, and an RTO e-challan lure.
The Indian caseload described in §5 is not hypothetical, and it is in this corpus.

#### What the misses specify

The 127 are a work list, not a disappointment. Ranked by what the measurement shows:

| Finding | Evidence | Action |
|---|---|---|
| **Five integrity signals were inert** | `zip.encryption_flag_on_package` fired on **71 of 195** malicious packages and on no legitimate app — and could not raise a tier. Same for `zip.path_collisions` (34), `axml.unknown_chunk` (21), `axml.attribute_start` (14), `zip.oversized_filename` (9) | **Fixed** (§8.10). Needs a benign re-measurement to take effect |
| **`cap.dynamic_code_loading` has no rule** | 0 / 31 legitimate, **35 / 195** malicious. A capability that clean, unused by any behaviour rule | Write the rule: dynamic loading of code fetched at runtime |
| **Accessibility is the largest signal we cannot use** | `cap.accessibility_actions` **71 / 195**; `beh.accessibility_control_with_overlay` fired on 11 but is *experimental* | Re-measure after the manifest-attribution fix (§8.1); it may validate |
| **SMS rules are too narrow** | `cap.sms_receiver` **48 / 195**, `cap.sms_read` 36, `cap.sms_send` 34 — but the only SMS rule is Telegram-specific and fired on **1** | Write a general SMS-exfiltration rule, not bound to one channel |

### 8.10 A measurement bug that disqualified the best signals

`engine.signals()` recorded an integrity signal only when it *fired*. A signal that fired on none of
the 31 legitimate apps therefore never reached `baselines.json` at all, and `baselines.status` then
called it **unmeasured** — which bars it from raising a tier.

The effect is exactly backwards: **the signals that discriminate best were the ones structurally
disqualified**, because discriminating perfectly means never appearing in the benign corpus. It cost
us the strongest single signal in the run.

Fixed: every indicator in `integrity.INDICATORS` is now written out, present or absent — but only
when the check completed, since "did not fire" is otherwise a claim about a file nothing could read.
Three tests hold it (`test_integrity.MeasurementTests`).

**This does not change any verdict yet.** `baselines.json` still lacks those signals, and it cannot
be regenerated while 8 of the 31 benign samples are missing from this machine (§8.6). A benign
corpus from `scripts/fetch_fdroid_corpus.py` is now the blocking dependency for a real re-measurement
— and on this evidence it should raise the detection rate substantially.

### 8.7 What was not built, and why

**Capture correlation promoted to evidence (§4.2)** scores highest on novelty of anything left and
was still rejected. Promoting it needs a measured base rate for "a benign app's own-code host
appears in an unrelated capture", and there are no benign captures paired with benign apps to
measure it on. Building it now would mean shipping an unmeasured tier-raiser — the precise failure
this rebuild exists to remove. It stays at `tier_effect: 'none — corroboration only'`.

**A malicious corpus (§4.4)** — the tooling is built and verified (§8.8), but **nothing has been
downloaded**. Every MalwareBazaar endpoint requires an Auth-Key from an abuse.ch account, which is a
registration only the operator can make.

### 8.11 Rule candidates, from the families actually in the corpus (18 Sep 2026)

The 127 misses are a work list, and the corpus itself says which rules to write: the families
MalwareBazaar labelled are the ones whose published analyses describe concrete, detectable
combinations. Each candidate below cites the report it comes from, as every shipped rule must.

| Candidate rule | Combination | Documented in | Corpus evidence |
|---|---|---|---|
| `beh.dynamic_code_from_network` | dynamic class loading **and** network egress in the app's own code | Google's own policy forbids Play apps downloading executable code from outside Play ✅; SpyNote "fetches encrypted modules at runtime and decrypts them in memory" ⚠️ | 0 / 31 in the baseline corpus and **1 / 299 held out**, against 35 / 195 malicious — good, not perfect (§8.13) |
| `beh.accessibility_text_entry_with_overlay` | accessibility **text entry** (not just gestures) **and** an overlay window | Copybara: taps, swipes, text entry, global actions, overlay via `TYPE_APPLICATION_OVERLAY` ⚠️; Herodotus: randomised 300–3000 ms delays between input events to imitate human typing and defeat behavioural biometrics ⚠️ | `cap.accessibility_actions` **71 / 195** — the largest capability signal in the run |
| `beh.screen_streaming` | `MediaProjection` capture **and** network egress | SpyNote records screen and audio to `video.mp4` ⚠️; Copybara offers screen streaming and capture ⚠️ | not yet a capability; would need one added |
| `beh.sms_exfiltration` (generalised) | SMS read/receive **and** any network egress — not bound to one channel | the present rule requires `api.telegram.org`, which fired on **1 / 195** while `cap.sms_receiver` fired on **48 / 195** | the narrowness is measured, not assumed |
| `beh.nfc_relay` | NFC / `IsoDep` **and** network egress | ESET on NGate: relays NFC payloads from the victim's card to the attacker's device for ATM withdrawal ⚠️ | NGate is in the corpus (2 samples) |
| `beh.notification_suppression` | notification listener **and** programmatic dismissal | Copybara suppresses notifications to hide bank alerts ⚠️ | `cap.notification_listener` 22 / 195 |

The first is the best justified. Dynamic code loading is not merely unusual in legitimate apps — it
is **against Google Play policy**: "An app may not download executable code (such as dex, JAR, .so
files) from a source other than Google Play" ✅. It is also, on the held-out evidence, *not* clean
enough to stand alone: one of 299 unseen legitimate apps used it (§8.13). That is exactly why the
rule is written as a conjunction with network egress rather than as a bare capability — and exactly
what a held-out corpus is for.

None of these were implemented during the measurement run, deliberately: changing the detector while
a held-out measurement is in flight would make the measurement describe neither the old engine nor
the new one.

### 8.12 What the benign corpus can and cannot prove

The 300-app F-Droid corpus (§8.5) tightens the false-positive bound by an order of magnitude, and it
is worth being exact about what it does not fix.

F-Droid apps carry **89% fewer tracking libraries than their Google Play equivalents** (University of
Oxford, 2025 ⚠️), and over three quarters of the repository is built from source with proprietary
components removed ⚠️. Developers frequently ship a deliberately stripped FOSS build to F-Droid.
That is a cleaner population than the one an examiner actually meets.

The consequence is directional and should be stated wherever the bound is: **a false-positive rate
measured on F-Droid is optimistic for Play Store apps.** The app that broke the old scorer was
Flipkart — a Play build whose merged manifest declares components under `com.facebook`, `in.juspay`
and `org.npci.upi` — and that class of app is precisely what F-Droid under-represents. It is also
one of the 8 samples no longer on this machine (§8.6).

This does not undermine the corpus; it bounds the claim. "Fired on none of 300 legitimate F-Droid
builds" is a real and checkable statement. "Fires on fewer than 1% of Android apps generally" is not
one the corpus supports, and is not made.

### 8.13 The held-out result, and two claims it corrected (18 Sep 2026)

300 F-Droid packages that had never been measured before were run against the baselines in force,
in `--check` mode, so nothing was written and nothing was fitted. 299 were examined; one
(`pw.faraday.faraday`) exceeded the 6 GB memory cap and was recorded **tier 0, "Could not be
examined"** — the correct outcome, and never presented as clean.

**No legitimate app reached tier 2 or above. Every signal that is permitted to raise a tier fired on
zero of 299.** That includes all eight AXML indicators, all seven ZIP indicators, `cert.debug_certificate`,
and all three validated behaviour rules:

| Signal class | Fired on 299 unseen legitimate apps |
|---|---|
| `beh.install_under_network_blackout`, `beh.install_from_quick_tunnel`, `beh.sms_to_telegram_bot` | **0** |
| every `zip.*` integrity indicator, including `zip.encryption_flag_on_package` | **0** |
| every `axml.*` integrity indicator | **0** |
| `cert.debug_certificate`, `cap.telegram_bot_api`, `cap.quick_tunnel_url` | **0** |

`zip.encryption_flag_on_package` deserves its own line: **0 / 299 legitimate, 71 / 195 malicious.**
That is the signal §8.10 found inert because of the measurement bug, and the held-out corpus now
confirms it is not merely unfired on benign apps but genuinely clean on a population ten times
larger.

The exercise also corrected two things this document previously asserted, which is what a held-out
corpus is supposed to do:

**`cap.dynamic_code_loading` is not zero.** It was 0/31 in the baseline corpus; on 299 unseen apps it
fired **once** (95% upper bound 1.6%). The capability alone is therefore not a clean discriminator,
and §8.11's description of it as "the cleanest unused signal we have" was an artefact of a 31-app
sample. The conjunction rule is still worth writing; the bare capability is not.

**`cert.malformed_country` is mislabelled `validated`.** It was 0/31, so `baselines.status` calls it
validated — and it fired on **15 of 299** unseen apps (5%). It does no damage today, because
certificate subject anomalies are reported on the certificate and are not integrity findings, so
`verdict.decide` never reads them and none of those 15 apps moved above tier 1. But the label is
wrong, and if that signal were ever wired into the tier path it would produce false positives at
about one in twenty. It should be re-measured and demoted before it is used for anything.

Both corrections come from the same source: a 31-app corpus cannot distinguish "never happens" from
"happens rarely". That is the entire argument for §8.5, made against our own claims.

---

## Sources

- VirusTotal, *How it works* — file sharing with partners and premium customers ✅
  <https://docs.virustotal.com/docs/how-it-works>
- Pithus, *About* — aggregated tools, no overall verdict, MalwareBazaar auto-upload ✅
  <https://beta.pithus.org/about/>
- MobSF issue #1069, *Improve security scoring of apps* ⚠️
  <https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues/1069>
- MobSF issue #1731, *Better Scoring and Risk metrics* ⚠️
  <https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues/1731>
- I4C / NCTAU advisory, 26 Aug 2026, six-stage modus operandi ⚠️
  <https://thenewsmill.com/2026/08/i4c-warns-of-financial-fraud-from-malicious-android-porn-apps/>
- I4C advisory, 8th Pay Commission WhatsApp APK scam, 14 Feb 2026 ⚠️
  <https://www.indiatvnews.com/technology/news/8th-pay-commission-whatsapp-scam-i4c-warns-government-employees-against-malicious-apk-files-2026-02-14-1030266>
- Bharatiya Sakshya Adhiniyam 2023, §63 — dual certification, hash value and algorithm ⚠️
  <https://indiankanoon.org/doc/125020475/>
- LAMDA: *A Longitudinal Android Malware Benchmark for Concept Drift Analysis*, ICLR 2026 ⚠️
  <https://arxiv.org/pdf/2505.18551>
- TESSERACT / *Breaking Out from the TESSERACT: Reassessing ML-based Malware Detection under
  Spatio-Temporal Drift* ⚠️ <https://arxiv.org/pdf/2506.23814>
- LibScout ⚠️ <https://github.com/reddr/LibScout> · LibRadar ⚠️
  <https://yaoguopku.github.io/papers/Ma-ICSE-16.pdf> · LibID ⚠️
  <https://www.cl.cam.ac.uk/~arb33/papers/ZhangBeresfordKollmann-LibID-ISSTA2019.pdf>
- FSquaDRA, *Fast Detection of Repackaged Applications* ⚠️
  <https://link.springer.com/chapter/10.1007/978-3-662-43936-4_9>
- Axelsson, *The base-rate fallacy and the difficulty of intrusion detection* (1999) — via ⚠️
- Android Developers, *Dynamic code loading* and the Play policy forbidding executable code from
  outside Play ✅ <https://developer.android.com/privacy-and-security/risks/dynamic-code-loading>
- Zscaler ThreatLabz, *Technical Analysis of Copybara* — MQTT C2, accessibility text entry,
  `TYPE_APPLICATION_OVERLAY`, notification suppression ⚠️
  <https://www.zscaler.com/blogs/security-research/technical-analysis-copybara>
- ThreatFabric, *Herodotus: new Android malware mimics human behaviour* — device takeover,
  randomised 300–3000 ms input delays against behavioural biometrics ⚠️
  <https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection>
- CYFIRMA, *SpyNote: unmasking a sophisticated Android malware* — MediaProjection capture,
  BOOT_COMPLETED persistence, in-memory DEX injection ⚠️
  <https://www.cyfirma.com/research/spynote-unmasking-a-sophisticated-android-malware/>
- ESET, *NGate: Android malware relays NFC traffic to steal cash from ATMs* ⚠️
  <https://www.welivesecurity.com/en/eset-research/ngate-android-malware-relays-nfc-traffic-to-steal-cash/>
- University of Oxford (2025), F-Droid builds carry 89% fewer tracking libraries than their Play
  equivalents — reported via ⚠️ <https://protonvpn.com/blog/what-is-f-droid>
- Our own measurements: `backend/apk_engine/data/baselines.json`, measured 18 Sep 2026,
  engine 2.0.0, 31 benign / 1 malicious; MalwareBazaar sensitivity run and F-Droid held-out check,
  18 Sep 2026.

---

**Audit note.** Every claim this document makes about our own code was checked against the source by
a separate audit pass on 18 Sep 2026. It found one false claim ("no network call anywhere in
`apk_engine/`" — `refresh_data.py` is in that package), one overstatement (§2.3's SDK guarantee,
which does not cover manifest evidence — now §3.5), one set of figures recorded nowhere (Flipkart's
app/SDK endpoint split — removed), and an incomplete signal table (`cap.boot_start` = 20 was
missing). All are corrected above.
