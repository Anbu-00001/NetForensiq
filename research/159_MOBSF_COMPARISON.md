# 159 — MobSF on the same samples

**Question:** research/150 §2.1 read MobSF's source and concluded that it "does
not classify malware and never claimed to — its security score is an appsec
score", which is why it was evaluated and not shipped (it is also GPL-3.0).
That was an argument from reading. This measures it: MobSF is run over samples
this engine has already been scored on, and the two are compared claim by claim.

**Setup.** `opensecurity/mobile-security-framework-mobsf:latest` (3.48 GB image),
in Docker with a 6 GB cap, REST API on 127.0.0.1:8081. Peak container memory
during scanning: 482 MB. Driven by `scripts/mobsf_compare.py` (upload → scan →
report_json). No VirusTotal key is configured, so no sample left the machine.
Raw reports are 39 MB of full MobSF output and are kept outside this repository,
in `apk_corpus/analysis/mobsf/` alongside the corpora they describe.

**Samples (14).** 10 from the blind set — the first 5 in sorted order this
engine flagged and the first 5 it missed — plus 3 F-Droid apps and the KANAD
S.H.I.E.L.D. hackathon sample.

---

## 1. MobSF's security score does not separate malware from legitimate apps

| App | What it is | MobSF score | high | This engine |
|---|---|---:|---:|---|
| com.example.tiramisudropper | blind malware | **67** | 0 | tier 2 |
| watchdog.streamguard.shuffler | blind malware | 62 | 0 | tier 3 |
| **org.fdroid.fdroid** | **legitimate** | **62** | 3 | tier 1 |
| watcher.lords.upp | blind malware | 56 | 0 | tier 3 |
| **de.blinkt.openvpn** | **legitimate** | **52** | 1 | tier 1 |
| netjrt454t.wetkgr46b.securi87ty | blind malware | 49 | 2 | tier 1 (missed) |
| com.user.ad | blind malware | 49 | 3 | tier 1 (missed) |
| com.devpranto.efztour | blind malware | 49 | 3 | tier 1 (missed) |
| com.example.variousdata | blind malware | 48 | 5 | tier 4 |
| **com.termux** | **legitimate** | **47** | 2 | tier 1 |
| com.doxgram.io | blind malware | 46 | 2 | tier 1 (missed) |
| com.startup | blind malware | 46 | 2 | tier 1 (missed) |

Every score lands between 46 and 67, and the three legitimate apps sit in the
middle of the malware. Termux, a legitimate terminal emulator, scores *lower*
(i.e. looks worse) than seven of the nine malware samples.

**This is not a defect in MobSF.** Its score measures hardening and code
quality — debuggable flags, weak crypto, cleartext traffic, exported components
— which is what it is documented to do. It is a defect only in the assumption
that a security score is a malware verdict. Predicted before the run that the
score would separate the two sets cleanly: p = 0.25, and it did not.

## 2. The hackathon sample: MobSF scored it 73/100

Run on the real APK (see §4), MobSF gave `com.mrram.loader` — the fake pension
card app handed out at KANAD S.H.I.E.L.D. 2026 — a security score of **73/100**,
the *best* of every app in this comparison, with **zero** high-severity findings.

The reason is visible in its own report:

```
permissions: 0 · activities: 0 · services: 0 · receivers: 0 · manifest findings: 0
apkid: manipulator: ["Resources Confusion"], anti_vm: ["Build.FINGERPRINT check", ...]
```

The manifest is deliberately malformed — MobSF's own APKiD module names the
technique — so MobSF's manifest parse returned nothing. Its score is computed
from findings, so **finding nothing scored well**. Absence of evidence became
evidence of absence, and the number went up.

This engine reads the same file as **tier 3 — harmful behaviour demonstrated**:
`beh.install_under_network_blackout` and `beh.install_from_quick_tunnel`,
package `com.mrram.loader`, with the manifest parsed by its own AXML reader
rather than androguard's.

**What MobSF did find, and this is worth saying:** the Cloudflare quick-tunnel
host `representation-certified-accomplish-existed.trycloudflare.com`, the
anti-VM `Build.FINGERPRINT` checks, 13 matched behaviour rules, and an insecure
WebView. As an *analyst's workbench* it produced real material. It is the
headline number that misleads.

## 3. Where MobSF is stronger, and where it broke

- **Stronger:** far more breadth — trackers, certificate detail, APKiD packer and
  obfuscator identification, code-level pattern rules, a web UI, and dynamic
  analysis with Frida that this engine does not have at all.
- **Broke on one sample.** `050d91cd…` returned HTTP 500. The container log shows
  `Unzipping Error - Corrupt extra field 5866 (size=11822)` followed by
  `UnboundLocalError: cannot access local variable 'stop_fallback_extraction'` —
  a tampered archive hitting a bug in MobSF's fallback extraction path. This
  engine reads that same sample as tier 2, built to evade inspection: the
  tampering *is* the finding here, which is the design difference in one line.
- **Five samples this engine missed** scored 46–49 with 2–3 high findings each —
  indistinguishable from the legitimate apps' scores. MobSF does not rescue our
  misses by any threshold that would not also flag F-Droid.

## 4. A discovery about the hackathon sample itself

The file distributed as `PENSION CARD VERIFICATION.apk` (SHA-256 `7b95893a…`,
1,268,990 bytes, the copy in `mal/TEST_KIT/apks_malicious/`) **is not an APK**.
It is an AES-encrypted ZIP, password `infected`, containing the real 2,112,553-byte
APK (SHA-256 `664e43ef…`).

That matters when comparing tools:

| Input | MobSF | This engine |
|---|---|---|
| the encrypted container | score 60, package "Failed", nothing parsed | tier 2 — encryption flag and compression method forged |
| the real APK inside | score 73, package "Failed", 0 permissions | **tier 3** — install under network blackout, quick-tunnel install |

The platform's upload path unwraps containers with conventional passwords, so an
officer uploading the distributed file gets the tier 3 result; `python -m
apk_engine examine --apk` on the raw container does not, which is what produced
the tier 2 reading above. Both numbers are correct for what they were given.

## 5. What this does not show

- Nine malware samples and three legitimate apps is far too small for any rate.
  No detection claim is made here for either tool.
- MobSF was run with default settings, no VirusTotal key, static analysis only.
  Its dynamic analysis was not used and would likely find more.
- The comparison is of *what each tool says*, not of accuracy: MobSF does not
  claim to classify malware, and holding it to that standard would be unfair.

*Run 23 Sep 2026. Tool: `scripts/mobsf_compare.py`. Raw reports and the sample
selection are in `apk_corpus/analysis/mobsf*/`. Image:
`opensecurity/mobile-security-framework-mobsf:latest` (3.48 GB), static analysis
only, no VirusTotal key, `--memory 6g`.*
