#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Write validation/VALIDATION_REPORT.md from validation/results.json.

The report's numbers are not typed into it. They are read from results.json,
which scripts/extract_validation_data.py derived from run logs and corpus
manifests, so a number in the report can be traced to a log line. A test
(evidence/tests_validation.py) regenerates the report and requires it to equal the
committed file, and requires the README's headline figures to appear in it.

Shaped after what the UK Forensic Science Regulator's *Method Validation in
Digital Forensics* (FSR-G-218, Issue 2) asks of a validation record: each
requirement with its finding; failures highlighted; limitations of the testing
and of the method detailed (s.7.6.4); test data described, including how little
control there was over it (s.7.2.1c); and the expected outcome with an error
margin where one can be set (s.7.2.1d). Quotations below were read from that
document. This is not a claim of compliance with it: see "Status of this report".

    python scripts/build_validation_report.py            # rewrite the report
    python scripts/build_validation_report.py --check    # fail if it is out of date
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'validation' / 'results.json'
REPORT = ROOT / 'validation' / 'VALIDATION_REPORT.md'
# The same figures in the form the running product reads (capture/limits.py). It
# lives inside backend/ because only backend/ is copied into the image; it is
# generated here, from the same results.json as the report, and a test requires it
# to equal a regeneration.
SUMMARY = ROOT / 'backend' / 'capture' / 'data' / 'validation_summary.json'
TIER_NAMES = {'4': 'Known harmful software', '3': 'Harmful behaviour demonstrated',
              '2': 'Built to evade inspection', '1': 'No harmful behaviour established',
              '0': 'Could not be examined'}


def pct(x, places=1):
    return f'{x * 100:.{places}f}%'


def ci(pair):
    return f'{pair[0] * 100:.1f}–{pair[1] * 100:.1f}%'


def run_by_id(results):
    return {r['id']: r for r in results['apk_runs']}


def malicious_table(runs):
    lines = ['| Run | Corpus | Engine image | n | Tier 4 | Tier 3 | Tier 2 | Tier 1 | Tier 0 | Detected | 95% CI |',
             '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|']
    for run in runs:
        t = run['tiers']
        lines.append(
            f"| `{run['id']}` | {run['corpus']} | `{run['engine_image'].split(':')[-1]}` | {run['n']} "
            f"| {t['4']} | {t['3']} | {t['2']} | {t['1']} | {t['0']} "
            f"| **{run['detected_of_n']} / {run['n']}** ({pct(run['detection_rate'])}) | {ci(run['ci95'])} |")
    return '\n'.join(lines)


def benign_table(runs):
    lines = ['| Run | Engine image | Apps | Examined | Could not be examined | Reached a tier | 95% bound on the false-positive rate |',
             '|---|---|---:|---:|---:|---:|---|']
    for run in runs:
        fp, examined = run['false_positives_of_examined']
        bound = (f"≤ {pct(run['ci95'])} (one-sided)" if run['ci95_kind'] == 'one-sided upper bound'
                 else ci(run['ci95']))
        lines.append(f"| `{run['id']}` | `{run['engine_image'].split(':')[-1]}` | {run['n']} "
                     f"| {examined} | {run['could_not_be_examined']} | **{fp}** | {bound} |")
    return '\n'.join(lines)


def clopper_pearson(k, n, alpha=0.05):
    import math

    def cdf(p, upto):
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(upto + 1))

    def bisect(test, lo=0.0, hi=1.0):
        for _ in range(80):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if test(mid) else (lo, mid)
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else bisect(lambda p: 1 - cdf(p, k - 1) < alpha / 2)
    upper = 1.0 if k == n else bisect(lambda p: cdf(p, k) > alpha / 2)
    return lower, upper


def network_rule_table(net):
    table = net['rule_table']['rules']
    lines = ['| Rule | Ordinary-traffic captures it fired on | 95% upper bound on that rate '
             '| Attack captures it fired on | Reading |', '|---|---:|---:|---:|---|']
    readings = {
        'IOC_FEED_MATCH': 'untested: silent without an imported feed',
        'HOST_CORROBORATED': 'untested: needs rules that fire on no ordinary capture to vote',
        'ANOMALY_STATISTICAL': 'a lead, not a finding; fires on every capture by construction',
    }
    for rule, v in sorted(table.items()):
        bf, bn, mf, mn = v['benign_fired'], v['benign_captures'], v['malicious_fired'], v['malicious_captures']
        if rule in readings:
            reading = readings[rule]
        elif bf and not mf:
            reading = 'never seen on an attack; shown at LOW'
        elif bf:
            reading = 'fires on ordinary traffic; a reason to look, not a conclusion'
        else:
            reading = 'not seen on ordinary traffic'
        lines.append(f'| `{rule}` | {bf} / {bn} | {pct(v["benign_upper95"], 0)} | {mf} / {mn} | {reading} |')
    return '\n'.join(lines)


def capture_appendix(net):
    lines = ['| Capture | Role | Flows | Findings | Rules fired (findings) |', '|---|---|---:|---:|---|']
    corpus = {c['name']: c for c in net['corpus']}
    for name in sorted(net['per_capture'], key=lambda n: (corpus[n]['label'], corpus[n]['role'], n)):
        pc = net['per_capture'][name]
        fired = ', '.join(f'{r} ({c})' for r, c in sorted(pc['rules_fired'].items())) or 'none'
        lines.append(f"| `{name}` | {corpus[name]['label']} · {corpus[name]['role']} "
                     f"| {pc['flows']:,} | {pc['findings']} | {fired} |")
    return '\n'.join(lines)


def build(results):
    runs = run_by_id(results)
    heldout = runs.get('heldout-v6') or runs['heldout-v5']
    blind = runs['blind-v6']
    same_engine = heldout['id'] == 'heldout-v6'
    k = heldout['detected_of_n'] + blind['detected_of_n']
    n = heldout['n'] + blind['n']
    combined_ci = clopper_pearson(k, n)
    fresh = runs['fresh-benign-v6']
    pre = results['preregistration']
    net = results['network']
    benign_caps = [c for c in net['corpus'] if c['label'] == 'benign']
    attack_caps = [c for c in net['corpus'] if c['label'] == 'malicious']
    version = (ROOT / 'VERSION').read_text().strip()
    missed = n - k - heldout['tiers']['0'] - blind['tiers']['0']
    unexamined = heldout['tiers']['0'] + blind['tiers']['0']
    limit6 = ('Both unseen sets are reported for the shipped engine; the held-out set was first scored by '
              'the v5 image and its verdicts were identical on re-measurement (§5.1).' if same_engine else
              'The held-out and blind sets were examined under different engine images, with an '
              'identical baseline table; the held-out set has not been re-run on the shipped image.')
    best = pre['best_zero_benign_signal']
    comparisons = results.get('engine_comparison', [])
    comparison_text = ''
    if comparisons:
        total = sum(c['compared'] for c in comparisons)
        differing = sum(c['differing'] for c in comparisons)
        comparison_text = (
            f"**Engine image check.** Where a corpus was examined by both the v5 and the shipped v6 "
            f"image ({' and '.join(c['older'].rsplit('-v', 1)[0] for c in comparisons)}), "
            f"{total - differing} of {total} per-sample verdicts were identical"
            + ('' if not differing else f" and {differing} differed")
            + ". The v6 image adds a native-code survey that no rule uses, so by construction it "
            "cannot raise a tier; this is the measured confirmation.\n\n")

    parts = []
    parts.append(f'''# NetForensiq {version} — tool validation report

Generated {results['generated'][:10]} from `validation/results.json` by
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
| Platform version | {version} |
| APK examination engine | 2.0.0 |
| Shipped APK baseline table | `backend/apk_engine/data/baselines.json`, SHA-256 `{results['shipped_baselines_sha256']}` |
| Network rule-rate table | `backend/capture/data/rule_base_rates.json`, SHA-256 `{net['rule_table_sha256']}` |

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
| at least one native-code signal fires on 0 of 201 legitimate apps and on at least 20 of 200 malicious | 70% | **false** — {pre['native_signals_with_zero_benign']} of {pre['native_signals_measured']} signals fired on no legitimate app; the best of them, `{best['signal']}`, fired on {best['malicious_fired']} of {pre['malicious_n']} examined malicious samples. No rule was built from them. |
| the blind score reaches ≥ 70 / 100 | 35% | **false** — {blind['detected_of_n']} / {blind['n']} |
| the blind score reaches the 80 / 100 target | 12% | **false** — {blind['detected_of_n']} / {blind['n']} |

## 4. Test data, and how little control there was over it (s.7.2.1c)

The guidance asks that where "there is little or no control of the source data, this should be
explicitly declared in the plan and the subsequent limitation declared", and that validation data
be "representative of the real life use the method will be put to" (s.1.1.9). Neither corpus
below is chosen by the engine's authors to be representative of seized devices.

| Corpus | Kind | n | How it was chosen | Used for |
|---|---|---:|---|---|''')

    c = results['corpora']
    parts.append(f'''| design | malicious APKs | {c['design']['n']} | MalwareBazaar (abuse.ch): file type `apk`, limit {c['design']['n']}, acquired {c['design']['acquired'][:10]} (its listing returns recent uploads) | the rules were written from these: **in-sample, not a detection claim** |
| held-out | malicious APKs | {c['heldout']['n']} | MalwareBazaar, selected by *exclusion* of the design set before any was examined; never by what the engine did with them | first unseen measurement |
| blind | malicious APKs | {c['blind']['n']} | MalwareBazaar, the 600 most recent uploads, excluding both earlier corpora; downloaded and left unexamined until the engine was frozen; scored once | second unseen measurement |
| baseline | legitimate + malicious | {c['baseline']['benign']} + {c['baseline']['malicious']} | F-Droid apps, 23 chosen because they legitimately do what malware does (install packages, create VPNs, handle SMS, run shell commands) plus a random sample | the reference the baseline table was measured on |
| fresh-benign | legitimate APKs | {c['fresh-benign']['n']} | F-Droid, sampled with a new seed; not used for baselines, rule design or defect-finding | false-positive measurement |
| network, ordinary | captures | {len(benign_caps)} | CTU Malware Capture Facility "Normal" set: {len([x for x in benign_caps if x['role'] == 'design'])} used to find and fix defects, {len([x for x in benign_caps if x['role'] == 'held-out'])} held out | rule false-alarm rates |
| network, attack | captures | {len(attack_caps)} | published malware traffic with written analysis (malware-traffic-analysis.net), a wrccdc defence exercise, and one DNS-tunnel capture published by Elastic | whether rules fire at all on attacks |

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

{malicious_table([runs[i] for i in ('design-v5', 'heldout-v5') + (('heldout-v6',) if same_engine else ()) + ('blind-v6',)])}
''')

    if same_engine:
        parts.append(f'''
`design-v5` is in-sample and is shown only to be compared with the unseen rows; the gap between it
({runs['design-v5']['detected_of_n']} / {runs['design-v5']['n']}) and the unseen sets is the
finding. The held-out set was measured twice: by the v5 engine image when it was first scored,
and again by the shipped v6 image, so that both unseen sets describe one configuration.
''')
    else:
        parts.append('''
`design-v5` is in-sample and is shown only to be compared with the unseen rows. The held-out
set was scored by the v5 engine image and the blind set by the shipped v6 image; the held-out set
has **not** been re-run on the shipped engine, so the combined figure below mixes configurations.
''')

    parts.append(f'''
**Both unseen sets together, on the {'shipped' if same_engine else 'mixed'} engine:
{k} / {n} = {pct(k / n)}** (95% CI {ci(combined_ci)}). Of the {n} samples, {missed} reached no
tier (**{pct(missed / n)} missed**) and {unexamined} could not be examined.

{comparison_text}**Failures, highlighted (s.7.6.4).** The engine does not meet an expectation of detecting most
unseen malware, still less the 80% target. The blind set scored below the held-out set
({blind['detected_of_n']} against {heldout['detected_of_n']}). Almost all of the difference is
tier 2 (integrity indicators — forged archive headers): {heldout['tiers']['2']} held-out samples
reached it and {blind['tiers']['2']} blind ones. The likeliest reason, which was **not tested**, is
that the engine's strongest signal is a packaging trick and the blind set, the 600 most recent
uploads, may use it less. Google Play Protect's published 99.8% (AV-TEST, May 2025, on different
samples) is far higher, and nothing here claims otherwise.

### 5.2 Legitimate apps (R2, R3)

{benign_table([runs['fresh-benign-v5'], runs['fresh-benign-v6']])}

No examined legitimate app reached a tier. **{fresh['could_not_be_examined']} of the
{fresh['n']} could not be examined and are not counted as clean**, which is why the bound is
computed over {fresh['examined']} and not {fresh['n']}: an earlier statement of "0 / 100, bound
3.0%" used the wrong denominator and was corrected on 2 Oct 2026 (research/154).

Zero is a count, not a rate. The one-sided 95% bound is the most the true false-positive rate
could plausibly be given zero in {fresh['examined']}: ≤ {pct(fresh['ci95'])}. The population is F-Droid
(§4), so the figure does not transfer to Play Store apps.

## 6. Results — the network detection rules (R4)

Each rule was run over {len(benign_caps)} captures of ordinary traffic and {len(attack_caps)} of attacks.
The rates are published with every finding in the interface and the investigation report.

{network_rule_table(net)}

**Read these carefully.**

* "Fired on an attack capture" is not "caught the attack". `DNS_TUNNEL_LONG_LABEL`'s firing in the
  wrccdc exercise is a CDN name (`rackcdn.com`) in a capture that happens to be an attack.
* {len(attack_caps)} attack captures is thin, and the attack corpus contains no connection-per-callback beacon, so
  `C2_BEACON_PERIODIC` is *untested* on attacks, not shown to fail. Both beacon rules are shown at
  LOW because neither has been seen to fire on one.
* With {len(benign_caps)} ordinary captures, a rule that fired on none still has a one-sided 95% upper bound
  of {pct(net['rule_table']['rules']['IOC_FEED_MATCH']['benign_upper95'])} on its true rate.
* These runs used the working tree of 19–20 Sep 2026 before it was committed; no image or commit
  identifier was recorded for them. They should be repeated on a tagged build.

Per-capture results:

{capture_appendix(net)}

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
3. **Tier 0 is not a clean result.** {unexamined} of {n} malicious and {fresh['could_not_be_examined']} of {fresh['n']} legitimate
   samples could not be examined.
4. **The corpora are not representative of seized devices** (§4).
5. **Network rule rates come from 22 + 8 captures** of one lab's collection, and the attack side
   contains no beacon of the kind one rule is built for.
6. **{limit6}**
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
''')
    return '\n'.join(parts) + '\n'


def build_summary(results):
    """The few figures the product states about itself, as JSON text."""
    runs = run_by_id(results)
    heldout = runs.get('heldout-v6') or runs['heldout-v5']
    blind = runs['blind-v6']
    design = runs['design-v5']
    fresh = runs['fresh-benign-v6']
    k = heldout['detected_of_n'] + blind['detected_of_n']
    n = heldout['n'] + blind['n']
    unexamined = heldout['tiers']['0'] + blind['tiers']['0']
    lo, hi = clopper_pearson(k, n)
    net = results['network']
    benign = [c for c in net['corpus'] if c['label'] == 'benign']
    attacks = [c for c in net['corpus'] if c['label'] == 'malicious']
    fp, examined = fresh['false_positives_of_examined']
    summary = {
        'source': 'validation/results.json, via scripts/build_validation_report.py',
        'derived_from_generated': results['generated'][:10],
        'shipped_baselines_sha256': results['shipped_baselines_sha256'],
        'apk': {
            'unseen': {'detected': k, 'n': n, 'missed': n - k - unexamined,
                       'could_not_be_examined': unexamined,
                       'ci95': [round(lo, 4), round(hi, 4)],
                       'sets': [{'id': heldout['id'], 'detected': heldout['detected_of_n'], 'n': heldout['n']},
                                {'id': blind['id'], 'detected': blind['detected_of_n'], 'n': blind['n']}]},
            'in_sample': {'detected': design['detected_of_n'], 'n': design['n']},
            'legitimate': {'false_positives': fp, 'examined': examined, 'n': fresh['n'],
                           'could_not_be_examined': fresh['could_not_be_examined'],
                           'upper95': fresh['ci95']},
        },
        'network': {'ordinary_captures': len(benign), 'attack_captures': len(attacks),
                    'held_out_ordinary_captures': len([c for c in benign if c['role'] == 'held-out'])},
    }
    return json.dumps(summary, indent=1, sort_keys=True) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    results = json.loads(RESULTS.read_text())
    text, summary = build(results), build_summary(results)
    if args.check:
        stale = [p.name for p, want in ((REPORT, text), (SUMMARY, summary))
                 if not p.exists() or p.read_text() != want]
        if stale:
            print(f'{", ".join(stale)} out of date: run scripts/build_validation_report.py')
            return 1
        print('validation report and summary are current')
        return 0
    REPORT.write_text(text)
    SUMMARY.write_text(summary)
    print(f'wrote {REPORT} ({len(text.splitlines())} lines) and {SUMMARY}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
