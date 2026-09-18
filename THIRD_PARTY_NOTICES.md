# Third-party notices

NetForensiq's own code is MIT-licensed (see LICENSE). It depends on, and ships
data from, the projects below. Nothing here is legal advice; it records what
was checked and when.

## Why the licence is MIT, and why the APK engine is a separate process

The web process imports **scapy**, which is `GPL-2.0-only`. The APK examination
engine is built on **androguard** and **apkInspector**, which are Apache-2.0,
and the Apache Software Foundation states that Apache-2.0 code "cannot be
included in GPLv2 projects"
(<https://www.apache.org/licenses/GPL-compatibility.html>).

So the engine is a separate program: `capture/apk_runner.py` invokes
`python -m apk_engine examine` with a path on the command line and reads one
JSON report from its stdout. The GNU GPL FAQ treats "pipes, sockets and
command-line arguments" as "communication mechanisms normally used between two
separate programs"
(<https://www.gnu.org/licenses/gpl-faq.html#MereAggregation>). The two licences
never share an address space, and `apk_engine/tests/test_cli.py` enforces that:
the engine may not import scapy or Django, and the modules the web process
imports may not pull androguard in.

MIT (Expat) is GPL-compatible per the FSF's licence list, so NetForensiq's own
code combines with scapy in one process and with androguard in the other. No
GPL-licensed tool is used: APKiD, Quark-Engine and MobSF were evaluated (see
`research/150_APK_MALWARE_CLASSIFICATION.md`) and are deliberately not shipped.

## Code dependencies of the APK engine

| Project | Licence | Use |
|---|---|---|
| [androguard](https://github.com/androguard/androguard) 4.1.4 | Apache-2.0 | APK/AXML/DEX parsing, signatures, cross-references |
| [apkInspector](https://github.com/erev0s/apkInspector) 1.3.7 | Apache-2.0 | ZIP/AXML tampering indicators |

androguard is installed with `--no-deps`; the imports it needs are pinned in
`backend/requirements.txt`.

## Bundled reference data (`backend/apk_engine/data/`)

Regenerate with `python -m apk_engine.refresh_data`; provenance, retrieval date
and SHA-256 of every file are recorded in `data/sources.json`.

| Data | Source | Licence | Notes |
|---|---|---|---|
| `exodus_trackers.json` | [Exodus Privacy](https://exodus-privacy.eu.org/) tracker signatures | ODbL-1.0, contents DbCL-1.0 | Used to attribute code and network endpoints to SDKs. A derivative database; stays under ODbL. |
| `stalkerware_indicators.json` | [Echap stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | CC-BY-4.0 | Packages, signing-certificate SHA-1s, C2 domains and sample hashes. Only `ioc.yaml` (stalkerware) and `samples.csv` are included; `watchware.yaml` (parental-monitoring apps) is deliberately excluded so a parental control is never reported as stalkerware. |
| `tlds.txt` | [IANA root zone database](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | IANA public data | Distinguishes hostnames from Java package names. |
| Permission metadata | AOSP, bundled inside androguard | Apache-2.0 | Protection levels, labels and descriptions shown for each permission. |

## Classification vocabulary

Category names and definitions are Google's Potentially Harmful Application
categories (<https://developers.google.com/android/play-protect/phacategories>);
technique identifiers are MITRE ATT&CK for Mobile
(<https://attack.mitre.org/matrices/mobile/android/>). Both are quoted with a
link to the source rather than paraphrased.

## Reference captures

Network captures used for demonstration come from Netresec,
malware-traffic-analysis.net and WRCCDC under their published terms, and are
marked REFERENCE in the evidence store — real traffic, never evidence.
