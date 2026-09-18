"""
Static examination of Android packages — a separate program, not a library.

NetForensiq asks this engine one question per sample: *what can be shown about
this package, and how strongly?* The answer is a tier of evidence, never a
score. See research/150_APK_MALWARE_CLASSIFICATION.md for why the previous
additive score was replaced: it called Flipkart a remote access trojan and
missed what the judge's dropper actually did.

Why it runs in its own process
==============================
Two independent reasons arrive at the same design.

1. **Licensing.** The web process imports scapy, which is GPL-2.0-only. This
   engine is built on androguard and apkInspector, both Apache-2.0. The Apache
   Software Foundation states that Apache-2.0 code "cannot be included in GPLv2
   projects" (apache.org/licenses/GPL-compatibility.html). The GNU GPL FAQ
   treats "pipes, sockets and command-line arguments" as "communication
   mechanisms normally used between two separate programs". So the engine takes
   a path on its command line and writes a documented JSON report to stdout,
   and the two licences never share an address space.

2. **The input is hostile by hypothesis.** A sample is built to break parsers —
   the judge's dropper forged its ZIP headers for exactly that purpose. A parser
   crash, a runaway allocation or a decompression bomb here kills this process,
   under resource limits the caller sets, instead of a gunicorn worker holding
   other officers' requests. The caller also withholds its environment, so the
   process examining a sample never sees the database password or SECRET_KEY.

Import discipline
=================
Nothing in this package may import django or scapy, and androguard/apkInspector
are imported only inside functions that run in the engine process. The web
process imports ``report``, ``container`` and ``endpoints`` — standard library
only — for tier-0 reports, pre-extraction archive checks and correlation. Tests
enforce both directions.
"""

ENGINE_VERSION = '2.0.0'
REPORT_SCHEMA = 'netforensiq.apk-examination/2'
