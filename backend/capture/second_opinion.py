# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
A second opinion on a sample: another tool's report, filed beside the exhibit.

Why MobSF, and what this is for
-------------------------------
MobSF is the open-source Android static analyser that cybercrime labs already
run. A lab that has run it on a sample has a report in hand; this lets that
report be filed against the sealed exhibit, with a custody entry recording that it
was, and read next to what this engine concluded.

What it deliberately does not do
--------------------------------
* **It does not turn MobSF's score into a verdict.** MobSF's security score
  measures hardening and code quality — debuggable flags, weak crypto, exported
  components. In the one comparison run on this project's own samples the scores of
  malware and of legitimate apps overlapped completely, and the hackathon's
  malware scored *best* because its manifest was malformed and MobSF read nothing
  from it (research/159). The comparison therefore puts the two side by side and
  says what the score is, instead of ranking them.
* **It does not trust the report to be about the exhibit.** The report states the
  SHA-256 of what it examined; a link exists only if that matches a sealed
  exhibit's examined file. Two different hashes are two different files.
* **It does not run MobSF.** The report is another tool's output, produced
  elsewhere, and is stored as such — which is also why it records whether MobSF
  consulted VirusTotal while producing it, because on an air-gapped workstation
  that is worth knowing.

Untrusted input
---------------
A report is a large JSON document written by a program that analysed a hostile
package, so strings in it can contain anything the package contained. Nothing is
executed or rendered as markup: fields are whitelisted, lists and strings are
capped, and the interface shows the text as text. Only MobSF 4.x was tested (4.5.4);
another major version is accepted but flagged.
"""
import hashlib
import json
import os
import re
from pathlib import Path

from django.conf import settings

from evidence import crypto

MAX_REPORT_BYTES = 64 * 1024 * 1024
TESTED_MAJOR = 4
_HEX = {64: re.compile(r'^[0-9a-f]{64}$'), 40: re.compile(r'^[0-9a-f]{40}$'),
        32: re.compile(r'^[0-9a-f]{32}$')}

SCORE_NOTE = (
    "MobSF's security score measures hardening and code quality, not whether an app is "
    'malicious. It is not comparable with an evidence tier. In the comparison run on this '
    "project's own samples, malware and legitimate apps scored in overlapping ranges, and the "
    'hackathon malware scored best because MobSF could not read its manifest (research/159).')


class NotAMobsfReport(ValueError):
    """The file is not a MobSF report this system can read. The message says why."""


def _text(value, limit):
    return str(value if value is not None else '')[:limit]


def _titles(items, limit_items=25, limit_chars=200):
    out = []
    for item in (items if isinstance(items, list) else []):
        title = item.get('title') if isinstance(item, dict) else item
        if title:
            out.append(_text(title, limit_chars))
        if len(out) >= limit_items:
            break
    return out


def _count(value):
    return len(value) if isinstance(value, (list, dict)) else 0


def _hash(report, key, length):
    value = str(report.get(key) or '').lower()
    return value if _HEX[length].match(value) else ''


def parse_mobsf(data):
    """
    Validate a MobSF JSON report and extract what the comparison needs.

    Returns (summary, report_sha256). Raises NotAMobsfReport. The summary is plain
    JSON-serialisable data with every list and string bounded.
    """
    if len(data) > MAX_REPORT_BYTES:
        raise NotAMobsfReport(
            f'The file is larger than the {MAX_REPORT_BYTES // (1024 * 1024)} MB limit.')
    try:
        report = json.loads(data)
    except (ValueError, RecursionError):
        raise NotAMobsfReport('The file is not valid JSON.')
    if not isinstance(report, dict):
        raise NotAMobsfReport('The file is JSON but not a MobSF report (it is not an object).')

    subject = _hash(report, 'sha256', 64)
    if not subject:
        raise NotAMobsfReport(
            'The file has no SHA-256 of the analysed package, so it cannot be tied to an '
            'exhibit. A MobSF JSON report (the "JSON report" download) carries one.')
    structure = [k for k in ('appsec', 'permissions', 'manifest_analysis', 'code_analysis')
                 if k in report]
    if not structure:
        raise NotAMobsfReport(
            'The file has a SHA-256 but none of the sections of a MobSF report '
            '(appsec, permissions, manifest_analysis, code_analysis).')

    version = _text(report.get('version'), 40)
    major = re.match(r'^v?(\d+)\.', version)
    appsec = report.get('appsec') if isinstance(report.get('appsec'), dict) else {}
    score = appsec.get('security_score')
    permissions = report.get('permissions') if isinstance(report.get('permissions'), dict) else {}
    dangerous = sorted(
        _text(name, 120) for name, detail in permissions.items()
        if isinstance(detail, dict) and detail.get('status') == 'dangerous')[:100]
    manifest_findings = _count((report.get('manifest_analysis') or {}).get('manifest_findings')
                               if isinstance(report.get('manifest_analysis'), dict) else None)
    components = {name: _count(report.get(name))
                  for name in ('activities', 'services', 'receivers', 'providers')}
    package = _text(report.get('package_name'), 255)

    apkid = []
    if isinstance(report.get('apkid'), dict):
        for where, kinds in list(report['apkid'].items())[:30]:
            if isinstance(kinds, dict):
                for kind, items in kinds.items():
                    for item in (items if isinstance(items, list) else [])[:10]:
                        apkid.append(f'{_text(where, 80)}: {_text(kind, 40)}: {_text(item, 120)}')
    domains = report.get('domains') if isinstance(report.get('domains'), dict) else {}
    trackers = report.get('trackers') if isinstance(report.get('trackers'), dict) else {}

    notes = []
    unreadable = package in ('', 'Failed') or (
        not permissions and not any(components.values()) and manifest_findings == 0)
    if unreadable:
        notes.append(
            'MobSF reported no usable package name, permissions or components for this package, '
            'so its manifest was not read. Its score reflects what MobSF could read, which here '
            'is little: a package whose manifest cannot be read can score well.')
    if not major or int(major.group(1)) != TESTED_MAJOR:
        notes.append(f'Only MobSF {TESTED_MAJOR}.x was tested; this report is from '
                     f'"{version or "an unknown version"}".')
    virus_total = bool(report.get('virus_total'))
    if virus_total:
        notes.append('MobSF consulted VirusTotal while producing this report, which means the '
                     'sample or its hash left the machine it ran on.')

    summary = {
        'tool': 'mobsf', 'tool_version': version,
        'file_name': _text(report.get('file_name'), 255),
        'package': package, 'app_name': _text(report.get('app_name'), 255),
        'version_name': _text(report.get('version_name'), 80),
        'subject': {'sha256': subject, 'sha1': _hash(report, 'sha1', 40),
                    'md5': _hash(report, 'md5', 32)},
        'score': score if isinstance(score, int) and 0 <= score <= 100 else None,
        'appsec_counts': {k: _count(appsec.get(k))
                          for k in ('high', 'warning', 'info', 'secure', 'hotspot')},
        'appsec_high': _titles(appsec.get('high')),
        'appsec_warning': _titles(appsec.get('warning')),
        'dangerous_permissions': dangerous,
        'permission_count': len(permissions),
        'components': components,
        'manifest_findings': manifest_findings,
        'trackers_detected': trackers.get('detected_trackers') if isinstance(
            trackers.get('detected_trackers'), int) else None,
        'apkid': apkid[:40],
        'domains': sorted(_text(d, 253) for d in list(domains)[:200])[:40],
        'behaviour_rules': _count(report.get('behaviour')),
        'virus_total_consulted': virus_total,
        'manifest_unreadable': unreadable,
        'notes': notes,
        'score_note': SCORE_NOTE,
    }
    return summary, hashlib.sha256(data).hexdigest()


def store_report(data, report_sha256):
    """
    Keep the report's bytes where the evidence store keeps its own, encrypted when
    the store is. Returns (path, encrypted).

    Content-addressed: the same bytes land in the same file, so re-filing a report
    against a second exhibit does not store it twice.
    """
    root = Path(settings.MEDIA_ROOT) / 'third_party'
    root.mkdir(parents=True, exist_ok=True)
    destination = root / f'{report_sha256}.json'
    if destination.parent.resolve() != root.resolve():
        raise ValueError('refusing to write outside the third-party store')
    key = crypto.load_key(create=True)
    if destination.exists():
        return str(destination), crypto.is_encrypted(destination)
    plain = destination.with_suffix('.tmp')
    plain.write_bytes(data)
    try:
        if key is not None:
            crypto.encrypt_file(plain, destination, key)
        else:
            os.replace(plain, destination)
    finally:
        if plain.exists():
            plain.unlink()
    return str(destination), key is not None


def find_examination(subject_sha256):
    """The most recent recorded examination of the package with this hash, or None."""
    from .models import ApkExamination

    return (ApkExamination.objects.filter(analysed_sha256=subject_sha256)
            .select_related('evidence').order_by('-examined_at').first())


def find_exhibit(subject_sha256):
    """
    The sealed exhibit this report describes, or None, with how it was matched.

    Two routes, both by hash and neither by trust: an exhibit whose recorded
    examination read a package with this hash (which covers a sample that arrived
    inside a ZIP), or an exhibit whose own sealed hash is it (an APK sealed before
    examinations were recorded).
    """
    from evidence.models import EvidenceRecord

    exam = find_examination(subject_sha256)
    if exam:
        return exam.evidence, 'examined', exam
    exhibit = EvidenceRecord.objects.filter(sha256_hash=subject_sha256).first()
    if exhibit:
        return exhibit, 'sealed', None
    return None, 'none', None


def compare(exam, summary):
    """
    Side-by-side rows for the interface. No ranking and no agreement score: where the
    two cannot be compared the row says so.
    """
    rows = []
    if exam:
        rows.append({'aspect': 'Conclusion',
                     'netforensiq': f'Tier {exam.tier} of 4 — {exam.tier_label}',
                     'mobsf': ('No conclusion about malice. Security score '
                               f"{summary['score']}/100 (hardening)"
                               if summary['score'] is not None else 'No security score in the report')})
    rows.append({'aspect': 'Package read',
                 'netforensiq': (exam.package or 'not read') if exam else 'not examined here',
                 'mobsf': summary['package'] or 'not read'})
    counts = summary['appsec_counts']
    rows.append({'aspect': 'What it flagged',
                 'netforensiq': ', '.join(exam.basis_ids) if exam and exam.basis_ids else
                                ('nothing that raised a tier' if exam else '—'),
                 'mobsf': f"{counts['high']} high, {counts['warning']} warning findings"})
    rows.append({'aspect': 'Permissions and components',
                 'netforensiq': '—',
                 'mobsf': f"{summary['permission_count']} permissions "
                          f"({len(summary['dangerous_permissions'])} dangerous), "
                          f"{sum(summary['components'].values())} components"})
    return rows
