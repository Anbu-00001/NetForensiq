#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Run MobSF over the same APKs NetForensiq's engine was scored on.

MobSF (Mobile Security Framework) is the standard open-source Android static
analyser. It does NOT answer "is this malware" — it produces findings and a
0-100 "security score", which is a code-quality and hardening measure. So the
comparison this makes is deliberately narrow and is the only honest one:

  * what MobSF says about samples this engine flagged,
  * what it says about the ones this engine missed,
  * and whether its score separates malware from legitimate apps at all.

Talks to MobSF's REST API (upload -> scan -> report_json), which is what
anyone automating it would use:
https://mobsf.github.io/docs/#/rest_api

    ./mobsf_compare.py --samples /home/anbu/26_class/mal/mobsf_samples \
                       --out mobsf/ --key "$MOBSF_API_KEY"
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import uuid

BASE = 'http://127.0.0.1:8081/api/v1'


def _post(path, key, fields=None, files=None, timeout=1800):
    """Multipart or form POST, without pulling in `requests`."""
    boundary = uuid.uuid4().hex
    body = b''
    for name, value in (fields or {}).items():
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"'
                 f'\r\n\r\n{value}\r\n').encode()
    for name, (filename, payload) in (files or {}).items():
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}";'
                 f' filename="{filename}"\r\n'
                 f'Content-Type: application/octet-stream\r\n\r\n').encode()
        body += payload + b'\r\n'
    body += f'--{boundary}--\r\n'.encode()

    request = urllib.request.Request(
        f'{BASE}{path}', data=body, method='POST',
        headers={'Authorization': key,
                 'Content-Type': f'multipart/form-data; boundary={boundary}'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b'{}')


def scan(path, key):
    with open(path, 'rb') as handle:
        uploaded = _post('/upload', key, files={'file': (os.path.basename(path), handle.read())})
    if 'hash' not in uploaded:
        raise RuntimeError(f'upload failed: {uploaded}')
    _post('/scan', key, fields={'hash': uploaded['hash'],
                                'scan_type': uploaded.get('scan_type', 'apk'),
                                'file_name': uploaded['file_name']})
    return _post('/report_json', key, fields={'hash': uploaded['hash']})


def summarise(report):
    """The handful of fields worth comparing, out of a very large report."""
    appsec = report.get('appsec') or {}
    counts = {level: len(appsec.get(level) or [])
              for level in ('high', 'warning', 'info', 'secure', 'hotspot')}
    findings = report.get('code_analysis', {}).get('findings') or {}
    by_severity = {}
    for detail in findings.values():
        severity = (detail.get('metadata') or {}).get('severity', 'unknown')
        by_severity[severity] = by_severity.get(severity, 0) + 1
    permissions = report.get('permissions') or {}
    return {
        'package': report.get('package_name'),
        'security_score': appsec.get('security_score'),
        'appsec_counts': counts,
        'appsec_high': [item.get('title') for item in (appsec.get('high') or [])],
        'code_findings_by_severity': by_severity,
        'dangerous_permissions': sorted(
            name for name, detail in permissions.items()
            if detail.get('status') == 'dangerous'),
        'trackers': (report.get('trackers') or {}).get('detected_trackers'),
        'certificate_summary': (report.get('certificate_analysis') or {}).get('certificate_summary'),
        'behaviour_rules': len(report.get('behaviour') or {}),
        'apkid': report.get('apkid'),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--samples', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--key', default=os.environ.get('MOBSF_API_KEY'))
    args = parser.parse_args()
    if not args.key:
        sys.exit('set MOBSF_API_KEY or pass --key')

    os.makedirs(os.path.join(args.out, 'reports'), exist_ok=True)
    rows = {}
    names = sorted(f for f in os.listdir(args.samples) if f.endswith('.apk'))
    for i, name in enumerate(names, 1):
        path = os.path.join(args.samples, name)
        started = time.time()
        print(f'[{i}/{len(names)}] {name} ({os.path.getsize(path) // 1024} KB)', flush=True)
        try:
            report = scan(path, args.key)
            with open(os.path.join(args.out, 'reports', f'{name}.json'), 'w') as handle:
                json.dump(report, handle, indent=1)
            rows[name] = {**summarise(report), 'seconds': round(time.time() - started, 1)}
            print(f'    score {rows[name]["security_score"]} · '
                  f'high {rows[name]["appsec_counts"]["high"]} · '
                  f'{rows[name]["seconds"]}s', flush=True)
        except Exception as exc:                                    # noqa: BLE001
            rows[name] = {'error': f'{type(exc).__name__}: {str(exc)[:300]}',
                          'seconds': round(time.time() - started, 1)}
            print(f'    FAILED {rows[name]["error"]}', flush=True)

    with open(os.path.join(args.out, 'summary.json'), 'w') as handle:
        json.dump(rows, handle, indent=1, sort_keys=True)
    print(f'\nwrote {os.path.join(args.out, "summary.json")}')


if __name__ == '__main__':
    main()
