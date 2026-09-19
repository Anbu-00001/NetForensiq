# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Apply Google Play Protect's "enhanced fraud protection" rule to a set of APKs.

The rule, as Google published it for the India pilot (Nov 2024): when an app is
installed from an Internet-sideloading source — "web browsers, messaging apps
and file managers" — and it declares any of "RECEIVE_SMS, READ_SMS,
BIND_Notifications, and Accessibility", the install is blocked.
https://blog.google/intl/en-in/products/launching-enhanced-fraud-protection-pilot-in-india/

This reproduces that rule from the manifest so it can be run on the *same*
samples NetForensiq's engine is scored on. It is the only part of what a phone
does at install time that is published precisely enough to reproduce; Play
Protect's cloud and on-device classifiers are not, and nothing here pretends
to measure them.

"Declares" is read two ways, because Google's wording names permissions and an
app can hold notification or accessibility access either way: as a
<uses-permission>, or as the permission guarding one of its own services
(which is how Android actually grants both). Each hit records which.

Run inside the analysis sandbox (see apk_corpus/analysis/run_efp.sh), because
it parses untrusted manifests:

    python -m efp_permission_check --label malicious /work/apk --label benign /benign1
"""
import argparse
import json
import os
import sys

TRIGGERS = (
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
)


def check(path):
    from androguard.core.apk import APK
    from apk_engine.identity import read_identity

    identity = read_identity(APK(path))
    requested = {p['name'] for p in identity['permissions']}
    guarded = {c['permission'] for c in identity['components'] if c.get('permission')}
    hits = []
    for name in TRIGGERS:
        if name in requested:
            hits.append(f'{name.rsplit(".", 1)[1]}(uses-permission)')
        elif name in guarded:
            hits.append(f'{name.rsplit(".", 1)[1]}(service)')
    return hits


# Each app is read in its own child with an address-space ceiling, the way the
# engine examines them: malware ships manifests built to exhaust a parser, and
# one such sample must fail alone rather than take the whole run with it.
MEMORY_MB = 1024


def _quiet():
    import logging
    logging.disable(logging.CRITICAL)
    try:
        from loguru import logger
        logger.remove()
    except ImportError:
        pass


def _limit():
    import resource
    cap = MEMORY_MB * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (cap, cap))


def main():
    import subprocess

    parser = argparse.ArgumentParser()
    parser.add_argument('--label', nargs=2, action='append', metavar=('LABEL', 'DIR'))
    parser.add_argument('--one', help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.one:
        _quiet()
        json.dump(check(args.one), sys.stdout)
        return

    rows = []
    for label, directory in args.label or []:
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            row = {'label': label, 'name': name}
            try:
                done = subprocess.run(
                    [sys.executable, '-m', 'efp_permission_check', '--one', path],
                    capture_output=True, text=True, timeout=300, preexec_fn=_limit)
                if done.returncode:
                    raise RuntimeError(f'exit {done.returncode}: {done.stderr[-200:]}')
                hits = json.loads(done.stdout)
                row.update(examined=True, blocked=bool(hits), triggers=hits)
            except Exception as exc:  # a manifest the parser cannot read in bounds
                row.update(examined=False, blocked=None, error=str(exc)[:200])
            rows.append(row)
    json.dump(rows, sys.stdout, indent=1)


if __name__ == '__main__':
    main()
