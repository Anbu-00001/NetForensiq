#!/usr/bin/env python
"""
Keep the numbers in the documentation true.

Why this exists
---------------
README.md said 61 backend tests, PROGRESS.md said 74, and the suite actually
had 79. Three documents, three numbers, none of them right — on a project
whose pitch is that every figure traces to something real. It is also the
cheapest claim in the repository for a reviewer to check: `manage.py test`
prints the answer in under a minute.

So the counts are measured, not remembered:

    python scripts/check_docs.py          # report drift, exit 1 if any
    python scripts/check_docs.py --fix    # rewrite the documents to match

Run from the repository root. verify.sh runs it on every phase.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / 'backend'
FRONTEND = ROOT / 'frontend'
PYTHON = BACKEND / '.venv' / 'bin' / 'python'


# ── measuring ────────────────────────────────────────────────────────────

def backend_test_count():
    """Built by Django's own discovery, so it cannot disagree with the runner."""
    script = (
        "import django, os;"
        "os.environ.setdefault('DJANGO_SETTINGS_MODULE','netforensiq_backend.settings');"
        "django.setup();"
        "from django.conf import settings;"
        "from django.test.utils import get_runner;"
        "print(get_runner(settings)().build_suite([]).countTestCases())"
    )
    out = subprocess.run(
        [str(PYTHON), '-c', script], cwd=BACKEND,
        capture_output=True, text=True,
    )
    return int(out.stdout.strip().splitlines()[-1])


def e2e_test_count():
    """Playwright's own listing, including tests generated inside loops."""
    out = subprocess.run(
        ['npx', 'playwright', 'test', '--list'], cwd=FRONTEND,
        capture_output=True, text=True,
    )
    match = re.search(r'Total:\s+(\d+)\s+tests?', out.stdout)
    if not match:
        raise RuntimeError(f'could not read the Playwright listing:\n{out.stdout[-500:]}')
    return int(match.group(1))


def engine_counts():
    script = (
        "import django, os;"
        "os.environ.setdefault('DJANGO_SETTINGS_MODULE','netforensiq_backend.settings');"
        "django.setup();"
        "from capture.detection import RULE_IDS, RULES, THRESHOLDS;"
        "print(len(RULE_IDS), len(RULES), len(THRESHOLDS))"
    )
    out = subprocess.run(
        [str(PYTHON), '-c', script], cwd=BACKEND,
        capture_output=True, text=True,
    )
    rule_ids, rule_fns, thresholds = out.stdout.strip().splitlines()[-1].split()
    return int(rule_ids), int(rule_fns), int(thresholds)


# ── the claims we police ────────────────────────────────────────────────
#
# Each entry is (regex with ONE capturing group around the number, key). The
# regex has to match how the sentence is actually written, so adding a new
# phrasing to the docs means adding it here too — which is the point: a number
# in prose that nothing checks is how the last three got out of date.

CLAIMS = [
    (r'Backend:\s+(\d+)\s+tests', 'backend_tests'),
    (r'\*\*(\d+)\s+backend tests', 'backend_tests'),
    (r'(\d+)\s+backend tests', 'backend_tests'),
    (r'Frontend:\s+(\d+)\s+Playwright', 'e2e_tests'),
    (r'\*\*(\d+)\s+Playwright E2E', 'e2e_tests'),
    (r'(\d+)\s+Playwright E2E', 'e2e_tests'),
    (r'Detection Engine<br/>(\d+)\s+rules', 'rule_ids'),
]

DOCUMENTS = ['README.md', 'PROGRESS.md']

# The detection specification has to keep up with the engine.
#
# Two rule types shipped without ever appearing in SPEC_02, and the omission
# was found by an outside reviewer rather than by us: a specification the code
# has drifted away from is worse than no specification, because it invites a
# judge to ask about a rule the document cannot explain.
SPEC = 'research/SPEC_02_DETECTION_ALGORITHMS.md'


def undocumented_rules(rule_ids):
    """Rule IDs the engine emits that the specification never mentions."""
    path = ROOT / SPEC
    if not path.exists():
        return list(rule_ids)
    text = path.read_text()
    return [rule_id for rule_id in rule_ids if rule_id not in text]


def engine_rule_ids():
    script = (
        "import django, os;"
        "os.environ.setdefault('DJANGO_SETTINGS_MODULE','netforensiq_backend.settings');"
        "django.setup();"
        "from capture.detection import RULE_IDS;"
        "print(' '.join(RULE_IDS))"
    )
    out = subprocess.run(
        [str(PYTHON), '-c', script], cwd=BACKEND,
        capture_output=True, text=True,
    )
    return out.stdout.strip().splitlines()[-1].split()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fix', action='store_true',
                        help='Rewrite the documents to match reality.')
    args = parser.parse_args()

    rule_ids, rule_fns, thresholds = engine_counts()
    actual = {
        'backend_tests': backend_test_count(),
        'e2e_tests': e2e_test_count(),
        'rule_ids': rule_ids,
        'rule_functions': rule_fns,
        'thresholds': thresholds,
    }

    print('Measured:')
    for key, value in actual.items():
        print(f'  {key:<18} {value}')
    print()

    drift = []

    missing = undocumented_rules(engine_rule_ids())
    if missing:
        drift.append(
            f'{SPEC}: no section documents ' + ', '.join(missing)
        )

    for name in DOCUMENTS:
        path = ROOT / name
        if not path.exists():
            continue
        text = path.read_text()
        updated = text

        for pattern, key in CLAIMS:
            expected = actual[key]
            for match in re.finditer(pattern, text):
                claimed = int(match.group(1))
                if claimed == expected:
                    continue
                drift.append(f'{name}: "{match.group(0)}" — actually {expected}')
                if args.fix:
                    start, end = match.span(1)
                    fixed = match.group(0)[:start - match.start()] + str(expected) \
                        + match.group(0)[end - match.start():]
                    updated = updated.replace(match.group(0), fixed)

        if args.fix and updated != text:
            path.write_text(updated)
            print(f'  rewrote {name}')

    if not drift:
        print('All documented counts match the code.')
        return 0

    print('Drift found:')
    for line in drift:
        print(f'  ✘ {line}')
    if args.fix:
        if missing:
            print(
                '\nThe specification gap is NOT auto-fixable: a rule needs a '
                'section explaining what it detects and where its thresholds '
                'come from, and only a person can write that.'
            )
            return 1
        print('\nRewritten. Re-run without --fix to confirm.')
        return 0
    print('\nRun with --fix to correct them.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
