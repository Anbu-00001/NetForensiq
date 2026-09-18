"""
Command line — the only interface the web process uses.

    python -m apk_engine examine --apk sample.apk [--container received.zip] [--name NAME]
        Writes one JSON report to stdout. Exit status 0 whenever a report was
        written, including tier 0; non-zero only for a usage error.

    python -m apk_engine evaluate --benign DIR [DIR ...] --malicious DIR [DIR ...]
        Measures every signal over labelled corpora and writes data/baselines.json.
"""

import argparse
import json
import logging
import sys


def _limit(resource_name, value, always=False):
    if not value and not always:
        return
    try:
        import resource
        limit = getattr(resource, resource_name)
        resource.setrlimit(limit, (value, value))
    except (ImportError, ValueError, OSError):
        # Not every platform exposes every limit; the caller's timeout still applies.
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(prog='apk_engine')
    sub = parser.add_subparsers(dest='command', required=True)

    ex = sub.add_parser('examine')
    ex.add_argument('--apk', required=True)
    ex.add_argument('--container')
    ex.add_argument('--name', default='')
    ex.add_argument('--max-memory-mb', type=int, default=0)
    ex.add_argument('--max-cpu-seconds', type=int, default=0)

    ev = sub.add_parser('evaluate')
    ev.add_argument('--benign', nargs='+', default=[])
    ev.add_argument('--malicious', nargs='+', default=[])
    ev.add_argument('--out')
    ev.add_argument('--jobs', type=int, default=1,
                    help='parallel samples; each can need several GB of memory')
    ev.add_argument('--max-memory-mb', type=int, default=6144)
    ev.add_argument('--description', default='')
    ev.add_argument('--check', action='store_true',
                    help='held-out test: report tiers under current baselines, write nothing')

    args = parser.parse_args(argv)
    # apkInspector logs every tampered entry at DEBUG through the root logger.
    # The report already carries those facts; stderr is for failures.
    logging.disable(logging.INFO)

    if args.command == 'examine':
        # Limits are set here, by the process on itself, before the sample is
        # opened — rather than by the parent through preexec_fn, which Python
        # documents as unsafe when the parent has threads (Django's development
        # server does). Soft and hard limits are equal, so code running later
        # in this process cannot raise them.
        _limit(resource_name='RLIMIT_AS', value=args.max_memory_mb * 1024 * 1024)
        _limit(resource_name='RLIMIT_CPU', value=args.max_cpu_seconds)
        _limit(resource_name='RLIMIT_CORE', value=0, always=True)
        from .report import unexaminable
        try:
            from .engine import examine
            report = examine(args.apk, args.container, args.name)
        except Exception as exc:        # a report is always written
            report = unexaminable(f'The examination failed: {type(exc).__name__}: {exc}')
        json.dump(report, sys.stdout, default=str)
        sys.stdout.write('\n')
        return 0

    from .evaluate import evaluate
    evaluate(args.benign, args.malicious, out=args.out, jobs=args.jobs,
             description=args.description, check=args.check,
             memory_mb=args.max_memory_mb)
    return 0


if __name__ == '__main__':
    sys.exit(main())
