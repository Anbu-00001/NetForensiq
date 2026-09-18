"""
Command line — the only interface the web process uses.

    python -m apk_engine examine --apk sample.apk [--container received.zip] [--name NAME]
        Writes one JSON report to stdout. Exit status 0 whenever a report was
        written, including tier 0; non-zero only for a usage error.

    python -m apk_engine evaluate --benign DIR [DIR ...] --malicious DIR [DIR ...]
        Measures every signal over labelled corpora and writes data/baselines.json.

    python -m apk_engine reference --from DIR [DIR ...] --authority publisher --note TEXT
        Records package name -> authorised signing key from packages known to be
        genuine, so later examinations can check what a sample claims to be.
        Run where it is deployed: a laboratory's reference set is its own.

    python -m apk_engine corpus
        Prints the corpus every signal's base rate was measured on, with the
        SHA-256 of each sample, so the measurement can be repeated and
        contradicted.
"""

import argparse
import json
import logging
import os
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

    rf = sub.add_parser('reference')
    rf.add_argument('--from', dest='sources', nargs='+', required=True,
                    help='directories or .apk files known to be genuine')
    rf.add_argument('--authority', choices=('publisher', 'distributor'), default='distributor',
                    help='publisher: this is THE authorised key (a mismatch is tier 3). '
                         'distributor: a key observed on one channel\'s build (tier 2)')
    rf.add_argument('--note', default='', help='where these packages came from, for the record')
    rf.add_argument('--out')
    rf.add_argument('--max-memory-mb', type=int, default=6144)

    sub.add_parser('corpus')

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

    if args.command == 'reference':
        _limit(resource_name='RLIMIT_AS', value=args.max_memory_mb * 1024 * 1024)
        from .reference_set import build, write
        paths = []
        for source in args.sources:
            if os.path.isdir(source):
                paths += [os.path.join(source, n) for n in sorted(os.listdir(source))
                          if n.lower().endswith('.apk')]
            else:
                paths.append(source)
        data = build(paths, authority=args.authority, note=args.note)
        written = write(data, args.out)
        print(f'{data["entry_count"]} package(s) recorded as {args.authority} -> {written}',
              file=sys.stderr)
        for failure in data['failures']:
            print(f'  skipped {failure}', file=sys.stderr)
        return 0

    if args.command == 'corpus':
        from .baselines import load
        corpus = load().get('corpus', {})
        print(f'{corpus.get("benign", 0)} legitimate, {corpus.get("malicious", 0)} malicious')
        print(corpus.get('description', ''))
        print()
        for sample in corpus.get('manifest', []):
            print(f'{sample["sha256"]}  {sample["label"]:9s}  {sample["name"]}')
        return 0

    from .evaluate import evaluate
    evaluate(args.benign, args.malicious, out=args.out, jobs=args.jobs,
             description=args.description, check=args.check,
             memory_mb=args.max_memory_mb)
    return 0


if __name__ == '__main__':
    sys.exit(main())
