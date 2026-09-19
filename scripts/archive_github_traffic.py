#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Keep a permanent record of who is reaching the repository — in aggregate.

What GitHub can and cannot tell you
===================================
GitHub's traffic API reports, for the last 14 days only: clone counts and unique
cloners per day, page views and unique visitors per day, the top 10 referring
sites and the top 10 pages. It needs write access to the repository.

It does **not** identify anyone. No GitHub feature tells a repository owner *who*
cloned it or downloaded a ZIP, and no honest tool can — a clone is anonymous by
design. So this script does the one useful thing available: GitHub discards
traffic after 14 days, and this merges each fetch into a local archive, so the
history of how many people clone, from where they arrived, and what they read
accumulates for as long as you keep running it.

Referrers are the closest thing to "who": a spike of clones arriving from a
particular site, a course page or a forum thread shows where the project is
being passed around.

What it deliberately does not do
================================
It does not add tracking to the code. A "phone home" in NetForensiq would break
the offline guarantee a forensic tool depends on, would be removed by anyone
copying the project in a minute, and would record people who never agreed to it.
Voluntary reports go through the deployment-report issue template instead.

Usage (needs the GitHub CLI, authenticated as someone with write access):
    python scripts/archive_github_traffic.py
    python scripts/archive_github_traffic.py --repo Anbu-00001/NetForensiq --out ~/nf-traffic

Run it at least once every 14 days — a weekly cron entry is the easy way — or
the days in between are lost for good.
"""

import argparse
import datetime
import json
import os
import subprocess
import sys

ENDPOINTS = {
    'clones': 'traffic/clones',
    'views': 'traffic/views',
    'referrers': 'traffic/popular/referrers',
    'paths': 'traffic/popular/paths',
}


def gh_api(repo, endpoint):
    result = subprocess.run(['gh', 'api', f'repos/{repo}/{endpoint}'],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f'gh api {endpoint} failed')
    return json.loads(result.stdout)


def load(path, default):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(data, handle, indent=1, sort_keys=True)
        handle.write('\n')
    os.replace(tmp, path)


def merge_daily(archive, fetched, key):
    """Daily series keyed by timestamp: newer fetches overwrite the same day."""
    days = {entry['timestamp']: entry for entry in archive}
    for entry in fetched.get(key, []):
        days[entry['timestamp']] = entry
    return [days[k] for k in sorted(days)]


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', default='Anbu-00001/NetForensiq')
    parser.add_argument('--out', default=os.path.expanduser('~/.netforensiq-traffic'),
                        help='archive directory (kept outside the repository by default)')
    args = parser.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    today = datetime.date.today().isoformat()

    try:
        clones = gh_api(args.repo, ENDPOINTS['clones'])
        views = gh_api(args.repo, ENDPOINTS['views'])
        referrers = gh_api(args.repo, ENDPOINTS['referrers'])
        paths = gh_api(args.repo, ENDPOINTS['paths'])
    except (OSError, RuntimeError) as exc:
        sys.exit(f'Could not read traffic for {args.repo}: {exc}\n'
                 'Install the GitHub CLI and run `gh auth login` as an account with '
                 'write access to the repository.')

    clone_path = os.path.join(args.out, 'clones.json')
    view_path = os.path.join(args.out, 'views.json')
    save(clone_path, merge_daily(load(clone_path, []), clones, 'clones'))
    save(view_path, merge_daily(load(view_path, []), views, 'views'))

    # Referrers and paths are 14-day totals, not daily series, so each fetch is
    # kept as a dated snapshot rather than merged.
    snapshots_path = os.path.join(args.out, 'referrers_and_paths.json')
    snapshots = load(snapshots_path, {})
    snapshots[today] = {'referrers': referrers, 'paths': paths}
    save(snapshots_path, snapshots)

    all_clones = load(clone_path, [])
    total = sum(e['count'] for e in all_clones)
    print(f'{args.repo}: {len(all_clones)} day(s) archived, {total} clone(s) recorded in total.')
    print(f'Last 14 days: {clones.get("count", 0)} clone(s) by {clones.get("uniques", 0)} '
          f'unique cloner(s); {views.get("count", 0)} view(s) by {views.get("uniques", 0)}.')
    if referrers:
        print('Top referrers:', ', '.join(f'{r["referrer"]} ({r["count"]})' for r in referrers[:5]))
    print(f'Archive: {args.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
