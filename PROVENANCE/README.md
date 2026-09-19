# Provenance

Proof that NetForensiq, as written by Anbuchelvan Ganesan, existed at a given time —
checkable by anyone, without trusting this repository, GitHub, or its author.

## What is here

```
PROVENANCE/stamps/
└── 2026-09-19T0322Z/          one directory per stamp, named by UTC time
    ├── manifest.sha256        SHA-256 of every authored file at that moment
    └── manifest.sha256.ots    OpenTimestamps proof, anchored to Bitcoin
```

Each manifest lists code, tests, research notes and documentation — one file per
line, sorted by path. Third-party data, captures and samples are deliberately not
listed. Only a manifest's hash ever left the author's machine; nothing about the
code was sent anywhere.

**Stamps are frozen.** A stamp is never rebuilt or overwritten, because an early
proof is only worth anything if it still describes the code as it was then. New work
gets a new directory beside the old ones, so `stamps/` is a timeline: the earliest
entry is the earliest proof of authorship, and each later one shows the work growing.

## Why this settles "who wrote it first"

A repository's commit dates are whatever the committer's clock said, and a copy can
be re-committed under any name with any date. A Bitcoin-anchored timestamp cannot be
backdated: it proves a manifest — and so every file hash in it — existed no later than
the block that recorded it.

So if a copy of this code turns up elsewhere:

1. `python scripts/provenance_check.py <copy>` shows which of its files are
   NetForensiq's, including files whose licence header was removed, renamed or edited.
2. `sha256sum <file>` on a matched original gives a hash that appears in a manifest.
3. That manifest's `.ots` proof shows it existed at the stamped time.

## Verifying

**Without a Bitcoin node** — checks every stamp against two independent public block
explorers, which must agree:

```bash
pip install opentimestamps-client          # for the proof format
python scripts/verify_timestamp.py
```

**In a browser** — open <https://opentimestamps.org/> and drop in a stamp's
`manifest.sha256.ots` together with its `manifest.sha256`.

**With a Bitcoin node** — `ots verify PROVENANCE/stamps/<time>/manifest.sha256.ots`.

A new stamp is *pending* for a few hours while the calendar servers wait for Bitcoin to
confirm it. `ots upgrade <file>.ots` then embeds the complete Bitcoin attestation, after
which the proof no longer depends on the calendar servers at all. Commit the upgraded file.

## Adding a stamp

```bash
python scripts/provenance_manifest.py --check      # what changed since the latest stamp
python scripts/provenance_manifest.py --snapshot   # freeze a new stamp and ots-stamp it
```

## Stronger still, in India

Copyright in software arises automatically on creation under the Copyright Act, 1957,
where a computer program is a literary work. Registration with the Copyright Office
is optional, but under section 48 the Register of Copyrights is *prima facie* evidence
of the particulars entered in it — the strongest formal record available. The
stamps here are independent evidence that supports, but does not replace, registration.

*Not legal advice.*
