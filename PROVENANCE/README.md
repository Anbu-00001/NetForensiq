# Provenance

Proof that NetForensiq, as written by Anbuchelvan Ganesan, existed at a given time —
checkable by anyone, without trusting this repository, GitHub, or its author.

## What is here

| file | what it is |
|---|---|
| `manifest.sha256` | SHA-256 of every authored file — code, tests, research notes, documentation — one per line, sorted by path. Third-party data, captures and samples are deliberately not listed. |
| `manifest.sha256.ots` | An [OpenTimestamps](https://opentimestamps.org/) proof that `manifest.sha256` existed at the time it was stamped, anchored to the Bitcoin blockchain. |

Only the manifest's hash left the author's machine to make the proof. Nothing about
the code was sent anywhere.

## Why this settles "who wrote it first"

A repository's commit dates are whatever the committer's clock said, and a copy can
be re-committed under any name with any date. A Bitcoin-anchored timestamp cannot be
backdated: it proves the manifest — and so every file hash in it — existed no later
than the block that recorded it.

So if a copy of this code turns up elsewhere:

1. `python scripts/provenance_check.py <copy>` shows which of its files are
   NetForensiq's, including files whose licence header was removed or that were
   renamed or edited.
2. `sha256sum <file>` on any matched original gives a hash that appears in
   `manifest.sha256`.
3. The `.ots` proof shows that manifest existed at the stamped time.

## Verifying the timestamp

**Without installing anything:** open <https://opentimestamps.org/>, drop in
`manifest.sha256.ots` together with `manifest.sha256`, and the page verifies the
attestation in the browser.

**From the command line:**

```bash
pip install opentimestamps-client
ots info    PROVENANCE/manifest.sha256.ots     # what the proof commits to
ots verify  PROVENANCE/manifest.sha256.ots     # full check; needs a Bitcoin node
```

A freshly made proof is *pending*: the calendar servers have accepted the hash and
it reaches the blockchain within a few hours. `ots upgrade PROVENANCE/manifest.sha256.ots`
then replaces the pending attestation with the complete Bitcoin one, after which the
proof no longer depends on the calendar servers at all. Commit the upgraded file.

## Keeping it current

The manifest describes the code at the moment it was built. After significant work:

```bash
python scripts/provenance_manifest.py             # rebuild
ots stamp PROVENANCE/manifest.sha256              # re-stamp (hash only is sent)
```

Each stamp is an independent point in the timeline; keeping the old proofs (e.g.
under a dated name) shows the project's history of existence as well as its current
state. `python scripts/provenance_manifest.py --check` reports whether the manifest
is out of date.

## Stronger still, in India

Copyright in software arises automatically on creation under the Copyright Act, 1957,
where a computer program is a literary work. Registration with the Copyright Office
is optional, but under section 48 the Register of Copyrights is *prima facie* evidence
of the particulars entered in it — the strongest formal record available. The
manifest and timestamp here are independent evidence that supports, but does not
replace, registration.

*Not legal advice.*
