# 164 — How new data crosses the air gap

**Question.** `IOC_FEED_MATCH` is the only network rule that has never fired on ordinary
traffic, which makes it the only one allowed to corroborate (research/158). It is silent
unless an operator imports a feed, and the engine's reference data goes stale. On a machine
that must not connect to anything, new data arrives on removable media. `import_ioc_feed`
recorded a SHA-256 of what it imported and checked no signature. How does a lab take an
update from a USB stick without taking it on trust?

## Design, against The Update Framework's attack list

The threats are from <https://theupdateframework.io/docs/security/>. What was done, and what
was deliberately not:

* **Arbitrary content.** An Ed25519 signature over the manifest, with a document-type prefix
  (so it cannot be replayed as a signature over a case package), strict RFC 8032. The key must
  be one the operator chose to trust, and choosing requires typing the key's fingerprint —
  from a source other than the bundle being examined.
* **Rollback.** A per-publisher sequence that must increase. The database refuses a second
  application of the same sequence even if two operators race.
* **Freeze.** An expiry, checked against the local clock.
* **Endless data.** Limits on the bundle, each item and the item count.
* **Mix-and-match.** One signed manifest names every payload by SHA-256, so payloads need no
  signature of their own, and the bundle is applied wholly or not at all (tested by pairing a
  good feed with an empty one and requiring that nothing is left behind).
* **Wrong content installed.** Two item types only, and engine files by allow-list. **The
  baseline table, the detection rules and the known-signers list cannot be updated**: they
  define what the method treats as validated and what counts as genuine, so changing them is
  re-validation (research/163), not an update. A hostile overlay containing a `baselines.json`
  is tested and ignored.
* **Not prevented, and said so:** a fast-forward by the key's holder (sequence 10^9 would
  refuse every later honest bundle), and compromise of the one key. Both are answered by
  ceasing to trust the key. No threshold signing; no key rotation protocol.

## Applying it

An operator runs a command, not a web page: accepting update content through the interface
would put a file parser behind a login on a machine whose purpose is to be hard to feed.
`--dry-run` lists every problem rather than the first. Indicator feeds go in through the
ordinary importer with their provenance and a note naming the bundle; engine data is staged
in a new directory and switched in by an atomic link rename, carrying forward files an earlier
bundle supplied.

**The engine process gets the data it was meant to.** The web process hands the overlay
directory to the engine in its environment, as it already did for baselines, and the engine
takes only the three updatable files from it. A test applies a bundle, runs the actual engine
process, and reads the SHA-256 of each reference file from the report's own provenance block:
the updated file's hash appears, and everything not updatable is what shipped.

## Checked by breaking it

Each defence was removed in turn and the matching test confirmed to fail: the file allow-list,
the rollback check (the database constraint still caught a replay, which is defence in depth),
trust, cleanup of a failed application, the overlay's file restriction, and the report naming
the file actually used.

## Not done

* No UI for applying updates, by design; the status page does not yet list applied bundles.
* No rotation or revocation list: removing a key from the trust file is the whole mechanism.
* The clock. Expiry is only as good as the operator's setting of an offline machine's clock.
* Not tested across a real removable-media transfer or under Podman.
