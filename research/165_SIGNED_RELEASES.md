# 165 — Can a laboratory tell that the file in its hand is what was published?

**Question.** The platform is carried across an air gap on removable media as a Docker
image archive. `save_airgap_images.sh` writes `SHA256SUMS`, which catches a truncated copy,
and nothing else: whoever can alter the archive can alter the sums beside it. What would let
a lab check, offline, that the archive is the author's and say what is inside it?

`scripts/make_release.py` builds, signs and verifies a release directory.

## What a release contains

* the image archive (`docker save`, gzipped with a zeroed timestamp);
* four CycloneDX 1.6 bills of materials: the image's operating-system packages, its Python
  packages, the frontend's runtime dependencies, and the verifier's;
* the offline verifier page, the validation report and its data, and the air-gap compose file;
* `release-<version>.json`: an Ed25519-signed manifest naming each of those by SHA-256, with
  the source commit, a digest of the source tree, the baseline and rate tables' hashes, and a
  `dirty` flag; and a plain `SHA256SUMS` that works with `sha256sum -c` for someone who has
  none of our tools.

Measured on 2 Oct 2026, on the image built from this working tree: 50 s end to end, a
193.6 MB archive; bills of materials of 40 Python, 92 operating-system, 172 frontend and 4
verifier components, each validated against CycloneDX's own JSON schema.

## What it does not claim — and an earlier plan that was dropped

**Reproducible builds are not claimed.** An earlier plan listed them. A Docker image built
twice is not bit-identical (timestamps, layer ordering, package metadata), and making it so
is weeks of work for a claim nobody asked for. The manifest binds *one specific archive* to
a version; it does not let anyone rebuild it, and its `not_claimed` field says so.

What *is* reproducible is the source identity. `source.tree_sha256` is a digest over every
tracked file's path and SHA-256, so two checkouts of one commit agree whatever their
timestamps or permissions; `scripts/tree_digest.py` (standard library only) recomputes it.
A test shows it ignores order, timestamps and permissions and changes with a single byte.

A build from a tree with uncommitted or untracked files is refused unless `--allow-dirty`,
and the manifest then says `dirty: true`. This very test run was dirty, so the output above
records the commit it started from and says so.

## What a signature adds, and its limit

The signed manifest lets a recipient detect any change to any artefact after signing. It
does not tell them the key belongs to the author. Anyone can sign a manifest with their own
key; the recipient must compare the key's fingerprint with one obtained another way. A test
builds a forgery under another key: it verifies, and only the fingerprint comparison exposes
it. The fingerprint therefore has to be published somewhere independent of the releases —
the README, a signed commit — and that publication is a decision for the author. **No
release has been signed with a real key yet, and none is published.**

## Checked by breaking it

Removing, in turn, the artefact comparison, the signature check, the dirty-tree detection
and the content hashing in the tree digest each makes a specific test fail. The verifier was
also run on a real release directory: flipping one byte of a bill of materials fails it, a
wrong fingerprint fails it, the right one passes, and `sha256sum -c SHA256SUMS` agrees.

## Found on the way

* The bill of materials for the image's operating-system packages is built directly from
  `dpkg-query` output rather than by a tool, because the data is already structured and a
  scanner would add a dependency. It is checked against the schema like the others. It lists
  what is installed; it says nothing about which listed packages have known vulnerabilities.
* `libcap2-bin` is correctly absent from the list: the Dockerfile installs it to set the
  capture capability and purges it in the same layer.

## Not done

* No real signing key exists and nothing is published, by design: that is the author's act.
* Container-image signing in a registry (cosign) is not used; there is no registry, and the
  distribution path is a file. Cosign's offline verification could be added if one appears.
* The bills of materials are not compared with vulnerability databases.
* Verified on one machine and one Docker image store.
