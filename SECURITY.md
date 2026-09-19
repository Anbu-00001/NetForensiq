# Security policy

NetForensiq handles evidence, network captures and live Android malware. A flaw
in it can mislead an investigation or expose the people in the data, so security
reports are taken seriously and handled privately first.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.** Use GitHub's private
reporting instead: on the repository page, open the **Security** tab and choose
**Report a vulnerability**. That reaches the maintainer without disclosing the
problem to anyone else.

Useful things to include: what is affected, how to reproduce it, and what an
attacker could achieve. A proof of concept is welcome; a live exploit against
someone else's deployment is not.

In scope, in rough order of seriousness:

- anything that lets a result be **altered without trace** — a sealed exhibit's
  hash, a finding, a custody record, a certificate;
- anything that lets a **crafted APK or capture** do more than fail to parse —
  escape the examination sandbox, write outside its working area, reach the
  network, or exhaust the host;
- anything that lets a role do what its separation of duties forbids — an
  investigator countersigning as examiner, a viewer reading communication
  content;
- anything that makes a clean result **look clean when it is not** — a way to
  force "no harmful behaviour established" on a sample the engine would
  otherwise flag.

## How malware is kept from causing harm

The APK engine reads Android malware by design. It never executes it: there is
no Android runtime, and an APK on Linux is an inert archive. What the engine is
exposed to is its parsers reading attacker-chosen bytes, so the design is built
around that:

- Samples are stored **encrypted at rest**, as MalwareBazaar's password-protected
  archives named by SHA-256. No `.apk` sample is written to the host filesystem.
- `scripts/fetch_malwarebazaar_corpus.py` **refuses to write inside a git work
  tree**, so a sample cannot be committed by accident. `.gitignore` excludes
  `*.apk`, the corpora, captures, evidence and keys as a second line.
- Samples are decrypted and examined only inside a container started with
  `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`,
  a memory cap, and a `noexec` tmpfs — see `scripts/analyse_untrusted.sh`.
- Each examination runs under `RLIMIT_AS` and `RLIMIT_CPU`, so a decompression
  bomb or a pathological DEX ends in a recorded failure rather than a hung host.

## Before publishing

`scripts/check_publish_safety.py` scans what would be published for secrets,
keys, databases, captures and samples, and exits non-zero if it finds any. Run
it before every push or release.

## Supported versions

Only the latest release receives fixes.
