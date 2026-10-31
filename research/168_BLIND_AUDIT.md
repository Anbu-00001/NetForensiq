# 168 — A blind audit, and what was done about it

On 31 Oct 2026 the public repository at commit `0dbdb95` was audited blind: a separate AI
agent (Claude Opus 5.5), given only a fresh clone and no notes from the author, read the code,
ran the test suite and wrote probe tests against a running copy. It is not an independent human
review, and nothing here should be read as one; the point of it was to find what the author had
stopped seeing. It scored evidence integrity 6/10, security 4, detection 4, engineering 7,
documentation honesty 7 and usefulness to a police lab 4.

Every finding was checked against the code before anything changed. Where the audit said
"verified by running", the fix came with a test that is that probe.

| # | Finding | Outcome |
|---|---|---|
| H1 | Sign-in limit bypassed by changing `X-Forwarded-For` | **Fixed.** Header ignored unless `TRUSTED_PROXY_COUNT` is set; per-account limit added |
| H2 | Custody log stored a client-supplied "IP", `|` included | **Fixed.** Validated before storing; server chain check rejects `|` outside `detail` |
| H3 | A `<` in a file name broke certificate issue part-way | **Fixed.** Every value escaped; issue and countersigning are single transactions |
| H4 | The certificate PDF changed on every download | **Fixed.** Rendered once, digest recorded, served as issued, 409 if changed |
| H5 | No per-case access control | **Open.** A policy decision, below |
| M1 | A read-only viewer's download wrote to the custody log | **Fixed.** Audit log only for viewers |
| M2 | Anonymous endpoint re-hashed whole exhibits; any I/O error set a permanent TAMPERED | **Fixed.** Three-valued check; recent result reused |
| M3 | Entries cut from the end of a custody log went unnoticed | **Fixed** inside the database; anchored outside it by certificate and package |
| M4 | Certificate printed the account name, which no hash covers | **Fixed.** Badge (hashed) leads; note says the name is not covered |
| M5 | Signing key, evidence key and database on one volume | Open. Already stated in the README |
| M6 | `HOST_CORROBORATED` cannot fire on shipped data | Open. Detection work, below |
| M7 | Network rules fire as often on ordinary traffic as on attacks | Open. Detection work, below |
| M8 | APK detection rests mainly on tier 2 | Open |
| M9 | One in ten legitimate apps cannot be examined | Open |
| M10 | APK engine runs as the web user, with access to keys and database | Open |
| M11 | Two tests fail on a clean clone | **Fixed.** Skip, naming the fetch script, when no reference capture is present |
| M12 | No field for the hash taken at the scene | Open |
| L1 | Custody append not concurrency-safe | **Fixed** with M3: appends lock the exhibit's recorded end |
| L4 | API sent the server's PDF path | **Fixed** |
| L6 | `IsAdministrator` did not require approval | **Fixed** |
| L2, L3, L5, L7–L10 | Case edits unaudited; expert route unreachable over HTTP; plaintext with the cipher magic; JWT storage; missing merge script; verifier lockfile; `cap_net_raw` | Open |

## Rate limits and the client address (H1, H2)

DRF's throttle identifies a client by `X-Forwarded-For` when `NUM_PROXIES` is unset, and
`get_client_ip` took the header's first entry. Both now take `REMOTE_ADDR` unless
`TRUSTED_PROXY_COUNT` declares that many proxies, in which case the entry that proxy appended is
used. Whatever comes out must parse as an IP address or it is stored as unknown. A second limit,
ten attempts an hour at one username from any number of addresses, closes the rotation route
the address limit cannot. It has a cost that is stated in the code and README: someone who knows
a username can lock that account out for an hour.

Tests are the audit's probes: a rotating header gets 429 on the ninth attempt; rotating real
addresses gets 429 on the eleventh; another account is unaffected; `6.6.6.6|forged` is stored as
unknown; a `|` written around the check is rejected by the server's chain check.

## The certificate document (H3, H4, M1)

ReportLab's `Paragraph` reads a small markup language, and file names, form fields and capture
text went into it unescaped. They are now escaped in the certificate, the investigation report
and the FSL forwarding letter. Issue and countersigning are transactions, so a failed render
leaves no certificate row and no custody entry.

The PDF is rendered with `invariant=1` into a temporary file that replaces the stored one only
when complete, and its SHA-256 is recorded. Downloads serve that file; one that no longer matches
is refused (HTTP 409). Tests: two downloads equal the issued bytes; a package exported later
records the same digest; the same state renders to the same bytes; an appended byte is refused.

## The seal check (M2)

`EvidenceRecord.verify()` now answers True, False or None. None, "not checked", covers a file
that cannot be read and an encrypted store with no key configured, and leaves the status alone.
A hash mismatch or a failed authentication tag still sets the sticky TAMPERED. Certification,
countersigning and the encrypt command treat None as a refusal, with their own message.

The anonymous verify page and the status strip reuse a check made within
`SEAL_CHECK_REUSE_SECONDS` (900 by default, a chosen figure, not a measured one), report when it
was made and whether this request made it, and do not read a TAMPERED exhibit at all. The cost:
a file altered since the last check is not seen by those two until the window passes. The
officer's Verify button always hashes now.

## The end of the custody log (M3, M4, L1)

A hash chain is anchored at its start. Cutting entries from its end leaves a shorter chain that
still re-derives, and the audit did that. Each exhibit now has a `CustodyHead` row (entry count
and last hash), locked and moved in the same transaction as every append; the chain check reports
a log that is shorter than recorded, longer than recorded, ends in a different hash, or has no
recorded end. The migration records the end of every existing log as it stands, so a log
shortened before the migration is recorded at its shortened length.

Someone with write access to the database can move this row too. The anchors outside it are the
head hash in every signed package, and now the full last-entry hash and entry count printed on
each Section 63 certificate. A later copy of the log that is shorter or ends differently has lost
or replaced entries, and anyone holding the certificate can see that.

The certificate's Officer column now leads with the badge, which the entry hash covers, followed
by the account name, which it does not, with a sentence saying so.

## H5, left open on purpose

Every approved account can read every case. Restricting reads to a user's `CaseAssignment` rows
is a few lines of queryset filtering, but which rule is right is not a code question: a single
cyber cell may want every officer to see every case, and a district deployment shared by several
units does not. It also changes what the demonstration data shows and needs the assignment
screens to be used in practice. It is listed here and in the README, not decided by the author
of the code alone.

## Detection (M6, M7)

Not changed in this pass. The plan is to collect new attack and ordinary captures, split them
into a development set and a held-out set before any rule is touched, rebuild the beacon rules
on published methods (RITA's timestamp score, a coefficient-of-variation test, a dominant-interval
share, and constant payload size), and re-measure. Retuning against the same 30 captures would fit
the rules to the test. The literature survey for that is in `prep/` outside the repository until
the rules are rebuilt.
