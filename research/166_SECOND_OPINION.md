# 166 — Filing MobSF's report beside a sample

**Question.** The Gujarat Cyber Crime Branch contact named MobSF, and research/159 measured
what it says about this project's samples. A lab that already runs MobSF has a report in
hand when a sample reaches this tool. Can that report be filed against the sealed exhibit,
read next to this engine's conclusion, and kept in a form a court could be shown — without
turning MobSF's number into a verdict it was never meant to be?

## What was missing first: the examination was not recorded

Building the comparison exposed a gap in what already existed. An APK examination's result
was returned in the HTTP response and written as one line of the audit log. Nothing kept it
with the exhibit, so a tier could not later be shown beside anything, and nothing recorded
which baseline table had produced it.

`ApkExamination` now records, per examination: the exhibit, the tier and label, the ids of
the behaviours and integrity indicators that set it, the engine version, and the SHA-256 of the
baseline table actually in force (read from the engine's own provenance block).

It also records **the hash of the package the engine read**. For a sample that arrives
inside a ZIP — which is how MalwareBazaar, VirusShare and most advisories distribute them —
the exhibit's hash is the ZIP's, while MobSF, and every other tool, reports the inner file's.
That is the only reason a report can be matched to such an exhibit, and it is the case the
hackathon's own sample is.

## How a report is tied to an exhibit

By hash and by nothing else. The report states the SHA-256 of what it examined; it is linked
only if that equals the examined package of a recorded examination, or the sealed hash of an
APK sealed before examinations were recorded. Otherwise it is stored **unlinked**, with the
reason, and no custody entry is written anywhere. This system does not take the importer's word
that two different hashes are the same sample. Tested by filing a real report re-addressed to a
different hash, and by breaking the rule to link to the latest exhibit regardless: the test fails.

Filing is a custody event on the exhibit (`report_attached`), naming the report's hash and the
package's, and saying it is an opinion produced elsewhere. The chain still verifies.

## What it will not do

* **It does not rank the two or score their agreement.** MobSF's security score measures
  hardening. In research/159 the scores of malware and legitimate apps overlapped completely,
  and the hackathon malware scored *best* (73) because its manifest is deliberately malformed
  and MobSF read nothing from it. The comparison shows both, labels MobSF's number as a
  hardening score, and says in words that it is not comparable with a tier. The same note
  carries no digits, so it cannot go stale.
* **It does not run MobSF.** The report is another tool's output, produced elsewhere.
* **It does not hide that MobSF may have left the machine.** If the report shows MobSF
  consulted VirusTotal, the page says the sample or its hash left the machine it ran on.

## The real scenario, run end to end

Through the browser, on the isolated stack: the hackathon sample as distributed (an
AES-encrypted ZIP) was sealed and examined — **tier 3, `com.mrram.loader`**, behaviours
`install_under_network_blackout` and `install_from_quick_tunnel`. The **unedited** MobSF 4.5.4
report from research/159 was then filed. It matched through the inner package's hash
(`664e43ef…`, not the ZIP's), a custody entry was written, and the panel showed:
NetForensiq tier 3, MobSF "package: Failed", 0 permissions, 0 components, score 73/100, with
the warning that MobSF could not read the manifest. Filing it a second time was recognised and
did not create a second opinion.

## Untrusted input

A report is a large JSON document written by a program that analysed a hostile package, so
its strings can contain anything the package contained. Fields are whitelisted, lists capped
at 25 and strings at 200 characters, the true counts still reported, wrong types ignored, a
score outside 0–100 dropped, 200,000-deep nesting a refusal and not a crash, and the page
renders the text as text. A test files a report whose finding titles are `<img onerror>` and
`<script>`, and checks they come back as the literal strings.

Stored encrypted when the evidence store is (checked by reading the stored bytes), content-
addressed so the same report is one file, and re-hashing to the recorded value.

## Checked by breaking it

Six defences were removed in turn and the matching test confirmed to fail: linking by hash,
recording the inner package's hash, the custody event, the caps, the permission check (an
investigator may not file: it appends to the custody log), and encryption at rest. One of my
own assertions was too weak and was found by this: nothing tested that the stored file was
encrypted until I broke it.

## Not done

* Only MobSF 4.x was tested (4.5.4); another major version is accepted and flagged.
* Only MobSF. The model and parser are written for one tool; adding another is a new parser.
* The reports filed against an exhibit are not yet listed on the Evidence page; the API lists
  them (`GET /api/samples/second-opinion/?exhibit=<id>`).
* No browser test in the project's Playwright suite: the real scenario above was driven by
  hand because it needs the real engine and a sample, and the logic is covered by 39 backend tests.
* A report cannot be filed against a PCAP exhibit; it describes an APK.
