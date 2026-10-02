# 163 — A validation report that cannot drift from the data

**Question.** A forensic unit evaluating a tool is entitled to ask what it was tested on, how it
did, where it failed and what was not tested. Until now those answers were spread across
research notes written as the work went. Can they be one document — and can that document be
made unable to disagree with the data it summarises?

## The shape

`validation/VALIDATION_REPORT.md`, arranged after what the UK Forensic Science Regulator's
*Method Validation in Digital Forensics* (FSR-G-218, Issue 2) asks of a validation record:
each requirement with its finding, failures explicitly highlighted, limitations of the testing
and of the method detailed, test data described including how little control there was over it.
The quotations in the report were read from that document (extracted from the PDF text; section
numbers 1.1.9, 1.1.10, 3.3.1, 6.3.10, 7.2.1, 7.6.4).

**One thing the research summary got wrong, and the reading corrected.** A research agent
summarised the guidance as "tools must have limits and error rates determined". What it says
(footnote 3) is that tools "designed to be used by non-practitioners require validation for that
purpose, including to determine the limits of operation and error rates". NetForensiq is for
practitioners, so the sentence does not describe it, and the report does not cite it. What does
apply is s.1.1.10: the onus of validation is the using unit's, and the developer "may greatly
assist the end user by providing information on the testing that has already been performed".
The report presents itself as exactly that, and as nothing more.

## How it cannot drift

* The report is rendered from `validation/results.json` by a script. A test regenerates it and
  requires the committed file to match.
* `results.json` is derived from run logs and corpus manifests by another script; where the
  engine's own log carries a tally the derived counts must equal it.
* `apk_samples.csv` must agree with the summary derived from it, tier by tier.
* The README's headline figures must appear in the report.
* The report names the SHA-256 of the shipped baseline table and the network rate table. Change
  either without re-deriving the data and a test fails (change control).

Each was checked by breaking it: editing a figure in the report, changing one sample's tier in
the CSV, and altering the rate table, and confirming the right test failed.

## What deriving it from the logs found

* **The README's false-positive bound used the wrong denominator.** It said "0 / 100, bound
  3.0%". Eleven of the 100 apps could not be examined, and an app that could not be examined is
  not a clean result. Zero of 89 examined gives a bound of 3.3%. The count was right; the
  denominator and bound were not. Corrected in the README, with a dated note on research/154.
* **Two unseen sets were scored by two engine images.** The held-out set's 64/100 came from the
  v5 image, the blind set's 52/100 from the shipped v6 image. The held-out set was re-run on the
  shipped image (nothing was tuned; it is a re-measurement): **64/100 again, and all 100
  per-sample verdicts identical**, as were all 100 fresh legitimate apps. So the native-code
  survey added in v6, which no rule uses, changed no tier on any of 200 samples. The report now
  states one configuration for both unseen sets.
* **An explanation I had stated as fact was a hypothesis.** The README and research/158 said the
  blind set scored lower because newer samples use the engine's strongest packaging trick less.
  What was measured is that tier 2 fell from 45 to 25. Why was never tested. Both now say so.
* **The pre-registered native-signal prediction was false by a wide margin.** Of 16 native
  signals, 2 fired on no legitimate app, and the better of those fired on 1 of 197 malicious
  samples. Predicted at 70%: at least one on 0 of 201 benign and 20 or more of 200 malicious.

## Not done

* The network measurements ran on the working tree of 19–20 Sep before it was committed; no
  image or commit identifier was recorded. They should be repeated on a tagged build.
* No independent review. The author wrote the tool, chose the corpora and ran the tests.
* No acceptance criteria: none has been set by a forensic unit, so none is invented here.
