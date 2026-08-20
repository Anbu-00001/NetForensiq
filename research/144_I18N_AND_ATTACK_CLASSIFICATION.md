# 144 — Multilingual reports and MITRE ATT&CK classification, verified

**Date:** 2026-08-20
**Method:** Read the code (`frontend/src/i18n/gujarati.js`, `backend/evidence/certificate_pdf.py`,
`backend/evidence/investigation_report.py`, `backend/capture/attack_mapping.py`,
`backend/capture/scenario.py`) and the prior research (`research/99_GUJARAT_FIT.md`,
`research/120_OBJECTIVES_COMPLIANCE.md`) first. Then fetched primary sources (library docs,
attack.mitre.org technique pages, GitHub repos, statute PDFs) directly. Where a claim could be
tested rather than only read about, it was tested: **Part A's central finding is an empirical
result from actually running reportlab 4.4.4 against the Gujarati font already installed on this
machine, not a reading of documentation.** Every claim below is marked VERIFIED (with source) or
UNVERIFIED. Nothing is invented.

---

## Part A — Gujarati / multilingual reports

### A0. Headline finding — the project's own prior rejection needs revising

`research/99_GUJARAT_FIT.md` records, correctly, that ReportLab's **default** text rendering
mangles Gujarati — placing the િ matra after its consonant instead of before it, and failing to
form conjuncts like ત્ર and દ્દ. That test is accurate for what it tested. But `backend/requirements.txt`
already pins **reportlab==4.4.4**, which is *newer* than reportlab 4.4.0 (April 2025), the release
that added an opt-in HarfBuzz shaping path via the optional `uharfbuzz` dependency. That path was
not exercised in the original test — `uharfbuzz` was never installed, and reportlab's `shaping`
style attribute defaults to off. **VERIFIED by direct experiment, not by reading about it:**

```
$ python3 -c "import reportlab; print(reportlab.Version)"
4.4.4
$ pip install uharfbuzz          # 1.9 MB manylinux wheel, prebuilt, no compiler needed
$ fc-list | grep -i gujarati
/usr/share/fonts/truetype/noto/NotoSansGujarati-Regular.ttf: Noto Sans Gujarati:style=Regular
```

Rendering the exact four words `research/99_GUJARAT_FIT.md` recorded as mangled, through
`reportlab.platypus.Paragraph` with `ParagraphStyle(fontName='NotoGuj', shaping=1)` and the font
registered as `TTFont('NotoGuj', path, shapable=True)` (the default), against the **same** font
(`NotoSansGujarati-Regular.ttf`) and the **same** reportlab version already pinned in this repo:

| Word | Intended | `shaping=0` (today's behaviour, matches the documented bug) | `shaping=1` (harfbuzz path) |
|---|---|---|---|
| અધિનિયમ (Act) | અધિનિયમ | અધનિયિમ — matra after, not before | **અધિનિયમ — correct** |
| સ્થળ (place) | સ્થળ | સ્થળ (already fine either way) | સ્થળ — correct |
| પ્રમાણપત્ર (certificate) | પ્રમાણપત્ર | પ...ત્ર conjunct does not form | **પ્રમાણપત્ર — conjunct forms correctly** |
| મુદ્દામાલ (exhibit) | મુદ્દામાલ | દ્દ conjunct does not form | **મુદ્દામાલ — conjunct forms correctly** |

Screenshots of the actual PDF output (rasterised with `pdftoppm`, both blocks on one page for direct
comparison) confirm this visually — the `shaping=0` block reproduces the exact mangling documented
in `99_GUJARAT_FIT.md`; the `shaping=1` block, same font, same words, same reportlab install, is
correct: the matra moves before its consonant and both conjuncts ligate into single glyphs. A
lower-level check with raw `uharfbuzz` confirms *why*: HarfBuzz's Indic shaper collapses
સ્થ → 1 glyph and ત્ર/દ્દ → 1 glyph each (cluster analysis on the shaped buffer), and reorders the
i-matra's glyph before its base consonant's glyph in the output order — which is the actual
mechanism Gujarati requires and codepoint-order rendering cannot do.

**One real limitation found, also empirically, not documented anywhere else:** shaping is gated on
the **paragraph's own base font**, not on whichever font an inline run happens to use. reportlab's
source (`platypus/paragraph.py`) computes `shaping = style.shaping and getFont(style.fontName).shapable`
— `style.fontName` is the paragraph's *primary* font. A bilingual paragraph built like
`Paragraph('Certificate (<font name="NotoGuj">પ્રમાણપત્ર</font>)', style)` where `style.fontName` is
`Helvetica` (not shapable — that flag only exists on `TTFont`) does **not** shape the embedded
Gujarati run, even with `shaping=1` set and even though the inline `<font>` tag switches to the
Gujarati font for that span — confirmed by the same experiment, run a third way. The practical fix
is structural, not a config flag: **put English and Gujarati in separate `Paragraph` flowables (or
separate table cells)**, each with its own `fontName` and its own `shaping` setting, rather than
mixing scripts inside one `Paragraph` string. This actually matches how `certificate_pdf.py` already
lays out the Schedule form — label cells and value cells are already separate flowables in a
`Table` — so the fix is additive, not a rewrite.

### A1. The four PDF paths compared

| Path | Shapes Gujarati? | Package / version | Offline? | Verdict |
|---|---|---|---|---|
| **ReportLab (current) + `uharfbuzz`** | **Yes — empirically verified above** | reportlab==4.4.4 (already pinned), `uharfbuzz` 0.56.0 (Apache-2.0, prebuilt manylinux wheel, ~1.9 MB) | Yes — wheel has no runtime network dependency; shaping is a local library call over a local font file | **Recommended.** No library swap, no rewrite of `certificate_pdf.py`'s document model — add one dependency, register fonts `shapable=True` (already the default), set `shaping=1` on Gujarati-only paragraph/cell styles, keep English and Gujarati in separate flowables. |
| **WeasyPrint (Pango/HarfBuzz)** | Yes — Pango ≥1.44 uses HarfBuzz internally for shaping, and HarfBuzz's Indic shaper explicitly lists Gujarati among the scripts it handles (`harfbuzz.github.io/opentype-shaping-models.html`, VERIFIED). Current release is WeasyPrint 68/69 (2026), VERIFIED (`doc.courtbouillon.org/weasyprint/stable/`). | System packages: `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0` (Debian/Ubuntu, VERIFIED from install docs) plus the `weasyprint` PyPI package | Yes for rendering (all shaping happens locally against installed fonts); WeasyPrint *can* fetch `@font-face`/image URLs over the network if the HTML references them, but nothing requires that — an air-gapped container with local fonts and no remote references works | **Real alternative, not chosen because it is a bigger lift.** `certificate_pdf.py` is built entirely on `reportlab.platypus` (`BaseDocTemplate`, `Frame`, `Table`, `Flowable`) — moving to WeasyPrint means rewriting the whole document as HTML/CSS, a much larger change than adding one dependency to the pipeline already in place. Worth it only if reportlab's shaping path (A0) turns out to be too fragile in wider testing. |
| **fpdf2 + `uharfbuzz`** | Yes — fpdf2 added `set_text_shaping()` via `uharfbuzz` in **version 2.7.5** (VERIFIED, `py-pdf.github.io/fpdf2/TextShaping.html`), and documents Indic scripts (Bengali, Devanagari, **Gujarati**, Gurmukhi, Kannada, Malayalam, Oriya, Tamil, Telugu) as covered by HarfBuzz's Indic shaping model | `fpdf2`, `pip install uharfbuzz` | Yes, same reasoning as above | Technically equivalent to the ReportLab path since both go through the same `uharfbuzz`/HarfBuzz engine. Not recommended **only** because it means abandoning the reportlab document model already built and tested (647 lines in `certificate_pdf.py` alone) for no shaping-quality gain. |
| **Render to SVG/PNG via HarfBuzz, embed as image** | Yes, trivially — you're not relying on any PDF library's text layer at all | HarfBuzz + a rasteriser (e.g. `cairo`, `Pillow`+`freetype`) | Yes | **Not recommended for a statutory form.** The Gujarati text becomes a raster image inside a legal PDF — not selectable, not searchable, and looks materially different from the English text around it (font smoothing, DPI artefacts, no text layer for accessibility tools). Falls back to exactly the "handled carelessly" impression `99_GUJARAT_FIT.md` was right to worry about. Only reach for this as a last resort if the shaping paths above somehow fail wider testing. |

**Bottom line for Part A, technical:** the fix is `pip install uharfbuzz` (already-compatible with the
already-pinned reportlab==4.4.4), not a rewrite. This should be prototyped against the *actual*
certificate layout (not just isolated words) before being called done — four words shaping correctly
is strong evidence, not a full-form guarantee; test the whole Schedule text, table cells with mixed
alignment, and page-break behaviour with the harfbuzz path enabled.

### A2. Which Gujarati font is licensed for redistribution

| Font | Licence | Redistribution | Source |
|---|---|---|---|
| **Noto Sans Gujarati** (Google) | **SIL Open Font License 1.1** — confirmed by fetching the font repo's own `OFL.txt`: *"This Font Software is licensed under the SIL Open Font License, Version 1.1."* | Yes — OFL explicitly permits bundling, embedding and redistribution; the only restriction is not selling the font *by itself* under the reserved name | VERIFIED, `github.com/notofonts/gujarati` (repo contains `OFL.txt`); latest tagged release `NotoSansGujarati-v2.106` (26 Oct 2024). Also obtainable from Google Fonts (`fonts.google.com/noto/specimen/Noto+Sans+Gujarati`), same OFL-1.1 licence. This exact font file is already installed on this machine at `/usr/share/fonts/truetype/noto/NotoSansGujarati-Regular.ttf` and is what the empirical test in A0 used. |
| **Lohit Gujarati** (Red Hat / Fedora, `pagure.io/lohit`) | **SIL Open Font License 1.1** since 2011 (originally GPL, relicensed to OFL after community consultation) | Yes, same OFL terms | VERIFIED via search of the Lohit fonts project and Gentoo/Fedora packaging metadata; also present on this machine (`fonts-lohit-gujr` package, referenced in `/snap/.../66-lohit-gujarati.conf`). A viable second choice, not needed — Noto already covers this and is the more actively maintained, more complete family (regular through black weights, plus a serif companion). |
| **Shruti** (Microsoft) | **Proprietary, Microsoft EULA** — bundled with Windows, licensed for on-device display use only | **No.** The EULA explicitly prohibits redistribution, embedding for editing, or bundling outside the scope of the Windows product licence; commercial redistribution requires direct permission from Microsoft | VERIFIED via Microsoft's own Typography font-list page and multiple font-vendor licence pages describing it as proprietary/non-redistributable. **Do not ship this font in the Docker image or the repo.** |

**Recommendation:** ship `NotoSansGujarati-Regular.ttf` (and `-Bold.ttf` for headings/labels) as a
vendored asset under `backend/evidence/fonts/`, with the `OFL.txt` licence text alongside it — this
is exactly the licence-plus-font pairing OFL requires and is what the project already has installed
system-wide for testing.

### A3. Is Gujarati even the right language for this document — verified against actual law

This is the most important finding in Part A, and it argues for **translating less, not more.**

- **Constitution, Art. 348**: proceedings of every High Court are in English unless Parliament
  provides otherwise; a Governor may, with the President's prior consent, authorise Hindi or a
  state's other official language for a High Court's proceedings — but **judgments, decrees and
  orders of that High Court must still be in English.** VERIFIED (Constitution text, corroborated by
  the Gujarat High Court's own January 2022 ruling that "the language of the Court is English" and
  a litigant cannot insist on addressing the Bench in Gujarati — *Contempt Petition*, Div. Bench,
  CJ Aravind Kumar & Ashutosh J. Shastri, reported by LiveLaw, `livelaw.in/amp/news-updates/high-courts-language-is-english-party-cant-insist-on-speaking-another-language-gujarat-hc-189090`). **So: whatever this tool produces for the Gujarat High Court must stay English — that part of the pipeline is already correctly English-only and should remain so.**
- **The Gujarat Official Languages Act, 1960, s.3** (VERIFIED, `indiacode.nic.in/bitstream/123456789/4501/1/officiallanguages.pdf`, cross-checked via `latestlaws.com`): *"Hindi in Devnagari script and Gujarati shall be the languages to be used for all official purposes of the State of Gujarat except such purposes as the State Government may, from time to time by notification in the Official Gazette, specify."* This is the operative provision for **subordinate courts and police work** — investigation records, FIRs, and the language a Gujarati-medium magistrate below the High Court actually reads in. It names **two** languages, Hindi and Gujarati, not Gujarati alone, and it is a default with a carved-out exception for English by state notification (the practical position for cybercrime — English is common in fact for technical evidence, per this project's own `research/95_ESAKSHYA_VERIFIED_FINDINGS.md` and `112_POLICE_WORKFLOW_NEEDS.md`, not independently re-verified this pass).
- **BNSS 2023, s.530** — "Trial and proceedings to be held in electronic mode" (VERIFIED,
  `drishtijudiciary.com`, `latestlaws.com`): permits trials, inquiries, summons/warrant service,
  examination of witnesses, recording of evidence, and appellate proceedings to be conducted "by use
  of electronic communication or use of audio-video electronic means." It is silent on *language* —
  it authorises the electronic *mode*, not a translation requirement. **s.530 does not create a
  Gujarati-language obligation; it is not the right hook for this feature at all.** (This closes out
  the prompt's specific question — s.530 was worth checking and it turns out to be orthogonal.)
- **No Gujarat High Court rule specifically mandating Gujarati-language police software or reports
  was found** — consistent with the prior pass's finding in `99_GUJARAT_FIT.md` ("No such mandate
  located... across two passes"), re-confirmed this pass with no new contradicting result.
- **Charge sheets**: BNSS s.193 (formerly CrPC s.173) governs the police report/charge sheet filed
  with a Magistrate; s.193(3) explicitly permits filing "through electronic communication" (VERIFIED,
  multiple secondary summaries of the bare section — the section text itself was not independently
  refetched this pass, mark this **UNVERIFIED at the primary-source level** though widely and
  consistently reported). **No primary source was found stating the specific language Ahmedabad's
  cyber-crime charge sheets are actually filed in** (Gujarati vs. English vs. Hindi) — searches
  surfaced only the general s.3 Official Languages Act default above, not a documented practice for
  this specific district or offence type. **State this as a gap, not a fact**: the honest claim is
  "Gujarat's default official language for subordinate-court and police work is Gujarati/Hindi under
  the 1960 Act, with no confirmed exception found for cybercrime charge sheets" — not "Ahmedabad
  charge sheets are filed in Gujarati," which was not independently confirmed this pass.

**What this means for the product**: the two documents this platform actually produces —
(1) the **BSA 2023 §63(4)(c) certificate**, destined for a court record, and (2) the **investigation
report**, destined for an investigating officer and eventually a charge sheet — sit on two different
sides of the Art. 348 line. The certificate is closer to the High-Court-adjacent, English-mandatory
end (it is a form a magistrate applies a statutory test to, and *Kshitijbhai Manubhai Patel v.
Dilipbhai Laxmanbhai Kanani*, already verified in `99_GUJARAT_FIT.md`, treats the certificate as a
strict, form-bound "condition precedent" — not a place to improvise translation). The investigation
report is closer to the s.3-default end (internal to the investigating agency, read by an officer,
feeding into charge-sheet material more directly).

### A4. What to translate and what NOT to — with the legal reasoning

- **No official Gujarati text of THE SCHEDULE to the BSA 2023 was found.** The search surfaced only
  (a) India Code's own translated-BSA page explicitly marked **"Draft stage of the translated
  version"** (`indiacode.nic.in/handle/123456789/21070`, VERIFIED as a page that exists and is
  labelled draft) and (b) commercial diglot editions from private law publishers (e.g. Punahal's
  English–Gujarati BSA-2023 edition on Amazon) — **not** a Gazette-notified, legally authoritative
  Gujarati Schedule. **This is decisive**: translating a statutory form yourself, when the
  government's own translation is still in draft and unpublished, means putting words into a court
  document that are not the words Parliament (or the Gujarat government under the Official Languages
  Act) actually enacted. If the translation is imprecise in a way that changes a declarant's legal
  undertaking — and Indic legal translation, done badly, absolutely can (an incorrect particle can
  flip a conditional) — the certificate stops being an accurate rendering of the Schedule and starts
  being this project's own paraphrase wearing the Schedule's authority. **Continue to keep the
  §63(4)(c) certificate English-only**, verbatim from `indiacode.nic.in`'s bare Act as it already is
  (`certificate_pdf.py`'s own docstring says as much) — this is not a limitation to apologise for, it
  is the legally correct choice given no authoritative Gujarati Schedule exists yet.
- **Do translate**: UI chrome, navigation, and the glossary of terms a Gujarati-medium officer would
  scan for — exactly what `frontend/src/i18n/gujarati.js` already does, and exactly the reasoning
  its own docstring gives (the browser shapes the script correctly; the glossary is explicitly *not*
  a translation of the interface, just the handful of load-bearing terms). This is the right scope
  and should stay as-is.
- **New, now realistic given A0/A1**: the **investigation report** (`investigation_report.py`) is
  this project's own document, not a reproduction of a statutory form — there is no "Schedule" to get
  wrong. Adding a **bilingual heading/section-label layer** (English authoritative, Gujarati gloss
  beside it, using the same `GUJARATI` glossary already maintained for the frontend, reusing the
  now-working shaping path from A0/A1) is low-risk: it is UI-style labelling, not a legal
  undertaking, and the existing glossary already carries the exact terms Gujarat Police's own
  case-property registers use (e.g. `મુદ્દામાલ` for "exhibit" — the docstring in `gujarati.js` already
  makes this claim; not independently re-verified against a specific register this pass). **Do not**
  translate the report's *findings prose* (the sentences a rule or the anomaly detector generated) —
  those are analytical claims an examiner may be cross-examined on, and machine-translating them
  introduces exactly the same "did the tool say what we think it said" risk as the Schedule question,
  for a benefit (readability) the glossary already delivers more safely.
- **Certificate**: stays English-only. State the reason on the certificate's own generation code (as
  it already does) **and update it** — the reason is no longer purely "the renderer can't shape
  Gujarati" (A0 shows it now can); the operative reason going forward is **legal**: no authoritative
  Gujarati Schedule text exists to translate from, and the certificate is a statutory form where
  wording precision is the entire point.

### A5. Honest risks

- The A0 test covered four words and one short bilingual phrase, not the full Schedule's ~600 words
  across justified paragraphs, tables, and page breaks. Line-breaking, justification and hyphenation
  with a shaped Indic font are known trouble spots for text layout engines generally; this needs a
  full-document pass before shipping, not just a word-level proof of concept.
  Effort: **half a day**, not the "real work" `99_GUJARAT_FIT.md` estimated for a from-scratch
  HarfBuzz integration — most of that estimate assumed writing the shim; it already exists in the
  pinned reportlab version.
- ReportLab's own team calls this feature **"experimental"** and states outright they "don't promise
  we're rendering these languages correctly," targeting full confidence at a future 5.0 (VERIFIED,
  `reportlab.substack.com/p/reportlab-440-arabic-accessible-tables`). Treat A0's clean result as
  strong evidence for these specific words/this specific font, not a vendor guarantee for every
  Gujarati string the codebase might ever produce.
- The mixed-fragment limitation in A0 is a real trap: anyone who later writes
  `Paragraph("Field (<font name='NotoGuj'>ગુજરાતી</font>)", default_style)` without knowing this will
  silently get unshaped, mangled output with no error. **Worth a one-line comment in the code, and
  ideally a lint/test that renders every Gujarati-containing template and OCRs or glyph-inspects
  the output**, rather than trusting future edits to remember the constraint.
- No authoritative Gujarati BSA Schedule exists *today*, but India Code's own listing shows one is
  in progress ("draft stage"). If a Gazette-notified Gujarati Schedule appears later, that changes
  A4's certificate recommendation — this should be re-checked before the next release, not assumed
  permanent.
- The Doshi ruling and the Art. 348 material above are reused from `research/99_GUJARAT_FIT.md`
  (already verified there) rather than re-verified from scratch this pass — flagged here for
  transparency, not re-fetched.

---

## Part B — Attack classification (MITRE ATT&CK), strengthened

### B1. Current ATT&CK version, and every technique ID this project uses, checked live

**Current live version: ATT&CK v19.2, released 28 April 2026** (VERIFIED, `attack.mitre.org/resources/versions/`).
Version history confirmed: v16.1 (31 Oct 2024) → v17.1 (22 Apr 2025) → v18.1 (28 Oct 2025) → v19.2
(28 Apr 2026, current). `scenario.py`'s own comment citing "v17 matrix ordering" for its 14-tactic
list is now two major versions behind the current release name, though — importantly — **the tactic
list itself has not changed** (Enterprise ATT&CK has held at 14 tactics through v17, v18 and v19;
VERIFIED via the v18 statistics summary and cross-checked against each technique page's tactic field
below, all of which report tactics already in `scenario.py`'s `TACTIC_ORDER`/`TACTIC_NAMES`). Every
technique page was fetched directly from `attack.mitre.org` (not a mirror or a summary) on 2026-08-20:

| ID in our code | Name (as coded) | Current name (attack.mitre.org) | Tactic (as coded) | Tactic (verified) | Status |
|---|---|---|---|---|---|
| T1071 | Application Layer Protocol | Application Layer Protocol | Command and Control | Command and Control (TA0011) | **Current.** Last modified 24 Oct 2025 (v2.4). Has 5 sub-techniques including .004 (DNS) and .005 (Publish/Subscribe, newer than our code's comment set). |
| T1071.004 | Application Layer Protocol: DNS | Application Layer Protocol: DNS | Command and Control | Command and Control (TA0011) | **Current.** Now documented with Detection Strategy **DET0400** and 5 named analytics (AN1121–AN1125) — see B3. |
| T1572 | Protocol Tunneling | Protocol Tunneling | Command and Control | Command and Control (TA0011) | **Current.** Last modified 12 May 2026. |
| T1095 | Non-Application Layer Protocol | Non-Application Layer Protocol | Command and Control | Command and Control (TA0011) | **Current.** ICMP named explicitly on the technique's own page, confirming the code comment's claim. |
| T1571 | Non-Standard Port | Non-Standard Port | Command and Control | Command and Control (TA0011) | **Current.** No sub-techniques. |
| T1046 | Network Service Discovery | Network Service Discovery | Discovery | Discovery (TA0007) | **Current.** v3.2, last modified 12 May 2026. |
| T1595.001 | Active Scanning: Scanning IP Blocks | Scanning IP Blocks | Reconnaissance | Reconnaissance (TA0043) | **Current.** |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration Over Alternative Protocol | Exfiltration | Exfiltration (TA0010) | **Current.** Confirmed 3 sub-techniques: .001 (symmetric-encrypted), .002 (asymmetric-encrypted), .003 (unencrypted) — matches the code's own comment about not being able to distinguish .001/.002 without the cipher. |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | Exfiltration (TA0010) | **Current.** |
| T1041 | Exfiltration Over C2 Channel | Exfiltration Over C2 Channel | Exfiltration | Exfiltration (TA0010) | **Current.** v2.3. |

**None of the ten technique IDs this project cites are deprecated, revoked, or renamed.** No
corrections are needed to `attack_mapping.py`'s mapping table. This is a genuinely good outcome for
hand-curated content that predates today's check — worth stating plainly rather than manufacturing a
problem to fix.

**One thing worth doing regardless**: the code comment in `scenario.py` says *"Verified against
attack.mitre.org (v17 matrix ordering)."* Since the tactic list hasn't changed but the version has,
update the comment to note it was re-verified against v19.2 on this date, so the next person doesn't
have to redo this whole check to know it's still current.

### B2. A machine-readable ATT&CK source to validate mappings automatically, offline

- **`mitre/cti`** (`github.com/mitre/cti`) ships **STIX 2.0**, not 2.1 — VERIFIED by the repository's
  own description. It is the older, now largely superseded distribution.
- **`mitre-attack/attack-stix-data`** (`github.com/mitre-attack/attack-stix-data`) is the current,
  actively maintained **STIX 2.1** distribution — VERIFIED, its own README states "This repository
  contains the MITRE ATT&CK dataset represented in STIX 2.1 JSON collections." It ships both a
  rolling `enterprise-attack.json` (always the latest release) and version-pinned files (the pattern
  confirmed was `enterprise-attack-<version>.json`, e.g. historic `enterprise-attack-9.0.json`) — so
  a specific version, e.g. `enterprise-attack-19.2.json`, can be pinned and vendored for a fully
  reproducible offline copy rather than tracking a moving `master`.
- **Licence**: content is *"Copyright 2020-2025 The MITRE Corporation. Approved for public release,"*
  governed by MITRE's own **ATT&CK Terms of Use** (`attack.mitre.org/resources/terms-of-use/`),
  VERIFIED: MITRE grants "a non-exclusive, royalty-free license" for research, development and
  **commercial** use, on condition the copyright notice and licence text travel with any copy.
  Shipping `enterprise-attack.json` inside this project's Docker image or repo, with MITRE's
  copyright notice preserved, **is permitted.**
- **File size**: a specific figure of **45.3 MB** was reported for `mitre/cti`'s (STIX 2.0)
  `enterprise-attack.json` by a secondary source; this was **not independently re-measured this pass
  and should be treated as approximate** — mark **UNVERIFIED (exact byte count)**. Either way, this
  is a "vendor a JSON file in the repo" problem, not a scale problem — trivial for an air-gapped
  deployment already discussed in `research/101_AIRGAP_AUDIT.md`.
- **What this buys**: `attack_mapping.py`'s hand-written `_technique()` calls (id, name, tactic, URL)
  could be **checked in CI** against the STIX bundle — a script that loads `enterprise-attack.json`,
  looks up each of the 10 IDs above, and fails the build if a name changed, a technique was revoked,
  or a tactic mapping drifted. This converts B1's one-time manual check into a repeatable, automated
  regression test — genuinely useful, and a good "ranked improvement" candidate (see B4).

### B3. Data Sources are gone — this changed since the project's own comments were written

**Important, and not something the existing code or research anticipated**: MITRE **deprecated the
legacy Data Sources object type (the `DS-xxxx` identifiers the prompt asked about) in ATT&CK v18**
(October 2025) — VERIFIED, multiple independent sources describing the same change (Picus Security,
Cymulate, and MITRE's own "ATT&CK v18: Detection Strategies" summary, cross-checked against the
T1071.004 technique page fetched directly, which shows the *new* model in place, not the old one).
**What replaced it:**

- **Detection Strategies** (`DET-xxxx`, e.g. `DET0400` for T1071.004) — a behaviour-focused
  description of a defensive approach for a technique.
- **Analytics** (`AN-xxxx`, e.g. `AN1121`–`AN1125` under DET0400) — specific, actionable detection
  logic tied to a Detection Strategy.
- **Data Components** (`DC-xxxx`) — now carry the "Log Source" information that used to live on the
  old Data Source objects.

So the prompt's original framing — *"cite the DS-xxxx identifier for Network Traffic"* — targets a
mechanism that **no longer exists** in the current ATT&CK content model. The honest, current
equivalent claim for this project is at the Analytic level: for T1071.004 specifically, ATT&CK's own
site (fetched directly, 2026-08-20) documents five analytics under DET0400 that describe exactly the
kind of thing `attack_mapping.py`'s DNS-tunnelling rule already detects — e.g. **AN1122**, "local
daemons generating outbound queries with lengthy or frequent subdomains." **This is citable evidence
that ATT&CK itself, not just this project, considers DNS query characteristics a legitimate
detection signal for T1071.004** — a stronger and more current claim than the DS-xxxx framing the
prompt anticipated, and one this project doesn't currently make anywhere. Worth adding to
`attack_mapping.py`'s per-technique notes for the four-ish techniques where an Analytic maps
cleanly onto what the rule actually does (DNS tunnelling ↔ AN1122 is the clean case found this pass;
the other nine IDs were not individually checked at the Analytic level — that is unfinished work, not
a claim made here).

### B4. What else is standard, and what a judge would actually recognise

| Framework | What it is | Recognisable to a judge? | Adds real value here, or a second label? |
|---|---|---|---|
| **MITRE ATT&CK** (already used) | Adversary tactics/techniques/procedures, network-and-endpoint scope | Yes — the most widely known of this group | Already the right choice; keep it primary. |
| **CAPEC** (`capec.mitre.org`) | Common Attack Pattern Enumeration — attack-mechanism patterns (e.g. "SQL Injection"), **application-security focused**, VERIFIED via CAPEC's own "ATT&CK Comparison" page (`capec.mitre.org/about/attack_comparison.html`) | Moderate — well known in AppSec circles, less so in network forensics | **Second label, not real value here.** CAPEC's own comparison page frames it as complementary to ATT&CK for *application* weaknesses; this project observes network behaviour, not app-layer exploitation mechanics. Skip it. |
| **Lockheed Martin Cyber Kill Chain** | Seven linear phases: **Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives** (VERIFIED, consistent across Vectra, Picus, EC-Council, Microsoft Security summaries) | Very — arguably *more* recognisable to a non-specialist judge than ATT&CK's 14-tactic matrix, because it's simpler and older | **Real, cheap value as a second, simpler view**, not a replacement. `scenario.py` already builds a kill-chain-style staged reconstruction using ATT&CK's 14 tactics; a thin *presentation-layer* mapping from the already-computed ATT&CK tactic to one of the 7 Kill Chain phases (e.g. TA0011 Command and Control → "Command & Control," TA0010 Exfiltration/TA0040 Impact → "Actions on Objectives") would let the UI offer "explain this simply" toggle for a non-technical judge, with zero new detection logic — pure relabelling of data already computed. Ranked improvement #1 (see B5). |
| **VERIS** (Verizon, `verisframework.org`) | Incident-classification vocabulary (Actor/Action/Asset/Attribute — "the 4 A's"), for aggregating *incidents* across an organisation for trend reporting (the Verizon DBIR) | Low in this context — it's an analyst/GRC tool, not an investigator-facing one | Not a fit. VERIS classifies incidents for statistical reporting across many cases; this tool produces a single-capture forensic finding. Skip it. |
| **STIX 2.1 patterns** | A machine-readable indicator/pattern language | Not to a judge; relevant to *other tools*, not to a courtroom | Already indirectly relevant via B2 (STIX is the format the ATT&CK data itself ships in) — no separate product feature needed. |
| **MITRE D3FEND** | Defensive-countermeasure knowledge graph, reached **1.0 general availability in January 2025** after NSA-funded beta since 2021 (VERIFIED, multiple vendor summaries + `d3fend.mitre.org`) — maps countermeasures (Hardening, Detection, Deception, Isolation, Eviction) to ATT&CK techniques | Growing, not yet as recognisable as ATT&CK | **Genuinely interesting, low-priority.** Once a finding is mapped to an ATT&CK technique (already done), a D3FEND lookup could suggest a specific, named countermeasure category ("this is Network Traffic Analysis, a D3FEND Detection technique") for the investigator's next step — a real capability upgrade (advice, not just classification), but it's additive scope, not a fix to anything broken. Ranked improvement #3. |

### B5. Ranked improvements for `attack_mapping.py` / `scenario.py`

1. **Add a Cyber Kill Chain relabelling layer for the UI** (cheap, high legibility payoff — see B4).
   Pure derived data from the ATT&CK tactic already computed; no new detection logic, no new false
   claims, just a second vocabulary for a non-specialist reader. Effort: small.
2. **Automate B1's verification as a CI check against the STIX 2.1 bundle** (see B2): pin
   `enterprise-attack-19.2.json`, write a test that loads it and asserts each of the 10 technique IDs
   in `attack_mapping.py` still exists, is not revoked, has the name the code claims, and belongs to
   the tactic the code claims. Converts a one-off manual audit (this document) into a standing
   regression test that catches the *next* ATT&CK version bump automatically. Effort: small-medium.
3. **Update the stale "v17" comment in `scenario.py`** to reflect this pass's v19.2 re-verification
   (see B1) — trivial, but leaving a superseded version number in a comment that exists specifically
   to record "this was checked" undercuts the whole practice.
4. **Selectively cite Detection Strategies/Analytics (B3)** for techniques where a clean, honest match
   exists between our rule's actual logic and a published Analytic (DNS tunnelling ↔ AN1122 is
   confirmed this pass; the rest are unaudited). Do this technique-by-technique, the same way the
   original ten mappings were built — checked against the source, not bulk-copied. Effort: medium,
   because it requires the same one-at-a-time honesty the original mapping used.
5. **D3FEND countermeasure suggestions** (see B4) — genuinely additive scope, lowest priority of the
   five because it's a new feature, not a strengthening of the existing classification.

### B6. Confidence and accuracy of automated ATT&CK mapping — is hand-curation defensible?

**Yes, and the evidence found this pass supports it, though it is not a large or definitive
literature.**

- **CISA's own "Best Practices for MITRE ATT&CK Mapping"** (originally June 2021, updated January
  2023, jointly with MITRE's own HSSEDI-affiliated ATT&CK team) — its existence and scope were
  confirmed via CISA's own news release and multiple secondary summaries (the PDF itself returned
  HTTP 403 to direct fetch this pass, so its exact wording is **UNVERIFIED at the primary-source
  level**, though the document's existence, authorship, and general guidance — map from sufficient
  technical detail, cross-check between analysts, avoid the mistakes that recur when mapping is
  rushed — are corroborated by several independent secondary sources describing its contents
  consistently). CISA's guidance is explicitly aimed at **human analysts doing careful, checked
  mapping** — it is not a document written to justify or describe automated mapping, which is itself
  informative: the field's own best-practice authority still frames this as an analyst discipline
  problem, not a solved automation problem.
- **A concrete automated-mapping accuracy figure was found**: SYNAPSE, an LLM-powered honeypot
  system, reports **75% precision and 68% recall** mapping observed attacker activity to ATT&CK
  techniques automatically, evaluated against real-world attack data (VERIFIED via search summary of
  the SYNAPSE paper's own reported figures; the paper itself was not independently opened and
  re-read this pass — mark **UNVERIFIED at full-text level**, but the figure is specific and
  attributable, not a vague secondary characterisation). 75/68 means roughly **one in four claimed
  techniques is wrong, and roughly one in three real techniques is missed** — for a domain
  (honeypot/attacker-activity classification) that is arguably *easier* than this project's task
  (distinguishing genuine malicious network behaviour from benign-but-unusual traffic).
- **Network-traffic technique coverage is inherently partial regardless of method**: a 2022 survey
  found network traffic relevant to **131 of 707** Enterprise techniques/sub-techniques (ATT&CK
  v10.1-era count; the totals have grown since — VERIFIED via `arxiv.org/pdf/2206.14539`, not
  independently recomputed against the current v19.2 technique count this pass), spanning 13 of 14
  tactics *at the technique-existence level*. This project's own, stricter `UNOBSERVABLE` list in
  `scenario.py` claims only **4 of 14 tactics** are honestly network-observable *at the standard this
  project holds itself to* (something an examiner could testify to, not merely "some sub-technique
  somewhere touches the wire"). That gap between "13 tactics have *a* network-relevant technique
  somewhere" and "4 tactics are ones we'd stand behind in court" is not a contradiction — it is this
  project choosing a **more conservative, more defensible** bar than the literature's own headline
  number would technically permit. Worth stating exactly this way if asked "why only 4 tactics" —
  it's a deliberate, evidence-grounded restraint, not a coverage gap.
- **No published paper directly comparing hand-curated vs. automated ATT&CK mapping accuracy from
  *network* observables specifically was found this pass** — this is a real gap in the search, not a
  claim that none exists. What was found (SYNAPSE's 75/68, CISA's human-analyst-focused best
  practices, the coverage-limits survey) is **consistent with, but does not conclusively prove**, the
  hypothesis that hand-curation is the defensible choice for a hackathon-scale, courtroom-adjacent
  tool. State it as: *the available evidence favours hand-curation and does not contradict it; a
  rigorous head-to-head study specific to this domain was not located.*

---

## Summary of concrete recommendations

**Part A**: Don't switch PDF libraries. `pip install uharfbuzz` against the reportlab==4.4.4 already
pinned; register the already-available `NotoSansGujarati-Regular.ttf`/`-Bold.ttf` (OFL-1.1, freely
redistributable, vendor it with its `OFL.txt`) as `shapable=True` fonts; set `shaping=1` on
Gujarati-only `ParagraphStyle`s; keep English and Gujarati in **separate** flowables/cells rather than
mixed inline runs (empirically required, not optional). Keep the §63(4)(c) certificate English-only —
now for a *legal* reason (no authoritative Gujarati Schedule text exists to translate from) rather
than the previous *technical* one (which A0 shows is no longer the blocker). Extend the investigation
report with bilingual section headings using the existing `gujarati.js` glossary, now that the
rendering path can actually carry it correctly. Test the full certificate layout, not just isolated
words, before calling this shipped.

**Part B**: All 10 ATT&CK technique IDs currently used are verified current against live
`attack.mitre.org` as of v19.2 (28 April 2026) — no corrections needed. The biggest verified finding
is structural, not a technique-ID error: **ATT&CK's Data Sources (DS-xxxx) were deprecated in v18**
and replaced by Detection Strategies/Analytics — the ecosystem moved out from under a framing the
original prompt (reasonably) assumed still held. Ship a STIX 2.1-backed CI check
(`mitre-attack/attack-stix-data`, Apache/MITRE-licensed, redistribution permitted) so the next
version bump is caught automatically instead of manually. Add a Cyber Kill Chain relabelling layer as
a cheap, high-legibility second vocabulary for non-specialist readers — reusing data already computed,
not new detection logic. Hand-curation over automated mapping remains the better-supported choice
given what was found (SYNAPSE's 75%/68% precision/recall on an easier task; CISA's own guidance
targets careful human analysts, not automation) — though a domain-specific, network-observable-only
accuracy study was not located and this should be stated as "evidence favours it," not "proven."
