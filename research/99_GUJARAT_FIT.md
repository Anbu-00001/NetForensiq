# 99 — What would make NetForensiq land specifically with Ahmedabad City Police, Gujarat Police, and Gujarat society

*Research pass compiled 18 Aug 2026, one day before KANAD S.H.I.E.L.D. 2026 (confirmed dates: **19–20 August
2026**, venue **i-Hub Gujarat, Prajna Puram, KCG Campus, opp. PRL, Navrangpura, Ahmedabad 380015** — fetched
directly from kanadshield.com/timeline.html). This document builds on, and deliberately does not repeat,
[01](01_gujarat_police_structure_and_leadership.md), [02](02_gujarat_police_existing_tech_and_ai.md),
[03](03_gujarat_cybercrime_landscape.md) and [95](95_ESAKSHYA_VERIFIED_FINDINGS.md). Every claim is sourced
inline; anything not independently confirmed is marked ⚠️ **UNVERIFIED**.*

---

## Do this — ranked by impact, each with its evidence

1. **Cite the Gujarat High Court's own 2026 ruling on the §63/§65B certificate, not just eSakshya/GSJA
   training.** On or around **8 May 2026**, **Justice J.C. Doshi, Gujarat High Court**, held that production of
   the certificate under §65B(4) of the Evidence Act / §63(4) of the BSA is a **"condition precedent"** to a
   court even considering electronic evidence, and that a trial court which sent an audio recording to FSL for
   examination *before* ruling on that certificate committed **"patent illegality."** [lawyerenews.com](https://lawyerenews.com/legal_detail/secondary-electronic-evidence-inadmissible-without-mandatory-certificate-sending-to-fsl-before-deciding-admissibility-is-patent-illegality-gujarat-high-court),
   [lawyerenews.com (companion piece)](https://lawyerenews.com/legal_detail/fsl-probe-before-electronic-evidence-meets-section-65b-admissibility-standards-gujarat-high-court).
   ⚠️ Sourced to a legal-news aggregator, not a primary judgment PDF or a LiveLaw digest entry (LiveLaw's
   [May 2026 Gujarat HC monthly digest](https://www.livelaw.in/high-court/gujarat-high-court/gujarat-high-court-monthly-digest-536445),
   fetched directly, does **not** list this case among its 26 entries) — do not state a case citation, only the
   holding as reported twice by the same secondary source. Even with that caveat, this is a **Gujarat court**,
   not a national precedent or a training-agenda line item, insisting on exactly the certificate-first,
   two-part sequencing NetForensiq already enforces. It is a stronger, more local answer to "why would a
   Gujarat court accept this" than anything in [research/95](95_ESAKSHYA_VERIFIED_FINDINGS.md), and it should
   sit next to the GSJA training-session material on the same slide, not replace it.

2. **Cite the Gujarat High Court's April 2026 AI Policy to justify the rules-engine (not ML) design choice.**
   The Gujarat High Court released a formal **"Policy on the Use of Artificial Intelligence in the Judicial and
   Court Administration"** in April 2026 — the second High Court in India to do so, after Kerala (July 2025).
   It **prohibits** AI use in "decision-making, judicial reasoning, order drafting, judgment preparation, bail
   and sentencing considerations, and other substantive adjudicatory processes," permits it only for
   administrative workload distribution and case-law research, and requires human verification of anything AI
   touches. [taxguru.in](https://taxguru.in/corporate-law/gujarat-hc-issues-policy-ai-judicial-court-administration.html),
   [medianama.com](https://www.medianama.com/2026/04/223-gujarat-hc-releases-ai-policy-barring-court-decisions-reasoning-orders/)
   (fetch blocked, headline/summary only — treat medianama's specific wording as ⚠️ secondary),
   [primary PDF, Gujarat High Court](https://gujarathighcourt.nic.in/hccms/sites/default/files/miscnotifications/Policy%20on%20the%20use%20of%20Artificial%20Intelligence%20in%20the%20Judicial%20and%20Court%20Administration.pdf),
   [lawyerenews.com](https://lawyerenews.com/legal_detail/gujarat-high-court-bans-ai-from-judicial-decision-making-lays-down-strict-policy-for-court-use-of-artificial-intelligence).
   **Use this carefully**: the policy governs *judicial and court-administration* AI use, not investigative
   tooling used by police before evidence reaches a court — do not claim it directly regulates NetForensiq. The
   legitimate, honest move is analogical: "the Gujarat High Court has just told the state's judiciary it wants
   auditable, human-verified reasoning, not opaque model output — NetForensiq's 9 rules, each with a cited
   threshold or an explicit `[OUR HEURISTIC]` tag, is exactly that posture applied to network evidence, not an
   ML black box." This turns PROGRESS.md's own discipline (no fabricated ML feature cards, thresholds always
   labelled) into a pitch point specific to *this* state's judiciary.

3. **Add MD5 as a genuine secondary hash field, matching THE SCHEDULE's literal checkboxes.** THE SCHEDULE
   (already quoted verbatim in [SPEC_01](SPEC_01_EVIDENCE_INTEGRITY.md) lines 79–103) presents the certifying
   officer/expert with checkboxes for ☐ SHA1 ☐ SHA256 ☐ MD5 ☐ Other, not SHA-256 alone. SPEC_01 already flags
   this as `[GOOD PRACTICE]` and not yet confirmed implemented. Given finding #1 above — a Gujarat judge who
   has just rejected a case for skipping a certificate *step*, not just a certificate — a certificate PDF that
   only ever offers one hash algorithm when the statutory form printed under it shows three checkboxes is a
   visible, easily-noticed mismatch to exactly the kind of literalist reading Justice Doshi's ruling
   demonstrates. This is a small, mechanical fix relative to its visibility. **Do not**, however, claim MD5 is
   *required* — no source found states dual-hashing is mandatory; the Schedule offers algorithm choices, it
   does not mandate more than one. (See "Claims we should NOT make.")

4. **State plainly, in the pitch itself, that network/packet forensics is a minority slice of Gujarat's actual
   cybercrime caseload — and reframe accordingly.** Gujarat's own 2025 data: **142,476 people targeted,
   72,091 actually defrauded, ₹678 crore lost** in the first nine months of 2025 alone
   ([the420.in](https://the420.in/gujarat-cybercrime-losses-hit-678-crore-72000-victims-targeted/), already in
   [03](03_gujarat_cybercrime_landscape.md)) — and the dominant typologies named by Gujarat's own officers and
   Operation Mule Hunt's own framing are **mule-account financial plumbing and psychological-coercion social
   engineering (digital arrest, investment fraud)**, not technical intrusion or malware C2
   ([03 §9](03_gujarat_cybercrime_landscape.md)). Confirming this from the organiser's own side: KANAD
   S.H.I.E.L.D.'s own problem-statement list (fetched directly from kanadshield.com/category-2.html and
   about.html) contains **26 problem statements across both categories**, of which the great majority target
   exactly those typologies — `CryptoTrack`, `Detection and Analysis of Mule Bank Accounts`, `IntelliBank`,
   `SIMScanner`, `CallGuard`, `CellScope`, `DARKTRACE`, `TruthShield` (deepfakes/fake news), `VoiceInsight`,
   `SMIntelliTrack` — and only **one**, `Network & Packet Forensics Platform`, is packet-forensics-specific.
   The honest framing for the pitch is not "we solve Gujarat's cybercrime problem" but **"every one of those
   other 25 problem statements eventually produces digital evidence that needs an integrity/custody layer
   before it reaches a Gujarati court — NetForensiq is infrastructure the other 25 tools would eventually need
   too, demonstrated first on the one evidence type (network capture) that currently has none."** This is more
   defensible than competing head-on with tools purpose-built for the typologies that actually dominate the
   caseload, and it turns the niche-ness into the argument rather than hiding it.

5. **Address Gujarati-language accessibility narrowly and specifically — the certificate, not the whole app.**
   GIGW 3.0 (the Guidelines for Indian Government Websites, maintained by NIC/MeitY) is the baseline standard
   "all central and state government ministries, departments, and public-sector undertakings are expected to
   comply with... as a condition of digital service delivery under Digital India," built on WCAG 2.1 AA plus
   explicit multilingual-support requirements
   ([guidelines.india.gov.in](https://guidelines.india.gov.in/introduction/),
   [skynettechnologies.com summary](https://www.skynettechnologies.com/blog/gigw-3-0-government-website-accessibility-in-india)).
   Separately, **Gujarat Informatics Limited (GIL)** is the state's designated standards body and is explicitly
   tasked with defining standards for "technology/platform, database, coding, **usage of Gujarati Software**,
   security, system documentation" for state IT projects
   ([gil.gujarat.gov.in policy document](https://gil.gujarat.gov.in/Media/GRDocument/gr_tsp.-25pdf.pdf) — ⚠️ the
   PDF itself could not be parsed for exact wording via automated fetch, this summary is from search-result
   snippets only, re-verify before quoting a section number). NetForensiq is an **internal analyst tool**, not
   a citizen-facing portal like Citizen First/e-FIR (which *are* the clear GIGW/Gujarati-mandate targets per
   [02](02_gujarat_police_existing_tech_and_ai.md) §4) — full UI localization is not the highest-value use of
   hackathon time. The **§63 certificate PDF**, however, is the one artefact in this product explicitly meant
   to be read by a magistrate, and BSA/GSJA training already assumes a Gujarati-medium judicial officer at the
   taluka-court level. A bilingual (English + Gujarati) header/declaration block on the certificate — not a
   full localization of the dashboard — is the highest-signal, lowest-effort accessibility move available in
   the time remaining.

6. **Frame the post-hackathon path as GSDC hosting, not a vague "we'll integrate."** The **Gujarat State Data
   Center (GSDC)**, established 2010, was "the first State Data Center implemented in India under the National
   e-Governance Plan," built explicitly to host state departments' applications, web/app/DB servers
   ([dst.gujarat.gov.in](https://dst.gujarat.gov.in/Home/GujaratStateDataCenter),
   [guj.nic.in](https://guj.nic.in/en/infrastructure/)) — the same hosting model e-GujCop/CCTNS already sit on
   ([02](02_gujarat_police_existing_tech_and_ai.md) §4, §7). "Designed to be deployable on GSDC, the
   infrastructure Gujarat Police's other systems already run on" is a concrete, checkable claim a judge can
   ask a follow-up question about — stronger than any claim of a live integration, which
   [SPEC_03](SPEC_03_CONNECTORS_AND_MCP.md) has already established does not exist for any Indian police system
   (CCTNS/ICJS are confirmed point-to-point, firewall-cleared, police-network-only).

7. **Calibrate to what this specific hackathon's mechanics reward: working demos on real data, not slideware.**
   No published judging rubric exists for KANAD S.H.I.E.L.D. 2026 — the public site's own "How It Works" page
   states the process as five steps ending in "Pitch at Hackathon Event — Present your solution live to
   Experts & government officials" then "Results & Rewards," with no scoring criteria listed (fetched directly
   from kanadshield.com/how-it-works.html). The strongest available signal instead comes from the *concurrent*
   **Gujarat Police Innovation Challenge 2026** (announced 17 Aug 2026, run by Gujarat Police directly, not the
   Ahmedabad Cyber Crime Branch — a separate event, do not conflate the two) targeting 80,000 CCTV cameras,
   ₹37 lakh in prizes, and an explicit **finale format using live production data and real-world policing
   scenarios**, not synthetic demos
   ([aninews.in](https://aninews.in/news/national/general-news/gujarat-police-to-host-countrys-largest-ai-based-cctv-hackathon20260817135250/),
   [openthemagazine.com deep-dive](https://openthemagazine.com/india/can-80000-cameras-think-as-one-inside-gujarat-polices-mega-ai-hackathon)).
   Read together with KANAD S.H.I.E.L.D.'s own "pitch to Experts & government officials" language, the state's
   2026 hackathon posture across both events rewards **demonstrable results on real inputs over polish**. This
   validates — it does not newly establish — PROGRESS.md's existing bet on real-traffic validation over a
   larger synthetic corpus; the recommendation is to lead the demo with the real-capture defects-found story
   (research/96), not the thresholds-and-architecture story, in whatever time slot is available.

8. **Do not oversell "next steps after winning" — the only sourced language is generic hackathon marketing.**
   Third-party listings describe KANAD S.H.I.E.L.D. as including "pilot-deployment and government-procurement
   pathway[s] for winning teams" and an "Investment & Fundraising track... providing structured investor
   engagement opportunities, pilot deployment pathways, and access to government procurement channels"
   ([fundsforcompanies.fundsforngos.org](https://fundsforcompanies.fundsforngos.org/events/startup-police-cybersecurity-innovation-program-cybershield-ahmedabad-india/)).
   No named programme (e.g. a "Gujarat Police Innovation Cell") distinct from this marketing language was
   found, and no GeM empanelment path specific to Gujarat Police software procurement was found. The event's
   academic partner appears to be **Karnavati University's incubator (KIIF)** — the venue "i-Hub Gujarat...
   KCG Campus" is consistent with i-Hub being physically hosted at/operated in partnership with Karnavati
   University, though this exact relationship is ⚠️ **UNVERIFIED** (inferred from venue naming, not confirmed
   in any source). **The honest move is to ask the organisers directly, on the day, what the concrete next
   step is** — do not build a slide asserting a specific procurement programme exists.

---

## 1. Gujarat Police cyber infrastructure, 2025–2026

Most of this ground is already covered by [02](02_gujarat_police_existing_tech_and_ai.md) §11–13 and
[03](03_gujarat_cybercrime_landscape.md) §4 (AASHVAST, the State Cyber Crime Cell at Karmyogi Bhavan
Gandhinagar, the Cyber Centre of Excellence under CID Crime, the Rajkot Cyber Sentinels Lab opened Feb 2025).
What this pass adds:

- **"Shree Cyber Suraksha" as named in the task brief could not be confirmed as an existing, distinctly-named
  Gujarat Police programme.** Search surfaced a **"Cyber Suraksha Kavach"** — a citizen-facing mobile-security
  cell/app referenced on a status-check aggregator ([statusin.in](https://www.statusin.in/10207.html)) — plus
  several unrelated private-sector and NGO users of similar names ("Cyber Suraksha Setu," a Surat-based
  nonprofit; "Cyber Suraksha," a Vadodara training institute). None of these match "Shree Cyber Suraksha"
  precisely, and none was independently corroborated as an official state programme with a primary
  government source. **Treat this as either a naming variant of AASHVAST/Cyber Suraksha Kavach or as
  ⚠️ UNVERIFIED/possibly non-existent** — do not build pitch material assuming it exists under that name.
- **No Gujarat-specific published SOP for FSL Gandhinagar's digital-evidence workflow was found.** Search
  returned only generic, non-Gujarat-specific descriptions of a three-hash chain-of-custody protocol
  (hash-at-seizure by the IO, hash-at-receipt by the FSL expert before unsealing, hash-at-analysis after
  imaging) from law-firm/blog sources
  ([legalserviceindia.com](https://www.legalserviceindia.com/Legal-Articles/the-digital-forensic-investigation-process-chain-of-custody-and-evidence-preservation/),
  [advocategandhi.com](https://advocategandhi.com/fsl-report-in-cyber-crime-cases-the-silent-witness-behind-every-digital-offence/)),
  neither naming Gujarat's DFS specifically. What *is* independently confirmed (from [01](01_gujarat_police_structure_and_leadership.md)
  §6): DFS Gujarat, established 2003, was **"first state in India to implement Digital Scanning-only system,"**
  with all district FSLs connected online to HQ ([dfs.gujarat.gov.in](https://dfs.gujarat.gov.in/dfsl/default.aspx)).
  A workflow description matching NetForensiq's own three-hash model (capture hash, custody-transfer hash,
  analysis hash) to DFS Gandhinagar's *specific* published intake process would strengthen the pitch, but no
  such document was locatable in this pass — flag as a gap for the team to close via a direct FSL contact if
  one exists, rather than asserting a match that isn't sourced.
- **Turnaround times**: one blog source states Gujarat FSL cyber-forensics access is "through FIR and
  investigating officer referral, with turnaround times varying from 45–180 days" — ⚠️ UNVERIFIED, single
  secondary source, no primary FSL document found corroborating this figure. If true, it is a strong argument
  for NetForensiq's value: a capture sealed and certificate-ready at ingest removes exactly the kind of delay
  a 45–180 day FSL queue implies for cases where network evidence is the bottleneck.

## 2. Case volume and typology — is network forensics even the bottleneck?

**No — and the evidence for this is already fully assembled in [03](03_gujarat_cybercrime_landscape.md), this
section synthesizes it against the specific question asked.**

- Gujarat recorded **168,000 NCRP cybercrime complaints in 2024** (4th-highest state)
  ([isignal.in](https://www.isignal.in/data-viz/dataviz-how-indias-cyber-crime-incidence-is-rising-972933)),
  and **142,476 people targeted / 72,091 defrauded / ₹678 crore lost** in the first nine months of 2025 alone
  ([the420.in](https://the420.in/gujarat-cybercrime-losses-hit-678-crore-72000-victims-targeted/)).
- The dominant typologies by every measure in [03](03_gujarat_cybercrime_landscape.md) §2 are **digital
  arrest** (₹30 cr in two 2025 cases alone), **fake investment apps** (₹35.34 cr senior-citizen cluster), **mule
  bank accounts** (Operation Mule Hunt 1.0 + 2.0: ₹250 cr + ₹802 cr = **₹1,052 crore combined**), and **SIM
  fraud/smuggling** feeding Southeast Asian cyber-slavery compounds. None of these typologies is centrally a
  packet-capture forensics problem — they are financial-trail, KYC, and social-engineering problems.
- Officers and experts quoted on Gujarat's own cases (Prof. Triveni Singh, on the CID's ₹250 cr mule case;
  the unattributed official statement on Operation Mule Hunt) consistently frame the operative bottleneck as
  **"mule account networks... making financial trails more difficult to detect"** and **psychological coercion
  ("fear, urgency, respect for authority")** — not technical attribution or malware analysis
  ([03 §9](03_gujarat_cybercrime_landscape.md)).
- **Corroborating this from the organiser side** (new in this pass): of KANAD S.H.I.E.L.D. 2026's 26 published
  problem statements across both categories, only **one** — Category 2's `Network & Packet Forensics Platform`
  — targets network-level forensics; the remainder cluster around exactly the typologies above (mule accounts,
  crypto tracing, SIM fraud, voice/call fraud, deepfakes, social media monitoring). This is independent
  confirmation, from the event's own problem-statement design, that network forensics is a minority interest
  even among the organisers, not just relative to raw case-count statistics.

**The honest conclusion for the team**: NetForensiq is solving a real gap (§evidence custody for the network
evidence that does exist — data breaches, unauthorized access, DDoS, malware C2 within the corporate/critical
systems Gujarat does police), but it is not solving the typologies that generate the overwhelming majority of
Gujarat's cybercrime caseload or victim harm. See "Do this" item 4 for how to frame this rather than paper over
it.

## 3. The judicial reality in Gujarat since January 2025

- **New in this pass**: **Justice J.C. Doshi, Gujarat High Court, ~8 May 2026** — ruled that a certificate
  under §65B(4)/§63(4) is a **"condition precedent"** for a court to consider electronic evidence at all, and
  that ordering FSL examination before resolving admissibility is **"patent illegality."** The underlying
  dispute concerned an oral bungalow-sale agreement and an audio cassette of a telephonic conversation, **not**
  network or packet-capture evidence
  ([lawyerenews.com](https://lawyerenews.com/legal_detail/secondary-electronic-evidence-inadmissible-without-mandatory-certificate-sending-to-fsl-before-deciding-admissibility-is-patent-illegality-gujarat-high-court)).
  ⚠️ Sourced only via a legal-news aggregator; not found in LiveLaw's May 2026 Gujarat HC monthly digest
  (checked directly) or any primary judgment PDF — case name/citation unconfirmed. Use the holding, not a
  citation.
- **New in this pass**: the **Gujarat High Court's April 2026 "Policy on the Use of Artificial Intelligence in
  the Judicial and Court Administration"** — the second Indian High Court (after Kerala, July 2025) to
  formalise one. It bars AI from decision-making/reasoning/order-drafting/bail-and-sentencing, permits it only
  for administrative workload balancing and legal research, and threatens disciplinary/civil/criminal liability
  for violations across "judicial officers, court staff, interns, legal assistants, and affiliated
  institutions" ([taxguru.in](https://taxguru.in/corporate-law/gujarat-hc-issues-policy-ai-judicial-court-administration.html),
  primary PDF at
  [gujarathighcourt.nic.in](https://gujarathighcourt.nic.in/hccms/sites/default/files/miscnotifications/Policy%20on%20the%20use%20of%20Artificial%20Intelligence%20in%20the%20Judicial%20and%20Court%20Administration.pdf)).
  This governs judicial/court use, not police investigative tooling — see "Claims we should NOT make."
- **National-level reinforcement, not Gujarat-specific**: *Pooranmal v. State of Rajasthan* (2026 INSC 217) —
  Supreme Court, reaffirming mandatory §65-B certification and strict chain-of-custody for CDR/FSL evidence in
  a circumstantial-murder trial ([casemine.com](https://www.casemine.com/commentary/in/pooranmal-v.-state-of-rajasthan-(2026-insc-217)-%E2%80%94-mandatory-section-65-b-certification-and-strict-chain-of-custody-as-preconditions-for-reliance-on-cdr-fsl-in-circumstantial-murder-trials/view)).
  Confirms the same certificate-first doctrine at the Supreme Court level, applied to CDR (call-detail-record)
  evidence — structurally the closest existing precedent to "network/log evidence," though it is telecom
  metadata, not packet capture, and it is not a Gujarat court.
- **No case was found — Gujarat or national — that specifically rules on packet-capture or network-flow
  evidence.** Every certificate-requirement ruling located in this pass and in [95](95_ESAKSHYA_VERIFIED_FINDINGS.md)
  concerns audio recordings, CDRs, WhatsApp chats, or video. This is worth stating plainly rather than implying
  by omission: **no Gujarat court has yet accepted or rejected network/PCAP evidence on the record, as far as
  this research could establish.** NetForensiq's pitch should say it is *designed for* the certificate regime
  those rulings establish, not that a Gujarat court has already dealt with evidence like it.
- **Procedural infrastructure, found but tangential**: Gujarat High Court Gazette notices for **SARAS Courts**
  (StateWide Access to Remote Adjudication System, notified 24 Mar 2026) and **District Courts of Gujarat
  Rules for the Use of Electronic Communication and Audio-Video Electronic Means, 2025** exist
  ([gujarathighcourt.nic.in SARAS notice](https://gujarathighcourt.nic.in/hccms/sites/default/files/rules_files/Government%20Gazette%20-%2024032026%20-%20The%20Gujarat%20High%20Court%20Rules%20for%20seamless%20functioning%20of%20SARASCourts%20-StateWide%20Access%20to%20Remote%20Adjudication%20System-%202026.pdf),
  [2025 e-communication rules](https://gujarathighcourt.nic.in/hccms/sites/default/files/rules_files/The%20District%20Courts%20of%20the%20Gujarat%20States%20for%20the%20Use%20of%20Electronic%20Communication%20and%20Audio-Video%20Electronic%20Means%20Rules,%202025.pdf)).
  Neither was read in full for this pass — flagged only as evidence that Gujarat's district judiciary is
  actively formalising its electronic-evidence/electronic-hearing procedure in 2025–2026, consistent with the
  GSJA training push already documented in [95](95_ESAKSHYA_VERIFIED_FINDINGS.md).

## 4. Language and accessibility

- **GIGW 3.0** (Guidelines for Indian Government Websites/apps, NIC/MeitY) is the operative national standard:
  WCAG 2.1 AA baseline, "88 mandatory checkpoints across accessibility, quality, cybersecurity, and lifecycle
  management," explicit multilingual-content requirements, STQC certification
  ([guidelines.india.gov.in](https://guidelines.india.gov.in/introduction/),
  [accordcompliance.org](https://accordcompliance.org/regulations/india/gigw-3.0),
  [skynettechnologies.com](https://www.skynettechnologies.com/blog/gigw-3-0-government-website-accessibility-in-india)).
  It applies to "all central and state government ministries, departments, and public-sector undertakings...
  as a condition of digital service delivery under Digital India" — this framing is about citizen-facing
  digital *service delivery*; whether it extends as a hard requirement to an internal law-enforcement analyst
  tool (as opposed to a citizen portal) is ⚠️ UNVERIFIED and was not resolved in this pass.
- **Gujarat-specific**: Gujarat Informatics Limited (GIL) is named as the state's IT standards body, tasked
  with defining "technology/platform, database, coding, usage of Gujarati Software, security, system
  documentation" standards for state government IT projects — found in a GIL policy circular referenced by
  search snippets; the PDF itself
  ([gil.gujarat.gov.in](https://gil.gujarat.gov.in/Media/GRDocument/gr_tsp.-25pdf.pdf)) could not be parsed by
  automated fetch (returned as a binary/font-table stream, not extractable text) — **re-verify the exact
  section and wording before quoting this on a slide.**
- **Precedent within Gujarat Police's own tech stack**: [02](02_gujarat_police_existing_tech_and_ai.md) §4
  already establishes that **e-FIR / Citizen First is form-based, English/Hindi-oriented, with "no evidence
  found of a speech-to-text or conversational-AI layer" in Gujarati** — i.e., even Gujarat's flagship
  citizen-facing e-governance app has not solved Gujarati-language accessibility comprehensively. This lowers
  the bar of what a hackathon team is expected to deliver, and raises the value of even a partial gesture (see
  "Do this" item 5 — the certificate, not the whole UI).

## 5. Procurement and deployment reality

- **KANAD S.H.I.E.L.D. mechanics, confirmed directly from the organiser's site** (kanadshield.com, fetched
  18 Aug 2026): run by **Cyber Crime Branch, Ahmedabad City Police**, in collaboration with **i-Hub Gujarat**;
  registration closed 10 May 2026; submission deadline 28 June 2026; event **19–20 August 2026** at i-Hub
  Gujarat, Navrangpura. Process is a five-step funnel (explore problem statement → apply, no login required →
  submit prototype/documents → pitch live to "Experts & government officials" → results/rewards) with **no
  published scoring rubric**.
- **Stated (marketing-language) post-hackathon pathway**: "pilot-deployment and government-procurement
  pathway for winning teams," an "Investment & Fundraising track... investor engagement opportunities, pilot
  deployment pathways, and access to government procurement channels"
  ([fundsforcompanies.fundsforngos.org listing](https://fundsforcompanies.fundsforngos.org/events/startup-police-cybersecurity-innovation-program-cybershield-ahmedabad-india/)).
  No specific programme name (e.g. a distinctly-branded "Gujarat Police Innovation Cell") was found to exist
  independent of this language — treat "there is a named post-win programme" as unconfirmed.
- **Realistic deployment target**: the **Gujarat State Data Center (GSDC)**, established 2010 as "the first
  State Data Center implemented in India under the National e-Governance Plan," hosts Gujarat government
  departments' web/app/DB servers under NeGP
  ([dst.gujarat.gov.in](https://dst.gujarat.gov.in/Home/GujaratStateDataCenter),
  [guj.nic.in](https://guj.nic.in/en/infrastructure/)) — this is the concrete, checkable hosting model to name
  in a pitch, rather than an abstract "cloud deployment."
- **GeM**: Government e-Marketplace is the national public-procurement platform (MSMEs/DPIIT-recognised
  startups can register as sellers; a "GeM Startup Runway" exists for innovative products) — but no
  Gujarat-Police-specific or KANAD-S.H.I.E.L.D.-specific GeM empanelment path was found
  ([gem.gov.in](https://gem.gov.in/), [startupindia.gov.in](https://www.startupindia.gov.in/content/sih/en/public_procurement.html)).
  This is the generic national route any startup could pursue, not a hackathon-specific shortcut.
- **Comparative signal from the concurrent Gujarat Police Innovation Challenge 2026** (a separate event, run
  directly by Gujarat Police, not Ahmedabad's Cyber Crime Branch — announced 17 Aug 2026, targeting 80,000
  CCTV cameras statewide, ₹37 lakh total prizes, live-production-data finale, registration/rules via
  **sentinel.gujarat.gov.in**) shows Gujarat Police's *general* 2026 posture toward hackathon-sourced
  technology: large, structured, government-run competitions with real infrastructure access at the finale
  stage, rather than informal pilots
  ([aninews.in](https://aninews.in/news/national/general-news/gujarat-police-to-host-countrys-largest-ai-based-cctv-hackathon20260817135250/),
  [openthemagazine.com](https://openthemagazine.com/india/can-80000-cameras-think-as-one-inside-gujarat-polices-mega-ai-hackathon)).
  This is useful context for what "winning" tends to lead to in this state's current pattern — structured
  follow-on competition/pilot stages — but it is evidence about a *different* hackathon, not a documented
  next step for KANAD S.H.I.E.L.D. specifically.

## 6. What judges at KANAD S.H.I.E.L.D. 2026 are likely to reward

- **No published judging rubric or criteria exists** for KANAD S.H.I.E.L.D. 2026 in any source found, including
  the organiser's own site (kanadshield.com's "How It Works" page lists process steps, not scoring criteria).
- **No prior "KANAD S.H.I.E.L.D." edition was found.** The nearest confirmed predecessor is a distinct, earlier
  **Ahmedabad Cyber Crime Branch hackathon in March 2023** (registration 16–23 March 2023, "12 major
  challenges") ([cyberyodha.org](https://www.cyberyodha.org/2023/03/ahmedabad-cyber-crime-branch-has.html)) —
  ⚠️ UNVERIFIED whether this 2023 event is formally the same series under a different name, or an unrelated
  predecessor; no winners or judging criteria for it were located either. **Do not claim to know what won
  KANAD S.H.I.E.L.D. before**, because there is no confirmed prior KANAD S.H.I.E.L.D. to reference.
- **Full problem-statement list, fetched directly** (kanadshield.com/category-2.html and about.html, 18 Aug
  2026) — for context on the field NetForensiq is competing within:
  - **Category 1** (16 PS): Big Data Analysis Tool; CallGuard (spam-call detection); CellScope (cell-ID
    finder); CryptoTrack; DARKTRACE (dark-web surveillance); Mule Bank Account Detection; ForensiX (mobile
    forensics); IntelliBank; Mobile Hygiene Guardian; SafeInbox; SIMScanner; SMIntelliTrack; TeleScan AI;
    TruthShield (fake news/deepfakes); VisionScan (CCTV analysis); VoiceInsight.
  - **Category 2** (10 PS): Crime Hotspot Mapping; CrimeGPT; Cyber Safety for Children; Cyber-Aware Safety for
    Senior Citizens; Cyber-Integrated Safety for Women; Health & Wellness Monitoring for Police Personnel;
    **Network & Packet Forensics Platform**; Open-Ended Innovation Platform; Real-Time Data Breach Alert
    System; Unified Legal & Government Intelligence Platform.
  - The **Academic Partner** credited on the site is unnamed in the fetched HTML beyond a generic "Academic
    Partner" label with logo; combined with the venue description ("i-Hub Gujarat, ... KCG Campus"), this is
    consistent with **Karnavati University / its incubator KIIF** being the academic/venue partner
    ([kiif.org](https://kiif.org/)), but this specific relationship is ⚠️ UNVERIFIED — not stated explicitly on
    any fetched page.
- **The best available signal on organiser priorities** is the shape of the problem statements themselves:
  heavy weighting toward citizen-protection framing (children, senior citizens, women — three of ten Category
  2 statements), financial/mule-account/crypto tracing (four of sixteen Category 1 statements), and
  officer-welfare (health monitoring for police personnel is itself a Category 2 problem statement) — i.e., the
  organisers are explicitly rewarding solutions that connect to **victim protection and officer welfare
  narratives**, not only raw technical capability. NetForensiq's pitch has an opening to connect to this if it
  frames evidence integrity as protecting *victims'* eventual case outcomes (a case dismissed for
  broken chain-of-custody is a victim denied justice), not only as an investigator-efficiency tool.

---

## Claims we should NOT make

- **"BSA/the Schedule mandates dual-hashing (MD5 + SHA-256)."** False. The Schedule offers a checklist of
  algorithm options (SHA1/SHA256/MD5/Other) for the certifying officer to select and report; it does not
  require more than one. [SPEC_01](SPEC_01_EVIDENCE_INTEGRITY.md) already documents this correctly — do not let
  a "do this" item (add an MD5 field, item 3 above) drift into a false "the law requires it" claim in the
  pitch. Frame it as matching the form's options, not complying with a mandate.
- **"A Gujarat court has already ruled on network/packet-capture evidence."** Not found. Every Gujarat and
  national certificate-requirement ruling located in this pass concerns audio, CDR, WhatsApp, or video
  evidence — never packet capture. Say "designed for the certificate regime these rulings establish," not "a
  court has already dealt with evidence like ours."
- **"The Gujarat High Court's AI policy governs/validates NetForensiq's design."** The policy explicitly
  governs judicial and court-administration use of AI, not investigative tooling used by police pre-trial. The
  parallel drawn in "Do this" item 2 is a persuasive analogy for a pitch, not a description of an applicable
  rule — do not imply the High Court has reviewed or endorsed anything about this product.
- **"Shree Cyber Suraksha" as a real, specifically-named Gujarat Police programme.** Not confirmed to exist
  under that name in any source found in this pass. Do not build a slide referencing it without independent
  confirmation from the team's own contacts.
- **"There is a named post-hackathon programme (e.g. a 'Gujarat Police Innovation Cell') for winners to join."**
  Not found. Only generic "pilot deployment / investor / procurement channel" marketing language exists.
- **"NetForensiq addresses Gujarat's cybercrime problem" (broadly stated).** The caseload data says otherwise
  by a wide margin — financial fraud, mule accounts, and social engineering dominate by orders of magnitude
  over anything network-forensics would touch. Say "the evidence-integrity layer for the network-evidence
  subset of Gujarat's caseload," not "Gujarat's cybercrime problem."
- **"Gujarat mandates a Gujarati-language interface for police software."** No such mandate was located for
  internal/analyst-facing law-enforcement tools specifically; GIGW's multilingual requirement is documented
  for citizen-facing government *websites/service delivery*, and its extension to an internal LEA tool is
  unverified. Don't claim a compliance obligation that wasn't found.
- **"KANAD S.H.I.E.L.D. has a known judging rubric," or any claim about what won a "prior KANAD S.H.I.E.L.D.
  edition."** No rubric and no confirmed prior edition under this exact name were found. If asked, say this
  honestly rather than inventing a precedent.
- **The 8 May 2026 Justice Doshi ruling's case name/citation.** Not confirmed beyond a secondary legal-news
  aggregator; do not cite a case number that hasn't been independently verified against a primary source or
  LiveLaw/SCC Online/Indian Kanoon.

---

## Sources (consolidated)

- Gujarat HC electronic-evidence ruling (May 2026): https://lawyerenews.com/legal_detail/secondary-electronic-evidence-inadmissible-without-mandatory-certificate-sending-to-fsl-before-deciding-admissibility-is-patent-illegality-gujarat-high-court , https://lawyerenews.com/legal_detail/fsl-probe-before-electronic-evidence-meets-section-65b-admissibility-standards-gujarat-high-court , https://www.livelaw.in/high-court/gujarat-high-court/gujarat-high-court-monthly-digest-536445 (checked, not listed there)
- Gujarat HC AI Policy (Apr 2026): https://taxguru.in/corporate-law/gujarat-hc-issues-policy-ai-judicial-court-administration.html , https://gujarathighcourt.nic.in/hccms/sites/default/files/miscnotifications/Policy%20on%20the%20use%20of%20Artificial%20Intelligence%20in%20the%20Judicial%20and%20Court%20Administration.pdf , https://lawyerenews.com/legal_detail/gujarat-high-court-bans-ai-from-judicial-decision-making-lays-down-strict-policy-for-court-use-of-artificial-intelligence , https://www.verdictum.in/columns/policy-on-the-use-of-artificial-intelligence-gujarat-high-court-1613405
- Pooranmal v. State of Rajasthan (2026 INSC 217): https://www.casemine.com/commentary/in/pooranmal-v.-state-of-rajasthan-(2026-insc-217)-%E2%80%94-mandatory-section-65-b-certification-and-strict-chain-of-custody-as-preconditions-for-reliance-on-cdr-fsl-in-circumstantial-murder-trials/view
- SARAS Courts / e-communication rules: https://gujarathighcourt.nic.in/hccms/sites/default/files/rules_files/Government%20Gazette%20-%2024032026%20-%20The%20Gujarat%20High%20Court%20Rules%20for%20seamless%20functioning%20of%20SARASCourts%20-StateWide%20Access%20to%20Remote%20Adjudication%20System-%202026.pdf , https://gujarathighcourt.nic.in/hccms/sites/default/files/rules_files/The%20District%20Courts%20of%20the%20Gujarat%20States%20for%20the%20Use%20of%20Electronic%20Communication%20and%20Audio-Video%20Electronic%20Means%20Rules,%202025.pdf
- BSA §63 Schedule / hash checkboxes: https://chat2evidence.in/public/pages/section-63-bsa-certificate-template , https://corpotechlegal.com/admissibility-electronic-evidence-sec-63-bsa/ , https://indianlawlive.net/2025/06/29/sakshya-adhiniyam-doesnt-mandate-hashing-copy-pen-drive-or-cd-produced-it-mandates-hashing-original-only/ (and SPEC_01_EVIDENCE_INTEGRITY.md, already-verified primary quote)
- FSL/chain-of-custody generic (not Gujarat-specific): https://www.legalserviceindia.com/Legal-Articles/the-digital-forensic-investigation-process-chain-of-custody-and-evidence-preservation/ , https://advocategandhi.com/fsl-report-in-cyber-crime-cases-the-silent-witness-behind-every-digital-offence/
- DFS Gujarat: https://dfs.gujarat.gov.in/dfsl/default.aspx (also in research/01)
- "Shree Cyber Suraksha" search / Cyber Suraksha Kavach: https://gujaratcybercrime.org/eng/raj_kumar.html , https://www.statusin.in/10207.html , https://surakshasetu.org/
- GIGW 3.0: https://guidelines.india.gov.in/introduction/ , https://accordcompliance.org/regulations/india/gigw-3.0 , https://www.skynettechnologies.com/blog/gigw-3-0-government-website-accessibility-in-india
- GIL / Gujarati software standards: https://gil.gujarat.gov.in/Media/GRDocument/gr_tsp.-25pdf.pdf (snippet-only, PDF unparseable), https://dst.gujarat.gov.in/Home/gjstateititespolicy
- Gujarat State Data Center: https://dst.gujarat.gov.in/Home/GujaratStateDataCenter , https://guj.nic.in/en/infrastructure/ , https://guj.nic.in/en/service/data-centres/
- GeM: https://gem.gov.in/ , https://www.startupindia.gov.in/content/sih/en/public_procurement.html
- KANAD S.H.I.E.L.D. site (fetched directly 18 Aug 2026): https://kanadshield.com/ , https://kanadshield.com/category-2.html , https://kanadshield.com/about.html , https://kanadshield.com/timeline.html , https://kanadshield.com/how-it-works.html
- KANAD S.H.I.E.L.D. / CyberShield third-party listing: https://fundsforcompanies.fundsforngos.org/events/startup-police-cybersecurity-innovation-program-cybershield-ahmedabad-india/
- 2023 Ahmedabad Cyber Crime Branch hackathon (possible predecessor, unconfirmed link): https://www.cyberyodha.org/2023/03/ahmedabad-cyber-crime-branch-has.html
- Karnavati Innovation and Incubation Foundation: https://kiif.org/
- Gujarat Police Innovation Challenge 2026 (separate, concurrent event): https://aninews.in/news/national/general-news/gujarat-police-to-host-countrys-largest-ai-based-cctv-hackathon20260817135250/ , https://openthemagazine.com/india/can-80000-cameras-think-as-one-inside-gujarat-polices-mega-ai-hackathon , https://www.prokerala.com/news/articles/a1801331.html
