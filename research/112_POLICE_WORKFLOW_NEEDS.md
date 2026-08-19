# 112 — What would make a Gujarat cybercrime IO say "this saves me hours every week"

*Compiled 19 August 2026. Continues a prior pass that broke off after locating one primary
source — a dated, signed, rank-attributed investigation checklist issued by a Superintendent
of Police (Cyber) — and a Jharkhand SOP. Both are now fully read and quoted below, alongside
four more primary SOPs found in this pass (Kerala Police, Delhi FSL, a Gujarat-hosted
financial-cybercrime SOP, and BPRD training material). Every claim below carries a URL or is
explicitly marked as an inference/unverified. Where a number could not be corroborated in a
primary document, that is stated directly rather than filled in.*

---

## VERDICT

**The single most useful thing this product could add is not a better certificate — it is
auto-assembling the paperwork that surrounds the certificate.** Read the checklist a real Cyber
Crime SP issued to his own staff (quoted in full below): the problems he names first are not
"we lack forensic tools" but *"not able to arrange the case file,"* *"hesitations to finalize
the investigation,"* *"fear to prepare Final Report,"* and *"no idea about the Investigation
Check-list to finalize"* — i.e., an experienced cyber IO's stated daily pain is clerical
assembly and paperwork anxiety, not evidence capture. NetForensiq already produces a BSA
§63 certificate and a hash-chained custody log for a network-evidence exhibit — that is a real,
narrow, already-built strength. What it does not yet do is turn that same exhibit record into
the two artefacts every SOP found in this research independently names as mandatory and
currently hand-typed: (1) a **forwarding-letter/FSL-form draft** carrying the exhibit's case
number, seizure details and hash, and (2) a **Memo of Evidence / List of Documents table** —
the exact structure the SP's own checklist specifies line-by-line — auto-populated from data
NetForensiq already holds. This is a small, honest, non-overclaiming extension: it uses fields
already in the exhibit model, it does not pretend to solve financial-fraud investigation (which
is the overwhelming majority of Gujarat's actual caseload — see §4), and it targets a
pain point independently documented by a working SP, not one a hackathon team invented.

---

## 1. SOP / checklist findings, quoted

### 1a. The primary find: a Cyber Crime SP's own investigation checklist (Puducherry)

**Source (primary, government, dated, rank-attributed):**
`https://police.py.gov.in/Cyber%20Crime%20-%201%20Investigation%20check%20list%20by%20Dr%20Bascarane%20SP%20Cyber%20dt%2014.02.24.pdf`
— "CYBER CRIME – INVESTIGATION GUIDELINES," Cyber Crime Cell, No.151/SP(Cyber)/2024,
O/o the SP (Cyber Crime), Puducherry, dated 14.02.2024, issued by **Dr. S. Bascarane, PPS,
SP (Cyber/Wireless/CCTNS/WIM), Puducherry**, explicitly marked *"This issued with the approval
of DGP."* This is exactly the class of document the brief asked for: a real, dated, named,
approved-by-DGP checklist an SP circulated to his own investigating officers.

The document opens by naming the *actual observed failure modes* among IOs — not hypothetical
ones:

> "1. Collecting data from social media / Telecom / Internet Service providers
> 2. Not able to arrange the case file / enquiry file
> 3. Hesitations to finalize the investigation / enquiry
> 4. Fear to prepare Final Report
> 5. No idea about the Investigation Check-list to finalize
> 6. Needy action on Social Media ID (Hacking / Fake creation)
> ...
> 11. Updating / Sensitizing complainant on the status of his complaint."

It then gives numbered checklists per crime type. **Online Financial Fraud checklist** (the
dominant caseload — see §4), quoted in full:

> "1. FIR / NCRP Registration
> 2. Complaint copy
> 3. Complainant payment details with time stamping
> 4. Accused Account details & Website address
> 5. 65-B Certificate on the screen prints for proof of crime.
> INVESTIGATION
> 6. GO through the SOP issued by DIG.
> 7. Identifying route of crime [mobile number / social media / URL / web-app link]
> 8. Transaction details from the accused account obtained from NCRP Portal
>    A. Layer 1 – Accused account / B. Layer 2 – Amount disposal / C. Layer 3 / D. Layer 4
> 9. Data request from Service Providers [bank KYC, transaction details, social media, ISP/TSP]
> 10. Receipt of reports from Social Media Service Provider.
> 11. Blocking [Letter to Banks to block/Lien mark; Letter to I4C to block URL; Letter to
>     Service Provider to block Mobile/IMEI/User ID]
> 12. Tracking accused [IP mapping from bank/social media, GPS mapping, email log IP]
> 13. Statement of the complaint / Witnesses.
> 14. List of Documentary evidence
> 15. Memo of evidence"

The **"Arranging of Case Files"** section is the clearest documented statement of the clerical
burden — it specifies that every case file must be assembled as a chronological "CD" (case
diary) bundle:

> "3. First CD — A. Rough work sheet of the IO / B. Statement of the Complainant & Victim /
> C. Statement of other witnesses / D. Crime Details Form / E. Documentary evidences including
> NCRP portal findings / F. Request sent / G. Reports received / H. Other
> 4. Second CD [repeat] ... 5. Continue"

And the **Memo of Evidence** table this document specifies, verbatim, is a fixed three-row
structure any exhibit-tracking system could generate mechanically:

| SN | Name and Address | Evidence |
|---|---|---|
| 1 | Complainant | Occurrence, lodging of complaint, submission of documents and other related facts |
| 2 | IO / EO | To speak about registration of FIR, investigation and other facts |
| 3 | Nodal Officer / Manager etc. | To speak about Bank Statement, CDR, CAF, IPDR etc. and connected facts |

The **Final Report** section gives the exact four-paragraph structure the SP expects for an
Action Drop / Mistake-of-Fact report:

> "Para-1. Reproducing the DOR @ Gist of the offence. Para-2. Brief on the Investigation so
> far conducted. Para-3. Views of the IO and reason there on for action drop... Para-4.
> Requesting court to consider the facts in issue and to treat the investigation as AD/MF..."

It also carries a confidential nodal-officer contact sheet (FB/WhatsApp/Twitter/Telegram/
Google/LinkedIn legal-request emails; Jio/Airtel/Vodafone/BSNL LEA-nodal emails) that the IO
is expected to look up and copy into a letter by hand each time.

### 1b. Jharkhand SOP for Cyber Crime Investigation (Judicial Academy Jharkhand)

**Source:** `https://jajharkhand.in/wp/wp-content/uploads/2019/10/02_sop_english.pdf`
(also referenced by the Gujarat-hosted SOP below as one of its two source documents). The
**official Jharkhand Police Cyber Crime Investigation Manual** also exists at
`https://jhpolice.gov.in/sites/default/files/documents-reports/jhpolice_cyber_crime_investigation_manual.pdf`
but could not be parsed in this pass (file exceeded the fetch tool's size limit); its existence
and title are confirmed, its contents were not verified.

The Judicial Academy SOP gives the actual **seizure/Panchnama guidelines**:

> "SEIZURE MEMO [PANCHNAMA] AND SEIZURE PROCEEDINGS ... The time zone/system time plan plays
> a very important role... it should be ensured that the correct time is marked when the
> system is [in] switch on mode along with its 'hash value'. If the system is found switched
> off, it should not be switched on. It should be ensured that the serial number which is
> found on the system is also recorded in the Panchnama, so that the chain of custody is not
> broken."

And the **Digital Evidence Collection (DEC) Form** field list — the fields an officer must
write out by hand for every seized item:

> "Crime Number / Section of law involved / Date [when generated or sent to lab] / Name of the
> Investigating Officer / Address [location of collection] / Equipment type / Manufacturer /
> Model No. / Serial number / Preserving hash value and maintaining chain of custody."

And the **forwarding-to-forensic-lab checklist**:

> "WHEN THE INVESTIGATING OFFICER FORWARDS THE COLLECTED ELECTRONIC EVIDENCE FOR FORENSIC
> ANALYSIS... The electronic evidence should accompany: Brief history of the case and the DEC
> form. The details of the exhibits seized and their place of seizure. The model, make and
> description of the hard disk... The date and time of visit... The condition of the computer
> system (on or off)... Is the photograph of the place of occurrence taken?... All electronic
> evidences must be examined by the examiner of electronic evidence notified under Section
> 79A IT Act 2000. All columns in the charge sheet must be filled carefully and the original
> documents and seized articles must accompany the charge sheet."

It also spells out the two-certificate trap on bank evidence that IOs routinely miss —
Bankers' Books Evidence Act §2A/4 certification **and** a separate §65B(4) certificate are
both required if a bank statement is a computer printout:

> "In such circumstances where the statement of account is obtained by computer printout it
> will also be mandatory to take a certificate separately under the provisions of Section 65B
> (4) [of] the Indian Evidence Act, 1872."

### 1c. Kerala Police SOP — Digital Evidence (crimes against women & children)

**Source:** `https://keralapolice.gov.in/storage/pages/custom/ckFiles/file/7GafuMCjLbFgjBNh8aXz8WhLv2Zqtfczvbi7Uv6m.pdf`
— issued 29-04-2021, signed **Loknath Behera IPS, DGP & State Police Chief, Kerala**, prepared
by ADGP Crimes, a DIG and an Addl. SP, Hi-Tech Cell. This is the most operationally detailed
of the primary sources found: it is a five-step evidentiary workflow (Identification →
Collection → Examination → Preservation → Presentation) with device-specific procedures.

Mobile-phone seizure procedure, quoted:

> "If the device is 'OFF', do not turn 'ON'. With PDAs or cell phones, if device is ON, leave
> ON. Powering down device could enable password, thus preventing access to evidence.
> Photograph device and screen display... Label and collect all cables (including power
> supply) and transport with device. Keep the device charged. If device cannot be kept
> charged, analysis by a specialist must be completed prior to battery discharge or data may
> be lost."

CCTV/DVR seizure is given as an explicit 13-point **"Checklist"** (the document uses that
exact word as a heading) — items include noting make/model/camera count, comparing system
clock against real time, determining the retention/overwrite window before data is lost,
and a direct statement that the officer "can seize the entire DVR/NVR (preferable due to
proprietary software), or can collect the relevant part of recording from the
owner/operator/technician along with a 65 B(4) Certificate."

On hash verification specifically — the exact check a network-forensics tool already performs
automatically, but which Kerala's SOP describes as a manual step for physically seized media:

> "An identical hash value of the original evidence seized under panchanama (Seizure Memo)
> and[,] the forensically imaged copy, helps the IO to prove the integrity of the evidence."

### 1d. Delhi FSL — "Guidelines for Forwarding Crime Exhibits"

**Source:** `https://cdnbbsr.s3waas.gov.in/s3ec02bd85282513da4089c441926e1975/documents/circular/GUIDELINES_FOR_FORWARDING_CRIME_EXHIBITS_1__2.pdf`
— Forensic Science Laboratory, Govt. of NCT of Delhi, Rohini. **This is a Delhi document, not
a Gujarat one** — no Gujarat FSL (Gandhinagar) equivalent was found publicly, confirming the
prior research pass's finding in `99_GUJARAT_FIT.md` that Gujarat FSL has no locatable
published intake SOP. Delhi's document is used here only as an illustration of what an FSL
forwarding form generally requires, not as evidence Gujarat's form is identical.

General forwarding rule (applies to all exhibit types):

> "13.6. A duly filled forwarding letter (FSL form), an attested copy of FIR, seizure memo,
> postmortem report, transcription (for speaker identification), sample seal and other
> relevant documents must be enclosed with the parcels for submission of the case in the
> laboratory."

The **Computer Forensic Unit** section (digital exhibits specifically: hard disks, SIM cards,
memory cards, pen drives, CDs/DVDs, CCTV, mobile phones) gives the "Formal requirement from
Forwarding authorities":

> "1. The original digital exhibits... should be properly preserved in bubbled bag... 2.
> Detached Battery from Mobile Phones/Laptop etc. before packing/sealing. 3. Small size
> exhibits... preserved in small plastic box... 4. The investigation should mention specific
> nature of examination required. 5. The investigation should deposit the documents in
> closed/sealed envelope along with duly filled FSL Forms and blank Hard Disk/Storage Device
> of similar or higher storage capacity for preparation of image copy required in
> examination."

**Important nuance for scope-fit:** this list is built entirely around *physically seized
media* (a hard disk, a SIM card, a DVR). It has no line item for "network capture already in
digital custody with no physical device seized" — which is exactly NetForensiq's evidence
type. This is an **inference, not a documented fact**: it plausibly means a PCAP exhibit does
not travel the FSL-forwarding physical-parcel route at all, and instead needs an expert-opinion
referral (BSA equivalent of old Evidence Act §45A, examiner of electronic evidence under IT
Act §79A) rather than an FSL parcel. No primary document confirms which route Gujarat FSL
actually uses for a pure network-capture exhibit; treat this as an open question worth asking
a real Gujarat cyber IO directly, not a settled fact to pitch on.

### 1e. Gujarat-hosted SOP: "Handling Financial Cybercrimes" (CAWACH, Govt. of Gujarat)

**Source:** `https://cawach.gujgov.edu.in/assets/documents/sop/cyberAwareness/Handling_Financial_Cyber_Crimes.pdf`
— August 2022. **CAWACH ("Cybersecurity Awareness And Creative Handholding Kendra") is a
Higher & Technical Education Department initiative (with Home Department collaboration),
aimed primarily at college-student cyber-hygiene awareness — it is not the Cyber Crime
Branch's own operational manual**, and its own footnotes cite the Jharkhand SOP (§1b above)
and a "Cyber Crime Investigation Manual by Data Security Council of India, Nasscom and
Deloitte India" as its sources. It is, nonetheless, the closest thing to a Gujarat-government
cyber-investigation document found in this research, and its Investigative Procedures section
(§6) is a compact, citable restatement of the seizure/chain-of-custody rules above, including:

> "A seizure memo or Panchanama must be drawn up under Sec.165 CrPC read with Sec.80 ITA. A
> technical expert who can properly identify the equipment and sound advice to the IO should
> accompany the search and seizure. The panchanama must record timezone/system time along
> with the system's hash value and serial number."

It also names two **existing citizen/officer-facing tools already in use for tracing** —
relevant to §5 below, i.e. things this project must not propose rebuilding:

> "Where money has been withdrawn using UPI, UTR details can be entered on
> cybercell.phonepe.com portal, where beneficiary details will be provided in 24 hours."
> "...information regarding service providers of the sender can be found on
> smsheader-trai-gov-in/" [TRAI's SMS header registry, for tracing SMS senders]

### 1f. BPRD training material (found, not deep-extracted)

BPRD (Bureau of Police Research & Development) hosts several relevant PDFs, located but not
fully parsed in this pass — listed for the next research cycle:
- "Investigation of Cyber Crime Cases (10 Days)" training-day schedule:
  `https://bprd.nic.in/WriteReadData/userfiles/file/2380118601-Investigation%20of%20Cyber%20Crime%2010%20days.pdf`
- "Investigative workflow Manual — Cyber Harassment Cases":
  `https://bprd.nic.in/WriteReadData/News/BPRD%20Cyber%20harassment%20cases%206-3-21.pdf`
- "Capacity Building at PS Level in Cyber Crime Investigation":
  `https://bprd.nic.in/uploads/pdf/201703011131097856883Revised-CapBldgatPSLevelinCYBERCRIMEINVESTIGATION.pdf`
No BPRD document titled exactly "Cyber Crime Investigation Manual" was located — that specific
title, if it exists, was not found in this pass.

### What was searched for but not found

- **No Gujarat CID Crime– or Ahmedabad Cyber Crime Branch–authored investigation manual or
  checklist** was found publicly (consistent with `99_GUJARAT_FIT.md`'s earlier finding that
  Gujarat FSL has no locatable published SOP either).
- **No official 65B(4)/§63(4) certificate *template/form*** (as opposed to the legal
  requirement) was found for any state, Gujarat included — every SOP above describes what the
  certificate must contain, none publish a fillable form.
- **Mizoram SOP for Cyber Crime Investigation v1.0** — URL found via search
  (`police.mizoram.gov.in/wp-content/uploads/2023/01/SOP-Cyber-Crime-Investigation-v1.0.pdf`)
  but returned HTTP 404 when fetched; not verified.
- **Maharashtra Cyber cell's own SOP manual** — not located as a standalone public PDF in this
  pass (only secondary references to its existence).

---

## 2. What this converts to: manual work and what software could remove

| Manual task today | Source naming it | Plausible time cost (inference) | What a tool could auto-generate |
|---|---|---|---|
| Typing the FSL/forwarding-letter cover sheet by hand for every exhibit sent for analysis | Delhi FSL §13.6, Computer Forensic Unit item 5 (§1d) | 15–30 min/exhibit (inference — no primary source times this) | Pre-filled draft from exhibit's case number, FIR number, hash, seizure date/time already in the exhibit record |
| Assembling the "Memo of Evidence" table (who will testify to what) | Puducherry SP checklist, item 15 / dedicated table (§1a) | 10–15 min/case (inference) | Mechanical fill of the 3-row template from complainant/IO/nodal-officer fields already on file |
| Chronologically arranging the case file into "CD1, CD2..." bundles | Puducherry SP checklist, "Arranging of Case Files" (§1a) — named as the IO's #1 observed failure mode | Hours per case, recurring (SP's own framing: staff are *"not able to"* do this, not merely slow at it) | Auto-ordered exhibit/document index generated from timestamped records already in the system — **but only for the network-evidence documents NetForensiq itself holds**, not the whole case file (witness statements etc. live outside this tool) |
| Recording the ~19-field CCTV/DVR system metadata (make, model, camera count, clock offset, retention window, password) | Kerala SOP CCTV Checklist (§1c); Delhi FSL §2.2.1–2.2.19 (near-identical list, independently authored) — two states converging on the same ~19 fields is itself evidence this is a real, recurring paperwork task | 20–40 min per CCTV seizure (inference) | A guided in-app form with these exact fields — **out of current NetForensiq scope** (physical DVR seizure, not packet capture) |
| Looking up and typing nodal-officer emails for banks/telcos/platforms into each request letter | Puducherry SP's own confidential contact sheet (§1a) exists precisely because officers don't have this memorised | 5–10 min/request, multiplied by requests-per-case | Template letters with contact fields — **high staleness risk**: Puducherry's own list is state-specific and dated; a Gujarat product must source Gujarat's own current nodal list, not copy Puducherry's |
| Verifying the panchnama-recorded hash matches the forensic-image hash | Kerala SOP (§1c) | Minutes, but skipped/mis-done is a real admissibility risk | **Already solved for network evidence** by NetForensiq's existing hash-chained custody log — worth stating as a strength, not a gap |
| Structuring the 4-paragraph Action-Drop/Mistake-of-Fact report | Puducherry SP checklist (§1a) | 20–40 min/report (inference) | Structural scaffold (para headers, auto-filled DOR/gist from FIR) — **must not auto-draft the legal reasoning in Para-3 ("Views of the IO")**, only the skeleton |

---

## 3. Prioritised feature table

| Candidate feature | Manual work removed | Evidence it is a real pain point (source) | Build effort | Risk of overclaiming |
|---|---|---|---|---|
| **Auto-draft FSL/forwarding-letter fields from the exhibit record** | Hand-typing case no., FIR no., exhibit description, hash, seizure date onto a cover letter each time | Delhi FSL §13.6 and Computer Forensic Unit item 5 both make a "duly filled forwarding letter/FSL Form" a hard prerequisite for lab intake (§1d) | **S** — every field already exists in NetForensiq's `Section63Certificate`/exhibit models | **Medium.** No Gujarat FSL form was found, so this must ship as a generic, editable draft, explicitly labelled "not an official Gujarat FSL form" — and it's unverified whether a pure-PCAP exhibit even goes through physical FSL forwarding at all (see §1d nuance) |
| **Auto-generate the Memo of Evidence table** | Manually re-deriving "who testifies to what" for the charge sheet | Puducherry SP checklist names this the final, mandatory step of every investigation checklist, with a fixed 3-row template (§1a) | **S** — mechanical fill of a fixed table from data already on file | **Low.** Reproducing a public table structure, not asserting anything about the case |
| **Structural scaffold for the Final Report / Action-Drop paragraph set** | Officer-named fear: *"Fear to prepare Final Report"* (§1a, item 4 in the SP's own list of observed staff struggles) | Puducherry SP checklist gives the exact 4-paragraph structure verbatim | **M** | **High if mishandled.** Must generate headers/skeleton only — auto-drafting "Views of the IO" (legal reasoning) would be a serious overclaim and a genuine liability if wrong |
| **CCTV/DVR seizure metadata checklist (guided form)** | Recreating a ~19-field checklist from memory each seizure | Two independent SOPs (Kerala §1c, Delhi FSL §1d) converge on nearly the same field list | **M–L** | **High scope risk.** This is physical-device seizure, outside NetForensiq's packet-capture scope — building it would be a genuine pivot, not an extension |
| **Nodal-officer request-letter templates (bank/ISP/platform blocking requests)** | Looking up emails and retyping boilerplate for each of 3–5 requests per financial-fraud case | Puducherry SP checklist step 11 ("Letter to Banks... Letter to I4C... Letter to Service Provider") appears in both the social-media and financial-fraud checklists (§1a) | **S–M** | **High.** Contact lists go stale fast (Puducherry's own is dated, marked confidential); shipping wrong/outdated Gujarat nodal emails is worse than not shipping the feature. Also drifts outside "network forensics" positioning |
| **Bankers' Books Evidence Act §2A/4 + §65B dual-certificate reminder** | Missing the second certificate on bank-statement printouts, which Jharkhand's SOP flags as a common trap (§1b) | Directly quoted from Jharkhand SOP (§1b) | **L** | **Very high.** Requires correctly handling a different Act (Bankers' Books Evidence Act) for a different evidence type (bank statements) NetForensiq does not currently ingest — real scope creep, and legal accuracy risk if done sloppily |

---

## 4. The caseload reality (why this must stay a narrow claim)

- **National, NCRB 2023:** 86,420 registered cyber-crime cases; **~68.9% (59,526 cases)
  fraud-motive**, 4.9% sexual exploitation, 3.8% extortion
  [[TechObserver/NCRB](https://techobserver.in/news/egov/cybercrime-cases-in-india-rose-31-in-2023-fraud-accounted-for-most-incidents-ncrb-317418/)].
- **National, NCRB 2024** (already verified in this project's `03_gujarat_cybercrime_landscape.md`):
  101,928 cases, **72.6% (73,987 cases) financial fraud**
  [[Vajiram & Ravi](https://vajiramandravi.com/current-affairs/crime-in-india-2024/)].
- **Gujarat, registered FIRs:** 1,995 (2023) → 1,592 (2024), a >20% *decline*, even as NCRP
  complaint volume rose
  [[Gujarat Samachar/NCRB](https://english.gujaratsamachar.com/news/gujarat/ahmedabad-cyber-crimes-surge-61-in-2024-amid-statewide-decline-ncrb-37168049478.html)]
  — already documented in this project's own research.
- **Ahmedabad city, 2024:** 396 cases, of which 57% (229) cheating/forgery, only 36
  "computer-related offences," 30 identity theft [same source as above].
- **No NCRB table isolates "network intrusion" as a distinct, state-level reportable
  category.** The closest national proxy — "computer related offences" under IT Act §66 — is
  itself dominated by cheating-by-personation rather than technical intrusion, per secondary
  reporting on the NCRB 2023 table (cheating-by-personation cases nearly doubled from 13,506
  to 25,334 nationally, driving 60% of the year's cybercrime growth)
  [[TechObserver](https://techobserver.in/news/egov/cybercrime-cases-in-india-rose-31-in-2023-fraud-accounted-for-most-incidents-ncrb-317418/)].
  **This figure is drawn from a secondary aggregator's summary of the NCRB table, not
  independently verified against the primary NCRB PDF in this pass — treat the exact split
  as an inference, not a hard number.**

**Plain statement:** network/packet-level intrusion is a small, likely low-single-digit-percent
slice of Gujarat's actual registered cybercrime caseload. The overwhelming majority is
financial fraud and social-engineering, which is a bank-KYC/transaction-tracing/mule-account
problem, not a packet-capture problem. This project should keep saying so, not soften it —
this project's own `99_GUJARAT_FIT.md` already reached the same conclusion independently.

---

## 5. Existing tools — do not propose rebuilding these

- **National Cyber Crime Reporting Portal (NCRP)** — `cybercrime.gov.in` — the central intake
  and transaction-layer-tracing system every SOP above assumes the IO already uses (§1a, §1e).
- **1930 helpline / Gujarat's Cyber Financial Fraud e-Zero FIR** (launched 27 July 2026) —
  already documented in `03_gujarat_cybercrime_landscape.md`.
- **I4C Cyber Fraud Mitigation Centre (CFMC)** — launched 10 Sept 2024, banks/telcos/IT
  intermediaries/state LEAs co-located for account-freeze/SIM-block coordination; by Dec 2024
  had frozen 8.67 lakh mule accounts and blocked 7 lakh SIMs
  [[Hackers4u/PIB summary](https://www.hackers4u.com/Why-Was-the-Cyber-Fraud-Mitigation-Centre-CFMC-Created-and-How-Does-It-Work)].
- **I4C Samanvay Platform** — MIS/data-repository/coordination layer for inter-state case
  linking [[Hackers4u](https://www.hackers4u.com/How-Does-the-Samanvay-Platform-Strengthen-India%E2%80%99s-Cybercrime-Response)].
- **I4C Suspect Registry** — shares Layer-1 mule-account/suspect identifiers with banks
  [same source].
- **cybercell.phonepe.com** — UPI/UTR-to-beneficiary lookup portal, named directly in the
  Gujarat CAWACH SOP as something an IO already uses (§1e).
- **TRAI SMS header registry** (`smsheader-trai-gov-in`) — for tracing SMS-sender service
  providers, also named directly in the Gujarat CAWACH SOP (§1e).
- **CCTNS Property Register Service** — already documented in this project's own
  `deep-research-report.md` as the existing (if unintegrated) module for physical seized-item
  tracking; a Jharkhand CCTNS tender specifically required tracking property status
  ("released/transferred to other PS/Lab/testing").
- **eSakshya** — mandated scene-video capture app under BNSS §105 — already extensively
  verified in this project's `deep-research-report.md` and `95_ESAKSHYA_VERIFIED_FINDINGS.md`;
  confirmed to stop at upload, with no post-seizure custody tracking — this project's own
  positioning ("falls between eSakshya and CCTNS") remains accurate and should not change.
- **Gujarat's own existing tech stack** (ASTR, VISHWAS, e-GujCop, NARIT AI) — already
  catalogued in `02_gujarat_police_existing_tech_and_ai.md`; none overlap with network-packet
  forensics or exhibit paperwork generation.

---

## 6. What would impress a judge but not an officer — and the reverse

**Impresses a judge, not an officer:**
- Cryptographic rigor of the hash chain, precision of BSA §63 statutory language, citing the
  exact *Kshitijbhai Manubhai Patel* Gujarat HC holding on certificate sequencing (already in
  `PROGRESS.md`) — none of this saves an IO a minute on a Monday morning. It matters at trial,
  months or years later, not during the investigation.
- The sophistication of the 9-rule detection engine — a judge (or a hackathon judge acting as
  a proxy for one) will find this technically impressive; an IO drowning in case-file assembly
  will not notice or care how the detection was done, only whether the output is admissible
  and the paperwork is ready.

**Impresses an officer, not a judge:**
- A pre-filled FSL forwarding-letter draft and Memo of Evidence table (§3) — genuinely saves
  clerical time every single case, but is invisible to a judge; it never becomes part of the
  evidentiary record itself, it just gets the record produced faster.
- Nodal-officer contact templates — pure time-saving, zero evidentiary weight.
- The CCTV/DVR metadata checklist — useful, but again purely a workflow aid with no bearing on
  what a court evaluates.

**The honest takeaway:** the certificate/chain-of-custody work already done is the
judge-facing half of the product. The paperwork-generation work identified in §3 is the
officer-facing half that is currently missing, and it is the half the SP's own checklist says
officers are actually struggling with.

---

## 7. What we must not claim

- **Must not claim this addresses the bulk of Gujarat's cybercrime caseload.** Per §4, network
  intrusion is a small slice; financial fraud dominates. Say this plainly, as this project's
  own `99_GUJARAT_FIT.md` already does.
- **Must not claim any of the SOPs above are Gujarat Police's own operational manual.** The
  Puducherry checklist is Puducherry's; the Jharkhand SOP is Jharkhand's; the Kerala SOP is
  Kerala's; the CAWACH document is a Gujarat Education-Department student-awareness resource
  that cites Jharkhand and a DSCI/Nasscom/Deloitte manual as its own sources, not an
  independent Gujarat Cyber Crime Branch product. **No Gujarat CID Crime– or Ahmedabad Cyber
  Crime Branch–authored investigation manual was located.**
- **Must not claim a Gujarat FSL forwarding-letter format was found.** None was. The Delhi FSL
  document is used here only to illustrate the general pattern; do not present it, or an
  invented equivalent, as Gujarat's actual form.
- **Must not claim network/packet evidence necessarily goes through the FSL physical-parcel
  forwarding route at all.** Per §1d, Delhi FSL's Computer Forensic Unit requirements are built
  around physically seized media; whether a pure PCAP exhibit (no physical device seized) uses
  this route, an expert-opinion referral, or something else in Gujarat is unverified — flag it
  as an open question for a real IO to answer, not a settled workflow to build against blindly.
- **Must not repeat the Gujarat FSL "45–180 day" turnaround figure as fact.** This project's
  own `99_GUJARAT_FIT.md` already found it to be a single, uncorroborated secondary claim —
  that finding stands; do not re-cite it as verified.
- **Must not claim a Gujarat court has ruled on network/packet-capture evidence specifically.**
  Per `99_GUJARAT_FIT.md`, every certificate ruling located (Gujarat or national) concerns
  audio, CDR, WhatsApp, or video — not packet captures.
- **Must not auto-draft the substantive legal reasoning of a Final Report** (the "Views of the
  IO" paragraph in the Puducherry template). Scaffolding structure is defensible; generating
  the actual investigative conclusion is not this product's place and is a liability if wrong.
- **Must not ship nodal-officer contact lists sourced from another state's confidential
  circular** (e.g., copying Puducherry's bank/platform emails and presenting them as current
  or Gujarat-applicable). If this feature is built, it needs Gujarat's own current list,
  sourced separately and kept current — stale contact data is worse than no feature.
- **Must not claim this replaces CCTNS's Property Register, eSakshya, or I4C's CFMC/Samanvay/
  Suspect Registry** (§5) — all already exist and already do the jobs they do.
