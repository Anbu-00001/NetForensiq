# SPEC 01 — Digital Evidence Integrity & Admissibility Layer (NetForensiq)

**Status:** DRAFT — living document, built incrementally during research.
**Scope:** Bharatiya Sakshya Adhiniyam (BSA) 2023 §63 electronic-evidence certificate, applied to a PCAP network-forensics tool.
**Non-goal:** This is a research/spec document only. No application code here.

**Primary source verified against:** Official bare-act PDF from indiacode.nic.in, fetched directly:
`https://upload.indiacode.nic.in/view-casepdf?type=act&id=AC_CEN_5_23_00049_2023-47_1719292804654`
(The Bharatiya Sakshya Adhiniyam, 2023 — Act No. 47 of 2023, assented 25 Dec 2023, in force 1 July 2024.)
Local copy retrieved and converted with `pdftotext -layout` for verbatim extraction; page/line references below are from that extraction.

---

## 1. Section 63 — Admissibility of Electronic Records

### 1.1 Verbatim text (§63(1)–(5))

Source: indiacode.nic.in bare act PDF, pages 29–31 (Act No. 47 of 2023).

> **63. Admissibility of electronic records.**—(1) Notwithstanding anything contained in this Adhiniyam, any information contained in an electronic record which is printed on paper, stored, recorded or copied in optical or magnetic media or semiconductor memory which is produced by a computer or any communication device or otherwise stored, recorded or copied in any electronic form (hereinafter referred to as the computer output) shall be deemed to be also a document, if the conditions mentioned in this section are satisfied in relation to the information and computer in question and shall be admissible in any proceedings, without further proof or production of the original, as evidence or any contents of the original or of any fact stated therein of which direct evidence would be admissible.
>
> (2) The conditions referred to in sub-section (1) in respect of a computer output shall be the following, namely:—
> (a) the computer output containing the information was produced by the computer or communication device during the period over which the computer or Communication device was used regularly to create, store or process information for the purposes of any activity regularly carried on over that period by the person having lawful control over the use of the computer or communication device;
> (b) during the said period, information of the kind contained in the electronic record or of the kind from which the information so contained is derived was regularly fed into the computer or Communication device in the ordinary course of the said activities;
> (c) throughout the material part of the said period, the computer or communication device was operating properly or, if not, then in respect of any period in which it was not operating properly or was out of operation during that part of the period, was not such as to affect the electronic record or the accuracy of its contents; and
> (d) the information contained in the electronic record reproduces or is derived from such information fed into the computer or Communication device in the ordinary course of the said activities.
>
> (3) Where over any period, the function of creating, storing or processing information for the purposes of any activity regularly carried on over that period as mentioned in clause (a) of sub-section (2) was regularly performed by means of one or more computers or communication device, whether—
> (a) in standalone mode; or
> (b) on a computer system; or
> (c) on a computer network; or
> (d) on a computer resource enabling information creation or providing information processing and storage; or
> (e) through an intermediary,
> all the computers or communication devices used for that purpose during that period shall be treated for the purposes of this section as constituting a single computer or communication device; and references in this section to a computer or communication device shall be construed accordingly.
>
> (4) In any proceeding where it is desired to give a statement in evidence by virtue of this section, a certificate doing any of the following things shall be submitted along with the electronic record at each instance where it is being submitted for admission, namely:—
> (a) identifying the electronic record containing the statement and describing the manner in which it was produced;
> (b) giving such particulars of any device involved in the production of that electronic record as may be appropriate for the purpose of showing that the electronic record was produced by a computer or a communication device referred to in clauses (a) to (e) of sub-section (3);
> (c) dealing with any of the matters to which the conditions mentioned in sub-section (2) relate,
> and purporting to be signed by a person in charge of the computer or communication device or the management of the relevant activities (whichever is appropriate) and an expert shall be evidence of any matter stated in the certificate; and for the purposes of this sub-section it shall be sufficient for a matter to be stated to the best of the knowledge and belief of the person stating it in the certificate specified in the Schedule.
>
> (5) For the purposes of this section,—
> (a) information shall be taken to be supplied to a computer or communication device if it is supplied thereto in any appropriate form and whether it is so supplied directly or (with or without human intervention) by means of any appropriate equipment;
> (b) a computer output shall be taken to have been produced by a computer or communication device whether it was produced by it directly or (with or without human intervention) by means of any appropriate equipment or by other electronic means as referred to in clauses (a) to (e) of sub-section (3).

Supporting provisions in the same chapter (verbatim, indiacode.nic.in, p.29):

> **61. Electronic or digital record.**—Nothing in this Adhiniyam shall apply to deny the admissibility of an electronic or digital record in the evidence on the ground that it is an electronic or digital record and such record shall, subject to section 63, have the same legal effect, validity and enforceability as other document.
>
> **62. Special provisions as to evidence relating to electronic record.**—The contents of electronic records may be proved in accordance with the provisions of section 63.

### 1.2 THE SCHEDULE — verified: Part A / Part B IS in the statute, not just commentary

**Answer to the critical question:** The Part A / Part B two-part certificate structure **is in the statute itself**, as **THE SCHEDULE** to the Act, expressly cross-referenced by §63(4)(c) ("...in the certificate specified in the Schedule."). The Schedule heading itself states `[See section 63(4)(c)]`. This is confirmed directly from the official indiacode.nic.in PDF (pp. 51–53), not from secondary commentary. It is also listed in the Act's own Table of Contents as "THE SCHEDULE" following Chapter XII (Repeal and Savings).

**Full field list, reproduced exactly (including checkbox options) from THE SCHEDULE:**

> ### THE SCHEDULE
> [See section 63(4)(c)]
> ### CERTIFICATE
>
> #### PART A (To be filled by the Party)
>
> "I, _____________ (Name), Son/daughter/spouse of _____________ residing/employed at _____________ do hereby solemnly affirm and sincerely state and submit as follows:—
>
> I have produced electronic record/output of the digital record taken from the following device/digital record source (tick mark):—
> Computer / Storage Media ☐  DVR ☐  Mobile ☐  Flash Drive ☐
> CD/DVD ☐  Server ☐  Cloud ☐  Other ☐
> Other: _____________
> Make & Model: _____________ Color: _____________
> Serial Number: _____________
> IMEI/UIN/UID/MAC/Cloud ID _____________ (as applicable)
> and any other relevant information, if any, about the device/digital record ____(specify).
>
> The digital device or the digital record source was under the lawful control for regularly creating, storing or processing information for the purposes of carrying out regular activities and during this period, the computer or the communication device was working properly and the relevant information was regularly fed into the computer during the ordinary course of business. If the computer/digital device at any point of time was not working properly or out of operation, then it has not affected the electronic/digital record or its accuracy. The digital device or the source of the digital record is:—
> Owned ☐  Maintained ☐  Managed ☐  Operated ☐
> by me (select as applicable).
>
> I state that the HASH value/s of the electronic/digital record/s is _____________, obtained through the following algorithm:—
> ☐ SHA1:
> ☐ SHA256:
> ☐ MD5:
> ☐ Other __________ (Legally acceptable standard)
> (Hash report to be enclosed with the certificate)
>
> (Name and signature)
> Date (DD/MM/YYYY): _____
> Time (IST): ____ hours (In 24 hours format)
> Place: _____________"
>
> #### PART B (To be filled by the Expert)
>
> "I, _____________ (Name), Son/daughter/spouse of _____________ residing/employed at _____________ do hereby solemnly affirm and sincerely state and submit as follows:—
>
> The produced electronic record/output of the digital record are obtained from the following device/digital record source (tick mark):—
> [same device checklist as Part A: Computer/Storage Media, DVR, Mobile, Flash Drive, CD/DVD, Server, Cloud, Other, with Make & Model, Color, Serial Number, IMEI/UIN/UID/MAC/Cloud ID fields]
>
> I state that the HASH value/s of the electronic/digital record/s is _____________, obtained through the following algorithm:—
> ☐ SHA1:
> ☐ SHA256:
> ☐ MD5:
> ☐ Other __________ (Legally acceptable standard)
> (Hash report to be enclosed with the certificate)
>
> (Name, designation and signature)
> Date (DD/MM/YYYY): _____
> Time (IST): ____ hours (In 24 hours format)
> Place: _____________"

**Implication for the implementation:** Because the Schedule is a *prescribed form* (not free text), a compliant "generate §63 certificate" feature should reproduce these exact fields and layout for Part A and Part B, not a paraphrase. This is the single most load-bearing finding for the tool's certificate-generation feature.

### 1.3 What the provision says about hash value / algorithm — quoted, precisely

The **operative text of §63(1)–(5) itself does NOT mention "hash" anywhere.** The word "hash" appears **only in THE SCHEDULE** (the prescribed certificate form), not in the statutory sub-sections that define admissibility conditions. This is an important distinction: hashing is a *certificate-form* requirement (how you attest), not a *statutory admissibility condition* under §63(2) (which is about regular use / regular operation / no tampering-affecting-malfunction — a business-records-style test, not a cryptographic one).

Exact quote, THE SCHEDULE, Part A and Part B (identical wording in both):

> "I state that the HASH value/s of the electronic/digital record/s is _________________, obtained through the following algorithm:— ☐ SHA1: ☐ SHA256: ☐ MD5: ☐ Other __________ (Legally acceptable standard) (Hash report to be enclosed with the certificate)"

**Algorithms explicitly named in the statute (Schedule): SHA1, SHA256, MD5**, plus an open "Other (Legally acceptable standard)" checkbox. **NOT VERIFIED / open question:** the Schedule does not define "legally acceptable standard" — there is no statutory list beyond these three named algorithms. Note MD5 and SHA1 are both cryptographically broken for collision-resistance (see NIST guidance, §4 below); the statute names them anyway as checkbox options, it does not endorse them as best practice. **Design recommendation (flagged [GOOD PRACTICE], not statutory):** compute and report SHA-256 as primary (it is one of the three named options and is NIST/FIPS-approved, still collision-resistant), and optionally MD5 alongside it purely because MD5 is explicitly enumerated in the Schedule and some officers/courts expect to see it — never MD5-only.

Also relevant, from the Statement of Objects and Reasons (indiacode.nic.in PDF p. 53, not part of the operative Act but part of the same official document): the Bill "seeks to expand the scope of secondary evidence to include ... oral accounts of the contents of a document given by some person who has himself seen it and giving matching hash value of original record will be admissible as proof of evidence in the form of secondary evidence" — confirming legislative intent that hash-matching is the mechanism referenced for secondary-evidence integrity, even though it's not written into the operative sub-sections of §63 itself.

### 1.4 Who must sign, and in what capacity

From §63(4) verbatim (see 1.1) and confirmed by the Schedule's two-part structure:

1. **"a person in charge of the computer or communication device or the management of the relevant activities (whichever is appropriate)"** — this is the **Part A signatory**, i.e., the custodian/party: the person who operated, owned, maintained, or managed the device (Schedule Part A offers checkboxes: Owned / Maintained / Managed / Operated).
2. **"an expert"** — this is the **Part B signatory**. The statute does not further define "expert" in §63 itself. **NOT VERIFIED**: no statutory definition of "expert" was found within §63 or its Schedule (e.g., no requirement of a certifying-authority registration, no reference to Examiner of Electronic Evidence under IT Act notifications). Section 39 of BSA 2023 (opinions of experts) may be relevant context but was not fetched/verified in this pass — flagged for follow-up rather than asserted.

Both signatures are required conjunctively — the statute's phrase is "purporting to be signed by a person in charge ... **and** an expert" — this is the "dual certification" that secondary commentary (Drishti Judiciary, KSandK, Corpotech Legal — see search results, not independently re-verified against the bare act beyond this cross-check) describes as new relative to the old §65B (which arguably required only one signatory). This dual-signature structure is directly reflected in the Schedule's Part A / Part B split.

**Sources for §1:**
- Official bare act PDF (primary, used for all verbatim quotes above): https://upload.indiacode.nic.in/view-casepdf?type=act&id=AC_CEN_5_23_00049_2023-47_1719292804654
- India Code landing page: https://www.indiacode.nic.in/handle/123456789/20063
- India Code show-data page: https://www.indiacode.nic.in/show-data?actid=AC_CEN_5_23_00049_2023-47_1719292804654&orderno=1
- (Secondary, used only to cross-check framing, not quoted verbatim from): Drishti Judiciary https://www.drishtijudiciary.com/bharatiya-sakshya-adhiniyam-&-indian-evidence-act/electronic-evidence-under-bhartiya-sakshya-adhiniyam-2023 ; KSandK https://ksandk.com/litigation/section-63-bharatiya-sakshya-adhiniyam-2023/

---

## 2. Implementable schema (draft — to be expanded)

Tagging: **[STATUTORY]** = required by §63 text or Schedule; **[STANDARD]** = from ISO/NIST guidance; **[GOOD PRACTICE]** = our design choice, no legal backing claimed.

*(This section is being filled in during research; see below for current draft. Will be revised after standards/case-law sections are complete.)*

### 2.1 `EvidenceRecord` (the original PCAP artefact)

| Field | Type | Tag | Description |
|---|---|---|---|
| `evidence_id` | UUID | [GOOD PRACTICE] | Internal unique identifier for the record. |
| `original_filename` | string | [GOOD PRACTICE] | Filename as ingested. |
| `file_size_bytes` | integer | [GOOD PRACTICE] | Size at ingest, for tamper cross-check. |
| `sha256_hash` | hex string (64 char) | [STATUTORY] (named in Schedule) + [STANDARD] | Primary hash per Schedule Part A/B "HASH value/s ... algorithm" field; SHA256 is checkbox-listed and NIST-current. |
| `md5_hash` | hex string (32 char) | [STATUTORY] (named in Schedule) | Secondary hash, included because MD5 is explicitly a Schedule checkbox option even though cryptographically weak; [GOOD PRACTICE] to also compute, [STATUTORY] only in the sense the form has a box for it. |
| `hash_algorithm_declared` | enum {SHA1, SHA256, MD5, Other} | [STATUTORY] | Mirrors the Schedule's checkbox field verbatim. |
| `acquisition_timestamp` | ISO 8601 datetime + timezone | [STATUTORY] (Schedule "Date"/"Time (IST)") + [STANDARD] | Schedule requires Date (DD/MM/YYYY) and Time (IST, 24h) — modeled here as a single field for implementation convenience, rendered back into the two Schedule fields at export time. |
| `acquisition_device_type` | enum matching Schedule checkboxes {Computer/Storage Media, DVR, Mobile, Flash Drive, CD/DVD, Server, Cloud, Other} | [STATUTORY] | Verbatim Schedule checkbox list. |
| `acquisition_device_make_model` | string | [STATUTORY] | Schedule "Make & Model". |
| `acquisition_device_serial` | string | [STATUTORY] | Schedule "Serial Number". |
| `acquisition_device_identifier` | string | [STATUTORY] | Schedule "IMEI/UIN/UID/MAC/Cloud ID (as applicable)". |
| `custodian_relationship` | enum {Owned, Maintained, Managed, Operated} | [STATUTORY] | Schedule Part A checkbox. |
| `source_description` | string | [GOOD PRACTICE] | e.g., "mirrored traffic from switch SPAN port X", free text supplementing statutory fields. |
| `storage_uri` | string | [GOOD PRACTICE] | Where the immutable original is stored (e.g., write-once bucket path). |
| *(remainder pending §3 practical-guidance research)* | | | |

### 2.2 `CustodyEvent` — draft, will finalize after §3/§4 research

| Field | Type | Tag | Description |
|---|---|---|---|
| `event_id` | UUID | [GOOD PRACTICE] | |
| `evidence_id` | UUID (FK) | [GOOD PRACTICE] | Links to `EvidenceRecord`. |
| `event_type` | enum {ACQUIRED, TRANSFERRED, ANALYZED, EXPORTED, VERIFIED, ...} | [STANDARD] (ISO 27037 custody concept) | |
| `actor` | string / user id | [STANDARD] | Person/role performing the event. |
| `timestamp` | ISO 8601 datetime | [STANDARD] | |
| `hash_at_event` | hex string | [GOOD PRACTICE] | Re-computed hash at this custody step, to prove integrity persisted. |
| `prev_event_hash` | hex string | [GOOD PRACTICE] | For hash-chained audit log (see §3.4). |
| `notes` | string | [GOOD PRACTICE] | |

### 2.3 `Section63Certificate` — draft, mapped directly to the Schedule fields above

*(To be finalized — will mirror Part A / Part B field-for-field per §1.2, plus a `signatory_role` discriminator {PARTY, EXPERT} and `expert_qualification` free-text field pending resolution of the "expert" NOT VERIFIED item in §1.4.)*

---

## 3. PCAP-tool-specific guidance (in progress)

*(placeholder — being researched next: hashing at ingest, artefact vs. derived-data relationship, court export contents, tamper-evidence/hash-chaining)*

---

## 4. Standards mapping (in progress)

*(placeholder — ISO/IEC 27037, 27041, 27042, 27043; NIST SP 800-86)*

---

## 5. Case law (in progress)

*(placeholder — Anvar P.V. v. P.K. Basheer (2014); Arjun Panditrao Khotkar v. Kailash Kushanrao Gorantyal (2020); post-July-2024 §63 judgments)*

---

## Research log / methodology notes

- Primary statutory text obtained by direct `curl` fetch of the official indiacode.nic.in PDF (not WebSearch snippets), then `pdftotext -layout` extraction, then manual line-range read — this is the most reliable method available and was used specifically to avoid hallucinating section text.
- Local working files: `/tmp/bsa_full.pdf`, `/tmp/bsa_full.txt` (not part of deliverable, scratch only).
