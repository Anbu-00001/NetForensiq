# 100 — Prompt for ChatGPT / Gemini / Grok

Six facts in [research/99](99_GUJARAT_FIT.md) are marked ⚠️ UNVERIFIED. They
matter because each one, if true, is something worth saying to a Gujarat Police
panel — and if false, is something that would be caught.

Paste the block below into each of ChatGPT (with browsing), Gemini and Grok
separately. Run all three: they index different sources, and where they
disagree the disagreement is itself the answer.

Save each reply into `research/` as `101_chatgpt.md`, `102_gemini.md`,
`103_grok.md`.

---

## The prompt

```
You are fact-checking claims for a project being presented to the Cyber Crime
Branch, Ahmedabad City Police on 19–20 August 2026. Accuracy matters more than
helpfulness: for each item, say VERIFIED, FALSE, or NOT FOUND, and give the
primary source URL. Do not fill gaps with plausible-sounding detail. If you
cannot find something, say so — "not found" is a useful answer here and a
fabricated citation is a harmful one.

1. GUJARAT HIGH COURT, SECTION 63/65B CERTIFICATE, MAY 2026
   A ruling attributed to Justice J.C. Doshi of the Gujarat High Court, around
   8 May 2026, reportedly held that a certificate under section 65B(4) of the
   Indian Evidence Act / section 63(4) of the Bharatiya Sakshya Adhiniyam 2023
   is a "condition precedent" to a court considering electronic evidence, and
   that sending an audio recording to a Forensic Science Laboratory before
   ruling on the certificate was "patent illegality". The underlying dispute
   concerned an oral agreement to sell a bungalow and an audio cassette of a
   telephone conversation.
   - Does this judgment exist? Give the case name, the case number, the exact
     date, and a link to the judgment text or a report on a primary legal
     database (Indian Kanoon, LiveLaw, SCC Online, Bar & Bench, the Gujarat
     High Court's own site).
   - Quote the two phrases verbatim if they appear.

2. ANY INDIAN JUDGMENT ON NETWORK OR PACKET-CAPTURE EVIDENCE
   Has ANY Indian court — any level, any state — issued a judgment dealing
   specifically with the admissibility of network traffic evidence: packet
   captures (PCAP), firewall or router logs, NetFlow records, IDS alerts, or
   server access logs, under section 65B or section 63?
   - Exclude call detail records (CDR), WhatsApp chats, CCTV, audio and email.
     Those are already known and are not what is being asked.
   - If nothing exists, say so plainly. That is a useful finding.

3. GUJARAT DIRECTORATE OF FORENSIC SCIENCE — DIGITAL EVIDENCE INTAKE
   Is there a published standard operating procedure, circular, manual or
   citizen-charter entry describing how the Gujarat Directorate of Forensic
   Science (Gandhinagar) accepts digital evidence?
   - Specifically: does it require a hash at the point of seizure, a hash at
     receipt before unsealing, or a particular chain-of-custody form?
   - Is there any published turnaround time for cyber-forensic examination?
     One secondary source claims 45–180 days; confirm or refute it.
   - Prefer dfs.gujarat.gov.in, home.gujarat.gov.in, Gujarat Government
     Gazette, or an RTI reply.

4. "SHREE CYBER SURAKSHA"
   Is there a Gujarat Police or Gujarat Government programme by this exact
   name? Distinguish it from AASHVAST, Cyber Suraksha Kavach, Cyber Suraksha
   Setu (a Surat nonprofit) and Cyber Suraksha (a Vadodara training institute).
   If no programme by that exact name exists, say so.

5. KANAD S.H.I.E.L.D. 2026 — JUDGING AND VENUE
   The event is run by the Cyber Crime Branch, Ahmedabad City Police with
   i-Hub Gujarat, on 19–20 August 2026 (kanadshield.com).
   - Are the judging criteria or the scoring rubric published anywhere?
   - Was there a previous edition? Who won, and with what?
   - The site shows two addresses: "Bungalow No. 15, Nr. IPS Mess, Dafanala
     cross road, Shahibaug, Ahmedabad 380004" and a reference to i-Hub Gujarat,
     Navrangpura. Which is the venue for the 19–20 August event, and which is
     merely the organiser's office?
   - Is there a named programme — incubation, pilot deployment, procurement —
     that winning teams enter afterwards? Name it, or say none is published.

6. GUJARAT STANDARDS FOR POLICE SOFTWARE
   - Does GIGW 3.0 (Guidelines for Indian Government Websites) apply to an
     internal law-enforcement analyst tool, or only to citizen-facing services?
     Quote the scope clause.
   - Does Gujarat Informatics Limited publish a standard requiring Gujarati
     language support in state government software? Give the document and the
     clause. Say whether it covers internal tools.
   - Is Gujarat State Data Center (GSDC) hosting available to a third-party
     application, and through what process?

For every item: state your confidence, and name the single strongest source
you found. Where you found nothing, say "not found" rather than inferring.
```

---

## Why each one matters

| # | If VERIFIED | If FALSE or NOT FOUND |
|---|---|---|
| 1 | The strongest possible opening: a Gujarat judge, this year, insisting on exactly the sequence this system enforces. | Fall back to the Gujarat State Judicial Academy training and the Supreme Court's *Pooranmal* line — both already verified. |
| 2 | Cite it and address it directly. | **Say it out loud**: no Indian court has ruled on packet evidence, which is precisely why the certificate has to be right the first time. That is a stronger position than silence. |
| 3 | Match our three-hash model to their intake, and quote the turnaround time as the cost of not having this. | Do not claim a match. Ask the FSL officers who attend. |
| 4 | Name it correctly. | Do not mention it. |
| 5 | Aim the demo at the rubric; know the room. | Prepare for a general panel and ask the organisers about next steps rather than asserting one. |
| 6 | Cite the standard being met. | Say the design targets WCAG 2.1 AA on its own initiative, which is true and checkable — there is a test for it. |
