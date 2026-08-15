# eSakshya — verified findings, and what they change

Merge of the three external reports ([grok.d](../grok.d),
[deep-research-report.md](../deep-research-report.md), the Gemini PDF), with every
load-bearing claim checked against primary sources on 15 Aug 2026.

**Rule applied:** a claim is marked ✅ only if I fetched the primary source myself.
Everything else is ⚠️ or ❌, regardless of how confidently the report stated it.

---

## 1. The decisive question — answered

**eSakshya does not track an exhibit after seizure.** Three independent methods agree:

| Method | Result |
|---|---|
| Gemini — screen-by-screen audit | Malkhana, custody, transfer, handover, exhibit logging, FSL forwarding all **NOT FOUND** in the app |
| ChatGPT — rules and SOPs | Maharashtra e-Sakshya Rules 2025 and all located guidance **silent** on post-seizure custody |
| Grok — 14 months of X | **Zero** posts discussing custody transfer inside eSakshya, from anyone |

The mobile menu is exactly four items: New Sakshya · Pending to Upload · Pending for
Verification · Sakshya Mini Statement. Capture, buffer, seal, upload. Nothing else.

BNSS §497 (*Order of Custody and Disposal of Property*) **does** appear in the app's
provision dropdown — but only to record *video* of property at judicial disposal. It is a
recording purpose, not a tracking function.

Physical custody lives elsewhere: **CCTNS Property Registers** and the **ICJS e-Forensics
module**, both desktop. Bihar (Buxar) and Delhi have separate e-Malkhana pilots.

---

## 2. What this costs us — read before pitching

✅ **eSakshya already generates a BSA §63(4)(c) Part A certificate**, eSigned via Aadhaar,
and computes **SHA-256** on the packet at freeze (Gemini Screens 9–10; Maharashtra
e-Sakshya Rules 2025 via ChatGPT; corroborated by the Play Store description).

**The claim "nobody else produces a §63 certificate" is false and must not be said.**

It survives only in narrowed form, which the evidence supports:

> eSakshya seals *scene video*. CCTNS Property Registers track *physical objects*.
> A packet capture is neither — it has no scene to videograph and no object to log into a
> malkhana. **Network evidence falls in the gap between the two systems, and nothing
> currently covers it.**

That is a smaller claim than the one in PROGRESS.md, and unlike it, it is defensible.

---

## 3. The opportunity nobody flagged

The **Gujarat State Judicial Academy** ran a Master Trainer Programme on **6–7 July 2026**
(ECT-03-2026) whose Session III — *Concept of ICJS* — covers "Courts & Evidence Tracking
eSakshya" and "E-Forensics, e-Prisons and e-Prosecution Integration". Delivered by
**Ms. Suman Nala, SP, State Crime Record Bureau, Gandhinagar** and **Mr. Neeraj Nama,
Scientist, NIC Gandhinagar**. ✅ *Verified — I downloaded the programme PDF from gsja.nic.in.*

**Gujarat judges are being trained, right now, to expect digital evidence in a specific
shape: an ID, a hash, and a §63 certificate.**

So NetForensiq should deliberately mirror that shape for network evidence — a capture ID
analogous to a 16-digit SID, SHA-256 at seal, a §63 Part A/B certificate. Not imitation:
**landing in a mental model the local judiciary already has.** That is a far stronger
answer to "why would a court accept this?" than any technical argument.

Also on that agenda, Session II: *"Policy on the Use of Artificial Intelligence"* — the
Gujarat High Court has an AI policy. Worth locating before claiming anything about AI in
a courtroom context.

---

## 4. Claim-by-claim verification

| Claim | Source | Verdict |
|---|---|---|
| BSA §63(4)(c) → THE SCHEDULE → CERTIFICATE → PART A / PART B | indiacode.nic.in bare act, lines 2289–2335 | ✅ **Verified in primary text** |
| *Shadab v. State of U.P.*, Allahabad HC, 5 Jan 2026 — failure to videograph a 40-motorcycle recovery; bail granted; UP DGP directed to issue an SOP; non-compliance may attract disciplinary proceedings | Justice Arun Kumar Singh Deshwal; full judgment PDF on lawbeat.in; SCC Online; Law Trend | ✅ **Verified** |
| *Suresh v. State of Kerala* (2025) — murder conviction set aside over investigation quality; directions to use "e-Sakshya or any other capable platform" | Kerala HC; CaseMine commentary; LiveLaw | ✅ **Verified** |
| *Mani Roy v. State of H.P.*, 27 May 2025 — "the court **held** an eSakshya recording without a §63 certificate inadmissible" | indiankanoon.org/doc/51080317/ | ❌ **FALSE AS STATED.** The case is real and the sentence appears in it — but as an argument in the **petitioner's rejoinder**, not a holding. The court never ruled on it; bail turned on DNA results and the victim's position. **Do not cite this as precedent.** |
| Play Store `com.nic.esaakshya`, developer National Informatics Centre, contact `developer.mapmyindia@gmail.com` | play.google.com listing, fetched directly | ✅ **Verified — the odd gmail address is genuinely on NIC's listing.** I flagged it as likely fabricated and was wrong. |
| GSJA Master Trainer Programme, Session III, Suman Nala + Neeraj Nama | gsja.nic.in programme PDF | ✅ **Verified** |
| GSJA deck "Slide 1/2/3", incl. automated SHA-256 verification on judicial terminals | — | ⚠️ **Unsourced.** The PDF is a **one-page agenda with no slides**. Gemini extrapolated slide contents from agenda line items. The hash-on-judicial-terminals detail has no source. |
| Gujarat Home Dept Notification HD/SB.5/BNS/102025 | — | ⚠️ **Not independently confirmable.** Plausible but not indexed; treat as unverified. |
| Per-clip cap of 4 minutes | Gemini Screen 6 ("Recording Time Remaining: 04:00"), Marathi training video, prior research | ✅ Corroborated 3× — ChatGPT's "10 minutes" is the **outlier, rejected** |
| 15,899 police stations across 35 States/UTs | MHA Rajya Sabha reply, 11 Feb 2026 (via ChatGPT); PIB echo on X | ⚠️ Consistent across two reports, primary not fetched |
| 24,000+ Gujarat officers; Gujarat leads nationally | DGP Gujarat via TV9 Gujarati / NewsCapital, Oct 2025 | ⚠️ Press claim, leadership-sourced |
| No public API; police-network only | ChatGPT §E; matches [SPEC_03](SPEC_03_CONNECTORS_AND_MCP.md) | ✅ Consistent with prior independent research |

### Report quality

- **Grok** — most disciplined. Reported `NOT FOUND ON X` four times rather than padding, and
  its X post IDs are internally consistent with their stated dates under Twitter's snowflake
  scheme (spot-checked: Oct 2025 → Aug 2026 delta matches elapsed time to ~3%).
- **Gemini** — richest and largely accurate on verifiable specifics, but blurs seen from
  inferred, and leaked raw `[cite: N]` markers.
- **ChatGPT** — strong on documents; **converted an advocate's argument into a judicial
  holding**, the single most dangerous error in the set.

---

## 5. The judicial-custody argument — our strongest external support

Bar & Bench, 1 May 2026: **Jay Thareja**, Delhi judicial officer and former CBI judge, now
Central Project Coordinator at the Delhi High Court, publicly warned that the State is
*"fully capable of tampering"* with MLCs, post-mortem reports, forensic material and **BNSS
§105 videos** when such records are housed with investigating agencies rather than the
judiciary. ⚠️ *Sourced to a Grok-supplied X post; the quote should be re-checked against
Bar & Bench directly before being put on a slide.*

If it holds, the argument for independently verifiable, hash-chained custody is being made
by a sitting judicial officer — not by us. That is worth more than any feature.
