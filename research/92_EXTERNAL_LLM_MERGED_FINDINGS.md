# Merged Findings — ChatGPT · Gemini · Grok Reports

> **Compiled:** 2026-08-09. Source files in the project root:
> `A. Procurement – Gujarat Police Tenders.docx` (ChatGPT),
> `KANAD SHIELD Hackathon Research Plan - Google Docs.pdf` (Gemini),
> `grok_report.pdf` (Grok).
>
> **This document does not just merge — it cross-validates.** Where the three engines
> disagree, or where an engine's own citations don't support its claim, that is recorded
> below. Several claims did not survive checking. Read §4 before using any number in a slide.

---

## 1. Reliability assessment

| Engine | Verdict | Why |
|---|---|---|
| **Grok** | ⭐ **Most reliable** | Real X URLs with status IDs, dates, engagement counts. Distinguishes what it found from what it didn't. Its one big claim independently cross-validated |
| **ChatGPT** | ⚠️ **Substantively valuable, but unverifiable as delivered** | The procurement section is the single highest-value find of the three — but every citation is an internal token (`【41†L1-L5】`) with **no URLs**. Also truncated: it promises an annotated bibliography and delivers nothing. ~2,170 words against a much larger brief |
| **Gemini** | ⚠️ **Richest, but with real citation-integrity failures** | Excellent dataset/repo discovery and UI benchmarks. But several headline claims are cited to sources that do not support them, and two rupee figures are wrong by 10× |

**Practical rule:** trust Grok's X findings, use ChatGPT's tenders only after verifying on GeM
directly, and treat Gemini's *specific numbers* as unverified while keeping its *pointers*
(dataset links, GitHub repos, tool names) which are checkable and mostly good.

---

## 2. ✅ Confirmed — corroborated by two or more independent sources

| Finding | Sources |
|---|---|
| **Karnavati University is the Academic Partner** (NAAC A+) | Grok saw `@karnavati_uni` tagged in the official promo post; **I independently confirmed by pulling the partner logo from `kanadshield.com/assets/img/kanadshield/naac.png`** — it is the Karnavati University logo. **Verified.** |
| **No prior edition — 2026 is the first** | Grok (no winners/recaps found on X) + our own PS_04 agent |
| **i-Hub Gujarat ran a "Cyber Security Demo Day", 27–28 July 2026**, with ISRO / Army / NFSU experts and investment partners | Grok (`@ihubgujarat` posts) + PS_04 agent |
| **DCP Dr. Lavina Sinha (`@DrLavina_IPS`) and MoS Home Harsh Sanghavi (`@sanghaviharsh`) are attached to the event** | Grok (tagged in every official promo) + PS_04 agent |
| **₹44 lakh "digital arrest" case, two accused arrested from Jodhpur, early Aug 2026** | Gemini (Sandesh, Gujarati) + Grok (`@AhmedabadPolice`, 6 Aug 2026, 5,855 views) — **two independent language sources.** Best-attested local case we have |
| **The official promo campaign ran 24 May → 7 Jul 2026** with low engagement (likes <15, views in the hundreds) | Grok, with post URLs and metrics |

**What the low engagement means:** this is a small, focused event, not a mass hackathon.
Fewer competing teams than a Smart India Hackathon — and organisers likely to remember
individual submissions.

---

## 3. 🆕 High-value new findings

### 3.1 An open tender from the exact customer — ⚠️ needs verification

ChatGPT reports **`GEM/2026/B/7843621` — "Crime Analytics and Mapping Software" (1 unit),
issued 31 Jul 2026, closing 17 Aug 2026, procuring agency Ahmedabad City Police.**

If real, this is the most strategically important fact in all three reports: the hackathon's
own customer is *actively buying* the commercial equivalent of Category 2 problem statement #7
(Crime Hotspot Mapping & Predictive Patrol), with a tender closing within days.

**Reading it both ways:** it proves genuine demand — but it also means a funded procurement
may already be underway, so a hackathon prototype would be competing with a purchased product.
Combined with §3.2 below, **PS #7 is contested territory.**

Other tenders ChatGPT reports (all ⚠️ unverified, no URLs given):

| Tender | Date | Scope | Agency |
|---|---|---|---|
| GEM/2024/B/5699566 | closed 27 Dec 2024 | Mobile forensic & CDR analysis, 3 units | DGP Office, Gandhinagar |
| GEM/2025/B/5899508 | closed 12 Feb 2025 | Mobile forensic & CDR analysis, **29 units** | DGP Office |
| GEM/2026/B/7618374 | closed 9 Jul 2026 | **Video Analytics Tools, 21 units** (EMD ₹56.7 lakh) | DGP Office, Gandhinagar |
| eProc/TOT | Dec 2024 | **4G/5G IMSI Catcher, ~₹5 crore** | Home Dept, for Gujarat ATS |

> **I attempted to verify `GEM/2026/B/7843621` by search and could not confirm it.** GeM tender
> IDs are not well indexed by general web search. **Verify directly on gem.gov.in before
> citing this anywhere.** If it holds up, it's a powerful slide.

### 3.2 Ahmedabad Cyber Crime Branch already has more than we knew

From Gemini (sourced to official Ahmedabad Police YouTube — plausible, ⚠️ not independently checked):

- **Cyber Suraksha Lab** — free device scanning / malware inspection for citizens
- **Incident Response Unit (IRU)** — immediate fraud reporting to block transactions before
  funds move through mule networks
- **Anti-Cyber Bullying Unit** — 24×7 line for women and minors
- **QuickPass** — QR-code app against commuting harassment with emergency dispatch
- **Cyber Yoddha** — citizen/student volunteer network
- **Police AI/ML Lab** — *"predictive patrol routing, tower dump analysis, pattern matching"*

⚠️ **That last one matters a lot.** If the Branch already runs an AI/ML lab doing predictive
patrol routing, then PS #7 is not green-field at all — it's already staffed internally *and*
(per §3.1) possibly under procurement.

**And from Grok:** the Branch runs **"Mission Cyber Rakshika" / "SecureHerSpace"**, its own
women-focused cyber-safety campaign. **Any submission against the Women's Safety PS that
doesn't reference and extend this will look like it didn't do its homework.**

### 3.3 Live fraud typologies in Ahmedabad — pitch-opening material

Best-attested, freshest examples:

| Case | Amount | Typology | Confidence |
|---|---|---|---|
| Fake CBI/police digital arrest, 2 arrested from Jodhpur (Aug 2026) | ₹44 lakh | Digital arrest | ✅ Two sources |
| SIM swapping, 19 rapid transactions (Jul 2026, Sandesh) | ₹83 lakh | SIM swap / 2FA intercept | ⚠️ One source |
| Fake SEBI certificates, pharma executive, Vejalpur (Jul 2026) | ₹22 lakh | Fake stock investment | ⚠️ One source |
| Investment scam, proceeds converted to **USDT** (Jul 2026) | ₹56 lakh | Crypto laundering | ⚠️ One source |
| AI-fabricated purchase orders + govt ID cards on GeM portal | ₹9.6 lakh | AI document forgery | ⚠️ One source |
| Vastral "ayurvedic medicine" racket, 7 arrested, 5,000+ victims | — | Extortion + fake healthcare | ⚠️ One source |
| **Surat MP Govind Dholakia deepfake video used in fraud attempt (9 Aug 2026)** | — | Deepfake impersonation | ⚠️ Grok only; **I could not verify by search** |
| Winprofx crypto investment app arrest (Jun 2026) | ₹19.07 lakh | Crypto investment app | ⚠️ Grok only |

**Recovery signal (Grok, `@cybercrimeahd`):** ~80% of ₹1.5 crore recovered after a ZIP/WhatsApp
hack case — useful as the "when it works, it works fast" counterpoint.

### 3.4 Citizen pain points in victims' own words — the best pitch openers we have

Real X complaints Grok surfaced, with URLs:

> *"30/07/2026 ko complaint ki thi 1930 avi tk koi response nhi mila… 40000 jo nikl gye the…
> lgta hai sapna smjh kr bhoolna pdhega…"* — `@Lalabha88086425`, 3 Aug 2026

> *"how am i supposed to file a complaint when i constantly get this error… 1930 … couldnt
> login due to server issues…"* — `@Valipokkann`, 7 Aug 2026

Recurring themes: long waits for freeze/recovery, incomplete portal functionality, having to
re-file or physically visit a station, low recovery outside the rapid-1930 window.

**This is the single most useful thing in all three reports for framing.** Opening a pitch with
a real, dated, quoted victim complaint beats any statistic.

### 3.5 Directly usable build assets (Gemini — links are checkable and look sound)

**Datasets (HuggingFace):** `prithivMLmods/Deepfake-vs-Real-60K` (60k images) ·
`nuriachandra/Deepfake-Eval-2024` (44h video/56.5h audio, CC-BY-SA-4.0, gated) ·
`garystafford/deepfake-audio-detection` · `ealvaradob/phishing-dataset` (18k emails, 5.9k SMS,
800k URLs) · `pirocheto/phishing-url` (CC-BY-4.0) · `ylacombe/google-gujarati` (Gujarati speech).

**GitHub — highly relevant to the Unified Legal Platform pick:**
- `pankil-soni/india-law-ai-rag` — 10,860+ Indian legislative Acts, PyMuPDF + Tesseract OCR,
  bilingual EN/HI, ChromaDB
- `ShubhamKumarNigam/NyayaRAG` — 56,387 Supreme Court judgments, Mixtral-8x7B + ChromaDB
- `sarfarajansari/legalSphere.Web` — Apache 2.0, 280k cases, case-tree/timeline/entity UI

**UI benchmarks** — Gemini's table of what Magnet AXIOM, BriefCam, Chainalysis Reactor,
Maltego, Arkime and Cellebrite UFED actually look like is genuinely useful. Judges have seen
these vendor demos; our UI shouldn't look like a student project next to them.

### 3.6 The 1930 / e-Zero FIR workflow

Gemini's reconstruction (⚠️ sourced to YouTube explainers, plausible and consistent with
[PS_03](PS_03_LEGAL_AND_DATA_REALITY.md)):

```
Victim → 1930 helpline / NCRP portal
  → Triage: account no. · amount debited · exact timestamp · UTR/transaction ID
  → FCFRS dispatches automated lien/freeze to beneficiary banks
  → e-Zero FIR auto-generated → CCTNS
  → Cyber Crime Branch: ledger tracing, IPDR/CDR analysis, mule graph mapping
```

**Those four intake parameters are worth hard-coding into any citizen-reporting UI** — it makes
the tool speak the operators' language.

---

## 4. ⚠️ Claims that did NOT survive checking

**Do not use these.**

### Gemini — citation misattribution

1. **"Evaluation Criteria: technical feasibility, speed of processing over massive datasets,
   seamless UI integration, strict adherence to Indian legal and digital evidence standards"**,
   and its claims about the promo video's content and target audience, are all cited to
   footnote ¹ — which is **"Cyber Challenge 2024: Delhi Police Hackathon | PDF - Scribd."**
   That is a *different hackathon in a different state*. ❌ **Discard.** We already hold the
   real, verbatim evaluation criteria in
   [PS_00](PS_00_OFFICIAL_PROBLEM_STATEMENTS.md) — use those.
2. **Gujarat portal document counts** — "Home Dept ~2,500–5,000 documents", "Gazette 10,000+",
   "GAD 15,000+, 60% text-searchable" — are cited to footnotes 38–41, which are: *Gujarat –
   Wikipedia*, *"Threat of Hindutva to Religious Freedom in India"*, *Urban ARC 2022
   Proceedings*, and *India Annual Report on Torture 2020*. **None support the claim.**
   ❌ Treat the counts as invented. The *structural* description (HTML tables + linked PDFs,
   historical items scanned, OCR needed) is plausible but must be checked by hand — and it
   **directly gates the feasibility of the Unified Legal Platform pick**, so check it early.
3. **Rupee errors of 10×:** ₹44 lakh written as "₹44,000,000" (correct: ₹4,400,000) and
   ₹83 lakh as "₹83,000,000" (correct: ₹8,300,000). Other rows are right, so the table is
   internally inconsistent.
4. **Hoax bomb-threat case** — Gemini presents Rene Joshilda as an Ahmedabad case targeting
   local schools and the Narendra Modi Stadium, "lodged in Sabarmati Central Jail", complete
   with a Gujarati headline. Its own cited source (The Hindu, footnote 27) is
   *"Chennai woman behind hoax bomb threat emails across India arrested by RGIA police"* —
   Hyderabad airport police, not Ahmedabad. The Gujarati headline appears fabricated for an
   English source. Meanwhile **Grok** reports a *different, later* case: a US-based software
   engineer detained at Chennai airport (Jul 2026) for 1,000–1,500 hoax emails over three
   years. ❌ **Do not cite the Ahmedabad framing.** The hoax-email problem is real and national
   — that part stands, and it supports the SafeInbox PS.

### ChatGPT — unverifiable as delivered

5. Every citation is an internal reference token with no URL. The **NCRB Gujarat cybercrime
   series** (1,283 / 1,536 / 1,417 / 1,995 / 1,592 for 2020–2024) and the **Gujarat Home
   Department budget** figures (₹10,378 crore FY2024-25; ₹15 crore for a State Cyber Crime Cell
   "Trishul Yojana") are plausible but **unsourced as given.** Verify before use.
6. Its I4C national figures (₹11,158 crore frozen; 6,589,201 NCRP complaints 2021-25 totalling
   ₹55,050 crore reported, ₹8,189 crore held) are the kind of number that gets garbled in
   re-reporting. Verify against a PIB release or Parliament answer.

### Unverified-but-plausible (kept, flagged)

7. **Surat MP Govind Dholakia deepfake (9 Aug 2026)** — Grok only. I searched and could not
   confirm. If true it is an outstanding hook for TruthShield, because it's local, current and
   involves a public figure. **Verify before building a pitch around it.**
8. Gemini's *"cyber fraud up 30%+, ~500 complaints daily across Gujarat"* — single-sourced.

---

## 5. What this changes in our strategy

| Pick | Before | After |
|---|---|---|
| **Unified Legal & Govt Intelligence Platform** | 🥇 Top pick — data is public and scrapeable | **Still top pick, but the document-count evidence collapsed.** Three strong open-source RAG repos found (§3.5) materially de-risk the build. **Action: manually verify scrapeability of gad.gujarat.gov.in and gazette.gujarat.gov.in before committing** |
| **Police Health & Wellness** | 🥈 Green-field | **Unchanged and still strong.** Nothing in any report contradicts it; no competitor surfaced |
| **CrimeGPT** | 🥉 High operational value | **Unchanged.** BNS/BNSS/BSA novelty argument holds |
| **Crime Hotspot / Predictive Patrol** | Medium, some prior-art risk | **⬇️ Downgrade.** They may already have an internal Police AI/ML Lab doing predictive patrol routing *and* an open procurement for commercial crime-analytics software. Avoid unless we have a sharp cyber-correlation angle |
| **Women's Safety** | High but crowded | **Unchanged, with a new requirement:** must build on **Mission Cyber Rakshika / SecureHerSpace**, not ignore it |
| **SafeInbox (hoax bomb email)** | Dark horse | **⬆️ Slightly up.** Hoax-email waves confirmed as a live national problem, though the Ahmedabad-specific framing didn't hold |

**New cross-cutting insight:** the Branch is visibly proud of its citizen-facing programmes
(Cyber Suraksha Lab, IRU, Anti-Cyber Bullying Unit, QuickPass, Cyber Yoddha, Mission Cyber
Rakshika). A submission that positions itself as *extending* a named existing programme will
land better than one implying they have nothing.

---

## 6. Verification queue — do these before the event

1. **`GEM/2026/B/7843621`** on gem.gov.in — is Ahmedabad City Police really buying crime
   analytics software, closing 17 Aug 2026? *(Highest value, highest uncertainty.)*
2. **Scrape-test `gad.gujarat.gov.in` and `gazette.gujarat.gov.in`** by hand — real document
   counts, HTML vs scanned PDF ratio. Gates the top pick.
3. **Govind Dholakia deepfake** — confirm via Gujarati press before using as a hook.
4. **NCRB Gujarat cybercrime series** and **Gujarat Home budget** — find primary sources.
5. **The event date.** Still unpublished. Watch `@cybercrimeahd` — it is the channel that
   announced everything else first.
6. **Karnavati University's role** — confirmed as Academic Partner; worth knowing whether they
   supply judges or venue support.

---

## 7. Prompt post-mortem — for next time

The non-overlap design worked: there was essentially **no duplicated content** across the three
reports, and each engine's assigned territory produced findings the others missed entirely.

What I'd change:

- **Demand raw URLs explicitly.** ChatGPT's internal citation tokens made its best material
  unverifiable. Add: *"every citation must be a full https:// URL in the visible text — internal
  reference markers are not acceptable."*
- **Add an anti-misattribution instruction.** Gemini attached real sources to unrelated claims.
  Add: *"before each citation, confirm the source actually contains the claim; if you are
  inferring or generalising, write INFERRED instead of citing."*
- **Ask for currency conversion discipline** — *"write amounts in both formats: ₹44 lakh
  (₹4,400,000)"* — would have caught the 10× errors automatically.
- **Grok's prompt needed no changes.** Asking it for engagement metrics and post URLs is what
  made its output auditable; replicate that pattern for the others.
