# KANAD S.H.I.E.L.D. 2026 — Strategic Synthesis & Opportunity Map

> **Compiled:** 2026-08-09 · Based on the **26 official problem statements** retrieved
> from https://kanadshield.com on 2026-08-09 (see
> [PS_00_OFFICIAL_PROBLEM_STATEMENTS.md](PS_00_OFFICIAL_PROBLEM_STATEMENTS.md)).
>
> Everything marked **INFERENCE** is my judgement, not sourced fact.

---

## 1. The single most important correction to our assumptions

We went in expecting a broad "Gujarat Police" hackathon. It is **not** that. It is:

**A cybersecurity / cyber-investigation hackathon run by the Cyber Crime Branch of
Ahmedabad City Police, with i-Hub Gujarat as startup-ecosystem partner.**

Consequences:

| We assumed | Reality |
|---|---|
| Broad policing themes (traffic, narcotics, crowd control, coastal security) | **Almost none of that.** 26/26 statements are cyber, digital-forensics, data-analytics or citizen-safety-platform shaped |
| State-wide Gujarat Police | **Ahmedabad City Police, Cyber Crime Branch** is the customer. Shahibaug, Ahmedabad |
| Problem statements unknown | **All 26 are public**, with objectives, functional requirements, evaluation criteria, suggested tech and bonus points |
| One pool of problems | **Two categories** with different eligibility — Cat 1 (startups/industry, 16 PS) and Cat 2 (students/graduates/doctoral, 10 PS) |

**The broad Gujarat research (files 01–03) is still useful — but as pitch framing, not as
theme prediction.** Use it for the "why this matters in Ahmedabad" opening slide, not for
guessing the problem.

> ⚠️ Every problem-statement page also carries the line **"Registrations Closed — the
> application window for this problem statement has ended."** while simultaneously showing
> `Status: Open`. Since we are attending, we are presumably already registered; treat the
> registration banner as stale UI, but **confirm our assigned/chosen PS with the organisers**.

---

## 2. What the evaluation criteria reveal about the judges

The Category 2 problems share an almost identical evaluation rubric. That repetition is a
gift — it tells us exactly what the panel scores. Verbatim, the recurring criteria:

1. Effectiveness of **police integration** and real-time response
2. Accuracy of location tracking and alert mechanisms
3. **Quality and admissibility of digital evidence**
4. Scalability and performance
5. User interface and accessibility
6. Innovation in preventive safety features
7. **Data privacy and security compliance**
8. **Real-world applicability**

And the recurring **bonus points**:

- AI-based unsafe zone prediction
- **Voice-activated SOS trigger**
- **Offline / SMS-based alert system**
- **Multilingual support (Gujarati, Hindi, English)**
- Wearable device integration
- Facial recognition for missing persons (optional)

**INFERENCE — the four things that will actually win this:**

| Signal | Why it scores | Cheap to implement? |
|---|---|---|
| **Gujarati-language support that visibly works** | Named in bonus points on nearly every Cat-2 PS. Ahmedabad police work in Gujarati. Most teams will ship English-only | Yes — highest ROI item in the entire event |
| **Evidence admissibility done properly** | "Quality and admissibility of digital evidence" is criterion #3 everywhere. It maps to **BSA s.63 certificates, hashing, chain of custody** (post-1 July 2024 law) | Yes — it's mostly disciplined logging + a generated certificate PDF |
| **A working police-side dashboard**, not just a citizen app | "Police dashboard demonstration" is an explicit *deliverable* on the Cat-2 safety platforms | Medium — but non-negotiable |
| **Offline / SMS fallback** | Named in bonus points; also genuinely correct for Indian field conditions | Medium — an SMS/USSD path or queued-offline mode |

The rubric rewards **operational realism over model novelty**. A modest model wrapped in a
correct police workflow beats a clever model with no workflow.

---

## 3. All 26, scored for a student team

Scoring key — **Fit** = suitability for a student team in a short hackathon;
**Data** = can you obtain/simulate the data honestly; **Crowd** = how many teams will pick it
(lower is better for standing out). All ratings are **INFERENCE**.

### Category 1 — Startups / Industry / Researchers (16)

*These assume access to telecom, banking and forensic pipelines. Listed for completeness and
because several are technically adjacent to Category 2 ideas.*

| # | Problem statement | Fit | Data reality | Note |
|---|---|---|---|---|
| 1 | Big Data Analysis Tool | Low | Needs FIR/CDR/IPDR/1930/CEIR files | This is effectively "build us Palantir". Scope is enormous |
| 2 | DARKTRACE — dark web surveillance | Low | Tor crawling; legal/ethical care | Name collides with the real company Darktrace |
| 3 | Mule bank account detection | **Med-High** | PS *explicitly permits* "anonymized/simulated" data | Graph/GNN problem; public datasets exist (Elliptic, PaySim, IEEE-CIS) |
| 4 | IntelliBank — bank statement analysis | **Med-High** | Simulated statements are legitimate here | Very tractable; strong demo value |
| 5 | CryptoTrack — crypto forensics | Med | Public blockchains = **genuinely open data** | One of the few PS with real, free, live data |
| 6 | SMIntelliTrack — social media monitoring | Med | X API is expensive now; other platforms restrictive | Feasible on Reddit/Telegram/YouTube |
| 7 | CallGuard — spoofed/VoIP call detection | Low-Med | Needs telecom-side signal | Hard to do honestly on-device |
| 8 | TruthShield — fake news + deepfake detection | Med | Open benchmarks exist (FF++, DFDC, Celeb-DF) | Crowded; generalisation is genuinely poor — be honest about it |
| 9 | TeleScan AI — Telegram monitoring | **Med-High** | Telegram API is actually accessible (Telethon/TDLib) | Underrated: real data, real crime, tractable |
| 10 | Mobile Hygiene Guardian | **High** | No sensitive data needed at all | Android permissions/patch audit. Very buildable |
| 11 | ForensiX — mobile forensics | Med | Use your own test device | OSS base exists (ALEAPP, Autopsy) |
| 12 | VisionScan — CCTV analysis | Med | Shoot your own footage | "Search CCTV by natural language" (CLIP+FAISS) demos beautifully |
| 13 | VoiceInsight — call recording to text | **Med-High** | Record your own calls | **Gujarati ASR is the differentiator** |
| 14 | SIMScanner — bulk SIM IMSI reading | Low | Needs PC/SC smartcard hardware | Hardware-gated |
| 15 | CellScope — Cell ID finder 2G–5G | Low-Med | Android telephony APIs give partial access | Vendor/OS restrictions bite hard |
| 16 | SafeInbox — hoax bomb-threat email detection | **High** | Email corpora are public; **hoax bomb threats to Ahmedabad schools are a real, current problem** | Narrow, concrete, winnable |

### Category 2 — Students / Graduates / Doctoral (10) — **our likely track**

| # | Problem statement | Fit | Crowd risk | Verdict |
|---|---|---|---|---|
| 1 | Cyber-Integrated Safety Platform for **Women** | High | **Very high** — the obvious pick | Only choose with a sharp differentiator |
| 2 | Cyber Safety Platform for **Children** | High | High | Grooming-detection NLP is the real technical core |
| 3 | Cyber-Aware Platform for **Senior Citizens** | High | **Low-Med** | ⭐ Underpicked; scam-call detection + simple UI is a genuinely strong story |
| 4 | **Unified Legal & Government Intelligence Platform** | High | Low | ⭐⭐ RAG over Gujarat GRs/Acts/judgments. Data is *public and scrapeable* — rare advantage |
| 5 | **Police Health & Wellness Monitoring** | High | **Low** | ⭐⭐ Judges *are* the users. Emotionally resonant. No sensitive data needed |
| 6 | **CrimeGPT** — crime documentation automation | Med-High | Med | ⭐⭐ Highest operational value; maps narrative → BNS sections. Needs legal precision |
| 7 | Crime Hotspot Mapping & Predictive Patrol | Med | Med | Predictive policing has a documented bias record — address it explicitly or it's a liability |
| 8 | Network & Packet Forensics Platform | Med | Low | Mature OSS (Zeek/Suricata/Arkime) means judges may ask "why not just Arkime?" |
| 9 | Real-Time Data Breach Alert System | High | Low | Narrow, buildable; HIBP-style. Explicitly framed as a module of #4 |
| 10 | **Open-Ended Innovation for Smart Policing** | High | Med | Escape hatch — lets you build the best idea and still be in-scope |

---

## 4. Recommended shortlist

**INFERENCE — my ranked picks for a strong student team:**

### 🥇 Pick 1 — Unified Legal & Government Intelligence Platform (Cat 2, #4)
The only problem statement whose **entire data source is legitimately public and scrapeable**:
Gujarat GR portals, India Code, gazette notifications, Indian Kanoon, eCourts. Every other PS
forces you to simulate data; here you can demo on *real documents*, which is enormously more
convincing. Cross-linking GR ↔ Act ↔ Judgment is a genuinely useful artefact, and Gujarati
summarisation hits the multilingual bonus directly.

**Risk:** it's an information-retrieval product, not visibly "cyber". Counter this by wiring in
PS #9 (breach alerts) as a module — the PS text *itself* invites that.

### 🥈 Pick 2 — Police Health & Wellness Monitoring (Cat 2, #5)
The judges are police officers. This problem is *about them*. Almost no team will pick it, and
the PS explicitly contrasts itself with Apple Health/WHOOP, so the bar is "police-specific",
not "beat Apple". The **duty-hours ↔ health correlation module** and supervisory dashboard are
the differentiators, and both are pure data work — no scarce data required. Strong ethical
framing available (police suicide and stress are documented problems).

**Risk:** low technical glamour. Mitigate with a real wearable/phone-sensor integration and a
genuinely good analytics dashboard.

### 🥉 Pick 3 — CrimeGPT (Cat 2, #6)
Highest real operational value: narrative in → correct **BNS/BNSS** sections, auto-drafted
documents, running case diary, no re-keying of the same facts. Gujarati speech-to-text for an
officer dictating a complaint is a showstopper demo.

**Risk:** legal-section mapping must be *accurate*. A hallucinated section in front of police
judges is fatal. Ground it in retrieval over bare-act text with citations, never free generation.

### Dark horse — SafeInbox (Cat 1, #16) if we can enter Category 1
Hoax bomb-threat emails to schools and airports have been a recurring, high-profile Indian
problem. The scope is narrow enough to actually finish, and the demo ("this email is a
high-risk hoax, here's why, here's the escalation packet") is crisp.

---

### Prior-art check (added 2026-08-09, from [PS_01_PRIOR_ART_LANDSCAPE.md](PS_01_PRIOR_ART_LANDSCAPE.md))

A dedicated prior-art sweep **independently reached the same shortlist**, and added three
findings that change how specific problems should be approached:

**Green-field — almost no existing competitor:**
- **Senior Citizen Safety & Welfare Platform** — no real Indian precedent found
- **Police Health & Wellness Monitoring** — the only comparable thing found anywhere was a
  small UK academic pilot pairing Fitbit with an insurer's app across two police forces
- **CrimeGPT** — for a structural reason worth understanding: it targets **BNS/BNSS/BSA**,
  which only replaced the IPC/CrPC/Evidence Act in 2024. Even India's legacy legal-tech was
  built for a now-obsolete framework, so no mature competitor has had time to emerge

**⚠️ Prior-art risk — do not pitch the base capability as novel:**
- **Mule account detection** — RBI's **MuleHunter.AI** is already live across 26 banks, and
  the national **DPIP** data-sharing platform launched in 2025. Differentiate on the
  *investigator-facing* graph/reporting layer, not on detection itself
- **Crime Hotspot / Predictive Patrol** — Delhi Police's **CMAPS** (with ISRO-ADRIN, since
  2015) already does GIS predictive hotspot mapping. The available gap is the
  cyber-crime correlation that CMAPS reportedly lacks

**Heavy global competition, but a conspicuous India-language gap** — TruthShield (deepfakes),
CallGuard (spoofed calls), VoiceInsight (transcription). None of the surveyed deepfake vendors
advertise Hindi/Gujarati support, and Truecaller's crowd-sourced model is being displaced by
TRAI's own **CNAP** rollout. Leaning on Indian government infrastructure — Bhashini /
AI4Bharat IndicWhisper for voice, PIB Fact Check / BOOM / AltNews plus Google's Fact Check API
for claims, DoT's **Chakshu** and CNAP for calls — reads as informed rather than naive.

**Naming issue worth raising with organisers:** the "DARKTRACE" problem statement collides
with **Darktrace plc**, a real UK cybersecurity company.

---

### Stack reality checks (from [PS_02_BUILDABLE_STACK.md](PS_02_BUILDABLE_STACK.md))

Findings that should change design decisions on day zero:

| Finding | Implication |
|---|---|
| **AI4Bharat IndicConformer-600M** (MIT, all 22 Indian languages incl. Gujarati) + **faster-whisper** (MIT, CPU-viable) are genuinely free and run locally | Gujarati ASR — the highest-ROI bonus item — is achievable offline. No API dependency |
| Real Gujarati WER is **double-digit (~11–12%)** even on the best models, and **no benchmark isolates code-mixed Gujarati-Hindi-English** | Claim "Gujarati support", demo it honestly, don't claim accuracy you can't evidence |
| **Elliptic dataset** — 203k labelled Bitcoin transactions | The single best "show real ML with a real confusion matrix" opportunity in the whole event |
| **DeepfakeBench** (CC BY-NC-4.0, 36 pretrained detectors) is the fastest path — but cross-dataset AUC drops of **20–50 points are the norm, not an edge case** | Build around a calibrated trust score, never a confident binary verdict |
| **X/Twitter free API tier is gone** (Feb 2026 pay-per-use pivot) | Do not architect anything around live X pulls — affects SMIntelliTrack |
| **InsightFace `buffalo_l` weights are non-commercial-research-only** | A licence problem for anything pitched toward police procurement |
| **NCRB data is aggregate district-year counts, not geocoded incidents** | Hotspot mapping needs synthetic data from hour one, not hour 30 |
| **DuckDB** is the realistic answer to "petabyte-scale search" at hackathon scale | Don't stand up a Hadoop/Spark cluster to impress anyone |

---

## 5. Cross-cutting design principles (apply to whatever we pick)

1. **Gujarati first, not Gujarati-later.** Ship the UI and at least one AI path (ASR, summary,
   or alerts) in Gujarati. Named in bonus points across the board.
2. **Generate a proper BSA §63 electronic evidence certificate.** Since 1 July 2024 this is a
   **two-part certificate**: Part A from whoever operated the device, Part B from a technical
   expert stating **the hash value *and* the hash algorithm used** (§63(4)(c)). Compute
   SHA-256 at ingestion, re-verify on every export, and model Part A / Part B as **structured
   fields, not free text**. Pair it with an append-only, tamper-evident audit log covering the
   full custody chain (seizure → transport → lab → storage → court) — a broken chain of custody
   defeats even a technically valid certificate, and police judges know that. This is the
   single clearest signal that you read the new law rather than copying a 65B-era workflow.
   *(Detail and ⚠️-flagged section numbers in [PS_03_LEGAL_AND_DATA_REALITY.md](PS_03_LEGAL_AND_DATA_REALITY.md).)*
3. **Build the police dashboard.** It's a stated deliverable, and it's what the judges will
   actually look at.
4. **Offline/SMS fallback path.** Even a simulated one, clearly shown.
5. **Show the integration path honestly.** Say "ERSS 112 / CCTNS integration simulated via
   this interface, here is the real adapter we'd write." The PS text itself says *"simulated if
   required"* — they expect this, and pretending otherwise reads as naive.
6. **Name your limits.** Deepfake detectors generalise badly; predictive policing has bias
   risks. Stating this earns more credibility with a professional panel than overclaiming.
7. **Use synthetic data openly and well.** Label it. A well-built synthetic Indian-context
   dataset (names, IFSC codes, Gujarat districts, realistic CDR shape) is itself impressive.
8. **Respect the metadata/content and citizen/LEA boundaries out loud.** Do not imply the tool
   can "pull call records" or "trace an IMEI". CDR and CAF come via a **§94 BNSS production
   summons** to the telecom provider; live call *content* needs a categorically different and
   far more tightly gated **interception order under the Telecommunications Act 2023**,
   reviewed by a Central/State Review Committee. Likewise, **CEIR lets a citizen block their
   own lost phone — full historical IMEI tracing is law-enforcement-only.** Stating this on the
   integration-path slide reads as trustworthy; blurring it for a flashier demo reads as naive.
9. **Treat CGNAT attribution as the hard problem it is.** IP-to-person is not a lookup. It
   needs a three-way join of platform log (**including source port**), ISP NAT syslog, and
   synchronised clocks — per DoT's 2021 IPDR mandate. Modelling the failure modes explicitly
   (missing port, clock skew, expired retention) demonstrates you understand why this defeats
   real investigators daily. Pretending "IP → person" is one API call is the fastest way to
   lose a police panel.

---

## 6. Confirmed logistics (from kanadshield.com/timeline.html, retrieved 2026-08-09)

| Item | Status |
|---|---|
| Registration | **Closed** |
| Final date of submission | **28 June 2026** on the timeline page — ⚠️ but the site's own pages conflict (20 Jun vs 28 Jun 2026) and a third-party listing says 25 May 2026. **Unresolved** |
| Event date | **"Will be announced shortly"** — not published |
| Venue | **i-Hub Gujarat**, Prajna Puram, KCG Campus, opp. PRL, Navrangpura, Ahmedabad 380015 |
| **Team size** | **2–6 members** |
| **Prizes — Category 1** | **₹5,00,000 / ₹3,00,000 / ₹2,00,000** (1st / 2nd / 3rd) |
| **Prizes — Category 2** | **₹1,50,000 / ₹1,00,000 / ₹50,000** (1st / 2nd / 3rd) |
| **IP terms** | ✅ **Clean.** Both `terms-and-condition.html` and `disclaimer.html` were read in full: **no clause claims organiser ownership, licence, or usage rights over submitted work.** The only IP language protects participants from each other (no plagiarism, respect third-party IP, comply with open-source licences) and disclaims organiser liability in inter-participant disputes |
| **Prior editions** | **None — this is the first.** A 2023 "Parakram CTF" predecessor exists but left no winner data. There is no past-winner signal to reverse-engineer |
| Official notice | *"Currently, there is heavy rain in Ahmedabad city … due to this natural emergency, this Kanad S.H.I.E.L.D. — Cyber Security Hackathon-2026 event is currently **postponed**. This event is going to be held soon in the near future…"* |

**⚠️ This materially changes the picture.** The submission deadline has already passed
(28 June 2026) and the event was **postponed due to flooding in Ahmedabad**. The site has not
been updated with a new date.

**INFERENCE:** the on-site event is most likely a **finale / presentation-and-judging round for
already-submitted solutions**, not an open build-from-scratch hackathon. If that's right, the
priority shifts from "pick a problem" to "polish, harden and rehearse the submitted solution."

**Confirm with the organisers before doing anything else:** which PS we are registered against,
what was submitted, and what the on-site format actually is. Venue is i-Hub Gujarat
(Navrangpura), *not* the Cyber Crime Branch office at Shahibaug.

### Who you are pitching to

Named, currently-serving officers associated with the event (all active on live cases into 2026):

- **JCP Sharad Singhal, IPS**
- **DCP Dr. Lavina Sinha, IPS**
- **ACP Hardik Makadia**

The official promo also tags **Harsh Sanghavi**, Gujarat's Minister of State for Home —
ministerial-level visibility. Separately, i-Hub Gujarat ran a **"Cyber Security Demo Day" on
27–28 July 2026** with these same three officers as keynotes, and mentors drawn from **ISRO,
the Indian Army, NFSU and VC partners**.

**INFERENCE:** the judging panel will likely extend well beyond police into technical and
investor territory. Prepare for both audiences — operational credibility *and* a viability
story. The clean IP terms plus i-Hub's investment track mean a genuine deployment/commercial
path is a legitimate thing to talk about.

### Pitch-framing number

**Gujarat CID data: 72,091 people defrauded of ₹678 crore between January and September 2025
alone**, with Ahmedabad among the two worst-hit districts. A new statewide cyber unit was
announced in August 2025 explicitly citing **"fake digital arrests and deepfake audio-video
calls"** — which maps directly onto several problem statements. *(Verify before slide use —
see [PS_04](PS_04_ORGANISERS_AND_EVENT_MECHANICS.md).)*

### Still open

- Which **category** are we registered in, and is our PS already fixed?
- On-site **format** — build, demo, or pitch? Duration?
- The actual **event date**, still unpublished as of 2026-08-09
- **Prize structure** and whether there is a procurement/pilot pathway for winners
- **IP terms** — what rights the organisers take over submissions (terms-and-condition page)
- Is internet access at the venue reliable enough for API-dependent designs?
- Will any **real or sample data** be provided by the Cyber Crime Branch on the day?

*(A dedicated agent is scraping the timeline/about/how-it-works/terms pages for exactly these —
see [PS_04_ORGANISERS_AND_EVENT_MECHANICS.md](PS_04_ORGANISERS_AND_EVENT_MECHANICS.md).)*

---

## 7. Companion documents

| File | What it gives you |
|---|---|
| [PS_00_OFFICIAL_PROBLEM_STATEMENTS.md](PS_00_OFFICIAL_PROBLEM_STATEMENTS.md) | All 26, verbatim — **the primary source** |
| [PS_01_PRIOR_ART_LANDSCAPE.md](PS_01_PRIOR_ART_LANDSCAPE.md) | What already exists per problem, and the gap to exploit |
| [PS_02_BUILDABLE_STACK.md](PS_02_BUILDABLE_STACK.md) | Open models/datasets/APIs you can actually assemble in 36h |
| [PS_03_LEGAL_AND_DATA_REALITY.md](PS_03_LEGAL_AND_DATA_REALITY.md) | CDR/IPDR/CAF/CEIR explained; BNSS/BSA compliance checklist |
| [PS_04_ORGANISERS_AND_EVENT_MECHANICS.md](PS_04_ORGANISERS_AND_EVENT_MECHANICS.md) | Dates, judging, IP terms, who the organisers are |
| [01](01_gujarat_police_structure_and_leadership.md) · [02](02_gujarat_police_existing_tech_and_ai.md) · [03](03_gujarat_cybercrime_landscape.md) | Gujarat context — use for pitch framing and local numbers |
| [91_EXTERNAL_LLM_RESEARCH_PROMPTS.md](91_EXTERNAL_LLM_RESEARCH_PROMPTS.md) | Prompts for ChatGPT / Gemini / Grok to cover what we can't scrape |
