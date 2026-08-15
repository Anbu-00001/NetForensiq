# External LLM Research Prompts — ChatGPT · Gemini · Grok

> **Why this file exists:** some sources can't be reached from this machine — X/Twitter is
> paywalled to scrapers (we got HTTP 402), YouTube transcripts, Gujarati-language news sites,
> Google-indexed PDFs, tender portals and academic databases are all easier for the hosted
> assistants that have native access to those corpora.
>
> **Non-overlap is enforced by design.** Each prompt has an explicit **DO NOT COVER** section
> naming the other two engines' territory. Run all three, then merge.

## The split

| Engine | Territory | Why it wins here |
|---|---|---|
| **Grok** | **X/Twitter + live social signal.** Real-time chatter, official police handles, participant/alumni posts, scam typologies circulating right now | Native, unrestricted X index. The others cannot see X properly |
| **ChatGPT** | **Documents & rigour.** Government PDFs, tenders/procurement, academic literature, benchmarks, standards, legal texts | Deep Research mode handles long PDFs and citation chains best |
| **Gemini** | **Video & vernacular.** YouTube content, Gujarati-language press, Google-indexed local sources, dataset discovery | Native YouTube + Google index + strong Indic-language coverage |

**Context to paste at the top of all three (shared preamble):**

```
CONTEXT (shared): I am preparing for KANAD S.H.I.E.L.D. 2026 — "Security Hackathon for
Intelligence, Encryption, Law Enforcement and Defence" — the Ahmedabad City Police
Innovation Challenge, run by the Cyber Crime Branch, Ahmedabad City Police (Shahibaug,
Ahmedabad, Gujarat, India) with i-Hub Gujarat as startup-ecosystem partner.
Official site: https://kanadshield.com

It has 26 published problem statements in two categories:
- Category 1 (startups/industry/researchers, 16 PS): big-data search over FIR/CDR/IPDR/1930
  data; dark web monitoring; mule bank account detection; bank statement analysis;
  cryptocurrency forensics; social media monitoring; spoofed/VoIP call detection; fake news
  and deepfake detection; Telegram illicit-group monitoring; mobile security hygiene; mobile
  forensics; CCTV video analysis; call-recording transcription; bulk SIM/IMSI reading;
  2G-5G Cell ID mapping; hoax bomb-threat email detection.
- Category 2 (students/graduates/doctoral, 10 PS): cyber-integrated safety platforms for
  women / children / senior citizens; unified legal & government intelligence platform for
  Central + Gujarat documents; police health & wellness monitoring; "CrimeGPT" crime
  documentation automation; crime hotspot mapping & predictive patrol routing; network &
  packet forensics; real-time data breach alerting; and an open-ended smart policing track.

I need research, not code. Cite every claim with a working URL and a date. If you cannot
verify something, say so explicitly rather than guessing — a confident "not found" is more
useful to me than a plausible invention.
```

---

# 1 · GROK — X/Twitter and live social signal

**Best mode:** DeepSearch / Think, with X search enabled.

```
[PASTE SHARED PREAMBLE ABOVE FIRST]

YOUR ASSIGNED TERRITORY: X (Twitter) and live social signal ONLY. You have native access
to X that other engines don't — that is the entire reason I'm asking you and not them.

Search X aggressively and report actual posts with @handles, dates, engagement, and links.

A. THE EVENT AND ITS PEOPLE
1. Everything posted about "KANAD SHIELD", "KANAD S.H.I.E.L.D", "kanadshield", and the
   Ahmedabad City Police Innovation Challenge 2026. Quote the posts.
2. Full activity review of @cybercrimeahd (Ahmedabad Cyber Crime) — what do they post about,
   what campaigns do they run, what cases do they publicise, what tone do they use? Summarise
   their last ~6 months and list their most-engaged posts.
3. i-Hub Gujarat's handles, Gujarat Police (@GujaratPolice), Ahmedabad Police
   (@AhmedabadPolice), Gujarat Home Department, Gujarat DGP and Ahmedabad CP handles — any
   posts about this hackathon, cyber initiatives, or startup partnerships.
4. Anyone posting as a participant, mentor, judge, or sponsor of this event. Any team
   announcements, prep threads, or post-event recaps from previous editions.
5. Search for a prior edition (2024/2025). If winners were announced on X, tell me who won
   and with what solution.

B. LIVE CYBERCRIME SIGNAL IN GUJARAT (from X, not from news sites)
6. Gujarati/Ahmedabad citizens posting about being scammed right now — what fraud types
   dominate? Quote representative posts. Look for: digital arrest, investment/trading app
   scams, UPI fraud, courier/FedEx scam, task scams, loan apps, sextortion, fake customer care.
7. Posts by Indian police handles, cyber-security researchers, and journalists about NEW or
   emerging fraud modus operandi in India in the last 6-12 months. I want the freshest
   typologies, especially anything involving AI voice cloning or deepfakes.
8. Chatter about hoax bomb threat emails to Indian schools/airports/hospitals — scale,
   recent incidents, how police responded. (This maps to a specific problem statement.)
9. Public discussion of mule bank accounts in India — recent enforcement actions, how mule
   networks are recruited (often via Telegram/X), and what banks/NPCI are doing.
10. Indian OSINT and infosec community accounts worth following for this domain — list
    handles with a one-line description of why each matters.

C. SENTIMENT AND CRITICISM
11. What do Indian citizens complain about most regarding cybercrime reporting — the 1930
    helpline, cybercrime.gov.in, police response? Quote real complaints. I want the pain
    points in victims' own words, because that is what a good pitch opens with.
12. Any criticism or controversy about Indian police surveillance/AI tech on X (facial
    recognition, predictive policing) that I should be prepared to answer for.

DO NOT COVER (other engines are assigned these — do not duplicate):
- Academic papers, benchmarks, standards, or government PDF reports  → ChatGPT's territory
- Government tenders or procurement documents                        → ChatGPT's territory
- Legal texts, BNS/BNSS/BSA analysis                                 → ChatGPT's territory
- YouTube videos or video content of any kind                        → Gemini's territory
- Gujarati-language newspaper articles                               → Gemini's territory
- Dataset discovery                                                  → Gemini's territory

OUTPUT: Markdown. One section per lettered block. For every X finding give @handle, date,
a quote, and the post URL. End with "Top 15 accounts to follow" and "What I could not find".
```

---

# 2 · CHATGPT — documents, procurement, academic rigour

**Best mode:** Deep Research (or o-series with browsing).

```
[PASTE SHARED PREAMBLE ABOVE FIRST]

YOUR ASSIGNED TERRITORY: Formal documents and academic rigour ONLY — PDFs, government
reports, tenders, standards, peer-reviewed literature, and legal texts. Depth and citation
quality matter more than breadth. Go find primary sources, not blog summaries.

A. PROCUREMENT — WHAT AHMEDABAD/GUJARAT POLICE ACTUALLY BUY
This is the highest-value section. Public tenders reveal exactly what technology the police
lack and are willing to pay for.
1. Search GeM (Government e-Marketplace), nprocure.com, Gujarat state tender portals, and
   tenders.gov.in for tenders by Gujarat Police, Gujarat Home Department, Ahmedabad City
   Police, Gujarat CID, and DFS Gandhinagar for: cyber forensics tools, mobile forensic
   equipment, CDR/IPDR analysis software, video analytics, data analytics platforms,
   command-and-control systems.
2. For each: tender ID, date, value, scope, and who won. Summarise what the specifications
   reveal about their existing gaps and their required feature sets.
3. Any RFP/EOI mentioning AI, machine learning, or "cyber" from Gujarat Police 2023-2026.

B. OFFICIAL REPORTS AND STATISTICS (primary PDFs, not news summaries)
4. NCRB "Crime in India" — latest published volume: Gujarat's cybercrime figures, and the
   national cybercrime chapter. Give table numbers and page references.
5. BPRD "Data on Police Organisations" — Gujarat's sanctioned vs actual strength, training,
   and cyber-cell capacity.
6. I4C / MHA annual reports and Parliament (Lok Sabha/Rajya Sabha) Q&A answers on: cyber
   fraud amounts reported to 1930/CFCFRMS, amounts frozen vs recovered, mule accounts frozen,
   NCRP complaint volumes — broken down by state where available.
7. RBI reports on digital payment fraud; NPCI material on mule account controls.
8. Gujarat Budget documents — Home Department allocation, modernisation of police forces.

C. THE LEGAL LAYER (cite section numbers precisely)
9. Bharatiya Sakshya Adhiniyam 2023 **Section 63** — exact text and requirements for
   electronic evidence certificates; how it differs from the old Evidence Act s.65B; leading
   case law (Anvar P.V., Arjun Panditrao Khotkar) and any post-2024 judgments.
10. BNSS 2023 provisions on: audio-video recording of search and seizure, e-FIR/zero FIR,
    mandatory forensic team visits for offences punishable by 7+ years, investigation
    timelines. Give section numbers.
11. IT Act sections 43A, 66C, 66D, 67, 69, 69A, 79; CERT-In April 2022 Directions (6-hour
    reporting, 180-day log retention); DPDP Act 2023 law-enforcement exemptions;
    Telecommunications Act 2023 interception provisions.
12. Standards for digital evidence handling: ISO/IEC 27037, 27041, 27042, 27043; NIST
    SP 800-86; SWGDE guidelines; and any Indian equivalent (CDAC/NFSU/DFS SOPs).

D. ACADEMIC LITERATURE (peer-reviewed, with DOIs)
13. Mule account and money-laundering detection using graph neural networks — key papers,
    reported performance, and public datasets (Elliptic, PaySim, IEEE-CIS, AMLSim).
14. Deepfake detection generalisation — survey papers and the documented cross-dataset
    performance collapse. I need honest numbers so I don't overclaim in my pitch.
15. Predictive policing efficacy AND bias — the evidence base for and against, including the
    Geolitica/PredPol evaluations and any Indian studies.
16. Indian-language (Gujarati) ASR and NLP — published word-error rates for Whisper,
    IndicWhisper, IndicConformer on Gujarati and code-mixed speech.
17. Grooming/cyberbullying detection in text — published approaches and datasets (PAN,
    ChatCoder, PJZ), and their limitations.
18. Police occupational stress and health in India — published studies, especially any on
    Gujarat Police (relevant to a specific problem statement).

DO NOT COVER (other engines are assigned these — do not duplicate):
- X/Twitter posts, social media chatter, or public sentiment  → Grok's territory
- YouTube or any video content                                → Gemini's territory
- Gujarati-language newspaper reporting                        → Gemini's territory
- Discovering downloadable datasets/repos to build on          → Gemini's territory

OUTPUT: Markdown with full citations (title, publisher, date, URL, DOI/page number). Include
a table of tenders found, a table of key legal provisions with section numbers, and an
annotated bibliography. Flag explicitly anything you could not verify.
```

---

# 3 · GEMINI — video, vernacular, and Google-native sources

**Best mode:** Deep Research, with YouTube access.

```
[PASTE SHARED PREAMBLE ABOVE FIRST]

YOUR ASSIGNED TERRITORY: Video content, Gujarati-language media, Google-indexed local
sources, and dataset discovery ONLY. You have native YouTube access and the strongest Indic
-language coverage — that is why I'm asking you specifically.

A. VIDEO INTELLIGENCE
1. Watch and summarise this video in detail, including anything said that isn't on the
   official website: https://www.youtube.com/watch?v=_CXryX4Si5s
   ("KANAD S.H.I.E.L.D — Gujarat Cyber Crime Department's BIG Opportunity for Startups")
   Give me timestamps, the speaker's identity, stated dates, prizes, judging process, and
   what they say they're looking for.
2. Find any other video about KANAD S.H.I.E.L.D., the Ahmedabad City Police Innovation
   Challenge, or i-Hub Gujarat's police-startup programme. Summarise each.
3. Gujarat Police / Ahmedabad Police official YouTube channels and press conferences —
   especially any DGP or Ahmedabad CP annual crime review press conference, and anything on
   cybercrime. Summarise what officers say their biggest challenges are, quoting them.
4. Videos demonstrating the tools named in the problem statements (Cellebrite, Magnet AXIOM,
   BriefCam, Chainalysis, Maltego, Arkime). I want to know what a polished version of each
   product actually looks like, so my UI doesn't look amateurish next to what judges have
   seen in vendor demos.
5. Any recorded talks by Indian police officers about cybercrime investigation workflow —
   how a 1930 complaint actually flows, what an investigator's day looks like.

B. GUJARATI-LANGUAGE AND LOCAL PRESS (translate to English, keep the original headline)
6. Search Gujarati-language sources — Divya Bhaskar (divyabhaskar.co.in), Sandesh
   (sandesh.com), Gujarat Samachar, VTV Gujarati, ABP Asmita, News18 Gujarati — for coverage
   of: Ahmedabad Cyber Crime Branch operations, cyber fraud cases in Ahmedabad/Gujarat,
   arrests, and any coverage of this hackathon.
   Search in Gujarati script too: સાયબર ક્રાઈમ અમદાવાદ, સાયબર છેતરપિંડી ગુજરાત, અમદાવાદ પોલીસ.
7. Recent (2025-2026) Ahmedabad cybercrime case studies from local press — I want 5-10
   concrete, citable local incidents with amounts and dates to open a pitch with.
8. Local reporting on Gujarat Police technology initiatives, and on the Cyber Ashwast /
   cyber awareness programmes.
9. Any local reporting on hoax bomb threat emails to Gujarat schools/institutions.

C. DATASET AND REPOSITORY DISCOVERY (find things I can actually download)
10. Use Google Dataset Search, Kaggle, HuggingFace, GitHub and data.gov.in to find
    downloadable, openly-licensed datasets for: financial fraud / mule accounts; phishing and
    spam email corpora; deepfake detection benchmarks; CCTV/surveillance video with
    annotations; Gujarati speech and text corpora; Indian legal documents and judgments;
    crime incident data with geolocation; network traffic PCAPs.
    For each: name, size, licence, direct download link, and whether registration is needed.
11. Find GitHub repositories that are strong starting points for the Category 2 problems —
    especially: legal document RAG systems, Indian-language OCR pipelines, women's-safety app
    implementations, crime hotspot mapping with KDE/DBSCAN, and breach-monitoring tools.
    Give stars, last-commit date, and licence. Flag anything abandoned.
12. Gujarat government open data — GR portals, gujaratindia.gov.in, Gujarat gazette,
    Home Department circular archives. Tell me exactly which URLs are scrapeable, whether
    they're HTML or scanned PDF, and roughly how many documents each holds. (This directly
    determines feasibility of the Unified Legal Platform problem statement.)

D. LOCAL LOGISTICS
13. Ahmedabad: where is the Cyber Crime Branch at Shahibaug, what's nearby, and what should
    a visiting team know practically (travel, weather in the relevant season, accommodation)?

DO NOT COVER (other engines are assigned these — do not duplicate):
- X/Twitter posts or social media sentiment          → Grok's territory
- Academic papers, benchmarks, standards, DOIs        → ChatGPT's territory
- Government tenders and procurement documents        → ChatGPT's territory
- Legal analysis of BNS/BNSS/BSA section numbers      → ChatGPT's territory

OUTPUT: Markdown. For videos: title, channel, date, URL, and a detailed summary with
timestamps. For Gujarati articles: original headline, English translation, outlet, date, URL.
For datasets/repos: a table with licence and direct link. End with "What I could not find".
```

---

## After you run all three

Merge into a single file in this folder and reconcile conflicts. Where two engines disagree on
a number, keep both and mark the discrepancy — do not silently pick one.

**Highest-value answers to look for, in priority order:**

1. **Event mechanics from the Gemini video** — dates, prizes, judging. The website doesn't say.
2. **Previous-edition winners** (Grok) — the single best predictor of what this panel rewards.
3. **Scrapeability of Gujarat GR portals** (Gemini) — decides whether the Unified Legal
   Platform pick is viable.
4. **Tender specifications** (ChatGPT) — literally the police writing down what they lack.
5. **Local Ahmedabad fraud cases with amounts** (Gemini) — your opening slide.
6. **Honest deepfake/predictive-policing performance numbers** (ChatGPT) — so you don't
   overclaim in front of people who will know better.
