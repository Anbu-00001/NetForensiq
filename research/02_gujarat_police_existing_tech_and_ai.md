# Gujarat Police & Gujarat Government — Existing Technology, AI & Engineered Systems (Pre-Hackathon Intelligence)

*Compiled for KANAD S.H.I.E.L.D hackathon prep. Focus: 2022–2026 deployments. All figures are sourced inline; conflicting figures from different official/press sources are shown side-by-side rather than silently reconciled.*

---

## 1. Executive Summary

Gujarat Police runs one of India's most mature state-level policing tech stacks, built around **Project VISHWAS** (statewide CCTV + traffic + command centers), a body-worn-camera fleet, a growing drone program (**GP-DRASTI**), a long-running e-governance layer (**e-GujCop / Citizen First**), and — very recently (2025–2026) — a first wave of genuinely generative/AI tools (**NARIT AI** for narcotics case-building, AI crowd-analytics for Rath Yatra/Kankaria Carnival). Facial recognition exists but is **fragmented and city-specific** (Vadodara only, tied to the controversial Clearview AI), not a unified statewide capability. Predictive policing has been **discussed at conferences but has no confirmed operational deployment** in Gujarat. Most "AI" wins to date are narrow, single-purpose tools layered onto a very large existing camera/data estate — which is exactly where a hackathon team can add the most value: **integration, search, and citizen-facing intelligence layers on top of infrastructure that already exists**, rather than net-new hardware/surveillance builds.

---

## 2. Project VISHWAS — the backbone

**Full name:** Video Integration and State-Wide Advanced Security. Original vision dates to 2013–14 pilots in Ahmedabad, Vadodara and Gandhinagar under then-CM Narendra Modi ([Deccan Herald archive](https://www.deccanherald.com/archives/delhi-cops-learn-from-modis-gujarat-bring-his-cctv-plan-to-two-localities-400561.html)); the modern statewide rollout began around 2020.

| Phase | Cameras | Coverage | Status/Date | Source |
|---|---|---|---|---|
| Phase 1 | 7,000 CCTV | 34 district HQs, 41 cities, 6 pilgrimage sites (Somnath, Dwarka, Palitana, Ambaji, Pavagadh, Dakor) + Statue of Unity | Completed 1 May 2022 | [Vibes of India](https://www.vibesofindia.com/equipped-with-7-thousand-cctv-project-vishwas-of-surveillance-in-gujarat/), [DeshGujarat](https://deshgujarat.com/2022/07/02/7000-cctv-cameras-installed-in-gujarat-under-phase-i-of-viswas-10000-to-be-installed-in-phase-ii/) |
| Phase 2 | 10,000–12,500 additional | Surat city, Vadodara city, 51–52 Tier-3 municipalities, 79–80 inter-state entry/exit checkpoints | Targeted end-2023, still expanding as of late 2025 | [DeshGujarat](https://deshgujarat.com/2023/12/15/10500-cctv-cameras-being-installed-across-gujarat-under-viswas-project/) |
| Cumulative (latest) | 12,500+ | 54 cities (some coverage descriptions say "nearly 100 cities" including smaller towns) | As of Nov 2025 | [Indian Masterminds — Vishwas 2.0](https://indianmasterminds.com/states/gujarat/gujarat-project-vishwas-next-gen-policing-2030-games-163580/) |

**Additional VISHWAS assets:**
- **Body-worn cameras:** 10,000 units (9,000 standalone + ~1,000 with live-broadcast capability); docking/charging stations installed at **622 police stations** tied to a Digital Evidence Management System ([Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/)). Separately, **Axon** announced in August 2021 a **10,350-camera** rollout with its Digital Evidence Management solution, calling it the "largest body-worn camera rollout in India" — Gujarat State Police was the first Indian agency to pair BWCs with Axon's evidence platform ([Axon investor release](https://investor.axon.com/2021-08-24-Gujarat-State-Police-Joins-the-Axon-Network-with-Largest-Body-Worn-Camera-Rollout-in-India), [DeshGujarat](https://deshgujarat.com/2021/03/14/gujarat-police-gets-10000-body-worn-cameras-including-1000-that-can-do-live-broadcast/)).
- **Drone cameras:** reported as 15 (2023 figure) growing to 21 (later figure), thermal + daylight vision, up to 200 m altitude, ~90-minute endurance — this is the VISHWAS drone layer, distinct from the newer GP-DRASTI rapid-response program (see §5) ([Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/)).
- **ITMS (Intelligent/Integrated Traffic Management System):** ANPR, automatic red-light-violation detection, stolen-vehicle alerts, illegal parking, wrong-way driving, crowd density, unattended-object detection, camera-tampering detection ([Vibes of India](https://www.vibesofindia.com/equipped-with-7-thousand-cctv-project-vishwas-of-surveillance-in-gujarat/), [NITI Aayog Frontier Tech](https://frontiertech.niti.gov.in/story/ai-for-urban-vigilance-enforcement-and-safety-in-the-age-of-smart-governance)).
- **VIMS (Video Incident Management System)** for post-incident forensic video review ([Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/)).

**Claimed results (note: figures conflict across official/press sources — reproduced as published):**
- Road-accident reduction: **19.09%** (2018–2021) per one source vs **29%** (2018–2020) per another — ⚠️ **discrepancy, not reconciled by any source found**.
- **6,200+** criminal cases aided by video evidence; **₹13.99 crore** in recovered stolen property ([Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/)).
- **15,32,253 e-challans** worth **₹55.2 crore** issued by 13 June 2022 ([Vibes of India](https://www.vibesofindia.com/equipped-with-7-thousand-cctv-project-vishwas-of-surveillance-in-gujarat/)).
- **National e-Governance Gold Award** received for VISHWAS ([Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/)).
- Leadership credited: IPS officer **Narasimha Komar/Kumar** (1996 batch), now Vadodara Police Commissioner, has been the public face of the project ([Indian Masterminds](https://indianmasterminds.com/states/gujarat/gujarat-project-vishwas-next-gen-policing-2030-games-163580/)).
- **Vishwas 2.0** is explicitly framed as preparation for the **2030 Commonwealth Games in Ahmedabad** ([Indian Masterminds](https://indianmasterminds.com/states/gujarat/gujarat-project-vishwas-next-gen-policing-2030-games-163580/), [News on Air](https://www.newsonair.gov.in/ahmedabad-in-gujarat-recommended-as-the-host-city-for-2030-commonwealth-games)).
- No public vendor list or budget figure for VISHWAS overall was found in any source — ⚠️ **UNVERIFIED / not disclosed**.

---

## 3. TRINETRA — important correction to the assumed brief

Research shows **TRINETRA in Gujarat is *not* a separate AI/data-analytics platform** — it is the **name of the state-level mega command-and-control room in Gandhinagar** that anchors Project VISHWAS, functioning as the "third eye" of Gujarat Police ([Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/)). Physically this sits inside/alongside the **i3C (Integrated Command & Control Centre)** at Police Bhawan, Gandhinagar, which fuses CCTV, body-worn-camera and drone feeds ([DeshGujarat / Vishwas 2.0 coverage](https://indianmasterminds.com/states/gujarat/gujarat-project-vishwas-next-gen-policing-2030-games-163580/)).

Below TRINETRA sit **34 district-level command centres called "NETRAM"** (one per district), each with video walls, local data centres and secure networks, all uplinked to the Gandhinagar hub — giving a genuine single-point statewide monitoring capability ([Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/)).

**Do not confuse this with:**
- **"Project Trinetra" (Akola Police, Maharashtra)** — India's first AI-driven *predictive* policing initiative, unrelated to Gujarat ([Insights on India](https://www.insightsonindia.com/2025/10/17/project-trinetra-ai-predictive-policing/)).
- **C-DOT's "TRINETRA"** — a commercial AI-powered enterprise cybersecurity product, also unrelated ([C-DOT](https://www.cdot.in/cdotweb/assets/docs/products/sec_sol/trinetra.pdf)).
- **UP Police's 2018 "Trinetra" mobile app** — a different state, different tool ([search snippet reference only]).

There is **no evidence of a Gujarat-specific analytics/predictive layer branded "TRINETRA"** beyond the physical command centre — this is a naming collision the hackathon brief should not repeat.

---

## 4. e-GujCop, e-FIR, Citizen First & digital citizen services

- **e-GujCop** launched **19 September 2013** — the Home Department's core application building "a database of crime and criminal information for a strong decision support system" for officers ([The Protector](https://www.theprotector.in/egujcop-gujarat-police-steers-ahead-in-technology-use/), [GKToday](https://www.gktoday.in/what-is-e-fir-system-launched-by-gujarat-police/)).
- **e-FIR** (subset of e-GujCop): citizens can file FIRs online for **specific unidentified-accused theft cases** — two-wheeler/four-wheeler theft and lost/stolen mobile phones. Police contact the complainant **within 48 hours**, and investigation is expected to close within **21 days**, with a status report filed to court ([GKToday](https://www.gktoday.in/what-is-e-fir-system-launched-by-gujarat-police/)).
- The e-FIR/stolen-vehicle module is **synced with the VISHWAS CCTV command centre** — a stolen vehicle's number plate re-appearing on ANPR anywhere in the state auto-surfaces on control-room screens ([GKToday](https://www.gktoday.in/what-is-e-fir-system-launched-by-gujarat-police/)).
- **Citizen First** mobile app (Android package `com.tcs.digigov.mobility.dhs.citizen.gj` — confirms **TCS** built the platform) and a parallel web **Citizen Portal** (gujhome.gujarat.gov.in) offer **16 online services**: application registration, senior-citizen registration, missing-person registration, stolen-property registration, domestic-help/tenant registration, property/NOC requests, FIR-copy download, etc. ([Google Play](https://play.google.com/store/apps/details?id=com.tcs.digigov.mobility.dhs.citizen.gj&hl=en_US), [GKToday](https://www.gktoday.in/what-is-e-fir-system-launched-by-gujarat-police/)).
- No evidence found of a **speech-to-text or conversational-AI layer** on top of Citizen First / e-FIR — filing remains **form-based**, not voice/chat-based. See Whitespace §12.

---

## 5. Drones & UAVs

| System | What it is | Key facts | Source |
|---|---|---|---|
| **NETRA (2013)** | Early VTOL quadrotor UAV pilot | Day/night cameras, GPS, infrared; first used for crowd surveillance at Ahmedabad Rath Yatra 2013; also used by CRPF | [DeshGujarat](https://deshgujarat.com/2013/07/10/gujarat-police-uses-netra-uav-to-keep-watch-over-rath-yatra/) |
| **VISHWAS drone layer** | Ongoing surveillance drones tied to command centres | 15→21 units, thermal+daylight, 200 m altitude, 90-min endurance | [Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/) |
| **GP-DRASTI** | **G**ujarat **P**olice – **D**rone **R**esponse and **A**erial **S**urveillance **T**actical **I**nterventions | Launched April 2025; rapid-response drones dispatched to reported crime scenes ahead of/alongside PCR vans | [ANI](https://aninews.in/news/national/general-news/using-drones-to-reduce-response-time-gujarat-police-launches-special-project-gp-drasti20250404171558/), [IASGyan](https://www.iasgyan.in/daily-current-affairs/gp-drashti-drone) |

**GP-DRASTI details:** Quadcopters with **1 km zoom**, night vision, **45-minute flight time**, **4 km range** from base station; two-person teams (pilot + local guide); **Phase 1 covers 33 police stations across Ahmedabad, Surat, Vadodara, Rajkot** (chosen for higher crime rates); **16 officers** trained at the Gujarat Police Academy; pilot in Surat/Ahmedabad showed drones reaching scenes in **2–2.5 minutes**, less than half the time of PCR vans; vendor **Asteria Aerospace** supplied Phase 1 drones (8 received, 18+ more being procured) ([Inside FPV](https://insidefpv.com/blogs/blogs/how-gujarat-police-are-using-drones-to-combat-crime), [IASGyan](https://www.iasgyan.in/daily-current-affairs/gp-drashti-drone), [DeshGujarat](https://deshgujarat.com/2025/04/04/gujarat-police-to-launch-gp-drashti-a-drone-based-rapid-response-surveillance-project/)).

**Anti-drone / counter-UAS:** This capability at the **India-Pakistan border through Gujarat (Sar Creek to Barmer)** is run by the **BSF (a central force), not Gujarat Police**. BSF reported thwarting **600+ hostile drones** on the Gujarat frontier in 2025, using handheld RF jammers, and is developing AI-based counter-drone detection with DRDO, BPR&D and startup **Skylark Labs India**; the central Drone Forensic Lab is at Chhawla, Delhi — outside Gujarat ([DeshGujarat](https://deshgujarat.com/2025/05/30/india-thwarted-600-plus-drones-sent-by-pakistan-on-gujarat-frontier-bsf/), [ORF](https://www.orfonline.org/research/countering-hostile-drone-activity-on-the-india-pakistan-border)). **No evidence of a Gujarat-Police-owned counter-drone system** for cities/events (e.g., protecting Rath Yatra or Commonwealth Games airspace from hostile/rogue drones) was found — flagged as whitespace.

---

## 6. Facial Recognition

| Aspect | Detail | Source |
|---|---|---|
| First deployment | **Vadodara City Police** — first in the state to test an AI facial recognition system (FRS), Aug 2020 | [BusinessWorld/ANI](https://www.businessworld.in/article/Gujarat-police-tests-AI-based-facial-recognition-system-to-check-crime-/15-08-2020-309043/) |
| Scale | Tied to **~700 CCTV cameras** across Vadodara; matched against a database of absconders, missing children and wanted criminals | [Inc42](https://inc42.com/buzz/police-in-gujarat-to-use-controversial-clearview-ai-facial-recognition-system/) |
| Vendor | **Clearview AI** — the controversial US company that scrapes public social-media images (Facebook, Instagram) to build its face database | [Inc42](https://inc42.com/buzz/police-in-gujarat-to-use-controversial-clearview-ai-facial-recognition-system/) |
| Statewide FRS | **No evidence of a statewide, standardized Gujarat Police FRS** — only the Vadodara city pilot was documented | — |
| Accuracy claims | None published/audited that could be found | ⚠️ UNVERIFIED |

**ASTR (separate, DoT-owned tool used by Gujarat agencies):** Artificial-intelligence + facial-recognition tool ("**A**rtificial Intelligence and Facial Recognition Powered **S**olution for **T**elecom SIM Subscriber Verification") built by India's Department of Telecommunications, not by Gujarat Police. Gujarat's **CID cybercrime cell and Anti-Terrorist Squad (ATS)** used ASTR in April 2023 to analyze a national database of **8.12 crore telecom subscribers**, uncovering **29,552 fake/duplicate SIM cards** issued on forged documents and leading to **37 arrests** ([Medianama](https://www.medianama.com/2023/04/223-gujarat-officials-astr-catch-fake-sim-card-holders/), [ThePrint](https://theprint.in/india/more-than-29000-sim-cards-activated-using-fake-documents-in-gujarat-18-held/1523945/)).

**Context/criticism:** India has **no dedicated law governing facial recognition** in policing; civil-liberties groups nationally warn of mass-surveillance risk, misidentification bias against women and minorities, and chilling effects on assembly/speech ([Outlook India](https://www.outlookindia.com/national/facial-recognition-in-india-privacy-surveillance-and-missing-legal-framework), [Al Jazeera](https://www.aljazeera.com/amp/news/2019/12/30/privacy-fears-as-india-police-use-facial-recognition-at-rally)). No Gujarat-specific FRS controversy/incident beyond the general Clearview-AI vendor-choice criticism was found.

---

## 7. CCTNS & ICJS status in Gujarat

- **CCTNS** (Crime and Criminal Tracking Network & Systems): Gujarat was cited among the **early leading states** (with Karnataka, Goa, Andhra Pradesh) in CCTNS rollout ([MHA evaluation report](https://www.mha.gov.in/sites/default/files/IIPA-Report-CCTNS.pdf)). In the most recent **CCTNS PRAGATI performance ranking** referenced in press coverage, Gujarat scored **97.08**, placing **3rd nationally**, behind Himachal Pradesh (99.77) and Uttar Pradesh (99.01) — ⚠️ exact month/year of this specific ranking not confirmed in source ([Deccan Herald](https://www.deccanherald.com/india/himachal-pradesh-tops-crime-and-criminal-tracking-network-and-systems-pragati-ranking-for-january-1195779.html)).
- **ICJS** (Inter-operable Criminal Justice System): implemented across **36 states/UTs including Gujarat**, integrating Police (CCTNS), Courts (e-Courts), Jails (e-Prisons), Forensic Labs (e-Forensic) and Prosecution (e-Prosecution) on a "one data, one entry" principle; run by NCRB with NIC ([MHA](https://www.mha.gov.in/en/commoncontent/inter-operable-criminal-justice-system-icjs), [PIB factsheet](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2022/jun/doc202262367401.pdf)). No Gujarat-specific ICJS performance data (e.g., FIR-to-chargesheet-to-trial latency) was found — flagged as a gap.

---

## 8. City-level Safe City / Smart City surveillance (Ahmedabad, Surat, Vadodara, Rajkot)

| City | Program | Cameras / Infra | Vendor | Claimed impact | Source |
|---|---|---|---|---|---|
| Ahmedabad | ITMS + ATCS integrated with ICCC | ATCS at 63 junctions, ITMS at 43 junctions; auto e-challans for red-light, no-helmet, triple-riding, no-seatbelt, driving-on-call, speeding | Not identified in sources found | Not quantified | [NIUA ICCC case study](https://iccc.niua.org/iccc/sector/use-case/815e6212def15fe76ed27cec7a393d59) |
| Surat | **Safe City Project** | 604 HD-CCTV (older figure) up to ~6,000 cameras (broader claim, unclear if same base) | **Microsoft** (CityNext, 60+ digital solutions) — Surat was first Indian city on Microsoft CityNext | **27% crime reduction** claimed | [SourceSecurity/RK Fibergrid](http://www.rkfibergrid.com/safecity.html) |
| Vadodara | Smart City surveillance | ANPR at **15 traffic junctions**, UVCP (Unified Video Computing Platform), Command Control Centre, "smart poles" (Wi-Fi + CCTV + SOS + sensors) | **Videonetics** | Not quantified | [Videonetics case study](https://www.videonetics.com/case-study/gujarat-case-study), [Better India — smart poles](https://thebetterindia.com/innovation/vadodara-smart-poles-urban-safety-free-wifi-10920851) |
| Rajkot | ICCC-based smart city monitoring | ~1,000 cameras at key public/traffic/municipal locations | Not identified | Cited as "model smart city" | [ANI/Construction World](https://www.constructionworld.in/urban-infrastructure/smart-cities-projects/rajkot-emerges-as-model-smart-and-sustainable-city/) |

⚠️ Note the **Surat camera-count discrepancy** (604 vs ~6,000) across sources — not reconciled; likely reflects different points in time or different scope (Safe City core vs city-wide aggregate).

---

## 9. Emergency Response Systems

### Dial 112 (ERSS)
- Launched statewide framework **19 February 2019**, merging Police, Fire, Health, Women & Child Development, and Revenue-Disaster-Management toll-free numbers into one ([DeshGujarat](https://deshgujarat.com/2025/03/27/112-emergency-helpline-set-to-roll-out-across-gujarat-1-4-crore-calls-handled-so-far/)).
- Piloted in **7 districts**: Gir Somnath, Devbhoomi Dwarka, Morbi, Chhota Udepur, Botad, Aravalli, Mahisagar — average **police response time: 26 minutes 59 seconds** in these districts (⚠️ figure's currency/date unclear).
- **1.49 crore emergency calls** handled cumulatively; **69,477 cases** with physical emergency-team dispatch; statewide expansion beyond the pilot districts underway as of March 2025 ([DeshGujarat](https://deshgujarat.com/2025/03/27/112-emergency-helpline-set-to-roll-out-across-gujarat-1-4-crore-calls-handled-so-far/)).

### 108 (GVK EMRI)
- **Gujarat was the first state in India** where GVK EMRI's "108" ambulance service was launched, in partnership with the state government ([Global Gujarat](https://www.globalgujarat.com/108_EMRI.html)).
- Technology: GPS-based automatic vehicle-location tracking, real-time patient-vitals monitoring at Emergency Response Centres ([The Better India](https://thebetterindia.com/187773/gvk-emri-108-ambulance-emergency-healthcare-service-india/)).
- National-scale aggregate (not Gujarat-only, cited for context): ~13,000 ambulances, 68 million cases attended, 3.2 million lives saved, across 16 states + 2 UTs ([The Better India](https://thebetterindia.com/187773/gvk-emri-108-ambulance-emergency-healthcare-service-india/)) — ⚠️ **Gujarat-specific case counts not isolated in sources found**.

### 181 Abhayam (Women's Helpline)
- Run by Women & Child Development Dept with EMRI; mobile app since **August 2018** ([DeshGujarat](https://deshgujarat.com/2018/08/06/gujarat-government-launches-181-abhayam-helpline-mobile-app/)).
- App features: **panic button**, **"phone-shake" silent trigger**, live location via Google Maps, photo/video evidence upload, automatic SMS alerts to 5 pre-designated relatives ([Deccan Herald](https://www.deccanherald.com/india/gujarat-launches-new-mobile-app-for-women-safety-685947.html)).
- **59 modern rescue vans** with GPS tracking deployed as mobile safety centres ([Assam Tribune](https://assamtribune.com/national/gujarats-181-abhayam-marks-12-yrs-18-lakh-women-helped-1609153)).
- 12-year cumulative impact (as of ~2024–25): **18 lakh+ women supported**, **1 lakh+ rescued** from high-risk situations.

---

## 10. National Forensic Sciences University (NFSU), Gandhinagar

- Status: **Institution of National Importance**, described as "the world's first and only University dedicated to Forensic, behavioral, cybersecurity, digital forensics, and allied Sciences" ([NFSU](https://www.nfsu.ac.in/)).
- **8 schools**, 46 courses, including a dedicated **School of Cyber Security and Digital Forensics** ([IES Online](https://www.iesonline.co.in/national-forensic-sciences-university-gandhinagar/)).
- **Centres of Excellence** in Cyber Security, DNA Profiling, and Narcotic Drugs; a dedicated **Cyber Defence Centre (CDC)** on campus ([NFSU CoE page](https://www.nfsu.ac.in/centre_of_excellence)).
- **DGGI–NFSU Digital Forensic Laboratory** inaugurated **8 January 2024** at the Gandhinagar campus — one of **5 such labs** built nationally (Gandhinagar, Delhi, Kolkata, Mumbai, Chennai) at a combined cost of **₹16 crore**, in partnership with the Directorate General of GST Intelligence, to strengthen GST-fraud/cyber-forensic capability ([PIB](https://www.pib.gov.in/PressReleasePage.aspx?PRID=1994273), [NFSU](https://nfsu.ac.in/details/201)).
- No direct evidence found of NFSU running **operational AI R&D specifically embedded into Gujarat Police's day-to-day tools** (e.g., NARIT AI's developer is credited to Western Railway Police + an unnamed Mumbai AI startup, not NFSU) — worth flagging as a **partnership gap/opportunity**: NFSU's research capacity does not appear to be the direct engine behind Gujarat Police's newest AI tools.

---

## 11. AI-specific deployments (2025–2026 wave)

### NARIT AI — Narcotics Analysis & RAG-based Investigation Tool
- Launched **10 April 2026** in Gandhinagar — described as **India's first AI tool dedicated to narcotics (NDPS) investigations** ([Deccan Herald](https://www.deccanherald.com/india/gujarat/gujarat-police-launch-ai-based-tool-to-aid-narcotics-investigation-3963622), [DD News](https://ddnews.gov.in/en/narit-ai-gujarat-police-launches-ai-tool-for-ndps-case-analysis/)).
- **Developer:** Western Railway Police (Vadodara Division) in collaboration with an unnamed **Mumbai-based AI startup**.
- **Architecture:** RAG (retrieval-augmented generation) over a **closed, verified database** — explicitly designed to minimize hallucination — trained on Supreme Court/High Court judgments, the **NDPS Act 1985**, and the new criminal codes (**BNS, BNSS, BSA**).
- **Function:** Investigating Officer uploads an FIR → tool generates a structured case-strength/weakness report, a mandatory evidence checklist specific to the narcotic type, a draft chargesheet and court summary, and flags "Prosecution Weaknesses" with anticipated "Defence Rebuttals."
- **Governance:** Per **Gujarat High Court guidelines**, NARIT AI is classified as an **internal-only tool**, not accessible to the public — an important signal about judicial caution on AI in the criminal-justice pipeline that any hackathon investigation-assist tool should design around ([Insights on India](https://www.insightsonindia.com/2026/04/22/narcotics-analysis-rag-based-investigation-tool-narit-ai/)).
- **Scope limitation:** covers **only narcotics/NDPS cases** — no equivalent tool found for cyber fraud, POCSO, economic offences, etc. (see Whitespace).

### AI Crowd Management (Ahmedabad Rath Yatra, Kankaria Carnival)
- **148th Ahmedabad Jagannath Rath Yatra (June 2025):** 16 km route secured with **3,500+ CCTV cameras**, **227 live-monitored cameras**, **41 drones**, **2,872 body-worn cameras**, **240 terrace observation points**, **25 watchtowers**, and **23,884+ security personnel** ([DeshGujarat](https://deshgujarat.com/2025/06/24/ahmedabad-rath-yatra-2025-over-23000-cops-227-live-cameras-41-drones-2872-body-cameras-to-monitor-security/)).
- **AI system:** an "anti-stampede" crowd-monitoring layer using **pixel-counting and thermal imaging** to estimate crowd density in real time, flagging zones exceeding safe density thresholds, forecasting bottlenecks from movement trends, and suggesting dispersal routes ([Insights on India](https://www.insightsonindia.com/2025/06/11/ahmedabad-polices-ai-crowd-management-system/), [ETV Bharat](https://www.etvbharat.com/en/!bharat/jagannath-rath-yatra-2025-ahmedabad-police-to-use-ai-for-public-safety-effective-crowd-control-enn25062106240)).
- Same/similar AI crowd-analytics layer was **extended to the Kankaria Carnival** in Ahmedabad ([Gujarat Samachar English](https://english.gujaratsamachar.com/news/gujarat/ai-surveillance-deployed-for-crowd-management-at-kankaria-carnival-in-ahmedabad)) — vendor not identified in research (search budget exhausted before this could be resolved; ⚠️ UNVERIFIED vendor).
- **No evidence found** that this event-specific AI crowd system has been generalized to **Rann Utsav, Somnath, Dwarka, Ambaji** or routine Navratri crowds statewide — it currently appears **event-specific and Ahmedabad-centric**, not a reusable statewide "crowd safety" platform.

### Predictive Policing
- Discussed at the **44th All India Police Science Congress** (Gandhinagar, March) in a DGP round-table on "predictive policing," alongside sessions on voice identification, tele-forensics and cyber forensics ([search-derived, conference-context only]).
- **No confirmed operational predictive-policing deployment** by Gujarat Police was found (contrast with Bengaluru City Police and Akola Police in Maharashtra, which have documented live predictive/preventive-policing tools) ([Deccan Herald — Bengaluru](https://www.deccanherald.com/amp/story/india%2Fkarnataka%2Fbengaluru%2Fb-luru-police-use-ai-driven-techniques-to-prevent-crime-2784552)). This is a genuine **capability gap for Gujarat** relative to peer states.

### Gujarat AI Action Plan 2025–2030
- **Approved** following the CM's "Chintan Shivir" in **Somnath, November 2024**; CM **Bhupendra Patel** announced the state would broadly adopt AI in administration ([Outlook India](https://www.outlookindia.com/announcements/gujarat-cm-bhupendra-patel-unveils-5-year-ai-action-plan-2025-2030-to-lead-ai-driven-governance-digital-innovation)).
- Built on a **10-member AI task force**; **6 focus pillars**: data security, digital infrastructure, capacity building, R&D, startup support, and safe/trustworthy AI ([Elets eGov](https://egov.eletsonline.com/2025/07/ai-mission-2025-to-2030-announced-by-gujarat-chief-minister/)).
- Phased rollout: state-level **AI data repository**, **"AI factories,"** and **department-specific pilot projects**; targets skilling **2.5 lakh** people (students, MSME staff, govt employees) ([Storyboard18](https://www.storyboard18.com/digital/gujarat-approves-5-year-action-plan-to-integrate-ai-in-governance-77303.htm)).
- Named priority sectors in coverage found: **healthcare, education, agriculture, finance** — ⚠️ **Home Department/Police was not explicitly named as a pilot vertical** in any source found, which is notable given how much policing infrastructure already exists to build on.
- Separately, Gujarat has a stated **Intel partnership** for AI/digital-economy growth ([IndiaAI](https://indiaai.gov.in/article/gujarat-and-intel-forge-partnership-to-propel-ai-and-digital-economy-growth)) — details thin in sources found, flagged for follow-up.

---

## 12. Citizen-facing programs beyond apps

### Suraksha Setu Society
- Established **September 2012** under then-CM Narendra Modi, focused on community policing and bridging the police-public gap ([ANI](https://www.aninews.in/news/national/general-news/suraksha-setu-society-strengthening-gujarats-safety-through-a-strong-police-public-connection20250214041045/)).
- **Annual budget: ₹20–30 crore** ([Big News Network](https://www.bignewsnetwork.com/news/278049501/gujarat-government-allocates-rs-20-30-crore-to-suraksha-setu-society-for-public-safety-initiatives)).
- FY2024–25 activity: **98,852 women** given self-defense training; **Student Police Cadet Scheme** reached **45,579 students** (classes 8–9); traffic-safety awareness reached **1,62,000+ citizens**; **478 women bootleggers** rehabilitated into lawful livelihoods.
- This is a **people/programme layer, not a technology platform** — but it is a plausible distribution channel for any citizen-facing hackathon product (e.g., an app/chatbot could be piloted through Suraksha Setu's existing community-outreach network).

---

## 13. Cyber Crime Infrastructure

| Component | Detail | Source |
|---|---|---|
| **1930 helpline** | National cyber-fraud helpline (est. Jan 2018 nationally); Gujarat DGP has publicly reviewed operations "for faster resolution"; toll-free since ~May 2022 in Gujarat messaging | [DeshGujarat](https://deshgujarat.com/2022/05/20/dial-toll-free-helpline-number-1930-for-redressal-of-cyber-crime/) |
| **State Cyber Crime Cell, CID Crime** | HQ at Karmyogi Bhavan, Sector-10A, Gandhinagar | [SKOCH exhibition profile](https://exhibition.skoch.in/beacon-of-hope/state-cyber-crime-cell-cid-crime-gandhinagar-gujarat/) |
| **Cyber Sentinels Lab, Rajkot** | Gujarat's **first** district-level cyber lab of this kind; opened **Feb 2025**; staffed by 1 PI, 3 PSI, 10 constables + 3 contract cyber experts; 14 high-tech workstations | [Aaj Tak](https://www.aajtak.in/india/gujarat/story/cyber-crime-will-be-curbed-in-gujarat-first-cyber-sentinels-lab-established-in-rajkot-lcly-strc-2159235-2025-02-05) |
| **AASHVAST** | Cyber-security project launched **alongside VISWAS** by the Union Home Minister — headline-level confirmation only; article body not retrievable (404) ⚠️ **UNVERIFIED details** | [CMO Gujarat headline](https://cmogujarat.gov.in/en/latest-news/union-home-minister-launches-aashvast-and-viswas-project-of-gujarat-police-for-cyber-security/) |
| **Cyber Gujarat / Cyber Centre of Excellence** | Active public-facing social presence (@CyberGujarat) for awareness; scope beyond social media not confirmed | [X/Twitter](https://x.com/CyberGujarat) |
| **gujaratcybercrime.org** | Public complaint/awareness portal | [Gujarat Cyber Crime](https://gujaratcybercrime.org/eng/) |

**Note:** despite Gujarat Police's clear investment in cyber-fraud response infrastructure, **no AI/graph-analytics tool for detecting mule-account networks or fraud rings** from 1930-helpline data was found — a plausible hackathon opportunity given fraud volumes nationally are enormous.

---

## 14. Partnerships & Vendors — consolidated table

| Partner | Role | System | Source |
|---|---|---|---|
| **TCS** | App/platform developer | Citizen First app, e-GujCop mobility platform | [Google Play package ID](https://play.google.com/store/apps/details?id=com.tcs.digigov.mobility.dhs.citizen.gj) |
| **Axon** | Body-worn camera + evidence mgmt vendor | 10,350 BWCs + Digital Evidence Mgmt (Aug 2021) | [Axon investor release](https://investor.axon.com/2021-08-24-Gujarat-State-Police-Joins-the-Axon-Network-with-Largest-Body-Worn-Camera-Rollout-in-India) |
| **Asteria Aerospace** | Drone supplier | GP-DRASTI Phase 1 drones | [Inside FPV](https://insidefpv.com/blogs/blogs/how-gujarat-police-are-using-drones-to-combat-crime) |
| **Videonetics** | Video analytics / ANPR / UVCP vendor | Vadodara Smart City surveillance | [Videonetics case study](https://www.videonetics.com/case-study/gujarat-case-study) |
| **Microsoft (CityNext)** | Cloud/digital-solutions partner | Surat Safe City Project | [RK Fibergrid](http://www.rkfibergrid.com/safecity.html) |
| **Clearview AI** | Facial recognition vendor | Vadodara FRS pilot (controversial) | [Inc42](https://inc42.com/buzz/police-in-gujarat-to-use-controversial-clearview-ai-facial-recognition-system/) |
| **Mumbai-based AI startup (unnamed)** | AI/RAG developer | NARIT AI (with Western Railway Police) | [Insights on India](https://www.insightsonindia.com/2026/04/22/narcotics-analysis-rag-based-investigation-tool-narit-ai/) |
| **Indian AI Research Organisation (IAIRO)** | Academic AI research MoU | With IIT Gandhinagar (general AI research, **not** police-specific) | [ANI](https://aninews.in/news/national/general-news/iit-gandhinagar-signs-mou-with-indian-ai-research-organisation-to-advance-ai-research-talent-development20260730162507/) |
| **Intel** | AI/digital-economy MoU | State-level, details thin | [IndiaAI](https://indiaai.gov.in/article/gujarat-and-intel-forge-partnership-to-propel-ai-and-digital-economy-growth) |
| **BISAG-N** | National geospatial/GIS institute, HQ Gandhinagar | General e-governance GIS (agriculture, land/water, disaster mgmt) — **no confirmed Gujarat-Police-specific project found** | [Wikipedia](https://en.wikipedia.org/wiki/Bhaskaracharya_Institute_For_Space_Applications_and_Geo-Informatics) |
| **DAIICT** | — | **No direct Gujarat Police partnership found** ⚠️ GAP | — |
| **C-DAC** | — | Only generic national-ERSS blog content found; **no Gujarat-Police-specific link confirmed** ⚠️ GAP | [C-DAC ERSS blog](https://www.cdac.in/index.aspx?id=blog_ni_erss) |
| **NFSU Gandhinagar** | Forensic science research/training | Not confirmed as the developer behind Gujarat Police's live AI tools (e.g., NARIT AI credited elsewhere) | [NFSU](https://www.nfsu.ac.in/) |

---

## 15. Comparative snapshot: Gujarat's system-by-system maturity

| System | Maturity | Coverage | AI content | Public-facing? |
|---|---|---|---|---|
| Project VISHWAS (CCTV/ITMS) | Mature, scaling (Phase 2 ongoing) | Statewide, 54+ cities | Video analytics (ANPR, red-light, crowd density) | No (police-internal) |
| Body-worn cameras | Mature | 10,000+ units, 622 stations | None (recording only) | No |
| GP-DRASTI (response drones) | Early rollout (2025) | 33 police stations, 4 cities | Minimal (live video only) | No |
| e-GujCop / e-FIR / Citizen First | Mature, long-running (since 2013) | Statewide | None (form-based) | **Yes** |
| Facial Recognition | Pilot only | Vadodara city only (~700 cams) | Yes (Clearview AI) | No |
| NARIT AI | Brand-new (Apr 2026) | Narcotics cases only, statewide use by IOs | Yes (RAG/LLM) | No (HC-restricted) |
| AI Crowd Management | Event-pilot | Ahmedabad events only (Rath Yatra, Kankaria) | Yes (density/thermal analytics) | No |
| Predictive policing | **Discussion stage only** | None confirmed | N/A | N/A |
| Dial 112 / 108 / 181 | Mature, statewide | Statewide (112 pilot→statewide 2025) | GPS/dispatch automation, not AI-scored | **Yes** |
| Cyber (1930, Cyber Sentinels) | Growing | 1 dedicated lab (Rajkot) + state cell | None confirmed | **Yes** (helpline) |

---

## 16. Gaps / What I couldn't find

- **Exact, current, single-source-of-truth camera count for VISHWAS** — sources range from 7,000 (Phase 1 only) to 12,500 to "nearly 100 cities," with no single authoritative dashboard found.
- **Any public budget figures** for VISHWAS overall, GP-DRASTI, or NARIT AI.
- **Vendor for the Rath Yatra / Kankaria Carnival AI crowd-analytics system** (search budget was exhausted before this could be resolved).
- **AASHVAST cyber-security project** — only a headline reference found; the source article 404'd and no alternate source with details was located.
- **Any confirmed statewide (vs. Vadodara-only) facial recognition deployment**, and any published accuracy/error-rate audit for the FRS in use.
- **Dashcams in patrol/PCR vehicles** — no evidence found (only body-worn and static/drone cameras documented).
- **Whether the Home Department/Police is an explicit named pilot vertical** in the Gujarat AI Action Plan 2025–2030 (named sectors found were healthcare, education, agriculture, finance).
- **Gujarat-specific case/lives-saved statistics for 108 EMRI** (only found as a national 16-state aggregate).
- **Direct NFSU involvement in any live Gujarat Police AI tool** (NARIT AI's credited developer is Western Railway Police + an unnamed Mumbai startup, not NFSU).
- **Confirmed DAIICT or C-DAC collaboration specifically with Gujarat Police** (searched explicitly; nothing found).
- **A reconciled figure for VISHWAS's claimed road-accident reduction** (19.09% vs 29% — both cited by different outlets, no source reconciles them).
- **Current 2026 status of the 112/ERSS statewide rollout** (last confirmed data point was March 2025, mid-rollout).

---

## 17. Whitespace — what Gujarat Police does NOT appear to have yet (hackathon ideation)

This is the actionable section: each gap below is a plausible hackathon build target, because it sits **on top of infrastructure that already exists** rather than requiring new hardware.

1. **No conversational/voice AI layer on citizen services.** e-FIR and Citizen First are pure form-based UIs. There is no evidence of a **Gujarati-language speech-to-text or chatbot** that lets a citizen *speak* a complaint (in Gujarati or code-mixed Gujarati/Hindi/English) and get a structured FIR draft, status update, or guidance. This is a clean, low-risk build: it augments an existing intake pipeline rather than replacing any surveillance system.

2. **No unified "investigator's copilot" across siloed systems.** VISHWAS (video), e-GujCop/CCTNS (case records), the Vadodara FRS pilot, and ASTR (DoT-owned) are **four separate systems** with no evidence of a single search/query interface a field officer could use ("show me all footage + records + prior cases connected to this plate/face/phone number"). NARIT AI proves Gujarat Police is comfortable with RAG-based case-assist tools *if scoped to internal, non-public use* — the same pattern could extend beyond narcotics.

3. **NARIT AI's pattern is narcotics-only.** No equivalent AI case-analysis/chargesheet-drafting assistant was found for **cyber fraud, POCSO, economic offences, or general IPC/BNS crimes** — a generalized version of the NARIT AI architecture (RAG over verified law + precedent, HC-compliant internal-only deployment) is a strong, de-risked hackathon direction because Gujarat Police and the Gujarat High Court have already signaled comfort with this exact model.

4. **No fraud-network/mule-account analytics on top of the 1930 helpline.** Despite a dedicated cyber cell, a new Rajkot lab, and clear political attention to cyber fraud, no graph-analytics or link-analysis tool surfaced for identifying **mule-account rings or repeat-offender fraud networks** from helpline/complaint data — a high-value, non-controversial (fraud detection, not surveillance) AI target.

5. **No forensic video search across the archived VISHWAS/BWC footage estate.** ANPR does real-time plate matching, but nothing found suggests officers can **query archived footage** ("find this person/vehicle across all stored footage from the last 30 days") — an AI video-retrieval tool over the existing Evidence Management System (622 police stations already have docking/storage infrastructure) is a natural extension, not a new surveillance build.

6. **No integration between emergency dispatch (112/108/181) and the VISHWAS camera network.** When a 112 call comes in, there's no evidence the system automatically pulls the nearest CCTV feed to verify severity/location before dispatch — a genuinely useful, safety-positive integration layer.

7. **Facial recognition is fragmented, small-scale, and vendor-risky.** Only Vadodara has FRS, via Clearview AI (a controversial vendor with no local accountability). A hackathon team proposing FRS work should instead focus on **governance/audit tooling** (bias/accuracy testing, watchlist-management oversight) rather than a new raw FRS build — this is both differentiated and addresses a real, documented weakness.

8. **No confirmed operational predictive policing**, despite it being discussed at the state's own police science congress. Gujarat lags Bengaluru and even Akola (Maharashtra) here. A crime-hotspot/resource-allocation dashboard built on existing CCTNS data would fill a real, publicly-acknowledged gap — but should be framed carefully given the documented bias/privacy criticism of predictive policing nationally.

9. **Crowd-safety AI is event-specific and Ahmedabad-centric.** The Rath Yatra/Kankaria density-analytics system has not been shown to generalize to **Rann Utsav (Kutch), Somnath, Dwarka, Ambaji Navratri, or Pavagadh** — large seasonal/pilgrimage crowds elsewhere in the state appear to rely on manpower rather than the same AI tooling. A "crowd-safety-as-a-service" layer reusable across events/venues (not hard-coded to one route) is a strong, evidently wanted capability.

10. **No Gujarat-Police-owned counter-drone/anti-UAS capability for cities or events**, only BSF border-level jamming. With drone use rising (both hostile and hobbyist) around VIP events, Commonwealth Games prep, and religious gatherings, a lightweight **drone-detection alerting layer** (even software-only, e.g., RF/acoustic-signature classification feeding into the existing i3C dashboard) addresses a documented capability gap.

11. **No public transparency/impact dashboard.** The conflicting official statistics found in this research (19.09% vs 29% accident reduction; 604 vs 6,000 Surat cameras) suggest **no single, consistently-updated public dashboard** reconciles VISHWAS/ITMS outcome metrics. A trustworthy public-facing analytics dashboard (built on already-public e-challan/accident data) would be a credible, low-controversy civic-tech contribution.

12. **No gunshot-detection system** was found anywhere in Gujarat Police's stack — a common feature in some Western smart-policing deployments; may be low-priority given Indian firearms-crime patterns, but worth flagging as an explicit absence.

---

## 18. Sources

- [Project Vishwas 2.0: Gujarat Builds Statewide AI-Ready Surveillance Before Hosting 2030 Commonwealth Games — Indian Masterminds](https://indianmasterminds.com/states/gujarat/gujarat-project-vishwas-next-gen-policing-2030-games-163580/)
- [How Gujarat Police Built a 'Third Eye' for Smart and Transparent Policing — Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/how-gujarat-police-built-third-eye-smart-transparent-policing-177614/)
- [10,500 CCTV cameras being installed across Gujarat under VISWAS project — DeshGujarat](https://deshgujarat.com/2023/12/15/10500-cctv-cameras-being-installed-across-gujarat-under-viswas-project/)
- [7000 CCTV cameras installed in Gujarat under Phase-I of VISWAS — DeshGujarat](https://deshgujarat.com/2022/07/02/7000-cctv-cameras-installed-in-gujarat-under-phase-i-of-viswas-10000-to-be-installed-in-phase-ii/)
- [Gujarat Equipped With 7 Thousand CCTV in Project Vishwas — Vibes of India](https://www.vibesofindia.com/equipped-with-7-thousand-cctv-project-vishwas-of-surveillance-in-gujarat/)
- [Citizen's Success Story of VISWAS — MyGov Blog](https://blog.mygov.in/citizens-success-story-of-video-integration-and-state-wide-advance-security-viswas/)
- [Union Home Minister launches AASHVAST and VISWAS — CMO Gujarat](https://cmogujarat.gov.in/en/latest-news/union-home-minister-launches-aashvast-and-viswas-project-of-gujarat-police-for-cyber-security/)
- [Part 1: AI for Urban Vigilance — NITI Aayog Frontier Tech](https://frontiertech.niti.gov.in/story/ai-for-urban-vigilance-enforcement-and-safety-in-the-age-of-smart-governance)
- [Project Trinetra: India's AI Predictive Policing Model (Akola) — Insights on India](https://www.insightsonindia.com/2025/10/17/project-trinetra-ai-predictive-policing/)
- [Inside Akola's AI Policing Lab: TRINETRA — Indian Masterminds](https://indianmasterminds.com/feature-stories-on-bureaucrats-changemakers/sp-archit-chandak-trinetra-ai-policing-167203/)
- [TRINETRA — C-DOT product page](https://www.cdot.in/cdotweb/web/product_page.php?lang=en&catId=11&pId=77)
- [Gujarat Police unveils GP Drashti — DeshGujarat](https://deshgujarat.com/2025/04/04/gujarat-police-to-launch-gp-drashti-a-drone-based-rapid-response-surveillance-project/)
- [About Gujarat Police's GP-DRASTI Drone — IASGyan](https://www.iasgyan.in/daily-current-affairs/gp-drashti-drone)
- [Gujarat Police Launches GP-DRASTI — Civilstap Himachal](https://civilstaphimachal.com/current-affair/gujarat-police-launches-gp-drasti/)
- [How Gujarat Police Are Using Drones to Combat Crime — Inside FPV](https://insidefpv.com/blogs/blogs/how-gujarat-police-are-using-drones-to-combat-crime)
- [Using drones to reduce response time, Gujarat Police launches GP-DRASTI — ANI](https://aninews.in/news/national/general-news/using-drones-to-reduce-response-time-gujarat-police-launches-special-project-gp-drasti20250404171558/)
- [Gujarat Police uses Netra UAV to keep watch over Rath Yatra — DeshGujarat](https://deshgujarat.com/2013/07/10/gujarat-police-uses-netra-uav-to-keep-watch-over-rath-yatra/)
- [What is e-FIR system launched by Gujarat Police? — GKToday](https://www.gktoday.in/what-is-e-fir-system-launched-by-gujarat-police/)
- [Gujarat Police — Apple App Store](https://apps.apple.com/in/app/gujarat-police/id1546587116)
- [Gujarat Police — Google Play](https://play.google.com/store/apps/details?id=com.tcs.digigov.mobility.dhs.citizen.gj&hl=en_US)
- [eGujCop: Gujarat Police Steers Ahead in Technology Use — The Protector](https://www.theprotector.in/egujcop-gujarat-police-steers-ahead-in-technology-use/)
- [CCTNS Evaluation Report — MHA/IIPA](https://www.mha.gov.in/sites/default/files/IIPA-Report-CCTNS.pdf)
- [Himachal Pradesh tops CCTNS PRAGATI ranking — Deccan Herald](https://www.deccanherald.com/india/himachal-pradesh-tops-crime-and-criminal-tracking-network-and-systems-pragati-ranking-for-january-1195779.html)
- [ICJS Factsheet — PIB](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2022/jun/doc202262367401.pdf)
- [Inter-Operable Criminal Justice System — MHA](https://www.mha.gov.in/en/commoncontent/inter-operable-criminal-justice-system-icjs)
- [Gujarat police tests AI-based facial recognition — ANI/BusinessWorld](https://www.businessworld.in/article/Gujarat-police-tests-AI-based-facial-recognition-system-to-check-crime-/15-08-2020-309043/)
- [Police In Gujarat To Use Controversial Clearview AI — Inc42](https://inc42.com/buzz/police-in-gujarat-to-use-controversial-clearview-ai-facial-recognition-system/)
- [After Haryana police, Gujarat officials use ASTR to catch fake SIM-card holders — Medianama](https://www.medianama.com/2023/04/223-gujarat-officials-astr-catch-fake-sim-card-holders/)
- [More than 29,000 SIM cards activated using fake documents in Gujarat — ThePrint](https://theprint.in/india/more-than-29000-sim-cards-activated-using-fake-documents-in-gujarat-18-held/1523945/)
- [Facial Recognition in India: Privacy, Surveillance — Outlook India](https://www.outlookindia.com/national/facial-recognition-in-india-privacy-surveillance-and-missing-legal-framework)
- [Privacy fears as India police use facial recognition at rally — Al Jazeera](https://www.aljazeera.com/amp/news/2019/12/30/privacy-fears-as-india-police-use-facial-recognition-at-rally)
- [India thwarted 600-plus drones sent by Pakistan on Gujarat Frontier: BSF — DeshGujarat](https://deshgujarat.com/2025/05/30/india-thwarted-600-plus-drones-sent-by-pakistan-on-gujarat-frontier-bsf/)
- [Countering Hostile Drone Activity on the India-Pakistan Border — ORF](https://www.orfonline.org/research/countering-hostile-drone-activity-on-the-india-pakistan-border)
- [Gujarat State Police Joins the Axon Network — Axon Investor Relations](https://investor.axon.com/2021-08-24-Gujarat-State-Police-Joins-the-Axon-Network-with-Largest-Body-Worn-Camera-Rollout-in-India)
- [Gujarat Police gets 10,000 body worn cameras — DeshGujarat](https://deshgujarat.com/2021/03/14/gujarat-police-gets-10000-body-worn-cameras-including-1000-that-can-do-live-broadcast/)
- [ITMS Challan — Parivahan/National Government Services Portal](https://services.india.gov.in/service/detail/apply-for-itms-e-challan-intelligent-traffic-management-system)
- [Integrated Command and Control Centre (ICCC), Ahmedabad — NIUA](https://iccc.niua.org/iccc/sector/use-case/815e6212def15fe76ed27cec7a393d59)
- [112 Emergency Helpline set to roll out across Gujarat — DeshGujarat](https://deshgujarat.com/2025/03/27/112-emergency-helpline-set-to-roll-out-across-gujarat-1-4-crore-calls-handled-so-far/)
- [Emergency Response Support System — MHA](https://www.mha.gov.in/en/commoncontent/emergency-response-support-system-erss)
- [GVK EMRI](https://www.emri.in/)
- [Calling 108: How One Institution Pioneered Emergency Medical Services in India — The Better India](https://thebetterindia.com/187773/gvk-emri-108-ambulance-emergency-healthcare-service-india/)
- [Gujarat's 181 Abhayam marks 12 yrs; 18 lakh women helped — Assam Tribune](https://assamtribune.com/national/gujarats-181-abhayam-marks-12-yrs-18-lakh-women-helped-1609153)
- [Gujarat government launches 181 Abhayam helpline mobile app — DeshGujarat](https://deshgujarat.com/2018/08/06/gujarat-government-launches-181-abhayam-helpline-mobile-app/)
- [National Forensic Sciences University — Centre of Excellence](https://www.nfsu.ac.in/centre_of_excellence)
- [Inauguration of Digital Forensic Laboratory at NFSU Gandhinagar — PIB](https://www.pib.gov.in/PressReleasePage.aspx?PRID=1994273)
- [NFSU-Gandhinagar DGGI Digital Forensic Lab — NFSU](https://nfsu.ac.in/details/201)
- [NARIT AI Gujarat 2026: Police launch tool to boost NDPS convictions — Deccan Herald](https://www.deccanherald.com/india/gujarat/gujarat-police-launch-ai-based-tool-to-aid-narcotics-investigation-3963622)
- [Gujarat Police Launches 'NARIT AI' — Drishti IAS](https://www.drishtiias.com/state-pcs-current-affairs/gujarat-police-launches-narit-ai-to-strengthen-ndps-investigations)
- [NARIT-AI: Gujarat Police's AI Tool for Narcotics Investigation — Insights on India](https://www.insightsonindia.com/2026/04/22/narcotics-analysis-rag-based-investigation-tool-narit-ai/)
- [NARIT AI Transforming Drug Case Investigation in Gujarat — Usthadian Academy](https://www.usthadian.com/narit-ai-transforming-drug-case-investigation-in-gujarat/)
- [Ahmedabad Rath Yatra 2025: Over 23,000 cops, 227 live cameras, 41 drones, 2,872 body cameras — DeshGujarat](https://deshgujarat.com/2025/06/24/ahmedabad-rath-yatra-2025-over-23000-cops-227-live-cameras-41-drones-2872-body-cameras-to-monitor-security/)
- [Ahmedabad Uses AI Crowd Management System for Jagannath Rath Yatra 2025 — Insights on India](https://www.insightsonindia.com/2025/06/11/ahmedabad-polices-ai-crowd-management-system/)
- [Jagannath Rath Yatra 2025: Ahmedabad Police To Use AI — ETV Bharat](https://www.etvbharat.com/en/!bharat/jagannath-rath-yatra-2025-ahmedabad-police-to-use-ai-for-public-safety-effective-crowd-control-enn25062106240)
- [AI surveillance deployed for crowd management at Kankaria Carnival — Gujarat Samachar English](https://english.gujaratsamachar.com/news/gujarat/ai-surveillance-deployed-for-crowd-management-at-kankaria-carnival-in-ahmedabad)
- [Gujarat Government Approves AI Action Plan for 2025-2030 — Patrika English](https://www.patrika.com/en/national-news/gujarat-government-approves-ai-action-plan-for-2025-2030-19814874)
- [Gujarat CM Unveils 5-Year AI Action Plan — Outlook India](https://www.outlookindia.com/announcements/gujarat-cm-bhupendra-patel-unveils-5-year-ai-action-plan-2025-2030-to-lead-ai-driven-governance-digital-innovation)
- [AI Mission 2025 to 2030 Announced by Gujarat CM — Elets eGov](https://egov.eletsonline.com/2025/07/ai-mission-2025-to-2030-announced-by-gujarat-chief-minister/)
- [Gujarat approves 5-year action plan to integrate AI in governance — Storyboard18](https://www.storyboard18.com/digital/gujarat-approves-5-year-action-plan-to-integrate-ai-in-governance-77303.htm)
- [Gujarat and Intel forge partnership — IndiaAI](https://indiaai.gov.in/article/gujarat-and-intel-forge-partnership-to-propel-ai-and-digital-economy-growth)
- [Suraksha Setu Society: Strengthening Gujarat's safety — ANI](https://www.aninews.in/news/national/general-news/suraksha-setu-society-strengthening-gujarats-safety-through-a-strong-police-public-connection20250214041045/)
- [Gujarat government allocates Rs 20-30 crore to Suraksha Setu Society — Big News Network](https://www.bignewsnetwork.com/news/278049501/gujarat-government-allocates-rs-20-30-crore-to-suraksha-setu-society-for-public-safety-initiatives)
- [IIT Gandhinagar signs MoU with Indian AI Research Organisation — ANI](https://aninews.in/news/national/general-news/iit-gandhinagar-signs-mou-with-indian-ai-research-organisation-to-advance-ai-research-talent-development20260730162507/)
- [Bhaskaracharya Institute For Space Applications and Geo-Informatics — Wikipedia](https://en.wikipedia.org/wiki/Bhaskaracharya_Institute_For_Space_Applications_and_Geo-Informatics)
- [Dial toll free helpline number 1930 for cyber crime — DeshGujarat](https://deshgujarat.com/2022/05/20/dial-toll-free-helpline-number-1930-for-redressal-of-cyber-crime/)
- [Gujarat DGP Reviews Cyber Crime Ops, Helpline 1930 — Newkerala](https://www.newkerala.com/news/a/gujarat-dgp-reviews-cyber-crime-ops-focuses-faster-915.htm)
- [State Cyber Crime Cell, CID Crime, Gandhinagar — SKOCH Exhibition](https://exhibition.skoch.in/beacon-of-hope/state-cyber-crime-cell-cid-crime-gandhinagar-gujarat/)
- [Cyber Sentinels Lab established in Rajkot — Aaj Tak](https://www.aajtak.in/india/gujarat/story/cyber-crime-will-be-curbed-in-gujarat-first-cyber-sentinels-lab-established-in-rajkot-lcly-strc-2159235-2025-02-05)
- [Gujarat Cyber Crime portal](https://gujaratcybercrime.org/eng/)
- [Videonetics security cameras, ANPR and UVCP secure Vadodara — SourceSecurity](https://www.sourcesecurity.com/news/videonetics-security-cameras-anpr-uvcp-secure-vadodara-city-co-4403-ga.1580300179.html)
- [Vadodara Smart City case study — Videonetics](https://www.videonetics.com/case-study/gujarat-case-study)
- [Vadodara Smart Poles — The Better India](https://thebetterindia.com/innovation/vadodara-smart-poles-urban-safety-free-wifi-10920851)
- [Gujarat's Rajkot emerges as model Smart City — ANI](https://aninews.in/news/national/general-news/gujarats-rajkot-emerges-as-model-smart-city-with-innovative-initiatives20251001133824/)
- [Rajkot Emerges As Model Smart And Sustainable City — Construction World](https://www.constructionworld.in/urban-infrastructure/smart-cities-projects/rajkot-emerges-as-model-smart-and-sustainable-city/79696)
- [India's First Safe City Project - Safe City Surat — RK Fibergrid](http://www.rkfibergrid.com/safecity.html)
- [Inside Surat's Safe City CCTV Project — YouTube](https://www.youtube.com/watch?v=Iqjl33SjaqE)

---

*Research method note: 40 WebSearch queries executed across all 15 assigned sub-topics, plus targeted WebFetch retrieval of the highest-signal articles (Indian Masterminds' two deep-dive pieces on VISHWAS/TRINETRA, IASGyan on GP-DRASTI, GKToday on e-FIR, Vibes of India and DeshGujarat on camera-count phases). Several WebFetch attempts (DeshGujarat article pages, CMO Gujarat AASHVAST page, cybernodal.gujarat.gov.in) returned 404/DNS errors due to dynamic/JS-rendered content or site changes — those data points are marked unverified above rather than fabricated. WebSearch quota was exhausted near the end of research (200/200 session calls), so a small number of planned follow-up queries (Kankaria Carnival AI vendor, further AASHVAST detail) could not be run.*
