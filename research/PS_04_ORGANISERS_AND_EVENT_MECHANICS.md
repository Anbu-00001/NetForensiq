# KANAD S.H.I.E.L.D. 2026 — Organisers, Event Mechanics, and the Judges' World

> **Scope:** Who is running this event, who is judging it, what they've published about
> logistics/rules/money/IP, and what their own recent public record says they care about.
> Compiled 2026-08-09. All site pages fetched live via curl (browser UA) on 2026-08-09.
> Companion document: `PS_00_OFFICIAL_PROBLEM_STATEMENTS.md` (the 26 problem statements
> themselves — read that first for subject-matter content; this file is mechanics/people).

---

## Event fact sheet

| Field | Value | Source |
|---|---|---|
| Full name | **KANAD S.H.I.E.L.D.** — Security Hackathon for Intelligence, Encryption, Law Enforcement and Defence | kanadshield.com/index.html |
| Site branding | "Ahmedabad City Police Innovation Challenge 2026" | `<title>` tag, all pages |
| Organiser | Cyber Crime Branch, Ahmedabad City Police, Government of Gujarat | index.html, terms-and-condition.html |
| Ecosystem/collaboration partner | **i-Hub Gujarat** (Gujarat Student Startup and Innovation Hub) | about.html: "an initiative by the Cyber Crime Branch of Ahmedabad City Police in Collaboration with i-Hub Gujarat" |
| "Academic Partner" (as labelled on site) | Logo shown is filed as `naac.png` in site assets, directly under the "Academic Partner" label in the footer | Raw HTML inspection of index.html footer, see §Verbatim below — ⚠️ **identity unclear**, see Gaps |
| Likely academic partner (external evidence) | **Karnavati University** — tagged `@karnavati_uni` on the official KANAD S.H.I.E.L.D. promotional post on X | x.com/cybercrimeahd/status/2058429341655278042 (via search index) |
| "Technology Partner" slot | A commented-out (**not live**) footer block reads `alt="Google for Developers"` — this partnership was removed from the page before publication, not currently active | Raw HTML of index.html footer |
| Site built by | Compubrain (compubrain.com) | Noted in PS_00 (prior research) |
| Office address | Cyber Crime Branch, Bungalow No. 15, Nr. IPS Mess, Dafanala Cross Road, Shahibaug, Ahmedabad 380004, Gujarat | contact.html |
| Phone | +91 96242 51798 | contact.html |
| Email | support@kanadshield.com (Cloudflare-obfuscated on-page; confirmed via PS_00 header) | contact.html, PS_00 |
| Parent department | Gujarat Home Department — gujhome.gujarat.gov.in | index.html footer ("Email gujhome.gujarat.gov.in" — likely a placeholder bug, see Gaps) |
| Socials (tagged on official posts) | X **@cybercrimeahd**, Instagram **@ahmedabadcybercrime**, Facebook "Ahmedabad Cyber Crime"; also tags **@GujaratPolice, @DrLavina_IPS, @AhmedabadPolice, @ihubgujarat, @karnavati_uni, @sanghaviharsh** | X post via search index |
| **Category 1** | Startups · Industry Partners · Companies with Tech Solutions · Innovators & Researchers — **16 problem statements**, posted 23 Apr 2026 | category-1.html, PS_00 |
| **Category 2** | Graduates · Post Graduates · Doctoral students · Other technical-course students — **10 problem statements**, posted 27 Apr 2026 | category-2.html, PS_00 |
| Team size | Minimum 2, maximum 6 members; larger teams need prior written approval from the organising committee | terms-and-condition.html |
| One-team rule | An individual may be part of only one team at a time | terms-and-condition.html |
| Problem-statement submission cap | A single team may submit **at most 5** problem statements | terms-and-condition.html |
| Submission format | Abstract (PPT/PDF/JPEG) covering problem-solving approach, technical stack, and prior cybersecurity work | index.html "Registration" section |
| Final submission deadline | ⚠️ **CONFLICTING dates published** — see below | See discrepancy note |
| Registration status (as scraped) | **Closed** | index.html, timeline.html, category-1.html (all "Registrations Closed" / "Login to Apply" now dead) |
| Event date | **"Will be announced shortly"** — event is **currently postponed** | timeline.html, verbatim below |
| Reason for postponement | Heavy rain / natural-emergency conditions in Ahmedabad | timeline.html, verbatim below |
| Event venue | i-Hub Gujarat, Prajna Puram, KCG Campus, opp. PRL, Navrangpura, Ahmedabad 380015, Gujarat | timeline.html |
| **Prizes — Category 1** | 1st ₹5,00,000 · 2nd ₹3,00,000 · 3rd ₹2,00,000 | index.html "Awards and Recognition" table |
| **Prizes — Category 2** | 1st ₹1,50,000 · 2nd ₹1,00,000 · 3rd ₹50,000 | index.html "Awards and Recognition" table |
| Non-cash benefits | Chance to deploy solution with government/LEA; certification; strategic networking; future LEA engagement; possible Cyber Expert/Intern role with the police department | index.html |
| Selection process | Jury panel evaluates submitted abstracts/problem statements → shortlisting → live pitch "to Experts & government officials" at the event → results/rewards | index.html, how-it-works.html |
| Shortlisting criteria (as stated) | **Novelty of idea, technical depth of methodology, clarity of presentation** | index.html "Shortlisting" section (verbatim below) |
| Per-problem evaluation criteria | Vary by problem statement — see PS_00; e.g. accuracy/speed, innovation in methodology, scalability, UI/UX, AI/ML integration, real-world usability | PS_00 (already compiled) |
| IP / ownership terms | **No clause found anywhere on the site granting the organiser rights over submitted work.** Terms & Disclaimer pages address only participant-vs-participant conduct (originality, no plagiarism, respect others' IP, open-source license compliance) and explicitly disclaim organiser liability for IP disputes *between participants*. Silent on what happens to your code/idea after submission. See "IP terms" analysis below. | terms-and-condition.html, disclaimer.html |
| Code of conduct | Ethical hacking required; disrupting event infrastructure or unauthorised access to third-party systems → permanent ban + potential legal action | terms-and-condition.html |
| Disqualification triggers | No presentation/abstract at evaluation phase; plagiarism; ethical misconduct | terms-and-condition.html, disclaimer.html |

### Deadline discrepancy — flagged, not resolved

Three different final-submission dates appear across sources, and I could not find anything reconciling them:

| Date | Where stated |
|---|---|
| **20 June 2026, 11:59 PM** | terms-and-condition.html: "The final date for registration and application submission is June 20, 2026. Any applications submissions received after 11:59 PM on the deadline date will not be considered." |
| **28 June 2026** | timeline.html: "Final Date of Submission — 28 June 2026" |
| **25 May 2026** | ⚠️ UNVERIFIED, third-party listing on fundsforcompanies.fundsforngos.org, which frames the whole program as "Startup-Police Cybersecurity Innovation Program: CyberShield Ahmedabad" |

Most likely explanation: the deadline was extended over time (25 May → 20 Jun → 28 Jun) and the Terms & Conditions page simply wasn't updated when Timeline was. Treat **28 June 2026** (the most specific, most recently-styled page) as most likely correct, but do not state a submission date to anyone without flagging this.

---

## Verbatim site text

### Home (index.html)

> "Kanad S.H.I.E.L.D. — Security Hackathon for Intelligence, Encryption, Law Enforcement and Defence"
> "Cybersecurity Hackathon 2026 — Initiative by Cyber Crime Branch"
> "A flagship Cybersecurity event inviting Startups and Innovators to build cutting-edge technology solutions for Real World Cybersecurity challenges."

**Leadership panel shown on homepage (with photo/video blocks):**
> "Shri Sharad Sighal (IPS) — JCP of Crime Branch, Ahmedabad City Police"
> "Shri Dr. Lavina Sinha (IPS) — DCP of Cyber Crime Branch, Ahmedabad City Police"

(Note: the site itself spells the surname "Sighal" — a typo; every independent news source spells it **Singhal**. See organiser profile below.)

**Objective:**
> "Identification and articulation of real-world cybercrime problems. Direct engagement between cybersecurity industry and law enforcement agencies. Co-creation & validation of technology-driven solutions."

**Benefits:**
> "Winners will get a chance to deploy their solution with government and LEA. Certification, strategic networking & future engagement opportunities with LEAs."

**Awards and Recognition table (verbatim):**
```
Rank    Category 1    Category 2
1st     5 lakhs       1.5 Lakh
2nd     3 lakhs       1 Lakh
3rd     2 lakh        50k
```

**Registration section:**
> "Registrations for the Kanad S.H.I.E.L.D. Cybersecurity Hackathon 2026 is officially closed!
> Participation: Team (2 to 6 members).
> Submission: Upload a concise abstract (PPT/PDF/JPEG) highlighting your problem-solving approach, technical stack and your previous work in the cybersecurity field."

**Shortlisting:**
> "After completing registration and submission for the CyberSecurity Hackathon, all the problem statements and abstracts you submit will be rigorously evaluated by our expert jury panel. Participants and teams will be selected based on the novelty of their idea, technical depth of their methodology and clarity of their presentation."

**Who Can Apply:**
> Category 1: Startups / Industry Partners / Companies with Tech Solutions / Innovators & Researchers.
> Category 2: Graduates / Post Graduates / Students in doctoral programs / Students in other technical courses.

**"Cybersecurity Hackathon – Opportunities" (audience-segmentation copy — reveals who the site imagines its stakeholders are):**
> Government & Public Sector: "Best Participants will get an Opportunity to work as Cyber Expert/Intern with Police Department." "Secure essential services and protect large-scale infrastructure from cyber threats."
> Enterprise & Corporate Security, Financial Sector (Banking & FinTech): "Secure financial systems, prevent fraud, and ensure robust compliance."
> Academia & Research: "Universities & Researchers Drive innovation by bridging academic research with real-world industry challenges." "Forensics & Threat Analysts Improve investigation methods and collaborate on advanced threat intelligence research."
> Talent & Community Development: "Future Cyber Leaders Gain hands-on experience, solve challenges, and unlock career and mentorship opportunities." "Ethical Hackers & Bug Hunters Showcase offensive skills, identify vulnerabilities, and earn global recognition."
> Innovation & Industry Ecosystem: "Startups & Developers Scale cyber solutions, collaborate with experts, and explore growth or funding opportunities."

### About (about.html)

> "Kanad S.H.I.E.L.D. Cybersecurity Hackathon 2026 is a initiative by the Cyber Crime Branch of Ahmedabad City Police in Collaboration with i-Hub Gujarat. The primary objective of this program is to strengthen Cyber Space World through the power of advanced technology. We are bringing together the nation's brightest startups, Industries, and tech experts & academics on a single platform to develop cutting-edge solutions to combat modern-day cyber threats.
>
> This hackathon is more than just a competition; it is a collaborative ecosystem designed to bridge the gap between investors, entrepreneurs, academics and the LEA. Together, we aim to build a secure digital future and a safer environment for all."

(Note: "bridge the gap between investors, entrepreneurs, academics and the LEA" — investors are explicitly named as a stakeholder class even on the About page; this matches the "Investment & Fundraising Track" described by the third-party fundsforngos listing, and is corroborated by the separate "Cyber Startups Investment Demo Day" — see Prior Editions/Sibling Events section.)

### Timeline (timeline.html) — full verbatim, this is the most operationally important page

> "Timeline
> Registration Closed
> Final Date of Submission — 28 June 2026
> Event Date — Will be announced shortly
>
> **Important Notice**
> Currently, there is heavy rain in Ahmedabad city and heavy rain is predicted in the coming days, due to this natural emergency, this Kanad S.H.I.E.L.D. - Cyber Security Hackathon-2026 event is currently postponed.
> This event is going to be held soon in the near future, so stay connected with us. 🤝
> Inconvenience Regretted.. 🙏
>
> **Event Venue:**
> i-Hub Gujarat
> Prajna Puram, KCG Campus,
> opp. PRL, Navrangpura,
> Ahmedabad 380015, Gujarat"

**This is a live, current-as-of-scrape notice.** As of 2026-08-09 the actual pitch/judging event has **not yet happened** and has no announced date. This has direct implications for pitch-prep timing — see closing section.

### How It Works (how-it-works.html)

> "Step-1: Explore Problem Statement — Browse problem statements across policing categories and find the right challenge
> Step-2: Click on Apply Now — Hit the apply now button (No login required)
> Step-3: Submission — Upload your solution, prototype details and supporting documents
> Step-4: Pitch at Hackathon Event — Present your solution live to Experts & government officials
> Step-5: Results & Rewards — Get recognized & win rewards."

### Terms & Condition (terms-and-condition.html) — full verbatim

> "**Team Composition and Eligibility**
> Team Size: Each participating team must consist of a minimum of 2 members and a maximum of 6 members.
> Exceptions: If a team requires more than 6 members due to the complexity, they must seek prior written approval by contacting the organizing committee at [email].
> Single Participation: An individual can be a part of only one team at a time.
>
> **Registration and Deadlines**
> Submission Deadline: The final date for registration and application submission is June 20, 2026.
> Late Entries: Any applications submissions received after 11:59 PM on the deadline date will not be considered for the event.
>
> **Problem Statement Guidelines**
> Submission Limit: A single team is permitted to submit a maximum of 5 problem statements for consideration.
> Relevance: All submitted statements must be strictly related to the field of Problem Statements.
>
> **Presentation & Abstract**
> Presentation: Teams are required to prepare a presentation to be delivered during the event. There should be in-depth, accurate information about the problem statement that the solution is intended to address and a presentation that can be demoed.
> Abstract: Every team must provide a concise abstract detailing their proposed solution, methodology, and the tools they intend to use.
> Documentation: Failure to produce a presentation or abstract during the evaluation phase may lead to immediate disqualification.
>
> **Code of Conduct and Ethical Standards**
> Ethical Hacking: Participants must adhere to ethical hacking principles. Any attempt to disrupt the event infrastructure or unauthorized access to third-party systems will result in a permanent ban and potential legal action.
> Originality: All work submitted must be original. Plagiarism of code or concepts from existing proprietary software is strictly prohibited."

**This is the complete Terms & Conditions page.** There is no section addressing IP ownership, licensing, confidentiality, data handling, or what rights (if any) the organiser acquires over a submitted idea/prototype.

### Disclaimer (disclaimer.html) — full verbatim

> "**No Plagiarism**
> All participating startups, developers, and students must ensure that the source code, designs, and solutions submitted are their original work. Copying or using unauthorized source code from other participants or third-party proprietary sources is strictly prohibited.
>
> **Respect for IP**
> Participants, investors, and company representatives must respect the Intellectual Property (IP) of others. Any unauthorized use, reproduction, or distribution of another participant's code or innovative ideas will lead to immediate disqualification.
>
> **Open Source Usage**
> If any open-source libraries or frameworks are used, they must be properly documented and used in compliance with their respective licenses.
>
> **Liability**
> The organizers (Cyber Crime Branch, Ahmedabad City Police) shall not be held responsible for any intellectual property disputes arising between participants, investors, or third parties.
>
> Note: Any participant found guilty of plagiarism or ethical misconduct will be disqualified from Kanad S.H.I.E.L.D. Hackathon 2026 with immediate effect."

**This is the complete Disclaimer page.** Same finding: entirely about protecting participants' IP *from each other*; contains no grant, license, assignment, or transfer clause running from participant to organiser.

### IP terms — direct answer to "what rights does the organiser take over submissions"

**As published, the organiser claims none, explicitly.** Reading both legal pages in full:
- No clause requires participants to assign, license, or transfer IP to the Cyber Crime Branch, i-Hub Gujarat, or the Government of Gujarat.
- No clause grants the organiser a right to use, deploy, or commercialise a submitted solution without further agreement.
- The only IP language present is protective of *participants against each other* (no plagiarism, respect others' IP, disclose open-source licenses) and a liability disclaimer shielding the organiser from IP disputes *between participants/third parties* — not a rights grab.
- The "Benefits" language on the homepage ("Winners will get a chance to deploy their solution with government and LEA") reads as an **opportunity/option**, not an obligation — there's no published mechanism (MoU template, licensing terms, revenue share) for how that deployment would actually be papered. This is very likely handled off-site, post-selection, via a separate negotiated agreement — which is standard for government pilot deployments but means **the actual terms are not public and a team should ask for them directly before or during the pitch**, not assume either "they own nothing" or "they own it all."

This is a meaningfully different (and more favourable) IP posture than many government hackathons, which often bury a broad royalty-free license or full assignment clause in the T&Cs. Worth stating plainly in a pitch/Q&A if asked: teams retain their IP under the published terms.

### Category 1 / Category 2 pages

Both are pure listing pages (title + "Login to Apply" per problem statement, all now dead since registration closed) — full titles already captured verbatim in PS_00. No additional eligibility fine print beyond what's on About/Terms.

### Contact (contact.html)

> "Cyber Crime Branch, Ahmedabad City Police, Bungalow No. – 15, Nr. IPS Mess, Dafanala cross road, Shahibaug, Ahmedabad 380004, Gujarat. Call us on: +91 96242 51798. Email to: [obfuscated]"

---

## Organiser profiles — the actual customer

### Ahmedabad City Police — Cyber Crime Branch leadership

| Role | Name | Notes | Source |
|---|---|---|---|
| **Joint CP, Crime Branch, Ahmedabad City** | **Sharad Singhal, IPS** | 2006-batch IPS, Gujarat cadre; Joint CP (Crime) Ahmedabad since 26 Apr 2024. Awarded President's Police Medal for Meritorious Service. In July 2026 he was injured (hand) when a history-sheeter attacked him during an in-person questioning — he later clarified the accused didn't recognise him as JCP because the team wasn't in Crime Branch uniform. | [DeshGujarat](https://deshgujarat.com/2024/04/25/appointments-of-12-ips-officers-in-gujarat-declared/), [NIT Kurukshetra alumni newsroom](https://www.nitkkraa.org/newsroom/news/Celebrating-Excellence-Mr-Sharad-Singhal-IPS-Awarded-Presidents-Police-Medal-for-Meritorious-Service.dz), [prokerala.com](https://www.prokerala.com/news/articles/a1783090.html) |
| **DCP, Cyber Crime Branch, Ahmedabad City** | **Dr. Lavina Sinha, IPS** | 2017-batch IPS, Gujarat cadre. Daughter of Varesh Sinha, former Gujarat Chief Secretary. Holds MBBS and MD. DCP (Cyber Crime) Ahmedabad since 26 Apr 2024 (moved from DCP Zone-1). Publicly associated with busting large "digital arrest" scam networks. | [Indian Masterminds](https://indianmasterminds.com/features/the-unfolding-of-a-digital-nightmare-ips-lavina-sinha-busts-indias-largest-digital-arrest-scam-97966), [Indian Masterminds appointment piece](https://indianmasterminds.com/news/ips-news/gujarat-12-ips-officers-reshuffled-lavina-sinha-made-dcp-cybercrime-ahmedabad/) |
| **ACP, Cyber Cell, Ahmedabad** | **Hardik Makadia** | Working-level face of the branch in press and outreach. Featured as expert on I4C's "#CyberSafeLive Episode 17" (7 May 2025). Named in coverage of the illegal-call-centre-targeting-Canadians bust (Mar 2026) and the ₹1.26 crore elderly-victim digital-arrest-style scam. Was a keynote speaker (alongside Singhal and Sinha) at i-Hub Gujarat's "Cyber Security Demo Day 2026" on 27 July 2026. | [CyberDost I4C on X](https://x.com/Cyberdost/status/1920067448851546585), [Darpan Magazine](https://www.darpanmagazine.com/news/india/gujarat-ahmedabad-cyber-cell-busts-illegal-call-centre-targeting-canadians-four-arrested/) |
| **Ahmedabad City Police Commissioner** | **Anupam Singh Gahlaut** (also spelled "Gehlot"/"Gehlaut" across outlets — ⚠️ spelling inconsistent) | 1997-batch IPS, Gujarat cadre. Took office as CP Ahmedabad on 4 July 2026, having previously been CP Surat. He sits above the Crime Branch/Cyber Crime Branch in the city police hierarchy but is not shown as a named event figurehead on the kanadshield.com site itself. | [DeshGujarat](https://deshgujarat.com/2026/07/04/anupam-singh-gahlaut-joins-office-as-police-commissioner-of-ahmedabad-city/), [Gujarat Samachar](https://english.gujaratsamachar.com/news/ahmedabad/anupam-singh-gehlot-appointed-ahmedabad-police-commissioner-81880162554) |

**Political sponsorship signal:** the official promotional post for KANAD S.H.I.E.L.D. on X (@cybercrimeahd) tags `@sanghaviharsh` — **Harsh Sanghavi, Gujarat's Minister of State for Home Affairs** — alongside `@GujaratPolice`, `@DrLavina_IPS`, `@AhmedabadPolice`, `@ihubgujarat`, and `@karnavati_uni`. This indicates the event carries visibility at state-ministerial level, not just departmental level, which is a strong signal that the eventual demo/judging event will have political attendees, not only working police officers.

### Cyber Crime Police Station / Branch — address note

The event's own contact address (Bungalow 15, Nr IPS Mess, Dafanala Cross Rd, Shahibaug 380004) matches the Cyber Crime **Branch** (investigative HQ). One third-party business listing separately places a "Ahmedabad Cyber Crime Cell" under DCP (Crime) at **Gaikwad Haveli, Jamalpur** — plausibly the older/public-facing FIR-registration Cyber Crime **Police Station**, distinct from the Branch HQ. ⚠️ UNVERIFIED which address is currently operative for which function; treat Shahibaug (the event's own stated address) as authoritative for anything hackathon-related.

### Notable recent Ahmedabad Cyber Crime operations (2025–2026) — for "war story" pitch framing

- **May 2025:** Six members of a Cambodia- and Nepal-based Chinese cyber-fraud gang arrested. ([cyberyodha.org](https://www.cyberyodha.org/2025/05/ahmedabad-cyber-crime-branch-arrests-6.html))
- **Feb 2026:** Arrest of Sujit Shankarrao Dev (aka Jadav), wanted since 2021 (Mumbai Dahisar police complaint) for a bitcoin/crypto-mining investment fraud worth ~₹100 crore affecting 100+ victims; caught residing in Naroda, Ahmedabad.
- **Mar 2026:** Illegal call centre busted, impersonating tax officials to defraud Canadian citizens; four arrested. ([Darpan Magazine](https://www.darpanmagazine.com/news/india/gujarat-ahmedabad-cyber-cell-busts-illegal-call-centre-targeting-canadians-four-arrested/))
- **May 2026:** ₹17 lakh stock-market investment fraud; scam ran via a WhatsApp group ("Stock Market Forum 38") built on fake credibility/tips; three arrested including a Surat businessman. ([Gujarat Samachar](https://english.gujaratsamachar.com/news/gujarat/ahmedabad-cyber-crime-branch-arrests-three-in-17-lakh-stock-market-investment-fraud-case-53381370220.html))
- Elderly Ahmedabad resident duped of **₹1.26 crore** via a "digital arrest"-style scam involving sustained video-call surveillance and coerced FD liquidation.
- A "nationwide CCTV hacking racket" cracked by Ahmedabad Cybercrime (Gujarat Samachar) — directly relevant to Category 1's VisionScan CCTV problem statement and Mobile Hygiene Guardian.

**Pattern across all of these:** WhatsApp-group-based investment/pump scams, crypto-linked fraud, digital-arrest/video-surveillance coercion scams, and cross-border call-centre operations are the branch's live, recurring caseload — not hypothetical threats.

### Citizen outreach

- **"Cyber Safe Mission"** — awareness campaign by Ahmedabad Police's Crime Branch, launched by the Gujarat CM. ([cmogujarat.gov.in](https://cmogujarat.gov.in/en/latest-news/cm-launches-ahmedabad-polices-cyber-safe-mission-aiming-at-checking-cyber-frauds/))
- **"Cyber Aashvast"** (site's own PS_00 header spells it "Cyber Ashwast"; press spells it "Cyber Aashvast") — a scheme where police personnel directly assist fraud victims; one report (Patrika, undated period) cites **₹70 lakh saved and ₹15 lakh recovered** for victims through the scheme, reachable also via emergency numbers 100/112, not just 1930. ⚠️ Numbers/period unverified beyond this single source.
- **"Cyber Saathi"** — an official chatbot for Ahmedabad Police's Cyber Crime Branch, reachable at +91 6357 446 357, positioned alongside the 1930 helpline and online-complaint portal. ([X/@kumarmanish9](https://x.com/kumarmanish9/status/1963617934896762916))
- **CyberDost / I4C's "#CyberSafeLive"** webinar series regularly features Ahmedabad officers (e.g., ACP Makadia, Episode 17, 7 May 2025) as expert guests — the branch is a recurring national-level awareness-content contributor, not just a local enforcement unit.

### Gujarat CID Crime Cyber Cell vs. Ahmedabad City Cyber Crime — the distinction

| | Gujarat CID Crime Cyber Cell | Ahmedabad City Cyber Crime Branch |
|---|---|---|
| Level | State-wide | City-specific (Ahmedabad jurisdiction) |
| Address | 7th Floor, C Wing, Block-2, Karmyogi Bhavan, Sector-10A, Gandhinagar 382010 | Bungalow 15, Shahibaug, Ahmedabad 380004 |
| Role | Statewide coordination, statistics, oversight of district-level cyber cells | Case-level investigation and prosecution within Ahmedabad |
| Publishes | The statewide 2025 fraud-loss numbers cited below come from CID data | Runs KANAD S.H.I.E.L.D. directly |

**Institutional-reform signal (important for pitch framing):** as of Aug 2025, the Gujarat government was reported to be standing up a **new, separate, dedicated statewide Cyber Crime Unit** (IG/DIG-led, ~5 SPs, 8 DySPs, 15 PIs, its own building modeled on Police Bhavan, and even a fee-for-service model for private companies), explicitly because of "online link scams, fake digital arrests, and deepfake audio-video calls." No implementation date was reported. This is a strong, recent (12-month-old) signal of exactly which fraud typologies the state considers its top structural burden — digital arrest and deepfake/voice-clone scams — and maps directly onto Category 1's TruthShield (deepfakes) and the general digital-arrest pattern DCP Sinha is known for prosecuting. ([DeshGujarat](https://deshgujarat.com/2025/08/12/gujarat-govt-to-set-up-separate-cyber-crime-unit-amid-rising-online-frauds/))

---

## i-Hub Gujarat

- **Full name:** Gujarat Student Startup and Innovation Hub. Incorporated as a Section 8 company (Companies Act 2013), established under the Student Startup and Innovation Policy (SSIP) by the Education Department, Government of Gujarat.
- **Campus:** A five-storey, ~1.5 lakh sq ft building at Prajna Puram, KCG Campus, opp. PRL, Navrangpura, Ahmedabad — inaugurated 2023, can host ~500 startups at a time. **This is the same address published as the KANAD S.H.I.E.L.D. event venue.**
- **Track record:** Sources vary — one cites 840+ startups incubated; another (more recent) cites 620+ startups directly assisted and Rs 160+ crore in funding facilitated. Treat as "800+ range, growing."
- **SSIP 2.0 funding — conflicting figures found, both cited:**
  - Rs 300 crore over 5 years (Rs 60 cr/year: Rs 30cr technical education, Rs 12cr i-Hub, Rs 10cr higher education, Rs 8cr schools).
  - A separate report cites a Rs 500 crore corpus for SSIP 2.0 overall.
  - Seed funding to individual student startups: up to ₹2 lakh per idea, up to ₹25 lakh for commercially viable ventures; "Startup Srujan Seed Support (S4)" grants of ₹2.5–10 lakh; over ₹23 crore disbursed to 402 startups under the Seed Support Scheme to date.
- **The "Startup–Police Cybersecurity Innovation Program" framing:** a third-party grant/opportunity aggregator (fundsforcompanies.fundsforngos.org) describes KANAD S.H.I.E.L.D. under the name **"CyberShield Ahmedabad"** as having **two tracks**:
  1. **Innovation Track** — startups paired with law enforcement on real problem statements (this is the hackathon itself).
  2. **Investment & Fundraising Track** — for capital-seeking startups, offering structured investor engagement, pilot-deployment pathways, and **government procurement access**.
  This listing states a deadline of **25 May 2026**, which is earlier than and conflicts with the site's own June dates (see deadline discrepancy note above) — ⚠️ UNVERIFIED, likely stale/superseded, but the two-track structure itself is corroborated independently (see next point).

### Sibling/parallel event found: "Cyber Security Demo Day 2026"

Search turned up a **related but apparently separate i-Hub Gujarat event** that has already happened, even though the main KANAD S.H.I.E.L.D. hackathon pitch/judging remains postponed as of this scrape:

- **27–28 July 2026**, run by i-Hub Gujarat.
- **Day 1 (27 July):** Keynote addresses by the same three officers — **IPS Dr. Lavina Sinha, IPS Sharad Singhal, and ACP Hardik Makadia.**
- **Day 2 (28 July):** Mentorship and pitching across 3 parallel tracks; mentors drawn from **ISRO, SAC (Space Applications Centre), RACD, Indian Army, NFSU, NSSI-IFSCS, SSIT, and GVFL Limited**, mentoring 40 startups.
- A closely related (possibly the same) event, **"Cyber Startups Investment Demo Day,"** featured 1:1 startup–investor pitching — 25 startups matched with 15 investors — with named investment partners including **Cdr Kartik Gopal (Jamwant Ventures)** and **Vikrant Varshney (Sucseed Ventures)** (a third partner's name was truncated in the source and could not be recovered).

**Inference, clearly labelled as such:** given the identical named officers, identical i-Hub Gujarat venue/organiser, and the "Investment & Fundraising Track" language on the official About page, this Demo Day is very likely **the investment-track component of the same KANAD S.H.I.E.L.D. program**, running on its own schedule independent of the (weather-)postponed main hackathon pitch event. This means: (a) the ecosystem is actively running events under this umbrella right now even though the site says "postponed," and (b) mentors from ISRO/Indian Army/NFSU/GVFL are realistic judge/mentor-pool candidates for the eventual main event too — a materially different (and more technically serious) judge profile than "police officers only."

---

## Prior editions and sibling events

- **No evidence of a prior "KANAD S.H.I.E.L.D."-branded event.** This appears to be the **first edition** under this specific name.
- **A genuine predecessor exists:** the Ahmedabad Cyber Crime Branch ran **"Parakram CTF 2023"** (registration portal: parakram.ahd-cyber.org), with registration open 16–23 March 2023 and "**12 major challenges** addressing different aspects of cybercrime." No prize amounts, problem-statement list, or winner names could be found despite searching — the trail goes cold after the announcement stage. ([cyberyodha.org](https://www.cyberyodha.org/2023/03/ahmedabad-cyber-crime-branch-has.html))
- No evidence found of a distinct, recurring "Gujarat Police Cyber Hackathon" brand outside of KANAD S.H.I.E.L.D. and Parakram.
- **Implication:** there is no publicly documented "what won last time" to reverse-engineer. The single best proxy for judge taste is therefore (a) the branch's own recent casework (digital arrest, deepfake, crypto, mule accounts, WhatsApp investment scams — see operations list above), and (b) the explicit per-problem-statement evaluation criteria in PS_00, not a prior winner.

---

## Social/media coverage

- **X — @cybercrimeahd:** direct fetch of the profile returned an HTTP 402 (paywalled/blocked) via the available fetch tool; could not browse the full timeline. One indexed post (via search) is fully quotable: *"KANAD S.H.I.E.L.D. 2026 COMING SOON! Get ready to secure the future. Registrations are now open! Scan the QR code. More info: [link] @GujaratPolice @DrLavina_IPS @AhmedabadPolice @ihubgujarat @karnavati_uni @sanghaviharsh #hackathon #ahmedabadcybercrime"*.
- **Instagram — @ahmedabadcybercrime**, post [DYtdl_LtGEp](https://www.instagram.com/p/DYtdl_LtGEp/): *"KANAD S.H.I.E.L.D. 2026 — Security Hackathon for Intelligence, Encryption, Law Enforcement & Defence — COMING SOON! Get ready to secure the future. Organised by: @ahmedabadcybercrime (Cyber Crime Branch), @ahmedabadpolice (Ahmedabad City Police). Registrations are now open! Scan the QR code. More information: www.kanadshield.com"*
- **YouTube:** video titled *"KANAD S.H.I.E.L.D 🚨 Gujarat Cyber Crime Department's BIG Opportunity for Startups"* at https://www.youtube.com/watch?v=_CXryX4Si5s, uploaded approximately 13 May 2026. **Could not retrieve description text or transcript** — the fetch tool returned only YouTube's page chrome/navigation, not the video metadata panel. Title is confirmed; content of description/transcript is a genuine gap.
- **Press (DeshGujarat, TOI, Divya Bhaskar, Ahmedabad Mirror):** no dedicated news article specifically covering the KANAD S.H.I.E.L.D. launch or postponement was found in the searches run for this file. This is a real gap, not a "nothing exists" conclusion — the search budget for this task was capped and press coverage searches were deprioritised in favour of confirming organiser identities and event mechanics. It's plausible coverage exists in Gujarati-language press not well-indexed by the English-biased search tool used here.

---

## Gujarat/Ahmedabad cybercrime statistics — for pitch-opening numbers

| Stat | Value | Period | Source |
|---|---|---|---|
| People targeted statewide (Gujarat) | 142,476 | Jan–Sep 2025 | Gujarat CID Cyber Cell data, via [the420.in](https://the420.in/gujarat-cybercrime-losses-hit-678-crore-72000-victims-targeted/) |
| Of those, actually defrauded | 72,091 victims | Jan–Sep 2025 | same |
| Total lost | **₹678 crore** | Jan–Sep 2025 | same |
| Top districts by complaint volume | Ahmedabad and Surat | Jan–Sep 2025 | same |
| Cybercrime complaints, Gujarat | 1.31 lakh | Full year 2024 | same article, prior-year comparison |
| Returned to victims | ₹108 crore | 2024 | same |
| Frozen in fraudulent transactions | ₹285 crore | 2024 | same |
| National 1930-helpline complaints | 3.24 crore | 2025 | [the420.in](https://the420.in/india-cybercrime-1930-helpline-complaints-2025-digital-fraud-alarm/) |
| National cybercrime complaints registered on portal | 8.2 million, of which 184,000 → FIRs | as of 30 Nov 2025 | same |
| National amount safeguarded via 1930 | ₹8,189 crore, across 3.61 lakh complaints, against ~₹20,000 crore total fraud estimated | cited alongside above | same |
| Ahmedabad "Cyber Aashvast" scheme recovery | ₹70 lakh saved + ₹15 lakh recovered | period unstated | Patrika (⚠️ single source, unverified period) |

**Best single opening stat for a pitch, with clean sourcing:** *"Between January and September 2025 alone, cybercriminals targeted over 142,000 people in Gujarat and successfully defrauded 72,091 of them out of ₹678 crore — per the Gujarat CID's own Cyber Cell data — with Ahmedabad among the top two districts hit."*

---

## Sources

- https://kanadshield.com/index.html, /about.html, /timeline.html, /how-it-works.html, /contact.html, /terms-and-condition.html, /disclaimer.html, /category-1.html, /category-2.html (all fetched live, 2026-08-09)
- https://deshgujarat.com/2024/04/25/appointments-of-12-ips-officers-in-gujarat-declared/
- https://www.nitkkraa.org/newsroom/news/Celebrating-Excellence-Mr-Sharad-Singhal-IPS-Awarded-Presidents-Police-Medal-for-Meritorious-Service.dz
- https://www.prokerala.com/news/articles/a1783090.html
- https://indianmasterminds.com/features/the-unfolding-of-a-digital-nightmare-ips-lavina-sinha-busts-indias-largest-digital-arrest-scam-97966
- https://indianmasterminds.com/news/ips-news/gujarat-12-ips-officers-reshuffled-lavina-sinha-made-dcp-cybercrime-ahmedabad/
- https://deshgujarat.com/2026/07/04/anupam-singh-gahlaut-joins-office-as-police-commissioner-of-ahmedabad-city/
- https://english.gujaratsamachar.com/news/ahmedabad/anupam-singh-gehlot-appointed-ahmedabad-police-commissioner-81880162554
- https://x.com/Cyberdost/status/1920067448851546585
- https://www.darpanmagazine.com/news/india/gujarat-ahmedabad-cyber-cell-busts-illegal-call-centre-targeting-canadians-four-arrested/
- https://english.gujaratsamachar.com/news/gujarat/ahmedabad-cyber-crime-branch-arrests-three-in-17-lakh-stock-market-investment-fraud-case-53381370220.html
- https://www.cyberyodha.org/2025/05/ahmedabad-cyber-crime-branch-arrests-6.html
- https://www.cyberyodha.org/2023/03/ahmedabad-cyber-crime-branch-has.html
- https://parakram.ahd-cyber.org/
- https://fundsforcompanies.fundsforngos.org/events/startup-police-cybersecurity-innovation-program-cybershield-ahmedabad-india/
- https://www.instagram.com/p/DYtdl_LtGEp/
- https://www.youtube.com/watch?v=_CXryX4Si5s
- https://cmogujarat.gov.in/en/latest-news/cm-launches-ahmedabad-polices-cyber-safe-mission-aiming-at-checking-cyber-frauds/
- https://www.patrika.com/ahmedabad-news/cyber-crime-ahmedabad-dial-100-fraud-help-cyber-aashvast-5635398
- https://x.com/kumarmanish9/status/1963617934896762916
- https://ihubgujarat.in/ (fetched live)
- https://education.gujarat.gov.in/KeyInitiativePageDetails/qEITCG3U50OobCZFAdsNeQ==
- https://www.freepressjournal.in/business/gujarat-at-the-top-for-4th-time-1543-startups-funded-under-ssip-20
- https://the420.in/gujarat-cybercrime-losses-hit-678-crore-72000-victims-targeted/
- https://the420.in/india-cybercrime-1930-helpline-complaints-2025-digital-fraud-alarm/
- https://deshgujarat.com/2025/08/12/gujarat-govt-to-set-up-separate-cyber-crime-unit-amid-rising-online-frauds/
- https://the420.in/meet-the-cyber-forensics-champions-winners-of-the-worlds-biggest-digital-hackathon/ (found but not opened — unrelated "world's biggest" hackathon, not KANAD S.H.I.E.L.D.; flagged so it isn't mistaken for a prior edition)

---

## Gaps

1. **Exact event date** — genuinely not published. Site says "will be announced shortly."
2. **True final submission deadline** — three conflicting dates found (25 May / 20 Jun / 28 Jun 2026); not resolved.
3. **"Academic Partner" identity** — the site's footer logo file is named `naac.png`, but independent social posts tag Karnavati University as a partner. Could not confirm whether these are the same thing (e.g., Karnavati University displaying its NAAC accreditation mark as its partner logo) or two different entities. Not confirmed either way.
4. **YouTube video description/transcript** — only the title was retrievable; content unknown.
5. **Dedicated press coverage** (DeshGujarat/TOI/Divya Bhaskar/Ahmedabad Mirror specifically on KANAD S.H.I.E.L.D.) — none found within the search budget used; Gujarati-language coverage is a likely blind spot of the English-biased search tool.
6. **Exact judging-day format** — the site says "pitch live to Experts & government officials" but does not publish a judge roster, scoring rubric weights, pitch time limits, or number of finalists per category.
7. **What "deployment with government/LEA" actually entails contractually** — no MoU/licensing template published; presumably negotiated post-selection.
8. **Parakram 2023 outcomes** — no winners, prize amounts, or problem statements recoverable.
9. **Precise Cyber Crime Branch vs. Cyber Crime Police Station addressing** — Shahibaug (Branch, per the event's own contact page) vs. Gaikwad Haveli/Jamalpur (Cell, per a third-party directory listing) not reconciled.

---

## What this panel will reward (inference, clearly labelled)

This section is **inference**, built from the organiser identities, their own recent public record, and the published scoring language — not from any confirmed rubric.

1. **The shortlisting criteria are explicit and narrow: novelty, technical depth, presentation clarity.** Nothing about market size, business model, or team pedigree is mentioned at the shortlisting stage — this reads as a genuinely technical filter before it becomes a pitch competition.

2. **Judges will very likely include working investigators, not just executives.** Singhal, Sinha, and Makadia are all still actively running live cases (arrests reported into 2026) and have shown up as keynote/mentor figures at the closely-related Cyber Security Demo Day just two weeks before this scrape. A demo that assumes an executive audience unfamiliar with actual case friction will underperform versus one that speaks fluently to how CDR/IPDR/mule-account/crypto-tracing work is actually done today.

3. **Deepfakes, digital-arrest scams, and WhatsApp-group investment fraud are not one theme among many — they are the branch's current top structural burden**, evidenced independently by (a) DCP Sinha's own casework, (b) the recent CCTV-hacking-racket bust, (c) the new-statewide-cyber-unit announcement citing "fake digital arrests and deepfake audio-video calls" by name, and (d) Category 1's TruthShield problem statement. A Category 2 team building something adjacent to this (e.g., senior-citizen safety, women's safety) should explicitly reference digital-arrest/video-coercion patterns — it's demonstrably top-of-mind for the exact people judging.

4. **i-Hub Gujarat's involvement pulls in a technical mentor bench beyond policing** — ISRO, SAC, Indian Army, NFSU, GVFL, and investment partners (Jamwant Ventures, Sucseed Ventures) were all present at the July 2026 Demo Day under the same officer trio. If judging follows a similar format, expect at least some judges evaluating for deployability/fundability, not only police-operational fit — a hybrid pitch that speaks to both operational utility *and* a credible path to scale/funding is likely to outperform a pure-tech demo.

5. **The clean IP terms are worth stating in the pitch or Q&A, not just relying on.** Since the organiser publicly claims no ownership over submissions, a team can safely lead with a genuinely proprietary/defensible technical approach without hedging language — and can use the absence of a deployment MoU as a legitimate question to ask judges directly ("what would the path to a pilot actually look like"), which also signals seriousness about real-world adoption, something the "opportunities" framing on the homepage (interns, deployment, LEA engagement) suggests they explicitly want to see.

6. **The event's own postponement (weather) plus the parallel Investment Demo Day already having happened is a live signal**: the program is being run in modular, iterative fashion (investment track running ahead of the main hackathon pitch), not as a single monolithic ceremony. Teams should expect the eventual pitch event to be scheduled on short notice once weather/logistics clear, and should keep their materials submission-ready rather than assuming a long lead time once a date is announced.
