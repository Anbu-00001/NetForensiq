# PS_03 — The Legal, Procedural, and Data-Reality Layer

> **Scope note.** This document supports every Category 1 problem statement that references
> real investigative artefacts (Big Data Analysis Tool, CallGuard, SIMScanner, CellScope,
> IntelliBank/Mule-Account, CryptoTrack) and every Category 2 problem statement that touches
> evidence, FIRs, or citizen data. It answers: what these artefacts actually are, how police
> lawfully obtain them, what format they arrive in, what the new criminal-law codes now
> require of any tool that touches them, and how a student/hackathon team can demo
> credibly **without ever holding real citizen data**.
>
> Research date: 9 Aug 2026. Everything below reflects the law **as amended and in force on
> that date**, principally BNS/BNSS/BSA (in force since 1 July 2024), unless marked otherwise.
> Primary-source fetches to indiacode.nic.in were blocked (HTTP 403) during this research
> session; section-number claims below are cross-checked across 2–4 independent legal-
> commentary sources each, but **should be re-verified against the bare act** before being
> quoted in a submission or slide deck if the exact wording is load-bearing. Anything not
> independently corroborated is flagged **⚠️ UNVERIFIED**.

---

## Glossary

| Acronym | Full form | One-line meaning |
|---|---|---|
| **BNS** | Bharatiya Nyaya Sanhita, 2023 | Replaces IPC 1860 — substantive criminal offences |
| **BNSS** | Bharatiya Nagarik Suraksha Sanhita, 2023 | Replaces CrPC 1973 — criminal procedure (FIR, investigation, trial, search/seizure) |
| **BSA** | Bharatiya Sakshya Adhiniyam, 2023 | Replaces Indian Evidence Act 1872 — rules of evidence, incl. electronic evidence |
| **CAF** | Customer Application Form | Subscriber KYC form filled at SIM purchase |
| **CDR** | Call Detail Record | Per-call metadata log kept by a telecom operator |
| **IPDR** | Internet Protocol Detail Record | Per-session internet-usage metadata log kept by an ISP |
| **ILD** | International Long Distance (Gateway) | Entry/exit point for international voice traffic into India's PSTN |
| **CEIR** | Central Equipment Identity Register | DoT's national IMEI blacklist/database (via C-DoT) |
| **TAFCOP** | Telecom Analytics for Fraud Management & Consumer Protection | Citizen self-service: "how many SIMs are in my name" |
| **ASTR** | Artificial Intelligence and Facial Recognition powered Solution for Telecom SIM Subscriber Verification | DoT/C-DoT facial-match engine to find duplicate/fraud SIM photos |
| **CNAP** | Calling Name Presentation | Displays a verified caller's registered name on the receiving handset |
| **RICWIN** | Report Incoming International Call With Indian Number | Sanchar Saathi tool to report spoofed international calls masquerading as domestic |
| **KYM** | Know Your Mobile | IMEI genuineness/authenticity check |
| **NCRP** | National Cyber Crime Reporting Portal (cybercrime.gov.in) | Citizen portal to file cybercrime complaints |
| **CFCFRMS** | Citizen Financial Cyber Fraud Reporting and Management System | Backend that routes 1930/NCRP financial-fraud reports to banks/wallets for freeze |
| **I4C** | Indian Cyber Crime Coordination Centre | MHA's national nodal body for cybercrime coordination |
| **CCPWC** | Cyber Crime Prevention against Women and Children (Scheme) | I4C funding scheme for state forensic labs/training |
| **TAU** | (National Cybercrime) Threat Analytics Unit | I4C vertical producing MO/pattern intelligence |
| **CCTNS** | Crime and Criminal Tracking Network & Systems | Pan-India police-station-to-state crime records network |
| **ICJS** | Inter-operable Criminal Justice System | Integrates CCTNS (police), e-Courts, e-Prisons, e-Forensics, e-Prosecution |
| **NAFIS** | National Automated Fingerprint Identification System | NCRB's national fingerprint database, issues a 10-digit National Fingerprint Number |
| **NIDAAN** | National Integrated Database on Arrested Narco-Offenders | NCRB narcotics-offender database |
| **NDSO** | National Database on Sexual Offenders | NCRB registry |
| **ITSSO** | Investigation Tracking System for Sexual Offences | NCRB timeline-tracking tool for POCSO/rape investigations |
| **NJDG** | National Judicial Data Grid | Near-real-time case-data repository across courts |
| **NPCI** | National Payments Corporation of India | Operates UPI, IMPS rails; source of payment trail data |
| **DPIP** | Digital Payments Intelligence Platform (RBI) | 2025 RBI–NPCI–bank data-sharing network for mule/fraud signals |
| **CERT-In** | Indian Computer Emergency Response Team | National nodal agency under MeitY for cybersecurity incident response |
| **DPDP Act** | Digital Personal Data Protection Act, 2023 | India's data-protection statute |
| **eSakshya** | e-Sakshya (e-evidence) app | NIC mobile app for BNSS-mandated audio-video recording of search/seizure |
| **BSA §63 certificate** | — | Replaces IEA §65B certificate; authenticates electronic records for court |
| **UASL** | Unified Access Service Licence | Telecom operating licence — its conditions require CDR/IPDR retention |
| **TSP** | Telecom Service Provider | Any licensed telecom operator (Jio, Airtel, Vi, BSNL, etc.) |
| **MSISDN** | Mobile Station International Subscriber Directory Number | The dialable phone number |
| **IMEI** | International Mobile Equipment Identity | Unique handset (device) identifier |
| **IMSI** | International Mobile Subscriber Identity | Unique SIM (subscriber) identifier |
| **LAC/TAC** | Location Area Code / Tracking Area Code | GSM/UMTS vs LTE terms for the same concept — the tower-group location identifier |
| **CGI** | Cell Global Identity | MCC+MNC+LAC+CID — a globally unique cell-tower identifier |
| **eNodeB / gNodeB** | Evolved Node B / next-Generation Node B | 4G LTE / 5G NR base station |
| **CGNAT** | Carrier-Grade NAT | ISP-side NAT that shares one public IP among many subscribers |
| **NCRB** | National Crime Records Bureau | Central agency running CCTNS, NAFIS, "Crime in India" statistics |

---

## A. The data artefacts

### A.1 CDR — Call Detail Record

**What it is.** A per-call/per-SMS metadata log generated by the telecom switch, not the
content of the call. Standardised loosely on 3GPP TS 32.298 "charging data record" concepts,
though Indian operators expose it to LEAs in operator-specific spreadsheet/text exports rather
than the raw 3GPP ASN.1 format.

**Typical columns** (composited from telecom-forensics and legal-practice sources; exact
column names vary by operator):
- Calling number (A-party MSISDN) / Called number (B-party MSISDN)
- Date, call-start time, call-end time, duration (seconds)
- Call type: MOC/MTC (mobile-originated/terminated), SMS-MO/MT, data session
- IMEI of the handset used
- IMSI of the SIM used
- First Cell ID (cell that handled call setup) and Last Cell ID (cell at call end) — each
  resolvable to LAC + CI
- Roaming indicator / roaming operator (if applicable)
- Call forwarding indicator (if the call was a diversion)

CDRs **do not** contain call content (that requires a separate, much narrower, interception
warrant under the Telecommunications Act 2023 — see §B.6).

**How police request it.** Under the old regime this was **Section 91 CrPC**; under BNSS it is
**Section 94 BNSS** ("summons to produce document or other thing") — an investigating officer
(or the court) issues a written requisition to the TSP's nodal officer specifying the
number(s), the exact date range, and the investigative justification. For CDRs tied to an FIR,
police typically do **not** need a magistrate's separate order — Section 94 gives the
IO-in-charge of the police station this power directly, subject to internal supervisory
sign-off (SP/DCP level in practice for sensitive requests). This is distinct from **live call
interception**, which does require a competent-authority order under the Telecommunications
Act, 2023 rules (see §B.6) and cannot be obtained via a Section 94 summons.

**TSP turnaround & retention.** Per TRAI/DoT licence conditions (UASL), TSPs must retain CDRs
for a defined window — commonly cited as **at least 1 year** in current licence terms (older
sources cite 6 months; this figure has been revised upward over successive licence amendments
— **⚠️ UNVERIFIED exact current figure, confirm against the live UASL text/DoT circular before
quoting**). Turnaround to a police request is typically **days to a few weeks** depending on
the TSP's nodal-officer backlog and whether the request is routed through the TSP's law-
enforcement portal versus a manual letter.

**Court admissibility.** A CDR is an electronic record; it is admissible only when accompanied
by a **BSA Section 63(4) certificate** from a person occupying a responsible official position
in the TSP (see §B.1).

### A.2 IPDR — Internet Protocol Detail Record

**What it is.** IPDR is to internet sessions what CDR is to voice calls: a metadata record of
who connected to what, when, and for how long — **not** browsing content, not URLs in most
configurations, but the network-session envelope.

**Why it exists as a distinct compliance requirement.** DoT mandated IPDR logging so that,
given an IP address + timestamp, an ISP can resolve it back to a subscriber. In 2021, DoT
revised the mandated retention to **2 years** and issued updated parameter lists for IPDR and
for **NAT syslogs** specifically (DoT circular "Compliance of revised parameters for IPDR ...
and SYS of NAT", dated 2021, effective 31-10-2022 — source: `dot.gov.in/dataservices/...`,
page confirmed to exist but returned HTTP 403 to automated fetch during this research; **⚠️
verify the exact parameter list against the live DoT circular, not this summary**).

**Typical fields** (from telecom-compliance vendor documentation, cross-checked against the
DoT mandate's stated purpose):
- Subscriber identifier (MSISDN/IMSI/username)
- Private (internal) IP address and port assigned to the subscriber's session
- Public IP address and port **after CGNAT translation**
- Destination IP/port (where feasible/permitted)
- Protocol (TCP/UDP)
- Session start time, end time, duration
- Data volume (bytes up/down)
- Access Point Name (APN) for mobile data

**Why CGNAT makes attribution genuinely hard — this is a real, hard technical problem.**
IPv4 address exhaustion means most Indian mobile/broadband subscribers share a small pool of
public IPv4 addresses via large-scale Carrier-Grade NAT. When a cybercrime is traced to a
public IP address and timestamp, that IP by itself can correspond to **thousands of
concurrent subscribers** behind the same CGNAT pool. Attribution is only possible if:
1. The complainant/victim platform (bank, social media company) logged not just the source
   IP but also the **source port number** at the exact millisecond of the transaction, **and**
2. The ISP's own IPDR/NAT-syslog captured the private-IP↔public-IP:port mapping **for that
   exact port and timestamp**, **and**
3. Clocks on both systems are synchronised (NTP drift of even a few seconds can point to the
   wrong subscriber).
This three-way join (platform log + ISP CGNAT log + synchronised time) is precisely why the
2021 DoT mandate emphasises port-level logging — without it, an IP-only trace resolves to
"somewhere in a CGNAT pool of thousands," which is useless for an FIR. Any hackathon tool that
promises "IP-to-identity resolution" should explicitly model this three-way join and its
failure modes (missing port, clock skew, expired retention window) rather than pretending
IP→person is a one-step lookup — that is exactly the mistake that will read as naive to a
police judge.

### A.3 CAF — Customer Application Form

**What it is.** The KYC document filled at SIM purchase — physical form or (now standard)
Aadhaar-based e-KYC/digital KYC. Captures: full name, DOB, address, photo, ID-proof type and
number (Aadhaar/Passport/Voter ID/Driving Licence), alternate contact number, connection type
(prepaid/postpaid), retailer/point-of-sale ID, activation date, and for Aadhaar e-KYC, a
biometric or OTP consent artefact.

**The fake/forged CAF problem.** Because retail SIM dealers historically had weak verification
incentives, forged or photocopied CAFs (borrowed/stolen ID documents, look-alike photos) were
the primary channel for **bulk fraud SIM issuance** used in phishing/OTP-fraud call centres and
SIM-box operations. DoT's response has layered several controls:
- **Mandatory digital/Aadhaar e-KYC** for new connections, reducing (not eliminating) forged
  physical CAFs.
- **ASTR** (C-DoT's AI facial-recognition tool) — cross-matches subscriber photos across the
  ~134-crore-connection database to flag the same face registered under many different
  names/IDs; reported to have flagged **~67 lakh** suspected fraudulent connections and led to
  **~59 lakh disconnections** after TSP verification (figures as reported in 2023–24 press
  coverage of ASTR; treat as an order-of-magnitude, not an audited figure).
- **SIM-per-person cap**: current DoT rule allows a maximum of **9 mobile connections per
  ID nationally** (reduced from earlier limits; **6** in J&K, the Northeast, and Assam).
- **Bulk/business connections**: retail "bulk SIM" issuance to businesses now requires
  entity-level KYC (Certificate of Incorporation, GST registration, PAN, verified registered
  address) rather than just an authorised signatory's individual ID; **mandatory police
  verification of SIM dealers** was introduced and **bulk connections for individuals were
  discontinued** as an anti-fraud measure (Minister Ashwini Vaishnaw, reported policy change —
  confirm exact notification date/number before citing precisely).
- **90-day cooling-off**: a disconnected/surrendered mobile number cannot be reissued to a new
  subscriber for 90 days, to prevent immediate SIM-swap misuse of a just-vacated number.

This is exactly the terrain of the **SIMScanner** problem statement (bulk IMSI reading/
reporting) — the "AI-driven bulk SIM reading" ask maps directly onto what ASTR already does at
national scale; a hackathon team's honest differentiator is a **local/offline field tool** for
officers doing physical SIM-shop raids, not a re-implementation of ASTR's national face-match
database (which a student team cannot access).

### A.4 ILD Gateway data, VoIP spoofing, grey routes, SIM boxes

**What an ILD Gateway is.** The licensed international-long-distance gateway is the lawful
entry/exit point where international voice traffic crosses into India's domestic telecom
network; only licensed ILD operators may terminate international calls onto Indian numbers,
and the terminating call is supposed to retain an international-call marker/prefix so the
receiving subscriber and the network both know it originated abroad.

**How the fraud works (directly relevant to CallGuard PS).**
1. A fraud operation abroad originates VoIP calls (via any softphone/SIP trunk provider).
2. Instead of routing through a **licensed ILD gateway** (which would preserve the
   international marker and be traceable/taxable), the traffic is diverted through an
   unauthorised **grey route** — often terminated locally via a **SIM box**: a rack of
   dozens/hundreds of local SIM cards wired into a GSM gateway device that receives the VoIP
   call over the internet and re-originates it as an ordinary **domestic** call from a local
   number.
3. Because the call now looks like a normal India-to-India call, it (a) evades ILD termination
   charges (revenue/interconnect-bypass fraud against the telecom operator — reported to cost
   the industry on the order of tens of billions of dollars globally per year per CFCA figures)
   and (b) **defeats naive "is this an international number" spoofing checks**, because the
   displayed caller ID is a genuine-looking local mobile number, not a suspicious +xx prefix.
4. DoT's countermeasure is **RICWIN** ("Report Incoming International Call With Indian
   Number") on Sanchar Saathi — a citizen can report a call that *felt* international
   (accent, script, content) but *displayed* as a domestic Indian number, feeding DoT's
   detection of illegal telephone exchanges/SIM-box operations. DoT also launched an
   "International Incoming Spoofed Calls Prevention System" (reported Oct 2024) that flags/
   labels such calls before they reach subscribers.
5. Police raids on illegal telephone exchanges (SIM-box farms) recur across Indian cities —
   Bengaluru CCB and others have busted such operations; these are physical hardware seizures,
   not purely digital investigations, which is a useful detail for a CallGuard demo (the
   "target" isn't only software — it's often a room full of GSM modems).

**Implication for CallGuard.** A credible spoofed-call detector cannot rely solely on caller-ID
prefix heuristics (grey-route/SIM-box calls deliberately present *valid-looking local* caller
IDs). Genuinely useful signals are network-side: **CDR anomalies** (one SIM handling
implausibly high concurrent-call volume/duration typical of a SIM-box), **cell-ID clustering**
(many numbers all served by the same one or two cell towers — the SIM-box location), and
**RICWIN-style citizen reporting** correlated against those CDR anomalies. This is the honest
"integration path" story: the tool's real value is pattern-detection logic that a TSP or
police cyber cell could run **over their own CDR/IPDR feed**, not a standalone spoofing
classifier a citizen app could run with no telecom-side data at all.

### A.5 1930 / NCRP / CFCFRMS — the citizen financial-fraud reporting flow

**The flow.**
1. Victim calls the **1930** national cyber-fraud helpline (24×7) or files on
   **cybercrime.gov.in** (NCRP).
2. The call/portal entry generates a ticket that is pushed into **CFCFRMS** (Citizen Financial
   Cyber Fraud Reporting and Management System), which is wired into participating banks,
   payment wallets, and NPCI rails.
3. CFCFRMS attempts to place a **lien/hold** on the destination account(s) the money moved
   through, working backward along the transaction chain as far as the funds can still be
   traced before withdrawal/further layering.
4. The beneficiary bank places a **temporary hold ("intermediate hold")** — reported to last
   up to **7 working days** — during which the victim's bank/police can pursue a formal freeze
   order.

**The "golden hour."** Because mule-account layering (fast fan-out of stolen funds across many
downstream accounts, then rapid cash withdrawal) can be near-total within hours, the entire
CFCFRMS design is optimised around **speed of first report**. Reported effectiveness: calling
within minutes of the fraud gives a claimed **>60% success rate of freezing funds** before they
disperse; every hour of delay collapses that probability, because money already withdrawn or
moved through 3+ layered mule accounts is functionally unrecoverable through this channel.

**Why money still escapes, and the reported recovery rate.** Even with CFCFRMS, national
recovery has historically been poor: a 2024 Parliamentary Standing Committee figure widely
cited put actual recovered amount at roughly **₹0.57 crore out of ₹2,294.79 crore** lost in
2022 (a recovery rate under 1%) — a stark, quotable number for a hackathon problem framing.
More recent, localised efforts (e.g., a state cyber cell reporting recovery improving from
~24.6% to ~88.6% over a 6-month coordinated push in one state, 2025–26) show the ceiling is far
higher with disciplined golden-hour response — the gap between the national historical average
and these localised best-practice numbers **is** the opportunity space for the "Detection of
Mule Bank Accounts" and "IntelliBank" problem statements. NCRB's overall cybercrime numbers:
**28.15 lakh cases in 2025** (up from 22.68 lakh in 2024) with total reported losses around
**₹22,495 crore** in 2025 (marginally down from ₹22,845 crore in 2024, attributed to faster
intervention); I4C reports having **blocked over ₹8,031 crore** in fraudulent transactions
cumulatively since the mechanism's inception. Reported cybercrime **conviction rate was ~47%**
in 2023 per NCRB (⚠️ verify which case-outcome denominator this uses — conviction rates on
*disposed* cases read very differently from conviction rates on *all registered* cases).

**Mule-account lifecycle.** Recruit (often via fake job/loan-app offers, or an unwitting
account holder whose credentials were phished) → account opened/hijacked → receives layered
inbound transfers from multiple fraud victims within a short window → rapid fan-out to further
mule accounts or immediate cash withdrawal/crypto off-ramp → account effectively "burned" and
abandoned within days to weeks. RBI's 2025 **DPIP** (Digital Payments Intelligence Platform,
built with NPCI) and the **MuleHunter.AI** initiative are the state-of-the-art institutional
response — a nationwide bank/fintech/regulator signal-sharing network specifically to flag
mule-like accounts before/as fraud money transits them. A March-2026 report cited **524,121
suspected mule accounts/digital identities flagged in a single month**, indicating the scale a
production system operates at (a useful "why this needs to be automated, not manual" data
point). Legally, note the **Andhra Pradesh High Court** ruling (2026) holding that a merchant's
account cannot be frozen merely for receiving one incoming UPI payment later linked to fraud —
i.e., **not every downstream account is a knowing mule**, an important nuance for any
risk-scoring tool to avoid false-positive harm to innocent account holders (a point that will
read as legally sophisticated to a police panel).

### A.6 CEIR and the Sanchar Saathi service family

**CEIR (Central Equipment Identity Register).** DoT/C-DoT's national IMEI blacklist database.
Once a device IMEI is blacklisted, it is barred from registering on **any** Indian TSP network
— the block is network-wide, not carrier-specific.

**What a citizen can do (public, self-service, via sancharsaathi.gov.in or the app):**
- **Block a lost/stolen handset's IMEI** (own device only) — reportedly effective across
  networks within ~24 hours; **unblock** it if recovered.
- **TAFCOP** — see which mobile connections nationally are registered against one's own
  ID-proof, and flag ones not recognised for re-verification/disconnection.
- **KYM** (Know Your Mobile) — check an IMEI's authenticity/genuineness before buying a
  second-hand phone.
- **Chakshu** — report a specific suspicious call/SMS/WhatsApp message (impersonation,
  investment scam, financial fraud) or unsolicited commercial communication.
- **RICWIN** — report a suspicious international call that displayed as a domestic number.
- **CNAP** — (being rolled out) shows a verified caller's registered name, not just number.
- Impact claimed as of Feb 2026: **~7.7 lakh** suspected-fraud reports via Chakshu leading to
  **39.43 lakh** connections disconnected, **2.27 lakh** handsets blacklisted, **1.31 lakh**
  fraud SMS templates blocked (cumulative, since launch).

**What only police/law-enforcement/TSPs can do:** trace an IMEI's **full usage history**
(which SIMs it has carried, in which cell locations, over what period) — this requires a
**law-enforcement request to CEIR/DoT or a court order**, not the citizen self-service block
form. Similarly, bulk/programmatic querying of CEIR (e.g., "check these 500 IMEIs") is not a
citizen-facing capability. **This is the exact yes/no/only-via-police-partner line a
hackathon team must respect**: a CellScope/SIMScanner-style tool can legitimately build the
citizen-facing single-IMEI lookup UX pattern, but cannot claim to offer bulk/historical CEIR
tracing without an official police-partner integration — state that explicitly on the
integration-path slide rather than mocking it silently.

### A.7 Cell ID / LAC / TAC / eNodeB / gNodeB across 2G–5G

**What a "Cell ID" resolves to.** A **Cell Global Identity (CGI)** = MCC (country) + MNC
(operator) + LAC (2G/3G) or TAC (4G/5G "Tracking Area Code") + CI (Cell Identity, the specific
sector/tower). Knowing the CGI a phone was attached to at call time tells an investigator
**which physical cell tower/sector** served the device — a coarse location estimate (typically
a few hundred metres to a few kilometres radius depending on tower density), not GPS-precision.
Terminology differs by generation: **eNodeB** is the 4G LTE base station; **gNodeB** the 5G NR
base station; older 2G/3G equipment is a BTS/NodeB under a LAC.

**Why open cell-tower databases are patchy (relevant to the CellScope PS).** Public databases
like **OpenCelliD** are crowdsourced — built from phones running location-logging apps that
opportunistically record which cell towers they saw and their GPS position at that moment.
Coverage is therefore a function of app adoption density, not network completeness: dense
urban areas in countries with heavy OpenCelliD-contributing-app usage are well mapped; large
parts of rural India, newly deployed 5G gNodeBs, and towers on less-travelled routes are
**not** reliably present. There is **no authoritative, publicly downloadable, India-wide
Cell-ID-to-GPS-coordinate database** — the ground truth lives only inside each TSP's internal
network-planning systems, which are not public. Any "Cell ID finder" tool a student team builds
is therefore necessarily building against a **crowdsourced, incomplete** substrate (OpenCelliD
or similar) unless a police/TSP partner supplies authoritative tower-location data — again, the
honest integration-path framing: "this demo runs on OpenCelliD data; production accuracy
requires each TSP's authoritative tower database, obtainable only via police/DoT-mediated
request, not a public API."

### A.8 Bank/UPI data, NPCI trails, mule-account data flow

**What banks give police, and how slowly.** Bank account statements/KYC are obtained the same
way as CDRs — a **Section 94 BNSS** production summons (formerly Section 91 CrPC) to the bank's
nodal/law-enforcement liaison officer. Banks maintain such liaison desks specifically for
police requests, but turnaround is still commonly **days to weeks**, especially for
multi-branch/multi-bank transaction-chain tracing where each hop is a separate bank with its
own nodal officer and its own backlog. NPCI (which operates UPI/IMPS) can be approached
directly for **cross-bank UPI transaction-trail reconstruction** when funds moved through
several banks' UPI handles in sequence — this is often faster than chasing each bank
individually because NPCI sits above all of them on the UPI rail, but it still requires a
formal law-enforcement request, not an open API.

**Golden-hour freeze mechanism** — see §A.5 above (CFCFRMS/1930); the **DPIP** platform (RBI +
NPCI + banks, 2025) is the newer, faster, always-on layer designed to flag mule-pattern
accounts proactively rather than only reactively per-complaint.

---

## Table — Data artefacts at a glance

| Artefact | What it contains | Who holds it | Legal instrument to obtain | Typical delay |
|---|---|---|---|---|
| **CDR** | Call/SMS metadata: A/B number, time, duration, IMEI/IMSI, serving Cell ID | TSP (Jio/Airtel/Vi/BSNL etc.) | §94 BNSS production summons (police); interception under Telecom Act 2023 for live content | Days–weeks |
| **IPDR** | Internet session metadata: private/public IP:port, timestamps, data volume, APN | ISP/TSP | §94 BNSS summons; DoT-mandated 2-yr retention | Days–weeks; useless if CGNAT port not logged |
| **CAF** | Subscriber KYC: name, DOB, address, ID proof, photo | TSP / retail dealer chain | §94 BNSS summons; DoT/Sanchar Saathi channel for fraud-SIM flags | Days |
| **ILD Gateway records** | International call routing/termination logs | Licensed ILD operator | §94 BNSS summons; DoT enforcement for illegal-exchange raids | Days–weeks; often requires physical raid for SIM-box evidence |
| **1930/NCRP/CFCFRMS ticket** | Citizen fraud complaint + transaction trail + freeze status | I4C / bank / NPCI (via CFCFRMS) | Citizen-filed directly; police access via I4C's Samanvaya/state cyber cell dashboards | Minutes (report) to days (freeze/recovery) |
| **CEIR record** | IMEI blacklist status, (for LEA) device usage history | DoT / C-DoT | Citizen self-service (own device block only); full trace needs LEA request to DoT | 24 hrs (citizen block) / days (LEA trace) |
| **Cell ID / tower location** | CGI (MCC+MNC+LAC/TAC+CI) → approx. geographic cell coverage area | TSP (authoritative); OpenCelliD (crowdsourced, partial) | TSP: police request; public: no authoritative open API | N/A public; days via TSP |
| **Bank/UPI statement & trail** | Account KYC, transaction history, UPI handle trail | Bank; NPCI (cross-bank UPI) | §94 BNSS summons to bank nodal officer; NPCI for cross-bank UPI | Days–weeks per hop |

---

## B. The new criminal-law regime (BNS / BNSS / BSA, in force 1 July 2024)

This is the biggest source of **new software requirements** for any evidence-handling tool
built for this hackathon — a solution that ignores it will look naive; one that visibly
threads it will look professional.

### B.1 Section 63 BSA — the new electronic-evidence certificate (replaces IEA §65B)

- The **Bharatiya Sakshya Adhiniyam, 2023** replaced the Indian Evidence Act, 1872, effective
  1 July 2024. **Section 63 BSA** is the provision governing admissibility of electronic
  records without producing the originating device in court — the direct successor to the
  long-litigated **Section 65B, Indian Evidence Act**.
- **Certificate is now two-part**, per the Act's Schedule: **Part A**, completed by the person
  who operated/produced the electronic record (the "device operator" — e.g., the TSP's nodal
  officer, or the officer who imaged a seized phone); **Part B**, completed by an **expert**.
  This is a meaningful tightening versus the old §65B single-signatory certificate.
- **Section 63(4)(c)**: the certificate must state the **hash value of the electronic record**
  and **identify the hash function used** — i.e., the law now explicitly bakes hashing into
  the admissibility test, not merely best-practice forensic hygiene.
- **A drafting tension flagged by the Parliamentary Standing Committee** (on the precursor
  Bharatiya Sakshya Bill): electronic records were simultaneously reclassified as **primary
  evidence** ("unless disputed") while the Act **also retains** the certificate-authentication
  requirement — a logical friction the Committee itself noted (the certificate requirement,
  historically justified because electronic records were *secondary* evidence, sits oddly
  against a *primary*-evidence classification). Practically: **still get the certificate**;
  courts have not yet settled how the tension resolves, and no defence lawyer will forgo
  challenging an uncertified electronic record just because the Act calls it "primary."
- ⚠️ **Section-number caveat**: independently corroborated across naavi.org, ksandk.com,
  rkdewan.com, lawbeat.in, and bhattandjoshiassociates.com as "Section 63 BSA," but the
  precursor Bill (as fetched from PRS) used different clause numbers (e.g., "Clause 58" for a
  related secondary-evidence provision) before renumbering at enactment. **Verify against the
  gazetted Act text (indiacode.nic.in) before quoting the exact clause/sub-clause structure in
  a formal submission** — this research could not fetch that primary text directly (blocked).

### B.2 Mandatory audio-video recording of search & seizure — BNSS §105 / §185, and eSakshya

- **BNSS Section 105** (and related provisions, commonly discussed together with **Section
  185**) mandates that investigating officers **audio-video record the entire process** of any
  search or seizure — with or without a warrant — including preparation of the seizure list
  and witnesses' signatures, "preferably" using a mobile phone.
- **Warrant searches**: recordings must be forwarded to the Magistrate **within 48 hours**.
- **Warrantless searches**: recordings go **without delay** to the District Magistrate,
  Sub-Divisional Magistrate, or Judicial Magistrate First Class.
- **eSakshya** (developed by **NIC**) is the official app built to satisfy this mandate: it
  lets an officer record scene-of-crime/search-seizure video (reported cap of up to ~4 minutes
  per clip, multiple clips per FIR), attaches a **selfie for officer verification**, supports
  **offline capture with later upload** where connectivity is poor, and is explicitly framed as
  the BNSS-compliance tool for audio-video search/seizure and for the forensic-visit mandate
  below.
- **Implication for a hackathon tool**: any "evidence intake/case-management" tool (Big Data
  Analysis Tool, CrimeGPT, ForensiX) should show it can **ingest eSakshya-format
  video/metadata** (or at minimum, timestamped video + GPS + officer ID + hash) as a first-
  class evidence type, not just documents/spreadsheets — this is now a mandatory evidentiary
  artefact type in every serious investigation, not an edge case.

### B.3 Mandatory forensic-team crime-scene visit — BNSS Section 176(3)

- For any offence **punishable with imprisonment of 7 years or more**, the officer in charge
  of the police station **must** cause a **forensic expert to visit the crime scene**, collect
  forensic evidence, and **videograph the entire process** on a mobile phone or other
  electronic device.
- **Phase-in**: states were given up to a **5-year implementation window** to build out
  forensic capacity; where local forensic facilities don't yet exist, states are directed to
  use another state's facilities in the interim. This is a well-documented capacity concern —
  commentary (e.g., ThePrint) frames it as placing "immense stress" on India's forensic-lab
  system, since the mandate applies to a very large share of the IPC/BNS offence catalogue
  (most serious property and violent crimes clear the 7-year threshold).
- **Implication**: a tool that helps triage/schedule/track forensic-team dispatch against this
  new statutory obligation (which offences trigger it, which crime scenes are still pending a
  visit, SLA tracking) is a genuinely novel, high-value, low-glamour idea that directly answers
  a real capacity crisis — worth floating for CrimeGPT/Big-Data-Tool-style submissions.

### B.4 e-FIR / Zero FIR — BNSS Section 173

- **Section 173(1) BNSS** gives **statutory** (not merely judicially-evolved) recognition to
  **Zero FIR**: any person can report a **cognizable** offence at **any** police station
  regardless of territorial jurisdiction; it is registered "Zero" (no serial number yet) and
  transferred to the jurisdictional station, which then re-registers it as a normal numbered
  FIR.
- The same section expressly permits reporting "by electronic communication" — the statutory
  basis for **e-FIR**.
- **Refusal escalation**: if an officer declines to register, Section 175 BNSS empowers a
  complainant to approach the SP or another superior officer, who can direct registration/
  investigation.
- **Preliminary enquiry gate**: for offences punishable **3–7 years**, the officer-in-charge
  may (with prior permission) conduct a preliminary enquiry before formally registering/
  investigating, rather than being obligated to register instantly — a new discretion that
  didn't exist in this form under CrPC.

### B.5 Investigation and chargesheet timelines; electronic summons

- **Electronic summons — Sections 63–64 BNSS** (procedural, not to be confused with BSA §63
  above — same number, different code, a common source of confusion worth flagging in any
  document your team writes): summons may now be issued in encrypted/electronic form bearing
  the court seal's image, and **Section 64** allows service via electronic communication with
  read-receipt confirmation; electronically served summons under Sections 64–71 are deemed
  duly served.
- **Chargesheet/investigation timelines** — reported figures (⚠️ **treat the exact day-counts
  below as indicative pending bare-act verification**, since secondary sources gave partially
  inconsistent numbers): investigation-completion/default-bail thresholds broadly track the
  old CrPC §167 structure carried into BNSS (commonly cited as **60 days** for offences
  punishable up to 10 years, **90 days** for offences punishable by death/life/10+ years,
  beyond which the accused becomes eligible for statutory/default bail); separately, courts may
  in some case categories extend the chargesheet-filing window **up to 180 days** with reasons
  recorded. **Serious sexual-offence investigations (BNS §§64,65,66,67,68,70,71 / POCSO
  §§4,6,8,10) must complete within 2 months of FIR** per **Section 193(4) BNSS** — this one is
  corroborated with a specific section citation and is safe to quote.
- **Victim notification**: victims must be informed of investigation progress within **90
  days**.
- **Trial timelines**: judgment due within **30 days** of argument completion, extendable to
  **60 days** with reasons recorded; sessions courts must **frame charges within 60 days** of
  first hearing.

### B.6 Trial in absentia — BNSS Section 356

- Allows a court to **try and pronounce judgment on a proclaimed offender in absentia** when
  the person has absconded to evade trial and there is no immediate prospect of arrest —
  effectively a statutory waiver of the right to be personally present, once due-process
  safeguards are met.
- Safeguards: **two consecutive arrest warrants at least 30 days apart**, publication in a
  national/local newspaper summoning the person to appear, notice affixed at the last known
  residence and given to a relative/friend; trial **cannot commence until 90 days after
  framing of charges**; a **state-funded advocate** must represent an unrepresented proclaimed
  offender; **appeal against conviction is barred after 3 years** from judgment unless the
  offender presents himself.

### B.7 New organised-crime and terrorism sections — BNS §§111, 113

- **BNS Section 111 ("Organised crime")** — for the first time codifies syndicate criminal
  activity (extortion, land grabbing, contract killing, **cybercrime with severe
  consequences**, human trafficking, economic offences) directly in general penal law, keyed to
  a **"continuing unlawful activity"** test (multiple chargesheets filed and cognizance taken
  within the preceding 10 years). Cognizable; penalties range from **3–10 years to death**,
  plus fine of **₹1–10 lakh**. Notably, this is the first time cybercrime "with severe
  consequences" is explicitly named as a predicate for the organised-crime charge — directly
  relevant to any tool profiling repeat cyber-fraud syndicates/mule-account networks (the
  "linked network" framing of the mule-account and dark-web problem statements maps onto how a
  §111 charge would actually be built evidentially).
- **BNS Section 113 ("Terrorist act")** — for the first time brings a terrorism definition into
  the general penal code (intent to threaten India's unity/integrity/security/sovereignty, or
  to strike terror in the public), letting designated-rank police officers register and
  investigate terror offences without relying solely on special statutes (UAPA etc.).

### B.8 Hash values, chain of custody, write-blockers — what makes digital evidence admissible

- **Write-blocker**: hardware/software that permits read-only access to a seized storage
  device, physically preventing any write operation from touching the original media during
  imaging.
- **Hash value**: a cryptographic fingerprint (commonly SHA-256 in current practice) computed
  immediately on seizure/imaging; any subsequent re-hash that doesn't match proves tampering or
  corruption. Under **BSA §63(4)(c)** the hash value **and the hash function used** must now be
  stated in the evidence certificate — this is a statutory requirement, not just forensic
  best practice.
- **Chain of custody**: an unbroken, contemporaneously-logged record of every person who
  handled the evidence, when, and what they did (seizure → transport → sealing → lab intake →
  imaging → storage → court production). A broken chain — evidence not properly sealed, a hash
  not recorded at the point of transfer, an unexplained custody gap — is a standard, effective
  defence challenge **even against a technically-valid §63 certificate**.
- **What a hackathon evidence-handling tool must therefore log**, concretely, for every
  artefact it ingests or produces: (1) SHA-256 (or stated) hash at ingestion and at every
  export, (2) timestamp + officer ID + device/location for every custody transfer, (3) an
  audit-immutable event log (append-only; tampering with the log itself should be detectable),
  (4) the BSA §63 certificate's Part A/Part B fields as structured metadata, not free text, and
  (5) a clear separation between the "original" (never touched) and "working copy" (analysed)
  — mirroring the write-blocker discipline in software terms even where no literal write-
  blocker hardware is involved (e.g., ingesting a CDR export).

### B.9 IT Act 2000 — sections still live post-BNS/BNSS/BSA

The IT Act 2000 was **not repealed**; BNS/BNSS/BSA replaced the general penal/procedure/
evidence codes, but IT-Act-specific cyber offences and intermediary rules remain the operative
law for those specific matters:
- **Section 66C** — identity theft (fraudulent use of another's password/digital signature/
  unique identifying feature); up to 3 years + fine up to ₹1 lakh.
- **Section 66D** — cheating by personation using a computer resource (the core provision for
  most online-impersonation fraud).
- **Section 67 / 67A** — publishing/transmitting obscene material / sexually explicit material
  electronically.
- **Section 69** — government power to intercept/monitor/decrypt information in the interest of
  sovereignty, security, or public order.
- **Section 69A** — government power to **block public access** to information/websites.
- **Section 79** — **intermediary safe harbour**: platforms are not liable for third-party
  content **provided** they observe due diligence and comply with lawful government/court
  directions — directly relevant to any tool (SafeInbox, TruthShield, TeleScan) that proposes
  automated takedown-request generation, since the legal trigger for losing safe harbour is
  precisely a platform's failure to act on a lawful notice.

### B.10 CERT-In 2022 Directions — 6-hour reporting, 180-day log retention

- Issued **28 April 2022** under **Section 70B(6), IT Act 2000**.
- **Mandatory reporting of cyber incidents to CERT-In within 6 hours** of noticing/being made
  aware of them, for a defined list of incident categories (data breaches, ransomware,
  unauthorised access, DDoS, etc.).
- **Mandatory 180-day log retention** for all ICT systems, with logs to be **stored within
  India**.
- **Relevance to this hackathon**: any tool positioned as helping an organisation (or the
  Cyber Crime Branch itself) meet this obligation — automated incident classification,
  6-hour-clock tracking/alerting, log-retention compliance dashboards — is solving a real,
  named, currently-under-enforced compliance burden, and is a strong "who is the actual
  customer" answer for a citizen/enterprise-facing submission (SafeInbox, Real-Time Data
  Breach Alert System for Legal & Government Ecosystem).

### B.11 DPDP Act 2023 — law-enforcement exemption and citizen-tool implications

- **Section 17** exempts data fiduciaries (and, per broader government-notification powers, can
  exempt specific government agencies) from most DPDP obligations when processing is
  **necessary for prevention, detection, investigation, or prosecution of an offence** — i.e.,
  police investigative use of personal data is substantially carved out of DPDP's consent/
  purpose-limitation machinery.
- Separately, **Section 7** and related provisions allow the State to process personal data on
  sovereignty/security/public-order grounds; commentary (MediaNama et al.) has flagged this as
  a broad, minimally-checked exemption compared to the obligations imposed on private data
  fiduciaries.
- **What this means practically for the hackathon**: a tool built **for police internal
  investigative use** (case management, CDR/CAF correlation, mule-account graphing) sits inside
  this exemption and does not need to build full DPDP consent-management machinery to be
  "compliant" for that specific use. **But** any **citizen-facing** component of a submission
  (a public complaint portal, a "check if your number is misused" self-service tool, a public
  awareness app) is processing personal data **outside** the law-enforcement exemption and
  **does** need ordinary DPDP hygiene — purpose limitation, a real consent notice, a data-
  retention/deletion policy, and a grievance-officer contact. Judges will notice if a
  citizen-facing screen collects Aadhaar/PAN/phone number with no stated retention or consent
  language — that is an easy, free credibility point to pick up.

### B.12 Telecommunications Act 2023 — what changed on interception

- Replaced the colonial-era Indian Telegraph Act, 1885 provisions (old Rules 419/419A of the
  Indian Telegraph Rules, 1951) with a modern **Section 20** framework: authorised Central/
  State agencies may intercept messages pursuant to an interception order, issuable on grounds
  of **public emergency, public safety, or national security/public interest**.
- New **Review Committees** (Central and State level, senior-bureaucrat composition) oversee
  interception orders and can **set an order aside and order destruction of intercepted
  copies** if it doesn't meet statutory conditions — a procedural safeguard layer that didn't
  exist in the same form before.
- **Relevance**: interception (live call/message content) is a categorically different, much
  more tightly gated power than the CDR/metadata production summons discussed in §A.1 — a
  hackathon tool should never conflate "we can pull CDRs via a §94 BNSS request" with "we can
  listen to calls," since the latter requires this separate, higher-authority interception-
  order process and is not something any investigating officer can self-authorise.

---

## BNSS/BSA compliance checklist for any evidence-handling hackathon tool

Use this as a literal checklist against any submission that ingests, stores, analyses, or
exports investigative data:

- [ ] **Hashing at ingestion.** Every uploaded artefact (file, video, CDR export, image) gets a
      SHA-256 (or stated algorithm) hash computed and displayed at upload time.
- [ ] **Hash re-verification on export/access.** Re-hash on any export and flag mismatch.
- [ ] **Immutable, append-only audit log.** Who accessed/exported/modified what, when — ideally
      tamper-evident (e.g., hash-chained log entries), not a mutable database row.
- [ ] **BSA §63 certificate as structured data**, not an afterthought PDF: capture Part A
      (device operator: name, designation, how the record was produced) and Part B (expert:
      name, qualification, hash value, hash function) as first-class fields tied to each
      evidence item.
- [ ] **Custody-transfer events explicitly modelled**: seizure → transport → lab intake →
      analysis → storage, each with actor, timestamp, and location — not just a single
      "uploaded by" field.
- [ ] **Separation of original vs working copy** in the data model, even for non-file
      artefacts (e.g., a CDR spreadsheet): never let analysis operations mutate the ingested
      original.
- [ ] **eSakshya-compatible evidence types**: the tool should be able to ingest timestamped
      video + GPS + officer-ID + hash as a first-class record type, since this is now a
      mandatory artefact class under BNSS §105/185.
- [ ] **48-hour / without-delay forwarding awareness**: if the tool touches search-seizure
      workflow at all, it should be aware of (and ideally track/alert on) the BNSS deadline for
      forwarding recordings to the Magistrate.
- [ ] **No live interception claims.** Never imply the tool can access call/message *content*
      without a lawful interception order under the Telecommunications Act, 2023 — only
      metadata obtainable via a §94 BNSS summons.
- [ ] **DPDP hygiene on any citizen-facing surface**: explicit purpose statement, retention
      period, and grievance contact — even though the police-investigative core of the tool
      sits inside the DPDP §17 law-enforcement exemption.
- [ ] **No fabricated/scraped "real" PII in the demo.** Use synthetic or clearly-marked sample
      data only (see Section D below) — presenting real Aadhaar/CDR-shaped data of real
      individuals, even "found online," is itself a legal exposure for the team.
- [ ] **Distinguish "who can get this data" in the UI/pitch**: for every artefact type the tool
      claims to ingest, be ready to state — on demand — which legal instrument a real
      investigator would use to obtain it and roughly how long that takes (this document's
      table is exactly that answer key).

---

## C. Institutional plumbing — and can an outside team access it?

| System | What it is | Outside team access? |
|---|---|---|
| **I4C** (and its verticals: TAU, National Cybercrime Forensic Lab, CyTrain, Joint Cybercrime Investigation Facilitation Team, ecosystem-management vertical) | MHA's national cybercrime coordination body | **No** — internal LEA infrastructure; engagement only via a formal police/MHA partnership, not a public API |
| **CCPWC Scheme** | I4C funding for state forensic-training labs | **No** direct access — a funding/capacity scheme, not a data system |
| **Samanvaya Platform** | MIS/data-repository/coordination platform for LEAs to share cybercrime data | **No** — LEA-only |
| **Pratibimb Portal** | Geospatial mapping of criminals/crime infrastructure for jurisdictional officers | **No** — LEA-only |
| **CCTNS** | Pan-India police-station crime-records network | **No** — police-only; some anonymised aggregate stats surface via NCRB's public "Crime in India" reports |
| **ICJS / ICJS 2.0** | Interlinks CCTNS (police) + e-Courts + e-Prisons + e-Forensics + e-Prosecution | **No** — inter-agency backend, not public |
| **NAFIS** | National fingerprint database (NCRB) | **No** — LEA-only; issues National Fingerprint Numbers to arrestees |
| **NIDAAN** | Arrested narco-offender database (NCRB) | **No** — LEA-only |
| **NDSO / ITSSO** | Sexual-offender database / POCSO investigation-tracking | **No** — LEA/judiciary-only |
| **e-Courts / NJDG** | Case-status, orders, hearings, cause-lists across courts | **Yes, partially** — NJDG/e-Courts case-metadata is genuinely public via the eCourts services and (per this research) third-party API wrappers exist (e.g., eCourtsIndia API) built on the same public data feed. This is the **one system in this table an outside student team can legitimately integrate with today**, useful for the "Unified Legal & Government Intelligence Platform" (Category 2, PS 4) and "Real-Time Data Breach Alert" ideas. |
| **CEIR / Sanchar Saathi (citizen layer: TAFCOP, Chakshu, KYM, RICWIN, CNAP)** | DoT citizen self-service telecom-security tools | **Yes, for the citizen-facing single-lookup pattern** (own-IMEI block, own-ID SIM check, report-a-call) — this is intentionally public. **Bulk/historical/cross-subscriber CEIR queries remain LEA-only.** |
| **NCRB "Crime in India" reports / open data** | Annual aggregate crime statistics | **Yes** — published reports/PDFs are public and citable. |
| **NPCI / DPIP / bank data** | Payment-rail transaction data, mule-signal sharing | **No** — regulator/bank/NPCI-only; DPIP is a bank-to-bank/regulator network, not third-party accessible. |
| **1930/NCRP/CFCFRMS** | Citizen fraud-reporting and freeze pipeline | **Citizen can file a report** (that's the point of the portal); the backend coordination dashboard is **LEA-only**. |

**Bottom line for the pitch deck**: of everything in Category 1's "Tool Design Guidelines"
upload-file list (FIR, CAF, CDR, ILD Gateway, 1930 ticket, IPDR, IP information, CEIR portal,
etc.), the **only one with a genuinely open public data surface** an outside team can integrate
today is e-Courts/NJDG case-metadata, plus the narrow citizen-self-service slice of Sanchar
Saathi. Everything else requires either (a) a formal police-partner data-sharing arrangement,
or (b) synthetic/sample data for the demo — which is the expected, legitimate path (see
Section D).

---

## D. How to demo legitimately without real data

None of the artefacts the problem statements name (FIR, CAF, CDR, ILD Gateway, 1930 ticket,
IPDR, CEIR trace history) are legitimately obtainable by a student/outside team in bulk or with
real subject identities. The legitimate paths, in order of preference:

1. **Synthetic data generation matching the real schema.** Build a generator that produces
   CDR/IPDR/CAF-shaped records using the **field structures documented in Section A above**
   (A/B number, IMEI/IMSI, Cell ID, timestamps for CDR; IP:port pairs and session metadata for
   IPDR; name/DOB/ID-type/photo-placeholder for CAF) but with **fabricated, clearly-fictional**
   subject data — fake names, non-issuable phone-number ranges (India reserves certain ranges
   for fictional/test use in media — use those conventions), fake but well-formed IMEI/IMSI
   check-digit-valid values, and placeholder photos (never real people's photos, even stock
   photos of real people, without clear synthetic/AI-generated or explicitly-licensed-dummy
   framing). This is by far the strongest demo path because it forces you to actually understand
   and implement the real schema — which itself is the credibility signal.
2. **Publicly published sample formats.** Where a regulator has published an actual sample
   format (DoT/TRAI IPDR-parameter circulars, licence-condition schedules, NCRB's published
   "Crime in India" data tables, the CDR/IPDR field lists reconstructed in this document from
   corroborated secondary sources), build your ingestion parser against **that exact
   structure** and cite it. This lets you honestly say "our parser matches the DoT-mandated
   IPDR schema" rather than an invented one.
3. **Anonymised/aggregated public statistics as backdrop, not as row-level records.** NCRB's
   annual "Crime in India" reports, published cybercrime-loss/recovery figures (as cited in
   §A.5), and DoT's published Chakshu/ASTR impact numbers are legitimate to use for dashboard
   context, trend charts, or model-validation targets — they are aggregate/public, not personal
   data.
4. **Public e-Courts/NJDG data** — the one genuinely live, real, public dataset available (see
   Section C) — is fair game for anything that benefits from real case-metadata (the
   "Unified Legal & Government Intelligence Platform" and "Real-Time Data Breach Alert" PS
   ideas especially).
5. **Never** scrape, purchase, or otherwise obtain real citizens' CDR/CAF/bank data, even
   "leaked" or "for research" datasets circulating online — beyond being unethical, knowingly
   possessing/processing such data is itself a legal exposure (IT Act §66C/66D-adjacent
   territory, DPDP exposure outside the LEA exemption since a student team is not a law-
   enforcement agency) and would disqualify a team from a **police-run** hackathon on sight if
   discovered.

**How to phrase the "integration path" slide so police judges see you understand the real
pipeline.** Do not say "the system integrates with CDR/CAF/CEIR databases." Instead, structure
the slide as three explicit rows per artefact: **(a) legal instrument** used to obtain it in
production (cite the section, e.g., "§94 BNSS production summons to TSP nodal officer"),
**(b) typical turnaround** in production (cite this document's table), **(c) what we
demonstrate today** ("synthetic CDR generated to the field structure above, or public
NCRB/DoT aggregate figures"). This structure is itself the differentiator — it shows the
judges you know the difference between a prototype and a production integration, and exactly
what stands between them, which is precisely the maturity signal a real Cyber Crime Branch
officer is trained to look for.

---

## Sources

- [Section 63 of Bharatiya Sakshya Adhiniyam | Naavi.org](https://www.naavi.org/wp/section-63-of-bharatiya-sakshya-adhiniyam/)
- [Section 63: Bhartiya Sakshya Adhiniyam & Digital Evidence — RK Dewan](https://www.rkdewan.com/articles/electronic-records-now-governed-by-section-63-of-the-bhartiya-sakshya-adhiniyam-2023/)
- [Section 63 BSA 2023: Admissibility of Electronic Evidence — KSandK](https://ksandk.com/litigation/section-63-bharatiya-sakshya-adhiniyam-2023/)
- [Electronic Evidence Under BSA 2023 — Bhatt & Joshi Associates](https://bhattandjoshiassociates.com/electronic-evidence-under-bsa-2023-section-63-certificate-requirements-supreme-court-interpretation/)
- [Digital Evidence In Criminal Trials — LawBeat](https://lawbeat.in/articles/digital-evidence-in-criminal-trials-section-63-of-the-bharatiya-sakshya-adhiniyam-hash-values-the-new-rules-of-admissibility-1618510)
- [PRS India — The Bharatiya Sakshya Bill, 2023 billtrack](https://prsindia.org/billtrack/the-bharatiya-sakshya-bill-2023)
- [eSakshya (e-evidence) mobile application — NIC informatics.nic.in](https://informatics.nic.in/files/websites/october-2024/eSakshya.php)
- [Electronic recording of search and seizure processes is mandatory now — Nyaaya](https://nyaaya.org/nyaaya-weekly/electronic-recording-of-search-and-seizure-processes-is-mandatory-now/)
- [Recording Of Search And Seizure Through Audio-Video Electronic Means Under Section 105 BNSS — LiveLaw](https://www.livelaw.in/articles/recording-of-search-and-seizure-electronic-mode-section-105-bnss-281366)
- [Section 176(3), BNSS 2023 — Mandatory Forensic Visit — Budding Forensic Expert](https://www.buddingforensicexpert.in/2026/07/section-176-3-bnss-2023-mandatory-forensic-visit-to-the-crime-scene.html)
- [What new criminal law says about forensic evidence — ThePrint](https://theprint.in/judiciary/what-new-criminal-law-says-about-forensic-evidence-how-this-could-put-immense-stress-on-labs/2164108/)
- [BPRD handbook — collecting forensic evidence in serious crimes (PDF)](https://bprd.nic.in/uploads/pdf/202401261016313612262Forensic.pdf)
- [2022 CERT-In Directions on Reporting Cyber Incidents — Lexology](https://www.lexology.com/library/detail.aspx?g=5eae7307-664d-484e-8a58-f50bc24bb4d2)
- [CERT-In Directions on Cybersecurity 2022 — Tech Law Forum @ NALSAR](https://techlawforum.nalsar.ac.in/cert-in-directions-on-cybersecurity-2022-for-the-better-or-worse/)
- [2022 CERT-In Directions PDF — Trilegal](https://trilegal.com/wp-content/uploads/2022/05/2022-CERT-In-Directions-on-Reporting-Cyber-Incidents-1.pdf)
- [India's data protection law allows government to exempt itself — MediaNama](https://www.medianama.com/2023/08/223-dpdp-bill-2023-government-exemptions-3/)
- [DPDP Act Section 17 with interpretation — dpdpa.com](https://www.dpdpa.com/dpdpa2023/chapter-4/section17.html)
- [DPDP Rules Hold Off Personal Data From Pvt Firms, But Not Govt — MediaNama](https://www.medianama.com/2025/11/223-dpdp-framework-personal-data-companies-door-open-for-state/)
- [New Rules For Lawful Interception Of Telecommunications — Mondaq](https://www.mondaq.com/india/telecoms-mobile-cable-communications/1516996/new-rules-for-lawful-interception-of-telecommunications)
- [Decoding Interception: A Closer Look At The New Telecommunication Rules 2024 — Mondaq](https://www.mondaq.com/india/telecoms-mobile-cable-communications/1564748/decoding-interception-a-closer-look-at-the-new-telecommunication-rules-2024)
- [Guest Post: Access to call records under Section 91, CrPC — CCG Blog](https://ccgnludelhi.wordpress.com/2022/11/28/guest-post-access-to-call-records-under-section-91-crpc/)
- [Call Detail Records (CDRs) — Dr. Abhishek Gandhi](https://advocategandhi.com/call-detail-records-cdrs-the-digital-footprints-of-telecommunication-legal-insights-forensic-use-and-privacy-concerns/)
- [Application for Preserve of Call Details Record 91 CrPC or 94 BNSS — Scribd](https://www.scribd.com/document/793892637/Application-for-Preserve-of-Call-Details-Record-91-CrPC-or-94-BNSS)
- [IPDR Solution — Enabling ISPs for DoT/TRAI Compliance — Trisul Network Analytics](https://trisul.org/blog/ipdr-solution-enabling-isps-for-dot-trai-compliance/)
- [IPDR DoT Compliance in 2026 — Trisul Network Analytics](https://www.trisul.org/blog/ipdr-dot-compliance-in-2026-same-mandate-different-reality/)
- [DoT — Compliance of revised parameters for IPDR and SYS of NAT (circular page)](https://dot.gov.in/dataservices/compliance-revised-parameters-ipdr-internet-detail-protocol-record-and-sys-nat-network)
- [New SIM Card Rules — Vi Blog](https://www.myvi.in/blog/new-sim-card-rules)
- [KYC in Telecom: DoT Rules, SIM Issuance — HyperVerge](https://hyperverge.co/blog/kyc-in-telecom/)
- [5 new SIM card rules by DoT amid rising scams — Digit](https://www.digit.in/news/telecom/here-are-5-new-sim-card-rules-implemented-by-dot-amid-rising-scams-and-frauds.html)
- [Police verification of SIM dealers mandatory, bulk connections discontinued — Deccan Herald](https://www.deccanherald.com/india/police-verification-of-sim-dealers-mandatory-bulk-connections-discontinued-to-curb-frauds-ashwini-vaishnaw-2650964)
- [SIM Box Fraud in Telecom — Subex](https://www.subex.com/blog/simbox-fraud-challenges-and-ai-powered-solutions-for-telecom-operators/)
- [International Calls Disguised as Local Numbers — The420.in](https://the420.in/meerut-police-dot-voip-sim-box-fraud/)
- [SIM Box and eSIM Fraud in Telecom — Neuralt](https://www.neuralt.com/news-insights/telecom-interconnect-bypass-fraud-detecting-sim-box-and-esim-threats)
- [International Incoming Spoofed Calls Prevention System launched — News on Air](https://www.newsonair.gov.in/international-incoming-spoofed-calls-prevention-system-launched)
- [1930 cyber fraud helpline / golden hour — the420.in (UP CFMC)](https://the420.in/uttar-pradesh-cyber-fraud-recovery-1930-cfmc-golden-hour/)
- [Cybercrime complaints easy to file, justice takes longer — Business Standard](https://www.business-standard.com/technology/tech-news/cybercrime-complaints-firs-fund-recovery-investigation-delays-126062500294_1.html)
- [Sanchar Saathi Portal citizen services (sancharsaathi.gov.in)](https://sancharsaathi.gov.in/)
- [CEIR User Direct Request Blocking Form](https://www.ceir.gov.in/Request/CeirUserBlockRequestDirect.jsp)
- [ASTR — C-DoT product page](https://cdot.in/cdotweb/web/product_page.php?lang=en&catId=4&pId=67)
- [ASTR: AI, facial recognition-based tool to detect phone frauds — Vajiram & Ravi](https://vajiramandravi.com/current-affairs/astr-ai-facial-recognition-based-tool-to-detect-phone-frauds/)
- [India's Biometric AI Disconnects 50 Million Fraudulent Mobile Connections — Tech Times](https://www.techtimes.com/articles/320395/20260714/indias-biometric-ai-disconnects-50-million-fraudulent-mobile-connections.htm)
- [Why is DoT using facial recognition on SIM users? — MediaNama](https://www.medianama.com/2023/01/223-explained-astr-sim-facial-recognition-2/)
- [OpenCelliD — Wikipedia](https://en.wikipedia.org/wiki/OpenCelliD)
- [What is Cell ID (CID)? Guide to CGI, MCC, MNC & LAC — FindCellID](https://findcellid.com/blog/what-is-cell-id-cgi)
- [I4C — IAS Gyan](https://www.iasgyan.in/daily-current-affairs/i4c)
- [Cyber Security and Financial Fraud Combat — PIB](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2205201&reg=3&lang=1)
- [I4C Grokipedia entry](https://grokipedia.com/page/Indian_Cyber_Crime_Coordination_Centre)
- [Inter-Operable Criminal Justice System (ICJS) — MHA](https://www.mha.gov.in/en/commoncontent/inter-operable-criminal-justice-system-icjs)
- [ICJS/NCRB administration — MHA](https://www.mha.gov.in/en/commoncontent/icjsncrb-administration)
- [NIDAAN portal operational — Business Standard](https://www.business-standard.com/article/current-affairs/india-s-first-portal-on-arrested-narco-offenders-nidaan-gets-operational-122081700498_1.html)
- [Crime and Criminal Tracking Network & Systems (CCTNS) — Digital Police](https://digitalpolice.gov.in/DigitalPolice/AboutUs)
- [National Judicial Data Grid — Wikipedia](https://en.wikipedia.org/wiki/National_Judicial_Data_Grid)
- [eCourtsIndia API developer guide](https://blogs.ecourtsindia.com/2026/04/16/ecourts-india-api-developer-guide/)
- [National Crime Records Bureau — Wikipedia](https://en.wikipedia.org/wiki/National_Crime_Records_Bureau)
- [Cybercrime in India 2025: 24% Spike, ₹22,495 Crore Lost — Insights on India](https://www.insightsonindia.com/2026/02/21/cybercrime-in-india/)
- [Merchants' bank accounts can't be frozen for UPI payments from fraudsters: Andhra HC — MediaNama](https://www.medianama.com/2026/07/223-merchants-bank-accounts-frozen-upi-payments-fraudsters-andhra-hc/)
- [India's Digital Fraud Network Expands: 524,000 Mule Accounts Flagged — The420.in](https://the420.in/india-mule-accounts-upi-fraud-march-2026-report/)
- [DPIP vs Mule Accounts: How RBI Fights Fraud — Billcut](https://www.billcut.com/blogs/dpip-vs-mule-accounts-how-rbi-fights-fraud/)
- [Why Banks Freeze Accounts Suddenly in India — RTI Wiki](https://righttoinformation.wiki/bank-freeze-cyber-fraud-india)
- [The Information Technology Act, 2000 — indiacode.nic.in (PDF)](https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf)
- [Zero FIR & e-FIR Under BNSS Section 173 — EBC blog](https://blog.ebcwebstore.com/zero-fir-e-fir-bnss-section-173/)
- [Section 173 of BNSS — Drishti Judiciary](https://www.drishtijudiciary.com/current-affairs/section-173-of-bnss)
- [Time limit to file charge sheet in BNS — LawRato](https://lawrato.com/criminal-legal-advice/time-limit-to-file-charge-sheet-in-bns-75-78-79-111-356-255336)
- [BNSS Timelines: Investigation and Trial Completion Deadlines — JuriGram](https://jurigram.com/advocates/resources/new-laws/bnss-timelines-investigation-trial-completion)
- [Section 63 of BNSS — Form of Summons — ApniLaw](https://www.apnilaw.com/bare-act/bnss/section-63-bharatiya-nagarik-suraksha-sanhitabnss-form-of-summons/)
- [Section 64 of BNSS — Summons How Served — LawZone](https://www.lawzone.in/2026/06/section-64-of-bnss.html)
- [Trial in Absentia — BPRD (PDF)](https://bprd.nic.in/uploads/pdf/202401261019413843190TrialinAbsentia.pdf)
- [How Should Courts Try Proclaimed Offenders? Section 356 BNSS — LiveLaw](https://www.livelaw.in/high-court/allahabad-high-court/allahabad-hc-proclaimed-offenders-trial-in-absentia-procedure-356-bnss-533099)
- [Section 111 of BNS — Organised crime — Testbook](https://testbook.com/judiciary-notes/section-111-bns)
- [BNS Section 113 — Terrorist act — Devgan.in](https://devgan.in/bns/section/113/)
- [A handbook on Bharatiya Nyaya Sanhita, 2023 — BPRD (PDF)](https://bprd.nic.in/uploads/pdf/BNS_English_30-04-2024.pdf)
- [Chain of Custody and Evidence Preservation — Legal Service India](https://www.legalserviceindia.com/Legal-Articles/the-digital-forensic-investigation-process-chain-of-custody-and-evidence-preservation/)
- [The Cornerstone of Digital Evidence: Hash Values — Legal Service India](https://www.legalserviceindia.com/Legal-Articles/cornerstone-of-digital-evidence-ensuring-integrity-with-hash-values/)

---

## Gaps

- **BSA Section 63's exact sub-clause text** could not be verified against the primary
  gazetted Act (indiacode.nic.in blocked automated fetch with HTTP 403 on every attempt this
  session). Corroborated across 5 independent secondary legal-commentary sources with
  consistent detail, but a bare-act check is recommended before quoting sub-clause wording in
  a formal document.
- **Exact BNSS chargesheet/investigation timeline figures** (60/90/180-day framing) came from
  secondary sources that were not fully mutually consistent; only the **2-month sexual-offence
  timeline under Section 193(4)** was corroborated with a clean, specific citation. Treat the
  other day-counts as directionally correct, not citation-ready.
- **Current UASL-mandated CDR retention period** — sources conflict between "6 months" (older
  commentary) and longer windows implied by more recent circulars; could not pin the current
  authoritative figure. **⚠️ UNVERIFIED.**
- **Exact IPDR/NAT-syslog parameter list** per the 2021 DoT circular — the circular's own page
  (dot.gov.in) returned HTTP 403 to automated fetch; the field list in Section A.2 is
  reconstructed from telecom-compliance-vendor documentation describing that circular's intent,
  not the circular's verbatim text.
- **CERT-In's exact reportable-incident category list** was not retrieved in full (search
  results confirmed the 6-hour/180-day headline rules but not the complete enumerated incident
  list); recommend pulling the current cert-in.org.in directions PDF directly if a submission
  needs the full category list.
- **No Gujarat/Ahmedabad-specific procedural variations** are covered here (e.g., any Gujarat
  Police SOPs layered on top of the national BNSS framework) — this document is deliberately
  national-law-focused per the assigned scope; Gujarat-specific institutional detail is covered
  in the companion `01_gujarat_police_structure_and_leadership.md`,
  `02_gujarat_police_existing_tech_and_ai.md`, and `03_gujarat_cybercrime_landscape.md` files
  already in this research folder.
- **DoT's current exact SIM-per-ID cap and its notification number/date** — reported as "9
  nationally, 6 in J&K/NE/Assam" across multiple 2026 consumer-facing sources but the
  underlying DoT notification was not independently pulled; treat as reliable but not
  primary-sourced.
- **CERT-In directions page (cert-in.org.in)** renders as a frameset in automated fetch and did
  not yield readable content this session; anyone needing the primary text should browse it
  manually rather than relying on automated retrieval.

---

## How to demo legitimately without real data

(See full treatment in **Section D** above — repeated here per the requested structure for
quick reference.) In short: **generate synthetic data matching the real field schemas
documented in Section A**, **cite publicly published regulator sample formats where they
exist**, **use only aggregate/public statistics (NCRB, DoT, I4C press figures) for context, not
row-level personal data**, **use the one genuinely open public dataset (e-Courts/NJDG) where
relevant**, and **structure the "integration path" slide as legal-instrument → typical
turnaround → what's demoed today**, for every artefact type claimed. Never obtain, scrape, or
simulate-with-real-identities any actual citizen's CDR/CAF/bank/IMEI data.
