# eSakshya — external LLM research prompts

**Why this exists.** [PS_03_LEGAL_AND_DATA_REALITY.md §B.2](PS_03_LEGAL_AND_DATA_REALITY.md)
establishes that BNSS §105 mandates audio-video recording of every search and seizure, and
that **eSakshya** (NIC) is the official app for it. That kills any plan to build a
seizure-recording app of our own.

**The one question that decides our next phase:** does eSakshya track an exhibit *after*
seizure — malkhana → FSL → court → back — or does it stop at the seizure moment?

- If it **does** track transfers → the custody-handoff PWA is dead, and we pivot to ingesting
  eSakshya artefacts as a first-class evidence type.
- If it **does not** → the gap is real, and the PWA extends our differentiator into the exact
  place Indian custody chains break.

A secondary question of nearly equal weight: **does CCTNS already have a malkhana / property
module?** If it does, our idea isn't new — it's an integration.

I cannot reach eSakshya myself. It is distributed on the police network, not the public
Play Store.

---

## Anti-fabrication rules (embedded in all three prompts)

Of the three external reports collected in June, **two contained fabrications** that survived
confident presentation — invented evaluation criteria attributed to an unrelated Delhi Police
PDF, two 10× rupee errors, and a case relocated to the wrong city in contradiction of its own
cited source. See [92_EXTERNAL_LLM_MERGED_FINDINGS.md](92_EXTERNAL_LLM_MERGED_FINDINGS.md).

Every prompt below therefore demands: a URL per claim, an explicit `NOT FOUND` where the
answer isn't there, and a hard separation between what a source states and what the model is
inferring. Anything arriving without a source gets discarded on merge.

---

## Division of labour (non-overlapping)

| Engine | Territory | Why |
|---|---|---|
| **Grok** | X/Twitter — officer and journalist posts, rollout announcements, field complaints | Live X access; the only place candid practitioner opinion exists |
| **ChatGPT** | Documents — NIC/MHA/NCRB circulars, SOPs, manuals, tenders, judgments | Deep-research over PDFs and government sites |
| **Gemini** | Video and app listings — YouTube training walkthroughs, Play Store, screenshots | Google Search grounding + native YouTube comprehension |

Grok gets opinion, ChatGPT gets paper, Gemini gets pictures. No engine is asked for what
another is asked for.

---

## PROMPT 1 — GROK

```
You have live access to X/Twitter. I need field-level intelligence on the Indian police
app "eSakshya" (also written "e-Sakshya", Hindi "ई-साक्ष्य"), built by NIC to satisfy the
BNSS 2023 Section 105 mandate for audio-video recording of search and seizure.

Search X from June 2024 (BNSS came into force 1 July 2024) through today. Cover posts in
English, Hindi and Gujarati.

FIND:

1. Posts from verified police handles announcing or reporting on eSakshya rollout —
   especially @GujaratPolice, @AhmedabadPolice, Gujarat DGP/Commissioner handles, district
   SP handles, and any Gujarat Police cyber cell handle. Quote the post, give the handle,
   date and link.

2. Posts by serving or retired police officers, IPS officers, or police associations
   describing what using the app is actually like. I want friction: upload failures,
   the reported ~4-minute clip cap, connectivity problems at rural scenes, storage,
   battery, login/OTP trouble, court rejection, duplicate data entry. Candid complaints
   are more valuable to me than official announcements.

3. Any post containing a SCREENSHOT or PHOTO of the eSakshya app interface, or of a
   training session showing the screens. Describe exactly what is visible: menu items,
   button labels, form fields, tabs. This is the single most useful thing you can find.

4. THE KEY QUESTION — any post, from anyone, indicating whether eSakshya handles what
   happens to seized property AFTER the seizure is recorded: transfer to the malkhana
   (police evidence room), dispatch to an FSL, production in court, return. Does any post
   mention custody transfer, handover, exhibit tracking, malkhana entry, or property
   register inside eSakshya? If nobody discusses this, say so explicitly — that absence
   is itself an answer I need.

5. Journalists, legal commentators and lawyers on X discussing eSakshya's evidentiary
   weight — has a court accepted or rejected material from it? Any defence-side criticism?

6. Any numbers cited in posts: uploads recorded, districts live, officers trained,
   states deployed. Attribute each number to its post.

RULES:
- Every claim gets a direct link to the specific post. No link, no claim.
- Where you find nothing on a numbered item, write "NOT FOUND ON X" under that heading.
  Do not substitute general knowledge about BNSS or Indian policing for actual posts.
- Keep quotes verbatim; translate Hindi/Gujarati but include the original.
- Clearly separate "a post says X" from "I infer X". Label inferences as inference.
- Do not describe the app's features from memory or from news articles — I am asking you
  specifically for what X users have said and shown.
```

---

## PROMPT 2 — CHATGPT

```
Act as a research analyst. I need the documentary and legal record on the Indian
government app "eSakshya" / "e-Sakshya", developed by NIC for compliance with Section 105
of the Bharatiya Nagarik Suraksha Sanhita 2023 (mandatory audio-video recording of search
and seizure). Use web search and read PDFs directly.

DELIVER, under these exact headings:

A. OFFICIAL DOCUMENTATION
   Locate and cite primary documents: NIC or MHA circulars, standard operating procedures,
   user manuals, training material, NCRB or BPR&D publications, state police headquarters
   orders, PIB releases. Give the document title, issuing authority, date and URL. Quote
   the passages that describe what the app does.

B. TECHNICAL BEHAVIOUR — what the app actually produces
   - What artefact does an officer create? Video container and codec, per-clip duration
     limit, clips per FIR, still photographs, audio.
   - What metadata is captured and bound to it: GPS, timestamp, officer ID, FIR number,
     device identifiers, the reported verification selfie.
   - CRITICAL: does eSakshya compute a HASH of the recording, and if so which algorithm?
     Is that hash shown to the officer, printed, or forwarded to the court?
   - Where is the file stored and uploaded to — which server, which cloud, whose custody?
   - Does the app or its backend generate a Bharatiya Sakshya Adhiniyam Section 63
     certificate, or any certificate at all?

C. THE DECISIVE QUESTION — post-seizure custody
   Does eSakshya track a seized item AFTER the recording is made? Specifically: transfer
   into the malkhana / police property room, dispatch to a Forensic Science Laboratory,
   production before a magistrate, and return or disposal. Is there any custody-transfer,
   handover, or exhibit-movement function documented anywhere? Answer yes or no with
   citation. If the documentation is silent, say "DOCUMENTATION SILENT" — do not guess.

D. DOES CCTNS ALREADY DO THIS?
   Separately from eSakshya: does the Crime and Criminal Tracking Network & Systems
   (CCTNS), or the Interoperable Criminal Justice System (ICJS), already include a
   malkhana / property / case-property management module that records custody transfers of
   seized items? Cite the module name and its documentation. Also check whether any Indian
   state has separately procured or built a malkhana management system — look for state
   police tenders and RFPs. This determines whether an evidence-custody tracker is a new
   idea or an existing one.

E. INTEGRATION SURFACE
   Does eSakshya expose any API? How does it connect to CCTNS/ICJS? Is there any documented
   route by which a third-party forensic tool could receive or verify an eSakshya artefact?
   If integration is closed to the police network only, state that plainly.

F. GUJARAT DEPLOYMENT
   Is eSakshya live in Gujarat? Since when, in which districts or commissionerates, with
   what usage figures? Cite Gujarat government or Gujarat Police sources specifically.

G. JUDICIAL TREATMENT
   Search Indian Kanoon, SCC Online, LiveLaw, Bar and Bench for any reported judgment or
   order that mentions eSakshya or BNSS Section 105 audio-video recording. Has a court
   ruled on the consequence of failing to record, or on the admissibility of a recording?
   Cite case name, court, date.

RULES:
- Every factual claim carries a URL. Claims without sources will be discarded.
- Where you cannot find something, write "NOT FOUND" under that heading and move on. Do
  not fill a gap with a plausible-sounding answer; an honest gap is more useful to me than
  a confident guess, and I will be checking your citations.
- Quote statutory text verbatim from indiacode.nic.in where you cite the law.
- Do not conflate eSakshya with unrelated systems of similar name (e-Sakshya court
  digitisation projects, Sakshi/Sakshya NGO programmes, the eCourts eSakshya video
  conferencing facility). If you find a name collision, flag it — I need to know it exists.
- State separately, at the end, which of your findings you are least confident in and why.
```

---

## PROMPT 3 — GEMINI

```
Use Google Search grounding and your ability to analyse YouTube videos. Subject: the
Indian police mobile application "eSakshya" / "e-Sakshya" / "ई-साक्ष्य", built by NIC for
BNSS 2023 Section 105 compliance (audio-video recording of search and seizure).

I want to know what this app LOOKS LIKE and what its screens DO. Documentation and news
coverage are being gathered elsewhere — do not summarise news articles or the law.

TASKS:

1. YOUTUBE — find police training videos, demonstrations, or walkthroughs of eSakshya.
   Search in English, Hindi and Gujarati ("eSakshya app training", "ई-साक्ष्य ऐप",
   "eSakshya कैसे उपयोग करें", "eSakshya demo", plus state police training channels).
   For each video found: give the title, channel, date, URL, and then WATCH IT and
   describe, in order, every screen shown — the exact menu items, button labels, form
   fields, dropdown options and tabs visible on each. Transcribe any on-screen text.
   This screen inventory is the most valuable output of this entire prompt.

2. THE QUESTION I MOST NEED ANSWERED — in any video, screenshot or app listing you find,
   is there any screen, menu item, button or field relating to what happens to seized
   property AFTER recording? Look specifically for anything labelled: custody, chain of
   custody, transfer, handover, malkhana, property, exhibit, FSL, forwarding, disposal, or
   their Hindi/Gujarati equivalents (मालखाना, अभिरक्षा, हस्तांतरण). Report exactly which
   of these appear and which do not. If the app's menu contains only recording and upload
   functions, say that explicitly and list the full menu as evidence.

3. APP LISTING — locate eSakshya on Google Play, APKPure, APKMirror or any APK mirror.
   Report: exact package name, developer name, current version, last update date, download
   size, install count, requested Android permissions, and the full listing description.
   Reproduce every store screenshot and describe what each shows. If it is not publicly
   listed anywhere, state that clearly and say where you looked — that fact matters to me.

4. IMAGE SEARCH — find photographs and screenshots of the app in use: training sessions,
   press photos of officers using it at scenes, government presentation slides, PDFs of
   training decks. Describe the interface visible in each and link the source.

5. STATE TRAINING MATERIAL — find any police training presentation, PDF or slide deck
   about eSakshya that Google has indexed, from any state, and describe its contents
   screen by screen. Gujarat material is most valuable; any state is useful.

RULES:
- Give a URL for everything. If you did not open it, do not report it.
- Where you find nothing for a numbered task, write "NOT FOUND" and state what search
  terms you tried. A documented absence is a useful result; an invented feature list is
  worse than useless to me and I will be verifying against other sources.
- Describe only what is actually visible in a video, screenshot or listing. Do not
  reconstruct the interface from your general knowledge of what such an app would contain,
  and do not merge features from other police apps. If you are describing something you
  did not see, label it clearly as inference.
- If videos are in Hindi or Gujarati, translate the narration but note the original
  language and give timestamps for key moments.
```

---

## On merge

Discard anything without a working source link — that rule caught every fabrication last
time. Where the three engines disagree on whether custody transfer exists in the app,
Gemini's screen inventory outranks ChatGPT's documentation, which outranks Grok's posts:
what the menu actually contains beats what a manual claims beats what someone remembers.

If all three return NOT FOUND on the custody question, treat that as weak evidence the
function does not exist, not proof — and note that a single phone call to anyone who has
used the app still outranks all three.
