# 141 — What's actually state of the art, and what's buildable in days

Research pass for NetForensiq (KANAD S.H.I.E.L.D. 2026, PS#8). Question: what
published 2023–2026 work would a judge recognise as genuinely current, and
can be built offline in Python/Django + scapy + scikit-learn in a few days —
without duplicating what `research/SPEC_02_DETECTION_ALGORITHMS.md` and
`research/120_OBJECTIVES_COMPLIANCE.md` already document as built.

**Verification method**: every citation below was fetched directly (arXiv
abstract/HTML page or a search result page quoting the abstract) in this
session, not recalled from training. Where a fetch failed or returned only a
summary rather than the primary text, that is stated. Two papers surfaced by
search were checked and are flagged as **not usable** — one withdrawn, one of
unclear rigor — rather than silently omitted, because a judge who checks a
citation and finds it retracted is worse than a shorter list.

---

## Ranked shortlist

### 1. Conformal prediction for a testifiable, calibrated error rate — HIGHEST forensic defensibility

**Theory (solid, peer-reviewed, the citation to lead with):**
Angelopoulos, Bates, Fisch, Lei, Schuster, **"Conformal Risk Control,"** ICLR
2024. https://proceedings.iclr.cc/paper_files/paper/2024/hash/f3549ef9b5ff520a7e41ff3cc306ab2b-Abstract-Conference.html
— VERIFIED (fetched proceedings page). Generalises split conformal
prediction to control the expected value of any monotone loss (e.g. false
negative rate), with a coverage guarantee tight to O(1/n).

**Applied illustration (recent, unverified rigor — cite with a caveat):**
Michel A. Youssef, **"CALIBURN: Operationally Calibrated Streaming Intrusion
Detection with Regime-Dependent Conformal Risk Control,"** arXiv:2605.24696,
v1 23 May 2026 / v2 25 Jun 2026. https://arxiv.org/html/2605.24696 —
VERIFIED as an existing arXiv posting, but **single-author, no stated venue,
not peer-reviewed** — treat as "someone built this and posted numbers," not
as validated science. Reports AUC-PR 0.943 in a rare-attack regime (5.2%
prevalence, LITNET-2020), tested also on CICIDS2017 (22%) and UNSW-NB15
(64%); claims a 30% Brier-score reduction from isotonic calibration.

**Core idea in 3 sentences.** Conformal prediction wraps any existing
classifier or anomaly score with a distribution-free post-processing step
that converts a raw score into a calibrated statement of the form "this flow
is anomalous, and on held-out calibration data this method's false-positive
rate is bounded by α with probability ≥ 1−δ" — a guarantee that holds
regardless of the underlying model's correctness. Conformal *risk* control
(the ICLR 2024 generalisation) extends this from simple coverage to
bounding any monotone risk, e.g. false-negative rate, which is the number an
investigator actually cares about not missing. Unlike an IsolationForest
anomaly score, the output is not "−0.62"; it is "flagged at a threshold
calibrated to keep this system's false-positive rate at or below the number
we can name."

**What it concretely adds to NetForensiq.** `capture/anomaly.py`
(`ANOMALY_STATISTICAL`) currently caps IsolationForest output at MEDIUM
severity specifically because a raw isolation score "cannot be testified
to" (per SPEC_02 §7 and 120's own text). Conformal calibration is the
mechanism that would let that cap be lifted on principled grounds: instead
of "capped at MEDIUM because we distrust the score," the finding could read
"this detector's false-positive rate is calibrated to ≤5% on this capture's
held-out flows" — a sentence an investigator, and eventually a magistrate,
can be handed. This is the single most direct answer to the research
prompt's framing: *"a detection that states a calibrated error rate is
testifiable, one that states a score is not."*

**Buildable-in-days.** Yes. `mapie` (Model Agnostic Prediction Interval
Estimator) is a real, actively maintained, scikit-learn-compatible Python
library implementing exactly this (split conformal, conformal risk control
variants). It wraps `IsolationForest` output directly — no new model
architecture needed, just a calibration split held out from the fitting
data and a threshold computed from it. Fully offline: no external API, no
network calibration data required beyond the capture itself (though a
larger reference calibration set, e.g. from the existing synthetic
generator, would make the guarantee less capture-dependent — see catch
below).

**The honest catch.** Conformal guarantees are only as good as the
exchangeability assumption between calibration and test data — a capture
that is *entirely* the incident being investigated (SPEC_02's own stated
IsolationForest limitation: "if the whole capture is malicious, nothing in
it looks unusual") breaks this the same way it breaks IsolationForest
itself; conformal calibration bounds the *false-positive* rate, it does not
manufacture recall. CALIBURN's own reported numbers are on CICIDS2017/
UNSW-NB15/LITNET-2020 — CICIDS2017 is exactly the kind of synthetic,
methodologically-critiqued benchmark SPEC_02 §8 already flags via McHugh
2000 and Tavallaee et al. 2009. In court: the calibrated bound is a
statement about the calibration set's distribution, and a competent
cross-examiner's next question is "calibrated against what traffic, and
does this capture resemble it" — which is answerable, but must be answered,
not glossed over. Still the strongest defensibility story on this list
because it is the only one that produces a *number with a proof*, not a
model that is merely "explained."

---

### 2. MITRE ATT&CK auto-mapping — closes a gap 120_OBJECTIVES_COMPLIANCE.md names explicitly

**Methodology reference (peer-reviewed, real venue):**
Yashovardhan Sharma, Simon Birnbach, Ivan Martinovic, **"RADAR: A TTP-based
Extensible, Explainable, and Effective System for Network Traffic Analysis
and Malware Detection,"** Proceedings of the 2023 European Interdisciplinary
Cybersecurity Conference (EICC '23), DOI 10.1145/3590777.3590804. arXiv:2212.03793
(submitted 7 Dec 2022, revised 13 Apr 2023). https://arxiv.org/abs/2212.03793,
Oxford author repository: https://ora.ox.ac.uk/objects/uuid:39bb43c8-a1a2-4c14-812f-cb9d16d573e5
— VERIFIED title/authors/venue/DOI via ACM (dl.acm.org/doi/10.1145/3590777.3590804)
and Oxford's ORA archive. Two-stage method: extracts MITRE ATT&CK TTPs from
raw network traffic captures, then a **decision tree** (plain, interpretable
— not a black box) distinguishes malicious from benign uses of the same
detected TTP. Evaluated on 2,286,907 samples / 84,792,452 flows — a large,
real corpus, not a toy set, though its exact provenance (proprietary vs.
public) was not confirmed in this session; treat the dataset claim as
**partially verified** (size confirmed via ACM/Oxford listings, composition
not independently re-derived).

**The finding that should shape the implementation choice (2024, directly
on point):**
Nir Daniel, Florian Klaus Kaiser, Shay Giladi, Sapir Sharabi, Raz Moyal,
Shalev Shpolyansky, Andres Murillo, Aviad Elyashar, Rami Puzis, **"Labeling
Network Intrusion Detection System (NIDS) Rules with MITRE ATT&CK
Techniques: Machine Learning vs. Large Language Models,"** arXiv:2412.10978
(submitted 14 Dec 2024); published version at MDPI *Information* 2025,
9(2):23, https://www.mdpi.com/2504-2289/9/2/23 — VERIFIED via arXiv HTML
fetch. Tests three LLMs (ChatGPT, Claude, Gemini) against traditional ML for
mapping 973 Snort rules to ATT&CK techniques. **Finding: traditional ML
consistently outperforms LLMs** on precision, recall and F1 for this task.

**Core idea in 3 sentences.** A network-observable event (a flow, a rule
hit) can be mapped to a specific MITRE ATT&CK technique ID rather than left
as a free-text category, turning "DNS_TUNNEL_LONG_LABEL fired" into
"observed behaviour consistent with T1071.004 (Application Layer Protocol:
DNS)" — the vocabulary a SOC, a CERT-In advisory, and increasingly a court
now expects. RADAR shows this mapping is tractable directly from network
flow features using an interpretable decision tree, not a deep model. The
2024 comparison paper shows, counter to hackathon instinct, that reaching
for an LLM to do this labeling is the *worse* choice on accuracy — which
matters because it means the defensible answer here is also the cheap one.

**What it concretely adds to NetForensiq.** 120_OBJECTIVES_COMPLIANCE.md
lists this exact gap under bonus items: *"Automated attack classification |
🟡 | Findings carry rule, category and severity; **MITRE ATT&CK technique
mapping is the missing piece**."* NetForensiq already has ten rules with
known, fixed semantics (`C2_BEACON_PERIODIC`, `DNS_TUNNEL_LONG_LABEL`,
`EXFIL_VOLUME_ASYMMETRY`, etc.) — this is not the open-ended "classify
arbitrary traffic" problem RADAR solves, it is the much smaller "label ten
known rule outputs" problem the 2024 paper's Snort-rule-labeling task
resembles almost exactly.

**Buildable-in-days.** Yes, and the cheapest item on this list. With only
ten rule types, the defensible implementation is **not** RADAR's ML
pipeline and **not** an LLM — it's a small, hand-curated, explicitly-cited
lookup table (`rule_id → one or more ATT&CK technique IDs`), built by
reading the ATT&CK Enterprise matrix entries for each rule's behaviour
(e.g. `C2_BEACON_PERIODIC → T1071` Application Layer Protocol, `T1573`
Encrypted Channel where applicable; `RECON_PORT_SCAN → T1046` Network
Service Discovery). CISA's own **"Best Practices for MITRE ATT&CK
Mapping"** (https://www.cisa.gov/sites/default/files/publications/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf)
— a primary US-government source, fetched in search results this session
but not independently re-verified page-by-page — gives the methodology for
doing this rigorously (map to behaviour, not to tool name; cite the
technique's own ATT&CK page). No ML training needed at all; RADAR is cited
here to show the *approach* has academic backing if a judge asks "how do
you know your mapping is principled," and the 2024 paper is cited to
pre-empt the obvious "why not just ask an LLM" question with a published
answer: because it measurably performs worse.

**The honest catch.** A ten-entry lookup table is not itself a research
contribution — it is engineering, dressed in a citation. Say that plainly
to a judge rather than oversell it. RADAR's own numbers cannot be quoted as
"NetForensiq's MITRE mapping achieves X% accuracy" because NetForensiq
would not be running RADAR's classifier — the accuracy claim would be
false. The correct, honest framing is: "each rule's ATT&CK mapping is
declared once, by a human, against the technique's own published
definition, and is exactly as reliable as that one-time human judgment" —
which is in fact *more* defensible in court than a learned classifier would
be, since it is fully reproducible and requires no model to re-run.

---

### 3. Multi-stage attack / kill-chain reconstruction from alerts — closes a second named gap

**Grounding method (deterministic, not ML — just outside the 2023–2026
window but the concrete basis for the buildable graph):**
Florian Wilkens, Felix Ortmann, Steffen Haas, Matthias Vallentin (co-creator
of Zeek), Mathias Fischer, **"Multi-Stage Attack Detection via Kill Chain
State Machines,"** arXiv:2103.14628, submitted 26 Mar 2021.
https://arxiv.org/abs/2103.14628 — VERIFIED (fetched). Deterministic state
machine, not trained — synthesises attack-stage graphs directly from
network alert direction and sequencing. Evaluated on CSE-CIC-IDS2018:
reduces up to 446,458 singleton alerts to 700 APT scenario graphs (roughly
three orders of magnitude), and recovers most of an embedded synthetic APT
campaign as a coherent story.

**In-window companion (2024, peer-reviewed):**
Eric Ficke, Raymond M. Bateman, Shouhuai Xu, **"AutoCRAT: Automatic
Cumulative Reconstruction of Alert Trees,"** Proceedings of the 6th
International Conference on Science of Cyber Security (SciSec 2024),
arXiv:2409.10828, submitted 17 Sep 2024. https://arxiv.org/abs/2409.10828
— VERIFIED title/authors/venue/date via fetch. Automatically reconstructs
"alert trees" tracking security events emanating from or leading to a
given host, for incident-response triage and visualisation. Evaluated
against "a real-world dataset" per the abstract; this session's fetch did
not surface the specific numeric results — **flag that figure as
unconfirmed** rather than guess it.

**Broader landscape (survey, for context if a judge probes deeper):**
Agiollo, Bardhi, Palma, Lazzeretti, Bonomi, Kuipers, **"SoK: Harmonizing
Attack Graphs and Intrusion Detection Systems,"** arXiv:2603.08295,
submitted 9 Mar 2026. https://arxiv.org/abs/2603.08295 — VERIFIED (fetched).
Reviews 73 works on combining attack graphs with IDS alerts; finds the
field lacks a unifying framework and most approaches are single-purpose
(attack graphs filtering IDS false positives, or IDS alerts pruning attack
graphs) — useful as evidence NetForensiq's own scope here (alert-driven
graph, not a full formal attack-graph model) is a reasonable, literature-
consistent slice rather than a naive shortcut.

**Core idea in 3 sentences.** A single rule firing on a single host is a
prompt to look; the same host's alerts, correlated across time and
direction, into a *sequence* consistent with the cyber kill chain
(reconnaissance → foothold → lateral movement → exfiltration) is a story
an investigator and a magistrate can both follow. Both papers build this
deterministically from alert metadata already available — timestamps,
source/destination direction, alert type — with no need for host-level
telemetry, which matters because NetForensiq is network-only. The payoff
is alert-volume reduction (Wilkens: three orders of magnitude) that turns
an unreadable finding list into a handful of narratable incidents.

**What it concretely adds to NetForensiq.** `HOST_CORROBORATED` already
does the minimal version of this — flag one address named by ≥3 distinct
rules — but 120_OBJECTIVES_COMPLIANCE.md itself marks the next step as
open: *"Reconstruction of attack scenarios | 🟡 | `HOST_CORROBORATED`
assembles multi-rule host stories; **no explicit kill-chain view**."* A
kill-chain graph would take the existing findings table (already has
`rule_id`, `category`, `severity`, `host`, `timestamp`) and sequence them
by attack-chain stage — e.g. `RECON_PORT_SCAN` → `COVERT_CHANNEL_UNKNOWN_PORT`
→ `EXFIL_VOLUME_ASYMMETRY` on the same host, ordered in time — rendered as
a directed graph alongside the existing `NetworkGraph.jsx` traffic diagram.

**Buildable-in-days.** Yes. No new detection is required — this is a
post-processing pass over findings NetForensiq already produces. `networkx`
for graph construction (already a natural Django/Python dependency), a
kill-chain stage lookup keyed by existing `rule_id`/`category` (reuses the
ATT&CK tactic each technique in item #2 already belongs to — reconnaissance,
initial access, C2, exfiltration are ATT&CK *tactic* names already), and a
frontend graph render reusing the existing `NetworkGraph.jsx` conventions
(explanatory sentence per node, not a bare legend, per 120's stated design
constraint). Fully offline, no external data needed.

**The honest catch.** Wilkens 2021 is technically outside the 2023–2026
window the research brief asked for — cited because it is the concrete,
well-attributed, deterministic method (co-authored by Zeek's creator) that
AutoCRAT (2024, in-window) builds on conceptually; both are cited so the
in-window requirement is satisfied by AutoCRAT while the mechanism is
explained by the paper that actually publishes it clearly. Wilkens' own
evaluation notes the method only *links* alerts already present — a stage
missing from the ruleset entirely (e.g. no lateral-movement rule exists in
NetForensiq today) produces an incomplete chain that looks complete, which
is exactly the kind of silent gap 120_OBJECTIVES_COMPLIANCE.md's own
"orientation" and "speed" post-mortems show this project is careful about
elsewhere — the UI must state explicitly which kill-chain stages have no
corresponding rule, not silently skip them.

---

### 4. SHAP-based explanation upgrade for the anomaly model — validates, doesn't replace, what's already built

**Paper (very recent, unclear peer-review status — read with real caution):**
Jose Luis Vela Alonso, Carmen Pellicer, **"Forensic-Oriented Intrusion
Detection Using Synthetic Network Traffic Data and Explainable Artificial
Intelligence,"** arXiv:2607.00763, submitted 1 Jul 2026.
https://arxiv.org/abs/2607.00763 — VERIFIED as an existing arXiv posting
(fetched); **no venue/conference stated, two authors with no affiliation
surfaced in the fetch, and this is a very recent, not-yet-cited preprint —
treat its numbers as provisional, not as validated science.** Method: keeps
original evidence hash-verified and immutable; trains an XGBoost classifier
exclusively on SDV/CTGAN-synthesised traffic derived from CICIDS2017;
explains it with SHAP TreeExplainer; claims F1-macro 0.96 on CICIDS2017
(vs. 0.97 for a real-data baseline) and cross-dataset checks on UNSW-NB15
and Kitsune.

**Core idea in 3 sentences.** Train on synthetic derivatives of sensitive
network data so the original evidentiary capture never has to be exposed
to a training pipeline, then attach SHAP so every classification decision
comes with a per-feature attribution rather than a bare label. The paper's
own framing — evidence integrity plus explainability together, aimed
explicitly at forensic/ISO-aligned admissibility — is unusually close to
NetForensiq's own stated design philosophy (SPEC_02 §7: "every finding
names the features that made a flow stand out"). It reports the SHAP
attributions stay consistent between synthetic-trained and real-evaluated
instances for several attack classes, which is the specific claim that
would matter if NetForensiq's own synthetic corpus generator is ever
challenged on realism grounds.

**What it concretely adds to NetForensiq.** `capture/anomaly.py` already
produces per-feature signed z-scores (median/MAD-based) for every anomaly
finding — a home-grown, defensible explanation, not a black box. SHAP would
not replace this; it would be the more standard, third-party-recognised
form of the same idea, valuable specifically because "we used SHAP" is a
term a judge or a technical assessor may already know, whereas "signed
robust z-scores against the median" needs explaining from scratch every
time. `shap`'s `KernelExplainer` or the tree-based path (via a surrogate
tree model with similar splits to IsolationForest) can be layered on
without touching the underlying model.

**Buildable-in-days.** Yes, incrementally — `pip install shap`, and it
composes with scikit-learn models with minimal wiring. Full offline;
`SHAP` computes locally, no API calls.

**The honest catch.** This paper's F1 numbers are on **CICIDS2017** — the
exact synthetic/methodologically-critiqued benchmark SPEC_02 §8 already
flags via McHugh (2000) and Tavallaee et al. (2009) as a red flag for
"performance on generated traffic doesn't reliably predict real-network
performance." The paper is aware of this critique in spirit (that's its
whole synthetic-vs-real point) but the underlying dataset is still
CICIDS2017-derived, so its numbers should never be quoted to a judge as
"96% forensic accuracy" — only as "an existing explainability library
composes cleanly with our approach, and independent recent work supports
the general SHAP-for-forensic-IDS direction, with the usual synthetic-
benchmark caveat." Given NetForensiq already has an explanation mechanism
that satisfies the same requirement (feature attribution per finding),
this is a nice-to-have polish item, not a gap-closer — rank it below
items 1–3, which each close a gap 120_OBJECTIVES_COMPLIANCE.md names
explicitly.

---

### 5. JA4+ suite extension (JA4H / JA4L / JA4X) — spec-level, not a paper, but genuinely current practice

**Source**: FoxIO, JA4+ technical specification (same publisher/spec family
already implemented for JA4 in `capture/tls_fingerprint.py`).
https://github.com/FoxIO-LLC/ja4 — same sourcing pattern SPEC_02 §6 already
uses for JA4 itself. **The one academic paper found in this specific space
was checked and should NOT be cited**: Javier Izquierdo, Aygul Zagidullina,
"Applying JEPA-Style Predictive Learning to JA4-Derived Network
Fingerprints," arXiv:2607.08465 — VERIFIED as **withdrawn** (v2, 21 Jul
2026, author's own withdrawal note: "requires substantial revision
following further validation"), no stated institutional affiliation, never
peer-reviewed. Do not use it as a citation; it is listed here only so the
gap is visibly not silently skipped.

**Core idea in 3 sentences.** JA4H fingerprints an HTTP client from
header order, casing and value shape (analogous to JA4 but for the HTTP
layer instead of TLS ClientHello); JA4X fingerprints the X.509 certificate
chain a TLS server presents; JA4L estimates client network proximity from
handshake timing, useful for spotting a sudden path/geography change for
the same fingerprint. All three reuse the exact construction pattern
(concatenate normalised fields, hash, truncate) NetForensiq's JA4 code
already implements for the ClientHello.

**What it concretely adds.** `capture/protocols.py` already does full
HTTP transcript reconstruction, so the header data JA4H needs is already
being parsed — this is largely a formatting/hashing pass over data already
extracted, not a new capability. JA4X gives a certificate-level fingerprint
independent of SNI, useful when a C2 server reuses a self-signed cert
across domains (a genuinely common C2 behaviour the current SNI/JA4-client
view does not directly surface).

**Buildable-in-days.** Yes — lowest-risk item on this list precisely
because it extends code that already exists and works, using the same
verified spec FoxIO publishes for JA4 proper. No new library beyond what's
already in use (hashlib, scapy's existing TLS/X.509 parsing).

**The honest catch.** This is engineering extension, not new research —
say so rather than dressing it up as "state of the art." The only paper
in this exact space is withdrawn and unusable, which is itself worth
saying to a judge who might otherwise ask "what does the literature say
about JA4H specifically" — the honest answer is "very little yet; this is
FoxIO's own spec, independently useful, not yet a research literature."

---

### 6. Not a build item — a citation to justify *not* building an ML encrypted-content classifier

Nimesha Wickramasinghe, Arash Shaghaghi, Gene Tsudik, Sanjay Jha, **"SoK:
Decoding the Enigma of Encrypted Network Traffic Classifiers,"** 2025 IEEE
Symposium on Security and Privacy (S&P), final version 16 May 2025.
arXiv:2503.20093. https://arxiv.org/abs/2503.20093 — VERIFIED title,
authors, venue (a top-tier, highly credible venue — IEEE S&P) via fetch.
Systematises ML-based encrypted-traffic classifiers and finds: most
"encrypted traffic classifiers" were mistakenly evaluated on **unencrypted**
traffic due to stale datasets, and 348 feature-occlusion experiments expose
widespread overfitting in published systems.

**Why this belongs in the shortlist even though nothing gets built from
it.** NetForensiq's existing position (SPEC_02 §6, §7) is metadata-only for
encrypted traffic — JA4, SNI, timing, volume, never attempting to classify
*content* of an encrypted flow with ML. This SoK, from IEEE S&P 2025, is
direct third-party validation that the alternative approach (an ML
classifier claiming to infer things about encrypted payloads) is exactly
where the field's published results are least trustworthy. Citing it to a
judge converts "we didn't build an encrypted-traffic-content classifier"
from a gap into a stated, literature-backed engineering decision — which
is a stronger position than building a classifier that this same paper's
methodology would likely be able to show is overfit.

---

### 7. LLM-assisted, strictly-grounded report drafting — the riskiest item, include only with hard guardrails

**Peer-reviewed grounding:**
Akila Wickramasekara, Frank Breitinger, Mark Scanlon, **"Exploring the
Potential of Large Language Models for Improving Digital Forensic
Investigation Efficiency,"** *Forensic Science International: Digital
Investigation*, Vol. 52, 2025; arXiv:2402.19366 (submitted 29 Feb 2024,
revised 31 Jan 2025). https://arxiv.org/abs/2402.19366 — VERIFIED (fetched;
full abstract retrieved). Literature review, not a built system: identifies
bias, explainability, and resource-intensity as the open obstacles to LLM
use in digital forensics, concludes potential exists "with appropriate
constraints."

**Broader framing (arXiv only, in-window):**
Zhipeng Yin, Zichong Wang, Weifeng Xu, Jun Zhuang, Pallab Mozumder,
Antoinette Smith, Wenbin Zhang, **"Digital Forensics in the Age of Large
Language Models,"** arXiv:2504.02963, submitted 3 Apr 2025.
https://arxiv.org/abs/2504.02963 — VERIFIED (fetched). Explicitly names
"illusion" (hallucination), interpretability and bias as the open
limitations; this session's fetch did not surface a network/packet-
forensics-specific discussion or an offline-deployment discussion — those
claims should not be attributed to this paper without a deeper read.

**Core idea in 3 sentences.** Both papers agree LLMs can plausibly help
with the *labor* of digital forensics — drafting narrative summaries,
triage prioritisation — but neither claims LLM output should ever stand as
evidence itself, and both name hallucination/non-determinism as the open
problem, not a solved one. The only version of "LLM in the loop" that
survives a courtroom is one where every generated sentence is directly
traceable to a specific structured record already in the database, the
model never asked to infer or invent anything not already there, and the
output is explicitly watermarked as unreviewed until a human signs off.
This is close to the retrieval-grounded pattern seen in adjacent work
(e.g. OMNISEC, arXiv:2503.03108, LLM-driven provenance IDS via retrieval-
augmented prompting — surfaced in this session's search but **not
independently fetched/verified**, mentioned only as a pattern reference,
not a citation to rely on).

**What it would concretely add.** `evidence/investigation_report.py`
already generates a findings-by-machine report with "reasoning and
plain-language glosses" per 120_OBJECTIVES_COMPLIANCE.md. A local,
offline LLM (e.g. via `llama.cpp`/Ollama running a small model, no
network call) could draft the connective narrative prose between findings
— strictly retrieval-grounded on the finding records already in the
database — with a hard rule that any sentence not traceable to a specific
`Finding.id` is rejected before it reaches the report.

**Buildable-in-days.** Marginally yes for a narrow version (RAG-style
templated generation over existing structured findings, using a small
local model), but this is the item most likely to consume the whole
remaining time budget if scoped ambitiously, and the one most likely to be
distrusted by a judge who has read a single "AI hallucinated in court"
headline.

**The honest catch — the one to lead with in the pitch, not bury.** Both
cited papers name hallucination and non-determinism as the reason LLM
output cannot itself be evidence; a probabilistic model producing different
text on reruns of the same input directly conflicts with the reproducibility
standard NIST SP 800-86 sets (already cited in SPEC_02 §7 for exactly this
reason). **Recommendation: build this last, if at all, and frame it
explicitly as "drafting assistance for the human-readable narrative
section only, never touching the evidentiary findings table, always
watermarked, always requiring sign-off"** — the same posture
NetForensiq already takes toward the IsolationForest anomaly score
(capped severity, always explained, never sole basis for a claim). If time
is short, skip this one before skipping items 1–3.

---

## Summary table

| # | Technique | Judge impressiveness | Buildability (days) | Forensic defensibility | Gap it closes |
|---|---|---|---|---|---|
| 1 | Conformal prediction / calibrated FP-rate (`mapie`) | High — few teams will have this | Medium-high | **Highest** — the only item producing a proven number | Makes the existing anomaly score testifiable |
| 2 | MITRE ATT&CK mapping (curated table, RADAR/CISA-informed) | High — explicitly named bonus objective | **Highest** — no ML needed | High — fully reproducible, human-attributed | Named gap in obj. 4/8 |
| 3 | Kill-chain graph from existing findings (AutoCRAT/Wilkens-style) | High — visual, narratable | High — post-processing only | High — deterministic | Named gap in obj. 6 |
| 4 | SHAP explanation layer | Medium — judge may already expect this | High | Medium-high — validates, doesn't replace, existing z-scores | Polish, not a gap |
| 5 | JA4H/JA4L/JA4X | Medium — extends known-good work | Highest | High — same spec pattern as shipped JA4 | Extends obj. 2/bonus |
| 6 | SoK citation (don't build ML content classifier) | Low (it's a citation, not a feature) | N/A | High — pre-empts a bad-idea question | Defensive framing only |
| 7 | Grounded LLM narrative drafting | High if it works, high risk if it doesn't | Low-medium | **Lowest** — explicitly flagged non-reproducible by cited papers | Nice-to-have UX, not a gap |

## What was checked and excluded

- **JA4-JEPA** (arXiv:2607.08465) — withdrawn by its own authors, not
  peer-reviewed, no institutional affiliation found. Do not cite.
- **FIRCE** (arXiv:2605.01962) and the "High-Reliability Intrusion
  Detection Algorithm Under Conformal Prediction Framework" / "Kernel
  Methods for Conformal Prediction to Detect Botnets" (both ResearchGate
  listings, not independently fetched/confirmed in this session) — surfaced
  by search as further evidence conformal prediction is an active area for
  intrusion detection, but **not independently verified** here; not relied
  upon for any claim above.
- Provenance-graph systems descending from **NoDoze** (NDSS 2019) and
  **UNICORN** (NDSS 2020) were located and are real, well-cited systems —
  but both require host-level system-call/audit provenance (Linux Audit,
  ETW), which NetForensiq's network-only capture model does not produce.
  Cited in passing above (item 3) only insofar as the *alert-correlation*
  idea transfers; the provenance-graph machinery itself does not apply to
  a packet-forensics tool and is not recommended.
