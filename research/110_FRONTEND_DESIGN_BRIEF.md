# 110 — Design brief for Claude Design

Paste the block between the fences into Claude Design. Everything above and
below it is context for you, not for the tool.

## Why this exists

Screenshots of the current build, taken as all four roles, show three problems:

1. **Every role sees the same screen.** The investigator and viewer dashboards
   are pixel-identical except a name chip in the corner. The viewer is even
   shown an enabled "Run detection" button that the API will refuse. Role
   separation is real, enforced and tested in the backend — and completely
   invisible.
2. **The dashboard opens on packet statistics.** Packets, Flows, DNS queries,
   Flagged flows. A senior officer reading that screen for ten seconds learns
   nothing about what the tool is for.
3. **No case context anywhere.** Nothing on screen names the exhibit, the FIR,
   the seizure, or the custody state. It reads as a network monitoring console,
   which is what it looks like, rather than an evidence tool, which is what it
   is.

## Standards it should visibly meet

- **GIGW 3.0** — NIC, with CERT-In and STQC. 88 mandatory checkpoints across
  Quality, Accessibility, Cybersecurity and Lifecycle Management; takes
  **WCAG 2.1 AA** as its accessibility baseline. Applies to central, state,
  district and local government sites and apps.
  <https://guidelines.india.gov.in/scope-and-objective/>
- **Classification banner** — the standard pattern for high-assurance and
  air-gapped systems: a persistent bar stating the handling level, repeated at
  top and bottom when the page scrolls, so the level is never off-screen.
  Documented as a component in PatternFly.
  <https://pf3.patternfly.org/v3/pattern-library/communication/classification-banner/>

Whether GIGW binds an internal analyst tool rather than a citizen service is
unresolved — so the interface should *meet* WCAG 2.1 AA (it already passes a
contrast test on every build) without *claiming* GIGW compliance.

---

## The prompt

```
Design the interface for NetForensiq, a network-packet forensics platform used
by Indian police cyber-crime investigators on air-gapped workstations. It reads
a seized packet capture (a .pcap file), runs nine detection rules over it, and
produces a certificate under section 63(4) of the Bharatiya Sakshya Adhiniyam
2023 so the findings are admissible in an Indian court.

Produce a multi-artboard canvas covering the screens listed below.

WHO USES IT, AND WHY THE SCREENS MUST DIFFER

Four roles, and the interface must make the current role obvious at a glance
without the user reading a name:
  - Investigating Officer — runs detection, triages findings, seals exhibits.
  - FSL Expert — same permissions, but countersigns Part B of the certificate.
    The law requires two DIFFERENT people, not two permission levels.
  - Commander (admin) — additionally approves who may hold an account.
  - Records Viewer — read-only. Must never see a control they cannot use.

Today all four see an identical screen. That is the single biggest failure to
fix. Use a persistent operator strip: role name, badge number, clearance, and
for the read-only role an unmistakable visual state — not a greyed button, but
a screen that never offers the action at all, plus a standing indicator that
this session cannot alter evidence.

THE CENTRAL DESIGN PROBLEM

The dashboard currently opens on packet statistics: "Packets 46.3K", "Flows 36",
"DNS queries 14". A senior officer with no networking background learns nothing
from that. Restructure so the first thing on screen answers, in plain language:

  1. Which exhibit am I looking at, and is its seal intact?
  2. What did the system find, how serious, and what does it mean?
  3. What must I do next?

Packet statistics are supporting evidence for those answers, not the headline.
Every finding in this system already records the rule that fired, the value
observed, and the threshold it was compared against — surface that reasoning,
because "the machine proposes, a named officer disposes" is the product's core
claim. Never show a bare score with no explanation.

TRANSLATE THE VOCABULARY

These engineering terms appear on screen today and must be paired with plain
language an investigating officer understands (keep the technical term, add the
meaning — do not delete precision, add a translation):
  flows → conversations between two machines
  beaconing → a device checking in with a controller on a regular rhythm
  DNS tunnelling → data smuggled inside domain-name lookups
  JA4 fingerprint → a signature of the software making the encrypted connection
  exfiltration → data leaving the network
  risk score → why this was flagged
Gujarati glosses already exist for key terms; design a place for a second
language rather than bolting it on.

SCREENS TO DESIGN

  1. Sign-in — air-gapped terminal. States that attempts are recorded with
     timestamp, username and source address.
  2. Case dashboard — the exhibit, its seal state, findings by severity, what
     needs attention. Same layout for all roles, different capability.
  3. Findings — a triage queue. Each finding: plain-language claim, the rule
     that fired, observed value vs threshold, the conversation it came from,
     and an officer's decision (confirm / dismiss / escalate) with a note.
     Read-only role sees decisions already made, and no controls.
  4. Evidence register — exhibits with SHA-256 seal, chain of custody as a
     verifiable sequence, and provenance (seized / reference / synthetic /
     unattested). A demonstration capture must be impossible to mistake for
     real evidence — that distinction should be loud, not a small label.
  5. Section 63 certificate — a two-part statutory form. Part A signed by the
     person in charge of the device, Part B by the expert. Show clearly that
     one account cannot complete both.
  6. Approvals — admin only. Pending applications, approve or reject.

VISUAL DIRECTION

  - Government tool, not consumer SaaS. Sober, dense, legible. Information
    over decoration. No gradients-as-decoration, no playful illustration, no
    rounded-friendly styling.
  - A persistent handling banner in the manner of classified systems, stating
    that the machine is air-gapped and the material is evidentiary.
  - Dark interface is acceptable and appropriate for a forensics console, but
    it must be a deliberate palette rather than a default dark admin theme.
    The current build reads as a generic dark MUI template; it should read as
    an instrument.
  - WCAG 2.1 AA contrast on every text colour — 4.5:1 normal, 3:1 large. This
    is enforced by an automated test in the repository, so it is a hard
    constraint, not an aspiration.
  - Keyboard operable throughout: an officer works a 300-row findings queue
    without a mouse.
  - Must be legible on a modest station monitor at 1440x900, and not break on
    a phone.
  - Devanagari/Gujarati script must sit correctly alongside Latin.

WHAT THE INTERFACE MUST NEVER DO

  - Show a missing value as zero. A figure that did not arrive is an em dash.
  - Offer a control the signed-in role cannot use.
  - Present a threshold as authoritative without saying where it came from —
    of 35 thresholds, 23 are the team's own heuristics and are labelled as such.
  - Claim the system is tamper-proof. It is tamper-EVIDENT: hash-chained custody
    entries reveal alteration, they do not prevent it.
  - Let a demonstration capture look like seized evidence.

TONE

This is shown to serving police officers and may be read by a court. Plain,
exact, unshowy. No marketing language. Every number on screen traces to
something measured.
```

---

## After Claude Design returns

Two things to decide that the tool cannot decide for you:

1. **Does the dashboard lead with the case or with the capture?** Leading with
   the case is the stronger pitch and the bigger rewrite.
2. **How loud is the read-only state?** A persistent banner is unambiguous and
   slightly heavy. A softer treatment risks the demo failing to show the one
   thing that most distinguishes this from a monitoring tool.
