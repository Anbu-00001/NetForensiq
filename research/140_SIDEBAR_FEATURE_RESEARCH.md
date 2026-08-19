# 140 — What belongs in the sidebar: research for a real IO's persistent chrome

*Compiled 20 August 2026. Question: what should live in NetForensiq's left sidebar,
alongside navigation and the existing "EVIDENCE HELD" posture strip
(`frontend/src/components/layout/EvidencePosture.jsx`), that is meaningful and
much-needed rather than decorative. Every feature below is checked against three
constraints: (1) the data must be derivable from models that already exist —
`EvidenceRecord`, `CustodyEvent`, `Case`, `CaseAssignment`, `CaptureSession`, `Flow`,
`Detection`, `Section63Certificate`, `AuditLog` — rather than requiring new capture;
(2) nothing may require live internet access, since the box is air-gapped; (3) no
statute section, duration or case name is used unless verified against at least one
fetched source, quoted below, and anything not verified is marked UNVERIFIED rather
than filled in.*

---

## What already exists — do not re-propose

`EvidencePosture.jsx` (compact + full) already shows, refreshed every 60s from
`/api/evidence/posture/` (`backend/evidence/views.py:219`):

- **CASE** — FIR number / case number of the latest exhibit
- **LATEST EXHIBIT** — exhibit number, seal-intact/broken (re-verified on every read,
  not read from a cached flag)
- **TIME BASIS** — clock synchronisation state, from `evidence/timesource.py`
  (`timedatectl`'s `NTPSynchronized` field; never contacts a time server; resolves to
  `unknown` on any failure rather than guessing)
- **EVIDENCE STORE** — encrypted-on-disk count vs. total, from `evidence/crypto.py`
- A **SYNTHETIC** banner when the latest exhibit is demonstration traffic, and a
  **tampered-exhibit count** when `verify()` fails

`Sidebar.jsx`'s `CaptureWindow` shows the most recent session's capture start and the
span it covers (not "uptime" — deliberately, per the code comment, because "uptime" is
the wrong idea for imported evidence).

Two things `timesource.describe()` already computes but **`EvidencePosture.jsx` does
not render**: `rtc_in_local_time` (whether the hardware clock is kept in local time
rather than UTC — relevant across a DST-like boundary) and the raw `source` field. This
is a near-zero-cost addition to the existing card, not a new feature — see §8.

---

## Part 1 — Statutory clocks (verified)

### 1a. BNSS 2023 s.187(3) — default bail: 60/90 days from **arrest**

Verified against two independently fetched bare-act reproductions
([apnilaw.com](https://www.apnilaw.com/bare-act/bnss/section-187-bharatiya-nagarik-suraksha-sanhitabnss-procedure-when-investigation-cannot-be-completed-in-twenty-four-hours/),
corroborated by [ipleaders](https://blog.ipleaders.in/default-bail-section-187-bnss/),
[LiveLaw](https://www.livelaw.in/top-stories/bnss-right-to-default-bail-under-bharatiya-nagarik-suraksha-sanhita-282457),
[SCC Online](https://www.scconline.com/blog/post/2025/10/20/bom-hc-grants-default-bail-magistrate-seen-remark-not-enough/)).
Quoted text: *"no Magistrate shall authorise the detention of the accused person in
custody under this sub-section for a total period exceeding— (i) ninety days, where the
investigation relates to an offence punishable with death, imprisonment for life or
imprisonment for a term of ten years or more... (ii) sixty days, where the investigation
relates to any other offence... the accused person shall be released on bail if he is
prepared to and does furnish bail."* This replaces the proviso to CrPC s.167(2).

**Cannot be computed from the current schema.** The clock runs from the date of
**arrest**, and NetForensiq has no `Accused` record and no arrest-date field anywhere —
`Case` carries `opened_on` (FIR date), not an arrest date. Building this honestly needs
one new field; faking it off the FIR date would print a wrong deadline; a chargesheet
filed "late" against a fabricated clock is a worse failure than no clock at all. Held out
of the ranked list below for that reason, noted here as a documented gap.

### 1b. BNSS 2023 s.193(3)(ii) — 90-day duty to update the informant/victim, from **FIR date**

Verified against two independently fetched sources
([apnilaw.com](https://www.apnilaw.com/bare-act/bnss/section-193-bharatiya-nagarik-suraksha-sanhitabnss-report-of-police-officer-on-completion-of-investigation/),
corroborated by
[drishtijudiciary.com](https://drishtijudiciary.com/current-affairs/section-193-of-bnss)).
Quoted text: *"the police officer shall, within a period of ninety days, inform the
progress of the investigation by any means including through electronic communication
to the informant or the victim."* This is a distinct duty from filing the final report —
it fires regardless of whether the investigation is finished, and it is anchored to when
the FIR was recorded, not to arrest. **This is buildable today**: `Case.opened_on`
already carries that date. See §2.

### 1c. IT Rules 2021, Rule 3(1)(g) and CERT-In Directions (2022) — 180-day retention, 6-hour reporting

Two independently converging, but **not directly relevant to what an IO does inside
NetForensiq** — both regulate the upstream entity (intermediary/service
provider/body-corporate), not the investigator:

- **IT (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021, Rule
  3(1)(g)**: once an intermediary removes or disables information, it must preserve that
  information and associated records **for 180 days** for investigation purposes, "or
  for such longer period as may be required by the court or by Government agencies who
  are lawfully authorised." Verified via
  [multiple secondary summaries](https://www.mondaq.com/india/social-media/1235196/information-technology-intermediary-guidelines-and-digital-media-ethics-code-rules-2021-adequate-regulation-of-intermediaries)
  converging on the same figure and clause number.
- **CERT-In Directions under s.70B(6), IT Act 2000** — issued **28 April 2022** (not 6
  April; the date supplied in the task brief is wrong and is corrected here), effective
  27 June 2022. Primary PDF:
  [cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf).
  Requires covered entities to enable and **securely maintain logs of all ICT systems
  for a rolling period of 180 days**, within Indian jurisdiction, and to **report
  cyber-security incidents to CERT-In within 6 hours** of noticing them or being brought
  to notice. Corroborated by
  [Lexology](https://www.lexology.com/library/detail.aspx?g=5eae7307-664d-484e-8a58-f50bc24bb4d2)
  and [amlegals.com](https://amlegals.com/cert-in-compliance-guide-2025/).

**Correction to the task brief**: IT Act **s.67C itself does not fix "90 days."** The
bare section text (verified via
[indiankanoon.org/doc/91763765](https://indiankanoon.org/doc/91763765/)) delegates the
duration to the Central Government ("intermediary shall preserve and retain such
information as may be specified for such duration... as the Central Government may
prescribe"). The 90-day figure that circulates in secondary sources attaches to other,
narrower contexts (e.g. IT Rules obligations after actual knowledge of specific
unlawful content) and could not be pinned to a single, general, primary duration in this
pass. **Do not print "IT Act s.67C = 90 days" anywhere.** What is solidly verified is
**180 days** twice over, from two different instruments (Rule 3(1)(g) and the CERT-In
Directions).

**Why this doesn't become sidebar chrome**: NetForensiq has no field recording the date
a preservation/production request (BNSS s.94 summons) was sent to a third party such as
an ISP or platform, so there is nothing to count down from. The honest version of this
feature is a static reminder, not a computed clock — see §7.

### 1d. BSA 2023 s.63(4) certificate — already the subject of a verified Gujarat HC ruling

Not a new finding — already verified in `research/99_GUJARAT_FIT.md` — but it is the
strongest statutory clock this codebase can print, because unlike §1a–c it needs no new
field. *Kshitijbhai Manubhai Patel v. Dilipbhai Laxmanbhai Kanani*, Gujarat High Court,
Justice J.C. Doshi, judgment dated 8 May 2026
([indiankanoon.org/doc/19060776](https://indiankanoon.org/doc/19060776/)): a s.65B(4)/
s.63(4) certificate "is a condition precedent for admissibility of computer-generated
secondary evidence. It cannot be supplemented through oral evidence." `Section63Certificate.is_complete`
already encodes exactly the fact this ruling makes urgent — see §3.

---

## Part 2 — What professional forensic tools keep in persistent chrome (verified)

- **Wireshark's status bar** (verified,
  [wireshark.org/docs/wsug_html_chunked/ChUseStatusbarSection.html](https://www.wireshark.org/docs/wsug_html_chunked/ChUseStatusbarSection.html)):
  always shows the capture file name, size, elapsed capture time, and packet counts —
  captured, displayed, marked, **dropped**, ignored. The dropped-packet count is shown
  persistently because a capture that silently lost packets is a materially different
  exhibit from one that didn't, and that has to be visible without a click.
- **Magnet AXIOM's Case Dashboard** (verified,
  [magnetforensics.com/blog/better-case-starting-points-with-magnet-axioms-new-case-dashboard](https://www.magnetforensics.com/blog/better-case-starting-points-with-magnet-axioms-new-case-dashboard/)):
  case-level home screen showing evidence sources and a per-source summary, reachable in
  one click from anywhere in the case rather than requiring a page navigation.
- **Security Onion's Grid page** (verified,
  [docs.securityonion.net/en/3/main/grid](https://docs.securityonion.net/en/3/main/grid/);
  corroborated by GitHub discussions on sensor-fault display): shows node/sensor status
  and, via an options toggle, **disk-usage columns specifically to flag sensors "due for
  a hardware upgrade."** This is the closest vendor precedent for "capture storage
  headroom" as first-class chrome, not an afterthought — a network sensor's job is to
  keep capturing, and running out of disk mid-capture is the canonical way that job
  fails silently.
- **Velociraptor's client presence indicator** (verified,
  [docs.velociraptor.app/docs/clients/searching](https://docs.velociraptor.app/docs/clients/searching/)):
  a green dot for currently connected, a flashing warning triangle for "not connected,
  last seen 15 min–24h ago," a solid triangle for "not seen in over 24h." Colour **and**
  shape carry the state — the same pattern `EvidencePosture.jsx`'s `Dot` component
  already uses (ringed dot for anything not "good"), so this validates rather than
  changes the existing visual language.

**Pattern across all four**: identity + integrity counters are always visible;
deep detail is one click away. None of them put case metadata, entity graphs, or
anything requiring scrolling in the persistent rail — only counts, state, and dates.

---

## Ranked feature list

Ranked by (how much it would cost the officer to discover this only after something
went wrong) ÷ (effort to build, given the data already exists).

### 1. Findings awaiting triage — count by severity

**What it shows**: a small badge/row — e.g. "7 NEW · 2 CRITICAL" — counting
`Detection` rows with `triage_status='new'`, broken out by `severity`, clicking through
to the findings list pre-filtered to `?triage=new`.

**Data source**: `Detection.triage_status`, `Detection.severity` — both already exist
(`backend/capture/models.py`); the API already supports `?triage=` and `?severity=`
filters (`DetectionViewSet.get_queryset`, `backend/capture/views.py:769`). No new
endpoint is strictly required — a lightweight aggregate could be added to the existing
`posture` action or as a new `DetectionViewSet` action returning grouped counts.

**Why at a glance, not a page**: findings accumulate silently while an officer works
elsewhere in the tool (evidence register, certificate signing). A rule engine that
raised nine findings and a human who never re-opens the findings tab produces the exact
failure this project's own docs warn about: *"an alert nobody received that the system
believes it sent is worse than no alerting at all"* (`research/120_OBJECTIVES_COMPLIANCE.md`,
on why delivered-alert outcomes are logged). An unopened triage queue is the same failure
mode, one layer up.

**Precedent**: every SOC/EDR-class tool in Part 2 keeps an unresolved-item count in
persistent chrome (Security Onion's alert counts, Velociraptor's client state).

**Honest risk**: the count must reflect exactly `triage_status='new'`, not
"everything," or it silently overstates backlog every time an analyst confirms or
dismisses a finding elsewhere. If a session's `Detection` rows are re-created on
re-analysis without clearing old ones, the count could double-count stale findings — this
needs verifying against `analyse_session`'s actual behaviour before shipping, not
assumed.

### 2. Certificate completion status — Part A signed, Part B pending

**What it shows**: a count of `Section63Certificate` rows where `part_a_signed_at` is
set but `part_b_signed_at` is not (`is_complete` is `False`), scoped to the officer's
cases, with the exhibit number.

**Data source**: `Section63Certificate.is_complete` property already exists
(`backend/evidence/models.py:515`); `CaseAssignment.Role.EXPERT` already distinguishes
who is meant to countersign Part B from who signed Part A, so "which certificates am I
waiting on" is answerable with a query, not new modelling.

**Why at a glance**: BSA 2023 s.63(4) requires both parts, conjunctively — the statute's
own wording, already quoted correctly in this codebase's model docstring. A certificate
issued with only Part A signed is not evidence yet, and the Gujarat High Court's own
2026 ruling (§1d above, already verified in `99_GUJARAT_FIT.md`) treats a missing
certificate as a "patent illegality" grounds for setting aside a lower court's order — an
incomplete certificate sitting unnoticed for weeks is exactly the gap that ruling
punishes. This is precisely the kind of state that "changes what an officer should do
next" and is "invisible until something has already gone wrong" — the design principle
`EvidencePosture.jsx`'s own docstring already states for the four rows it shows.

**Honest risk**: must not present "Part A signed" as "certificate is fine" — the whole
point is the opposite. Must not claim the Doshi ruling holds anything about
network/packet-capture evidence specifically (per `99_GUJARAT_FIT.md`'s own caution) —
the correct framing is "designed for the certificate regime this ruling establishes," not
"this ruling covers our evidence type."

### 3. My cases — assigned capacity, one line each

**What it shows**: the cases the signed-in officer is on via `CaseAssignment`, each with
its role (IO / Expert / Supervisor / Observer) and `Case.status`
(Registered/Investigation/Chargesheeted/Closed).

**Data source**: `CaseAssignment` and `Case` already exist
(`backend/evidence/models.py:95` and `:174`); `CaseViewSet` already exposes case
assignments via `prefetch_related('assignments__officer', 'exhibits')`.

**Why at a glance**: an officer working more than one case needs to know, without
navigating away from whatever exhibit they're examining, which other cases have
something waiting — this is the same "context, not destination" logic the sidebar
already applies to `EvidencePosture` (per its own code comment: "below the navigation
because it is context rather than a destination"). It also makes the s.63(4) separation
of duties visible before it becomes a problem: if an officer is listed as both IO and
Expert on the same case (which `CaseAssignment`'s `unique_together` constraint and the
one-role-per-officer design should prevent, but a role change could still create a
confusing display), showing role plainly surfaces it rather than hiding it in a
detail page.

**Honest risk**: must clearly separate "cases I am IO on" from "cases I am Expert on" —
conflating them defeats the purpose of the constraint that makes the separation
checkable in the first place, per this codebase's own stated design.

### 4. Informant/victim update clock — BNSS s.193(3)(ii)

**What it shows**: for each case in the officer's list, days since `Case.opened_on`
against the 90-day mark — e.g. a plain "Day 41 of 90" or, past the mark, a flagged
"90-day update due" — computed only for cases with `status` in `REGISTERED` /
`INVESTIGATION` (the clock is a live obligation only while the case is open; a
`CHARGESHEETED` or `CLOSED` case should not still be nagging).

**Data source**: `Case.opened_on` and `Case.status` already exist; this is pure date
arithmetic on an existing field, no new capture.

**Why at a glance**: verified in §1b — BNSS 2023 s.193(3)(ii), quoted, requires the
investigating officer to inform the informant or victim of progress "within a period of
ninety days... by any means including through electronic communication." This is a
concrete, dated, plain-English statutory duty that fires regardless of case complexity,
and — per this project's own `112_POLICE_WORKFLOW_NEEDS.md` research — "updating/
sensitizing complainant on the status of his complaint" is explicitly named as one of the
observed failure modes in a real SP's own investigation-guidelines circular (item 11,
Puducherry Cyber Crime Cell checklist, 14.02.2024). A clock that quietly passes 90 days
with nobody having looked at the case is the failure this feature exists to prevent.

**Honest risk — this is the one that most needs care**: this is a *notification*
deadline, not a *chargesheet* deadline. It must never be labelled or implied as "the
case must be closed by this date" — that would misstate the statute and could genuinely
mislead an officer about their actual obligations. It must also never be confused with
or substitute for the BNSS s.187(3) default-bail clock (§1a), which runs from arrest, not
FIR, and which this system cannot currently compute at all (no arrest-date field exists).
Label it exactly: "Informant/victim update due (BNSS s.193(3)(ii))," nothing broader.

### 5. Evidence-store disk headroom

**What it shows**: free space and percentage-used on the volume backing the evidence
store / capture staging directory, with a plain colour threshold (e.g. amber under 20%
free, red under 10% free — thresholds to be set deliberately, not borrowed from an
unrelated domain).

**Data source**: **new** — nothing in the codebase currently calls `shutil.disk_usage`
or `os.statvfs` anywhere in application code (confirmed by search: the only hits are in
third-party packages under `.venv`). This is a small, self-contained addition: one
function reading the filesystem the evidence store lives on, exposed as one more field
on the existing `posture` endpoint.

**Why at a glance**: this is the single most operationally dangerous *silent* failure
mode for a capture appliance — a live capture (`CaptureSession.state == RUNNING`) that
fills the disk mid-run does not fail loudly, it truncates, and a truncated capture is
exactly the ambiguous-reconstruction case this codebase's own reassembly code already
treats as a distinct, disclosed failure mode (`research/120_OBJECTIVES_COMPLIANCE.md`,
§2: "Gaps end a run rather than being closed up"). Security Onion (§2 above) treats disk
headroom as first-class sensor chrome for exactly this reason — a monitoring appliance's
core job is uninterrupted capture, and storage exhaustion is the ordinary way that job
stops without an alarm.

**Honest risk**: report raw bytes-free and percentage, **not** a time estimate ("N hours
of capture remaining") — packet rate and compression vary enough that a time estimate
would be a promise the tool cannot keep, and a wrong estimate on an air-gapped machine
with no way to double-check against a live feed is worse than no estimate. Also: this
reads host disk state, which is new capability with a real (if small) cost — flag
honestly as "new," not "surfacing existing data," when it's built.

### 6. Live capture heartbeat

**What it shows**: when a `CaptureSession` is `RUNNING`, a distinct "capture in
progress" state — elapsed time since `started_at`, running `packet_count` /
`byte_count` — visually different from the existing `CaptureWindow`, which currently
shows only the *most recent* session regardless of whether it finished, and shows the
traffic's own timespan (`capture_start`/`capture_end`) rather than live progress.

**Data source**: `CaptureSession.state`, `packet_count`, `byte_count`, `started_at` all
already exist (`backend/capture/models.py:5`); this is a display change plus polling,
not new capture — the fields are already written during live capture, `CaptureWindow`
just doesn't currently distinguish "still running" from "already finished."

**Why at a glance**: verified precedent — Wireshark's status bar (§2 above) keeps
running packet/byte/dropped counters visible at all times during a live capture,
specifically because an officer running a live capture needs to know it is still
alive without switching windows. A capture that silently stalled (interface unplugged,
process killed) but still shows as the "latest session" in a static window is a false
positive for "capture is working."

**Honest risk**: must show *when the state was last confirmed*, not just the last known
packet count — a stalled capture process could leave `packet_count` frozen at a
plausible-looking number with nothing distinguishing it from a slow but live one, unless
the freshness of the read itself is part of what's displayed.

### 7. RTC-in-local-time flag (extend the existing TIME BASIS row)

**What it shows**: `timesource.describe()`'s already-computed `rtc_in_local_time`
boolean, currently discarded by `EvidencePosture.jsx` (it renders `clock.timezone` but
not this field), surfaced as a one-line addition to the existing TIME BASIS row: "RTC
kept in local time — offsets by daylight-saving boundaries" when true.

**Data source**: 100% existing — `evidence/timesource.py:140` already computes this
field from `timedatectl show`; it is simply not read by the frontend component.

**Why at a glance**: the module's own docstring states the reasoning already —
timestamps recorded across a DST-like boundary on a machine whose hardware clock is kept
in local time shift by an hour in a way UTC-based logging does not, and that is worth
knowing about an exhibit sealed in March or November. Since the whole point of
`timesource.py` was "disclose the clock's state, don't paper over it," leaving a field
it already computes unrendered is an inconsistency worth fixing regardless of anything
else in this document.

**Honest risk**: minimal — this is disclosure of already-computed state, not a new
claim. The only risk is under-explaining it (a bare "RTC: local" is meaningless to a
non-technical reader); it needs the same plain-language treatment the rest of the strip
already uses.

### 8. Custody-chain reconciliation flag

**What it shows**: a count of exhibits whose `case_reference` (the free-text field
recorded at seizure) disagrees with the `case_reference` on the `Case` they were later
linked to — a state this codebase's own `link_evidence_to_case` service function already
detects and logs to the custody chain rather than silently overwriting
(`research/120_OBJECTIVES_COMPLIANCE.md`: "If they disagree, the disagreement is recorded
in the custody log for the officer to see").

**Data source**: existing — the mismatch is already written as a `CustodyEvent` with
action `CASE_LINKED` and a detail note; this feature is a query over existing
`CustodyEvent` rows, not new data.

**Why at a glance**: this is precisely the kind of small, easily-missed discrepancy that
becomes a courtroom question — "which case does exhibit X actually belong to?" — only
once nobody remembers it happened. The system already refuses to silently paper over it;
surfacing the count is closing the loop on a design decision that is otherwise only
visible to someone who reads a specific exhibit's full custody log.

**Honest risk**: lowest-priority item on this list — genuinely niche (it only fires when
an exhibit was sealed before a `Case` record existed, or when a case's own reference was
edited after linking), and worth building only after 1–6 above. Listed for completeness,
not urgency.

---

## What was deliberately *not* proposed, and why

- **BNSS s.187(3) default-bail countdown** — needs an arrest-date field this schema
  does not have; faking it off FIR date would print a wrong number. See §1a.
- **CERT-In 6-hour / 180-day countdown for third-party evidence requests** — no field
  records when a preservation/production request was sent to an ISP or platform, so
  there is nothing to count down from; the honest version is static guidance text, not
  computed chrome. See §1c.
- **CCTNS/ICJS live case status** — explicitly out of scope per the task brief; no
  authorisation exists, and this project's own compliance doc already states this
  plainly (`research/120_OBJECTIVES_COMPLIANCE.md`, objective 8).
- **IOC feed staleness indicator** — there is no external IOC feed wired into this
  system at all (confirmed in `research/120_OBJECTIVES_COMPLIANCE.md`, "no external IOC
  feed"), so there is no feed whose staleness could be shown; building the indicator
  before the feed would be chrome describing a capability that does not exist.
- **Key escrow status** — `evidence/crypto.py`'s own docstring states plainly that key
  escrow is the *deploying agency's* responsibility ("has to escrow the key somewhere
  other than the machine it protects"), not something this system tracks or verifies.
  The existing EVIDENCE STORE row already shows whether a key is configured; claiming to
  show "escrow status" beyond that would assert a guarantee the code cannot back.

---

## Sources (consolidated)

- BNSS 2023 s.187(3): [apnilaw.com](https://www.apnilaw.com/bare-act/bnss/section-187-bharatiya-nagarik-suraksha-sanhitabnss-procedure-when-investigation-cannot-be-completed-in-twenty-four-hours/), [ipleaders](https://blog.ipleaders.in/default-bail-section-187-bnss/), [LiveLaw](https://www.livelaw.in/top-stories/bnss-right-to-default-bail-under-bharatiya-nagarik-suraksha-sanhita-282457), [SCC Online](https://www.scconline.com/blog/post/2025/10/20/bom-hc-grants-default-bail-magistrate-seen-remark-not-enough/)
- BNSS 2023 s.193(3)(ii): [apnilaw.com](https://www.apnilaw.com/bare-act/bnss/section-193-bharatiya-nagarik-suraksha-sanhitabnss-report-of-police-officer-on-completion-of-investigation/), [drishtijudiciary.com](https://drishtijudiciary.com/current-affairs/section-193-of-bnss)
- IT Act 2000 s.67C (bare text): [indiankanoon.org/doc/91763765](https://indiankanoon.org/doc/91763765/)
- IT (Intermediary Guidelines) Rules 2021, Rule 3(1)(g): [mondaq.com](https://www.mondaq.com/india/social-media/1235196/information-technology-intermediary-guidelines-and-digital-media-ethics-code-rules-2021-adequate-regulation-of-intermediaries)
- CERT-In Directions, 28 April 2022 (primary PDF): [cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf); corroborated: [Lexology](https://www.lexology.com/library/detail.aspx?g=5eae7307-664d-484e-8a58-f50bc24bb4d2), [amlegals.com](https://amlegals.com/cert-in-compliance-guide-2025/)
- *Kshitijbhai Manubhai Patel v. Dilipbhai Laxmanbhai Kanani*, SCA 120/2023, Gujarat HC, 8 May 2026: [indiankanoon.org/doc/19060776](https://indiankanoon.org/doc/19060776/) — already verified in `research/99_GUJARAT_FIT.md`, reused here, not re-litigated
- Wireshark statusbar: [wireshark.org/docs/wsug_html_chunked/ChUseStatusbarSection.html](https://www.wireshark.org/docs/wsug_html_chunked/ChUseStatusbarSection.html)
- Magnet AXIOM Case Dashboard: [magnetforensics.com/blog/better-case-starting-points-with-magnet-axioms-new-case-dashboard](https://www.magnetforensics.com/blog/better-case-starting-points-with-magnet-axioms-new-case-dashboard/)
- Security Onion Grid / disk usage: [docs.securityonion.net/en/3/main/grid](https://docs.securityonion.net/en/3/main/grid/)
- Velociraptor client presence indicator: [docs.velociraptor.app/docs/clients/searching](https://docs.velociraptor.app/docs/clients/searching/)
- Puducherry Cyber Crime Cell investigation checklist (item 11, "Updating/Sensitizing
  complainant"), 14.02.2024 — already verified in `research/112_POLICE_WORKFLOW_NEEDS.md`,
  reused here
- Codebase read directly this pass: `backend/evidence/models.py`, `backend/evidence/views.py`,
  `backend/evidence/timesource.py`, `backend/evidence/crypto.py`, `backend/capture/models.py`,
  `backend/capture/views.py`, `backend/accounts/models.py`, `frontend/src/components/layout/Sidebar.jsx`,
  `frontend/src/components/layout/EvidencePosture.jsx`
