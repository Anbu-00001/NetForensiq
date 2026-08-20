# 143 — SIEM integration and real-time alerting: an audit against the real specs

Scope: the two bonus objectives "Integration with SIEM systems" and "Real-time
alerting for active threats," checked against primary sources, not memory.
Every field name, RFC section and version number below was fetched during this
audit; anything not independently confirmed is marked **UNVERIFIED**.

Code audited: `backend/capture/siem.py`, `backend/capture/alerting.py`,
`backend/capture/service.py` (`run_live_capture`, `_run_live_monitor`),
`backend/capture/attack_mapping.py`, `backend/capture/tests.py::SiemExportTests`,
`backend/capture/tests_alerting.py`, `backend/capture/tests_live_monitor.py`,
`backend/netforensiq_backend/settings.py:253-266`,
`backend/capture/management/commands/capture_live.py`, `backend/capture/views.py`.

---

## A. SIEM integration

### A.1 Elastic Common Schema (ECS)

**Version fetched**: 9.5.0, confirmed independently from two pages —
[ECS field reference index](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
and the [event field set page](https://www.elastic.co/docs/reference/ecs/ecs-event).
The project's own comments never cite a version number, so there was nothing
to contradict — but nothing to hold the code to, either.

**The one MUST the guidelines state explicitly**
([ECS guidelines](https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html)):
*"The document MUST have the `@timestamp` field."* We do
(`siem.py:108`). The guidelines page did not state a required set beyond that
for a "security event" specifically — there is no ECS rule requiring
`event.kind`/`event.category`/`event.type` be populated, only strong
convention. There is, however, a field the schema itself marks required:

> `ecs.version` — *"ECS version this event conforms to. `ecs.version` is a
> required field and must exist in all events."*
> — [ECS field set: ecs](https://www.elastic.co/docs/reference/ecs/ecs-ecs)

**We do not emit it.** `siem.py:107-176` builds no `ecs` key at all. This is
the single cleanest, cheapest finding in this audit: the schema's own required
field is absent from every document we produce.

#### Findings table — ECS

| ECS says | Our code | File:line | Verdict |
|---|---|---|---|
| `ecs.version` is required in every document | Not emitted | `siem.py:107-176` | **Gap** — trivial fix |
| `event.kind` allowed values: `alert, asset, enrichment, event, metric, state, pipeline_error, signal` | `'alert'` | `siem.py:110` | Correct |
| `event.category` allowed values include `intrusion_detection`, `network` | `['intrusion_detection', 'network']` | `siem.py:57,111` | Correct |
| `event.type` allowed values include `info` (also `connection`, `denied`, `indicator`, `allowed`…) | Always `['info']`, regardless of finding kind | `siem.py:112` | **Weak** — same value for a port scan, a beacon and an exfil finding when more specific values exist |
| `event.dataset`, `event.module` are producer-defined free text | `'netforensiq.detection'`, `'netforensiq'` | `siem.py:115-116` | Correct (no fixed vocabulary to violate) |
| `threat.technique.id` / `.name` / `.reference` — *"the id/name/reference url of technique used by this threat"* | Emitted as arrays | `siem.py:147-151` | Correct field names |
| `threat.tactic.id` / `.name` / `.reference` | Only `.id` and `.name` emitted; **`.reference` missing** | `siem.py:152-155` | **Gap** — the tactic URL is one string away (`https://attack.mitre.org/tactics/{id}/`) and we already build the technique URL the same way in `attack_mapping.py:47` |
| `threat.technique.subtechnique.id` / `.name` / `.reference` exist as a **separate** sub-structure for dotted technique IDs (e.g. `T1071.004`) | Dotted sub-technique IDs are put directly into `threat.technique.id`, never split into the `subtechnique` object | `siem.py:148`, `attack_mapping.py` (`T1071_004`, `T1048_003`) | **Gap** — a SOC dashboard that groups by `threat.technique.id` will bucket `T1071` and `T1071.004` as unrelated strings instead of parent/child |
| `threat.framework` — *"name of the framework used to classify the tactic and technique"* | `'MITRE ATT&CK'` | `siem.py:156` | Correct |
| `related.ip` — *"all IPs seen on your event... append IPs from host, observer, source, destination... so a SOC can query one IP regardless of where it appeared"* | Not emitted | `siem.py:159-168` | **Gap** — cheap, and it is exactly the "find every event that mentions this IP" query a SOC analyst runs first |
| `event.created` — *"when the event was first read by an agent/pipeline"*, distinct from `@timestamp` (when the activity happened) | Both collapsed onto `detection.created_at`; the underlying flow's actual `first_seen` is never surfaced as `@timestamp` | `siem.py:108` vs `service.py` (flow has `first_seen`/`last_seen`) | **Gap** — for a detection raised minutes after the traffic (batch/PCAP analysis), `@timestamp` should be when the *activity* happened, `event.created` when the *detection* fired. Right now a SOC timeline plots every finding at analysis time, not attack time |
| `event.outcome` — `success` / `failure` / `unknown` | Not emitted | `siem.py:107-176` | **Gap, situational** — most rules can't know this, but the reconstruction work in §120 already found a rule-worthy example (`CVE-2024-4577` attempt that got a 404): where the evidence is in hand, `unknown` is dishonest and `failure` is available |

Sources fetched: [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference),
[ECS event fields](https://www.elastic.co/docs/reference/ecs/ecs-event),
[ECS threat fields](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html),
[ECS related fields](https://www.elastic.co/docs/reference/ecs/ecs-related),
[ECS guidelines](https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html),
[ECS `ecs` field set](https://www.elastic.co/docs/reference/ecs/ecs-ecs).

### A.2 CEF (ArcSight Common Event Format)

Primary source fetched directly: **Micro Focus, *Implementing ArcSight Common
Event Format (CEF)*, Version 25, dated 28 September 2017** — the current
published edition (no later version is publicly indexed as of this audit).
[PDF](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf).

**Header, verified verbatim:**
```
CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
```
Seven pipe-delimited components before the extension (`CEF:Version`, Vendor,
Product, Version, Class ID, Name, Severity). Our own test asserts exactly
this: `tests.py:1595-1606`, `test_the_cef_header_has_exactly_seven_fields`.
**Confirmed correct against the spec, not just against our own test.**

**Escaping rules, verified verbatim:**
- *"If a pipe (|) is used in the header, it has to be escaped with a
  backslash (\\). But note that pipes in the extension do not need
  escaping."*
- *"If a backslash (\\) is used in the header or the extension, it has to be
  escaped with another backslash (\\)."*
- *"If an equal sign (=) is used in the extensions, it has to be escaped with
  a backslash (\\). Equal signs in the header need no escaping."*

Our `_escape_cef_header` (`siem.py:60-68`, escapes `\` and `|`) and
`_escape_cef_extension` (`siem.py:71-76`, escapes `\` and `=`, and does *not*
touch `|`) match this **exactly**. This is the one place in the audit where
the code is not just plausible but verified byte-for-byte correct.

**One spec detail we deviate from, defensibly:** the spec's own example shows
multi-line values kept intact by encoding the newline as literal `\n`/`\r`
(*"Multi-line fields can be sent by CEF by encoding the newline character as
\\n or \\r"*). Our code instead **collapses** `\n`/`\r` to a single space
(`siem.py:75`) rather than emitting the two-character escape. Functionally
safe (a collapsed line can't corrupt the record), but it silently discards
line structure a spec-compliant consumer would have preserved. Low priority.

**Extension key names — all checked against the CEF v25 dictionary (pages
8-22 of the PDF).** Every key our code emits is real:

| Key we emit | CEF full name (verified) | Correct? |
|---|---|---|
| `rt` | `deviceReceiptTime` — *"MMM dd yyyy HH:mm:ss or milliseconds since epoch"* | Yes — `siem.py:196` sends ms-since-epoch |
| `cat` | `deviceEventCategory` | Yes |
| `act` | `deviceAction` | Yes |
| `msg` | `message` | Yes |
| `externalId` | `externalId` (String, length 40) | Yes |
| `cs1`/`cs1Label`, `cs2`/`cs2Label`, `cs3`/`cs3Label` | `deviceCustomString1-3` + labels | Yes — correct use of the "custom slot + label" pattern the spec requires |
| `src`, `spt`, `dst`, `dpt`, `proto` | `sourceAddress`, `sourcePort`, `destinationAddress`, `destinationPort`, `transportProtocol` | Yes |
| `in` | `bytesIn` — *"bytes transferred **inbound**, relative to the source→destination relationship"* | **No** — see below |

**Concrete defect found**: `in` is defined by the spec as one direction of a
src→dst flow. Our `_endpoints()` computes `bytes = bytes_sent + bytes_received`
(**both** directions summed) at `siem.py:93`, and `to_cef` puts that combined
total into `in` at `siem.py:224`. We never populate `out` (`bytesOut`) at all.
A consumer reading `in` as "inbound bytes" per the spec gets a number that is
actually total conversation volume — silently wrong in the same "shifted by
one field" sense the module's own docstring warns about for header escaping.
Two-line fix: split into `in=bytes_received, out=bytes_sent` (oriented on the
initiator, which `_endpoints()` already resolves).

Severity mapping (`CEF_SEVERITY = {'low': 3, 'medium': 5, 'high': 8,
'critical': 10}`, `siem.py:45`) was checked against the spec's bands —
*"0-3=Low, 4-6=Medium, 7-8=High, and 9-10=Very-High"* — and every value falls
correctly inside its band. Correct.

### A.3 RFC 5424 syslog and RFC 6587 framing

**RFC 5424 §6.3 (STRUCTURED-DATA)**, fetched from
[rfc-editor.org](https://www.rfc-editor.org/rfc/rfc5424): structured data is
optional; a compliant message with none **MUST** carry the NILVALUE `-` in
that slot. Our syslog line (`siem.py:239-242`):

```
<PRI>1 <TIMESTAMP> <HOST> netforensiq - <rule_id> - <CEF record as MSG>
```

maps onto `<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP
MSGID SP STRUCTURED-DATA SP MSG` with `APP-NAME=netforensiq`, `PROCID=-`
(nilvalue), `MSGID=<rule_id>`, `STRUCTURED-DATA=-` (nilvalue) — this is
**valid, well-formed RFC 5424**, not a hand-rolled lookalike.

But the question asked was sharper than "is it valid" — **do we use
STRUCTURED-DATA, or just cram everything into MSG?** Answer: we use the
NILVALUE. Every field a SIEM might want (rule ID, severity, source/dest IP,
ATT&CK technique) is *inside* the CEF blob that rides as MSG, not exposed as
parseable `SD-PARAM`s. A receiver that doesn't already speak CEF gets one
opaque string. RFC 5424 structured data would let those same fields ride as
`[netforensiq@<PEN> ruleId="..." srcIp="..." attackTechnique="T1071"]` —
parseable by a generic syslog-ng/rsyslog `structured-data` parser with zero
CEF-specific work. **Building this needs a registered IANA Private Enterprise
Number** (the `name@<private enterprise number>` form the RFC requires for
non-reserved SD-IDs) — registration is free via
[IANA PEN application](https://pen.iana.org/pen/PenApplication.page); the
processing time was **not verified** in this audit — mark UNVERIFIED.

**RFC 6587 §3.4.1 (octet-counted TCP framing)**, fetched from
[rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6587): format is `MSG-LEN
SP SYSLOG-MSG`. Our TCP path (`alerting.py:144-149`):

```python
payload = line.encode('utf-8')
sock.sendall(f'{len(payload)} '.encode('ascii') + payload)
```

is exactly this framing. **Confirmed correct.** The docstring's claim that we
"use octet-counted framing (RFC 6587 s.3.4.1)" is accurate, not aspirational.

### A.4 What SIEMs an Indian police lab would actually run

- **Wazuh** is the realistic target. It is GPL-2.0, self-hosted, and every
  component (manager, indexer, dashboard) runs with no mandatory outbound
  telemetry — consistent with an air-gapped forensic lab. This was checked
  against Wazuh's own product positioning and third-party deployment guides
  via search (not an authenticated primary fetch of wazuh.com's air-gap
  claims specifically — treat the "no mandatory cloud telemetry" framing as
  well-supported but **not independently verified against Wazuh's own
  documentation** in this pass).
- **Wazuh's remote syslog listener is real and directly compatible with our
  output.** Verified against
  [Wazuh's `<remote>` reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html):
  ```xml
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>tcp</protocol>
    <allowed-ips>192.168.2.15/24</allowed-ips>
  </remote>
  ```
  This is precisely our `alerting.py` syslog transport (`ALERT_SYSLOG_PORT`
  defaults to `514`, `settings.py:259`), on either UDP or TCP. **Point the
  `<remote>` block at the workstation and Wazuh will receive every line we
  send today, with no code change on our side.**
- **What Wazuh will *not* do automatically**: without a decoder, Wazuh stores
  our line as an unparsed string — it will not surface `severity`, `rule_id`,
  `src_ip` or `threat.technique.id` as searchable fields in the dashboard.
  Wazuh's own docs describe exactly the mechanism for fixing this: a
  `local_decoder.xml` (field extraction) plus a matching rule set placed in
  `/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/`. We ship neither.
  This is the real dividing line between "Wazuh can receive our bytes" and
  "Wazuh can alert on our findings" — see A.5 and the ranked list below.
- **CERT-In / NCIIPC do not mandate a log *format*.** The CERT-In Directions
  (verified primary text, §A of Part B below) require **logging and
  reporting**, not a specific SIEM product or wire format. NCIIPC guidelines
  exist as sector playbooks but nothing in what was fetched names Wazuh,
  Elastic, Splunk or QRadar as a mandated platform for a police cyber-crime
  lab — there is no MeitY/STQC product mandate found. Any claim that our
  format was "chosen because CERT-In requires it" would be **unsupported**;
  the honest claim is narrower — ECS because Elastic-family stacks are common
  in Indian government deployments generally, CEF/syslog because they are the
  lowest common denominator every SIEM (Wazuh included) can ingest without a
  vendor-specific connector.

### A.5 The honest gap — is a stream export really "SIEM integration"?

What exists today, precisely:

1. **Push — syslog** (`alerting.py:137-163`): UDP or TCP, RFC 5424-framed,
   RFC 6587 octet-counted on TCP. This is genuinely, directly consumable by
   any syslog-receiving SIEM, Wazuh included, today, with zero code on either
   side beyond pointing a `<remote>` block at us.
2. **Push — webhook** (`alerting.py:166-205`): one HTTP POST per batch,
   body = `{"source": "netforensiq", "sent_at": ..., "count": N,
   "withheld_over_batch_limit": M, "findings": [ECS docs...]}`. This is
   **not** a format any SIEM ingests natively — it is ECS-*shaped* JSON
   wrapped in a private envelope. Elasticsearch's own `_bulk` API needs
   newline-delimited action+source pairs, not a single object with a
   `findings` array; Splunk's HEC wants one event per line or a specific
   envelope of its own; Wazuh has no webhook listener built in at all. A
   receiver has to be written — a small Logstash filter, a Lambda, a custom
   script — to unwrap `findings[]` before any SIEM's normal ingestion path
   sees ECS documents.
3. **Pull — `GET /api/sessions/{id}/siem/?fmt={ecs|cef|syslog}`**
   (`views.py:71-104`): an authenticated, session-scoped, on-demand stream.
   A SIEM *could* poll this with a generic HTTP-polling input (Filebeat
   `httpjson`, Splunk's REST modular input) but that requires an operator to
   hand-configure that input, per session, on the SIEM side. There is no
   packaged "NetForensiq app" in Elastic's integration hub, no Wazuh
   ruleset, no Splunk Technology Add-on — nothing a SOC installs and gets
   field mappings for free.

**What a judge who runs a SOC would say**: syslog is a real integration
point — that claim survives scrutiny unmodified. The webhook and the pull
API are correctly described as **export in an ingestible format**, not
**integration** in the sense a SOC engineer means the word (a packaged
connector with field mappings, listed in the vendor's own integration
catalogue, requiring no bespoke glue). Calling all three "SIEM integration"
without distinction is the overclaim; the current
`research/120_OBJECTIVES_COMPLIANCE.md:189` entry ("✅ ECS, CEF 0 and RFC
5424, streamed line-by-line...") is accurate about the mechanics and silent
about this distinction.

**Minimum that makes the claim defensible**: ship the Wazuh decoder/rule pair
(item 1 below). That turns "we produce syslog Wazuh can technically receive"
into "we produce syslog Wazuh can search and alert on," which is the
difference between an export format and an integration, for the one SIEM
most likely to actually sit in a police lab.

---

## B. Real-time alerting

### B.1 How air-gapped SOCs actually alert

- **NIST SP 800-82 Rev. 3** (28 Sept 2023, the current OT security guide)
  codifies **unidirectional gateways / data diodes** as the standard pattern
  for getting alerts *out* of an isolated network: hardware that physically
  permits data to flow one way only, from the protected network to a
  monitoring system, with no return path. This is the standard answer to
  "how does an air-gapped network alert a human" — a diode carrying logs,
  alerts and telemetry outward to a SIEM/SOC on the other side.
  [Source discussion](https://www.opswat.com/blog/sending-logs-alerts-and-telemetry-through-a-data-diode).
- The pattern this implies for a platform like ours, which is asked to run
  **on** the air-gapped side, is **on-box alerting**: the detection and the
  alert surface live on the same machine an analyst is physically watching,
  because there is no wire to send the alert further without a diode most
  deployments won't have. Our design — write to the local console/API, and
  optionally push to a syslog/webhook sink that is *itself* inside the same
  isolated segment — matches this pattern. It does not, and should not,
  claim to solve the "get an alert out of an air gap" problem; that is a
  hardware problem (the diode), not a software one.
- **CISA guidance and a specific number for "one-way data diode + police
  network" were not found and are not cited here** — UNVERIFIED, not
  included as a claim.

### B.2 What latency counts as "real-time"

No single published standard defines a number — this was searched
specifically and no NIST, IETF or vendor document was found stating "X
seconds = real-time" for network security monitoring. What was found:

- **Suricata** documentation describes itself as built for
  ["real-time threat detection"](https://docs.suricata.io/en/latest/what-is-suricata.html)
  without publishing a latency figure in the page fetched.
- One academic evaluation (an IoT-focused access-control paper, not a
  general Zeek benchmark) measured **Zeek at an 11-14 second time-to-detect**
  on a pfSense deployment, average 12.1s — cite this narrowly as *one
  measured data point from one study*, not an industry figure: [arXiv
  2512.09934](https://arxiv.org/pdf/2512.09934).
- Beaconing-detection literature (RITA-style) treats **connection intervals
  in the tens of seconds** as the signal itself — regularity across 50+
  connections with inter-arrival standard deviation under 10-30 seconds is
  what marks a beacon as automated. This is the same logic
  `attack_mapping.py`/detection rules already build on; it is also why a
  30-60 second analysis window (see below) is not a compromise but close to
  the shortest window in which the signal a beacon rule looks for can even
  exist.
- **Our own claim should be a mechanism, not a number.** `service.py:75-102`
  documents this correctly already: *"Latency to an alert is one window, not
  the length of the capture."* The CLI's own `--window` help text
  (`capture_live.py:26-31`) suggests **30 seconds** as the example value.
  That is an honest, specific, buildable claim — "alert latency equals the
  configured window, typically 30-60s, because periodicity detection needs
  enough samples to exist" — and it is a stronger claim than an unsupported
  "real-time" would be, because it is falsifiable and true.

### B.3 CERT-In Directions, 28 April 2022 — verified against the primary PDF

Fetched directly:
[CERT-In Directions 70B, 28.04.2022](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf).

Exact clause (ii): *"Any service provider, intermediary, data centre, body
corporate and Government organisation **shall mandatorily report cyber
incidents** as mentioned in Annexure I **to CERT-In within 6 hours** of
noticing such incidents or being brought to notice about such incidents."*

Two things worth being precise about, because they are easy to overstate:

1. **This is an obligation to report *to CERT-In***, by email, phone or fax,
   within 6 hours of an organisation becoming aware. It is **not** a
   requirement to run real-time detection or alerting infrastructure. An
   organisation with no automated detection at all and a human who happens
   to notice something is fully compliant if they report within the window.
2. Clause (iii) does contain the phrase *"up to and including near
   real-time"* — but only inside a narrower power: CERT-In may, by its own
   specific order/direction to a named entity, demand information "in the
   format... up to and including near real-time" for incident-response
   purposes. That is CERT-In compelling a specific organisation on a
   specific incident, not a standing "run real-time monitoring" mandate on
   every body corporate.
3. Clause (iv) (verified, same PDF): logs of ICT systems **must be enabled
   and retained for a rolling 180 days, within Indian jurisdiction**, and
   produced to CERT-In on request or with an incident report. This is real
   and citable, and is closer to what our platform actually helps with
   (evidence retention, chain of custody) than to real-time alerting.

**The honest citation, therefore, is narrow**: CERT-In creates a *reporting*
deadline an investigator could plausibly meet faster with tooling that
surfaces findings quickly — it does **not** create a general "real-time
alerting" obligation, and claiming it as the legal basis for this feature
would be citing the wrong clause for what it says. This platform's alerting
should be justified on its own mechanism (B.2), not on CERT-In's 6-hour
rule.

### B.4 What "real-time" means in *this* codebase, checked against the code

| Claim | What the code actually does | File:line |
|---|---|---|
| "Real-time alerting for active threats" (bonus objective, marked ✅) | Alerting only fires from `_run_live_monitor`'s loop, or once at the end of a batch/PCAP analysis | `service.py:157-228`, `alerting.py:210-252` |
| Live monitoring exists | `manage.py capture_live --iface X --window 30` — **CLI only** | `capture_live.py:9-31` |
| Reachable from the web dashboard / API | **No.** `CaptureSessionViewSet` is `ReadOnlyModelViewSet` (`views.py:42`) — there is no endpoint to start a live capture, windowed or not, from the API or UI | `views.py:42` |
| Dashboard shows live findings as they happen | The "operator strip" **polls**, it does not push (`research/120_OBJECTIVES_COMPLIANCE.md:147`: *"the dashboard does not yet stream"*) | — |
| Alert is deduplicated across windows | Fingerprint on `(rule_id, subject_ip, title)`, not row id, so a beacon isn't re-announced every 30s | `service.py:146-154`, tested in `tests_live_monitor.py:204-219` |
| A down SIEM cannot break analysis | Every send wrapped, failures recorded not raised | `alerting.py:210-252`, tested in `tests_alerting.py:133-171` |

None of this is wrong — it is a correct, tested, deliberately-scoped
mechanism. It is just **narrower** than "real-time alerting" suggests on
first read: it is *operator-initiated, terminal-launched, single-machine*
live monitoring with a window-bounded latency, not a system that watches a
network continuously and pushes alerts to a dashboard. The gap between
"exists and is tested" and "is reachable by the people this tool is built
for" is real: an investigating officer using only the web UI (the documented
primary workflow — capture upload, evidence sealing, triage) has no path to
turn this feature on at all today.

### Honest replacement copy

Current framing (`research/120_OBJECTIVES_COMPLIANCE.md:188`):
> *"Real-time alerting for active threats | ✅ | `capture/alerting.py` —
> RFC 5424 syslog over UDP/TCP and ECS webhooks, fired after findings
> persist. Plus a live capture heartbeat in the operator strip"*

Proposed replacement, 4 sentences, specific about mechanism and honest about
reach:

> *"When a capture is run in monitor mode (`capture_live --window N`), every
> N seconds the platform re-analyses the traffic seen so far and pushes any
> new finding — not previously seen ones — to a configured syslog or webhook
> sink; alert latency is therefore bounded by the window, not by when the
> capture ends. This is on-box, single-workstation alerting suited to an
> air-gapped lab, not a continuously-watched network with push notifications
> to a dashboard: monitor mode is started from the command line by an
> operator, and the web UI does not yet expose it. A finding is announced
> once per rule-subject pair and never re-announced while it persists, so the
> channel stays usable across a shift."*

This trades the unqualified "real-time" for a specific, checkable mechanism —
which is the stronger claim in front of anyone who has run a SOC, because it
can't be falsified by asking "real-time compared to what?"

---

## Ranked, buildable improvements

All Python/Django, offline-capable, no new runtime dependency beyond the
stdlib unless noted.

### SIEM integration (Objective A)

1. **Ship a Wazuh decoder + rule pair.** *Effort: small (half a day).* A
   `local_decoder.xml` matching our CEF-in-syslog line and a `rules.xml`
   surfacing `rule_id`, `severity`, `src_ip`, `dst_ip`, `attackTechnique`
   (our `cs3`) as named, searchable Wazuh fields. This is the single change
   that converts "Wazuh can receive our bytes" into "Wazuh can alert on our
   findings" — the actual definition of integration a SOC engineer uses. Cite
   in the repo as a tested artifact (a fixture syslog line decoded against
   the shipped XML), not just a claim.
2. **Emit `ecs.version: "9.5.0"`.** *Effort: trivial (one line).* The one
   field ECS itself calls required and we do not send. `siem.py:107`.
3. **Fix `in`/`out` in CEF.** *Effort: trivial.* `_endpoints()` already knows
   which side is the initiator; split the summed `bytes` into `in` (received)
   and `out` (sent) instead of putting the total in `in`. `siem.py:93,224`.
4. **Add `threat.tactic.reference`.** *Effort: trivial.* Same URL pattern
   already used for technique (`attack_mapping.py:47`), applied to the
   tactic ID. `siem.py:152-155`.
5. **Add `related.ip`.** *Effort: trivial.* `[source.ip, destination.ip]`
   deduplicated — the single field that makes "show me everything involving
   this IP" a one-field query instead of an OR across `source.ip` and
   `destination.ip`. `siem.py:159-168`.
6. **Split `threat.technique.subtechnique.*` from the parent technique.**
   *Effort: moderate (touches `attack_mapping.py`'s return shape and both
   `to_ecs`/`to_cef` assembly).* Needed for any dotted ID (`T1071.004`,
   `T1048.003`) to roll up correctly under its parent in a SOC's ATT&CK
   matrix view.
7. **Separate `@timestamp` (activity time) from `event.created` (detection
   time).** *Effort: moderate.* Requires deciding which flow timestamp
   represents "the activity," likely `flow.first_seen` on the subject flow,
   and threading it through `Detection` or resolving it at export time.
8. **RFC 5424 STRUCTURED-DATA instead of an opaque CEF-as-MSG blob.**
   *Effort: moderate-to-large* — needs an IANA Private Enterprise Number
   (free, turnaround UNVERIFIED) before the SD-ID can be used correctly, plus
   a second syslog code path. Higher value for non-CEF-aware syslog
   consumers (bare rsyslog/syslog-ng) than for Wazuh, which will get more
   value from item 1.
9. **A packaged webhook receiver reference implementation**, e.g. a 30-line
   script unwrapping `findings[]` into individual `_bulk` actions for
   Elasticsearch/OpenSearch. *Effort: small.* Turns the webhook path from
   "you write the glue" into "here is the glue," without changing the wire
   format (so no test in `tests_alerting.py` needs to change).
10. **Use more specific `event.type` values per rule category** (e.g.
    `['connection']` for beaconing, `['indicator']` for IOC feed matches,
    `['denied']`/`['info']` for scans) instead of a constant `['info']`.
    *Effort: small* — a lookup table keyed on `detection.category`.

### Real-time alerting (Objective B)

1. **Expose monitor mode through the API**, even minimally (a `POST
   /api/sessions/live/` that shells out to the same `run_live_capture` path
   used by the CLI, or a documented "how an investigator starts monitoring"
   runbook if the API surface is deliberately out of scope for the hackathon
   timeline). *Effort: moderate.* This is the change that would make the
   "real-time alerting" claim reachable by someone who only uses the web UI,
   which is the platform's own documented primary workflow.
2. **Rewrite the compliance-doc and README claim to name the mechanism**
   (window-bounded latency, CLI-launched, on-box) rather than the
   unqualified word "real-time." *Effort: trivial* — copy edit only, see B.4
   above.
3. **Surface delivery failures somewhere an operator watching the dashboard
   would see them**, not only in the `DeliveryResult` returned from
   `dispatch()`. *Effort: small* — the data already exists
   (`alerting.py:59-86`); today the on-box heartbeat mentioned in the
   compliance doc would need to already be looking at `on_window`'s
   `alerts` key (`service.py:206`) to notice a sink is down.
4. **Do not cite CERT-In's 6-hour rule as the basis for this feature.** *Effort:
   trivial* — it is a reporting deadline to a government agency, not an
   alerting-infrastructure mandate; using it as justification is citing the
   wrong clause (see B.3) and is an easy thing for a technical judge to
   check and find thin.

---

## Sources fetched during this audit

- [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) — version 9.5.0
- [ECS event field set](https://www.elastic.co/docs/reference/ecs/ecs-event)
- [ECS threat field set](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
- [ECS related field set](https://www.elastic.co/docs/reference/ecs/ecs-related)
- [ECS `ecs` field set (ecs.version)](https://www.elastic.co/docs/reference/ecs/ecs-ecs)
- [ECS guidelines](https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html)
- [Micro Focus/OpenText, *Implementing ArcSight CEF*, v25, 28 Sept 2017 (PDF)](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf)
- [RFC 5424 §6.3 STRUCTURED-DATA](https://www.rfc-editor.org/rfc/rfc5424)
- [RFC 6587 §3.4.1 octet-counted framing](https://www.rfc-editor.org/rfc/rfc6587)
- [IANA Private Enterprise Number application](https://pen.iana.org/pen/PenApplication.page)
- [Wazuh `<remote>` configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html)
- [Wazuh JSON/custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
- [NIST SP 800-82 Rev. 3 (OT security, unidirectional gateways)](https://industrialcyber.co/nist/the-essential-guide-to-the-nist-sp-800-82-document/) — secondary summary, primary NIST PDF not fetched directly; **treat the Rev. 3 date (28 Sept 2023) as reported by a secondary source**
- [CERT-In Directions 70B, 28 April 2022 (primary PDF)](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf)
- [Suricata documentation, "What is Suricata"](https://docs.suricata.io/en/latest/what-is-suricata.html)
- [arXiv 2512.09934 — IoT access-control study citing Zeek 11-14s TtD](https://arxiv.org/pdf/2512.09934) — one study, not a general benchmark

**Marked UNVERIFIED in this document** (stated as such at point of use, not
treated as fact): IANA PEN application turnaround time; CISA-specific
air-gapped alerting guidance; Wazuh's own primary-source air-gap/telemetry
claims (checked via search results about Wazuh, not a direct fetch of
wazuh.com's own statement); NIST SP 800-82 Rev. 3's exact publication date
(sourced from a secondary summary, not the NIST PDF itself).
