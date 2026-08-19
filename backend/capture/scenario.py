"""
Attack scenario reconstruction.

What this is
------------
Findings arrive as a list. A list of nine things that happened to one machine
is not a scenario — an officer still has to work out what came first, what it
led to, and what part of the story is missing. This assembles the findings
against each implicated host into an ordered sequence and states plainly what
that sequence does and does not establish.

The three rules it is written under
-----------------------------------
**It reports a sequence of observations, never a proven attack.** Two findings
in kill-chain order are two findings in kill-chain order. Nothing here
establishes that the first caused the second, and the wording never implies it.
An automated narrative that reads like a conclusion is the fastest way to have
the whole exhibit excluded.

**The stages it cannot see are named, not omitted.** ATT&CK Enterprise has
fourteen tactics. Packet capture can evidence four of them. A diagram showing
four filled stages and no mention of the other ten tells the reader the attack
consisted of four steps, which is false — the tool simply was not looking at
the endpoint. `UNOBSERVABLE` below is printed every time.

**Where observed time contradicts kill-chain order, the contradiction wins.**
The tactics have a canonical order and traffic has timestamps, and they do not
always agree. Silently sorting by tactic would manufacture a tidy story out of
evidence that says something else — usually that the capture began partway
through, which is a fact about the exhibit an examiner has to disclose. So the
sequence is ordered by ATT&CK and every disagreement with the clock is
reported beside it.

Determinism
-----------
Pure post-processing over findings already written, with ties broken on the
rule identifier. The same capture produces the same reconstruction on every
run, which is the property that lets an examiner put it in a report.
"""

from collections import defaultdict

from .attack_mapping import UNMAPPED, beaconing_hosts_in, classify

# ATT&CK Enterprise tactic order, by the position each tactic holds on
# attack.mitre.org's own matrix. Written out in full — including the ten this
# tool can never fill — because the gaps are the honest part of the output.
#
# Verified against https://attack.mitre.org/tactics/enterprise/ (v17 matrix
# ordering: Reconnaissance, Resource Development, Initial Access, Execution,
# Persistence, Privilege Escalation, Defense Evasion, Credential Access,
# Discovery, Lateral Movement, Collection, Command and Control, Exfiltration,
# Impact).
TACTIC_ORDER = {
    'TA0043': 1,   # Reconnaissance
    'TA0042': 2,   # Resource Development
    'TA0001': 3,   # Initial Access
    'TA0002': 4,   # Execution
    'TA0003': 5,   # Persistence
    'TA0004': 6,   # Privilege Escalation
    'TA0005': 7,   # Defense Evasion
    'TA0006': 8,   # Credential Access
    'TA0007': 9,   # Discovery
    'TA0008': 10,  # Lateral Movement
    'TA0009': 11,  # Collection
    'TA0011': 12,  # Command and Control
    'TA0010': 13,  # Exfiltration
    'TA0040': 14,  # Impact
}

# Every tactic's name, so the track can be drawn without the frontend keeping
# its own copy of the matrix — two lists of the same thing drift.
TACTIC_NAMES = {
    'TA0043': 'Reconnaissance',
    'TA0042': 'Resource Development',
    'TA0001': 'Initial Access',
    'TA0002': 'Execution',
    'TA0003': 'Persistence',
    'TA0004': 'Privilege Escalation',
    'TA0005': 'Defense Evasion',
    'TA0006': 'Credential Access',
    'TA0007': 'Discovery',
    'TA0008': 'Lateral Movement',
    'TA0009': 'Collection',
    'TA0011': 'Command and Control',
    'TA0010': 'Exfiltration',
    'TA0040': 'Impact',
}

# The tactics a network capture cannot evidence, and why. Each of these
# describes something happening *on* a host; this tool watches the wire.
# Saying so is the difference between "we saw four stages" and "an attack has
# four stages".
UNOBSERVABLE = [
    ('TA0042', 'Resource Development',
     'Infrastructure the attacker built before touching this network. Nothing '
     'about it crosses the monitored link.'),
    ('TA0001', 'Initial Access',
     'How the machine was first compromised. A phishing attachment or a USB '
     'device leaves no packet here; a network exploit would, but only if the '
     'capture was already running when it arrived.'),
    ('TA0002', 'Execution',
     'Code running on the endpoint. Visible to host forensics, not to a tap.'),
    ('TA0003', 'Persistence',
     'Registry keys, services, scheduled tasks — all on disk.'),
    ('TA0004', 'Privilege Escalation',
     'A local privilege change produces no traffic.'),
    ('TA0005', 'Defense Evasion',
     'Disabling a defence is a local act. Its *effect* may show as a gap in '
     'other telemetry, which is not the same as observing it.'),
    ('TA0006', 'Credential Access',
     'Credentials read from memory or a file never reach the wire. Credentials '
     'sent in the clear over FTP or SMTP do, and this tool recovers those from '
     'a transcript — but that is the transmission, not the theft.'),
    ('TA0008', 'Lateral Movement',
     'Internal connections are recorded, but a legitimate administrative '
     'session and a stolen one look identical on the wire. Claiming lateral '
     'movement from a connection alone would be an assertion, not a finding.'),
    ('TA0009', 'Collection',
     'Files being gathered on the endpoint before they leave.'),
    ('TA0040', 'Impact',
     'Encryption, wiping or destruction of data at rest.'),
]


def _window(detection):
    """
    The traffic timestamps behind a finding, or None.

    Deliberately not `created_at`: that is when analysis ran, which is the same
    second for every finding in a capture and would sort the sequence into the
    order the rules happen to be listed in. Only the packet clock can order
    evidence.
    """
    flow = detection.flow
    if flow is None:
        return None
    return flow.first_seen, flow.last_seen


def _peer(detection):
    """Who the finding's conversation was with, from the host's point of view."""
    flow = detection.flow
    if flow is None or not detection.subject_ip:
        return ''
    if flow.src_ip == detection.subject_ip:
        return flow.dst_ip
    if flow.dst_ip == detection.subject_ip:
        return flow.src_ip
    return ''


def _stage_for(detection, beaconing):
    """
    (tactic_id, tactic_name, techniques) for one finding, or None.

    A finding maps to several techniques only when they share a tactic in
    practice — except ICMP tunnelling, which is Command and Control twice over.
    The first technique decides the stage; the rest ride along on it.
    """
    techniques = classify(detection, beaconing)
    if not techniques:
        return None
    lead = techniques[0]
    return lead['tactic_id'], lead['tactic'], techniques


def reconstruct(session, min_findings=1):
    """
    The findings against each implicated host, in kill-chain order.

    `min_findings` raises the bar for appearing at all. One finding is not a
    scenario, so a caller building a summary view can ask for two.
    """
    beaconing = beaconing_hosts_in(session)

    findings = list(
        session.detections
        .filter(subject_ip__isnull=False)
        .select_related('flow')
        .order_by('rule_id', 'id')
    )

    by_host = defaultdict(list)
    for finding in findings:
        by_host[finding.subject_ip].append(finding)

    hosts = []
    for host, host_findings in by_host.items():
        if len(host_findings) < min_findings:
            continue

        stages = {}
        unclassified = []

        for finding in host_findings:
            row = {
                'id': finding.id,
                'rule_id': finding.rule_id,
                'title': finding.title,
                'severity': finding.severity,
                'severity_rank': finding.severity_rank,
                'method': finding.method,
                'peer': _peer(finding),
                'flow': finding.flow_id,
            }
            window = _window(finding)
            row['first_seen'] = window[0].isoformat() if window else None
            row['last_seen'] = window[1].isoformat() if window else None

            stage = _stage_for(finding, beaconing)
            if stage is None:
                # Not a failure. Two of the rules deliberately map to nothing,
                # and their reason travels with them so the gap reads as a
                # decision rather than an omission.
                row['why_no_technique'] = UNMAPPED.get(
                    finding.rule_id,
                    'This rule has no MITRE ATT&CK mapping recorded.',
                )
                unclassified.append(row)
                continue

            tactic_id, tactic_name, techniques = stage
            bucket = stages.setdefault(tactic_id, {
                'tactic_id': tactic_id,
                'tactic': tactic_name,
                'order': TACTIC_ORDER.get(tactic_id, 99),
                'techniques': {},
                'findings': [],
            })
            for technique in techniques:
                bucket['techniques'][technique['id']] = technique
            bucket['findings'].append(row)

        ordered = sorted(stages.values(), key=lambda s: (s['order'], s['tactic_id']))
        for bucket in ordered:
            bucket['techniques'] = sorted(
                bucket['techniques'].values(), key=lambda t: t['id'])
            bucket['findings'].sort(
                key=lambda r: (r['first_seen'] or '', r['rule_id']))
            starts = [r['first_seen'] for r in bucket['findings'] if r['first_seen']]
            ends = [r['last_seen'] for r in bucket['findings'] if r['last_seen']]
            bucket['first_seen'] = min(starts) if starts else None
            bucket['last_seen'] = max(ends) if ends else None
            bucket['severity_rank'] = max(
                (r['severity_rank'] for r in bucket['findings']), default=0)

        conflicts = _time_conflicts(ordered)

        worst = max(host_findings, key=lambda f: f.severity_rank)
        hosts.append({
            'host': host,
            'finding_count': len(host_findings),
            'worst_severity': worst.severity,
            'worst_severity_rank': worst.severity_rank,
            'stages': ordered,
            'stages_observed': len(ordered),
            'unclassified': unclassified,
            'time_conflicts': conflicts,
            'summary': _summarise(host, ordered, unclassified, conflicts),
        })

    hosts.sort(key=lambda h: (-h['worst_severity_rank'], -h['finding_count'], h['host']))

    return {
        'hosts': hosts,
        'tactics_total': len(TACTIC_ORDER),
        # The stages this tool can reach, in order — the track a host's
        # sequence is drawn against. Derived from the two lists above rather
        # than written out a third time, so it cannot disagree with them.
        'observable': [
            {'tactic_id': tid, 'tactic': TACTIC_NAMES[tid], 'order': order}
            for tid, order in sorted(TACTIC_ORDER.items(), key=lambda kv: kv[1])
            if tid not in {row[0] for row in UNOBSERVABLE}
        ],
        'unobservable': [
            {'tactic_id': tid, 'tactic': name, 'reason': reason}
            for tid, name, reason in UNOBSERVABLE
        ],
        'basis': (
            'Stages are ordered by the MITRE ATT&CK Enterprise tactic sequence. '
            'That ordering is a convention for describing adversary behaviour, '
            'not a finding: nothing below establishes that one stage caused the '
            'next. Times are packet timestamps from the exhibit.'
        ),
        'limits': (
            f'{len(UNOBSERVABLE)} of {len(TACTIC_ORDER)} ATT&CK tactics cannot be '
            f'evidenced from network traffic at all and are listed separately. '
            f'A host showing no stage in this reconstruction has not been '
            f'cleared — it has not been implicated by a rule.'
        ),
    }


def _time_conflicts(ordered_stages):
    """
    Where the packet clock disagrees with the kill-chain order.

    Reported rather than smoothed over. A capture in which exfiltration is
    timestamped before the command-and-control channel that supposedly carried
    it is telling the examiner something real — most often that recording began
    after the intrusion was already underway, which is a limitation of the
    exhibit and belongs in the report.
    """
    conflicts = []
    timed = [s for s in ordered_stages if s['first_seen']]
    for earlier, later in zip(timed, timed[1:]):
        if later['first_seen'] < earlier['first_seen']:
            conflicts.append({
                'expected_first': earlier['tactic'],
                'observed_first': later['tactic'],
                'note': (
                    f"{later['tactic']} was recorded before "
                    f"{earlier['tactic']}, which the ATT&CK sequence places "
                    f"earlier. The capture may have begun after this activity "
                    f"started, or the two are unrelated."
                ),
            })
    return conflicts


def _summarise(host, stages, unclassified, conflicts):
    """One sentence an officer can read without expanding anything."""
    if not stages:
        if unclassified:
            return (
                f'{host} carries {len(unclassified)} finding'
                f'{"s" if len(unclassified) != 1 else ""} that map to no ATT&CK '
                f'technique, so no stage sequence can be drawn for it.'
            )
        return f'Nothing recorded against {host}.'

    names = [s['tactic'].lower() for s in stages]
    if len(names) == 1:
        spine = f'was seen at one stage — {names[0]}'
    else:
        spine = 'was seen at ' + ' then '.join(names)

    sentence = f'{host} {spine}.'
    if unclassified:
        sentence += (
            f' {len(unclassified)} further finding'
            f'{"s" if len(unclassified) != 1 else ""} support the picture '
            f'without mapping to a technique.'
        )
    if conflicts:
        sentence += ' The recorded times do not follow that order — see below.'
    return sentence
