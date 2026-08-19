"""
The forensic report.

What this is, and what the §63 certificate is not
-------------------------------------------------
`certificate_pdf.py` renders the statutory form: a declaration, in the words
THE SCHEDULE prescribes, that a particular file has a particular hash. It is
short by design and says nothing about what was found.

This is the other document — the one an investigating officer attaches to a
case file and a supervisor reads before deciding what to do. It states what was
captured, what the engine found, why each finding was made, which machines are
implicated, and what remains unproven. It is written to be read by someone who
does not know what a flow is.

Two rules it is written under
-----------------------------
**Every claim carries its basis.** A finding is never printed as a bare
assertion: it appears with the rule that produced it, the value observed, the
threshold compared against, and where that threshold came from. Twenty-three of
the thirty-five thresholds are the team's own heuristics rather than published
figures, and the report says so on the page where they are used.

**What was not established is stated.** A report that only lists hits reads as
a conclusion. This one names the limits — that a statistical anomaly proves
nothing, that protocol labels are mostly port inference, that an unsynchronised
clock makes timestamps machine-relative.
"""

from collections import defaultdict

from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle,
)

from . import timesource
from .certificate_pdf import ist, _styles

# Severity order for presentation — worst first, because a report read under
# time pressure is read from the top.
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low')

SEVERITY_COLOUR = {
    'critical': colors.HexColor('#B3261E'),
    'high': colors.HexColor('#C2591E'),
    'medium': colors.HexColor('#8A6D1F'),
    'low': colors.HexColor('#2A5C8A'),
}

# How many findings of one kind are printed in full before the rest are
# summarised. A port scan can produce three hundred findings that differ only
# in destination; printing them all buries the two that matter.
FULL_DETAIL_PER_RULE = 5

# Plain-language glosses. The report keeps the technical term — an officer
# should learn it — and puts the meaning beside it once, at first use.
PLAIN_LANGUAGE = {
    'C2_BEACON_PERIODIC': (
        'A machine contacting the same outside address on a regular rhythm. '
        'People browse irregularly; software checking in with a controller '
        'does not.'
    ),
    'C2_BEACON_KEEPALIVE': (
        'One connection held open and fed small messages at a steady interval '
        '— the same behaviour as above, hidden inside a single conversation '
        'instead of repeated ones.'
    ),
    'DNS_TUNNEL_LONG_LABEL': (
        'Data hidden inside domain-name lookups. The name being looked up is '
        'far longer than any real hostname.'
    ),
    'DNS_TUNNEL_SUBDOMAIN_VOLUME': (
        'An unusual number of different names queried under one domain — the '
        'pattern left by data being carried out in pieces.'
    ),
    'RECON_PORT_SCAN': (
        'One machine trying many doors on many machines, looking for one that '
        'opens.'
    ),
    'EXFIL_VOLUME_ASYMMETRY': (
        'Far more data leaving than arriving on a connection, which is the '
        'reverse of ordinary browsing.'
    ),
    'ICMP_TUNNEL_OVERSIZED': (
        'Data carried inside network test messages ("ping"), which normally '
        'carry nothing.'
    ),
    'COVERT_CHANNEL_UNKNOWN_PORT': (
        'A long-running connection on a port no known service uses, carrying '
        'traffic the system could not identify.'
    ),
    'HOST_CORROBORATED': (
        'Several independent rules pointing at the same machine. This is the '
        'strongest signal the system produces, because the rules do not share '
        'reasoning.'
    ),
    'ANOMALY_STATISTICAL': (
        'Traffic that stands apart from everything else in this same capture. '
        'A statistical observation, not a rule — it proves nothing on its own '
        'and is a reason to look, not a conclusion.'
    ),
}


def _para(text, style):
    return Paragraph(text, style)


def _kv_table(rows, styles, widths=(45 * mm, 120 * mm)):
    body = [
        [_para(f'<b>{k}</b>', styles['field']), _para(str(v), styles['field'])]
        for k, v in rows
    ]
    table = Table(body, colWidths=list(widths))
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#BBBBBB')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    return table


def _cover(session, evidence, styles):
    flow = [
        _para('FORENSIC EXAMINATION REPORT', styles['title']),
        _para('Network and packet analysis', styles['subtitle']),
        Spacer(1, 6),
    ]

    if evidence and evidence.is_demonstration_only:
        # The loudest thing on the first page, because a demonstration report
        # that reads like a real one is the most damaging artefact this system
        # could produce.
        flow.append(_para(
            'DEMONSTRATION DATA — NOT EVIDENCE. The capture examined here was '
            'generated or obtained for demonstration and describes no real '
            'incident, person or device.',
            ParagraphStyle('demo', parent=styles['note'],
                           textColor=colors.HexColor('#B3261E'),
                           borderWidth=1, borderPadding=5,
                           borderColor=colors.HexColor('#B3261E')),
        ))
        flow.append(Spacer(1, 6))

    rows = [
        ('Report generated', f'{ist(timezone.now()):%d/%m/%Y %H:%M:%S} IST'),
        ('Capture session', f'#{session.id} — {session.name}'),
        ('Source', session.get_source_type_display()),
    ]
    if evidence:
        rows += [
            ('Exhibit number', evidence.exhibit_number),
            ('SHA-256', evidence.sha256_hash),
            ('Origin', evidence.get_provenance_display()),
        ]
        if evidence.fir_number:
            rows.append(('FIR number', evidence.fir_number))
        if evidence.police_station:
            rows.append(('Police station', evidence.police_station))
    else:
        rows.append(('Exhibit', 'Not sealed — this capture is not in evidence'))

    if session.capture_start:
        rows.append((
            'Traffic captured',
            f'{ist(session.capture_start):%d/%m/%Y %H:%M:%S} IST'
            + (f' to {ist(session.capture_end):%H:%M:%S}' if session.capture_end else ''),
        ))
    rows += [
        ('Packets examined', f'{session.packet_count:,}'),
        ('Conversations', f'{session.flows.count():,}'),
    ]

    flow.append(_kv_table(rows, styles))
    return flow


def _what_was_found(session, styles):
    counts = defaultdict(int)
    for severity in session.detections.values_list('severity', flat=True):
        counts[severity] += 1
    total = sum(counts.values())

    flow = [
        _para('1. SUMMARY OF FINDINGS', styles['annex']),
    ]

    if not total:
        flow.append(_para(
            'The detection rules produced no findings for this capture. That '
            'is not the same as the traffic being clean: it means nothing in '
            'it matched the behaviours these ten rules describe.',
            styles['body'],
        ))
        return flow

    body = [[
        _para('<b>Severity</b>', styles['field']),
        _para('<b>Findings</b>', styles['field']),
        _para('<b>What this level means</b>', styles['field']),
    ]]
    meanings = {
        'critical': 'Several independent rules implicate the same machine.',
        'high': 'A rule matched with a wide margin over its threshold.',
        'medium': 'A rule matched, or the traffic is statistically unusual.',
        'low': 'A weak signal, recorded for completeness.',
    }
    for severity in SEVERITY_ORDER:
        if not counts.get(severity):
            continue
        body.append([
            _para(f'<b>{severity.upper()}</b>',
                  ParagraphStyle(f's{severity}', parent=styles['field'],
                                 textColor=SEVERITY_COLOUR[severity])),
            _para(str(counts[severity]), styles['field']),
            _para(meanings[severity], styles['field']),
        ])

    table = Table(body, colWidths=[28 * mm, 22 * mm, 115 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#999999')),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E8E8E8')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    flow.append(table)
    flow.append(Spacer(1, 4))

    # The machines, ranked. This is the question an officer is actually asking.
    implicated = (
        session.detections.filter(subject_ip__isnull=False)
        .values('subject_ip').distinct().count()
    )
    flow.append(_para(
        f'{total} findings were recorded across {implicated} machines. '
        f'Section 2 lists them by machine, worst first.',
        styles['body'],
    ))
    return flow


def _by_host(session, styles):
    from capture.attack_mapping import (
        beaconing_hosts_in, describe as attack_describe,
    )

    beacon_hosts = beaconing_hosts_in(session)
    flow = [_para('2. FINDINGS BY MACHINE', styles['annex'])]

    hosts = defaultdict(list)
    for finding in session.detections.select_related('flow').order_by('-severity_rank'):
        hosts[finding.subject_ip or '(no single machine)'].append(finding)

    if not hosts:
        flow.append(_para('No findings to report.', styles['body']))
        return flow

    ranked = sorted(
        hosts.items(),
        key=lambda item: max(f.severity_rank for f in item[1]),
        reverse=True,
    )

    for ip, findings in ranked:
        block = [
            _para(f'<b>{ip}</b> — {len(findings)} '
                  f'{"finding" if len(findings) == 1 else "findings"}',
                  styles['part']),
        ]

        seen_rules = defaultdict(int)
        for finding in findings:
            seen_rules[finding.rule_id] += 1

        printed = defaultdict(int)
        for finding in findings:
            printed[finding.rule_id] += 1
            if printed[finding.rule_id] > FULL_DETAIL_PER_RULE:
                continue

            block.append(_para(
                f'<b>{finding.severity.upper()}</b> · {finding.rule_id} — '
                f'{finding.title}',
                ParagraphStyle(f'f{finding.id}', parent=styles['field'],
                               textColor=SEVERITY_COLOUR.get(
                                   finding.severity, colors.black)),
            ))
            gloss = PLAIN_LANGUAGE.get(finding.rule_id)
            if gloss and printed[finding.rule_id] == 1:
                block.append(_para(f'<i>{gloss}</i>', styles['note']))

            # The ATT&CK classification, once per rule. Included because it is
            # the vocabulary a SOC and every threat report already share, so a
            # reader can look the behaviour up somewhere other than here. Two
            # of our rules map to nothing, and the report says so rather than
            # leaving a blank that reads as an oversight.
            if printed[finding.rule_id] == 1:
                block.append(_para(
                    f'<b>Classification:</b> {attack_describe(finding, beacon_hosts)}',
                    styles['note'],
                ))
            if finding.rationale:
                block.append(_para(finding.rationale, styles['note']))
            block.append(Spacer(1, 3))

        for rule_id, count in seen_rules.items():
            if count > FULL_DETAIL_PER_RULE:
                block.append(_para(
                    f'… and {count - FULL_DETAIL_PER_RULE} further '
                    f'{rule_id} findings against this machine, differing only '
                    f'in the other endpoint. The full set is in the case '
                    f'record.',
                    styles['note'],
                ))

        block.append(Spacer(1, 6))
        flow.append(KeepTogether(block))

    return flow


def _limits(session, styles):
    """
    What this report does not establish.

    Placed last and never omitted. A report that lists only what was found
    reads as a conclusion, and the honest limits are the part a competent
    defence will reach for first.
    """
    clock = timesource.describe()

    observed = session.flows.filter(app_protocol_source='observed').count()
    total_labelled = session.flows.exclude(app_protocol='').count()

    points = [
        'These rules detect <b>behaviour</b>, not identity. Traffic matching a '
        'rule shows a machine acted in a described way; it does not establish '
        'who was at the keyboard.',

        'Findings marked <b>ANOMALY_STATISTICAL</b> are observations that '
        'traffic stood apart from the rest of this capture. No threshold was '
        'compared and nothing is proven by them.',

        f'Of the thirty-five thresholds this engine compares against, '
        f'twenty-three are the examining team’s own heuristics rather than '
        f'published figures. Each finding names the threshold it used and its '
        f'source; those marked [OUR HEURISTIC] have no external authority.',

        'This system is tamper-<b>evident</b>, not tamper-proof. The custody '
        'chain reveals alteration; it does not prevent it.',

        'MITRE ATT&amp;CK identifiers classify the <b>behaviour observed</b> '
        'against a public catalogue. They are a shared vocabulary, not a '
        'finding of fact, and they do not attribute the behaviour to any '
        'group or person. Two of the ten rules carry no identifier because no '
        'technique honestly describes them.',
    ]

    if total_labelled:
        share = observed / total_labelled * 100
        points.append(
            f'Application protocols were positively observed for {observed:,} '
            f'of {total_labelled:,} labelled conversations ({share:.0f}%). The '
            f'remainder are inferred from the port number, which a tunnel '
            f'hiding on a permitted port would defeat.'
        )

    if clock['synchronisation'] != timesource.SYNCHRONISED:
        points.append(
            f'<b>Time basis:</b> {clock["note"]} Timestamps in this report '
            f'should be read as recorded by the examining machine.'
        )

    flow = [_para('3. LIMITS OF THIS EXAMINATION', styles['annex'])]
    for point in points:
        flow.append(_para(f'• {point}', styles['body']))
        flow.append(Spacer(1, 2))
    return flow


def render_investigation_report(session, path=None):
    """Render the report for one capture session. Returns the file path."""
    from django.conf import settings

    evidence = getattr(session, 'evidence', None)
    root = settings.CERTIFICATE_ROOT
    root.mkdir(parents=True, exist_ok=True)
    path = path or root / f'report-session-{session.id}.pdf'

    styles = _styles()
    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f'Forensic examination report — session {session.id}',
    )

    story = []
    story += _cover(session, evidence, styles)
    story.append(Spacer(1, 8))
    story += _what_was_found(session, styles)
    story.append(PageBreak())
    story += _by_host(session, styles)
    story.append(PageBreak())
    story += _limits(session, styles)

    doc.build(story)
    return path
