"""
The FSL forwarding package.

The manual work this removes
-----------------------------
An investigating officer sending a digital exhibit to a Forensic Science
Laboratory hand-writes a forwarding letter and a memo of evidence: the exhibit
number, the FIR, the sections invoked, the seal, the hash, what examination is
requested, and who is sending it. Every one of those facts is already recorded
in this system, on the exhibit, at the moment it was sealed. Re-typing them
into a letter is transcription — the kind of work that produces exactly one
kind of error, a transposed hash, and produces it silently.

So the letter is generated from the record rather than retyped from it.

Why this is the honest form of "integration with cybercrime systems"
---------------------------------------------------------------------
ICJS — the Inter-operable Criminal Justice System — integrates CCTNS (police),
eCourts, ePrisons, eProsecution and **eForensics**, the module that links police
to FSLs. Its stated design principle is *ONE DATA ONCE ENTRY*: a fact typed
once and reused, rather than re-keyed at each handoff.

A live connection to ICJS is not something a team can build. NCRB is the nodal
agency and NIC the technology partner; access requires firewall clearance
arranged between a state's NIC coordinator and the ICJS team. That is a
procedural gate, and no code opens it.

What *is* buildable, and what this is, is the other half: producing the
artefacts that handoff consists of, from data entered once, in a form a person
or an integrator can carry across. The claim this supports is "we produce what
eForensics consumes and expose it over an API" — which is true — and not "we
are integrated with CCTNS", which is not.

Nothing here should be described as an ICJS or CCTNS integration.
"""

from django.utils import timezone

from .certificate_pdf import ist

# The examinations a network capture can actually be sent for.
#
# Deliberately narrow. A forwarding letter that requests analysis the exhibit
# cannot support wastes an FSL's time and returns a report saying so, weeks
# later. A packet capture supports questions about traffic; it does not support
# device examination, and this list does not offer it.
EXAMINATIONS = (
    ('integrity', 'Verification of the exhibit hash against the accompanying '
                  'certificate under section 63(4) BSA'),
    ('traffic', 'Examination of network traffic contained in the capture, '
                'including endpoints contacted and volumes transferred'),
    ('malware_c2', 'Identification of command-and-control communication '
                   'patterns and the infrastructure contacted'),
    ('exfiltration', 'Examination for indications of data transfer out of the '
                     'monitored network'),
    ('tunnelling', 'Examination for covert channels — data carried inside DNS, '
                   'ICMP or non-standard-port traffic'),
)


def build_package(evidence, *, requested=(), officer=None, addressed_to='',
                  sections='', remarks=''):
    """
    Everything the forwarding letter states, as a dict, from the record.

    Returned as data rather than rendered text so the same facts drive the PDF,
    the API and any future integrator without a second transcription — which is
    the whole point.
    """
    # `sessions`, not `session`: the reverse accessor from an exhibit to the
    # captures analysed from it is plural, and asking for the singular returned
    # None without complaining — so the letter reported zero findings for an
    # exhibit that had thirty-five. An exhibit is normally analysed once, so
    # the most recent is the one this letter describes.
    session = evidence.sessions.order_by('-id').first()
    certificate = evidence.certificates.order_by('-generated_at').first()
    findings = list(session.detections.all()) if session else []

    by_severity = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    chosen = [
        (key, text) for key, text in EXAMINATIONS
        if not requested or key in requested
    ]

    return {
        'generated_at': timezone.now(),
        'addressed_to': addressed_to or 'Directorate of Forensic Science, Gandhinagar',

        # The case, as recorded once at seizure.
        'case': {
            'fir_number': evidence.fir_number,
            'police_station': evidence.police_station,
            'case_reference': evidence.case_reference,
            'sections': sections,
        },

        # The exhibit, as sealed.
        'exhibit': {
            'exhibit_number': evidence.exhibit_number,
            'original_filename': evidence.original_filename,
            'size_bytes': evidence.file_size_bytes,
            'sha256': evidence.sha256_hash,
            'md5': evidence.md5_hash,
            'sealed_at': evidence.created_at,
            'seized_from': evidence.seized_from,
            'device_make_model': evidence.device_make_model,
            'device_serial': evidence.device_serial,
            'provenance': evidence.get_provenance_display(),
            # Stated on the letter because an FSL should never be asked to
            # examine demonstration data as though it were an exhibit.
            'is_demonstration_only': evidence.is_demonstration_only,
        },

        'certificate': {
            'reference': certificate.reference if certificate else None,
            'complete': certificate.is_complete if certificate else False,
        },

        'custody': {
            'entries': evidence.custody_events.count(),
            'last_action': (
                evidence.custody_events.order_by('-sequence').first().get_action_display()
                if evidence.custody_events.exists() else None
            ),
        },

        # What this office already found, so the FSL knows what is being
        # corroborated rather than starting cold.
        'preliminary_findings': {
            'total': len(findings) if session else 0,
            'by_severity': by_severity,
            'engine_version': _engine_version(),
        },

        'examinations_requested': chosen,
        'forwarding_officer': {
            'username': getattr(officer, 'username', ''),
            'badge_id': getattr(officer, 'badge_id', ''),
            'department': getattr(officer, 'department', ''),
        },
        'remarks': remarks,
    }


def _engine_version():
    from netforensiq_backend.version import get_version
    return get_version()


def render_forwarding_letter(evidence, path=None, **kwargs):
    """Render the forwarding letter and memo of evidence as a PDF."""
    from django.conf import settings
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    from .certificate_pdf import _styles

    data = build_package(evidence, **kwargs)
    styles = _styles()

    root = settings.CERTIFICATE_ROOT
    root.mkdir(parents=True, exist_ok=True)
    path = path or root / f'fsl-forwarding-{evidence.exhibit_number}.pdf'

    def para(text, style):
        return Paragraph(text, style)

    def table(rows, widths=(50 * mm, 115 * mm)):
        body = [
            [para(f'<b>{k}</b>', styles['field']), para(str(v or '—'), styles['field'])]
            for k, v in rows
        ]
        t = Table(body, colWidths=list(widths))
        t.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#999999')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        return t

    story = [
        para('FORWARDING LETTER AND MEMO OF EVIDENCE', styles['title']),
        para('Digital exhibit — network packet capture', styles['subtitle']),
        Spacer(1, 6),
    ]

    if data['exhibit']['is_demonstration_only']:
        story.append(para(
            'DEMONSTRATION DATA — DO NOT FORWARD. This exhibit was generated '
            'or obtained for demonstration. It is not evidence and must not be '
            'submitted for examination.',
            ParagraphStyle('warn', parent=styles['note'],
                           textColor=colors.HexColor('#B3261E'),
                           borderWidth=1, borderPadding=5,
                           borderColor=colors.HexColor('#B3261E')),
        ))
        story.append(Spacer(1, 6))

    story += [
        para(f"To: {data['addressed_to']}", styles['body']),
        para(f"Date: {ist(data['generated_at']):%d/%m/%Y}", styles['body']),
        Spacer(1, 6),
        para('1. CASE PARTICULARS', styles['annex']),
        table([
            ('FIR number', data['case']['fir_number']),
            ('Police station', data['case']['police_station']),
            ('Case reference', data['case']['case_reference']),
            ('Sections', data['case']['sections']),
        ]),
        Spacer(1, 6),
        para('2. EXHIBIT FORWARDED', styles['annex']),
        table([
            ('Exhibit number', data['exhibit']['exhibit_number']),
            ('Description', 'Network packet capture (.pcap)'),
            ('Original filename', data['exhibit']['original_filename']),
            ('Size', f"{data['exhibit']['size_bytes']:,} bytes"),
            ('Sealed at', f"{ist(data['exhibit']['sealed_at']):%d/%m/%Y %H:%M:%S} IST"),
            ('Seized from', data['exhibit']['seized_from']),
            ('Origin', data['exhibit']['provenance']),
        ]),
        Spacer(1, 4),
        para('3. SEAL — HASH VALUES AT THE TIME OF SEIZURE', styles['annex']),
        para(
            'These are the values recorded when the exhibit was taken into '
            'custody, before it was read for analysis. The receiving officer '
            'is requested to verify them before unsealing.',
            styles['note'],
        ),
        table([
            ('SHA-256', data['exhibit']['sha256']),
            ('MD5', data['exhibit']['md5']),
            ('s.63(4) certificate', data['certificate']['reference']),
            ('Certificate complete',
             'Yes — both parts signed' if data['certificate']['complete']
             else 'No — Part B not yet countersigned'),
            ('Custody entries', data['custody']['entries']),
        ]),
        Spacer(1, 6),
        para('4. EXAMINATION REQUESTED', styles['annex']),
    ]

    for index, (_key, text) in enumerate(data['examinations_requested'], start=1):
        story.append(para(f'{index}. {text}', styles['body']))

    story += [
        Spacer(1, 6),
        para('5. PRELIMINARY EXAMINATION BY THIS OFFICE', styles['annex']),
        para(
            f"An automated examination recorded "
            f"{data['preliminary_findings']['total']} findings "
            f"(NetForensiq {data['preliminary_findings']['engine_version']}). "
            f"These are provided so the laboratory knows what is being put to "
            f"it; they are the output of this office's own tooling and are not "
            f"a substitute for examination.",
            styles['body'],
        ),
    ]
    if data['preliminary_findings']['by_severity']:
        story.append(table(
            sorted(data['preliminary_findings']['by_severity'].items()),
            widths=(50 * mm, 40 * mm),
        ))

    if data['remarks']:
        story += [Spacer(1, 6), para('6. REMARKS', styles['annex']),
                  para(data['remarks'], styles['body'])]

    officer = data['forwarding_officer']
    story += [
        Spacer(1, 14),
        para('Forwarded by', styles['field']),
        para(
            f"{officer['username'] or '—'}"
            + (f" ({officer['badge_id']})" if officer['badge_id'] else '')
            + (f", {officer['department']}" if officer['department'] else ''),
            styles['field'],
        ),
        Spacer(1, 12),
        para('Signature: ____________________________', styles['field']),
    ]

    SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f'FSL forwarding — {evidence.exhibit_number}',
    ).build(story)
    return path
