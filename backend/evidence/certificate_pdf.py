"""
Render a BSA 2023 s.63(4)(c) certificate as a PDF.

The layout is not a design of ours. It reproduces THE SCHEDULE to the Bharatiya
Sakshya Adhiniyam, 2023 — its wording, its field order, and its tick-boxes —
because a court receives the prescribed form, not a summary of it. The verbatim
text was taken from the bare Act on indiacode.nic.in; see
research/SPEC_01_EVIDENCE_INTEGRITY.md and research/95_ESAKSHYA_VERIFIED_FINDINGS.md.

Two rules govern everything below:

1. **Statutory blanks stay blank.** The Schedule asks for facts we may not hold
   (a parent's name, the device's colour). Where we do not know, the line is
   printed empty for a human to complete in ink. Filling it with a plausible
   value would be forging a statutory declaration.

2. **An unsigned certificate is visibly unsigned.** s.63(4) requires Part A and
   Part B conjunctively. A PDF missing either is stamped DRAFT — NOT A VALID
   CERTIFICATE across every page, so it cannot be mistaken for a filed document.

Tick-boxes are drawn as [X] / [ ] rather than ☑ / ☐: the Unicode box glyphs are
absent from reportlab's built-in Type1 fonts and render as a blank or a black
square depending on the viewer, which on a legal form is worse than plain ASCII.
"""

from pathlib import Path
from zoneinfo import ZoneInfo

from django.conf import settings
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Flowable, Frame, PageBreak, PageTemplate, Paragraph,
    Spacer, Table, TableStyle,
)

from .models import CustodianRelationship, DeviceType, HashAlgorithm

# THE SCHEDULE prints the device types in this order across two lines. We keep
# the order because an officer comparing our output against the bare Act should
# find the same form, not a reordered one.
DEVICE_ROWS = [
    [DeviceType.COMPUTER, DeviceType.DVR, DeviceType.MOBILE, DeviceType.FLASH_DRIVE],
    [DeviceType.CD_DVD, DeviceType.SERVER, DeviceType.CLOUD, DeviceType.OTHER],
]

RELATIONSHIPS = [
    CustodianRelationship.OWNED, CustodianRelationship.MAINTAINED,
    CustodianRelationship.MANAGED, CustodianRelationship.OPERATED,
]

# Verbatim from the Schedule, Part A. Reproduced rather than paraphrased.
PART_A_DECLARATION = (
    "The digital device or the digital record source was under the lawful control for "
    "regularly creating, storing or processing information for the purposes of carrying out "
    "regular activities and during this period, the computer or the communication device was "
    "working properly and the relevant information was regularly fed into the computer during "
    "the ordinary course of business. If the computer/digital device at any point of time was "
    "not working properly or out of operation, then it has not affected the electronic/digital "
    "record or its accuracy. The digital device or the source of the digital record is:—"
)

AFFIRMATION = (
    "do hereby solemnly affirm and sincerely state and submit as follows:—"
)



# Datetimes are stored UTC-aware (settings.TIME_ZONE = 'UTC', USE_TZ = True),
# and Python's strftime formats an aware datetime in its own tzinfo. So a bare
# f"{value:%H:%M}" under a label reading "Time (IST)" printed UTC while
# claiming IST — five and a half hours wrong, with the date rolling back a day
# for anything between 00:00 and 05:30 IST.
#
# On a document whose whole purpose is to fix a fact in time, under a statutory
# declaration, that is the worst defect this file could carry. Every timestamp
# printed here goes through ist() and nowhere else.
IST = ZoneInfo('Asia/Kolkata')


def ist(value):
    """The same instant, expressed in Indian Standard Time."""
    if value is None:
        return None
    if timezone.is_naive(value):
        # A naive datetime cannot be converted; assume it was already local
        # rather than silently shifting it by the UTC offset.
        return value
    return timezone.localtime(value, IST)

def _styles():
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle(
            'title', parent=base['Normal'], fontName='Helvetica-Bold',
            fontSize=12.5, leading=16, alignment=TA_CENTER, spaceAfter=2,
        ),
        'subtitle': ParagraphStyle(
            'subtitle', parent=base['Normal'], fontName='Helvetica',
            fontSize=9, leading=12, alignment=TA_CENTER, spaceAfter=8,
        ),
        'part': ParagraphStyle(
            'part', parent=base['Normal'], fontName='Helvetica-Bold',
            fontSize=11, leading=14, alignment=TA_CENTER, spaceBefore=6, spaceAfter=1,
        ),
        'body': ParagraphStyle(
            'body', parent=base['Normal'], fontName='Helvetica',
            fontSize=9.2, leading=13, alignment=TA_JUSTIFY, spaceAfter=5,
        ),
        'field': ParagraphStyle(
            'field', parent=base['Normal'], fontName='Helvetica',
            fontSize=9.2, leading=14, spaceAfter=2,
        ),
        'mono': ParagraphStyle(
            'mono', parent=base['Normal'], fontName='Courier',
            fontSize=8, leading=11, spaceAfter=2,
        ),
        'note': ParagraphStyle(
            'note', parent=base['Normal'], fontName='Helvetica-Oblique',
            fontSize=7.6, leading=10, textColor=colors.HexColor('#555555'), spaceAfter=4,
        ),
        'annex': ParagraphStyle(
            'annex', parent=base['Normal'], fontName='Helvetica-Bold',
            fontSize=10.5, leading=14, spaceBefore=8, spaceAfter=4,
        ),
    }


def _box(ticked):
    return '[X]' if ticked else '[  ]'


def _blank(value, width=34):
    """A filled value, or an underscore rule for a human to complete in ink."""
    return str(value) if value else '_' * width


def _tickrow(choices, selected, styles):
    """One row of the Schedule's tick-box grid."""
    cells = [
        Paragraph(f"{_box(choice == selected)} {choice.label}", styles['field'])
        for choice in choices
    ]
    # The first column is wider: "Computer/Storage Media" is the longest label
    # in the Schedule and wraps to two lines in an even split, which makes the
    # form look mis-set against the printed Act.
    table = Table([cells], colWidths=[52 * mm, 40 * mm, 40 * mm, 38 * mm][:len(cells)])
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
    ]))
    return table


def _hash_block(certificate, styles):
    """
    The Schedule's algorithm tick-list.

    It names SHA1, SHA256 and MD5 explicitly, so all three lines are printed
    even though we do not compute SHA1 — an absent line would misrepresent the
    form. Ours are ticked and filled; the rest stay empty.
    """
    declared = certificate.certified_algorithm
    rows = [
        (HashAlgorithm.SHA1, ''),
        (HashAlgorithm.SHA256, certificate.certified_sha256),
        (HashAlgorithm.MD5, certificate.certified_md5),
    ]

    flow: list[Flowable] = [Paragraph(
        "I state that the HASH value/s of the electronic/digital record/s is as set out "
        "below, obtained through the following algorithm:—", styles['body'],
    )]
    for algorithm, value in rows:
        ticked = bool(value) and (algorithm == declared or algorithm == HashAlgorithm.MD5)
        flow.append(Paragraph(
            f"{_box(ticked)} <b>{algorithm.label}:</b> "
            f"<font face='Courier' size='8'>{value or '&nbsp;' * 20}</font>",
            styles['field'],
        ))
    flow.append(Paragraph(
        f"{_box(False)} Other______________ (Legally acceptable standard)", styles['field'],
    ))
    flow.append(Paragraph(
        "(Hash report to be enclosed with the certificate)", styles['note'],
    ))
    return flow


def _device_block(evidence, styles):
    flow: list[Flowable] = [Paragraph(
        "I have produced electronic record/output of the digital record taken from the "
        "following device/digital record source (tick mark):—", styles['body'],
    )]
    for row in DEVICE_ROWS:
        flow.append(_tickrow(row, evidence.device_type, styles))
    flow.extend([
        Spacer(1, 3),
        Paragraph(
            f"Make &amp; Model: {_blank(evidence.device_make_model, 24)} &nbsp;&nbsp; "
            f"Color: {_blank('', 16)}", styles['field'],
        ),
        Paragraph(f"Serial Number: {_blank(evidence.device_serial, 24)}", styles['field']),
        Paragraph(
            f"IMEI/UIN/UID/MAC/Cloud ID {_blank(evidence.device_identifier, 24)} "
            f"(as applicable)", styles['field'],
        ),
    ])
    return flow


def _signature_block(name, designation, organisation, signed_at, caption, styles):
    """
    The Schedule's signature footer.

    Part A is captioned "(Name and signature)"; Part B "(Name, designation and
    signature)" — the difference is in the Act and is preserved.
    """
    when = ist(signed_at)
    rows = [[
        Paragraph(
            f"Date (DD/MM/YYYY): {when:%d/%m/%Y}<br/>"
            f"Time (IST): {when:%H:%M} hours (In 24 hours format)<br/>"
            f"Place: {_blank('', 22)}"
            if when else
            f"Date (DD/MM/YYYY): {_blank('', 12)}<br/>"
            f"Time (IST): {_blank('', 8)} hours (In 24 hours format)<br/>"
            f"Place: {_blank('', 22)}",
            styles['field'],
        ),
        Paragraph(
            f"<br/><br/>{'_' * 34}<br/>"
            f"{name or ''}"
            + (f"<br/>{designation}" if designation else '')
            + (f"<br/>{organisation}" if organisation else '')
            + f"<br/><font size='7.6'><i>{caption}</i></font>",
            styles['field'],
        ),
    ]]
    table = Table(rows, colWidths=[88 * mm, 82 * mm])
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    return table


def _part_a(certificate, styles):
    evidence = certificate.evidence
    flow: list[Flowable] = [
        Paragraph('PART A', styles['part']),
        Paragraph('(To be filled by the Party)', styles['subtitle']),
        Paragraph(
            f"I, {_blank(certificate.part_a_name, 30)} (Name), "
            f"Son/daughter/spouse of {_blank('', 26)} "
            f"residing/employed at {_blank(certificate.part_a_organisation or certificate.part_a_address, 30)} "
            f"{AFFIRMATION}",
            styles['body'],
        ),
    ]
    flow.extend(_device_block(evidence, styles))
    flow.append(Paragraph(
        "and any other relevant information, if any, about the device/digital record "
        f"{_blank(evidence.acquisition_notes, 20)} (specify).", styles['field'],
    ))
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(PART_A_DECLARATION, styles['body']))
    flow.append(_tickrow(RELATIONSHIPS, certificate.part_a_relationship, styles))
    flow.append(Paragraph('by me (select as applicable).', styles['field']))
    flow.append(Spacer(1, 4))
    flow.extend(_hash_block(certificate, styles))
    flow.append(_signature_block(
        certificate.part_a_name, certificate.part_a_designation,
        certificate.part_a_organisation, certificate.part_a_signed_at,
        '(Name and signature)', styles,
    ))
    return flow


def _part_b(certificate, styles):
    evidence = certificate.evidence
    flow: list[Flowable] = [
        Paragraph('PART B', styles['part']),
        Paragraph('(To be filled by the Expert)', styles['subtitle']),
        Paragraph(
            f"I, {_blank(certificate.part_b_name, 30)} (Name), "
            f"Son/daughter/spouse of {_blank('', 26)} "
            f"residing/employed at {_blank(certificate.part_b_organisation, 30)} "
            f"{AFFIRMATION}",
            styles['body'],
        ),
        Paragraph(
            "The produced electronic record/output of the digital record are obtained from "
            "the following device/digital record source (tick mark):—", styles['body'],
        ),
    ]
    for row in DEVICE_ROWS:
        flow.append(_tickrow(row, evidence.device_type, styles))
    flow.extend([
        Spacer(1, 3),
        Paragraph(
            f"Make &amp; Model: {_blank(evidence.device_make_model, 24)} &nbsp;&nbsp; "
            f"Color: {_blank('', 16)}", styles['field'],
        ),
        Paragraph(f"Serial Number: {_blank(evidence.device_serial, 24)}", styles['field']),
        Paragraph(
            f"IMEI/UIN/UID/MAC/Cloud ID {_blank(evidence.device_identifier, 24)} "
            "(as applicable)", styles['field'],
        ),
        Spacer(1, 4),
    ])
    flow.extend(_hash_block(certificate, styles))

    if certificate.part_b_qualification:
        # s.63 does not define "expert". Recording the qualification lets the
        # court assess competence rather than take the title on trust.
        flow.append(Paragraph(
            f"<b>Qualification of expert:</b> {certificate.part_b_qualification}",
            styles['field'],
        ))
    flow.append(_signature_block(
        certificate.part_b_name, certificate.part_b_designation,
        certificate.part_b_organisation, certificate.part_b_signed_at,
        '(Name, designation and signature)', styles,
    ))
    return flow


def _hash_report(certificate, styles):
    """
    The enclosure the Schedule asks for: "(Hash report to be enclosed with the
    certificate)".

    This is the working that backs the single hash value on the form — what was
    hashed, when, with which tool, and every verification since.
    """
    evidence = certificate.evidence
    flow: list[Flowable] = [
        Paragraph('ANNEXURE 1 — HASH REPORT', styles['annex']),
        Paragraph(
            "Enclosed pursuant to THE SCHEDULE to the Bharatiya Sakshya Adhiniyam, 2023, "
            "which requires a hash report to accompany the certificate.", styles['note'],
        ),
    ]
    rows = [
        ['Exhibit number', evidence.exhibit_number],
        ['Original filename', evidence.original_filename],
        ['Size (bytes)', f"{evidence.file_size_bytes:,}"],
        ['Acquired (IST)', f"{ist(evidence.acquisition_timestamp):%d/%m/%Y %H:%M:%S}"],
        ['SHA-256', certificate.certified_sha256],
        ['MD5', certificate.certified_md5 or '(not computed)'],
        ['Algorithm declared', certificate.get_certified_algorithm_display()],
        ['Integrity status', evidence.get_status_display()],
        ['Last verified (IST)',
         f"{ist(evidence.last_verified_at):%d/%m/%Y %H:%M:%S}" if evidence.last_verified_at else '—'],
        ['Case reference', evidence.case_reference or '—'],
    ]
    table = Table(
        [[Paragraph(f"<b>{k}</b>", styles['field']), Paragraph(v, styles['mono'])]
         for k, v in rows],
        colWidths=[46 * mm, 124 * mm],
    )
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#999999')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F2F2F2')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    flow.append(table)
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(
        "Digests were computed by streaming the file in 1 MiB chunks through Python's "
        "hashlib (OpenSSL). SHA-256 is the primary digest. MD5 is reproduced only because "
        "the Schedule prints a checkbox for it; it is not relied upon alone and is known to "
        "be vulnerable to collision attack.", styles['note'],
    ))
    return flow


def _custody_annexure(certificate, styles):
    """
    ANNEXURE 2 — the custody chain.

    Not required by the Schedule. It is included because the first question put
    to an exhibit is who has held it, and it is labelled as our own addition so
    nobody reads it as a statutory requirement.
    """
    from .service import verify_custody_chain

    evidence = certificate.evidence
    ok, problems = verify_custody_chain(evidence)

    flow: list[Flowable] = [
        Paragraph('ANNEXURE 2 — CHAIN OF CUSTODY', styles['annex']),
        Paragraph(
            "Not prescribed by the Schedule. Included as a matter of practice: each entry "
            "carries the SHA-256 digest of the entry before it, so any alteration to a past "
            "entry breaks every link that follows and is detectable by replay.",
            styles['note'],
        ),
    ]

    header = ['#', 'Action', 'Officer', 'Timestamp (IST)', 'Entry hash (first 16)']
    body: list[list[Flowable]] = [[
        Paragraph(f"<b>{h}</b>", styles['field']) for h in header
    ]]
    for event in evidence.custody_events.order_by('sequence'):
        body.append([
            Paragraph(str(event.sequence), styles['field']),
            Paragraph(event.get_action_display(), styles['field']),
            Paragraph(
                (event.actor.username if event.actor else 'system')
                + (f" ({event.actor_badge})" if event.actor_badge else ''),
                styles['field'],
            ),
            Paragraph(f"{ist(event.timestamp):%d/%m/%Y %H:%M:%S}", styles['field']),
            Paragraph(event.entry_hash[:16], styles['mono']),
        ])

    table = Table(body, colWidths=[10 * mm, 38 * mm, 34 * mm, 42 * mm, 46 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#999999')),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E8E8E8')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    flow.append(table)
    flow.append(Spacer(1, 4))

    verdict = ('Chain verified intact: every entry re-derives to its recorded digest.'
               if ok else
               'CHAIN BROKEN — ' + '; '.join(problems))
    flow.append(Paragraph(
        f"<b>Verification at time of issue:</b> {verdict}",
        ParagraphStyle('verdict', parent=styles['field'],
                       textColor=colors.HexColor('#1A7F37' if ok else '#B3261E')),
    ))
    return flow


def _decorate(canvas, doc, certificate):
    """Header, footer, and the draft watermark on an unsigned certificate."""
    canvas.saveState()
    width, height = A4

    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(colors.HexColor('#666666'))
    canvas.drawString(18 * mm, height - 10 * mm, f"Certificate {certificate.reference}")
    canvas.drawRightString(
        width - 18 * mm, height - 10 * mm,
        f"Exhibit {certificate.evidence.exhibit_number}",
    )
    canvas.drawCentredString(
        width / 2, 10 * mm,
        f"Page {doc.page}  ·  Generated by NetForensiq  ·  "
        f"{ist(certificate.generated_at):%d/%m/%Y %H:%M} IST",
    )

    if not certificate.is_complete:
        canvas.setFont('Helvetica-Bold', 34)
        canvas.setFillColor(colors.Color(0.85, 0.15, 0.15, alpha=0.16))
        canvas.saveState()
        canvas.translate(width / 2, height / 2)
        canvas.rotate(38)
        canvas.drawCentredString(0, 0, 'DRAFT — NOT A VALID CERTIFICATE')
        canvas.restoreState()

    canvas.restoreState()


def render_certificate_pdf(certificate, output_path=None):
    """
    Write the certificate to disk and return the path.

    The rendered PDF is a faithful reproduction of THE SCHEDULE with our known
    facts filled in. Unknown statutory fields are left as blank rules to be
    completed by hand; an unsigned certificate is watermarked DRAFT.
    """
    if output_path is None:
        root = Path(settings.CERTIFICATE_ROOT)
        root.mkdir(parents=True, exist_ok=True)
        output_path = root / f"{certificate.reference}.pdf"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = _styles()
    doc = BaseDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"BSA s.63 Certificate {certificate.reference}",
        author='NetForensiq',
        subject=f"Exhibit {certificate.evidence.exhibit_number}",
    )
    frame = Frame(
        doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='body',
    )
    doc.addPageTemplates([PageTemplate(
        id='cert', frames=[frame],
        onPage=lambda c, d: _decorate(c, d, certificate),
    )])

    story: list[Flowable] = [
        Paragraph('THE SCHEDULE', styles['title']),
        Paragraph('[See section 63(4)(c)]', styles['subtitle']),
        Paragraph('CERTIFICATE', styles['title']),
        Paragraph(
            'under the Bharatiya Sakshya Adhiniyam, 2023', styles['subtitle'],
        ),
    ]

    if not certificate.is_complete:
        missing = []
        if not certificate.part_a_signed_at:
            missing.append('Part A (person in charge)')
        if not certificate.part_b_signed_at:
            missing.append('Part B (expert)')
        story.append(Paragraph(
            f"<b>INCOMPLETE.</b> Section 63(4) requires both parts. Unsigned: "
            f"{', '.join(missing)}. This document is not a valid certificate until signed.",
            ParagraphStyle('warn', parent=styles['field'],
                           textColor=colors.HexColor('#B3261E'),
                           borderColor=colors.HexColor('#B3261E'),
                           borderWidth=0.6, borderPadding=5, spaceAfter=8),
        ))

    story.extend(_part_a(certificate, styles))
    story.append(PageBreak())
    story.extend(_part_b(certificate, styles))
    story.append(PageBreak())
    story.extend(_hash_report(certificate, styles))
    story.append(Spacer(1, 8))
    story.extend(_custody_annexure(certificate, styles))

    if certificate.findings_summary:
        story.append(PageBreak())
        story.append(Paragraph('ANNEXURE 3 — ANALYST FINDINGS', styles['annex']))
        story.append(Paragraph(
            "Not prescribed by the Schedule, and not evidence. This is opinion computed "
            "from the exhibit, reproduced so the court can see what was asserted and on "
            "what basis.", styles['note'],
        ))
        for line in certificate.findings_summary.split('\n'):
            if line.strip():
                story.append(Paragraph(line.strip(), styles['field']))

    doc.build(story)

    certificate.pdf_path = str(output_path)
    certificate.save(update_fields=['pdf_path'])
    return output_path
