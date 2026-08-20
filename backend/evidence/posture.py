"""
What the operator strip in the sidebar reports, assembled in one place.

Why this is one module and one request
--------------------------------------
Everything here is read together or not at all. An officer glances at the
sidebar; they do not read it. Eight separate requests to draw one strip is
eight chances for a partial answer, and a strip that is half-drawn while the
rest is in flight is a strip that flickers all day in the corner of someone's
eye until they stop looking at it — at which point it may as well not exist.

Why these facts and not others
------------------------------
Each one is either an obligation with a date on it, or a state that fails
silently. Those are the two categories worth spending permanent screen space
on. A number that is merely interesting belongs on a page.

The research behind the selection, with the statutory citations and the
verification of each, is in `research/140_SIDEBAR_FEATURE_RESEARCH.md`.

What is deliberately absent
---------------------------
The BNSS s.187(3) default-bail clock, which is the deadline an investigating
officer actually fears. It runs from the date of **arrest**, and this system
has no accused record and no arrest date. Computing it from the FIR date
instead would print a confident wrong deadline on a criminal matter, which is
worse than printing nothing. It is named here so that its absence is a
recorded decision rather than an oversight.
"""

import shutil
from datetime import date
from pathlib import Path

from django.db.models import Count

# ─────────────────────────────────────────────────────────────────────────────
# BNSS 2023 s.193(3)(ii). Verified against two independent reproductions of the
# bare act (see research/140 §1b), which agree on the text:
#
#   "the police officer shall, within a period of ninety days, inform the
#    progress of the investigation by any means including through electronic
#    communication to the informant or the victim."
#
# This is a *notification* duty, not a filing deadline, and it is anchored to
# when the FIR was recorded rather than to arrest. Both distinctions are
# load-bearing: labelling it as anything broader would misstate an officer's
# obligations, so the label travels with the number everywhere it is rendered.
INFORMANT_UPDATE_DAYS = 90

# Free space on the evidence volume. Chosen here rather than borrowed: 15% is
# roughly where a long capture can still complete on a modest workstation
# disk, and 5% is where the filesystem itself starts behaving badly. Both are
# engineering judgement and are labelled as such — no statute governs this.
DISK_WARN_PCT = 15
DISK_CRITICAL_PCT = 5


def triage_backlog():
    """
    Findings nobody has looked at yet, split by how bad they are.

    A count alone answers the wrong question. Ninety unreviewed low-severity
    findings and one unreviewed critical are the same number and completely
    different situations, and it is the second that has to survive being
    glanced at.
    """
    from capture.models import Detection

    rows = (Detection.objects.filter(triage_status=Detection.Triage.NEW)
            .values('severity').annotate(n=Count('id')))
    by_severity = {row['severity']: row['n'] for row in rows}
    total = sum(by_severity.values())

    worst = ''
    for level in ('critical', 'high', 'medium', 'low'):
        if by_severity.get(level):
            worst = level
            break

    return {
        'awaiting_review': total,
        'by_severity': {
            'critical': by_severity.get('critical', 0),
            'high': by_severity.get('high', 0),
            'medium': by_severity.get('medium', 0),
            'low': by_severity.get('low', 0),
        },
        'worst_waiting': worst,
    }


def certificate_state():
    """
    How many s.63 certificates are actually usable, and how many are stranded.

    BSA 2023 s.63(4) requires the certificate to be signed by a person in
    charge of the device **and** an expert — conjunctively. A certificate
    carrying only Part A is not a weaker certificate; it is not a certificate.

    The Gujarat High Court took that seriously enough to set aside an order
    over it (Kshitijbhai Manubhai Patel v. Dilipbhai Laxmanbhai Kanani,
    J.C. Doshi J., 8 May 2026): the certificate "is a condition precedent for
    admissibility ... It cannot be supplemented through oral evidence." The
    practical consequence is that a half-signed certificate discovered in
    court cannot be repaired in court, which is exactly why the count belongs
    where somebody sees it before then.
    """
    from .models import Section63Certificate

    certificates = list(
        Section63Certificate.objects.only('part_a_signed_at', 'part_b_signed_at'))

    complete = sum(1 for c in certificates if c.part_a_signed_at and c.part_b_signed_at)
    awaiting_b = sum(1 for c in certificates
                     if c.part_a_signed_at and not c.part_b_signed_at)
    awaiting_a = sum(1 for c in certificates
                     if c.part_b_signed_at and not c.part_a_signed_at)
    unsigned = sum(1 for c in certificates
                   if not c.part_a_signed_at and not c.part_b_signed_at)

    return {
        'total': len(certificates),
        'complete': complete,
        'awaiting_part_b': awaiting_b,
        'awaiting_part_a': awaiting_a,
        'unsigned': unsigned,
        'incomplete': awaiting_a + awaiting_b + unsigned,
    }


def case_docket(user, limit=4):
    """
    The cases this officer is on, in what capacity, and where the 90-day
    informant clock stands on each.

    Capacity is printed and not merely stored because BSA s.63(4) needs two
    *different* people, and `CaseAssignment` already enforces one capacity per
    officer per case. An officer who can see they are the IO on a case knows
    without asking that they cannot also sign Part B on it.

    Only open cases carry a clock. A case already charge-sheeted or closed
    should not still be nagging about a progress update.
    """
    from .models import Case, CaseAssignment

    if not user or not user.is_authenticated:
        return {'cases': [], 'total': 0, 'updates_due': 0}

    assignments = (CaseAssignment.objects
                   .filter(officer=user)
                   .select_related('case')
                   .order_by('case__opened_on'))

    live_states = {Case.Status.REGISTERED, Case.Status.INVESTIGATION}
    today = date.today()
    rows = []

    for assignment in assignments:
        case = assignment.case
        open_case = case.status in live_states
        # Day 1 is the day the FIR was recorded, which is how a police diary
        # counts. An off-by-one here is a day of an officer's deadline.
        elapsed = (today - case.opened_on).days + 1 if case.opened_on else None

        clock = None
        if open_case and elapsed is not None:
            clock = {
                'day': elapsed,
                'of': INFORMANT_UPDATE_DAYS,
                'overdue': elapsed > INFORMANT_UPDATE_DAYS,
                'days_left': INFORMANT_UPDATE_DAYS - elapsed,
                # The label travels with the number. This is the duty to
                # inform the informant or victim of progress — it is not a
                # deadline to finish the investigation, and it is not the
                # default-bail clock.
                'duty': 'Inform informant/victim of progress',
                'authority': 'BNSS 2023 s.193(3)(ii)',
            }

        rows.append({
            'case_number': case.case_number,
            'title': case.title,
            'fir_number': case.fir_number,
            'police_station': case.police_station,
            'status': case.status,
            'status_label': case.get_status_display(),
            'capacity': assignment.role,
            'capacity_label': assignment.get_role_display(),
            'opened_on': case.opened_on.isoformat() if case.opened_on else None,
            'informant_update': clock,
        })

    due = sum(1 for r in rows
              if r['informant_update'] and r['informant_update']['overdue'])
    # Overdue first, then whichever is closest to falling due.
    rows.sort(key=lambda r: (
        not (r['informant_update'] and r['informant_update']['overdue']),
        r['informant_update']['days_left'] if r['informant_update'] else 10 ** 6,
    ))

    return {'cases': rows[:limit], 'total': len(rows), 'updates_due': due}


def store_headroom():
    """
    Room left on the volume holding the evidence.

    A capture that runs out of disk does not stop cleanly; it produces a file
    that is shorter than the traffic it was recording, and nothing about that
    file announces it. The hash will verify — it is a hash of what was written.
    An exhibit that is intact and incomplete is the worst failure this system
    has, because every check it performs will pass.

    Reported as bytes and a percentage only. Deliberately **no** estimate of
    time or capture size remaining: that depends on traffic nobody has seen
    yet, and a wrong reassurance about how long a capture can run is worse
    than a plain number.
    """
    from django.conf import settings

    root = Path(getattr(settings, 'EVIDENCE_ROOT', None) or settings.BASE_DIR)

    # The store directory is created on first seizure, so before then it does
    # not exist yet — and "cannot stat" would be a misleading answer to "is
    # there room". Walk up to the nearest directory that does exist: that is
    # the volume the store will land on, which is the volume being asked about.
    probe = root
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    path = str(probe)

    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        # A path that cannot be stat'd is itself worth surfacing — it usually
        # means the volume is not mounted, which is the moment before a
        # capture writes into an empty directory on the root filesystem.
        return {'available': False, 'path': str(root), 'error': str(exc)}

    free_pct = (usage.free / usage.total * 100) if usage.total else 0.0
    if free_pct <= DISK_CRITICAL_PCT:
        level = 'critical'
    elif free_pct <= DISK_WARN_PCT:
        level = 'warning'
    else:
        level = 'ok'

    return {
        'available': True,
        'path': str(root),
        'measured_on': path,
        'total_bytes': usage.total,
        'free_bytes': usage.free,
        'used_bytes': usage.used,
        'free_pct': round(free_pct, 1),
        'level': level,
        'warn_below_pct': DISK_WARN_PCT,
        'critical_below_pct': DISK_CRITICAL_PCT,
    }


def capture_heartbeat():
    """
    Whether anything is being recorded right now, and when that was last true.

    The existing capture strip shows the most recent session whatever its
    state, which makes a capture that died ten minutes ago look identical to
    one that is running. On a live monitoring demo that is the difference
    between a working system and a stopped one, and nobody in the room can
    tell which they are looking at.

    `observed_at` is returned with the counts so the reader can see the age of
    the figure rather than assuming it is current.
    """
    from django.utils import timezone
    from capture.models import CaptureSession

    running = list(CaptureSession.objects
                   .filter(state=CaptureSession.State.RUNNING)
                   .order_by('-started_at')[:1])

    if not running:
        last = CaptureSession.objects.order_by('-started_at').first()
        return {
            'running': False,
            'last_session': ({
                'id': last.id,
                'name': last.name,
                'state': last.state,
                'state_label': last.get_state_display(),
                'ended_at': last.ended_at.isoformat() if last.ended_at else None,
            } if last else None),
            'observed_at': timezone.now().isoformat(),
        }

    session = running[0]
    return {
        'running': True,
        'session': {
            'id': session.id,
            'name': session.name,
            'source_type': session.source_type,
            'interface': session.interface,
            'started_at': session.started_at.isoformat(),
            'packet_count': session.packet_count,
            'flow_count': session.flow_count,
        },
        'observed_at': timezone.now().isoformat(),
    }


def custody_reconciliation():
    """
    Exhibits whose sealed case reference disagrees with the case they are
    filed under.

    The system already refuses to rewrite what an exhibit was sealed bearing —
    editing an exhibit's stated provenance so it matches newer software is
    altering the record to fit the tool. The disagreement is logged to the
    custody chain instead, which is correct and also means it is only visible
    to somebody who opens that exhibit's full custody log.

    A disagreement nobody sees is a disagreement that surfaces for the first
    time under cross-examination. So it is counted here.
    """
    from .models import EvidenceRecord

    stale = 0
    for record in (EvidenceRecord.objects
                   .exclude(case__isnull=True)
                   .exclude(case_reference='')
                   .select_related('case')
                   .only('case_reference', 'case__case_number', 'case__fir_number')):
        sealed = (record.case_reference or '').strip().lower()
        known = {(record.case.case_number or '').strip().lower(),
                 (record.case.fir_number or '').strip().lower()}
        known.discard('')
        if sealed and sealed not in known:
            stale += 1

    return {'mismatched_exhibits': stale}


def intel_feeds():
    """
    Which threat-intelligence feeds are loaded, and how old they are.

    This row was deliberately not built until there was a feed to describe —
    an indicator of feed freshness on a system with no feed is chrome
    describing a capability that does not exist. Now that
    `capture/ioc.py` imports them, the state is worth an officer's eyeline for
    one reason: **a feed silently going stale is invisible.** Detection keeps
    running, findings keep appearing, and nothing on screen distinguishes "the
    lists we hold say this traffic is clean" from "the lists we hold are
    fourteen months old and would not know".

    Age is measured from `retrieved_on`, which the importing officer stated,
    not from a file timestamp — see `IOCFeed`.

    The empty case is reported as a fact rather than as a warning. An
    air-gapped workstation nobody has carried a feed to is correctly
    configured, and the detection engine's own rules do not depend on one.
    """
    from datetime import date

    from capture.models import IOCFeed

    feeds = list(IOCFeed.objects.all()[:5])
    if not feeds:
        return {
            'loaded': 0,
            'feeds': [],
            'oldest_days': None,
            'level': 'none',
            'note': (
                'No indicator feed has been imported. Findings rest on this '
                'tool\'s own measured thresholds, which do not need one.'
            ),
        }

    today = date.today()
    rows = []
    for feed in feeds:
        age = (today - feed.retrieved_on).days
        rows.append({
            'name': feed.name,
            'entry_count': feed.entry_count,
            'retrieved_on': feed.retrieved_on.isoformat(),
            'age_days': age,
        })

    oldest = max(row['age_days'] for row in rows)
    # Judgement, not statute, and labelled as such wherever it is shown.
    # A blocklist a month old is ordinary; one past a quarter is describing an
    # internet that has moved on.
    if oldest > 90:
        level = 'stale'
    elif oldest > 30:
        level = 'ageing'
    else:
        level = 'current'

    return {
        'loaded': len(rows),
        'feeds': rows,
        'oldest_days': oldest,
        'level': level,
        'note': (
            'Age is measured from the date the importing officer stated the '
            'file was obtained.'
        ),
    }
