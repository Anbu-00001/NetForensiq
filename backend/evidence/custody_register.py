"""
The Chain of Custody Register, in the form a charge sheet has to carry it.

Why this file exists
--------------------
Two requirements landed on Indian investigators within a year of each other,
and both of them describe a document this system can already produce from its
own tables:

  Bharatiya Nagarik Suraksha Sanhita 2023, s.193(3)(i) — the report a police
  officer files on completion of investigation must state "the sequence of
  custody in case of electronic device". Not "should"; it is an enumerated
  content requirement of the report itself.

  Kattavellai @ Devakar v. State of Tamil Nadu, 2025 INSC 845 (15 July 2025) —
  the Supreme Court directed that "a Chain of Custody Register shall be
  maintained wherein each and every movement of the evidence shall be recorded
  with counter sign at each end thereof stating also the reason therefor", kept
  from collection through to conviction or acquittal and placed on the trial
  court record.

  That judgment arose on DNA evidence and its directions are framed for DNA.
  We do not claim it governs packet captures. What it settles is what a court
  now expects a custody register to contain, and there is no reason the answer
  would be narrower for an electronic device than for a swab.

What this is not
----------------
It is not a signature. The Supreme Court asked for a counter-signature at each
movement by the person making it; a database row recording who was logged in is
not that. The register prints a signature column and leaves it empty, because
the officer signs the printed page. Software that pre-filled that column would
be manufacturing the very attestation the direction exists to obtain.
"""

from django.utils import timezone

from .models import CustodyEvent
from .service import verify_custody_chain
from . import timesource


# The column that gets signed. It is printed empty and it stays empty.
SIGNATURE_COLUMN = 'Signature of officer making the entry'

# What each custody action means in the words a register uses, rather than in
# the words a schema uses. 'analysed' is a movement of the evidence in the
# sense the direction means: someone had it and did something to it.
ACTION_WORDING = {
    CustodyEvent.Action.ACQUIRED: 'Seized / taken into custody',
    CustodyEvent.Action.HASHED: 'Hash value computed and recorded',
    CustodyEvent.Action.VERIFIED: 'Integrity re-verified against recorded hash',
    CustodyEvent.Action.ANALYSED: 'Examined',
    CustodyEvent.Action.VIEWED: 'Accessed for viewing',
    CustodyEvent.Action.EXPORTED: 'Copy exported',
    CustodyEvent.Action.TRANSFERRED: 'Custody transferred',
    CustodyEvent.Action.CERTIFICATE_ISSUED: 'Certificate under BSA 2023 s.63 issued',
    CustodyEvent.Action.PART_B_SIGNED: 'Certificate Part B countersigned by examiner',
    CustodyEvent.Action.CASE_LINKED: 'Associated with case record',
}


def _actor_of(event):
    """Who made the entry, named the way a register names a person."""
    if not event.actor:
        return 'Not recorded'
    user = event.actor
    name = (f'{user.first_name} {user.last_name}'.strip() or user.username)
    badge = event.actor_badge or getattr(user, 'badge_id', '')
    return f'{name} (Badge {badge})' if badge else name


def build_register(evidence):
    """
    The register for one exhibit, as ordered rows plus the header a court needs.

    Returns a dict rather than a rendered page so the same content can go to
    PDF, to the API, or into the forwarding letter without three copies of the
    wording drifting apart.
    """
    case = evidence.case
    chain_ok, problems = verify_custody_chain(evidence)

    entries = []
    for event in evidence.custody_events.order_by('sequence'):
        entries.append({
            'sequence': event.sequence,
            'timestamp': event.timestamp,
            'movement': ACTION_WORDING.get(event.action, event.get_action_display()),
            'officer': _actor_of(event),
            'from_ip': event.actor_ip or '',
            # The direction asks for the reason for each movement, not only the
            # fact of it. This is the field that carries it.
            'reason': event.detail or 'Not recorded',
            'entry_hash': event.entry_hash,
            'previous_hash': event.previous_hash,
            'signature': '',
        })

    return {
        'statutory_basis': (
            'Sequence of custody of electronic device, furnished under section '
            '193(3)(i) of the Bharatiya Nagarik Suraksha Sanhita, 2023, in the '
            'form of a Chain of Custody Register as directed in Kattavellai @ '
            'Devakar v. State of Tamil Nadu, 2025 INSC 845.'
        ),
        'case': {
            'case_number': case.case_number if case else '',
            'fir_number': (case.fir_number if case else '') or evidence.fir_number,
            'police_station': (case.police_station if case else '') or evidence.police_station,
            'district': case.district if case else '',
            'offence_sections': case.offence_sections if case else '',
            # Printed when the exhibit predates the case record, so the reader
            # can see which identifier came from where.
            'reference_on_exhibit': evidence.case_reference,
        },
        'exhibit': {
            'exhibit_number': evidence.exhibit_number,
            'description': evidence.original_filename,
            'device_type': evidence.get_device_type_display(),
            'device_make_model': evidence.device_make_model,
            'device_serial': evidence.device_serial,
            'size_bytes': evidence.file_size_bytes,
            'sha256': evidence.sha256_hash,
            'acquired_at': evidence.acquisition_timestamp,
            'seized_from': evidence.seized_from,
            'status': evidence.get_status_display(),
        },
        'entries': entries,
        'integrity': {
            'chain_intact': chain_ok,
            'problems': problems,
            # A register that says "verified" without saying what verified it is
            # asking to be taken on trust.
            'method': (
                'Each entry stores the SHA-256 digest of the entry before it. '
                'The chain above was replayed and every digest re-derived at '
                'the time this page was produced.'
            ),
        },
        'signature_column': SIGNATURE_COLUMN,
        'produced_at': timezone.now(),
        # An entry timestamped by a clock nobody vouched for is worth less
        # than one that says so. The register carries the state of the clock
        # that stamped it.
        'clock': timesource.summary_line(),
        'demonstration_only': evidence.is_demonstration_only,
    }
