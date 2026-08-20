"""Evidence intake, custody chain maintenance, and certificate issue."""

import os
import re
import shutil
import uuid
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import crypto
from .models import (
    Case, CaseAssignment, CustodyEvent, EvidenceRecord, Section63Certificate,
    hash_file,
)


# Exhibit numbers become filenames inside the evidence store, so they are
# constrained to characters that cannot escape it. `../` in an exhibit number
# would write the sealed copy anywhere the process can reach, and the record
# would still claim the file was safely in custody. Only the CLI supplies this
# today; a validation that depends on which caller happens to reach the code is
# not a validation.
EXHIBIT_NUMBER_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')


def validate_exhibit_number(value):
    if not EXHIBIT_NUMBER_PATTERN.match(value or ''):
        raise ValueError(
            f"Refusing exhibit number {value!r}: it becomes a filename in the "
            f"evidence store, so it must be 1-100 characters of letters, "
            f"digits, dot, dash or underscore, starting with a letter or digit."
        )
    return value


def _next_sequence(evidence):
    last = evidence.custody_events.order_by('-sequence').first()
    return (last.sequence + 1) if last else 1


def record_custody(evidence, action, actor=None, detail='', actor_ip=None):
    """
    Append a hash-chained entry to an exhibit's custody log.

    The entry hash covers the previous entry's hash, so the log can be
    replayed and verified end to end; see verify_custody_chain.
    """
    previous = evidence.custody_events.order_by('-sequence').first()

    event = CustodyEvent(
        evidence=evidence,
        sequence=_next_sequence(evidence),
        action=action,
        actor=actor,
        actor_badge=getattr(actor, 'badge_id', '') or '',
        actor_ip=actor_ip,
        detail=detail,
        previous_hash=previous.entry_hash if previous else '',
    )
    # timestamp is auto_now_add, so the row must exist before it can be hashed.
    event.save()
    event.entry_hash = event.compute_hash()
    event.save(update_fields=['entry_hash'])
    return event


def verify_custody_chain(evidence):
    """
    Replay the custody log and re-derive every link.

    Returns (ok, problems). A break tells you exactly which sequence number
    failed, which is what an investigator would be asked in cross-examination.
    """
    problems = []
    expected_previous = ''

    for event in evidence.custody_events.order_by('sequence'):
        if event.previous_hash != expected_previous:
            problems.append(
                f"entry #{event.sequence}: previous_hash does not match entry "
                f"#{event.sequence - 1}"
            )
        recomputed = event.compute_hash()
        if recomputed != event.entry_hash:
            problems.append(f"entry #{event.sequence}: content has been altered")
        expected_previous = event.entry_hash

    return (not problems), problems


@transaction.atomic
def link_evidence_to_case(evidence, case, actor=None, actor_ip=None):
    """
    Attach an exhibit to an investigation, and say so in the custody log.

    Two things this refuses to do:

    It will not move an exhibit that is already on another case. Reassignment
    is a decision with consequences for a filed report, so it has to be an
    explicit unlink first rather than an overwrite that leaves no trace.

    It will not touch `case_reference`, `fir_number` or `police_station` on an
    exhibit that already has them. Those record what was written down at
    seizure. If they disagree with the Case, that disagreement is a fact about
    the investigation and the officer needs to see it, not have it tidied away.
    """
    if evidence.case_id and evidence.case_id != case.id:
        raise ValueError(
            f'{evidence.exhibit_number} is already on case '
            f'{evidence.case.case_number}; unlink it before reassigning.'
        )
    if evidence.case_id == case.id:
        return evidence

    evidence.case = case
    evidence.save(update_fields=['case'])

    detail = f'Linked to case {case.reference_line}'
    stated = evidence.case_reference or evidence.fir_number
    if stated and case.case_number not in stated and case.fir_number not in stated:
        # Surfaced rather than corrected. See the docstring.
        detail += (
            f' — note: the exhibit was sealed bearing the reference '
            f'"{stated}", which does not match this case.'
        )
    record_custody(
        evidence, CustodyEvent.Action.CASE_LINKED,
        actor=actor, detail=detail, actor_ip=actor_ip,
    )
    return evidence


@transaction.atomic
def ingest_evidence(
    source_path,
    original_filename=None,
    exhibit_number=None,
    collected_by=None,
    case_reference='',
    fir_number='',
    police_station='',
    seized_from='',
    device_make_model='',
    device_serial='',
    device_identifier='',
    acquisition_notes='',
    provenance=None,
    actor_ip=None,
):
    """
    Take custody of a capture file.

    The file is copied into the evidence store and hashed *before* anything
    reads it for analysis, so the recorded digest describes the artefact as
    received. The copy is what we keep; the original stays where it was.

    Provenance is read from the sidecar manifest beside the source file, if
    there is one, and can be overridden by an explicit `provenance` — which is
    how an officer declares a capture SEIZED. Neither path can silently claim
    a generated file is evidence: the manifest wins over nothing, and an
    explicit declaration is recorded as a declaration.
    """
    from capture.provenance import read_manifest, describe

    source = Path(source_path)
    if not source.exists():
        raise FileNotFoundError(f"No such capture file: {source}")

    manifest = read_manifest(source)
    if provenance:
        declared_provenance = provenance
        provenance_detail = describe(manifest) if manifest else ''
        if manifest and manifest['kind'] != provenance:
            # Someone is declaring a file to be something the tool that made
            # it says it is not. Recording both is the only honest option.
            provenance_detail = (
                f"Declared '{provenance}' at intake, but the sidecar manifest "
                f"says '{manifest['kind']}'. {provenance_detail}"
            )
    elif manifest:
        declared_provenance = manifest['kind']
        provenance_detail = describe(manifest)
    else:
        declared_provenance = EvidenceRecord.Provenance.UNATTESTED
        provenance_detail = (
            'No provenance manifest accompanied this file and no origin was '
            'declared at intake.'
        )

    prefix = getattr(settings, 'EXHIBIT_PREFIX', 'NF')
    exhibit_number = validate_exhibit_number(exhibit_number or (
        f"{prefix}-{timezone.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
    ))

    store = Path(settings.EVIDENCE_ROOT)
    store.mkdir(parents=True, exist_ok=True)
    # Belt and braces: the suffix comes from a path the caller chose, so it is
    # taken as a name rather than trusted as a path fragment.
    suffix = Path(source.suffix or '.pcap').name
    destination = store / f"{exhibit_number}{suffix}"
    if destination.parent.resolve() != store.resolve():
        raise ValueError(
            f"Refusing to write {destination} — it falls outside the evidence store."
        )
    shutil.copy2(source, destination)

    # Hash before encrypting. The digest that goes on the certificate is of the
    # capture as seized, which is the only digest anyone outside this system
    # can reproduce from the same file.
    digests, size = hash_file(destination)

    encrypted_at_rest = False
    encryption_algorithm = ''
    key = crypto.load_key(create=True)
    if key is not None:
        # Written alongside and swapped in, so a failure part-way through
        # leaves the plaintext copy intact rather than a half-encrypted file
        # that no longer hashes to anything.
        sealed = destination.with_suffix(destination.suffix + '.enc')
        crypto.encrypt_file(destination, sealed, key)
        os.replace(sealed, destination)
        encrypted_at_rest = True
        encryption_algorithm = crypto.ALGORITHM

    # Carry the provenance manifest into the store beside the sealed copy.
    #
    # Without this the statement of origin stays next to the *original* file,
    # and re-importing the sealed copy — which is exactly what someone does
    # when reprocessing an exhibit — produced a new record marked "unattested".
    # A synthetic capture would have quietly downgraded to "origin unknown",
    # which is less alarming than the truth. The manifest carries the file's
    # digest, so the copy still only describes the bytes it was written for.
    if manifest is not None:
        from capture.provenance import manifest_path as _manifest_path

        try:
            shutil.copy2(_manifest_path(source), _manifest_path(destination))
        except OSError:
            # A missing or unreadable sidecar is not a reason to refuse
            # custody of the evidence; the origin is already recorded on the
            # record itself.
            pass

    record = EvidenceRecord.objects.create(
        exhibit_number=exhibit_number,
        original_filename=original_filename or source.name,
        stored_path=str(destination),
        file_size_bytes=size,
        encrypted_at_rest=encrypted_at_rest,
        encryption_algorithm=encryption_algorithm,
        sha256_hash=digests['sha256'],
        md5_hash=digests.get('md5', ''),
        sha1_hash=digests.get('sha1', ''),
        acquisition_timestamp=timezone.now(),
        case_reference=case_reference,
        fir_number=fir_number,
        police_station=police_station,
        seized_from=seized_from,
        device_make_model=device_make_model,
        device_serial=device_serial,
        device_identifier=device_identifier,
        acquisition_notes=acquisition_notes,
        provenance=declared_provenance,
        provenance_detail=provenance_detail,
        collected_by=collected_by,
        last_verified_at=timezone.now(),
    )

    record_custody(
        record, CustodyEvent.Action.ACQUIRED, actor=collected_by,
        detail=(
            f"Acquired from {source.name} ({size:,} bytes) · "
            f"provenance: {record.get_provenance_display()}"
        ),
        actor_ip=actor_ip,
    )
    record_custody(
        record, CustodyEvent.Action.HASHED, actor=collected_by,
        detail=(
            f"SHA256={digests['sha256']} "
            f"SHA1={digests.get('sha1', '')} MD5={digests.get('md5', '')}"
        ),
        actor_ip=actor_ip,
    )
    return record


def issue_certificate(
    evidence,
    session=None,
    part_a_user=None,
    part_a_name='', part_a_designation='', part_a_organisation='', part_a_address='',
    part_b_user=None,
    part_b_name='', part_b_designation='', part_b_organisation='', part_b_qualification='',
    findings_summary='',
    actor_ip=None,
):
    """
    Issue a s.63 certificate over an exhibit.

    Integrity is re-verified first: certifying a hash we have not just checked
    would defeat the purpose. A failed check raises rather than producing a
    certificate that asserts something untrue.
    """
    ok, computed = evidence.verify()
    if not ok:
        raise ValueError(
            f"Refusing to certify {evidence.exhibit_number}: integrity check failed "
            f"(expected {evidence.sha256_hash}, computed {computed})"
        )

    prefix = getattr(settings, 'CERTIFICATE_PREFIX', 'S63')
    reference = f"{prefix}-{timezone.now():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"

    device_description = ' · '.join(filter(None, [
        evidence.get_device_type_display(),
        evidence.device_make_model,
        f"S/N {evidence.device_serial}" if evidence.device_serial else '',
        evidence.device_identifier,
    ]))

    certificate = Section63Certificate.objects.create(
        evidence=evidence,
        session=session,
        reference=reference,
        part_a_user=part_a_user,
        part_a_name=part_a_name or getattr(part_a_user, 'get_full_name', lambda: '')() or getattr(part_a_user, 'username', ''),
        part_a_designation=part_a_designation,
        part_a_organisation=part_a_organisation,
        part_a_address=part_a_address,
        part_a_relationship=evidence.custodian_relationship,
        part_a_signed_at=timezone.now() if part_a_user else None,
        part_b_user=part_b_user,
        part_b_name=part_b_name or getattr(part_b_user, 'username', ''),
        part_b_designation=part_b_designation,
        part_b_organisation=part_b_organisation,
        part_b_qualification=part_b_qualification,
        part_b_signed_at=timezone.now() if part_b_user else None,
        certified_sha256=evidence.sha256_hash,
        certified_md5=evidence.md5_hash,
        certified_sha1=evidence.sha1_hash,
        device_description=device_description,
        findings_summary=findings_summary,
    )

    record_custody(
        evidence, CustodyEvent.Action.CERTIFICATE_ISSUED,
        actor=part_b_user or part_a_user,
        detail=f"Certificate {reference} issued", actor_ip=actor_ip,
    )

    # Imported here rather than at module scope: certificate_pdf reads the
    # custody chain back through this module, and a top-level import would
    # close the cycle.
    from .certificate_pdf import render_certificate_pdf
    render_certificate_pdf(certificate)

    return certificate


def _is_examiner_for(user, evidence):
    """
    Whether this account may sign Part B for this exhibit.

    Two ways to qualify, and both are deliberate:

      the **account role** is FSL / Examiner — the ordinary case, an officer
      posted to the laboratory rather than to the investigation;

      or they hold the **EXPERT capacity on the case** this exhibit is filed
      under — which is how a qualified officer seconded to one matter is
      handled without changing what they are on every other matter.

    Administrators and Django superusers qualify because somebody has to be
    able to finish a certificate on a single-officer installation. That is a
    deliberate loosening and it is visible here rather than buried: an
    administrator signing Part B is recorded as an administrator signing Part B.
    """
    from accounts.models import User

    if user is None:
        return False
    if getattr(user, 'is_superuser', False):
        return True
    if getattr(user, 'role', None) in (User.Role.EXPERT, User.Role.ADMIN):
        return True

    case = getattr(evidence, 'case', None)
    if case is None:
        return False
    return case.assignments.filter(
        officer=user, role=CaseAssignment.Role.EXPERT,
    ).exists()


def sign_part_b(certificate, user, name='', designation='', organisation='',
                qualification='', actor_ip=None):
    """
    Countersign a certificate as the expert, then re-render it.

    Part B is a separate act by a different person — s.63(4) requires the
    person in charge *and* an expert — so it is a separate call rather than a
    field on issue. Integrity is re-checked first: an expert should not be
    attesting to a hash that no longer matches the file.
    """
    from django.utils import timezone

    # s.63(4) contemplates two different people: the person in charge of the
    # device, and an expert. If one account can sign both parts, the two-part
    # form guarantees nothing — and this code previously only *described* that
    # safeguard in a comment while allowing exactly it.
    if (
        certificate.part_a_user_id
        and getattr(user, 'pk', None)
        and certificate.part_a_user_id == user.pk
    ):
        raise ValueError(
            f"Refusing to countersign {certificate.reference}: Part A was signed by "
            f"'{getattr(user, 'username', user)}'. Section 63(4) requires the person in "
            f"charge of the device and an expert to be different people; a certificate "
            f"signed twice by one account attests to nothing."
        )

    # Two *different accounts* was the whole check, and it is not enough.
    #
    # Any two investigators satisfy it, and investigators are interchangeable —
    # so the guarantee reduced to "somebody remembered to use a second login".
    # The statute asks for the person in charge of the device and an expert,
    # which is a claim about what the second signatory *is*, not about their
    # session. So the countersignatory has to hold examiner standing: the
    # account role, or the EXPERT capacity on the case this exhibit is filed
    # under.
    #
    # The per-case capacity is honoured because a real FSL examiner is assigned
    # to a matter, and because it makes the assignment in the case file mean
    # something rather than being a label in a sidebar.
    if not _is_examiner_for(user, certificate.evidence):
        raise ValueError(
            f"Refusing to countersign {certificate.reference}: "
            f"'{getattr(user, 'username', user)}' does not hold examiner "
            f"standing. Part B is the expert's attestation — the signatory "
            f"must hold the FSL / Examiner role, or be assigned to this case "
            f"as its examiner."
        )

    ok, computed = certificate.evidence.verify()
    if not ok:
        raise ValueError(
            f"Refusing to countersign {certificate.reference}: integrity check failed "
            f"(expected {certificate.evidence.sha256_hash}, computed {computed})"
        )

    certificate.part_b_user = user
    certificate.part_b_name = name or getattr(user, 'username', '')
    certificate.part_b_designation = designation
    certificate.part_b_organisation = organisation
    certificate.part_b_qualification = qualification
    certificate.part_b_signed_at = timezone.now()
    certificate.save(update_fields=[
        'part_b_user', 'part_b_name', 'part_b_designation',
        'part_b_organisation', 'part_b_qualification', 'part_b_signed_at',
    ])

    record_custody(
        certificate.evidence, CustodyEvent.Action.PART_B_SIGNED, actor=user,
        detail=f"Certificate {certificate.reference} Part B signed by {certificate.part_b_name}",
        actor_ip=actor_ip,
    )

    from .certificate_pdf import render_certificate_pdf
    render_certificate_pdf(certificate)
    return certificate
