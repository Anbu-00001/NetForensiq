"""
Build a complete demonstration dataset.

Everything here is deliberate about one thing: **a demo must not be able to
pass itself off as a case.** Three rules follow from that.

1. Real traffic first. If `reference_captures/` holds the published captures
   (see scripts/fetch_reference_captures.sh) they are used, because a detector
   finding attacks in traffic the same codebase planted proves only that the
   two agree. Generated traffic is the fallback, not the default.

2. Statutory fields are filled with values no one could mistake for real. The
   case reference is literally `DEMO-NOT-A-REAL-CASE`. A plausible-looking FIR
   number on a Section 63 certificate would be a forged statutory declaration,
   and this command writes into the same database the dev server serves.

3. Provenance travels. Every exhibit carries where its bytes came from, so the
   register and the certificate say "reference capture" or "SYNTHETIC" rather
   than presenting demo traffic as seized evidence.
"""

import os
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand

from capture.detection import analyse_session
from capture.home_net import suggest
from capture.models import CaptureSession, Detection
from capture.provenance import read_manifest
from evidence.models import EvidenceRecord, Section63Certificate
from evidence.service import issue_certificate, sign_part_b

# Not an FIR number. Not in any format a court registry uses. That is the point.
DEMO_CASE_REFERENCE = 'DEMO-NOT-A-REAL-CASE'
DEMO_SEIZED_FROM = 'Demonstration dataset — no seizure took place'

# The two accounts exist as two accounts because s.63(4) requires the person in
# charge of the device and the expert to be different people, and the service
# layer refuses a certificate signed twice by one account.
DEMO_ACCOUNTS = [
    {
        'username': 'analyst',
        'badge_id': 'DEMO-INV-001',
        'department': 'Demonstration — Cyber Crime Branch',
        'role': 'investigator',
    },
    {
        'username': 'fsl-expert',
        'badge_id': 'DEMO-FSL-001',
        'department': 'Demonstration — Forensic Science Laboratory',
        'role': 'investigator',
    },
    {
        'username': 'viewer',
        'badge_id': 'DEMO-VIEW-001',
        'department': 'Demonstration — Records',
        'role': 'viewer',
    },
]

DEMO_PASSWORD = 'demo-pass-1234'


class Command(BaseCommand):
    help = 'Seed a demonstration dataset, preferring real reference captures.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--password', default=DEMO_PASSWORD,
            help='Password for the demo accounts.',
        )
        parser.add_argument(
            '--synthetic-only', action='store_true',
            help='Skip the reference captures and use generated traffic.',
        )
        parser.add_argument(
            '--captures', type=int, default=0,
            help='Limit how many reference captures to import (0 = all).',
        )
        parser.add_argument(
            '--skip-analysis', action='store_true',
            help='Import without running the detection engine.',
        )

    # ── entry point ──────────────────────────────────────────────────────

    def handle(self, *args, **opts):
        self.stdout.write(self.style.WARNING(
            '\n' + '=' * 72 + '\n'
            '  DEMONSTRATION DATA\n'
            f'  Case reference {DEMO_CASE_REFERENCE} · accounts share a known password.\n'
            '  Nothing produced here is evidence in any matter.\n'
            + '=' * 72
        ))

        self._seed_accounts(opts['password'])
        officer = get_user_model().objects.get(username='analyst')

        sources = [] if opts['synthetic_only'] else self._reference_captures()
        if opts['captures']:
            sources = sources[:opts['captures']]

        if sources:
            self.stdout.write(self.style.SUCCESS(
                f'\nUsing {len(sources)} real reference capture(s).'
            ))
        else:
            self.stdout.write(self.style.ERROR(
                '\nNo reference captures found — falling back to generated traffic.\n'
                '  Run scripts/fetch_reference_captures.sh to validate against real\n'
                '  traffic instead. Findings from generated traffic prove only that\n'
                '  the generator and the detector agree.'
            ))
            sources = [self._generate_synthetic()]

        for path in sources:
            self._import_one(path, officer)

        if not opts['skip_analysis']:
            self._analyse_all()

        self._certify(officer)
        self._report()

    # ── steps ────────────────────────────────────────────────────────────

    def _seed_accounts(self, password):
        User = get_user_model()
        for spec in DEMO_ACCOUNTS:
            user, created = User.objects.get_or_create(
                username=spec['username'],
                defaults={
                    'badge_id': spec['badge_id'],
                    'department': spec['department'],
                    'role': spec['role'],
                    'is_approved': True,
                },
            )
            if created:
                user.set_password(password)
                user.save()
                self.stdout.write(f"  + account {spec['username']} ({spec['role']})")
            else:
                self.stdout.write(f"  · account {spec['username']} already present")

    def _reference_captures(self):
        directory = Path(settings.BASE_DIR) / 'reference_captures'
        if not directory.is_dir():
            return []
        return sorted(
            path for path in directory.iterdir()
            if path.suffix in ('.pcap', '.pcapng')
        )

    def _generate_synthetic(self):
        out = Path(settings.BASE_DIR) / 'synthetic_captures' / 'demo_storyline.pcap'
        if not out.exists() or not read_manifest(out):
            call_command('generate_traffic', scenario='mixed', seed=7, verbosity=0)
        return out

    def _import_one(self, path, officer):
        if EvidenceRecord.objects.filter(original_filename=path.name).exists():
            self.stdout.write(f'  · {path.name} already sealed')
            return

        # The monitored network is read from the traffic rather than assumed.
        # Assuming RFC 1918 on a capture of a public-facing server inverts
        # every egress rule — the defect that produced 7,052 false alerts.
        home_net, detail = suggest(path)
        if home_net:
            self.stdout.write(
                f'  → {path.name}\n'
                f'      home_net {home_net} — {detail["basis"]}'
            )
        else:
            self.stdout.write(self.style.WARNING(
                f'  → {path.name}\n'
                f'      no home_net proposal ({detail.get("reason")}); '
                f'using the deployment default'
            ))

        call_command(
            'import_pcap', str(path),
            name=path.stem,
            case=DEMO_CASE_REFERENCE,
            seized_from=DEMO_SEIZED_FROM,
            officer=officer.username,
            home_net=home_net,
            verbosity=0,
        )

    def _analyse_all(self):
        for session in CaptureSession.objects.filter(detections__isnull=True).distinct():
            summary = analyse_session(session)
            self.stdout.write(
                f"  ✓ analysed '{session.name}' → {summary['total']} finding(s)"
            )

    def _certify(self, officer):
        """
        Issue one certificate, both parts, through the real service layer.

        Hand-built rows would prove nothing: the two-person rule, the
        integrity re-check and the PDF render all live in evidence/service.py,
        and a demo that skips them is a demo of something else.
        """
        if Section63Certificate.objects.exists():
            self.stdout.write('  · certificate already issued')
            return

        record = EvidenceRecord.objects.order_by('created_at').first()
        if record is None:
            return

        expert = get_user_model().objects.get(username='fsl-expert')
        session = CaptureSession.objects.filter(
            pcap_filename__contains=os.path.basename(record.stored_path),
        ).first()
        findings = Detection.objects.filter(session=session).count() if session else 0

        certificate = issue_certificate(
            record,
            session=session,
            part_a_user=officer,
            part_a_name=officer.username,
            part_a_designation='Investigating Officer (demonstration)',
            part_a_organisation=settings.ISSUING_ORGANISATION or '',
            part_b_user=None,
            findings_summary=(
                f'{findings} rule-based finding(s) recorded against this exhibit. '
                f'Demonstration dataset — see the provenance line on the register.'
            ),
        )
        sign_part_b(
            certificate, expert,
            name=expert.username,
            designation='Examiner (demonstration)',
            organisation=settings.ISSUING_ORGANISATION or '',
            qualification='expert',
        )
        self.stdout.write(
            f'  ✓ certificate {certificate.reference} — Part A {officer.username}, '
            f'Part B {expert.username}'
        )

    def _report(self):
        self.stdout.write(self.style.SUCCESS('\nSeeded:'))
        self.stdout.write(f'  exhibits     {EvidenceRecord.objects.count()}')
        self.stdout.write(f'  captures     {CaptureSession.objects.count()}')
        self.stdout.write(f'  findings     {Detection.objects.count()}')
        self.stdout.write(f'  certificates {Section63Certificate.objects.count()}')
        for record in EvidenceRecord.objects.all():
            self.stdout.write(
                f'  {record.exhibit_number} · {record.get_provenance_display()}'
            )
