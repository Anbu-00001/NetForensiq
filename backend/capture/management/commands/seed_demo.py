"""
Build a complete demonstration dataset.

Everything here is deliberate about one thing: **a demo must not be able to
pass itself off as a case by accident.** Three rules follow from that.

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

from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from capture.detection import analyse_session
from capture.home_net import suggest
from capture.models import CaptureSession, Detection
from capture.provenance import read_manifest
from evidence.models import EvidenceRecord, Section63Certificate
from evidence.service import issue_certificate, sign_part_b

# Not an FIR number. Not in any format a court registry uses. That is the point.
DEMO_CASE_REFERENCE = 'DEMO-NOT-A-REAL-CASE'
DEMO_SEIZED_FROM = 'Demonstration dataset — no seizure took place'
# Left deliberately blank. An FIR number is matched against a station's own
# register; inventing one that looks plausible is the single worst thing this
# command could write, and a blank line on the certificate is the honest answer.
DEMO_FIR_NUMBER = ''
DEMO_POLICE_STATION = ''

# The two accounts exist as two accounts because s.63(4) requires the person in
# charge of the device and the expert to be different people, and the service
# layer refuses a certificate signed twice by one account.
DEMO_ACCOUNTS = [
    {
        'username': 'investigator',
        'badge_id': 'DEMO-INV-001',
        'department': 'Demonstration — Cyber Crime Branch',
        'role': 'investigator',
    },
    {
        'username': 'expert',
        'badge_id': 'DEMO-FSL-001',
        'department': 'Demonstration — Forensic Science Laboratory',
        'role': 'investigator',
    },
    {
        'username': 'commander',
        'badge_id': 'DEMO-ADM-001',
        'department': 'Demonstration — Cyber Crime Branch',
        'role': 'admin',
    },
    {
        'username': 'viewer',
        'badge_id': 'DEMO-VIEW-001',
        'department': 'Demonstration — Records',
        'role': 'viewer',
    },
]

# One password for every demo account, chosen to be typed correctly at a
# keyboard in front of an audience: no hyphens to lose, no ambiguity between
# l/1 or O/0, and long enough to satisfy Django's validators so the same value
# works if an account is ever created through the registration form.
DEMO_PASSWORD = 'Netforensiq@2026'


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
            '--include-synthetic', action='store_true',
            help=(
                'Also seal the generated capture alongside the real ones. It '
                'contains every attack class the engine detects, including the '
                'one host implicated by several rules that the corroboration '
                'pass exists for — none of which appears in the reference '
                'captures. It is sealed with SYNTHETIC provenance and says so '
                'on the register and on its certificate.'
            ),
        )
        parser.add_argument(
            '--captures', type=int, default=0,
            help='Limit how many reference captures to import (0 = all).',
        )
        parser.add_argument(
            '--skip-analysis', action='store_true',
            help='Import without running the detection engine.',
        )
        parser.add_argument(
            '--force', action='store_true',
            help=(
                'Seed even on an instance that looks deployed. Required when '
                'ALLOWED_HOSTS names anything beyond loopback.'
            ),
        )

    # ── entry point ──────────────────────────────────────────────────────

    LOOPBACK = {'localhost', '127.0.0.1', '::1'}

    def _refuse_on_a_deployment(self, forced):
        """
        Do not seed demonstration data onto something that looks live.

        This command creates accounts with a password printed in its own help
        text and writes exhibits into whatever database it is pointed at. On a
        laptop that is the point; on a deployment it is an unauthenticated
        account and three fabricated exhibits in a case register.

        ALLOWED_HOSTS is the test because it is the one setting an operator
        must change to serve anyone but themselves.
        """
        beyond_loopback = sorted(
            set(settings.ALLOWED_HOSTS) - self.LOOPBACK - {'*'}
        )
        if '*' in settings.ALLOWED_HOSTS:
            beyond_loopback.append('* (any host)')

        if beyond_loopback and not forced:
            raise CommandError(
                'Refusing to seed demonstration data: ALLOWED_HOSTS names '
                f'{", ".join(beyond_loopback)}, so this instance is reachable by '
                'someone other than you. This command creates accounts with a '
                'known password and writes exhibits into the case register. '
                'Pass --force if you are certain this is a demonstration '
                'machine.'
            )
        if beyond_loopback:
            self.stdout.write(self.style.ERROR(
                f'--force given: seeding demonstration data onto an instance '
                f'reachable at {", ".join(beyond_loopback)}.'
            ))

    def handle(self, *args, **opts):
        self._refuse_on_a_deployment(opts['force'])
        self.stdout.write(self.style.WARNING(
            '\n' + '=' * 72 + '\n'
            '  DEMONSTRATION DATA\n'
            f'  Case reference {DEMO_CASE_REFERENCE} · accounts share a known password.\n'
            '  Nothing produced here is evidence in any matter.\n'
            + '=' * 72
        ))

        self._seed_accounts(opts['password'])
        officer = get_user_model().objects.get(username='investigator')

        sources = [] if opts['synthetic_only'] else self._reference_captures()
        if opts['captures']:
            sources = sources[:opts['captures']]

        if opts['include_synthetic'] and not opts['synthetic_only']:
            sources.append(self._generate_synthetic())

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
        # One unapproved application, so the approval queue is not an empty
        # page during a demonstration. It is unapproved on purpose: an account
        # awaiting approval cannot sign in or touch anything.
        pending = {
            'username': 'pending-applicant',
            'badge_id': 'DEMO-PND-001',
            'department': 'Demonstration — awaiting approval',
            'role': 'investigator',
        }
        for spec in [*DEMO_ACCOUNTS, pending]:
            user, created = User.objects.get_or_create(
                username=spec['username'],
                defaults={
                    'badge_id': spec['badge_id'],
                    'department': spec['department'],
                    'role': spec['role'],
                    'is_approved': spec['username'] != 'pending-applicant',
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
            fir=DEMO_FIR_NUMBER,
            police_station=DEMO_POLICE_STATION,
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

        records = list(EvidenceRecord.objects.order_by('created_at'))
        if not records:
            return

        # One certificate over a real capture, and — when a generated capture
        # was sealed too — one over that. Side by side they are the same
        # document except for the band across the top, which is the whole
        # point: a demonstration certificate must be unmistakable.
        chosen = [records[0]]
        synthetic = next((r for r in records if r.is_demonstration_only), None)
        if synthetic and synthetic not in chosen:
            chosen.append(synthetic)

        for record in chosen:
            self._certify_one(record, officer)

    def _certify_one(self, record, officer):
        expert = get_user_model().objects.get(username='expert')
        # The foreign key, not a filename match — the session records which
        # exhibit it analysed.
        session = record.sessions.first()
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
