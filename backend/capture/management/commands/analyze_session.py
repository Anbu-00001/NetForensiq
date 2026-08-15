from django.core.management.base import BaseCommand, CommandError

from capture.models import CaptureSession
from capture.detection import analyse_session


class Command(BaseCommand):
    help = 'Run the detection rules over a stored capture session.'

    def add_arguments(self, parser):
        parser.add_argument('session_id', type=int, nargs='?', help='Session id (default: latest)')

    def handle(self, *args, **opts):
        if opts['session_id']:
            try:
                session = CaptureSession.objects.get(pk=opts['session_id'])
            except CaptureSession.DoesNotExist:
                raise CommandError(f"No session with id {opts['session_id']}")
        else:
            session = CaptureSession.objects.order_by('-started_at').first()
            if session is None:
                raise CommandError('No capture sessions exist yet.')

        self.stdout.write(self.style.WARNING(f'Analysing session #{session.id} "{session.name}"…'))
        summary = analyse_session(session)

        self.stdout.write(self.style.SUCCESS(
            f"\n  Detections : {summary['total']}\n"
            f"  Flows hit  : {summary['flows_flagged']}"
        ))
        for rule_id, count in sorted(summary['by_rule'].items()):
            self.stdout.write(f'    {rule_id:32} {count}')
