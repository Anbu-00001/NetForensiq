"""
Backfill CaptureSession.evidence for sessions imported before the link existed.

Before this field, the only way to tell which exhibit a session analysed was to
compare `pcap_filename` against `EvidenceRecord.stored_path` — which is what
the seeding code did, and which is a coincidence that usually holds rather than
a relationship. Sessions created after the field exists get it set at import.

The match here is exact on the stored path, not a substring: two exhibits can
share a filename, and guessing wrong would attribute findings to the wrong
sealed artefact. Anything that does not match exactly is left null, which is
the honest outcome — the link is unknown, not assumed.
"""

from django.db import migrations


def link(apps, schema_editor):
    CaptureSession = apps.get_model('capture', 'CaptureSession')
    EvidenceRecord = apps.get_model('evidence', 'EvidenceRecord')

    by_path = {}
    for record in EvidenceRecord.objects.all():
        by_path.setdefault(record.stored_path, []).append(record)

    for session in CaptureSession.objects.filter(evidence__isnull=True):
        matches = by_path.get(session.pcap_filename, [])
        if len(matches) == 1:
            session.evidence = matches[0]
            session.save(update_fields=['evidence'])


def unlink(apps, schema_editor):
    CaptureSession = apps.get_model('capture', 'CaptureSession')
    CaptureSession.objects.update(evidence=None)


class Migration(migrations.Migration):

    dependencies = [
        ('capture', '0009_capturesession_evidence'),
        ('evidence', '0003_evidencerecord_provenance_and_more'),
    ]

    operations = [migrations.RunPython(link, unlink)]
