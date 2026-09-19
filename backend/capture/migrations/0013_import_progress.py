# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
#
# Progress reporting for an import that now runs outside the request that
# asked for it. See capture/importer.py.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('capture', '0012_livemonitorstate'),
    ]

    operations = [
        migrations.AddField(
            model_name='capturesession',
            name='progress_bytes_read',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='capturesession',
            name='progress_flows',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='capturesession',
            name='progress_packets',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='capturesession',
            name='progress_stage',
            field=models.CharField(blank=True, max_length=12),
        ),
        migrations.AddField(
            model_name='capturesession',
            name='progress_total_bytes',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='capturesession',
            name='progress_updated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
