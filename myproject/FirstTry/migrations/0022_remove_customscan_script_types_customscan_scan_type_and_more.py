# Generated by Django 5.0.3 on 2024-05-24 23:24

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('FirstTry', '0021_customscan_remove_scan_scan_type_scan_scan_type'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customscan',
            name='script_types',
        ),
        migrations.AddField(
            model_name='customscan',
            name='scan_type',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='FirstTry.nmapscripttype'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='customscan',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
    ]