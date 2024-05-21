# Generated by Django 5.0.3 on 2024-05-07 08:51

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('FirstTry', '0011_alter_scan_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='home',
            name='ip_address_scan',
        ),
        migrations.RemoveField(
            model_name='home',
            name='name_scan',
        ),
        migrations.RemoveField(
            model_name='task',
            name='Creation_Time',
        ),
        migrations.AddField(
            model_name='home',
            name='Configuration',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='FirstTry.scan'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='home',
            name='Creation_Time',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='home',
            name='name',
            field=models.CharField(default='Default', max_length=15),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='home',
            name='schedule',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='FirstTry.schedule'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='home',
            name='target',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='FirstTry.target'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='home',
            name='id',
            field=models.AutoField(default=1, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='home',
            name='status',
            field=models.CharField(max_length=20),
        ),
    ]
