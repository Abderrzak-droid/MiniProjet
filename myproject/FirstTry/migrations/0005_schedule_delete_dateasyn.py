# Generated by Django 5.0.3 on 2024-04-30 21:37

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('FirstTry', '0004_rename_etat_resultattcp_state'),
    ]

    operations = [
        migrations.CreateModel(
            name='Schedule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Schedule_Name', models.CharField(max_length=20)),
                ('recurrence', models.CharField(choices=[('monthly', 'Mensuelle'), ('daily', 'Quotidienne'), ('weekly', 'Hebdomadaire'), ('yearly', 'Annuelle'), ('none', 'Une seule fois')], default='none', max_length=15)),
                ('start_time', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.DeleteModel(
            name='dateasyn',
        ),
    ]
