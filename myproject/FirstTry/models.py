from django.db import models
from django.utils import timezone

# Create your models here.
class ResultVulners(models.Model): 
    cvss =  models.CharField(max_length=20)
    type =  models.CharField(max_length=20)
    is_exploit  =  models.CharField(max_length=20)
    nameVuln =  models.CharField(max_length=50)
                   
class Scan(models.Model):
    name = models.CharField(max_length=15)
    ip_address = models.CharField(max_length=15)
    scan_type = models.CharField(max_length = 20)
    dataBase = models.CharField(max_length=15)
    start_time = models.DateTimeField(default=timezone.now)

    RECURRENCE_CHOICES = (
        ("monthly", "Mensuelle"),
        ("daily", "Quotidienne"),
        ("weekly", "Hebdomadaire"),
        ("yearly", "Annuelle"),
        ("none", "Une seule fois"),
    )
    recurrence = models.CharField(max_length=10, choices=RECURRENCE_CHOICES, default="monthly")

class ResultatTCP(models.Model):
    port = models.CharField(max_length=10)
    state= models.CharField(max_length=10)
    service = models.CharField(max_length=20)

class Home(models.Model):
    name_scan = models.CharField(max_length=20)
    ip_address_scan = models.CharField(max_length=20)
    status = models.CharField(max_length=15)

class User(models.Model):
    username = models.CharField(max_length=20)
    password = models.CharField(max_length=20)


class dateasyn(models.Model):

    ip_address = models.CharField(max_length=15)
    scan_type = models.CharField(max_length = 20)

    name = models.CharField(max_length=255)
    comment = models.TextField(blank=True)
    time_zone = models.CharField(max_length=32, default="UTC")

    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(blank=True, null=True)

    DURATION_CHOICES = (
        ("entire", "Opération entière"),
    )
    duration = models.CharField(max_length=10, choices=DURATION_CHOICES, default="entire")

    RECURRENCE_CHOICES = (
        ("monthly", "Mensuelle"),
        ("daily", "Quotidienne"),
        ("weekly", "Hebdomadaire"),
        ("yearly", "Annuelle"),
        ("none", "Une seule fois"),
    )
    recurrence = models.CharField(max_length=10, choices=RECURRENCE_CHOICES, default="monthly")

    def __str__(self):
        return self.name