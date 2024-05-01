from django.db import models
from django.utils import timezone
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
# Create your models here.
class ResultVulners(models.Model): 
    cvss =  models.CharField(max_length=20)
    type =  models.CharField(max_length=20)
    is_exploit  =  models.CharField(max_length=20)
    nameVuln =  models.CharField(max_length=50)



class Schedule(models.Model):
    Schedule_Name = models.CharField(max_length=20)
    
    RECURRENCE_CHOICES = (
        ("monthly", "Mensuelle"),
        ("daily", "Quotidienne"),
        ("weekly", "Hebdomadaire"),
        ("yearly", "Annuelle"),
        ("none", "Une seule fois"),
    )
    recurrence = models.CharField(max_length=15, choices=RECURRENCE_CHOICES, default="none")
    start_time = models.DateTimeField(default=timezone.now)


class Target(models.Model):
    Target_Name = models.CharField(max_length=20)
    Address_IP = models.CharField(max_length=20)

class Scan(models.Model):
    Scan_Name = models.CharField(max_length=20)
    scan_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

class ScanPorts(models.Model):
    scan_id = models.PositiveIntegerField()
    typeScan = models.CharField(max_length=10)
    

class ScanVulnerabilities(models.Model):
    scan_id = models.PositiveIntegerField()
    DataBase = models.CharField(max_length=10)
class Task(models.Model):
    name = models.CharField(max_length=15)
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    Configuration = models.ForeignKey(Scan, on_delete=models.CASCADE)
    Creation_Time = models.DateTimeField(default=timezone.now)
    schedule = models.ForeignKey(Schedule, on_delete=models.CASCADE)


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

