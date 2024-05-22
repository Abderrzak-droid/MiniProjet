from django.db import models
from django.utils import timezone
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from yaml import scan
# Create your models here.
class ResultVulners(models.Model): 
    severity =  models.FloatField()
    type =  models.CharField(max_length=50)
    is_exploit  =  models.BooleanField()
    vulnerability =  models.CharField(max_length=50, unique=True)
    description = models.TextField()

class Target(models.Model):
    Target_Name = models.CharField(max_length=30)
    Address_IP = models.CharField(max_length=20)

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

class ScanPorts(models.Model):
    scan_id = models.PositiveIntegerField()
    typeScan = models.CharField(max_length=10)
    

class ScanVulnerabilities(models.Model):
    scan_id = models.PositiveIntegerField()
    DataBase = models.CharField(max_length=10)
    
class ResultatTCP(models.Model):
    port = models.CharField(max_length=10)
    state= models.CharField(max_length=10)
    service = models.CharField(max_length=20)

class Scan(models.Model):
    id = models.AutoField(primary_key=True)
    Scan_Name = models.CharField(max_length=20)
    scan_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    # GenericForeignKey allows the scan_type field to reference any object
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('scan_type', 'object_id')

class Home(models.Model):
    id = models.AutoField( primary_key=True)  # Adjust the max_length as per your requirements
    name = models.CharField(max_length=15)
    target = models.CharField(max_length=30)
    status = models.CharField(max_length=20)
    Configuration = models.CharField(max_length=20)
    Creation_Time = models.DateTimeField(default=timezone.now)
    schedule = models.CharField(max_length=30)

class User(models.Model):
    username = models.CharField(max_length=20)
    password = models.CharField(max_length=20)


class Task(models.Model):
    name = models.CharField(max_length=15)
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    Configuration = models.ForeignKey(Scan, on_delete=models.CASCADE)
    schedule = models.ForeignKey(Schedule, on_delete=models.CASCADE)
