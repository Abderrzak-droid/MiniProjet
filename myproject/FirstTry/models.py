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
    
    def __str__(self):
        return self.vulnerability

class NmapScriptType(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Nmap Script Type"
        verbose_name_plural = "Nmap Script Types"


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
    scan_type = models.ForeignKey(NmapScriptType, on_delete=models.CASCADE)

    def __str__(self):
        return self.Scan_Name

    class Meta:
        verbose_name = "Scan Configuration"
        verbose_name_plural = "Scan Configurations"


class CustomScriptType(models.Model):
    id = models.AutoField(primary_key=True)
    Script_Name = models.CharField(max_length=20)
    script_types = models.ManyToManyField(NmapScriptType)

    def __str__(self):
        return self.Script_Name
    
    def script_types_list(self):
        return ', '.join([st.name for st in self.script_types.all()])

    script_types_list.short_description = 'script_types'


class Resultats(models.Model):
    severity =  models.FloatField()    
    is_exploit  =  models.BooleanField()
    vulnerability =  models.CharField(max_length=50, unique=True)
    Task = models.CharField(max_length=30)
    Host_IP = models.CharField(max_length=30)
    Host_Name = models.CharField(max_length=20)
    description = models.TextField()



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

