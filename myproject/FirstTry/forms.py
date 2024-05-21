from django.forms import ModelForm
from . import models
from .models import Scan, Target 
from .models import ResultVulners,Home,ResultatTCP,Schedule,Task
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class SignupForm(UserCreationForm):
    class Meta:
        model = User 
        fields = ['username', 'password1', 'password2']

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class ScanForm(ModelForm):
  class Meta:
    model = Scan
    fields = ('Scan_Name','scan_type',)
    
class ResultatVulnersForm(ModelForm):
  class Meta:
    model = ResultVulners
    fields = ('vulnerability', 'severity','type','is_exploit',)


class TaskForm(ModelForm):
  class Meta:
    model = Task
    fields = ('name','target', 'schedule','Configuration')

class ResultatTCPForm(ModelForm):
  class Meta:
    model = ResultatTCP
    fields = ('port', 'state','service',)

class HomeForm(ModelForm):
  class Meta:
    model = Home
    fields = ('name','target', 'status','schedule','Configuration','Creation_Time',)

class TargetForm(ModelForm):
  class Meta:
    model = Target
    fields = ('Target_Name','Address_IP',)

class ScheduleForm(ModelForm):
  class Meta:
    model = Schedule
    fields = ('Schedule_Name', 'recurrence', 'start_time',)
