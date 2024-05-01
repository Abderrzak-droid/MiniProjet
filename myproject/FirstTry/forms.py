from django.forms import ModelForm
from . import models
from .models import Scan ,Task
from .models import ResultVulners,Home,ResultatTCP,Schedule,Target
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


class ScheduleForm(ModelForm):
  class Meta:
    model = Schedule
    fields = ('Schedule_Name', 'recurrence', 'start_time',)

class TaskForm(ModelForm):
  class Meta:
    model = Task
    start_time = forms.DateField(input_formats=['%Y-%m-%d'], required=True, error_messages={
        'invalid': 'Please enter a valid date in the format YYYY-MM-DD.'
    })
    fields = ('name','target', 'schedule','Configuration','Creation_Time',)

class ScanForm(ModelForm):
  class Meta:
    model = Scan
    fields = ('Scan_Name','scan_type','content_type',)

class ResultatVulnersForm(ModelForm):
  class Meta:
    model = ResultVulners
    fields = ('nameVuln', 'cvss','type','is_exploit',)

class ResultatTCPForm(ModelForm):
  class Meta:
    model = ResultatTCP
    fields = ('port', 'state','service',)

class HomeForm(ModelForm):
  class Meta:
    model = Home
    fields = ('name_scan','ip_address_scan','status')

class TargetForm(ModelForm):
  class Meta:
    model = Target
    fields = ('Target_Name','Address_IP',)