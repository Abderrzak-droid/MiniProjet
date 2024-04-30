from django.forms import ModelForm
from . import models
from .models import Scan , dateasyn
from .models import ResultVulners,Home,ResultatTCP
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
    start_time = forms.DateField(input_formats=['%Y-%m-%d'], required=True, error_messages={
        'invalid': 'Please enter a valid date in the format YYYY-MM-DD.'
    })
    fields = ('name','ip_address', 'scan_type','dataBase','start_time','recurrence',)
    
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

class dateasynForm(ModelForm) :
  class Meta:
    model = dateasyn  
    fields = ('ip_address','scan_type','start_time', 'end_time','duration','recurrence',)  