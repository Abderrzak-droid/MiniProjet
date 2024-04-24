from django.forms import ModelForm
from . import models
from .models import Scan , dateasyn
from .models import Result,Home
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
    fields = ('name','ip_address', 'scan_type','dataBase')
    
class ResultatForm(ModelForm):
  class Meta:
    model = Result
    fields = ('vulnerability', 'severity','host_ip','host_name','time',)

class HomeForm(ModelForm):
  class Meta:
    model = Home
    fields = ('name_scan','ip_address_scan','status')

class dateasynForm(ModelForm) :
  class Meta:
    model = dateasyn  
    fields = ('ip_address','scan_type','start_time', 'end_time','duration','recurrence',)  