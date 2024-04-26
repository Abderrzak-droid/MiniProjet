from django.contrib import admin

# Register your models here.
# myapp/admin.py

from .models import Scan,Home,dateasyn,User, ResultVulners,ResultatTCP

class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'ip_address', 'scan_type')  # Specify fields to display in admin list

class HomeAdmin(admin.ModelAdmin):
    list_display = ('id','name_scan','status','ip_address_scan')

class ScheduleAdmin(admin.ModelAdmin):
    list_display = ('id','start_time','recurrence')

class UserAdmin(admin.ModelAdmin):
    list_display = ('id','username','password')

class ResultsAdmin(admin.ModelAdmin):
    list_display = ('nameVuln', 'cvss','type','is_exploit',)

 # Register Scan model with customized admin options
admin.site.register(Home, HomeAdmin)  # Register Scan model with customized admin options
admin.site.register(dateasyn, ScheduleAdmin)  # Register Scan model with customized admin options
# Register Scan model with customized admin options
admin.site.register(ResultVulners,ResultsAdmin)