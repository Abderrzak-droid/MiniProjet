from django.contrib import admin

# Register your models here.
# myapp/admin.py

from .models import Task,Target,Schedule,Scan,Home,User, ResultVulners,ResultatTCP

class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'Scan_Name', 'scan_type', 'content_type',)  # Specify fields to display in admin list


class TaskAdmin(admin.ModelAdmin):
    list_display = ('id','name','target','Configuration','Creation_Time','schedule',)
class HomeAdmin(admin.ModelAdmin):
    list_display = ('id','name_scan','status','ip_address_scan')

class ScheduleAdmin(admin.ModelAdmin):
    list_display = ('id','Schedule_Name','recurrence','start_time')

class UserAdmin(admin.ModelAdmin):
    list_display = ('id','username','password')

class ResultsVulnersAdmin(admin.ModelAdmin):
    list_display = ('id','nameVuln', 'cvss','type','is_exploit',)

class TargetAdmin(admin.ModelAdmin):
    list_display= ('id','Target_Name','Address_IP',)

class ResultsTCPAdmin(admin.ModelAdmin):
    list_display = ('port', 'state','service',)
 # Register Scan model with customized admin options
admin.site.register(Home, HomeAdmin)  # Register Scan model with customized admin options
admin.site.register(ResultVulners,ResultsVulnersAdmin)
admin.site.register(ResultatTCP,ResultsTCPAdmin)
admin.site.register(Schedule,ScheduleAdmin)
admin.site.register(Target,TargetAdmin)
admin.site.register(Task,TaskAdmin)