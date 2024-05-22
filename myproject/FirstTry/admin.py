from django.contrib import admin

# Register your models here.
# myapp/admin.py

from .models import Task,Schedule,Scan,Home, Target,User, ResultVulners,ResultatTCP

class HomeAdmin(admin.ModelAdmin):
    list_display = ('id','name','target', 'schedule','Configuration','Creation_Time')


class UserAdmin(admin.ModelAdmin):
    list_display = ('id','username','password')

class ResultsVulnersAdmin(admin.ModelAdmin):
    list_display = ('id','vulnerability', 'severity','type','is_exploit','description',)

class ScheduleAdmin(admin.ModelAdmin):
    list_display = ('id','Schedule_Name','recurrence','start_time')
class ResultsTCPAdmin(admin.ModelAdmin):
    list_display = ('port', 'state','service',)


class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'Scan_Name', 'scan_type',)  # Specify fields to display in admin list

class TaskAdmin(admin.ModelAdmin):
    list_display = ('id','name','target','Configuration','schedule',)
class TargetAdmin(admin.ModelAdmin):
    list_display= ('id','Target_Name','Address_IP',)
 # Register Scan model with customized admin options
admin.site.register(Home, HomeAdmin)  # Register Scan model with customized admin options
# Register Scan model with customized admin options
admin.site.register(ResultVulners,ResultsVulnersAdmin)
admin.site.register(ResultatTCP,ResultsTCPAdmin)
admin.site.register(Schedule,ScheduleAdmin)
admin.site.register(Target,TargetAdmin)
admin.site.register(Scan,ScanAdmin)
admin.site.register(Task,TaskAdmin)