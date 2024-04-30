
from django.urls import path
from . import views

urlpatterns =[
    path("Home", views.home, name ="home"),
    path("viewhtml",views.form , name='form'),
    path("results",views.your_view, name ="results"),
    path("NewTask",views.AddTask,name = "NewTask"),
    path('login/', views.user_login, name='login'),
    path('', views.user_signup, name='signup'),
    path("ResultsTCP", views.ShowResultsTCP , name = 'TCPResults'),
    path("NewSchedule", views.AddSchedule , name ='NewSchedule')
   
]