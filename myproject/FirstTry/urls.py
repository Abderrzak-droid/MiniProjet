
from django.urls import path
from . import views

urlpatterns =[
    path("", views.index, name="index"),
    path("Home", views.home, name ="home"),
    path("viewhtml",views.form , name='form'),
    path("results",views.your_view, name ="results"),
    path("NewTask",views.AddTask,name = "NewTask"),
    path('login/', views.user_login, name='login'),
    path('signup/', views.user_signup, name='signup'),
    path('without',views.indexwithout , name= 'without'),
   
]