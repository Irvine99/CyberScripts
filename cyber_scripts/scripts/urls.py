from django.urls import path
from . import views

app_name = 'scripts'

urlpatterns = [
path('', views.IndexView.as_view(), name='index'),
path('scripts/', views.ScriptListView.as_view(), name='liste_scripts'),
path('scripts/manage/', views.ScriptManageListView.as_view(), name='manage_scripts'),
path('scripts/manage/create/', views.ScriptCreateView.as_view(), name='script_create'),
path('scripts/manage/<int:pk>/update/', views.ScriptUpdateView.as_view(), name='script_update'),
path('scripts/manage/<int:pk>/delete/', views.ScriptDeleteView.as_view(), name='script_delete'),
path('scripts/<int:pk>/run/', views.ScriptRunView.as_view(), name='script_run'),

path('signup/', views.signup, name='signup'), 
]
