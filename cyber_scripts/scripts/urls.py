from django.urls import path
from . import views
from .views import DirbusterScanView,IPCalculatorView,CVECheckerView,WebReconView,ReconDashboardView

app_name = 'scripts'

urlpatterns = [
path('', views.IndexView.as_view(), name='index'),
path('scripts/', views.ScriptListView.as_view(), name='liste_scripts'),
path('scripts/manage/', views.ScriptManageListView.as_view(), name='manage_scripts'),
path('scripts/manage/create/', views.ScriptCreateView.as_view(), name='script_create'),
path('scripts/manage/<int:pk>/update/', views.ScriptUpdateView.as_view(), name='script_update'),
path('scripts/manage/<int:pk>/delete/', views.ScriptDeleteView.as_view(), name='script_delete'),
path('scripts/<int:pk>/run/', views.ScriptRunView.as_view(), name='script_run'),
path('<int:pk>/', views.ScriptDetailView.as_view(), name='script_detail'),

path('signup/', views.signup, name='signup'),

# script
path('nmap/', views.NmapScanView.as_view(), name='nmap_scan'),
path('dirbuster/', DirbusterScanView.as_view(), name='dirbuster'),
path('ipcalculator/', IPCalculatorView.as_view(), name='ipcalculator'),
path('cve-checker/', CVECheckerView.as_view(), name='cve_checker'),
path('web-recon/', WebReconView.as_view(), name='web_recon'),
path('dashboard/' ,ReconDashboardView.as_view(), name='dashboard'),
]
