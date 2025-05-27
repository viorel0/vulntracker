from django.contrib import admin
from django.urls import path
from monitor.views import home_redirect, login_view, dashboard_view, settings_view, aboutcve_view, favorites_view, virus_scan_view, virus_scan_detail_view
from monitor.register_view import register
from django.contrib.auth import views as auth_views
from rest_framework.routers import DefaultRouter
from monitor.api_views import ScanInfoViewSet, ScanInfoByShaView

router = DefaultRouter()
router.register(r'api/scaninfos', ScanInfoViewSet, basename='scaninfo')

urlpatterns = [
    path('', home_redirect),
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('settings/', settings_view, name='settings'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('aboutcve/<str:cve_id>/', aboutcve_view, name='aboutcve'),
    path('favorites/', favorites_view, name='favorites'),
    path('virus/', virus_scan_view, name='virus_scan'),
    path('virus/scan/<str:file_name>/', virus_scan_detail_view, name='virus_scan_detail'),
    path('api/scaninfos/<str:sha256>/', ScanInfoByShaView.as_view(), name='scaninfo-by-sha'),
] + router.urls