from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'audit', views.AuditViewSet, basename='audit-api')

urlpatterns = [
    path('', views.index, name='index'),
    path('audit/', views.upload, name='upload'),
    path('audit/<int:job_id>/', views.results, name='results'),
    path('audit/<int:job_id>/download/', views.download_json, name='download_json'),
    path('report/<int:report_id>/', views.collective_results, name='collective_results'),
    path('reports/', views.batch_reports, name='batch_reports'),
    path('audit/<int:job_id>/delete/', views.delete_job, name='delete_job'),
    path('audits/delete-all/', views.delete_all_jobs, name='delete_all_jobs'),
    path('reports/<int:report_id>/delete/', views.delete_batch_report, name='delete_batch_report'),
    path('api/', include(router.urls)),
]
