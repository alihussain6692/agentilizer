from django.contrib import admin
from .models import AuditJob, AuditResult, CollectiveReport

admin.site.register(AuditJob)
admin.site.register(AuditResult)
admin.site.register(CollectiveReport)
