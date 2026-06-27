from django.db import models


class AuditJob(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'), ('running', 'Running'),
        ('complete', 'Complete'), ('failed', 'Failed'),
    ]
    workflow_file = models.FileField(upload_to='uploads/')
    workflow_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    def __str__(self):
        return f"{self.workflow_name} ({self.status})"


class AuditResult(models.Model):
    job = models.OneToOneField(AuditJob, on_delete=models.CASCADE, related_name='result')
    # EDE fields
    nodes_total = models.IntegerField(default=0)
    nodes_assessed = models.IntegerField(default=0)
    nodes_unassessed = models.IntegerField(default=0)
    avg_ede = models.FloatField(default=0.0)
    nodes_with_ede = models.IntegerField(default=0)
    unnecessary_pii_total = models.IntegerField(default=0)
    gdpr_concerns = models.IntegerField(default=0)
    gdpr_flag = models.BooleanField(default=False)
    ede_risk_level = models.CharField(max_length=20, default='UNKNOWN')
    node_results = models.JSONField(default=list)
    ede_error = models.TextField(blank=True, default='')
    # AI-BOM fields
    aibom_available = models.BooleanField(default=False)
    aibom_findings = models.JSONField(default=list)
    aibom_total_issues = models.IntegerField(default=0)
    aibom_risk_level = models.CharField(max_length=20, default='UNKNOWN')
    aibom_error = models.TextField(blank=True, default='')
    # Credential scan (always runs, no CLI dep)
    credential_findings = models.JSONField(default=list)
    total_credential_issues = models.IntegerField(default=0)
    # Combined
    combined_risk_score = models.CharField(max_length=20, default='UNKNOWN')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Result for {self.job.workflow_name}"


class CollectiveReport(models.Model):
    name = models.CharField(max_length=255, default='Batch Audit')
    created_at = models.DateTimeField(auto_now_add=True)
    jobs = models.ManyToManyField(AuditJob, related_name='collective_reports')
    total_workflows = models.IntegerField(default=0)
    avg_ede_across_all = models.FloatField(default=0.0)
    total_gdpr_flags = models.IntegerField(default=0)
    total_pii_violations = models.IntegerField(default=0)
    highest_risk = models.CharField(max_length=20, default='UNKNOWN')
    total_aibom_issues = models.IntegerField(default=0)
    summary = models.JSONField(default=list)

    def __str__(self):
        return f"Batch Report {self.created_at.strftime('%Y-%m-%d %H:%M')} ({self.total_workflows} workflows)"
