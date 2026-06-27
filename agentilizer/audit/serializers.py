from rest_framework import serializers
from .models import AuditJob, AuditResult, CollectiveReport


class AuditResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditResult
        fields = '__all__'


class AuditJobSerializer(serializers.ModelSerializer):
    result = AuditResultSerializer(read_only=True)

    class Meta:
        model = AuditJob
        fields = '__all__'


class CollectiveReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = CollectiveReport
        fields = '__all__'
