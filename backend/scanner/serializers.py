from rest_framework import serializers
from .models import ScanJob, ScanResult, ThreatReport

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = '__all__'

class ThreatReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatReport
        fields = '__all__'

class ScanJobSerializer(serializers.ModelSerializer):
    result = ScanResultSerializer(read_only=True)
    report = serializers.SerializerMethodField()

    class Meta:
        model = ScanJob
        fields = ['id', 'user', 'file_name', 'file_hash', 'sha256_hash',
                  'file_size', 'status', 'created_at', 'updated_at', 'result', 'report']
        read_only_fields = ['id', 'user', 'status', 'created_at', 'updated_at', 'result', 'report']

    def get_report(self, obj):
        try:
            if hasattr(obj, 'result') and obj.result and hasattr(obj.result, 'report'):
                return ThreatReportSerializer(obj.result.report).data
        except Exception:
            pass
        return None
