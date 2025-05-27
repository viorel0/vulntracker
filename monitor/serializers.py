from rest_framework import serializers
from .models import ScanInfo

class ScanInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanInfo
        fields = '__all__'

