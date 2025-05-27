from django.db import models
from django.contrib.auth.models import User
import json

class FavoriteCVE(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    cve_id = models.CharField(max_length=32)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'cve_id')

    def __str__(self):
        return f"{self.user.username} - {self.cve_id}"

class CVEComment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    cve_id = models.CharField(max_length=32, db_index=True)
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} on {self.cve_id}: {self.comment[:30]}"

class ScanInfo(models.Model):
    sha256 = models.CharField(max_length=128, unique=True)
    file_name = models.CharField(max_length=255, null=True, blank=True)
    type = models.CharField(max_length=128, null=True, blank=True)
    size = models.BigIntegerField(null=True, blank=True)
    md5 = models.CharField(max_length=64, null=True, blank=True)
    sha1 = models.CharField(max_length=64, null=True, blank=True)
    last_analysis_stats = models.JSONField(null=True, blank=True)
    last_analysis_date = models.CharField(max_length=32, null=True, blank=True)
    signature = models.CharField(max_length=255, null=True, blank=True)
    virustotal_link = models.URLField(max_length=512, null=True, blank=True)

    def __str__(self):
        return f"ScanInfo {self.sha256}"

class VirusScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    scanned_at = models.DateTimeField(auto_now_add=True)
    scan_info = models.ForeignKey(ScanInfo, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.file_name} by {self.user.username} at {self.scanned_at}"
