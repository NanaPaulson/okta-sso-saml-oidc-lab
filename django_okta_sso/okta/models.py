from django.db import models

class SecurityEvent(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
    ]
    PROTOCOL_CHOICES = [
        ("oidc", "OIDC"),
        ("saml", "SAML"),
        ("system", "SYSTEM"),
    ]

    created_at = models.DateTimeField(auto_now_add=True)
    protocol = models.CharField(max_length=10, choices=PROTOCOL_CHOICES, default="system")
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="low")
    actor = models.CharField(max_length=255, blank=True, default="")
    action = models.CharField(max_length=100)          # e.g. "LOGIN_START"
    outcome = models.CharField(max_length=30, default="INFO")  # SUCCESS / FAIL / INFO
    ip = models.CharField(max_length=64, blank=True, default="")
    detail = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.created_at} {self.protocol} {self.action} {self.outcome}"
