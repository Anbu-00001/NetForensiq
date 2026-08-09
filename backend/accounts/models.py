from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'admin', 'Admin'
        INVESTIGATOR = 'investigator', 'Investigator'
        VIEWER = 'viewer', 'Viewer'

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.VIEWER,
    )
    badge_id = models.CharField(max_length=50, unique=True)
    department = models.CharField(max_length=100)

    # Security / approval workflow fields
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='approved_users',
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    # Account security tracking
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.username} ({self.role})"
    
class AuditLog(models.Model):
    class Action(models.TextChoices):
        LOGIN_SUCCESS = 'login_success', 'Login Success'
        LOGIN_FAILED = 'login_failed', 'Login Failed'
        LOGOUT = 'logout', 'Logout'
        REGISTER = 'register', 'Registration Submitted'
        APPROVE_USER = 'approve_user', 'User Approved'
        VIEW_EVIDENCE = 'view_evidence', 'Evidence Viewed'
        EXPORT_EVIDENCE = 'export_evidence', 'Evidence Exported'

    user = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='audit_logs',
    )
    username_attempted = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=32, choices=Action.choices)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    detail = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp} · {self.action} · {self.username_attempted or self.user}"