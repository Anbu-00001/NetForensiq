from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models.signals import post_init, post_save
from django.dispatch import receiver


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
        # Each act gets its own name. Triage decisions, detection runs and
        # certificate signatures were all filed as VIEW_EVIDENCE or
        # EXPORT_EVIDENCE, which made the audit trail unreadable in exactly
        # the situation it exists for: an officer asked in court which of
        # these entries records the moment a finding was confirmed.
        LOGIN_SUCCESS = 'login_success', 'Login Success'
        LOGIN_FAILED = 'login_failed', 'Login Failed'
        LOGOUT = 'logout', 'Logout'
        REGISTER = 'register', 'Registration Submitted'
        APPROVE_USER = 'approve_user', 'User Approved'
        VIEW_EVIDENCE = 'view_evidence', 'Evidence Viewed'
        VERIFY_EVIDENCE = 'verify_evidence', 'Evidence Integrity Verified'
        EXPORT_EVIDENCE = 'export_evidence', 'Evidence Exported'
        ANALYSE_SESSION = 'analyse_session', 'Detection Run'
        TRIAGE_DETECTION = 'triage_detection', 'Finding Triaged'
        ISSUE_CERTIFICATE = 'issue_certificate', 'Section 63 Certificate Issued'
        SIGN_CERTIFICATE = 'sign_certificate', 'Section 63 Part B Signed'

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


# ── approval is an auditable act, wherever it happens ────────────────────
#
# AuditLog.Action.APPROVE_USER was defined and never written: there is no
# approval endpoint, because approving an officer is done through the Django
# admin. So the one administrative act that decides who may touch evidence was
# the only one leaving no trace.
#
# The signal catches it at the model layer, which covers the admin, a shell,
# a data migration and any endpoint added later — none of which can approve an
# account without saving the row.

@receiver(post_init, sender=User)
def _remember_approval_state(sender, instance, **kwargs):
    instance._was_approved = instance.is_approved


@receiver(post_save, sender=User)
def _record_approval_change(sender, instance, created, **kwargs):
    was = False if created else getattr(instance, '_was_approved', False)
    if instance.is_approved and not was:
        AuditLog.objects.create(
            user=instance,
            username_attempted=instance.username,
            action=AuditLog.Action.APPROVE_USER,
            detail=(
                f'Account approved: {instance.username} '
                f'(badge {instance.badge_id or "—"}, role {instance.role})'
            ),
        )
    instance._was_approved = instance.is_approved
