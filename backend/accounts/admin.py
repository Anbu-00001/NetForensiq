from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User
from .models import AuditLog

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'role', 'badge_id', 'is_approved', 'is_active')
    list_filter = ('role', 'is_approved', 'is_active')
    fieldsets = UserAdmin.fieldsets + (
        ('NetForensiq Details', {
            'fields': ('role', 'badge_id', 'department', 'is_approved', 'approved_by', 'approved_at')
        }),
    )


admin.site.register(User, CustomUserAdmin)

class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'action', 'username_attempted', 'user', 'ip_address')
    list_filter = ('action', 'timestamp')
    search_fields = ('username_attempted', 'ip_address')
    readonly_fields = [f.name for f in AuditLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(AuditLog, AuditLogAdmin)