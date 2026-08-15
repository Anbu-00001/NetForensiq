"""
URL configuration for netforensiq_backend.

Everything under /api/ requires a bearer token: DRF is configured to deny by
default, and the few public endpoints (register, login, approval status) opt
out explicitly.
"""
from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from capture.views import (
    CaptureSessionViewSet, DNSRecordViewSet, DetectionViewSet, FlowViewSet,
)
from evidence.views import CertificateViewSet, EvidenceViewSet

router = DefaultRouter()
router.register('sessions', CaptureSessionViewSet, basename='session')
router.register('flows', FlowViewSet, basename='flow')
router.register('dns', DNSRecordViewSet, basename='dns')
router.register('detections', DetectionViewSet, basename='detection')
router.register('evidence', EvidenceViewSet, basename='evidence')
router.register('certificates', CertificateViewSet, basename='certificate')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),
    path('api/', include(router.urls)),
]
