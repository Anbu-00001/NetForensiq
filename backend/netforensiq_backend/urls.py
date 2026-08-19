"""
URL configuration for netforensiq_backend.

Everything under /api/ requires a bearer token: DRF is configured to deny by
default, and the few public endpoints (register, login, approval status) opt
out explicitly.
"""
from django.contrib import admin
from django.urls import include, path, re_path
from rest_framework.routers import DefaultRouter

from capture.upload import CaptureUploadView
from capture.views import (
    CaptureSessionViewSet, DNSRecordViewSet, DetectionViewSet, FlowViewSet,
    engine_info,
)
from evidence.views import CertificateViewSet, EvidenceViewSet, PublicVerifyView

from .spa import serve_collected_static, serve_frontend

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
    # Public: the landing and login pages state the rule count and version,
    # and a number on a page nobody has signed in to see still has to be true.
    path('api/engine/', engine_info, name='engine-info'),
    # Open verification. A certificate asserts a SHA-256; the person handed
    # that certificate must be able to test the assertion without credentials
    # to the investigating agency's own system.
    # Take a capture into evidence from the browser, so an officer handed a
    # USB stick does not need a shell prompt.
    path('api/capture/upload/', CaptureUploadView.as_view(), name='capture-upload'),

    path('api/verify/<str:exhibit_number>/', PublicVerifyView.as_view(),
         name='public-verify'),
    path('api/', include(router.urls)),

    # Django's own static files (the admin's CSS). Needed only once DEBUG is
    # off, which is exactly the configuration an air-gapped deployment runs.
    re_path(r'^static/(?P<path>.*)$', serve_collected_static, name='collected-static'),

    # The built interface, last so every Django route above wins. This is what
    # makes the platform one process on one port: an air-gapped machine needs
    # Python and the built files, not Node. Paths the API owns still 404
    # properly — see spa.py for why that matters.
    re_path(r'^(?P<path>.*)$', serve_frontend, name='frontend'),
]
