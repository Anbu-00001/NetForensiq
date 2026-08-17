from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    ApprovalStatusView, CustomTokenObtainPairView, LogoutView, MeView, RegisterView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='login'),
    path('login/refresh/', TokenRefreshView.as_view(), name='login-refresh'),
    path('me/', MeView.as_view(), name='me'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('status/', ApprovalStatusView.as_view(), name='approval-status'),
]