from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    ApprovalStatusView, CustomTokenObtainPairView, LogoutView, MeView,
    PendingAccountsView, RegisterView, SignInAttemptsView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='login'),
    path('login/refresh/', TokenRefreshView.as_view(), name='login-refresh'),
    path('me/', MeView.as_view(), name='me'),
    path('logout/', LogoutView.as_view(), name='logout'),
    # The approval queue. Administrators only — approving an account is the
    # act that decides who may touch evidence.
    path('accounts/pending/', PendingAccountsView.as_view(), name='pending-accounts'),
    path('status/', ApprovalStatusView.as_view(), name='approval-status'),
    # The access log the sign-in page promises. Administrators only.
    path('sign-in-attempts/', SignInAttemptsView.as_view(), name='sign-in-attempts'),
]