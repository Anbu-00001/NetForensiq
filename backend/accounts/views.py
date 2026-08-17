from rest_framework.throttling import ScopedRateThrottle
from rest_framework import generics, status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from .serializers import RegisterSerializer, UserSerializer
from .models import User
from .utils import log_action
from .models import User, AuditLog
from .utils import log_action, get_client_ip

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        log_action(
            request, AuditLog.Action.REGISTER,
            username_attempted=serializer.validated_data.get('username', ''),
        )
        return Response(
            {'message': 'Registration submitted. Awaiting Admin approval.'},
            status=status.HTTP_201_CREATED,
        )


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        if not self.user.is_approved:
            raise serializers.ValidationError('Your account is pending Admin approval.')

        data['user'] = UserSerializer(self.user).data
        return data


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'login'

    def post(self, request, *args, **kwargs):
        username = request.data.get('username', '')
        try:
            response = super().post(request, *args, **kwargs)
        except Exception:
            log_action(
                request, AuditLog.Action.LOGIN_FAILED,
                username_attempted=username,
            )
            raise

        user = User.objects.filter(username=username).first()
        if user:
            user.last_login_ip = get_client_ip(request)
            user.failed_login_attempts = 0
            user.save(update_fields=['last_login_ip', 'failed_login_attempts'])
        log_action(request, AuditLog.Action.LOGIN_SUCCESS, user=user, username_attempted=username)
        return response


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)

class ApprovalStatusView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username', '').strip()
        badge_id = request.data.get('badge_id', '').strip()

        if not username or not badge_id:
            return Response(
                {'detail': 'Both username and badge ID are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(username__iexact=username, badge_id__iexact=badge_id)
        except User.DoesNotExist:
            return Response(
                {'detail': 'No enrollment record matches those details.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not user.is_active:
            stage = 'rejected'
        elif user.is_approved:
            stage = 'approved'
        else:
            stage = 'pending_authorization'

        return Response({
            'stage': stage,
            'username': user.username,
            'badge_id': user.badge_id,
            'department': user.department,
            'requested_role': user.role,
            'submitted_at': user.created_at,
            'approved_at': user.approved_at,
        })

class LogoutView(APIView):
    """
    End a session for real.

    Sign-out used to be a purely client-side act: the browser dropped its
    sessionStorage and redirected. The refresh token stayed valid for its full
    day, so anyone who had captured it could keep minting access tokens from a
    session the officer believed they had closed — and nothing recorded that
    the session ended, leaving AuditLog.Action.LOGOUT defined and never used.

    Blacklisting requires rest_framework_simplejwt.token_blacklist, which is in
    INSTALLED_APPS. A token that is already blacklisted, expired or malformed
    still yields success: the caller's intent is to end the session, and that
    outcome has been achieved either way.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh = request.data.get('refresh')
        blacklisted = False

        if refresh:
            try:
                RefreshToken(refresh).blacklist()
                blacklisted = True
            except TokenError:
                blacklisted = False

        log_action(
            request, AuditLog.Action.LOGOUT, user=request.user,
            username_attempted=request.user.username,
            detail=('Signed out; refresh token blacklisted' if blacklisted
                    else 'Signed out; no valid refresh token supplied to blacklist'),
        )
        return Response({'detail': 'Signed out.', 'token_blacklisted': blacklisted})
