from django.utils import timezone
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
from .models import User, AuditLog
from .permissions import IsAdministrator
from .utils import log_action, get_client_ip

class RegisterView(generics.CreateAPIView):
    """
    Submit an enrolment request.

    Throttled on its own scope rather than sharing the general anonymous
    limit: this endpoint creates rows in the user table from unauthenticated
    input, and an approval queue buried under a thousand fabricated
    applications is a denial of service against the administrator, not just
    against the server.
    """

    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'register'

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


def _attempted_username(request):
    """
    The username from a request that may never have been parsed.

    `throttled()` runs early enough that reading request.data can itself raise
    on a malformed body. A missing username must not turn a refused sign-in
    into a 500 — the row is worth writing even when the only thing known about
    the attempt is where it came from.
    """
    try:
        return (request.data.get('username') or '')[:150]
    except Exception:
        return ''


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        if not self.user.is_approved:
            raise serializers.ValidationError('Your account is pending Admin approval.')

        data['user'] = UserSerializer(self.user).data
        return data


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Sign in, and record the attempt either way.

    The sign-in page tells the officer that attempts are recorded with a
    timestamp, a username and a source address. That sentence is the reason
    every path out of this view writes an AuditLog row before it returns.
    """

    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'login'

    def throttled(self, request, wait):
        """
        Record an attempt that was refused before it reached the password check.

        Throttling happens in DRF's `initial()`, before `post()` runs, so the
        try/except below never sees it — which meant a burst of attempts
        produced eight audit rows and then silence, and the silence began
        exactly at the point the traffic became worth looking at. A rate-limited
        attempt is still an attempt, and the page promises it is recorded.
        """
        log_action(
            request, AuditLog.Action.LOGIN_FAILED,
            username_attempted=_attempted_username(request),
            detail=f'Refused by rate limit; retry permitted in {int(wait)}s',
        )
        super().throttled(request, wait)

    def post(self, request, *args, **kwargs):
        username = request.data.get('username', '')
        try:
            response = super().post(request, *args, **kwargs)
        except Exception:
            # The counter is on the account, not on the request, so it survives
            # an attacker changing source address. It was previously reset to
            # zero on success and never incremented anywhere — a field that
            # could only ever count down, and a capability the model implied
            # but the code did not have.
            attempted = User.objects.filter(username=username).first()
            if attempted:
                attempted.failed_login_attempts += 1
                attempted.save(update_fields=['failed_login_attempts'])
            log_action(
                request, AuditLog.Action.LOGIN_FAILED,
                username_attempted=username,
                detail=(
                    f'Credentials rejected; {attempted.failed_login_attempts} '
                    f'consecutive failures for this account'
                ) if attempted else 'Credentials rejected; no such account',
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
    """
    Check where an enrolment request has got to.

    Public by necessity — an applicant has no account to sign in with —
    which makes it an oracle: it answers "does this username hold this badge
    number" for anyone who asks. Both must match, and the reply is identical
    for a wrong username, a wrong badge and a pair that does not exist, so a
    single query leaks nothing. Volume is the remaining risk, so it has its
    own throttle scope.
    """

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'approval_status'

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


class PendingAccountsView(APIView):
    """
    The approval queue, and the decision on it.

    Approving an officer was only possible through the Django admin. That is a
    reasonable answer for a pilot and a poor one for a demonstration: the single
    act that decides who may touch evidence lived outside the application that
    is otherwise careful about recording every act.

    The AuditLog entry is written by a signal on the model, so it is recorded
    the same way whichever route is used — this endpoint adds a place to do it,
    not a second source of truth.
    """

    permission_classes = [IsAdministrator]

    def get(self, request):
        pending = User.objects.filter(is_approved=True).none() | User.objects.filter(
            is_approved=False, is_active=True,
        )
        return Response({
            'pending': UserSerializer(pending.order_by('created_at'), many=True).data,
            'approved_count': User.objects.filter(is_approved=True).count(),
        })

    def post(self, request):
        username = (request.data.get('username') or '').strip()
        decision = (request.data.get('decision') or '').strip()

        if decision not in ('approve', 'reject'):
            return Response(
                {'detail': "decision must be 'approve' or 'reject'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            account = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {'detail': f'No such account: {username}'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if account.pk == request.user.pk:
            # Self-approval would make the whole queue decorative.
            return Response(
                {'detail': 'An account cannot decide its own application.'},
                status=status.HTTP_409_CONFLICT,
            )

        if decision == 'approve':
            account.is_approved = True
            account.approved_by = request.user
            account.approved_at = timezone.now()
            account.save(update_fields=['is_approved', 'approved_by', 'approved_at'])
        else:
            # Rejection deactivates rather than deletes: the application, and
            # the decision on it, are part of the record.
            account.is_active = False
            account.save(update_fields=['is_active'])
            log_action(
                request, AuditLog.Action.APPROVE_USER, user=request.user,
                username_attempted=account.username,
                detail=f'Application from {account.username} rejected',
            )

        return Response(UserSerializer(account).data)
