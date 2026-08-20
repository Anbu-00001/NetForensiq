from datetime import timedelta

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
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework_simplejwt.exceptions import InvalidToken

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
        except (AuthenticationFailed, InvalidToken, TokenError, ValidationError):
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
        except Exception as exc:
            # Everything that is not the password being wrong.
            #
            # This used to be caught by the same `except Exception` above, which
            # meant a locked database or a dead dependency was written into the
            # permanent record as "Credentials rejected" *and* counted against
            # the officer's consecutive-failure total. It happened: a long
            # analysis held SQLite's write lock, three sign-ins by a legitimate
            # commander raised OperationalError, and the audit log recorded
            # three credential rejections that never occurred.
            #
            # That is the worst kind of defect this system can have. The audit
            # log is the artefact that goes to a court, and it was making a
            # false statement about a named officer while the screen in front of
            # them correctly said the fault was the server's. The counter is
            # also a lockout mechanism, so a busy database could have locked out
            # the person trying to use it.
            #
            # So: distinct action, no counter increment, and the reason recorded.
            log_action(
                request, AuditLog.Action.LOGIN_ERROR,
                username_attempted=username,
                detail=(
                    f'Sign-in could not be completed: {type(exc).__name__}: {exc}. '
                    f'This is not a statement about the credentials offered.'
                ),
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

        monitor_stopped = self._stop_own_monitor(request)

        log_action(
            request, AuditLog.Action.LOGOUT, user=request.user,
            username_attempted=request.user.username,
            detail=('Signed out; refresh token blacklisted' if blacklisted
                    else 'Signed out; no valid refresh token supplied to blacklist'),
        )
        return Response({
            'detail': 'Signed out.',
            'token_blacklisted': blacklisted,
            'monitor_stopped': monitor_stopped,
        })

    @staticmethod
    def _stop_own_monitor(request):
        """
        A live capture is a supervised acquisition, not a background daemon.
        If the officer who started it logs out, the account it is attributed
        to is no longer signed in to see the alerts it raises — so it is
        requested to stop rather than left sniffing unattended.

        Fire-and-forget, not `monitor.stop()`: that call blocks for up to a
        whole window waiting for the capture thread to finish, and a logout
        button that hangs for thirty seconds is its own bug. The capture
        thread already polls `stop_requested` between windows, so setting the
        flag is enough — it stops on its own without holding this request
        open.

        Scoped to this officer's own monitor: a second officer's logout must
        not stop a capture they did not start and are not the one accountable
        for.
        """
        from capture.models import LiveMonitorState

        state = LiveMonitorState.load()
        if state.running and state.started_by_id == request.user.pk:
            LiveMonitorState.objects.filter(pk=1).update(stop_requested=True)
            return True
        return False


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


class SignInAttemptsView(APIView):
    """
    Who tried to sign in, when, from where, and whether it worked.

    Why this exists
    ---------------
    The sign-in page tells every officer that their attempts are recorded with
    a timestamp, a username and a source address. That was true — the rows were
    written faithfully — and there was no way to read them from inside the
    application. A promise nobody can check is a promise on a poster.

    It also closes an objective the problem statement names outright: "secure
    storage and **access logs**". An access log that only a Django superuser
    with shell access can read is not an access log an investigating agency can
    produce.

    What it deliberately does not do
    --------------------------------
    It never shows a password, a token, or the body of any attempt — only what
    the AuditLog already holds. Failed attempts are shown with the username as
    it was typed, which is the point: a run of attempts against a username that
    does not exist is what a credential-stuffing attempt looks like, and hiding
    the string would hide the attack.

    Administrators only. This names officers and source addresses, and it is
    the one view where a viewer account could learn which usernames are real.
    """

    permission_classes = [IsAdministrator]

    # Enough to see a pattern without turning the page into a data dump.
    DEFAULT_LIMIT = 100
    MAX_LIMIT = 500

    SIGN_IN_ACTIONS = (
        AuditLog.Action.LOGIN_SUCCESS,
        AuditLog.Action.LOGIN_FAILED,
        AuditLog.Action.LOGIN_ERROR,
        AuditLog.Action.LOGOUT,
    )

    def get(self, request):
        try:
            limit = int(request.query_params.get('limit', self.DEFAULT_LIMIT))
        except (TypeError, ValueError):
            limit = self.DEFAULT_LIMIT
        limit = max(1, min(limit, self.MAX_LIMIT))

        outcome = (request.query_params.get('outcome') or '').strip()
        rows = AuditLog.objects.filter(action__in=self.SIGN_IN_ACTIONS)
        if outcome == 'failed':
            rows = rows.filter(action__in=(AuditLog.Action.LOGIN_FAILED,
                                           AuditLog.Action.LOGIN_ERROR))
        elif outcome in dict(AuditLog.Action.choices):
            rows = rows.filter(action=outcome)

        username = (request.query_params.get('username') or '').strip()
        if username:
            rows = rows.filter(username_attempted__icontains=username)

        window = timezone.now() - timedelta(hours=24)
        counted = AuditLog.objects.filter(action__in=self.SIGN_IN_ACTIONS)

        # Whether the username exists, resolved by *looking it up*.
        #
        # This was `bool(row.user_id)`, which is false for every failed sign-in
        # — a failure never attaches a user, because authentication is the
        # thing that failed. So the log printed "NO SUCH ACCOUNT" beside the
        # username of a serving officer who had simply mistyped a password.
        #
        # The label exists to separate a mistyped password from a run of
        # attempts against invented usernames, which is what credential
        # stuffing looks like. Getting it backwards inverted the one signal the
        # column was for.
        page = list(rows.select_related('user')[:limit])
        attempted = {row.username_attempted for row in page if row.username_attempted}
        known = set(
            User.objects.filter(username__in=attempted)
            .values_list('username', flat=True)
        ) if attempted else set()

        return Response({
            'attempts': [
                {
                    'id': row.id,
                    'timestamp': row.timestamp.isoformat(),
                    'action': row.action,
                    'action_label': row.get_action_display(),
                    # Whether it worked, as one word, so a reader does not have
                    # to know the action vocabulary to scan the column.
                    'outcome': (
                        'success' if row.action == AuditLog.Action.LOGIN_SUCCESS
                        else 'signed out' if row.action == AuditLog.Action.LOGOUT
                        else 'server fault' if row.action == AuditLog.Action.LOGIN_ERROR
                        else 'refused'
                    ),
                    # As typed. A run against a username that does not exist is
                    # the signature of credential stuffing.
                    'username_attempted': row.username_attempted,
                    'account_exists': row.username_attempted in known,
                    'ip_address': row.ip_address,
                    'user_agent': row.user_agent[:160],
                    'detail': row.detail,
                }
                for row in page
            ],
            'returned': min(limit, rows.count()),
            'total_matching': rows.count(),
            'last_24h': {
                'success': counted.filter(
                    action=AuditLog.Action.LOGIN_SUCCESS,
                    timestamp__gte=window).count(),
                'refused': counted.filter(
                    action=AuditLog.Action.LOGIN_FAILED,
                    timestamp__gte=window).count(),
                'server_fault': counted.filter(
                    action=AuditLog.Action.LOGIN_ERROR,
                    timestamp__gte=window).count(),
            },
            # Named so a reader knows the list is not the whole story where the
            # store has been trimmed.
            'retention_note': (
                'Every sign-in attempt this installation has recorded is held; '
                'nothing here is aged out automatically.'
            ),
        })
