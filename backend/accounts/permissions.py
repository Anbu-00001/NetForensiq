"""
Role-based permissions.

Registration asks an applicant to choose a "clearance level" and states that
Administrator cannot be self-requested. The role was stored and the admin
choice was blocked — but nothing anywhere checked it. A `viewer` could triage
findings, re-verify exhibits, issue a Section 63 certificate and countersign
it, because every endpoint was `IsAuthenticated`. A clearance that governs
nothing is worse than no clearance: it tells an officer an access model exists
when it does not.

The split is by consequence, not by convenience:

  * **Reading** — anyone approved. Investigations are collaborative and a
    viewer who cannot see the evidence is useless.
  * **Recording an opinion** (triage) — investigator or admin. A triage
    decision is attributed to a named officer and is the sort of thing quoted
    back in cross-examination.
  * **Acting on evidence** (verify, issue or countersign a certificate) —
    investigator or admin. A Section 63 certificate is a statutory declaration.

Approval is enforced alongside role: an account awaiting admin approval must
not act merely because it holds a token.
"""

from rest_framework.permissions import SAFE_METHODS, BasePermission

from .models import User


class IsApproved(BasePermission):
    """Authenticated, and an administrator has approved the account."""

    message = 'This account is awaiting administrator approval.'

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and (user.is_superuser or getattr(user, 'is_approved', False))
        )


class IsInvestigatorOrReadOnly(BasePermission):
    """
    Read for any approved account; write for investigators and admins.

    Applies to DRF's unsafe methods *and* to the POST-based custom actions that
    carry the real consequences here — triage, verify, certificate, sign — none
    of which are safe methods, so the SAFE_METHODS check covers them.
    """

    message = (
        'Your clearance is Viewer. Recording a decision on evidence requires '
        'Investigator clearance or above.'
    )

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            return False
        if not (user.is_superuser or getattr(user, 'is_approved', False)):
            return False
        if request.method in SAFE_METHODS:
            return True
        return (
            user.is_superuser
            or getattr(user, 'role', None) in (User.Role.ADMIN, User.Role.INVESTIGATOR)
        )


class IsAdministrator(BasePermission):
    """
    Administrators only.

    Approving an account is the act that decides who may touch evidence at all,
    so it sits above the investigator/viewer split rather than inside it. A
    Django superuser counts, because that is who bootstraps the first
    administrator on a fresh install.
    """

    message = 'Approving accounts requires Administrator clearance.'

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and (user.is_superuser or getattr(user, 'role', None) == User.Role.ADMIN)
        )


class CanReadCommunicationContent(BasePermission):
    """
    Investigators and administrators only — including for GET.

    Every other endpoint here treats a read as harmless, because every other
    endpoint returns metadata: who spoke to whom, how much, how often. A
    reconstructed session is different in kind. It is the substance of the
    communication, and handing it to a read-only records account because the
    HTTP verb happened to be GET is the wrong default.

    So this permission deliberately does NOT exempt safe methods. It is the one
    place in the API where reading is the privileged act.
    """

    message = (
        'Your clearance is Viewer. Reading the contents of a communication '
        'requires Investigator clearance or above; the summary and the flow '
        'record remain available to you.'
    )

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            return False
        if not (user.is_superuser or getattr(user, 'is_approved', False)):
            return False
        return (
            user.is_superuser
            or getattr(user, 'role', None) in (User.Role.ADMIN, User.Role.INVESTIGATOR)
        )
