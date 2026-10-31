# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import ipaddress

from django.conf import settings

from .models import AuditLog


def _valid_ip(text):
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return None


def get_client_ip(request):
    """
    The address a request came from, as a valid IP address, or None.

    X-Forwarded-For is written by whoever sends the request, so it is believed
    only as far as proxies the operator has declared (TRUSTED_PROXY_COUNT, which
    sets DRF's NUM_PROXIES so the rate limiter agrees). With none declared, the
    default, it is ignored and the socket address is used.

    Until 31 Oct 2026 the first entry of the header was taken as given. A blind
    audit showed what that allowed: a rotating header got unlimited sign-in
    attempts past the per-address limit, and a signed-in user could write any
    text, including '|', into the custody log's actor_ip.
    """
    proxies = settings.REST_FRAMEWORK.get('NUM_PROXIES') or 0
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if proxies and forwarded:
        hops = [h.strip() for h in forwarded.split(',') if h.strip()]
        if hops:
            # Each trusted proxy appends the address it received from; the
            # client is the entry the outermost trusted proxy wrote.
            return _valid_ip(hops[-min(proxies, len(hops))])
    return _valid_ip(request.META.get('REMOTE_ADDR', ''))


def log_action(request, action, user=None, username_attempted='', detail=''):
    AuditLog.objects.create(
        user=user,
        username_attempted=username_attempted,
        action=action,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')[:300],
        detail=detail,
    )