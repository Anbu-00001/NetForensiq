# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Transport security, and the one switch that removes Django's admin site.

`manage.py check --deploy` reports five warnings against the shipped settings
(HSTS, SSL redirect, secure session cookie, secure CSRF cookie, a short
secret key). Four of them are one decision: is this served over HTTPS? The
shipped default is plain HTTP on loopback, so turning them on unconditionally
would stop a browser reaching it at all. They are therefore all behind one
switch, off by default, with the reason written down.

Kept as a function of the environment, like throttles.py, so a test can state
what each environment gives without reloading the settings module.
"""

TRUE = {'1', 'true', 'yes', 'on'}

# A browser holds an HSTS instruction for the whole period and it cannot be
# withdrawn, so the default is short. One hour is this project's choice, not a
# standard; Django's documentation advises starting small and raising it.
DEFAULT_HSTS_SECONDS = 3600


def flag(value, default=False):
    """True/false from an environment string; an empty or missing one is the default."""
    if value is None or str(value).strip() == '':
        return default
    return str(value).strip().lower() in TRUE


def transport_settings(environ, trusted_proxies=0):
    """The Django settings that follow from HTTPS_ONLY, as a dict."""
    if not flag(environ.get('HTTPS_ONLY')):
        return {}
    settings = {
        'SECURE_SSL_REDIRECT': True,
        'SESSION_COOKIE_SECURE': True,
        'CSRF_COOKIE_SECURE': True,
        'SECURE_HSTS_SECONDS': int(environ.get('SECURE_HSTS_SECONDS') or DEFAULT_HSTS_SECONDS),
    }
    # Only when a proxy is declared: the header is otherwise written by the
    # client, and believing it would let anyone claim their request was HTTPS.
    if trusted_proxies:
        settings['SECURE_PROXY_SSL_HEADER'] = ('HTTP_X_FORWARDED_PROTO', 'https')
    return settings


def admin_enabled(environ):
    """Django's /admin/ is mounted unless ADMIN_ENABLED says otherwise."""
    return flag(environ.get('ADMIN_ENABLED'), default=True)
