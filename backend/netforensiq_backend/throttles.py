# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Request rate limits, and where each number comes from.

These are this project's own figures, not a standard. What matters is that the
shipped default is a real limit: from 21 Aug to 30 Oct 2026 every default here
was 10000/hour, raised so that demonstrations would not lock anyone out, while
PROGRESS.md and .env.example went on saying the sign-in limit was eight. The
documented numbers are now the defaults again, and a test holds them there.

A demonstration that signs in as several roles over and over can still exhaust
the sign-in limit. Raising it is a deliberate act with the value written down,
for example LOGIN_THROTTLE_RATE=200/hour in the environment of that one run.
"""

# Scope -> (environment variable that overrides it, default).
RATES = {
    # Anonymous requests per source address, across every public endpoint that
    # has no scope of its own.
    'anon': ('ANON_THROTTLE_RATE', '30/hour'),
    'user': ('USER_THROTTLE_RATE', '1000/hour'),
    # Eight sign-in attempts an hour per source address. Every refused attempt
    # is also counted on the account itself (accounts/views.py), so an attacker
    # who changes address is still recorded.
    'login': ('LOGIN_THROTTLE_RATE', '8/hour'),
    # Attempts at one account from any number of addresses (accounts/throttles.py).
    'login_user': ('LOGIN_USER_THROTTLE_RATE', '10/hour'),
    'register': ('REGISTER_THROTTLE_RATE', '5/hour'),
    'approval_status': ('APPROVAL_STATUS_THROTTLE_RATE', '20/hour'),
    'public_verify': ('PUBLIC_VERIFY_THROTTLE_RATE', '60/hour'),
    'upload': ('UPLOAD_THROTTLE_RATE', '20/hour'),
    # The interface asks /api/engine/ on every visit, so this one is generous.
    'engine': ('ENGINE_THROTTLE_RATE', '600/hour'),
}


def throttle_rates(environ, testing=False):
    """
    The rate for each scope. Under test the defaults are used whatever the
    environment says, so a developer's demo override cannot weaken the throttle
    tests. An empty variable counts as unset.
    """
    return {scope: (default if testing else (environ.get(var) or default))
            for scope, (var, default) in RATES.items()}
