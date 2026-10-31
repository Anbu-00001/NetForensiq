# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
A sign-in limit per account, beside the one per address.

The per-address limit stops one machine guessing quickly. It does nothing about
guesses spread across many addresses at one account, which is the attack that
matters for a handful of named officers. This counts attempts against the
username, whatever address they come from.

The cost is stated rather than hidden: someone who knows an officer's username
can use up that officer's attempts for the hour. Every refused attempt is
recorded with its address, so that is visible, and an administrator can clear
it (manage.py clear_throttle).
"""
import hashlib

from rest_framework.throttling import SimpleRateThrottle


class SignInUsernameThrottle(SimpleRateThrottle):
    scope = 'login_user'

    def get_cache_key(self, request, view):
        username = str(request.data.get('username', '') or '').strip().lower()
        if not username:
            return None
        # Hashed so that any text a client sends makes a safe cache key.
        ident = hashlib.sha256(username.encode('utf-8')).hexdigest()
        return self.cache_format % {'scope': self.scope, 'ident': ident}
