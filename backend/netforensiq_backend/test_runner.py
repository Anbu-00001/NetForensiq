"""
Test runner that gives the suite its own cache.

Why this exists
---------------
DRF's login throttle keeps its counters in the Django cache, and the default
cache is a directory under the backend. The test *database* is created fresh
for every run; the cache is not. So running the app and then running
`manage.py test` — the obvious order for anyone reviewing the project — left
the throttle already exhausted, and 27 tests failed on a 429 unrelated to
anything they were testing.

verify.sh papered over it by clearing the cache first, which meant the harness
was green while the command in the README was not.

The temp directory uses the same file-based backend as a deployment rather
than LocMemCache, so throttle behaviour under test still matches production:
counters shared between processes, surviving within a run.
"""

import tempfile

from django.test.runner import DiscoverRunner
from django.test.utils import override_settings


class IsolatedCacheRunner(DiscoverRunner):

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        self._cache_dir = tempfile.TemporaryDirectory(prefix='netforensiq-test-cache-')
        self._cache_override = override_settings(CACHES={
            'default': {
                'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
                'LOCATION': self._cache_dir.name,
            },
        })
        # enable() fires setting_changed, which resets Django's cache handler,
        # so anything that grabbed `caches['default']` earlier gets the new one.
        self._cache_override.enable()

    def teardown_test_environment(self, **kwargs):
        self._cache_override.disable()
        self._cache_dir.cleanup()
        super().teardown_test_environment(**kwargs)
