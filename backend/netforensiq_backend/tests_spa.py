"""
Tests for serving the built frontend from Django.

The point of this route is that an air-gapped machine runs one process. The
risk of this route is that a catch-all quietly answers everything, so most of
what follows is about the things it must *refuse* to answer.
"""

import tempfile
from pathlib import Path

from django.test import SimpleTestCase, override_settings
from django.urls import get_resolver

from .spa import INDEX, RESERVED_PREFIXES

HTML = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

_dist = tempfile.TemporaryDirectory()
DIST = Path(_dist.name)
(DIST / INDEX).write_text('<!doctype html><div id="root"></div>')
(DIST / 'assets').mkdir()
(DIST / 'assets' / 'index-abc123.js').write_text('console.log(1)')


@override_settings(FRONTEND_DIST=str(DIST))
class SpaRoutingTests(SimpleTestCase):
    def test_root_serves_the_app_shell(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="root"', b''.join(response.streaming_content))

    def test_client_side_route_serves_the_shell(self):
        """
        /evidence is a React Router path, not a file. Refreshing the page on it
        has to work, which means the server must answer with the shell and let
        the router sort it out.
        """
        response = self.client.get('/evidence', HTTP_ACCEPT=HTML)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="root"', b''.join(response.streaming_content))

    def test_built_asset_is_served(self):
        response = self.client.get('/assets/index-abc123.js')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b''.join(response.streaming_content), b'console.log(1)')

    def test_unknown_api_path_is_a_real_404(self):
        """
        The failure this guards against is subtle and expensive: a catch-all
        that answers /api/typo with the HTML shell and status 200. The caller
        then fails on `JSON.parse`, reporting a syntax error in a place with no
        connection to the mistake.
        """
        for path in ('/api/nonexistent', '/api/sessions/999999/bogus'):
            with self.subTest(path=path):
                response = self.client.get(path, HTTP_ACCEPT=HTML)
                self.assertEqual(response.status_code, 404)
                self.assertNotIn(b'id="root"', response.content)

    def test_missing_asset_404s_rather_than_returning_html(self):
        """
        The header a browser actually sends for a script, a stylesheet or a
        font — not the one it is convenient to assume.

        The first version of this route decided the question from the Accept
        header and treated a bare `*/*` as "wants HTML". Chrome sends exactly
        that for `<script src>` and for `@font-face`, and `fetch()` sends it by
        default, so a missing bundle came back as index.html with status 200
        and the browser reported a syntax error in a file it had never asked
        for. The rule is now taken from the path instead.
        """
        headers = {
            'script or fetch': '*/*',
            'stylesheet': 'text/css,*/*;q=0.1',
            'image': 'image/avif,image/webp,*/*',
            'font': '*/*',
        }
        for label, accept in headers.items():
            for path in ('/assets/does-not-exist.js',
                         '/assets/missing.woff2',
                         '/assets/missing.css'):
                with self.subTest(sent_by=label, path=path):
                    response = self.client.get(path, HTTP_ACCEPT=accept)
                    self.assertEqual(
                        response.status_code, 404,
                        f'{path} requested with Accept: {accept} must 404',
                    )

    def test_a_navigation_to_a_screen_reaches_the_app(self):
        """The other half of the same rule: a browser arriving at a deep link."""
        for path in ('/evidence', '/dashboard', '/detections'):
            with self.subTest(path=path):
                response = self.client.get(path, HTTP_ACCEPT=HTML)
                self.assertEqual(response.status_code, 200)
                self.assertIn(b'id="root"', b''.join(response.streaming_content))

    def test_the_root_answers_however_it_is_asked(self):
        """`curl http://host/` is how a person checks the server is up."""
        for accept in ('*/*', HTML, ''):
            with self.subTest(accept=accept or '(none)'):
                response = self.client.get('/', HTTP_ACCEPT=accept)
                self.assertEqual(response.status_code, 200)

    def test_a_data_request_to_an_unknown_path_404s(self):
        """
        The failure this prevents: a frontend built with a mistyped API base —
        `/apiv2` rather than `/api` — receiving the app shell with status 200
        for every call it makes, and reporting a JSON parse error that names
        neither the wrong path nor the reason.
        """
        for path in ('/apiv2/sessions/', '/api-v2/flows', '/graphql'):
            with self.subTest(path=path):
                response = self.client.get(path, HTTP_ACCEPT='*/*')
                self.assertEqual(response.status_code, 404)

    def test_traversal_out_of_the_dist_directory_is_refused(self):
        for path in ('/../settings.py', '/assets/../../settings.py',
                     '/%2e%2e/settings.py'):
            with self.subTest(path=path):
                response = self.client.get(path, HTTP_ACCEPT=HTML)
                body = (b''.join(response.streaming_content)
                        if response.streaming else response.content)
                self.assertNotIn(b'SECRET_KEY', body)

    def test_asset_and_shell_get_opposite_cache_policies(self):
        """
        Vite hashes asset filenames, so an asset URL is immutable and index.html
        is how a new build is found. Caching them the same way means either no
        caching at all, or an officer looking at a stale interface after an
        update.
        """
        asset = self.client.get('/assets/index-abc123.js')
        self.assertIn('immutable', asset.headers['Cache-Control'])

        shell = self.client.get('/', HTTP_ACCEPT=HTML)
        self.assertIn('no-store', shell.headers['Cache-Control'])

    def test_collected_static_is_served(self):
        """
        The admin's own CSS. Django serves this itself only while DEBUG is on,
        and a deployment runs with DEBUG off — without the route this covers,
        the admin renders as unstyled HTML with nothing to say why.
        """
        static_root = DIST / 'collected'
        (static_root / 'admin' / 'css').mkdir(parents=True, exist_ok=True)
        (static_root / 'admin' / 'css' / 'base.css').write_text('body{color:#000}')

        with override_settings(STATIC_ROOT=str(static_root)):
            response = self.client.get('/static/admin/css/base.css')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b''.join(response.streaming_content), b'body{color:#000}')

    def test_a_missing_static_file_404s(self):
        with override_settings(STATIC_ROOT=str(DIST / 'collected')):
            response = self.client.get('/static/admin/css/nope.css')
        self.assertEqual(response.status_code, 404)

    def test_reserved_prefixes_cover_the_urlconf(self):
        """
        Every mount in urls.py except the catch-all itself must be reserved,
        or that mount's 404s start returning the SPA shell. Adding a route
        without adding its prefix should fail here, not in production.
        """
        uncovered = []
        for pattern in get_resolver().url_patterns:
            if getattr(pattern, 'name', None) == 'frontend':
                continue
            route = str(pattern.pattern).lstrip('^')
            if not any(route.startswith(p) for p in RESERVED_PREFIXES):
                uncovered.append(route)
        self.assertEqual(
            uncovered, [],
            f'urls.py mounts {uncovered} but spa.RESERVED_PREFIXES does not '
            f'list them; their 404s would return the app shell instead.',
        )


@override_settings(FRONTEND_DIST=str(Path(tempfile.gettempdir()) / 'nf-no-such-dist'))
class SpaNotBuiltTests(SimpleTestCase):
    def test_missing_build_explains_itself(self):
        """
        A developer who has not run `npm run build` should be told that, not
        shown a 404 or a stack trace. 503 because the deployment is incomplete,
        not because the page does not exist.
        """
        response = self.client.get('/', HTTP_ACCEPT=HTML)
        self.assertEqual(response.status_code, 503)
        self.assertIn(b'npm run build', response.content)

    def test_api_still_works_without_a_build(self):
        response = self.client.get('/api/engine/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('rule_count', response.json())
