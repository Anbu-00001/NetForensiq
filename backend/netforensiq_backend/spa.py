"""
Serve the built React application from Django.

Why this exists
---------------
The platform is meant to run in a police room with no internet. Until now it
took two servers to show anything: Django on 8000 and Vite's dev server on
5173. That is fine on a developer's laptop and wrong for a forensic
workstation, because it means Node has to be installed on the evidence machine
and an officer has to start two processes in the right order.

With this module, `manage.py runserver` serves the API *and* the interface on
one port. The air-gapped machine needs Python and nothing else — the frontend
arrives as pre-built files, and the toolchain that produced them stays on the
build machine.

What it is not
--------------
This is the single-workstation path. Django's own file server is used to move
the bytes, which is honest but not fast, and Django's documentation is explicit
that it is not intended to stand in front of the public internet. A multi-user
deployment should put nginx in front, point it at the same `dist` directory,
and proxy `/api/` to Django. Nothing here prevents that; this module simply
means you do not *need* it to run.

The 404 rule
------------
A single-page app needs unknown paths to return `index.html`, or a deep link
like `/evidence` breaks on refresh. Applied carelessly that rule turns every
mistake into a silent success: a mistyped API path returns an HTML page with
status 200, and the caller fails later with "Unexpected token '<'", a very long
way from the cause. Two guards prevent it:

  * paths under a prefix the API owns raise a real 404, and
  * the fallback only applies to requests that asked for HTML.

A missing script or font therefore 404s like a missing file should.
"""

from pathlib import Path

from django.conf import settings
from django.http import Http404, HttpResponse
from django.views.static import serve as serve_static

# Prefixes that belong to Django and must never resolve to the SPA shell.
#
# This list has to agree with urls.py. It is not derived from the URL resolver
# because the catch-all lives in that same resolver and would match itself;
# instead `SpaRoutingTests.test_reserved_prefixes_cover_the_urlconf` walks the
# real urlconf and fails if a mount is added here without being listed. The
# constant is the statement; the test is what keeps it true.
RESERVED_PREFIXES = ('api/', 'admin/', 'static/', 'media/')

INDEX = 'index.html'

# Vite writes a content hash into every asset filename, so an asset URL refers
# to exactly one immutable body — it can be cached for as long as the browser
# likes. index.html carries no hash and is how a new build is discovered, so it
# must never be cached. Getting this backwards is how an officer ends up
# looking at yesterday's interface after an update.
ASSET_CACHE_CONTROL = 'public, max-age=31536000, immutable'
INDEX_CACHE_CONTROL = 'no-cache, no-store, must-revalidate'

NOT_BUILT = """NetForensiq: the frontend has not been built.

Expected to find {index}

Build it on a machine with the toolchain installed:

    cd frontend && npm ci && npm run build

or deploy the offline bundle, which ships the built files:

    scripts/build_offline_bundle.sh     (on a connected machine)
    scripts/install_offline.sh          (on the air-gapped machine)

The API is unaffected and is still answering on /api/.
"""


def dist_root():
    """The directory holding the built frontend, as a Path."""
    return Path(settings.FRONTEND_DIST)


def _is_reserved(path):
    return any(path.startswith(prefix) for prefix in RESERVED_PREFIXES)


def _wants_html(request):
    """
    Whether this request would accept an HTML page in place of what it asked
    for.

    Browsers navigating to a URL send `Accept: text/html,...`. A `fetch()` for
    JSON, and the browser's own request for a script or a stylesheet, do not.
    That difference is exactly the line between "deep link into the app" and
    "this file is missing", so it is the line used here.
    """
    accept = request.headers.get('Accept', '')
    return 'text/html' in accept or '*/*' == accept.strip()


def serve_frontend(request, path=''):
    """
    Serve a built asset, or the app shell for a client-side route.

    Mounted last in the root urlconf, so every Django route is tried first.
    """
    root = dist_root()
    index_path = root / INDEX

    if not index_path.is_file():
        # 503 rather than 404: the resource is not missing, the deployment is
        # incomplete, and the message says how to complete it.
        return HttpResponse(
            NOT_BUILT.format(index=index_path),
            content_type='text/plain; charset=utf-8',
            status=503,
        )

    if _is_reserved(path):
        # Django already had its chance at this path and declined it. Handing
        # back the SPA shell would turn a 404 into a 200 full of HTML.
        raise Http404(f'No route for /{path}')

    if path and path != INDEX:
        try:
            response = serve_static(request, path, document_root=root)
        except Http404:
            if not _wants_html(request):
                raise
        else:
            response.headers['Cache-Control'] = ASSET_CACHE_CONTROL
            return response

    response = serve_static(request, INDEX, document_root=root)
    response.headers['Cache-Control'] = INDEX_CACHE_CONTROL
    return response
