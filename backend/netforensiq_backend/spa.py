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
one port. The evidence machine needs Python 3 and the POSIX utilities any Linux
install already has — the frontend arrives as pre-built files, and the Node
toolchain that produced them stays on the build machine.

What it is not
--------------
This is the single-workstation path, and the tradeoff should be stated rather
than glossed. The bytes are moved by `django.views.static.serve`, which
Django's own documentation calls "inefficient and insecure" and tells you not
to use in production. That warning is aimed at a server exposed to the
internet; this one is bound to loopback on a machine with no network at all,
which is the case where the warning does not bite. It is used deliberately, not
in ignorance of the advice.

A multi-user or network-reachable deployment should put nginx in front, point
it at the same `dist` directory, and proxy `/api/` to Django. Nothing here
prevents that; this module means you do not *need* it in order to run.

The 404 rule
------------
A single-page app needs unknown paths to return `index.html`, or a deep link
like `/evidence` breaks on refresh. Applied carelessly that rule turns every
mistake into a silent success: a mistyped API path returns an HTML page with
status 200, and the caller fails later with "Unexpected token '<'", a very long
way from the cause. Three guards prevent it:

  * paths under a prefix the API owns raise a real 404,
  * paths that name a file 404 when that file is absent, and
  * only a browser *navigating* — which is the one thing that sends
    `Accept: text/html` — receives the shell for an unknown path.

So a missing script 404s like the missing file it is, a `fetch()` to a path
that does not exist 404s rather than returning a page, and `/evidence` — a
screen, not a file — still reaches the app.
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
ASSET_CACHE_CONTROL = f'public, max-age={365 * 24 * 60 * 60}, immutable'
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


def _looks_like_a_file(path):
    """
    Whether the last path segment carries a filename extension.

    `/assets/index-abc123.js` names a file; `/evidence` names a screen. That
    distinction is what decides whether a miss is a 404 or a client-side route,
    and it is taken from the path because the alternative — reading the Accept
    header — does not work. Chrome sends a bare `Accept: */*` for `<script
    src>` and for `@font-face`, exactly as `fetch()` does by default, so an
    Accept-based rule hands the browser index.html where a script was expected
    and produces `Unexpected token '<'` a long way from the cause. That bug was
    written here first and caught by the browser suite.

    A client-side route containing a dot would be misread as a file. None
    exists, and inventing one would be a stranger choice than this rule.
    """
    return '.' in path.rsplit('/', 1)[-1]


def _is_navigation(request, path):
    """
    Whether this is a person arriving at a screen, rather than code asking for
    data.

    Every browser sends `Accept: text/html,...` when it navigates to a URL, and
    nothing else does — `fetch()` and XHR default to `*/*`. So an unknown path
    reached with `*/*` is a client asking for something that is not there, and
    the honest answer is 404.

    That matters beyond tidiness. A frontend built with a mistyped API base —
    `/apiv2` instead of `/api` — would otherwise receive the app shell with
    status 200 for every call, and fail on `JSON.parse` with a message naming
    neither the wrong path nor the reason.

    The root is the exception: a bare `curl http://host/` sends `*/*` and is how
    a person checks the server is up. It gets the app.
    """
    return path == '' or 'text/html' in request.headers.get('Accept', '')


def serve_collected_static(request, path):
    """
    Serve Django's own collected static files — the admin's CSS and JavaScript.

    `django.contrib.staticfiles` serves these automatically, but only while
    DEBUG is on. A deployment runs with DEBUG off, and normally a reverse proxy
    takes over the job. The air-gapped workstation has no reverse proxy, so
    without this the admin renders as unstyled HTML and nothing says why.

    Harmless in development: `runserver` intercepts STATIC_URL before URL
    resolution reaches here, so this route only does anything once DEBUG is off
    and `collectstatic` has run.
    """
    return serve_static(request, path, document_root=settings.STATIC_ROOT)


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
            # Fall through to the app shell only for a navigation to something
            # that does not name a file. A missing script, stylesheet or font
            # must 404 like the missing file it is, and so must a data request
            # to a path that does not exist.
            if _looks_like_a_file(path) or not _is_navigation(request, path):
                raise
        else:
            response.headers['Cache-Control'] = ASSET_CACHE_CONTROL
            return response

    response = serve_static(request, INDEX, document_root=root)
    response.headers['Cache-Control'] = INDEX_CACHE_CONTROL
    return response
