# NetForensiq — one image serving the API and the interface.
#
# Why a single image rather than two
# ----------------------------------
# Django already serves the built frontend (netforensiq_backend/spa.py), which
# is what makes the air-gapped single-workstation deployment one process. The
# container follows the same shape: the React build happens here, at build
# time, and the runtime image carries only the static output. Node never
# reaches the machine that handles evidence.
#
# Air-gapped use
# --------------
# The running container needs no network. Verified by running it under
# `--network none`, where a socket to 1.1.1.1 fails with "Network is
# unreachable" and the platform still seals a capture, analyses it and issues a
# Section 63 certificate.
#
# BUILDING needs a network — this file pulls two base images and runs apt-get,
# npm ci and pip install. So the build happens on a connected machine and the
# result is carried across:
#
#     ./scripts/save_airgap_images.sh 1.1
#     # …carry airgap-images/ across…
#     ./scripts/load_airgap_images.sh airgap-images
#
# Use those scripts rather than a bare `docker save netforensiq:...`. Compose
# also starts Postgres, and on the target `docker compose up` fails when it
# tries to pull postgres:17-alpine — after printing enough to look like it is
# working. The scripts save and verify both images.
#
# `docker compose up --build` on an air-gapped machine cannot work, by
# definition. Use `docker compose up` with both images already loaded, or run
# this image on its own against SQLite, which needs no second container at all.
#
# scripts/build_offline_bundle.sh remains the path for machines with no Docker.

# ── stage 1: build the interface ──────────────────────────────────────────
FROM node:22-slim AS frontend

WORKDIR /build
# Copied separately from the source so a change to a component does not
# invalidate the dependency layer — npm ci is the slow step.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
# Same-origin /api, because Django serves this bundle from the same port.
RUN npm run build


# ── stage 2: the runtime ──────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# PYTHONUNBUFFERED so container logs appear as they happen rather than when a
# buffer fills — the difference between watching an import and guessing at it.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DJANGO_SETTINGS_MODULE=netforensiq_backend.settings

# libpcap is scapy's dependency for live capture. Reading a .pcap file is pure
# Python and needs none of this, but a container that can only read files
# cannot do half of what the platform does.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libpcap0.8 \
        tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
# The version file lives at the repository root, outside the build context
# copied above. Without this the container reports 0.0.0-unknown on its own
# landing page — see netforensiq_backend/version.py.
COPY VERSION ./
COPY --from=frontend /build/dist /app/frontend_dist

ENV FRONTEND_DIST=/app/frontend_dist \
    STATIC_ROOT=/app/staticfiles \
    # On a persisted volume, not the container filesystem.
    #
    # The default is BASE_DIR/.evidence.key, which inside a container is
    # /app/.evidence.key — a path that exists only for the life of that
    # container. Recreating it (a rebuild, an image bump, `docker rm`)
    # silently destroyed the key, and with it every encrypted exhibit: the
    # files survived on their volume and became permanently unreadable.
    #
    # /app/data is the volume the database already lives on, so the key
    # survives. That does put the key beside the data it protects, which is
    # weaker than it should be — a real deployment supplies
    # EVIDENCE_ENCRYPTION_KEY from a secrets manager instead and never writes
    # it to this disk. See RUN_OFFLINE.md.
    EVIDENCE_KEY_FILE=/app/data/.evidence.key

RUN python manage.py collectstatic --noinput

# Runs as a non-root user.
#
# A container handling seized evidence should not be able to write outside the
# paths it owns, and a compromise of the web process should not be a root
# compromise of the container. The evidence store and database directory are
# created and chowned here so the volumes mount writable.
RUN useradd --create-home --uid 10001 netforensiq \
    && mkdir -p /app/evidence_store /app/data \
    && chown -R netforensiq:netforensiq /app

# Raw-socket access for live capture, granted to the interpreter itself.
#
# The container runs as a non-root user, so `--cap-add=NET_RAW` on `docker
# run` is necessary but not sufficient: it puts the capability in the
# container's bounding set, and an unprivileged process still has to inherit
# it from somewhere. A file capability on the interpreter is that somewhere.
#
# Without this, live capture fails in the worst possible way — scapy opens no
# socket, reports no error, and the session completes claiming zero packets,
# which is indistinguishable from a quiet network. `/api/sessions/interfaces/`
# checks for the capability up front and refuses rather than pretending, but
# refusing is not the outcome anyone wants at a demonstration.
#
# It was previously applied by hand inside a running container, which meant it
# vanished the next time the container was recreated. Baking it into the image
# is the difference between "worked when we tried it" and "works".
#
# Narrower than running as root: it permits packet capture and nothing else.
# Reading a stored .pcap has never needed it.
# p7zip reads compression methods the standard library does not (Deflate64
# above all), which Android packers use specifically to break naive parsers.
# Kept installed, unlike libcap2-bin, because it is needed at run time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends p7zip-full \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(command -v python3)")" \
    && apt-get purge -y libcap2-bin \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

USER netforensiq

EXPOSE 8000

# tini as PID 1 so signals reach the server and zombie processes are reaped —
# a Python process as PID 1 ignores SIGTERM by default, which turns every
# `docker stop` into a ten-second timeout and a SIGKILL.
ENTRYPOINT ["/usr/bin/tini", "--"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/engine/', timeout=4).status==200 else 1)"

# --timeout is the ceiling on one synchronous request, and browser-uploaded
# PCAP import is the longest one there is: the file is hashed, sealed, parsed
# and flow-aggregated in-process, with no queue to hand it off to.
#
# The default 300s was killing large-but-legitimate imports mid-parse — a real
# 200MB / 2.27M-packet capture took ~530s, so gunicorn aborted the worker and
# the officer saw "the upload failed" for a file that was perfectly good.
# `capture/fastparse.py` has since cut the parse to a fraction of that, but the
# ceiling stays high deliberately: it is a backstop for the largest file the
# browser path accepts (512MB), not a target, and a timeout tuned to the
# machine that happened to be measured is a timeout that fails on a slower one.
# Imports beyond the upload cap are routed to `manage.py import_pcap`, which
# has no timeout at all.
CMD ["gunicorn", "netforensiq_backend.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--timeout", "1800", \
     "--access-logfile", "-"]
