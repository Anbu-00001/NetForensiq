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
# Build on a connected machine, then move the image on removable media:
#
#     docker build -t netforensiq:1.0 .
#     docker save netforensiq:1.0 | gzip > netforensiq-1.0.tar.gz
#     # …carry across…
#     docker load < netforensiq-1.0.tar.gz
#
# `docker save` is the supported way to move an image without a registry.
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
COPY --from=frontend /build/dist /app/frontend_dist

ENV FRONTEND_DIST=/app/frontend_dist \
    STATIC_ROOT=/app/staticfiles

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
USER netforensiq

EXPOSE 8000

# tini as PID 1 so signals reach the server and zombie processes are reaped —
# a Python process as PID 1 ignores SIGTERM by default, which turns every
# `docker stop` into a ten-second timeout and a SIGKILL.
ENTRYPOINT ["/usr/bin/tini", "--"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/engine/', timeout=4).status==200 else 1)"

CMD ["gunicorn", "netforensiq_backend.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--timeout", "300", \
     "--access-logfile", "-"]
