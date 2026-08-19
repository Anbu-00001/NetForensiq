#!/usr/bin/env bash
#
# Install NetForensiq on a machine with no internet.
#
#   ./scripts/install_offline.sh [install-dir]
#
# Run this from inside an extracted bundle produced by build_offline_bundle.sh
# on a connected machine. Nothing here reaches the network: pip is run with
# --no-index, so if a dependency were missing from the bundle this fails
# immediately and says which one, rather than hanging on a socket that will
# never connect.
#
# What the target machine needs
# -----------------------------
# Python 3, matching the version the bundle was built with, and nothing else.
# No Node, no npm, no compiler, no PostgreSQL — the interface arrives already
# built and the database defaults to SQLite in a single file.

set -euo pipefail

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$BUNDLE}"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()   { printf '\033[32m✔ %s\033[0m\n' "$1"; }
warn() { printf '\033[33m! %s\033[0m\n' "$1"; }
die()  { printf '\033[31m✘ %s\033[0m\n' "$1" >&2; exit 1; }

[[ -f "$BUNDLE/BUNDLE.json" ]] || die "no BUNDLE.json — run this from inside an extracted bundle"

read_manifest() {
  # The path and key go in as arguments rather than being interpolated into the
  # program text: a bundle unpacked into a directory whose name contains a
  # quote would otherwise produce a syntax error instead of an answer.
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' \
    "$BUNDLE/BUNDLE.json" "$1"
}

# --- 1. Refuse a mismatch rather than fail halfway --------------------------
step "Checking this machine against the bundle"
command -v python3 >/dev/null || die "python3 is not installed"

WANT_PY="$(read_manifest python)"
WANT_PLATFORM="$(read_manifest platform)"
HAVE_PY="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
HAVE_PLATFORM="$(python3 -c 'import platform; print(f"{platform.system().lower()}-{platform.machine()}")')"

# Compiled wheels — cryptography, numpy, scikit-learn — are built against a
# specific Python minor version and CPU architecture. Installing the wrong ones
# does not fail cleanly; it fails at import time, later, somewhere confusing.
[[ "$HAVE_PY" == "$WANT_PY" ]] \
  || die "bundle was built for Python $WANT_PY, this machine has $HAVE_PY.
Rebuild the bundle on a machine with Python $HAVE_PY."
[[ "$HAVE_PLATFORM" == "$WANT_PLATFORM" ]] \
  || die "bundle was built for $WANT_PLATFORM, this machine is $HAVE_PLATFORM.
Rebuild the bundle on matching hardware."
ok "Python $HAVE_PY on $HAVE_PLATFORM, version $(read_manifest version)"

# --- 2. Verify the bundle arrived intact ------------------------------------
step "Verifying the bundle"
if [[ -f "$BUNDLE/SHA256SUMS" ]] && command -v sha256sum >/dev/null; then
  # This is a transfer check, not a security control. It catches a truncated
  # copy onto a USB stick, which is a real thing that happens; it does not
  # detect deliberate tampering, because an attacker who can edit the files can
  # edit SHA256SUMS beside them.
  if ( cd "$BUNDLE" && sha256sum --quiet --check SHA256SUMS ); then
    ok "$(wc -l < "$BUNDLE/SHA256SUMS") files match the manifest"
  else
    die "checksum mismatch — the copy is incomplete or corrupt. Transfer again."
  fi
else
  warn "no SHA256SUMS or no sha256sum available; skipping the transfer check"
fi

# --- 3. Python environment, from the bundled wheels only --------------------
step "Creating the virtual environment"
VENV="$TARGET/backend/.venv"

# On Debian and Ubuntu, `python3 -m venv` lives in a separate `python3-venv`
# package, and a machine with no network cannot apt-get it. Rather than fail
# with pip's own message — which advises installing a package that cannot be
# installed — fall back to a venv without pip and bootstrap pip out of the
# bundle. A pip wheel is a zip that can be executed directly by putting it on
# sys.path, which is exactly how pip installs itself.
if python3 -m venv "$VENV" 2>/dev/null; then
  ok "$VENV"
else
  warn "python3 -m venv could not provision pip (on Debian/Ubuntu this means"
  warn "the python3-venv package is absent). Bootstrapping pip from the bundle."
  rm -rf "$VENV"
  python3 -m venv --without-pip "$VENV" \
    || die "python3 -m venv is unavailable entirely.
Install the python3-venv package for Python $HAVE_PY on this machine, or
rebuild the bundle against a Python that ships venv."

  PIP_WHEEL="$(find "$BUNDLE/wheelhouse" -maxdepth 1 -name 'pip-*.whl' | head -1)"
  [[ -n "$PIP_WHEEL" ]] || die "no pip wheel in the bundle to bootstrap from"
  PYTHONPATH="$PIP_WHEEL" "$VENV/bin/python" -m pip install \
    --no-index --find-links "$BUNDLE/wheelhouse" pip setuptools wheel >/dev/null \
    || die "could not bootstrap pip from $PIP_WHEEL"
  ok "$VENV (pip bootstrapped from the bundle)"
fi

step "Installing dependencies — no index, bundled wheels only"
"$VENV/bin/python" -m pip install --no-index --find-links "$BUNDLE/wheelhouse" \
  --upgrade pip setuptools wheel >/dev/null 2>&1 || true
"$VENV/bin/python" -m pip install --no-index --find-links "$BUNDLE/wheelhouse" \
  --requirement "$TARGET/backend/requirements.txt" \
  || die "install failed. --no-index means pip did not fall back to the network:
a package is missing from wheelhouse/, or was built for a different platform."
ok "$("$VENV/bin/python" -m pip list --format=freeze | wc -l) packages, none fetched"

# --- 3b. A stable signing key ----------------------------------------------
step "Generating the signing key"
# settings.py falls back to a fresh random SECRET_KEY when none is configured,
# which keeps a clone runnable but means every restart invalidates every issued
# token. On a workstation that is rebooted between shifts that is not a
# nuisance, it is an officer being signed out mid-case with no explanation. The
# key is generated here, once, on the machine that will use it — it is never
# carried in the bundle, because a signing key shared across every install is
# not a secret.
ENV_FILE="$TARGET/backend/.env"
if [[ -f "$ENV_FILE" ]] && grep -qE '^SECRET_KEY=.+' "$ENV_FILE"; then
  ok "existing SECRET_KEY left untouched"
else
  KEY="$("$VENV/bin/python" -c 'import secrets; print(secrets.token_urlsafe(50))')"
  touch "$ENV_FILE"
  # Remove any empty placeholder first so the file does not end up with two.
  grep -vE '^SECRET_KEY=' "$ENV_FILE" > "$ENV_FILE.tmp" || true
  mv "$ENV_FILE.tmp" "$ENV_FILE"
  printf 'SECRET_KEY=%s\n' "$KEY" >> "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  ok "written to $ENV_FILE (mode 600)"
fi

# --- 4. Database ------------------------------------------------------------
step "Preparing the database"
( cd "$TARGET/backend" && "$VENV/bin/python" manage.py migrate --noinput ) \
  || die "migrations failed"
ok "schema applied"

step "Collecting Django's own static files"
# Django serves the admin's CSS itself only while DEBUG is on. A deployment
# runs with DEBUG off and there is no reverse proxy here, so without this step
# the admin renders as unstyled HTML with nothing to say why. Purely a local
# file copy — no network.
( cd "$TARGET/backend" && "$VENV/bin/python" manage.py collectstatic --noinput ) >/dev/null \
  || die "collectstatic failed"
ok "admin assets collected"

# --- 5. Tell the operator what to do next -----------------------------------
DIST="$TARGET/frontend/dist"
step "Ready"
cat <<NEXT
Create the first administrator:

    cd $TARGET/backend
    .venv/bin/python manage.py createsuperuser

Start the platform — API and interface, one process, one port:

    cd $TARGET/backend
    FRONTEND_DIST=$DIST .venv/bin/python manage.py runserver 127.0.0.1:8000

Then open http://127.0.0.1:8000 in a browser on this machine.

Import a capture:

    .venv/bin/python manage.py import_pcap <file.pcap>

Nothing above needs a network. The machine may stay disconnected.
NEXT
