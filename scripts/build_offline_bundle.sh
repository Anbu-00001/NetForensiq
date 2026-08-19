#!/usr/bin/env bash
#
# Produce a bundle that installs and runs with no internet at all.
#
#   ./scripts/build_offline_bundle.sh [output-dir] [--with-reference-captures]
#
# Run this on a machine that HAS internet. Carry the result to the one that
# does not.
#
# What the problem actually is
# ----------------------------
# NetForensiq needs no network to *run* — it makes no outbound request, the
# fonts are bundled, and there is no threat feed to refresh. What needs the
# network is *installing* it: `pip install` fetches from PyPI and `npm install`
# fetches from the npm registry. That is the whole air-gap problem, and it is
# solved by moving both of those steps to this side of the wall.
#
# So the bundle carries:
#   * every Python dependency as a pre-built wheel — no compiler needed, and
#     no index consulted, on the target;
#   * the frontend already built to static files — so Node is never installed
#     on the evidence machine at all;
#   * the source, the migrations, and a manifest with a SHA-256 for every file.
#
# Platform note, and it matters
# -----------------------------
# Wheels are specific to the operating system, the CPU architecture and the
# Python minor version. cryptography, scapy's dependencies and psycopg2 all
# ship compiled code. A bundle built with Python 3.12 on x86-64 Linux will not
# install under Python 3.11, or on ARM, or on Windows. The manifest records
# what this bundle was built for, and install_offline.sh refuses to proceed on
# a mismatch rather than failing halfway through with a compiler error.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

# Third-party reference captures are opt-in.
#
# backend/reference_captures/ holds 70 MB of real malware traffic from
# malware-traffic-analysis.net. They are what makes a demonstration real, and
# an air-gapped machine cannot run fetch_reference_captures.sh to get them — so
# for a demo they belong in the bundle. They are also somebody else's files,
# they double its size, and a police deployment analysing its own captures has
# no use for them. Silently redistributing another party's malware corpus
# inside an installer is not a default worth having, so it is a flag.
WITH_CAPTURES=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --with-reference-captures) WITH_CAPTURES=1 ;;
    -h|--help)
      # Read the header block itself rather than a line range: the range was
      # '2,30p' and the header had already grown past it, so --help printed a
      # truncated sentence. This stops at the first line that is not a comment,
      # so it stays right however the header changes.
      awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
      exit 0 ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *) ARGS+=("$arg") ;;
  esac
done

OUT_DIR="${ARGS[0]:-$ROOT/build}"
VERSION="$(cat "$ROOT/VERSION" 2>/dev/null || echo 0.0.0)"
STAGE="$OUT_DIR/netforensiq-offline-$VERSION"
TARBALL="$OUT_DIR/netforensiq-offline-$VERSION.tar.gz"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()   { printf '\033[32m✔ %s\033[0m\n' "$1"; }
die()  { printf '\033[31m✘ %s\033[0m\n' "$1" >&2; exit 1; }

PY="${PYTHON:-$BACKEND/.venv/bin/python}"
[[ -x "$PY" ]] || PY="$(command -v python3)" || die "no python3 found"

PY_TAG="$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PLATFORM="$("$PY" -c 'import platform; print(f"{platform.system().lower()}-{platform.machine()}")')"

step "Building for Python $PY_TAG on $PLATFORM"
echo "The target machine must match both. See the note at the top of this script."

rm -rf "$STAGE"
mkdir -p "$STAGE"

# --- 1. Python dependencies, as wheels -------------------------------------
step "Downloading Python wheels"
# --only-binary :all: is the important flag. Without it pip is free to fall
# back to a source distribution, which would then need a compiler and network
# access to build on the air-gapped machine — exactly what this avoids. If a
# dependency has no wheel for this platform, this fails HERE, on the machine
# where it can be fixed.
"$PY" -m pip download \
  --only-binary :all: \
  --requirement "$BACKEND/requirements.txt" \
  --dest "$STAGE/wheelhouse" \
  || die "wheel download failed — see --only-binary note above"
ok "$(find "$STAGE/wheelhouse" -name '*.whl' | wc -l) wheels"

# pip itself must be present offline, or `python -m venv` on an old system
# bootstraps from the network.
"$PY" -m pip download --only-binary :all: pip setuptools wheel \
  --dest "$STAGE/wheelhouse" >/dev/null
ok "bootstrap wheels (pip, setuptools, wheel)"

# --- 2. Frontend, already built --------------------------------------------
step "Building the frontend"
if [[ ! -d "$FRONTEND/node_modules" ]]; then
  ( cd "$FRONTEND" && npm ci )
fi
( cd "$FRONTEND" && npm run build )
[[ -f "$FRONTEND/dist/index.html" ]] || die "npm run build produced no dist/index.html"
mkdir -p "$STAGE/frontend"
cp -r "$FRONTEND/dist" "$STAGE/frontend/dist"
ok "$(find "$STAGE/frontend/dist" -type f | wc -l) static files, $(du -sh "$STAGE/frontend/dist" | cut -f1)"

# Prove the claim rather than asserting it: if a built file references an
# external host, the bundle is not air-gapped and this is where to find out.
step "Checking the build for external references"
# A grep over a glob that matches no file reports success. That would make
# this step assert air-gappedness having read nothing, so count first.
SCANNED="$(find "$STAGE/frontend/dist" \( -name '*.css' -o -name '*.html' \) | wc -l)"
[[ "$SCANNED" -gt 0 ]] || die "no CSS or HTML in the build — this check would have passed without reading a byte"

EXTERNAL="$(grep -rhoE 'https?://[a-zA-Z0-9.-]+' "$STAGE/frontend/dist" \
  --include='*.css' --include='*.html' 2>/dev/null \
  | grep -vE '://(localhost|127\.0\.0\.1|www\.w3\.org)' | sort -u || true)"
if [[ -n "$EXTERNAL" ]]; then
  die "built stylesheets/HTML reference external hosts:
$EXTERNAL"
fi

# The JS bundle is the biggest artifact and was not being checked at all.
# It cannot be grepped for bare hostnames, though: React, MUI and Immer embed
# documentation URLs in their minified error strings (react.dev/errors/...,
# mui.com/production-error/...), which are never fetched and would fail every
# build. So match only the forms that actually *load* something — a CSS url(),
# a fetch, an importScripts, an src= or href= attribute — pointing off-box.
JS_SCANNED="$(find "$STAGE/frontend/dist" -name '*.js' | wc -l)"
[[ "$JS_SCANNED" -gt 0 ]] || die "no JS in the build — nothing to check"
EXTERNAL_JS="$(grep -rhoE '(url\(|fetch\(|importScripts\(|src=|href=)["'"'"'\`]?https?://[a-zA-Z0-9.-]+' \
  "$STAGE/frontend/dist" --include='*.js' 2>/dev/null \
  | grep -vE '://(localhost|127\.0\.0\.1|www\.w3\.org)' | sort -u || true)"
if [[ -n "$EXTERNAL_JS" ]]; then
  die "built JS loads resources from external hosts:
$EXTERNAL_JS"
fi
ok "no external stylesheet, font, script or image host in $SCANNED CSS/HTML and $JS_SCANNED JS files"

# --- 3. Application source --------------------------------------------------
step "Copying the application"
mkdir -p "$STAGE/backend"
# staticfiles/ is generated by collectstatic and is regenerated by the
# installer on the target, so shipping it would only be a stale copy.
# An array, not a string: an unquoted variable holding a tar option is one
# stray space away from being two options, and `set -u` hides the difference.
CAPTURE_EXCLUDE=()
if [[ "$WITH_CAPTURES" == 1 ]]; then
  echo "including backend/reference_captures ($(du -sh "$BACKEND/reference_captures" 2>/dev/null | cut -f1 || echo 'absent'))"
else
  CAPTURE_EXCLUDE=(--exclude=reference_captures)
fi
# The database exclusion is a glob, not the literal name 'db.sqlite3', because
# this project's database is netforensiq.sqlite3 (settings.py: SQLITE_NAME).
# Excluding one hardcoded filename meant a developer's working database — user
# accounts and their password hashes, the audit log, sealed evidence records
# and live JWTs — was packed into every installer. -wal and -shm are the
# journal sidecars and carry the same rows.
( cd "$BACKEND" && tar -cf - \
    --exclude='*.sqlite3' --exclude='*.sqlite3-wal' --exclude='*.sqlite3-shm' \
    --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.cache' --exclude='evidence_store' \
    --exclude='.env' --exclude='staticfiles' \
    "${CAPTURE_EXCLUDE[@]}" \
    . ) | ( cd "$STAGE/backend" && tar -xf - )
cp "$ROOT/VERSION" "$STAGE/VERSION" 2>/dev/null || true
cp "$ROOT/README.md" "$STAGE/README.md" 2>/dev/null || true
mkdir -p "$STAGE/scripts"
cp "$ROOT/scripts/install_offline.sh" "$STAGE/scripts/" 2>/dev/null || true
chmod +x "$STAGE/scripts/install_offline.sh" 2>/dev/null || true
ok "backend source, migrations and management commands"

# Assert it rather than trust the list above. The exclusion was wrong once
# already; a rename upstream must not be able to smuggle case data into an
# installer again, silently, at 50 MB a time. '.env' as an exact name so the
# .env.example template — which is meant to ship — still gets through.
LEAKED="$(find "$STAGE" \( -name '*.sqlite3*' -o -name '.env' -o -name 'evidence_store' \) -print 2>/dev/null || true)"
if [[ -n "$LEAKED" ]]; then
  die "case data leaked into the bundle — a bundle is software, not evidence:
$LEAKED"
fi
ok "no database, .env or evidence store in the staged tree"

# The evidence store is deliberately NOT copied. A bundle is software, not a
# case file, and shipping someone's sealed exhibits inside an installer is a
# chain-of-custody problem dressed up as a convenience.
echo "note: evidence_store/, *.sqlite3 and .env are excluded by design"
if [[ "$WITH_CAPTURES" == 1 ]]; then
  echo "note: third-party reference captures ARE included — check redistribution"
  echo "      terms before handing this bundle to anyone outside your team."
else
  echo "note: reference captures are NOT included. seed_demo will fall back to"
  echo "      generated traffic, clearly sealed as SYNTHETIC. Pass"
  echo "      --with-reference-captures to bundle the real ones for a demo."
fi

# --- 4. Manifest ------------------------------------------------------------
step "Writing the manifest"
cat > "$STAGE/BUNDLE.json" <<JSON
{
  "tool": "netforensiq",
  "version": "$VERSION",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "python": "$PY_TAG",
  "platform": "$PLATFORM",
  "wheels": $(find "$STAGE/wheelhouse" -name '*.whl' | wc -l),
  "frontend_files": $(find "$STAGE/frontend/dist" -type f | wc -l),
  "reference_captures": $([[ "$WITH_CAPTURES" == 1 ]] && echo true || echo false)
}
JSON

( cd "$STAGE" && find . -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )
ok "$(wc -l < "$STAGE/SHA256SUMS") files hashed"

# --- 5. Tarball -------------------------------------------------------------
step "Packing"
( cd "$OUT_DIR" && tar -czf "$(basename "$TARBALL")" "$(basename "$STAGE")" )
# Record the checksum against the bare filename. sha256sum writes whatever
# path it was given, and an absolute build-machine path makes `sha256sum -c`
# fail on the receiving side — where verifying the bundle is the entire point.
( cd "$OUT_DIR" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

printf '\n\033[32m✔ %s (%s)\033[0m\n' "$TARBALL" "$(du -h "$TARBALL" | cut -f1)"
echo
echo "On the air-gapped machine:"
echo "  tar -xzf $(basename "$TARBALL")"
echo "  cd $(basename "$STAGE")"
echo "  ./scripts/install_offline.sh"
