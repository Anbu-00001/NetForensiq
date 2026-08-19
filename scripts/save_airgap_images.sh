#!/usr/bin/env bash
#
# Package the container images for a machine with no network.
#
# Why this script exists
# ----------------------
# `docker save netforensiq:VERSION` is the obvious command and it is not
# enough. Compose also starts Postgres, and on an air-gapped machine
# `docker compose up` fails at the point where it tries to pull
# postgres:17-alpine — after it has printed enough output to look like it is
# working. That failure at a demo is unrecoverable in the time available.
#
# So both images are saved, and the loader verifies both arrived.
#
# Run this on a connected machine, carry the output, run load_airgap_images.sh
# on the target.
#
set -euo pipefail

VERSION="${1:-1.1}"
OUT="${2:-airgap-images}"

APP_IMAGE="netforensiq:${VERSION}"
DB_IMAGE="$(grep -oP 'image:\s*\Kpostgres:[^\s]+' docker-compose.yml | head -1)"

if [[ -z "$DB_IMAGE" ]]; then
    echo "Could not read the Postgres image out of docker-compose.yml." >&2
    exit 1
fi

mkdir -p "$OUT"

echo "Building ${APP_IMAGE} (this needs network — it is the last step that does)…"
docker build -t "$APP_IMAGE" .

echo "Fetching ${DB_IMAGE}…"
docker pull "$DB_IMAGE"

echo "Saving…"
docker save "$APP_IMAGE" | gzip > "${OUT}/netforensiq-${VERSION}.tar.gz"
docker save "$DB_IMAGE"  | gzip > "${OUT}/postgres.tar.gz"

# A manifest, so the target machine can tell a truncated transfer from a
# complete one before it finds out during the demo.
{
    echo "netforensiq_image=${APP_IMAGE}"
    echo "postgres_image=${DB_IMAGE}"
    echo "built_at=$(date -Iseconds)"
} > "${OUT}/manifest.txt"

( cd "$OUT" && sha256sum ./*.tar.gz > SHA256SUMS )

cat <<SUMMARY

Written to ${OUT}/
$(ls -lh "$OUT" | tail -n +2 | awk '{printf "  %-34s %s\n", $9, $5}')

Carry the whole directory across, then on the target:

    ./scripts/load_airgap_images.sh ${OUT}

SUMMARY
