#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
#
# Load images saved by save_airgap_images.sh, checking they arrived intact.
#
# Removable media truncates files silently. Verifying here costs two seconds
# and turns a mid-demo failure into a message before anyone is watching.
#
set -euo pipefail

DIR="${1:-airgap-images}"

if [[ ! -f "${DIR}/SHA256SUMS" ]]; then
    echo "No SHA256SUMS in ${DIR}. Is that the directory the save script wrote?" >&2
    exit 1
fi

echo "Verifying the transfer…"
( cd "$DIR" && sha256sum -c SHA256SUMS )

for archive in "${DIR}"/*.tar.gz; do
    echo "Loading $(basename "$archive")…"
    gunzip -c "$archive" | docker load
done

echo
echo "Loaded:"
grep '=' "${DIR}/manifest.txt" | sed 's/^/  /'
echo
APP_IMAGE="$(grep netforensiq_image "${DIR}/manifest.txt" | cut -d= -f2)"

echo "Nothing below this line needs a network."
echo
echo "  1. Keys, once. Keep a copy somewhere that is not this machine —"
echo "     a new evidence key makes every sealed exhibit permanently unreadable."
echo "       export NF_SECRET_KEY=\"\$(openssl rand -base64 48)\""
echo "       export NF_EVIDENCE_KEY=\"\$(openssl rand -base64 32)\""
echo
echo "  2. Start it with no route off the machine (recommended):"
echo "       export NF_IMAGE=${APP_IMAGE}"
echo "       docker compose -f docker-compose.airgap.yml up -d"
echo "       scripts/verify_airgap.sh"
echo "       # then open http://127.0.0.1:8000"
echo
echo "  Or, single container on the ordinary Docker network. Both volumes are"
echo "  needed: the database and the evidence key live in /app/data, and without"
echo "  a volume there stopping the container deletes the custody chain."
echo "       docker run -d --name netforensiq \\"
echo "         -p 127.0.0.1:8000:8000 \\"
echo "         -e SECRET_KEY=\"\$NF_SECRET_KEY\" \\"
echo "         -e EVIDENCE_ENCRYPTION_KEY=\"\$NF_EVIDENCE_KEY\" \\"
echo "         -e DEBUG=False -e ALLOWED_HOSTS=127.0.0.1,localhost \\"
echo "         -e SQLITE_NAME=/app/data/netforensiq.sqlite3 \\"
echo "         -v netforensiq_db:/app/data \\"
echo "         -v netforensiq_evidence:/app/evidence_store \\"
echo "         ${APP_IMAGE}"
echo
echo "  Do not combine --network none with -p: Docker accepts it without a"
echo "  warning and publishes nothing."
echo
echo "  Or with Postgres (both images are present, so no pull happens):"
echo "       docker compose up          # NOT --build; building needs a network"
