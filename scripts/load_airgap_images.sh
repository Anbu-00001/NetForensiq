#!/usr/bin/env bash
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
echo "Nothing below this line needs a network."
echo
echo "  Single workstation, SQLite, no Postgres:"
echo "    docker run --rm --network none -p 8000:8000 \\"
echo "      -e SECRET_KEY=\"\$(openssl rand -base64 48)\" \\"
echo "      -e DEBUG=False -e ALLOWED_HOSTS=127.0.0.1,localhost \\"
echo "      -v netforensiq_evidence:/app/evidence_store \\"
echo "      \$(grep netforensiq_image "${DIR}/manifest.txt" | cut -d= -f2)"
echo
echo "  Or with Postgres (both images are now present, so no pull happens):"
echo "    docker compose up          # NOT --build; building needs a network"
