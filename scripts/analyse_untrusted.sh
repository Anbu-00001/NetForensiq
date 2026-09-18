#!/usr/bin/env bash
#
# Measure the engine against untrusted samples, inside a container that can do
# nothing else.
#
# What this is actually defending against
# ---------------------------------------
# Not execution. There is no Android runtime here, so an APK on Linux is an
# inert ZIP and `apk_engine examine` never runs a line of its code. The exposure
# is that androguard, apkInspector, lxml and zlib parse attacker-chosen bytes,
# and the last two are C. A crash or a hang is the likely outcome and the engine
# already bounds both with RLIMIT_AS and RLIMIT_CPU. This script exists for the
# unlikely outcome — memory corruption in a decompressor — and for the far more
# probable accidents: a sample escaping onto the host filesystem as a runnable
# file, or reaching the network.
#
#   --network none            nothing it finds can phone home, and no stage 2
#                             can be fetched even if something did run
#   --read-only               the image cannot be modified
#   --cap-drop ALL            no capabilities at all, on top of the image's
#                             non-root USER and a binary without CAP_NET_RAW
#   --security-opt no-new-privileges
#                             no setuid path back up
#   tmpfs /work ... noexec    decrypted samples live in memory, cannot be
#                             executed, and vanish with the container
#   /samples read-only        the encrypted corpus is never written to
#   --user $(id -u)           the image's own user is uid 10001, which cannot
#                             write results to a host directory owned by you;
#                             mapping to the calling user keeps the process
#                             unprivileged and lets the report land
#   --memory / --pids-limit   androguard needs ~0.1 GB per MB of DEX; this
#                             machine has been knocked over by it before
#
# One consequence worth recording: the image's main python3 carries
# cap_net_raw,cap_net_admin for live packet capture, and a binary with file
# capabilities cannot be exec'd under no-new-privileges — the kernel refuses
# with EPERM. That is the correct refusal. The examination runs on
# /usr/local/bin/python3-analysis, the capability-free copy the Dockerfile makes
# for precisely this reason, which is also what APK_ENGINE_PYTHON points at in
# production. The sandbox and the deployed path use the same binary.
#
# Usage:
#   scripts/analyse_untrusted.sh /path/to/encrypted/corpus /path/to/benign/apks
#
# The first directory holds MalwareBazaar ZIPs plus corpus_manifest.json
# (see fetch_malwarebazaar_corpus.py); the second holds legitimate .apk files.
# Results are written to ./sandbox_results on the host — reports only, never
# samples.
set -euo pipefail

MALICIOUS_DIR=${1:?usage: analyse_untrusted.sh <encrypted-malicious-dir> [benign-dir]}
BENIGN_DIR=${2:-}
IMAGE=netforensiq-engine:sandbox
MEMORY=${SANDBOX_MEMORY:-6g}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/sandbox_results"

MALICIOUS_DIR="$(cd "$MALICIOUS_DIR" && pwd)"
[ -f "$MALICIOUS_DIR/corpus_manifest.json" ] || {
  echo "No corpus_manifest.json in $MALICIOUS_DIR — run fetch_malwarebazaar_corpus.py first." >&2
  exit 1
}
mkdir -p "$RESULTS"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building $IMAGE …" >&2
  docker build -t "$IMAGE" "$ROOT"
fi

MOUNTS=(-v "$MALICIOUS_DIR:/samples:ro" -v "$ROOT/scripts:/scripts:ro" -v "$RESULTS:/out")
BENIGN_ARG=()
if [ -n "$BENIGN_DIR" ]; then
  BENIGN_DIR="$(cd "$BENIGN_DIR" && pwd)"
  MOUNTS+=(-v "$BENIGN_DIR:/benign:ro")
  BENIGN_ARG=(--benign /benign)
fi

echo "Running the engine with no network, no capabilities and ${MEMORY} of memory." >&2

docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --memory "$MEMORY" --memory-swap "$MEMORY" \
  --pids-limit 512 \
  --tmpfs /work:rw,noexec,nosuid,nodev,size=4g \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m \
  -e PYTHONDONTWRITEBYTECODE=1 \
  "${MOUNTS[@]}" \
  --entrypoint /bin/sh \
  "$IMAGE" -c "
    set -e
    PY=/usr/local/bin/python3-analysis
    \$PY /scripts/fetch_malwarebazaar_corpus.py unpack --from /samples --into /work/apk
    \$PY -m apk_engine evaluate \
      ${BENIGN_ARG[*]} --malicious /work/apk \
      --jobs 1 --max-memory-mb 5120 --check \
      --description 'MalwareBazaar APK corpus, examined in a sandbox' \
      | tee /out/sensitivity.txt
  "

echo >&2
echo "Reports in $RESULTS. No sample left the container." >&2
