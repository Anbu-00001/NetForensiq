#!/usr/bin/env bash
#
# Fetch the real packet captures the detection engine is validated against.
#
#   ./scripts/fetch_reference_captures.sh
#
# Why this exists
# ---------------
# Everything the detector found was synthetic until these two captures went
# through it, and they immediately exposed six defects the synthetic corpus
# could not (research/96). They are real traffic with published ground truth,
# which is the only reason a detection rate quoted from them means anything.
#
# They are NOT committed: 72 MB of malware traffic does not belong in a git
# repository, and redistributing someone else's corpus is not ours to do. This
# script pulls them from the source and records where each one came from.
#
# Air-gap note: run this BEFORE the event. Once the files and their manifests
# are in backend/reference_captures/, nothing else in the project touches the
# network. The script is idempotent — it skips anything already present.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/backend/reference_captures"
PY="$ROOT/backend/.venv/bin/python"

mkdir -p "$DEST"

# Each entry: date-path | zip name | human description | ground-truth page
CAPTURES=(
  "2024/03/14|2024-03-14-AsyncRAT-and-XWorm-infection-traffic.pcap.zip|AsyncRAT and XWorm infection traffic|https://www.malware-traffic-analysis.net/2024/03/14/index.html"
  "2024/12/18|2024-12-18-one-week-of-server-scans-and-probes-and-web-traffic.pcap.zip|One week of server scans, probes and web traffic|https://www.malware-traffic-analysis.net/2024/12/18/index.html"
)

BASE="https://www.malware-traffic-analysis.net"

fail=0

for entry in "${CAPTURES[@]}"; do
  IFS='|' read -r datepath zipname description ground_truth <<< "$entry"
  pcap="${zipname%.zip}"
  url="$BASE/$datepath/$zipname"
  day="${datepath//\//}"          # 2024/03/14 -> 20240314

  if [[ -f "$DEST/$pcap" ]]; then
    echo "✔ $pcap already present"
  else
    echo "→ downloading $zipname"
    if ! curl -fL --max-time 300 -o "$DEST/$zipname" "$url"; then
      echo "✘ download failed: $url"
      fail=1
      continue
    fi

    # malware-traffic-analysis.net ships everything in a password-protected
    # zip so the samples are not fetched accidentally or scanned in transit.
    # Two schemes are in use across the archive's history; try both rather
    # than hardcoding the one that happened to work today.
    extracted=0
    for pw in "infected_$day" "infected"; do
      if unzip -o -q -P "$pw" "$DEST/$zipname" -d "$DEST" 2>/dev/null; then
        extracted=1
        break
      fi
    done

    if [[ "$extracted" != "1" ]]; then
      echo "✘ could not extract $zipname — see $BASE/about.html for the password"
      fail=1
      continue
    fi
    rm -f "$DEST/$zipname"
  fi

  # Record provenance beside the file. This is what stops a real capture being
  # confused with generated traffic once it is sealed into evidence.
  if ! (cd "$ROOT/backend" && "$PY" ../scripts/record_provenance.py \
        "$DEST/$pcap" --kind reference \
        --source-name "$description" \
        --source-url "$url" \
        --ground-truth-url "$ground_truth"); then
    echo "  could not record provenance for $pcap"
    fail=1
  fi
done

echo
if [[ "$fail" == "0" ]]; then
  echo "Reference captures ready in $DEST"
else
  echo "Some captures could not be fetched — see above."
fi
exit "$fail"
