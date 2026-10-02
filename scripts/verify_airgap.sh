#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
#
# Check that the application container started from docker-compose.airgap.yml
# has no route off the machine, and print what was checked.
#
#     scripts/verify_airgap.sh            # checks, exits non-zero on a failure
#     scripts/verify_airgap.sh --control  # also proves the probe can detect egress
#
# Two kinds of check, and the difference matters:
#
#   STRUCTURE (decisive)  Every network the application container is attached to
#       is an Docker `internal` network, it publishes no port, and it is not in
#       host-network mode or privileged. This is read from Docker's own state and
#       does not depend on what the host's network happens to be doing today.
#
#   BEHAVIOUR (corroboration only)  An outbound connection from inside the
#       container fails. On a host that is itself offline this passes whether or
#       not the container is isolated, so it cannot be the proof — which is why
#       the structural checks come first and decide the exit code. --control runs
#       the same probe from an ordinary container: if the host has a network that
#       probe must succeed, and then a failure from the application container
#       means something.
#
# What neither check shows: that the *host* is offline. Anything else running on
# the host can still use the host's network.
set -uo pipefail

PROJECT="netforensiq-airgap"
PROBE_HOST="${PROBE_HOST:-1.1.1.1}"
PROBE_PORT="${PROBE_PORT:-443}"
CONTROL=0
[[ "${1:-}" == "--control" ]] && CONTROL=1

fails=0
ok()   { printf '  PASS  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
note() { printf '  note  %s\n' "$1"; }

container_of() {
  docker ps -q \
    --filter "label=com.docker.compose.project=${PROJECT}" \
    --filter "label=com.docker.compose.service=$1" | head -1
}

APP="$(container_of app)"
GATE="$(container_of gate)"
if [[ -z "$APP" ]]; then
  echo "No running 'app' container for project ${PROJECT}." >&2
  echo "Start it with: docker compose -f docker-compose.airgap.yml up -d" >&2
  exit 2
fi

echo "Structure — read from Docker, independent of the host's network"

# 1. every attached network is internal
networks="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$APP")"
for net in $networks; do
  internal="$(docker network inspect -f '{{.Internal}}' "$net")"
  if [[ "$internal" == "true" ]]; then
    ok "application is on network '${net}', which is internal (no route off the host)"
  else
    bad "application is on network '${net}', which is NOT internal"
  fi
done
[[ -z "$networks" ]] && bad "application is attached to no network at all"

# 2. nothing published from the application container
published="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$APP")"
if [[ "$published" == "{}" || "$published" == "null" ]]; then
  ok "application publishes no port"
else
  bad "application publishes ports: ${published}"
fi

# 3. not host networking, not privileged
mode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$APP")"
priv="$(docker inspect -f '{{.HostConfig.Privileged}}' "$APP")"
[[ "$mode" != "host" ]] && ok "application is not in host network mode (${mode})" \
                        || bad "application is in host network mode"
[[ "$priv" == "false" ]] && ok "application is not privileged" \
                         || bad "application is privileged"

# 4. the relay publishes on loopback only
if [[ -n "$GATE" ]]; then
  hostips="$(docker inspect -f '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}} {{end}}{{end}}' "$GATE")"
  nonloop=0
  for ip in $hostips; do [[ "$ip" == "127.0.0.1" ]] || nonloop=1; done
  if [[ -n "$hostips" && "$nonloop" -eq 0 ]]; then
    ok "the relay publishes on 127.0.0.1 only"
  else
    bad "the relay publishes on something other than 127.0.0.1 (${hostips:-nothing})"
  fi
else
  bad "no relay container found, so nothing serves the interface"
fi

echo
echo "Behaviour — corroboration, not proof"

probe='import socket,sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=4).close()
    print("CONNECTED")
except Exception as e:
    print("FAILED " + type(e).__name__)'

result="$(docker exec "$APP" python -c "$probe" "$PROBE_HOST" "$PROBE_PORT" 2>&1 | tail -1)"
if [[ "$result" == FAILED* ]]; then
  ok "outbound connection to ${PROBE_HOST}:${PROBE_PORT} from the application failed (${result#FAILED })"
else
  bad "the application CONNECTED to ${PROBE_HOST}:${PROBE_PORT} — it has a route off the host"
fi

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8000/api/engine/ || true)"
[[ "$code" == "200" ]] && ok "the interface answers through the relay on 127.0.0.1:8000" \
                       || bad "the interface did not answer through the relay (HTTP ${code:-none})"

if [[ "$CONTROL" -eq 1 ]]; then
  echo
  echo "Control — the same probe from an ordinary container"
  img="$(docker inspect -f '{{.Config.Image}}' "$APP")"
  ctl="$(docker run --rm --entrypoint python "$img" -c "$probe" "$PROBE_HOST" "$PROBE_PORT" 2>&1 | tail -1)"
  if [[ "$ctl" == "CONNECTED" ]]; then
    ok "an ordinary container CAN reach ${PROBE_HOST}:${PROBE_PORT}, so the probe above detects egress"
  else
    note "an ordinary container could not reach ${PROBE_HOST}:${PROBE_PORT} either (${ctl})."
    note "This host appears to be offline, so the behavioural check cannot be validated here."
    note "The structural checks above are what decide the result."
  fi
fi

echo
if [[ "$fails" -eq 0 ]]; then
  echo "Result: the application container has no route off this machine."
  echo "Not shown: that the host itself is offline."
  exit 0
fi
echo "Result: ${fails} check(s) FAILED. Do not describe this deployment as isolated."
exit 1
