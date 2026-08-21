#!/usr/bin/env bash
#
# One-Command Demo Reset Harness for NetForensiq
# Use this script anytime before or during a live demonstration/presentation to ensure
# a clean, throttles-disabled state with pre-populated demo data and verified credentials.
#

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
PY="$BACKEND/.venv/bin/python"

printf "\033[1;36m========================================================================\033[0m\n"
printf "\033[1;36m  NETFORENSIQ DEMO ENVIRONMENT PREPARATION & RESET HARNESS              \033[0m\n"
printf "\033[1;36m========================================================================\033[0m\n\n"

# 1. Reset rate limiting throttle counters
printf "\033[1m[1/3] Clearing rate limiting throttle cache...\033[0m\n"
(cd "$BACKEND" && "$PY" manage.py clear_throttle)

# 2. Seed fresh demo data
printf "\n\033[1m[2/3] Seeding demo dataset & synthetic captures...\033[0m\n"
(cd "$BACKEND" && "$PY" manage.py seed_demo --include-synthetic)

# 3. Print Ready Confirmation and Role Cheatsheet
printf "\n\033[1;32m[3/3] DEMO ENVIRONMENT READY! Zero throttle bottlenecks, fresh exhibits.\033[0m\n\n"

printf "\033[1;33m------------------------------------------------------------------------\033[0m\n"
printf "\033[1;33m  LIVE DEMO CREDENTIAL CHEATSHEET (Password for all: Netforensiq@2026) \033[0m\n"
printf "\033[1;33m------------------------------------------------------------------------\033[0m\n"
printf "  1. Investigator (IO) : Username: \033[1mio1\033[0m  OR  \033[1minvestigator\033[0m\n"
printf "  2. Expert (Forensic) : Username: \033[1mexpert\033[0m\n"
printf "  3. Commander (Admin) : Username: \033[1mcommander\033[0m\n"
printf "  4. Viewer (Auditor)  : Username: \033[1mviewer\033[0m\n"
printf "  5. Pending Applicant : Username: \033[1mpending-applicant\033[0m\n\n"

printf "\033[1;34m------------------------------------------------------------------------\033[0m\n"
printf "\033[1;34m  LOCAL ENDPOINTS                                                       \033[0m\n"
printf "\033[1;34m------------------------------------------------------------------------\033[0m\n"
printf "  • Frontend Web UI   : \033[1mhttp://127.0.0.1:5173/\033[0m\n"
printf "  • Backend REST API  : \033[1mhttp://127.0.0.1:8000/api/\033[0m\n"
printf "  • Engine Metrics    : \033[1mhttp://127.0.0.1:8000/api/engine/\033[0m\n\n"

printf "\033[1;32mReady for presentation. Good luck with the panel!\033[0m\n"
