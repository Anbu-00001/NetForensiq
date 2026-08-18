#!/usr/bin/env bash
#
# End-of-phase verification. One command, everything checked.
#
#   ./scripts/verify.sh
#
# Why this exists: the Playwright suite needs a running API on :8011 with a
# seeded analyst account and at least one analysed capture. When that was left
# as a manual precondition it silently drifted — the server would be stopped,
# or running code from before the last edit, and the E2E run would fail for
# reasons unrelated to the change under test. This script owns the whole
# sequence so a phase is either green or it is not.
#
# It starts the API only if one is not already listening, and stops only what
# it started, so it is safe to run against a dev server you have open.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
PY="$BACKEND/.venv/bin/python"
API_PORT=8011
API_URL="http://127.0.0.1:$API_PORT"

STARTED_API=""
FAILED=0

cleanup() {
  if [[ -n "$STARTED_API" ]]; then
    echo "→ stopping the API this script started (pid $STARTED_API)"
    kill "$STARTED_API" 2>/dev/null || true
  fi
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
fail() { printf '\033[31m✘ %s\033[0m\n' "$1"; FAILED=1; }
ok()   { printf '\033[32m✔ %s\033[0m\n' "$1"; }

# ── 1. backend unit + integration tests ──────────────────────────────────
step "Backend tests"
if (cd "$BACKEND" && "$PY" manage.py test 2>&1 | tail -5); then
  ok "backend suite passed"
else
  fail "backend suite FAILED"
fi

# ── 2. demo data ─────────────────────────────────────────────────────────
# The E2E assertions compare on-screen figures against the API, so there has
# to be something to compare. Seeded only when missing — re-seeding every run
# would discard triage decisions made by hand while demoing.
step "Demo data"
# Evidence is checked too, not just detections: the certificate and custody
# E2E tests skip without an exhibit, and a suite that skips its way to green is
# worse than one that fails.
NEEDS_SEED=$(cd "$BACKEND" && "$PY" manage.py shell -c "
from capture.models import Detection
from evidence.models import EvidenceRecord, Section63Certificate
print('yes' if not (Detection.objects.exists()
                    and EvidenceRecord.objects.exists()
                    and Section63Certificate.objects.exists()) else 'no')
" 2>/dev/null | tail -1)

if [[ "$NEEDS_SEED" == "yes" ]]; then
  echo "→ seeding the demonstration dataset"
  # seed_demo owns every value it writes. The case reference it uses is
  # DEMO-NOT-A-REAL-CASE, on purpose: this writes into the same database the
  # dev server serves, and a plausible-looking FIR number would end up printed
  # on a Section 63 certificate — a forged statutory declaration.
  #
  # It prefers the real captures in backend/reference_captures/ and falls back
  # to generated traffic only when they are absent, so the suite runs against
  # traffic this project did not create whenever that is possible.
  (cd "$BACKEND" && "$PY" manage.py seed_demo) \
    && ok "demo data seeded" || fail "could not seed demo data"
else
  ok "demo data already present"
fi

# ── 3. API ───────────────────────────────────────────────────────────────
step "API on :$API_PORT"
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$API_URL/api/" || true)

if [[ "$CODE" == "000" ]]; then
  echo "→ nothing listening; starting one"
  (cd "$BACKEND" \
    && CORS_EXTRA_ORIGINS="http://127.0.0.1:5199,http://localhost:5199" \
       "$PY" manage.py runserver "127.0.0.1:$API_PORT" --noreload \
      >/tmp/netforensiq-verify-api.log 2>&1) &
  STARTED_API=$!
  for _ in $(seq 1 20); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$API_URL/api/" || true)
    [[ "$CODE" == "401" ]] && break
    sleep 1
  done
fi

# 401 is the healthy answer: the API denies by default, so an unauthenticated
# probe reaching it proves both that it is up and that the guard is on.
if [[ "$CODE" == "401" ]]; then
  ok "API responding (401 unauthenticated, as it should)"
elif [[ "$CODE" == "200" ]]; then
  fail "API returned 200 to an unauthenticated request — the permission guard is OFF"
else
  fail "API not reachable (got '$CODE'); see /tmp/netforensiq-verify-api.log"
fi

# ── 4. E2E ───────────────────────────────────────────────────────────────
# The login endpoint is throttled to 8/hour. Global setup reuses its cached
# token whenever it still works, so a normal run costs no login at all — but
# running this script repeatedly across a long session can still exhaust the
# window once the 30-minute access token expires. Clearing the local cache
# resets the counter. This is a developer harness against a local SQLite
# database; the throttle itself is untouched and still applies in every other
# context, which is the point of resetting it here rather than raising it.
step "Playwright E2E"
if [[ "${RESET_THROTTLE:-1}" == "1" ]]; then
  (cd "$BACKEND" && "$PY" manage.py shell -c \
    "from django.core.cache import cache; cache.clear()" >/dev/null 2>&1) \
    && echo "→ cleared the local login-throttle counter"
fi

if [[ "$FAILED" == "1" ]]; then
  echo "skipped — fix the failures above first"
else
  if (cd "$FRONTEND" && npx playwright test 2>&1 | tail -18); then
    ok "E2E suite passed"
  else
    fail "E2E suite FAILED"
  fi
fi

# ── 5. verdict ───────────────────────────────────────────────────────────
step "Result"
if [[ "$FAILED" == "0" ]]; then
  printf '\033[32mPhase verified.\033[0m\n'
else
  printf '\033[31mPhase NOT verified — see failures above.\033[0m\n'
fi
exit "$FAILED"
