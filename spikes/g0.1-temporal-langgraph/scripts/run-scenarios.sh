#!/usr/bin/env bash
# Run every G0.1 acceptance scenario and save the output under evidence/.
#   scripts/run-scenarios.sh            # reuse the current DB + Temporal dev-server data
#   scripts/run-scenarios.sh --fresh    # remove this spike's DB volume and Temporal data first
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--fresh" ]; then
  scripts/temporal-server.sh stop >/dev/null 2>&1 || true
  rm -f .runtime/temporal.db .runtime/temporal.db-*
  scripts/dev-reset.sh
fi

scripts/dev-up.sh >/dev/null
scripts/temporal-server.sh start >/dev/null

mkdir -p evidence
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="evidence/pytest-${STAMP}.txt"
.venv/bin/python -m pytest -q 2>&1 | tee "$LOG"
echo
echo "scenario log: $LOG"
echo "stop the stack with: scripts/temporal-server.sh stop && scripts/dev-down.sh"
