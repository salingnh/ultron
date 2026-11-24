#!/usr/bin/env bash
# One command for the local API stack behind the UI and the G1.5c demo:
#
#   1. make dev-up            - PostgreSQL 16, Neo4j, SeaweedFS, Temporal (idempotent);
#      LAB=1: make lab-up     - the authorized DNS lab, for Subfinder/DNSx demo data;
#   2. python -m aegis.migrations - apply the contract chain (one bookkeeper, see apply-schema.sh);
#   3. a dev operator token   - printed once; only its sha256 is stored in .local/operators.json;
#   4. uvicorn aegis.m26_api.main:app on 127.0.0.1:$AEGIS_API_PORT with CORS for the Vite origin;
#   5. prints the API base URL and the token, plus the UI settings that use them.
#
# Flags (environment variables, so `make run-local LAB=1`):
#   LAB=1         also start the authorized lab (stopped again by stop-local only if started here)
#   SEED=1        create a demo campaign through POST /campaigns (implies NEW_TOKEN=1)
#   NEW_TOKEN=1   rotate the dev operator token and print it
#   API_PORT=...  API port (default AEGIS_API_PORT from .env, else 8000)
#
# Everything this script starts is recorded in .local/ (git-ignored) so `make stop-local` stops
# exactly that and nothing else: the API process it started, and the dev stack/lab only when they
# were down before this run. Never touches another container, volume or database.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_cmd curl
require_cmd ss "install iproute2"
require_cmd uv "install uv (https://docs.astral.sh/uv/)"

STATE_DIR="$REPO_ROOT/.local"
mkdir -p "$STATE_DIR"
API_PID_FILE="$STATE_DIR/api.pid"
API_LOG="$STATE_DIR/api.log"
TOKENS_FILE="$STATE_DIR/operators.json"
STACK_MARKER="$STATE_DIR/stack.started"
LAB_MARKER="$STATE_DIR/lab.started"

# "Present" means anything of the project exists - a container (running or not) or a volume - so a
# stopped stack someone else created is never claimed, and never removed by stop-local.
dev_project_present() {
  if podman ps -a --filter "label=io.podman.compose.project=$DEV_PROJECT" --format '{{.Names}}' |
    grep -q .; then
    return 0
  fi
  if podman volume ls --filter "label=io.podman.compose.project=$DEV_PROJECT" --format '{{.Name}}' |
    grep -q .; then
    return 0
  fi
  if podman volume ls --format '{{.Name}}' | grep -qE "^${DEV_PROJECT}[_-]"; then
    return 0
  fi
  return 1
}

lab_project_present() {
  if podman ps -a --filter "label=io.podman.compose.project=$LAB_PROJECT" --format '{{.Names}}' |
    grep -q .; then
    return 0
  fi
  if podman volume ls --format '{{.Name}}' | grep -qE "^${LAB_PROJECT}[_-]"; then
    return 0
  fi
  if podman network ls --format '{{.Name}}' | grep -qx "${LAB_PROJECT}-lab"; then
    return 0
  fi
  return 1
}

# --- 1. the dev stack (and the lab, on request) ------------------------------
stack_was_present=0
dev_project_present && stack_was_present=1
make --no-print-directory -C "$REPO_ROOT" dev-up
if [ "$stack_was_present" = 0 ]; then
  : >"$STACK_MARKER"
  log "dev stack: started by run-local (stop-local will remove it)"
else
  log "dev stack: existed before run-local (stop-local will leave it as it is)"
fi

if [ "${LAB:-0}" = 1 ]; then
  lab_was_present=0
  lab_project_present && lab_was_present=1
  make --no-print-directory -C "$REPO_ROOT" lab-up
  if [ "$lab_was_present" = 0 ]; then
    : >"$LAB_MARKER"
    log "lab: started by run-local (stop-local will remove it)"
  else
    log "lab: existed before run-local (stop-local will leave it as it is)"
  fi
fi

load_env
API_PORT=${API_PORT:-${AEGIS_API_PORT:-8000}}
PG_DSN="postgresql://$AEGIS_PG_USER:$AEGIS_PG_PASSWORD@127.0.0.1:$AEGIS_PG_PORT/$AEGIS_PG_DB"
export AEGIS_PG_DSN="$PG_DSN"

# --- 2. migrations through the one runner ------------------------------------
log "postgres: applying the contract chain (python -m aegis.migrations)"
(cd "$REPO_ROOT" && uv run --frozen python -m aegis.migrations)

# --- 3. the dev operator token (printed once) --------------------------------
token=""
if [ ! -f "$TOKENS_FILE" ] || [ "${NEW_TOKEN:-0}" = 1 ] || [ "${SEED:-0}" = 1 ]; then
  token=$(head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_')
  digest=$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)
  (umask 077
    printf '{"operators":[{"principal_id":"op-local","token_sha256":"%s"}]}\n' "$digest" \
      >"$TOKENS_FILE")
  log "operator token: generated (only its sha256 is stored in .local/operators.json)"
else
  log "operator token: keeping the one from a previous run (NEW_TOKEN=1 rotates it)"
fi

# --- 4. the API --------------------------------------------------------------
if [ -f "$API_PID_FILE" ]; then
  "$DEV_DIR/stop-api.sh" || die "could not stop the previous API process (see .local/api.log)"
fi
if ss -ltn "sport = :$API_PORT" 2>/dev/null | grep -q LISTEN; then
  die "port $API_PORT is already in use - set API_PORT=<free port> and run make run-local again"
fi

cors_origins=${AEGIS_CORS_ORIGINS:-"http://127.0.0.1:5173,http://localhost:5173"}
log "api: uvicorn on 127.0.0.1:$API_PORT (log: .local/api.log)"
(
  cd "$REPO_ROOT"
  export AEGIS_PG_DSN AEGIS_OPERATOR_TOKENS_FILE="$TOKENS_FILE"
  export AEGIS_ALLOW_DEV_SIGNING_KEY=1 AEGIS_CORS_ORIGINS="$cors_origins"
  nohup "$REPO_ROOT/.venv/bin/uvicorn" aegis.m26_api.main:app \
    --host 127.0.0.1 --port "$API_PORT" --log-level info >>"$API_LOG" 2>&1 &
  echo $! >"$API_PID_FILE"
)
api_pid=$(cat "$API_PID_FILE")

deadline=$((SECONDS + 60))
until curl -fsS "http://127.0.0.1:$API_PORT/healthz" >/dev/null 2>&1; do
  if ! kill -0 "$api_pid" 2>/dev/null; then
    tail -20 "$API_LOG" >&2 || true
    rm -f "$API_PID_FILE"
    die "the API exited during start-up (log above, full log: .local/api.log)"
  fi
  ((SECONDS < deadline)) || {
    tail -20 "$API_LOG" >&2 || true
    die "the API did not answer /healthz within 60s"
  }
  sleep 0.5
done

# --- 5. the demo campaign (optional) ----------------------------------------
if [ "${SEED:-0}" = 1 ]; then
  log "seed: creating a demo campaign through POST /campaigns"
  (cd "$REPO_ROOT" && "$DEV_DIR/seed-demo.py" --api-url "http://127.0.0.1:$API_PORT" --token "$token")
fi

api_url="http://127.0.0.1:$API_PORT"
cat <<EOF

[run-local] ready
  api        $api_url/api/v2   (healthz: $api_url/healthz)
  openapi    $api_url/api/v2/openapi.json
  cors       $cors_origins
  log        .local/api.log      pid  .local/api.pid
  database   $PG_DSN

  UI (another terminal):
    cd ui
    VITE_USE_MOCK=false VITE_API_BASE=$api_url/api/v2 \\
      VITE_BEARER_TOKEN=<the token below> npm run dev

  stop: make stop-local   (stops only what this run started)
EOF

if [ -n "$token" ]; then
  cat <<EOF

  operator token (printed once, only its sha256 is stored; NEW_TOKEN=1 rotates it):
    $token
EOF
else
  cat <<EOF

  operator token: unchanged from the previous run - its digest is in .local/operators.json.
    Rotate and print it with: make run-local NEW_TOKEN=1
EOF
fi
