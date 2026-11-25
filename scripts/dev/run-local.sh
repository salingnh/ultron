#!/usr/bin/env bash
# One command for the whole local G1 stack: the API, the MCP boundary, the M02 worker and
# dispatcher, the M23 projector and the M06 runner, on the dev stack and the authorized lab.
#
#   make run-local                  everything below, with the lab (WORKERS=1, LAB=1)
#   make run-local LAB=0            no lab (Subfinder/DNSx jobs then have no endpoint to reach)
#   make run-local WORKERS=0        only the API + MCP server (UI work, no jobs run)
#   make run-local SEED=1           also create a demo campaign through POST /campaigns
#   make run-local NEW_TOKEN=1      rotate the dev operator token and print it again
#   make run-local API_PORT=8001    a different API port
#
# Steps:
#   1. make dev-up   - PostgreSQL 16, Neo4j, SeaweedFS, Temporal (idempotent);
#      LAB=1: make lab-up - the authorized DNS lab (internal network, no published port);
#   2. python -m aegis.migrations - apply the contract chain (one bookkeeper, see apply-schema.sh);
#   3. a dev operator token, printed once (only its sha256 goes to .local/operators.json) and kept
#      for the demo scripts in .local/operator-token (mode 600, git-ignored - a dev convenience);
#      an internal service token for the ingestion endpoint in .local/service-token (mode 600);
#   4. uvicorn aegis.m26_api.main:app on 127.0.0.1:$API_PORT (API + `POST /ingestion/results`);
#   5. WORKERS=1: uvicorn aegis.m05_registry.mcp.main:app (MCP), the M02 worker (`aegis-agent`
#      queue: the M03 scripted-policy session) and dispatcher, the M23 projector loop and the M06
#      runner loop (`python -m aegis.m06_runner`);
#   6. prints the URLs, the token and the exact UI settings, and how to run the G1 demo.
#
# Every process this script starts is recorded in .local/ (`<name>.pid`, `<name>.log`), so
# `make stop-local` stops exactly those and nothing else. The dev stack and the lab are removed
# only when run-local was the one that started them (markers). Never touches another container,
# volume or database.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_cmd curl
require_cmd ss "install iproute2"
require_cmd uv "install uv (https://docs.astral.sh/uv/)"

mkdir -p "$STATE_DIR"
TOKENS_FILE="$STATE_DIR/operators.json"
TOKEN_FILE="$STATE_DIR/operator-token"
SERVICE_TOKEN_FILE="$STATE_DIR/service-token"
STACK_MARKER="$STATE_DIR/stack.started"
LAB_MARKER="$STATE_DIR/lab.started"
LAB_PROFILE="$REPO_ROOT/deploy/lab/runner-profile.json"
# The lab profile names the lab network; a checkout with its own lab project gets its own network and
# therefore its own copy of the profile (absolute paths, so the copy can live under .local/).
LAB_PROFILE_LOCAL="$STATE_DIR/lab-runner-profile.json"
INTERNET_PROFILE="$REPO_ROOT/deploy/internet/runner-profile.json"
BROKER_IMAGE=${AEGIS_M06_BROKER_IMAGE:-localhost/aegis-broker:g16}
MCP_PORT=${MCP_PORT:-8105}

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

port_busy() { ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN; }

# A token file is a secret for this checkout only: 0600, never echoed to a log.
write_secret() {
  local file=$1 value=$2
  (umask 077 && printf '%s\n' "$value" >"$file")
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

if [ "${LAB:-1}" = 1 ]; then
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
# The services read URIs, the compose file publishes ports: derive the one from the other here so
# every process below gets the same endpoints without a second configuration file.
export AEGIS_NEO4J_URI=${AEGIS_NEO4J_URI:-"bolt://127.0.0.1:$AEGIS_NEO4J_BOLT_PORT"}
export AEGIS_S3_ENDPOINT=${AEGIS_S3_ENDPOINT:-"http://127.0.0.1:$AEGIS_S3_PORT"}
export AEGIS_API_URL="http://127.0.0.1:$API_PORT"
# The M06 runner runs the two DNS adapters on the authorized lab network when the lab is up. The
# profile is deploy config (deploy/lab/runner-profile.json); without it jobs keep their own per-job
# network and broker, and a lab tool would have no endpoint to reach.
if [ "${LAB:-1}" = 1 ] && [ -f "$LAB_PROFILE" ]; then
  if [ "$LAB_NETWORK" = "aegis-lab-lab" ]; then
    export AEGIS_M06_LAB_PROFILE="$LAB_PROFILE"
  else
    require_cmd python3
    python3 - "$LAB_PROFILE" "$LAB_PROFILE_LOCAL" "$LAB_NETWORK" <<'PY_PROFILE'
import json, sys
from pathlib import Path
source, target, network = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
document = json.loads(source.read_text(encoding="utf-8"))
document["network"] = network
for job in document.get("jobs", []):
    for mount in job.get("mounts", []):
        mount["source"] = str((source.parent / mount["source"]).resolve())
target.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PY_PROFILE
    export AEGIS_M06_LAB_PROFILE="$LAB_PROFILE_LOCAL"
  fi
fi
# The internet profile (G1.6) is what an operator campaign needs: its `network` is the broker's
# uplink, and the broker image is the stdlib-only broker container. Both are deploy config; a job
# whose campaign names `internet` without them is refused before a container exists (fail closed).
if [ "${INTERNET:-1}" = 1 ] && [ -f "$INTERNET_PROFILE" ]; then
  export AEGIS_M06_INTERNET_PROFILE="$INTERNET_PROFILE"
  if ! podman image exists "$BROKER_IMAGE" >/dev/null 2>&1; then
    log "broker: building $BROKER_IMAGE (deploy/broker/Containerfile)"
    podman build --quiet --file "$REPO_ROOT/deploy/broker/Containerfile" --tag "$BROKER_IMAGE" \
      "$REPO_ROOT" >/dev/null
  fi
  export AEGIS_M06_BROKER_IMAGE="$BROKER_IMAGE"
  # The broker's outbound leg gets a network of its own (G1.6): never the host's default bridge,
  # where unrelated containers could reach the broker or impersonate an upstream. run-local creates
  # it once and removes it only when it created it (marker file).
  UPLINK_NETWORK=${UPLINK_NETWORK:-aegis-uplink}
  if podman network exists "$UPLINK_NETWORK" >/dev/null 2>&1; then
    log "uplink: reusing network $UPLINK_NETWORK"
  else
    podman network create --label aegis.uplink=run-local "$UPLINK_NETWORK" >/dev/null
    printf '%s' "$UPLINK_NETWORK" >"$UPLINK_MARKER"
    log "uplink: created network $UPLINK_NETWORK (stop-local will remove it)"
  fi
  export AEGIS_UPLINK_NETWORK="$UPLINK_NETWORK"
  # The L3 channel's route hook is part of the checkout, so the runner can start L3 jobs; the
  # hook itself is deployment-owned and never configurable from a task.
  if [ -x "$REPO_ROOT/deploy/l3/hooks/aegis-l3-route" ]; then
    export AEGIS_L3_HOOK="$REPO_ROOT/deploy/l3/hooks/aegis-l3-route"
  fi
fi

# --- 2. migrations through the one runner ------------------------------------
log "postgres: applying the contract chain (python -m aegis.migrations)"
(cd "$REPO_ROOT" && uv run --frozen python -m aegis.migrations)

# --- 3. the dev tokens (the operator token is printed once) ------------------
token=""
if [ ! -f "$TOKENS_FILE" ] || [ ! -f "$TOKEN_FILE" ] || [ "${NEW_TOKEN:-0}" = 1 ] || [ "${SEED:-0}" = 1 ]; then
  token=$(head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_')
  digest=$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)
  write_secret "$TOKENS_FILE" \
    "{\"operators\":[{\"principal_id\":\"op-local\",\"token_sha256\":\"$digest\"}]}"
  write_secret "$TOKEN_FILE" "$token"
  log "operator token: generated (only its sha256 is stored in .local/operators.json)"
else
  log "operator token: keeping the one from a previous run (NEW_TOKEN=1 rotates it)"
fi

if [ ! -s "$SERVICE_TOKEN_FILE" ]; then
  write_secret "$SERVICE_TOKEN_FILE" "svc-$(head -c 24 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_')"
  log "service token: generated for the ingestion endpoint (.local/service-token)"
fi
AEGIS_SERVICE_TOKEN=$(cat "$SERVICE_TOKEN_FILE")
export AEGIS_SERVICE_TOKEN AEGIS_ALLOW_DEV_SIGNING_KEY=1
export AEGIS_OPERATOR_TOKENS_FILE="$TOKENS_FILE"

cors_origins=${AEGIS_CORS_ORIGINS:-"http://127.0.0.1:5173,http://localhost:5173"}
export AEGIS_CORS_ORIGINS="$cors_origins"

# --- 4. the API (and the ingestion endpoint M27 serves) ----------------------
stop_bg api "aegis.m26_api.main"
if port_busy "$API_PORT"; then
  die "port $API_PORT is already in use - set API_PORT=<free port> and run make run-local again"
fi
log "api: uvicorn aegis.m26_api.main:app on 127.0.0.1:$API_PORT (log: .local/api.log)"
start_bg api "$REPO_ROOT/.venv/bin/uvicorn" aegis.m26_api.main:app \
  --host 127.0.0.1 --port "$API_PORT" --log-level info
api_pid=$(cat "$STATE_DIR/api.pid")

deadline=$((SECONDS + 60))
until curl -fsS "http://127.0.0.1:$API_PORT/healthz" >/dev/null 2>&1; do
  if ! kill -0 "$api_pid" 2>/dev/null; then
    tail -20 "$STATE_DIR/api.log" >&2 || true
    rm -f "$STATE_DIR/api.pid"
    die "the API exited during start-up (log above, full log: .local/api.log)"
  fi
  ((SECONDS < deadline)) || {
    tail -20 "$STATE_DIR/api.log" >&2 || true
    die "the API did not answer /healthz within 60s"
  }
  sleep 0.5
done

# --- 5. the worker processes (WORKERS=1) ------------------------------------
if [ "${WORKERS:-1}" = 1 ]; then
  stop_bg mcp "aegis.m05_registry.mcp.main"
  if port_busy "$MCP_PORT"; then
    die "port $MCP_PORT is already in use - set MCP_PORT=<free port> and run make run-local again"
  fi
  log "mcp: uvicorn aegis.m05_registry.mcp.main:app on 127.0.0.1:$MCP_PORT (log: .local/mcp.log)"
  AEGIS_MCP_HOST=127.0.0.1 AEGIS_MCP_URL="http://127.0.0.1:$MCP_PORT/mcp" \
    start_bg mcp "$REPO_ROOT/.venv/bin/uvicorn" aegis.m05_registry.mcp.main:app \
    --host 127.0.0.1 --port "$MCP_PORT" --log-level info
  wait_bg_alive mcp 3

  export AEGIS_MCP_URL="http://127.0.0.1:$MCP_PORT/mcp"

  stop_bg m02-worker "aegis.m02_orchestrator.worker"
  log "m02: worker (aegis-orchestrator + aegis-agent) and dispatcher (log: .local/m02-*.log)"
  start_bg m02-worker "$REPO_ROOT/.venv/bin/python" -u -m aegis.m02_orchestrator.worker \
    --address "127.0.0.1:$AEGIS_TEMPORAL_PORT" --session-module aegis.m03_agent.activities
  wait_bg_alive m02-worker 3

  stop_bg m02-dispatcher "aegis.m02_orchestrator.dispatcher"
  start_bg m02-dispatcher "$REPO_ROOT/.venv/bin/python" -u -m aegis.m02_orchestrator.dispatcher \
    --address "127.0.0.1:$AEGIS_TEMPORAL_PORT"
  wait_bg_alive m02-dispatcher 3

  stop_bg m23 "aegis.m23_graph"
  log "m23: projector loop (log: .local/m23.log)"
  # A stable holder lets a restart take its own dispatcher lease back immediately (the fencing
  # token still invalidates the old process), so `make run-local` can be re-run at any time.
  export AEGIS_PROJECTOR_HOLDER="aegis-local-projector"
  start_bg m23 "$REPO_ROOT/.venv/bin/python" -u -m aegis.m23_graph run
  wait_bg_alive m23 3

  stop_bg m06 "aegis.m06_runner"
  log "m06: runner loop (log: .local/m06.log)"
  start_bg m06 "$REPO_ROOT/.venv/bin/python" -u -m aegis.m06_runner
  wait_bg_alive m06 3
else
  log "workers: skipped (WORKERS=0) - no MCP server, no job runs, nothing ingests"
fi

# --- 6. the demo campaign (optional) ----------------------------------------
if [ "${SEED:-0}" = 1 ]; then
  log "seed: creating a demo campaign through POST /campaigns"
  (cd "$REPO_ROOT" && "$DEV_DIR/seed-demo.py" --api-url "http://127.0.0.1:$API_PORT" --token "$(cat "$TOKEN_FILE")")
fi

api_url="http://127.0.0.1:$API_PORT"

# The demo scripts (`make demo-g1`, `make demo-recovery`, `make soak-start`) need exactly the
# endpoints this run created; they read them from here instead of guessing. Mode 600: it holds the
# two dev tokens.
run_env="$STATE_DIR/run-local.env"
(umask 077
  cat >"$run_env" <<RUNENV
# written by scripts/dev/run-local.sh - sourced by the demo scripts, do not edit
export AEGIS_API_URL="$api_url"
export AEGIS_PG_DSN="$PG_DSN"
export AEGIS_NEO4J_URI="$AEGIS_NEO4J_URI"
export AEGIS_NEO4J_USER="${AEGIS_NEO4J_USER:-neo4j}"
export AEGIS_NEO4J_PASSWORD="$AEGIS_NEO4J_PASSWORD"
export AEGIS_S3_ENDPOINT="$AEGIS_S3_ENDPOINT"
export AEGIS_S3_BUCKET="$AEGIS_S3_BUCKET"
export AEGIS_SERVICE_TOKEN="$AEGIS_SERVICE_TOKEN"
export AEGIS_ALLOW_DEV_SIGNING_KEY=1
export AEGIS_OPERATOR_TOKEN="$(cat "$TOKEN_FILE")"
export AEGIS_OPERATOR_TOKENS_FILE="$TOKENS_FILE"
export AEGIS_M06_LAB_PROFILE="${AEGIS_M06_LAB_PROFILE:-}"
export AEGIS_M06_INTERNET_PROFILE="${AEGIS_M06_INTERNET_PROFILE:-}"
export AEGIS_M06_BROKER_IMAGE="${AEGIS_M06_BROKER_IMAGE:-}"
export AEGIS_UPLINK_NETWORK="${AEGIS_UPLINK_NETWORK:-}"
export AEGIS_L3_HOOK="${AEGIS_L3_HOOK:-}"
export AEGIS_SUBFINDER_PROVIDER_CONFIG="${AEGIS_SUBFINDER_PROVIDER_CONFIG:-}"
export AEGIS_WORKERS="${WORKERS:-1}"
RUNENV
)

cat <<EOF

[run-local] ready
  api        $api_url/api/v2   (healthz: $api_url/healthz)
  openapi    $api_url/api/v2/openapi.json
  mcp        http://127.0.0.1:$MCP_PORT/mcp          (WORKERS=1)
  cors       $cors_origins
  logs       .local/{api,mcp,m02-worker,m02-dispatcher,m23,m06}.log
  database   $PG_DSN
  tokens     .local/operator-token (operator), .local/service-token (ingestion) - mode 600
  demo env   .local/run-local.env (what the demo scripts read; mode 600)

  demo (all processes are already running):
    make demo-g1          end to end on the lab: campaign -> agent/MCP -> Subfinder -> DNSx
    make demo-recovery    SIGKILL the runner mid-job: it resumes with no duplicate
    make soak-start       a 24 h shortened soak (SOAK_HOURS=... to change) writing .local/soak/

  UI (another terminal):
    cd ui
    VITE_USE_MOCK=false VITE_API_BASE=$api_url/api/v2 \\
      VITE_BEARER_TOKEN=$(cat "$TOKEN_FILE") npm run dev

  stop: make stop-local   (stops only what this run started)
EOF

if [ -n "$token" ]; then
  cat <<EOF

  operator token (printed once, only its sha256 is stored; NEW_TOKEN=1 rotates it):
    $token
EOF
else
  cat <<EOF

  operator token: unchanged from the previous run - .local/operator-token holds it.
    Rotate and print it with: make run-local NEW_TOKEN=1
EOF
fi
