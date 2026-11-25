#!/usr/bin/env bash
# Shared helpers for scripts/lab/*.sh. Source it; do not execute it directly.
#
# Everything here operates on compose project `aegis-lab` (deploy/lab/compose.yaml) and its
# network `aegis-lab-lab`. Run containers are named `aegis-lab-*` and labelled
# `aegis.lab=aegis-lab-run`; nothing outside the project is inspected or removed.

set -euo pipefail

# shellcheck disable=SC2034 # several of these are used by the sourcing scripts
LAB_SCRIPTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC2034
REPO_ROOT=$(cd "$LAB_SCRIPTS/../.." && pwd)
LAB_DIR="$REPO_ROOT/deploy/lab"
COMPOSE_FILE="$LAB_DIR/compose.yaml"
IMAGES_FILE="$LAB_DIR/images.env"
FIXTURES_DIR="$LAB_DIR/fixtures"
RUN_DIR="$LAB_DIR/.run"
TLS_DIR="$RUN_DIR/tls"

LAB_PROJECT=aegis-lab
LAB_NETWORK=aegis-lab-lab
DNS_CONTAINER=aegis-lab-dns
PASSIVE_CONTAINER=aegis-lab-passive
LAB_ZONE=lab.aegis.test
DNS_IP=10.114.53.53
PASSIVE_IP=10.114.53.80
RUN_LABEL=aegis.lab=aegis-lab-run

# The G1.6a service containers: the hosts and ports a scanner should see open.
SERVICE_CONTAINERS=(aegis-lab-web-legacy aegis-lab-app aegis-lab-ssh aegis-lab-cache)
SERVICE_ENDPOINTS=(
  "web.lab.aegis.test:80"
  "web.lab.aegis.test:443"
  "app.lab.aegis.test:8080"
  "ssh.lab.aegis.test:2222"
  "cache.lab.aegis.test:6379"
)

log() { printf '[lab] %s\n' "$*"; }
die() {
  printf '[lab] error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command '$1'${2:+ - $2}"
}

# Reads the image pins. They are repository state, so they are not taken from a .env.
load_images() {
  [ -f "$IMAGES_FILE" ] || die "missing $IMAGES_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$IMAGES_FILE"
  set +a
  : "${AEGIS_LAB_DNS_IMAGE:?deploy/lab/images.env: AEGIS_LAB_DNS_IMAGE missing}"
  : "${AEGIS_LAB_PASSIVE_IMAGE:?deploy/lab/images.env: AEGIS_LAB_PASSIVE_IMAGE missing}"
  : "${AEGIS_LAB_DNSX_IMAGE:?deploy/lab/images.env: AEGIS_LAB_DNSX_IMAGE missing}"
  : "${AEGIS_LAB_SUBFINDER_IMAGE:?deploy/lab/images.env: AEGIS_LAB_SUBFINDER_IMAGE missing}"
}

compose() { podman-compose -p "$LAB_PROJECT" -f "$COMPOSE_FILE" "$@"; }

container_exists() { podman container exists "$1" 2>/dev/null; }

container_running() {
  container_exists "$1" && [ "$(podman inspect --format '{{.State.Running}}' "$1")" = true ]
}

require_lab_up() {
  container_running "$DNS_CONTAINER" ||
    die "$DNS_CONTAINER is not running - run 'make lab-up' first"
  container_running "$PASSIVE_CONTAINER" ||
    die "$PASSIVE_CONTAINER is not running - run 'make lab-up' first"
}

# One-shot DNSx container with the G0.2 sandbox flags that apply to a lab verification run:
# rootless podman, current uid:gid, no host network (the internal lab network only), all
# capabilities dropped, no-new-privileges, read-only rootfs, tmpfs only, cgroup limits from
# the pinned dnsx manifest (cpu 0.5, memory 256 MiB, timeout 300 s) and the pinned resolver.
# Collector output caps are not repeated here: they belong to G1.3a (M06/collector).
podman_dnsx() { # <in-dir> <out-dir> <container-name> [dnsx args...]
  local in=$1 out=$2 name=$3
  shift 3
  podman run --rm --name "$name" --label "$RUN_LABEL" \
    --network "$LAB_NETWORK" \
    --cap-drop ALL --security-opt no-new-privileges \
    --read-only --tmpfs /tmp:size=16m \
    --pids-limit 256 --memory 256m --cpus 0.5 \
    --timeout 300 \
    --userns=keep-id --user "$(id -u):$(id -g)" \
    -v "$in:/in:ro,z" -v "$out:/out:Z" \
    "$AEGIS_LAB_DNSX_IMAGE" -silent -json -a -aaaa -cname -t 8 -r "$DNS_IP" "$@"
}

# Resolves one lab name and prints the single JSONL result line. Returns non-zero when the
# container or the query failed.
probe_dns() { # <host>
  local host=$1 work line
  work=$(mktemp -d "$RUN_DIR/probe-XXXXXX") || return 1
  mkdir -p "$work/in" "$work/out"
  printf '%s\n' "$host" >"$work/in/targets.txt"
  if ! podman_dnsx "$work/in" "$work/out" "aegis-lab-probe-$$" \
    -l /in/targets.txt -o /out/result.jsonl >/dev/null 2>&1; then
    rm -rf "$work"
    return 1
  fi
  line=$(cat "$work/out/result.jsonl" 2>/dev/null || true)
  rm -rf "$work"
  [ -n "$line" ] || return 1
  printf '%s\n' "$line"
}

# True when the lab resolver answers www.lab.aegis.test with the documented A record.
dns_answer_is_expected() { # <json-line>
  python3 - "$1" <<'PY'
import json
import sys

try:
    record = json.loads(sys.argv[1])
except (json.JSONDecodeError, IndexError):
    sys.exit(1)
ok = record.get("status_code") == "NOERROR" and "203.0.113.10" in (record.get("a") or [])
sys.exit(0 if ok else 1)
PY
}

# Human-readable one-line summary of a DNSx result, for status output.
describe_dns() { # <json-line>
  python3 - "$1" <<'PY'
import json
import sys

record = json.loads(sys.argv[1])
answers = [
    f"{kind.upper()} {value}"
    for kind in ("a", "aaaa", "cname")
    for value in (record.get(kind) or [])
]
print(f"{record.get('host')} {record.get('status_code')} " + ("; ".join(answers) or "(no answers)"))
PY
}

wait_dns_ready() { # <timeout-seconds>
  local timeout=${1:-120} deadline line
  deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if line=$(probe_dns www.lab.aegis.test) && dns_answer_is_expected "$line"; then
      return 0
    fi
    sleep 1
  done
  podman logs --tail 20 "$DNS_CONTAINER" >&2 2>&1 || true
  return 1
}

# True when every G1.6a service endpoint accepts a TCP connection from the lab network. One
# throwaway container runs the checks: the lab network is internal, so the probe is the same kind of
# client the scanner is, and nothing is published to the host.
services_ready() {
  local args=()
  for endpoint in "${SERVICE_ENDPOINTS[@]}"; do args+=("$endpoint"); done
  podman run --rm --name "aegis-lab-services-probe-$$" --label "$RUN_LABEL" \
    --network "$LAB_NETWORK" --cap-drop ALL --security-opt no-new-privileges --read-only \
    --tmpfs /tmp:size=8m "$AEGIS_LAB_PASSIVE_IMAGE" python3 - "${args[@]}" >/dev/null 2>&1 <<'PY'
import socket
import sys

for endpoint in sys.argv[1:]:
    host, _, port = endpoint.rpartition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            pass
    except OSError as error:
        print(f"{endpoint}: {error}", file=sys.stderr)
        sys.exit(1)
PY
}

wait_services_ready() { # <timeout-seconds>
  local timeout=${1:-120} deadline
  deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    services_ready && return 0
    sleep 2
  done
  for container in "${SERVICE_CONTAINERS[@]}"; do
    podman logs --tail 10 "$container" >&2 2>&1 || true
  done
  return 1
}

wait_passive_healthy() { # <timeout-seconds>
  local timeout=${1:-120} deadline status
  deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    container_exists "$PASSIVE_CONTAINER" || die "$PASSIVE_CONTAINER is gone (see: make lab-status)"
    status=$(podman inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$PASSIVE_CONTAINER")
    case $status in
    healthy) return 0 ;;
    unhealthy)
      podman logs --tail 30 "$PASSIVE_CONTAINER" >&2 || true
      die "$PASSIVE_CONTAINER is unhealthy"
      ;;
    esac
    sleep 1
  done
  podman logs --tail 30 "$PASSIVE_CONTAINER" >&2 || true
  die "timed out after ${timeout}s waiting for $PASSIVE_CONTAINER to become healthy"
}

# Throwaway lab CA plus a crt.sh certificate and the web service's TLS certificate, so the
# Subfinder run can trust the local stub without touching the system trust store and the lab web
# service can answer HTTPS with a lab-issued certificate. Generated on the host, git-ignored,
# removed by `make lab-down`; never committed and never installed anywhere else.
generate_lab_tls() {
  mkdir -p "$RUN_DIR" "$RUN_DIR/runs"
  chmod 755 "$RUN_DIR" "$RUN_DIR/runs"
  mkdir -p "$TLS_DIR"
  chmod 700 "$TLS_DIR"
  if [ -s "$TLS_DIR/ca.crt" ] && [ -s "$TLS_DIR/crt.sh.crt" ] && [ -s "$TLS_DIR/crt.sh.key" ] &&
    [ -s "$TLS_DIR/lab-web.crt" ] && [ -s "$TLS_DIR/lab-web.key" ]; then
    log "lab TLS: reusing the generated CA, crt.sh and web certificates"
    return 0
  fi
  require_cmd openssl
  local ext
  ext=$(mktemp)
  cat >"$ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:crt.sh
EOF
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" -days 30 \
    -subj "/CN=AEGIS lab CA (G0.4c, throwaway)" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$TLS_DIR/crt.sh.key" -out "$TLS_DIR/crt.sh.csr" \
    -subj "/CN=crt.sh" 2>/dev/null
  openssl x509 -req -in "$TLS_DIR/crt.sh.csr" \
    -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
    -out "$TLS_DIR/crt.sh.crt" -days 30 -extfile "$ext" 2>/dev/null
  rm -f "$TLS_DIR/crt.sh.csr" "$TLS_DIR/ca.srl"
  # The web service's certificate (G1.6a): the same CA, one name, so the TLS port is a real
  # handshake with a lab-issued chain instead of a PEM checked into the repository.
  cat >"$ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:web.lab.aegis.test
EOF
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$TLS_DIR/lab-web.key" -out "$TLS_DIR/lab-web.csr" \
    -subj "/CN=web.lab.aegis.test" 2>/dev/null
  openssl x509 -req -in "$TLS_DIR/lab-web.csr" \
    -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
    -out "$TLS_DIR/lab-web.crt" -days 30 -extfile "$ext" 2>/dev/null
  rm -f "$TLS_DIR/lab-web.csr" "$TLS_DIR/ca.srl" "$ext"
  chmod 644 "$TLS_DIR/ca.crt" "$TLS_DIR/crt.sh.crt" "$TLS_DIR/lab-web.crt"
  chmod 600 "$TLS_DIR/ca.key" "$TLS_DIR/crt.sh.key" "$TLS_DIR/lab-web.key"
  log "lab TLS: generated throwaway CA, crt.sh and web certificates in deploy/lab/.run/tls"
}

new_run_dir() { # <kind>; prints the evidence directory
  local kind=$1 stamp dir
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  dir="$RUN_DIR/runs/${kind}-${stamp}"
  mkdir -p "$dir/out"
  printf '%s\n' "$dir"
}
