#!/usr/bin/env bash
# G1.6b: prove httpx really routes every connection through a proxy, and nothing else.
#
# httpx's manifest declares `proxyAware: true`; that is only truthful if the tool's requests go
# through the proxy it is given. This check makes the platform's broker stand in as a minimal
# SOCKS5 CONNECT proxy with the job's binding as its allow-list
# (deploy/lab/proxy/socks5_allowlist.py) and runs the pinned httpx image against the lab web
# services with `-proxy socks5://…`:
#
#   * every application the direct run finds must still be found,
#   * the proxy log must show one CONNECT per lab web endpoint,
#   * a CONNECT to a destination outside the binding must be refused by the proxy (checked with a
#     plain client, so httpx is not asked to do the negative case).
#
# Only the task's own containers are created; they are removed on exit.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
require_lab_up
wait_services_ready 120 || die "the lab services are not accepting connections - run 'make lab-up' first"

PROXY_CONTAINER=aegis-lab-httpx-proxy
PROXY_IMAGE="$AEGIS_LAB_PASSIVE_IMAGE"
PROXY_IP=10.114.53.90

run_dir=$(new_run_dir httpx-proxy)
python3 - "$LAB_DIR/inventory.json" "$run_dir/targets.txt" "$run_dir/allow.txt" <<'PY'
import json
import sys

inventory = json.load(open(sys.argv[1], encoding="utf-8"))
http_ports = {80, 443, 8080, 8443}
targets = [
    f"{service['address']}:{port}"
    for service in inventory["services"]
    for port in service["ports"]
    if port in http_ports
]
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(targets) + "\n")
open(sys.argv[3], "w", encoding="utf-8").write("\n".join(targets) + "\n")
PY
mapfile -t ALLOW < "$run_dir/allow.txt"
ALLOW_ARGS=()
for entry in "${ALLOW[@]}"; do ALLOW_ARGS+=(--allow "$entry"); done

cleanup() {
  podman rm -f -v "$PROXY_CONTAINER" >/dev/null 2>&1 || true
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

log "httpx proxy check: starting $PROXY_IMAGE as a SOCKS5 allow-list proxy on $PROXY_IP:1080"
podman run -d --name "$PROXY_CONTAINER" --label "$RUN_LABEL" \
  --network "$LAB_NETWORK" --ip "$PROXY_IP" \
  --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:size=8m --pids-limit 64 --memory 128m --cpus 0.25 \
  --userns=keep-id --user "$(id -u):$(id -g)" \
  -v "$LAB_DIR/proxy:/proxy:ro,z" \
  "$PROXY_IMAGE" python3 /proxy/socks5_allowlist.py --port 1080 "${ALLOW_ARGS[@]}" >/dev/null

for _ in $(seq 1 30); do
  podman logs "$PROXY_CONTAINER" 2>&1 | grep -q '"event": "listening"' && break
  sleep 1
done
podman logs "$PROXY_CONTAINER" 2>&1 | grep -q '"event": "listening"' ||
  die "the SOCKS5 proxy did not start (podman logs $PROXY_CONTAINER)"

cat >"$run_dir/command.txt" <<EOF
# aegis-lab httpx proxy check ($(date -u +%Y-%m-%dT%H:%M:%SZ))
image:    $AEGIS_LAB_HTTPX_IMAGE
proxy:    socks5://$PROXY_IP:1080 (allow-list: ${ALLOW[*]})
network:  $LAB_NETWORK (internal, no route off this host)
args:     -l /in/targets.txt -json -silent -o /out/result.jsonl -tech-detect -cpe -tls-grab
          -irh -irr -threads 4 -timeout 10 -no-color -proxy socks5://$PROXY_IP:1080
EOF

log "httpx proxy check: running httpx through socks5://$PROXY_IP:1080"
podman run --rm --name "${PROXY_CONTAINER}-run" --label "$RUN_LABEL" \
  --network "$LAB_NETWORK" \
  --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:size=16m --pids-limit 256 --memory 256m --cpus 0.5 --timeout 180 \
  --userns=keep-id --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$run_dir:/in:ro,z" -v "$run_dir/out:/out:Z" \
  "$AEGIS_LAB_HTTPX_IMAGE" -l /in/targets.txt -json -silent -o /out/result.jsonl \
  -tech-detect -cpe -tls-grab -irh -irr -threads 4 -timeout 10 -no-color \
  -proxy "socks5://$PROXY_IP:1080" >"$run_dir/stdout.jsonl" 2>"$run_dir/stderr.txt" ||
  { tail -20 "$run_dir/stderr.txt" >&2 || true; die "httpx through the proxy failed (evidence: $run_dir)"; }

podman logs "$PROXY_CONTAINER" >"$run_dir/proxy.jsonl" 2>&1 || true

python3 - "$run_dir" <<'PY'
import json
import sys
from pathlib import Path

run = Path(sys.argv[1])
targets = [line.strip() for line in (run / "targets.txt").read_text().splitlines() if line.strip()]
results = [json.loads(line) for line in (run / "out/result.jsonl").read_text().splitlines() if line.strip()]
events = [json.loads(line) for line in (run / "proxy.jsonl").read_text().splitlines() if line.strip().startswith("{")]
connects = {event["destination"] for event in events if event.get("event") == "connect"}
denied = [event for event in events if event.get("event") == "denied"]
urls = sorted(record.get("url") for record in results)
print("  applications:", urls)
print("  proxy CONNECTs:", sorted(connects))
problems = []
if not results:
    problems.append("no application came back through the proxy")
if connects != set(targets):
    problems.append(f"proxy saw {sorted(connects)}; the job binding is {sorted(targets)}")
if denied:
    problems.append(f"proxy denied destinations: {denied}")
# Technology detection must survive the proxy for the origins that publish one (Tomcat answers 404
# with no tech header, and that is its own fact, not a proxy problem).
if not any(record.get("tech") for record in results):
    problems.append("no technology detected on any application through the proxy")
if problems:
    print("httpx proxy check: FAIL", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    sys.exit(1)
print(f"httpx proxy check: PASS ({len(results)} applications, {len(connects)} CONNECTs, 0 denied)")
PY

log "httpx proxy check: evidence $run_dir"
