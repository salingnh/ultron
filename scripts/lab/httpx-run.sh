#!/usr/bin/env bash
# Reproducible httpx run against the authorized lab (G1.6b), compared to the committed fixture.
# The pinned image runs with the same sandbox flags as the other lab verification runs; the raw
# JSONL and the comparison stay in deploy/lab/.run/runs/ as evidence.
#
# Targets are the HTTP(S) endpoints the inventory declares (nginx 80/443, Tomcat 8080, Apache 80);
# the non-HTTP services (sshd 2222, Redis 6379, AJP 8009) are deliberately left out: `web.probe_http`
# is proposed on the services fingerprinting identified as http(s). `-irr` carries the response body
# so a page that prints its product there (Tomcat's 404 page) can be read.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
require_lab_up
wait_services_ready 120 || die "the lab services are not accepting connections - run 'make lab-up' first"

run_dir=$(new_run_dir httpx)
python3 - "$LAB_DIR/inventory.json" "$run_dir/targets.txt" <<'PY'
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
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write("\n".join(targets) + "\n")
print(" ".join(targets))
PY
cat >"$run_dir/command.txt" <<EOF
# aegis-lab httpx run ($(date -u +%Y-%m-%dT%H:%M:%SZ))
image:    $AEGIS_LAB_HTTPX_IMAGE
network:  $LAB_NETWORK (internal, no route off this host)
targets:  HTTP(S) lab services as host:port, no scheme (runtime.targetsFormat=host_port; httpx
          probes HTTPS then HTTP)
args:     -l /in/targets.txt -json -silent -o /out/result.jsonl -tech-detect -cpe -tls-grab
          -irh -irr -threads 4 -timeout 10 -no-color
limits:   --cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 256
          --memory 256m --cpus 0.5 --timeout 180 (httpx manifest budget)
EOF

log "httpx: running $AEGIS_LAB_HTTPX_IMAGE against $(wc -l <"$run_dir/targets.txt") lab web endpoints"
if ! podman run --rm --name aegis-lab-httpx-run --label "$RUN_LABEL" \
  --network "$LAB_NETWORK" \
  --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:size=16m \
  --pids-limit 256 --memory 256m --cpus 0.5 \
  --timeout 180 \
  --userns=keep-id --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$run_dir:/in:ro,z" -v "$run_dir/out:/out:Z" \
  "$AEGIS_LAB_HTTPX_IMAGE" -l /in/targets.txt -json -silent -o /out/result.jsonl \
  -tech-detect -cpe -tls-grab -irh -irr -threads 4 -timeout 10 -no-color \
  >"$run_dir/stdout.jsonl" 2>"$run_dir/stderr.txt"; then
  tail -20 "$run_dir/stderr.txt" >&2 || true
  die "httpx run failed (evidence: $run_dir)"
fi

sha256sum "$run_dir/out/result.jsonl" >"$run_dir/result.sha256"
python3 "$LAB_SCRIPTS/compare_results.py" httpx \
  --expected "$FIXTURES_DIR/httpx.expected.json" \
  --actual "$run_dir/out/result.jsonl" | tee "$run_dir/comparison.txt"

log "httpx: raw $run_dir/out/result.jsonl ($(cat "$run_dir/result.sha256"))"
