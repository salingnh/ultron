#!/usr/bin/env bash
# Reproducible httpx run against the authorized lab (G1.6b), compared to the committed fixture.
# The pinned image runs with the same sandbox flags as the other lab verification runs; the raw
# JSONL and the comparison stay in deploy/lab/.run/runs/ as evidence.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
require_lab_up
require_lab_web

run_dir=$(new_run_dir httpx)
cat >"$run_dir/targets.txt" <<'EOF'
10.114.53.21:8080
10.114.53.22:8443
EOF
cat >"$run_dir/command.txt" <<EOF
# aegis-lab httpx run ($(date -u +%Y-%m-%dT%H:%M:%SZ))
image:    $AEGIS_LAB_HTTPX_IMAGE
network:  $LAB_NETWORK (internal, no route off this host)
targets:  deploy/lab/.run/runs/$(basename "$run_dir")/targets.txt (host:port, no scheme: httpx
          probes HTTPS then HTTP, which is why runtime.targetsFormat=host_port exists)
args:     -l /in/targets.txt -json -silent -o /out/result.jsonl -tech-detect -cpe -tls-grab
          -irh -threads 4 -timeout 10 -no-color
limits:   --cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 256
          --memory 256m --cpus 0.5 --timeout 180 (httpx manifest budget)
EOF

log "httpx: running $AEGIS_LAB_HTTPX_IMAGE against the lab HTTP and HTTPS services"
if ! podman_httpx "$run_dir" "$run_dir/out" "aegis-lab-httpx-run" \
  -l /in/targets.txt -json -silent -o /out/result.jsonl -tech-detect -cpe -tls-grab -irh \
  -threads 4 -timeout 10 -no-color >"$run_dir/stdout.jsonl" 2>"$run_dir/stderr.txt"; then
  tail -20 "$run_dir/stderr.txt" >&2 || true
  die "httpx run failed (evidence: $run_dir)"
fi

sha256sum "$run_dir/out/result.jsonl" >"$run_dir/result.sha256"
python3 "$LAB_SCRIPTS/compare_results.py" httpx \
  --expected "$FIXTURES_DIR/httpx.expected.json" \
  --actual "$run_dir/out/result.jsonl" | tee "$run_dir/comparison.txt"

log "httpx: raw $run_dir/out/result.jsonl ($(cat "$run_dir/result.sha256"))"
