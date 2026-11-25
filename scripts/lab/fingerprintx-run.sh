#!/usr/bin/env bash
# Reproducible fingerprintx run against the authorized lab (G1.6b), compared to the committed
# fixture. The pinned image (built by `make lab-build-fingerprintx`) runs with the sandbox flags
# that apply to a verification run (current uid:gid, internal lab network only, all capabilities
# dropped, read-only rootfs, cgroup limits from the pinned manifest); the raw JSONL and the
# comparison stay in deploy/lab/.run/runs/ as evidence.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
require_lab_up
require_lab_web
podman image exists "$AEGIS_LAB_FINGERPRINTX_IMAGE" ||
  die "missing $AEGIS_LAB_FINGERPRINTX_IMAGE - run 'make lab-build-fingerprintx' first"

run_dir=$(new_run_dir fingerprintx)
cat >"$run_dir/targets.txt" <<'EOF'
10.114.53.21:8080
10.114.53.22:8443
10.114.53.53:53
EOF
cat >"$run_dir/command.txt" <<EOF
# aegis-lab fingerprintx run ($(date -u +%Y-%m-%dT%H:%M:%SZ))
image:    $AEGIS_LAB_FINGERPRINTX_IMAGE
network:  $LAB_NETWORK (internal, no route off this host)
targets:  deploy/lab/.run/runs/$(basename "$run_dir")/targets.txt (service keys as host:port)
args:     -l /in/targets.txt --json -o /out/result.jsonl -w 2000
limits:   --cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 256
          --memory 256m --cpus 0.5 --timeout 120 (fingerprintx manifest budget)
EOF

log "fingerprintx: running $AEGIS_LAB_FINGERPRINTX_IMAGE against the lab web, TLS and DNS services"
if ! podman_fingerprintx "$run_dir" "$run_dir/out" "aegis-lab-fingerprintx-run" \
  -l /in/targets.txt --json -o /out/result.jsonl -w 2000 >"$run_dir/stdout.jsonl" 2>"$run_dir/stderr.txt"; then
  tail -20 "$run_dir/stderr.txt" >&2 || true
  die "fingerprintx run failed (evidence: $run_dir)"
fi

sha256sum "$run_dir/out/result.jsonl" >"$run_dir/result.sha256"
python3 "$LAB_SCRIPTS/compare_results.py" fingerprintx \
  --expected "$FIXTURES_DIR/fingerprintx.expected.json" \
  --actual "$run_dir/out/result.jsonl" | tee "$run_dir/comparison.txt"

log "fingerprintx: raw $run_dir/out/result.jsonl ($(cat "$run_dir/result.sha256"))"
