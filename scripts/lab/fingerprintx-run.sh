#!/usr/bin/env bash
# Reproducible fingerprintx run against the authorized lab (G1.6b/G1.6a), compared to the committed
# fixture. The pinned image (built by `make lab-build-fingerprintx`) runs with the sandbox flags of a
# verification run (current uid:gid, internal lab network only, all capabilities dropped, read-only
# rootfs, cgroup limits from the pinned manifest); the raw JSONL and the comparison stay in
# deploy/lab/.run/runs/ as evidence.
#
# Targets: every (address, port) the inventory declares for a lab service. The service containers are
# deliberately old releases (nginx 1.18, Tomcat 9.0.30, OpenSSH 9.9, Redis 6.0.5, Apache 2.4.49), so
# the run proves the fingerprinter reads a product and a version off real, versioned software.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
require_lab_up
wait_services_ready 120 || die "the lab services are not accepting connections - run 'make lab-up' first"
podman image exists "$AEGIS_LAB_FINGERPRINTX_IMAGE" ||
  die "missing $AEGIS_LAB_FINGERPRINTX_IMAGE - run 'make lab-build-fingerprintx' first"

run_dir=$(new_run_dir fingerprintx)
python3 - "$LAB_DIR/inventory.json" "$run_dir/targets.txt" <<'PY'
import json
import sys

inventory = json.load(open(sys.argv[1], encoding="utf-8"))
targets = [f"{service['address']}:{port}" for service in inventory["services"] for port in service["ports"]]
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write("\n".join(targets) + "\n")
print(" ".join(targets))
PY
cat >"$run_dir/command.txt" <<EOF
# aegis-lab fingerprintx run ($(date -u +%Y-%m-%dT%H:%M:%SZ))
image:    $AEGIS_LAB_FINGERPRINTX_IMAGE
network:  $LAB_NETWORK (internal, no route off this host)
targets:  deploy/lab/inventory.json services as host:port (runtime.targetsFormat=host_port)
args:     -l /in/targets.txt --json -o /out/result.jsonl -w 2000
limits:   --cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 256
          --memory 256m --cpus 0.5 --timeout 120 (fingerprintx manifest budget)
EOF

log "fingerprintx: running $AEGIS_LAB_FINGERPRINTX_IMAGE against $(wc -l <"$run_dir/targets.txt") lab service endpoints"
if ! podman run --rm --name aegis-lab-fingerprintx-run --label "$RUN_LABEL" \
  --network "$LAB_NETWORK" \
  --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:size=16m \
  --pids-limit 256 --memory 256m --cpus 0.5 \
  --timeout 120 \
  --userns=keep-id --user "$(id -u):$(id -g)" \
  -v "$run_dir:/in:ro,z" -v "$run_dir/out:/out:Z" \
  "$AEGIS_LAB_FINGERPRINTX_IMAGE" -l /in/targets.txt --json -o /out/result.jsonl -w 2000 \
  >"$run_dir/stdout.jsonl" 2>"$run_dir/stderr.txt"; then
  tail -20 "$run_dir/stderr.txt" >&2 || true
  die "fingerprintx run failed (evidence: $run_dir)"
fi

sha256sum "$run_dir/out/result.jsonl" >"$run_dir/result.sha256"
python3 "$LAB_SCRIPTS/compare_results.py" fingerprintx \
  --expected "$FIXTURES_DIR/fingerprintx.expected.json" \
  --actual "$run_dir/out/result.jsonl" | tee "$run_dir/comparison.txt"

log "fingerprintx: raw $run_dir/out/result.jsonl ($(cat "$run_dir/result.sha256"))"
