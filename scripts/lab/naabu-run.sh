#!/usr/bin/env bash
# Reproducible Naabu run against the authorized lab (G1.6a): the pinned image scans the four lab
# service containers on the internal lab network with the same CONNECT scan the manifest pins
# (`-s connect`, no NET_RAW), and the result is compared to the committed, inventory-derived
# expectation.
#
# The raw JSONL and the comparison stay in deploy/lab/.run/runs/ as evidence; the adapter package
# commits the same run as `adapters/m09/naabu/fixtures/lab/` (the file is copied, never regenerated
# by a different command).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
require_lab_up
wait_services_ready 120 || die "the lab services are not accepting connections - run 'make lab-up'"

# Ports: every port the inventory declares for a service, plus 22 as a negative control (no
# service listens there, so a run that reports it is scanning something else).
PORTS=22,80,443,2222,6379,8009,8080
mapfile -t TARGETS < <(python3 - "$LAB_DIR/inventory.json" <<'PY'
import json
import sys

inventory = json.load(open(sys.argv[1], encoding="utf-8"))
for service in inventory["services"]:
    print(service["address"])
PY
)

run_dir=$(new_run_dir naabu)
printf '%s\n' "${TARGETS[@]}" >"$run_dir/targets.txt"
printf '%s\n' "${PORTS//,/ }" | tr ' ' '\n' >"$run_dir/ports.txt"
cat >"$run_dir/command.txt" <<EOF
# aegis-lab Naabu run ($(date -u +%Y-%m-%dT%H:%M:%SZ))
image:    $AEGIS_LAB_NAABU_IMAGE
network:  $LAB_NETWORK (internal, no route off this host)
targets:  ${TARGETS[*]} (deploy/lab/inventory.json services)
ports:    $PORTS
args:     -silent -json -s connect -duc -list /in/targets.txt -ports-file /in/ports.txt \\
          -c 4 -rate 100 -timeout 1s -o /out/result.jsonl
limits:   --cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 256
          --memory 512m --cpus 1 --timeout 900 (naabu manifest budget)
EOF

log "naabu: scanning ${#TARGETS[@]} lab addresses on $LAB_NETWORK (CONNECT scan, ports $PORTS)"
if ! podman run --rm --name aegis-lab-naabu-run --label "$RUN_LABEL" \
  --network "$LAB_NETWORK" \
  --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:size=16m \
  --pids-limit 256 --memory 512m --cpus 1 \
  --timeout 900 \
  --userns=keep-id --user "$(id -u):$(id -g)" \
  -v "$run_dir:/in:ro,z" -v "$run_dir/out:/out:Z" \
  "$AEGIS_LAB_NAABU_IMAGE" -silent -json -s connect -duc \
  -list /in/targets.txt -ports-file /in/ports.txt \
  -c 4 -rate 100 -timeout 1s -o /out/result.jsonl \
  >"$run_dir/stdout.jsonl" 2>"$run_dir/stderr.txt"; then
  tail -20 "$run_dir/stderr.txt" >&2 || true
  die "naabu run failed (evidence: $run_dir)"
fi

sha256sum "$run_dir/out/result.jsonl" >"$run_dir/result.sha256"
python3 "$LAB_SCRIPTS/compare_results.py" naabu \
  --expected "$FIXTURES_DIR/naabu.expected.json" \
  --actual "$run_dir/out/result.jsonl" | tee "$run_dir/comparison.txt"

log "naabu: raw $run_dir/out/result.jsonl ($(cat "$run_dir/result.sha256"))"
