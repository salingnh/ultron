#!/usr/bin/env bash
# Reproducible DNSx run against the authorized lab (G0.4c), compared to the committed
# fixture. The pinned G0.2 image runs with the sandbox flags that apply to a verification
# run (current uid:gid, internal lab network only, all capabilities dropped, read-only
# rootfs, cgroup limits from the pinned manifest); the raw JSONL and the comparison stay in
# deploy/lab/.run/runs/ as evidence.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
require_lab_up
[ -f "$FIXTURES_DIR/targets.txt" ] || die "missing $FIXTURES_DIR/targets.txt"

run_dir=$(new_run_dir dnsx)
cat >"$run_dir/command.txt" <<EOF
# aegis-lab DNSx run ($(date -u +%Y-%m-%dT%H:%M:%SZ))
image:    $AEGIS_LAB_DNSX_IMAGE
network:  $LAB_NETWORK (internal, no route off this host)
resolver: $DNS_IP (authoritative for $LAB_ZONE)
targets:  deploy/lab/fixtures/targets.txt
args:     -silent -json -a -aaaa -cname -t 8 -r $DNS_IP -l /in/targets.txt -o /out/result.jsonl
limits:   --cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 256
          --memory 256m --cpus 0.5 --timeout 300 (dnsx manifest budget)
EOF

log "dnsx: running $AEGIS_LAB_DNSX_IMAGE against $LAB_ZONE on $LAB_NETWORK"
if ! podman_dnsx "$FIXTURES_DIR" "$run_dir/out" "aegis-lab-dnsx-run" \
  -l /in/targets.txt -o /out/result.jsonl >"$run_dir/stdout.jsonl" 2>"$run_dir/stderr.txt"; then
  tail -20 "$run_dir/stderr.txt" >&2 || true
  die "dnsx run failed (evidence: $run_dir)"
fi

sha256sum "$run_dir/out/result.jsonl" >"$run_dir/result.sha256"
python3 "$LAB_SCRIPTS/compare_results.py" dnsx \
  --expected "$FIXTURES_DIR/dnsx.expected.json" \
  --actual "$run_dir/out/result.jsonl" | tee "$run_dir/comparison.txt"

log "dnsx: raw $run_dir/out/result.jsonl ($(cat "$run_dir/result.sha256"))"
