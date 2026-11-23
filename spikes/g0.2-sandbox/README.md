# G0.2 — sandbox, network egress, collector/parser isolation, BBOT mapping

Spike code for task card **G0.2** (plan `g0-g1-plan.md`). It answers four
questions with runnable evidence, not prose:

1. Do CPU/memory/PID/timeout/output limits actually apply on this host under
   rootless Podman (cgroup v2 delegation), or do they fail silently?
2. Can a job container be kept off the control/data plane, loopback, metadata
   and the campaign denylist — including IPv4-mapped, NAT64 and 6to4 forms —
   while still reaching its own targets and declared provider sources?
3. Can the collector/parser treat scanner output as hostile (symlinks, FIFOs,
   zip bombs, sockets) without a trusted process touching it?
4. Can BBOT passive JSON be mapped onto a valid `ResultEnvelope` v2 today, and
   which versions/images are safe to pin (14-day rule, license, SBOM)?

Findings are written into `docs/living/dac-ta-ky-thuat/02-nen-tang.md`
(§Sandbox) and `04-module-ket-noi-oss.md` (§Chọn provider và quản lý phiên
bản) by the docs-only PR that accompanies this spike branch.

## Layout

```
aegis_g02/netpolicy.py      allow/deny decision per connection (pure, unit-tested)
aegis_g02/egress_broker.py  per-job HTTP CONNECT / plain HTTP / SOCKS5 broker
aegis_g02/podman_runner.py  hardened `podman run` argv, one internal network per job
aegis_g02/collector.py      regular files only, caps, zip-bomb check, SHA-256
aegis_g02/parser_host.py    parser in a user+net namespace, clean env, rlimits
aegis_g02/parser_child.py   the child that runs `parse()`
aegis_g02/bbot_map.py       BBOT NDJSON -> ParsedResults -> ResultEnvelope v2
aegis_g02/probes.py         probe parsers (network, env, OOM, crash, determinism)
aegis_g02/job_probe.py      in-container probe reporting what it can reach
aegis_g02/standins.py       stand-in PG/Neo4j/S3/Temporal listeners (test only)
aegis_g02/allowed_target.py the single allowed destination of the egress tests
fixtures/bbot/              synthetic BBOT NDJSON + provenance note
pins/                       pin table (JSON + Markdown)
sbom/                       SPDX 2.3 SBOMs of the pinned images
tests/                      unit + Podman integration tests
```

## Run

```bash
cd spikes/g0.2-sandbox
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# unit tests: policy, collector, parser isolation, BBOT mapping, contract validation
G02_REPO_ROOT=<repo root> .venv/bin/python -m pytest tests -q

# everything incl. Podman isolation tests (needs rootless Podman + cgroup v2)
G02_REPO_ROOT=<repo root> G02_PODMAN=1 .venv/bin/python -m pytest tests -q
```

`scripts/verify.sh` does both, then prints the host facts the spike relied on.
`scripts/pins.sh` regenerates `sbom/` and re-checks the pin table inputs.

## What the tests prove (short)

| Question | Test | Observed |
|---|---|---|
| cgroup v2 delegated | `test_cgroup_v2_is_the_controller` | cgroup2fs, systemd manager, `cpu memory pids` controllers |
| memory cap enforced | `test_memory_limit_kills_the_container` | `OOMKilled=true`, exit 137 |
| pids cap enforced | `test_pids_limit_blocks_forks` | `pids.events: max N>0`, forks fail |
| cpu cap enforced | `test_cpu_quota_throttles` | `nr_throttled > 0` |
| timeout stops the job | `test_wall_clock_timeout_kills_and_still_reports` | state `timeout`, duration < 20 s |
| read-only rootfs + output quota | `test_read_only_rootfs_and_output_quota` | `/etc` write fails, `/out` write hits the tmpfs cap |
| caps dropped, no-new-privs | `test_all_capabilities_dropped_and_no_new_privileges` | `CapEff/CapBnd = 0`, `NoNewPrivs=1` |
| NET_RAW only when granted | `test_raw_socket_denied_without_capability_and_allowed_with_it` | ping fails without, succeeds with `--cap-add=NET_RAW` |
| job is unprivileged | `test_job_runs_as_unprivileged_user` | uid/gid 65534 |
| no control-plane path | `test_job_has_no_route_to_control_plane_or_metadata` | stand-in PG/Neo4j/S3/Temporal, gateway, host IP, metadata, `::1`, `::ffff:127.0.0.1` all unreachable |
| no external DNS | `test_job_has_no_external_dns` | internal network has `--disable-dns` |
| egress broker allows the bound target | `test_broker_allows_the_bound_target` | 200 + body |
| broker denies control/metadata/loopback/unbound | `test_broker_denies_control_plane_metadata_and_unbound` | 403 with stable reason codes, incl. `::ffff:127.0.0.1` |
| redirect re-checked | `test_redirect_target_is_rechecked` | 302 target is denied on the next hop |
| SOCKS5 path | `test_socks5_broker_denies_and_allows` | allowed target CONNECTED, loopback `DENIED-BY-RULESET` |
| collector rejects hostile output | `tests/test_collector.py` | symlink/FIFO skipped, byte/count/zip-bomb caps raise |
| parser cannot open a socket | `test_parser_cannot_open_a_socket` | `ENETUNREACH`, no inherited env |
| BBOT fixture → envelope | `tests/test_bbot_map.py` | validates against `result-envelope.v2.schema.json` |

## Known limits (see the report)

- A job's only egress path is the L7 broker, so **raw-socket/SYN scans and UDP
  scans cannot be served by this mode**; Naabu SYN silently degrades to CONNECT
  inside rootless Podman. G1 therefore runs Subfinder/DNSx/BBOT (HTTP/DNS) via
  the broker and keeps `rawSocket` off.
- The broker is trusted control-plane code: it must be digest-pinned, read-only
  and policy-mounted per job (the tests start it that way).
- SELinux on Fedora requires `:Z` (or label handling) for host bind mounts that
  a non-root container user must read; the runner must relabel only its own
  private output/policy directories.
- The BBOT fixture is synthetic (no lab targets are authorized yet).
