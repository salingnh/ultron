# AEGIS–Vanguard: dev environment (G0.4a), contract checks (G0.4b), authorized lab (G0.4c) and
# the Python gate (G1.1a).
#
# `make dev-up` brings up the local stack and applies the contract schema;
# `make lab-up` brings up the authorized DNS lab;
# `make ci-local` runs exactly what the contracts workflow runs on a PR;
# `make lint test codegen-check` runs exactly what the python workflow runs on a PR.
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help dev-up dev-down dev-reset dev-status dev-logs contracts-gate graph-check ci-local \
	lab-up lab-down lab-status lab-check lab-dnsx lab-subfinder lab-naabu \
	lab-fingerprintx lab-httpx lab-httpx-proxy lab-build-fingerprintx demo-g16b \
	vulnlab-up vulnlab-down vulnlab-status vulnlab-check vulnlab-test intel-kev intel-sync \
	deps lint test codegen codegen-check migrate ci-python \
	temporal-live demo-g15a demo-g1 demo-discovery demo-g16c demo-recovery soak-start soak-stop \
	run-local stop-local seed-demo llm-smoke broker-image internet-smoke \
	llm-gateway-up llm-gateway-down llm-gateway-status llm-gateway-reload llm-gateway-test

# The help text is data, not shell: one entry per .PHONY target, printed with `$(info)` so an
# apostrophe or any other shell metacharacter in a description cannot break the recipe. It was a
# chain of single-quoted printf arguments before, and `checkout\'s` in one of them ended the
# quote early: `make help` died in the shell with a syntax error before printing a line.
# tests/test_makefile_help.py fails when a .PHONY target has no entry here.
define HELP
make help            this list
make dev-up          start PostgreSQL 16, Neo4j 5.26, SeaweedFS (S3) and Temporal;
                     apply migrations, graph constraints and the raw bucket
make dev-down        remove only this checkout's dev compose project (containers + volumes);
                     AEGIS_DEV_PROJECT in .env names it when several checkouts share a host
make dev-reset       dev-down then dev-up: a database from the replaced migration chain is
                     reset (the contract schema has one baseline migration)
make dev-status      health and endpoints of the dev stack (non-zero if not healthy)
make dev-logs        follow the dev stack logs
make lab-up          start the authorized lab (or use the one already running on this host):
                     lab zone DNS + local passive-source stub on an internal network
make lab-down        remove only this checkout's lab project and the throwaway lab CA
make lab-status      lab health and boundary (non-zero if not healthy)
make lab-check       inventory consistency + Subfinder, DNSx, Naabu, fingerprintx and
                     httpx runs compared to fixtures
make lab-dnsx        only the DNSx run and its fixture comparison
make lab-subfinder   only the Subfinder run and its fixture comparison
make lab-naabu       only the Naabu CONNECT run on the lab service containers
make lab-fingerprintx     only the fingerprintx run (service fingerprint) and comparison
make lab-httpx       only the httpx run (web.probe_http) and comparison
make lab-httpx-proxy     httpx through a SOCKS5 allow-list proxy (the proxyAware evidence)
make lab-build-fingerprintx  build the pinned fingerprintx image (no upstream image)
make vulnlab-up      start the CVE test lab (deploy/vulnlab): known-vulnerable HTTP
                     origins on their own internal network + the lab network; auto-stops
                     after VULNLAB_TTL_MINUTES (default 120). Publishing is explicit:
                     VULNLAB_TUNNEL=1 (default lab-only). One stack per host; name this
                     checkout with AEGIS_VULNLAB_PROJECT in deploy/vulnlab/.env
make vulnlab-down    remove only the aegis-vulnlab project (containers + its two networks)
make vulnlab-status  boundary, tunnel state and remaining TTL (non-zero if not healthy)
make vulnlab-check   PROFILE=lab|internet: every origin (lab) or public hostname (internet)
                     serves the page its catalog entry documents (read-only; works on
                     another checkout's running stack too)
make vulnlab-test    PROFILE=lab|internet: one campaign per catalog case, assert the
                     detections and CVE candidates (needs make run-local)
make contracts-gate  README contract gate: validator, tests, PostgreSQL 16 chains
make graph-check     Neo4j Cypher smoke (CI: neo4j step)
make ci-local        contracts-gate + graph-check
make deps            create/refresh the locked Python 3.12 environment (uv sync --frozen)
make lint            ruff check + ruff format --check + mypy over src/tests/adapters
make test            pytest (database tests run when AEGIS_TEST_PG_DSN is set)
make codegen         regenerate src/aegis/contracts_gen from contracts/
make codegen-check   fail if the committed DTOs differ from a fresh generation
make migrate         apply contracts/db/postgres in contracts/README.md order
                     (needs $$AEGIS_PG_DSN; recovery after an interrupted run:
                     python -m aegis.migrations mark-applied VERSION --sha256 SHA)
make temporal-live   M02 workflow gate on a real Temporal + throwaway PostgreSQL;
                     refreshes the replay fixture the CI test uses
make demo-g15a       G1.5a evidence: the flow document and the event stream over HTTP
                     (needs AEGIS_TEST_PG_DSN)
make ci-python       the python workflow: deps + lint + test + codegen-check
make run-local       the whole local stack of this checkout: dev stack, contract schema,
                     API + MCP, M02 worker/dispatcher, M23 projector, M06 runner
                     (LAB=0 no lab, WORKERS=0 API only, SEED=1 demo campaign)
make stop-local      stop exactly what make run-local started (its pids, and the stack/lab
                     only when run-local started them)
make seed-demo       POST the demo campaign and targets to a running API;
                     needs AEGIS_DEV_TOKEN from make run-local
make demo-g1         end-to-end G1 gate on the lab: campaign -> agent/MCP -> Subfinder ->
                     DNSx -> raw + metadata + graph + events, with the evidence printed
make demo-discovery  G1.6a: the same chain plus Naabu, so IP -> Service and EXPOSES edges
                     are in PostgreSQL and Neo4j
make demo-g16b       G1.6b gate: Naabu port -> fingerprintx service/CPE -> httpx
                     application, checked in PostgreSQL, Neo4j and the flow read model
make demo-g16c       CVE/CTI gate (G1.6c): fingerprinted service -> NVD/KEV/EPSS intel ->
                     candidate AFFECTED_BY in PostgreSQL and Neo4j + the candidate read API
make intel-kev       refresh the configured CISA KEV mirror: cisagov/kev-data default-branch
                     HEAD via the GitHub API, validated (shape, bounds, version) and recorded
                     with its commit; no fallback source
make intel-sync      the scheduled/incremental intel refresh: NVD (auto), EPSS when
                     AEGIS_EPSS_SOURCE is set, then KEV; exits non-zero if any leg is stale
make demo-recovery   SIGKILL the runner mid-job and show it resumes with no duplicate
make broker-image    build the internet-profile egress broker image (stdlib-only)
make internet-smoke  passive Subfinder on an authorized domain over the internet profile;
                     needs make run-local up, usage: make internet-smoke DOMAIN=<domain>
make soak-start      start the shortened 24 h soak (SOAK_HOURS=... to change) in .local/soak/
make soak-stop       stop the soak; its report stays in .local/soak/report.txt
make llm-smoke       ONE real provider call with the key from .env (never in CI);
                     prints the provider answer, tokens and cost - see .env.example
make llm-gateway-up  start the owner LLM gateway (LiteLLM proxy, pinned image) on
                     127.0.0.1 only; endpoints come from ~/.config/ultron/llm-gateway/config.yaml,
                     every key from this checkout's .env (one file, mode 600), and both are
                     merged with deploy/llm-gateway/base.yaml and validated before a container
                     exists
make llm-gateway-status   container, readiness, model groups, and per endpoint
                     healthy/cooling-down with its cooldown count
make llm-gateway-reload   apply edited endpoints or keys (.env): recreate only the gateway
                     container, then prove the router serves the file groups/endpoints
make llm-gateway-down     remove only this checkout gateway project
make llm-gateway-test     two fake upstreams (one 429, one OK) behind the pinned gateway:
                     rotation, cooldown skip, all-exhausted -> RATE_LIMITED, both standards
endef

help:
	$(info $(HELP))
	@:

dev-up:
	@scripts/dev/dev-up.sh

dev-down:
	@scripts/dev/dev-down.sh

# The contract schema is one baseline migration, so a database built by the replaced 0001..0016 chain
# is reset instead of upgraded: drop the dev project's volumes and apply the baseline again.
dev-reset:
	@scripts/dev/dev-down.sh
	@scripts/dev/dev-up.sh

dev-status:
	@scripts/dev/dev-status.sh

dev-logs:
	@scripts/dev/compose.sh logs -f

lab-up:
	@scripts/lab/lab-up.sh

lab-down:
	@scripts/lab/lab-down.sh

lab-status:
	@scripts/lab/lab-status.sh

lab-check:
	@python3 scripts/lab/check_inventory.py
	@scripts/lab/subfinder-run.sh
	@scripts/lab/dnsx-run.sh
	@scripts/lab/naabu-run.sh
	@scripts/lab/fingerprintx-run.sh
	@scripts/lab/httpx-run.sh

lab-dnsx:
	@scripts/lab/dnsx-run.sh

lab-subfinder:
	@scripts/lab/subfinder-run.sh

lab-naabu:
	@scripts/lab/naabu-run.sh

# G1.6b: service fingerprint and web probe against the lab service containers.
lab-fingerprintx:
	@scripts/lab/fingerprintx-run.sh

lab-httpx:
	@scripts/lab/httpx-run.sh

# Proves httpx's `proxyAware: true`: it reaches the lab services only through a SOCKS5 CONNECT
# proxy whose allow-list is the job binding, and a destination outside it is refused.
lab-httpx-proxy:
	@scripts/lab/httpx-proxy-check.sh

# fingerprintx publishes no container image; this builds the pinned one from the upstream source.
# A rebuild changes the image digest, which is a pin bump: deploy/lab/images.env, the adapter
# manifest and contracts/fixtures/valid/manifest.fingerprintx.yaml move together.
lab-build-fingerprintx:
	@podman build --network host -t localhost/aegis/fingerprintx:v1.1.19 deploy/lab/tools/fingerprintx
	@podman image inspect localhost/aegis/fingerprintx:v1.1.19 --format 'fingerprintx image: {{.Digest}}'

# --- CVE test lab (G1.6 slice E) ----------------------------------------------
# Known-vulnerable HTTP origins for the discovery chain (port -> fingerprint -> CVE candidates).
# Isolation and auto-stop are owned by scripts/vulnlab/*.sh: every container is created with a
# podman --timeout (VULNLAB_TTL_MINUTES), so the stack stops itself even if nobody remembers.

vulnlab-up:
	@scripts/vulnlab/vulnlab-up.sh

vulnlab-down:
	@scripts/vulnlab/vulnlab-down.sh

vulnlab-status:
	@scripts/vulnlab/vulnlab-status.sh

vulnlab-check:
	@python3 scripts/vulnlab/check_live.py --profile "$${PROFILE:-lab}"

vulnlab-test:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python scripts/vulnlab/test_cases.py --profile "$${PROFILE:-lab}"

intel-kev:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python -m aegis.m18_intel sync-kev

intel-sync:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python -m aegis.m18_intel sync-intel

contracts-gate:
	@scripts/ci/contracts-gate.sh

graph-check:
	@scripts/ci/neo4j-smoke.sh

ci-local: contracts-gate graph-check

# --- Python backend (G1.1a) ---------------------------------------------------
# Every target runs through `uv run --frozen`: the lockfile is authoritative, so a target can never
# pass locally on a dependency version CI does not install.

deps:
	@uv sync --frozen

lint:
	@uv run --frozen ruff check .
	@uv run --frozen ruff format --check .
	@uv run --frozen mypy

test:
	@uv run --frozen pytest

codegen:
	@uv run --frozen python scripts/codegen.py

codegen-check:
	@uv run --frozen python scripts/codegen.py --check

migrate:
	@uv run --frozen python -m aegis.migrations

ci-python: deps lint test codegen-check

temporal-live:
	@scripts/temporal/run-live.sh

# G1.5a acceptance evidence: the flow document and the event stream over HTTP (needs AEGIS_TEST_PG_DSN).
demo-g15a:
	@uv run --frozen pytest tests/test_g15a_http_demo.py -q -s

# --- G1 gate: demo, recovery, soak (G1.5c) ------------------------------------
# Each target reads .local/run-local.env, the file `make run-local` writes: the API URL, the two
# dev tokens and the endpoints of PostgreSQL/Neo4j/S3. `make run-local` must be up first.

demo-g1:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python scripts/demo/demo-g1.py

# G1.6a: the discovery chain continues past DNS to the ports/services on the resolved addresses.
demo-discovery:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python scripts/demo/demo-discovery.py


# G1.6b acceptance: the discovery chain plus fingerprintx/httpx, evidence in PostgreSQL and Neo4j.
demo-g16b:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python scripts/demo/demo-g16b.py

demo-g16c:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python scripts/demo/demo-g16c.py

demo-recovery:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python scripts/demo/demo-recovery.py

# --- G1.6 internet profile: broker image and the owner's manual smoke -----------------------
# The broker image is the stdlib-only broker container (`deploy/broker/Containerfile`). The smoke
# is manual: it refuses a domain the owner has not authorized (owner, item 61, 2026-11-25) and runs
# one passive Subfinder job only. `make run-local` builds the image itself; this target is for a
# runner started by hand, or after changing `aegis.m06_runner`.
broker-image:
	@tag=$$(scripts/dev/broker-image.sh); \
		podman tag "$$tag" localhost/aegis-broker:g16; \
		echo "broker image: $$tag (alias localhost/aegis-broker:g16; set AEGIS_M06_BROKER_IMAGE to it)"

internet-smoke:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "usage: make internet-smoke DOMAIN=<domain you own>" >&2; exit 2; fi
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python scripts/internet/smoke.py "$(DOMAIN)"

# The soak runs detached and keeps writing .local/soak/report.{jsonl,txt} until SOAK_HOURS is up
# (default 24) or `make soak-stop`. Starting it twice is refused, not silently duplicated.
soak-start:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		mkdir -p .local/soak; \
		if [ -f .local/soak/soak.pid ] && kill -0 "$$(cat .local/soak/soak.pid)" 2>/dev/null; then \
			echo "soak: already running (pid $$(cat .local/soak/soak.pid)); report .local/soak/report.txt"; \
			exit 0; \
		fi; \
		rm -f .local/soak/stop; \
		nohup uv run --frozen python scripts/demo/soak.py >>.local/soak/soak.log 2>&1 & \
		echo $$! >.local/soak/soak.pid; \
		sleep 2; \
		echo "soak: started (pid $$(cat .local/soak/soak.pid))"; \
		echo "  log    .local/soak/soak.log"; \
		echo "  report .local/soak/report.txt (jsonl history: .local/soak/report.jsonl)"; \
		echo "  stop   make soak-stop"

soak-stop:
	@if [ -f .local/soak/soak.pid ] && kill -0 "$$(cat .local/soak/soak.pid)" 2>/dev/null; then \
		kill "$$(cat .local/soak/soak.pid)"; \
		echo "soak: stopping (the final report is written on exit)"; \
	else \
		echo "soak: not running"; \
	fi
	@touch .local/soak/stop 2>/dev/null || true

# --- Local stack (G1.5a follow-up) --------------------------------------------
# run-local brings up the dev stack, applies migrations, mints a dev operator token and serves the
# API for the UI; stop-local stops only what it started. State lives in .local/ (git-ignored).

run-local:
	@scripts/dev/run-local.sh

stop-local:
	@scripts/dev/stop-local.sh

seed-demo:
	@scripts/dev/seed-demo.py --api-url "$${AEGIS_API_URL:-http://127.0.0.1:8000}" \
		--token "$${AEGIS_DEV_TOKEN:?set AEGIS_DEV_TOKEN to the token make run-local printed}"

# --- G1.6: the live model (owner decision 2026-11-25) --------------------------
# One real provider call with the key from .env (or the environment). Manual only: it sends a
# request the platform pays for, so it is not part of any CI gate. The script validates the live
# settings first (a missing key/price/provider is an error, never a silent 0) and refuses a CI host.
llm-smoke:
	@uv run --frozen python scripts/dev/llm-smoke.py

# --- G1.6: the owner's LLM gateway (deploy/llm-gateway) -----------------------
# The scripts validate the owner's config and keys first, keep the compose project to this checkout
# and never touch another stack. `llm-gateway-test` runs the shipped example shape against two fake
# upstreams - no real provider is called, in CI or locally.
llm-gateway-up:
	@scripts/llm-gateway/up.sh

llm-gateway-down:
	@scripts/llm-gateway/down.sh

llm-gateway-status:
	@scripts/llm-gateway/status.sh

llm-gateway-reload:
	@scripts/llm-gateway/reload.sh

llm-gateway-test:
	@AEGIS_TEST_LLM_GATEWAY=1 uv run --frozen python -m pytest tests/test_llm_gateway_rotation.py -x -q
