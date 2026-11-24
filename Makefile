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
	lab-up lab-down lab-status lab-check lab-dnsx lab-subfinder \
	deps lint test codegen codegen-check migrate ci-python \
	temporal-live demo-g15a demo-g1 demo-recovery soak-start soak-stop \
	run-local stop-local seed-demo

help:
	@printf '%s\n' \
	  'make dev-up          start PostgreSQL 16, Neo4j 5.26, SeaweedFS (S3) and Temporal;' \
	  '                     apply migrations, graph constraints and the raw bucket' \
	  'make dev-down        remove only the aegis-dev compose project (containers + volumes)' \
	  'make dev-reset       dev-down then dev-up: a database from the replaced migration chain is' \
	  '                     reset (the contract schema has one baseline migration)' \
	  'make dev-status      health and endpoints of the dev stack (non-zero if not healthy)' \
	  'make dev-logs        follow the dev stack logs' \
	  'make lab-up          start the authorized lab: lab zone DNS + local passive-source stub' \
	  '                     on an internal network (aegis-lab, no published ports)' \
	  'make lab-down        remove only the aegis-lab compose project and the throwaway lab CA' \
	  'make lab-status      lab health and boundary (non-zero if not healthy)' \
	  'make lab-check       inventory consistency + Subfinder and DNSx runs compared to fixtures' \
	  'make lab-dnsx        only the DNSx run and its fixture comparison' \
	  'make lab-subfinder   only the Subfinder run and its fixture comparison' \
	  'make contracts-gate  README contract gate: validator, tests, PostgreSQL 16 chains' \
	  'make graph-check     Neo4j Cypher smoke (CI: neo4j step)' \
	  'make ci-local        contracts-gate + graph-check' \
	  'make deps            create/refresh the locked Python 3.12 environment (uv sync --frozen)' \
	  'make lint            ruff check + ruff format --check + mypy over src/tests/adapters' \
	  'make test            pytest (database tests run when AEGIS_TEST_PG_DSN is set)' \
	  'make codegen         regenerate src/aegis/contracts_gen from contracts/' \
	  'make codegen-check   fail if the committed DTOs differ from a fresh generation' \
	  'make migrate         apply contracts/db/postgres in contracts/README.md order' \
	  '                     (needs $$AEGIS_PG_DSN; recovery after an interrupted run:' \
	  '                     python -m aegis.migrations mark-applied VERSION --sha256 SHA)' \
	  'make ci-python       the python workflow: deps + lint + test + codegen-check' \
	  'make demo-g1         end-to-end G1 gate on the lab: campaign -> agent/MCP -> Subfinder ->' \
	  '                     DNSx -> raw + metadata + graph + events, with the evidence printed' \
	  'make demo-recovery   SIGKILL the runner mid-job and show it resumes with no duplicate' \
	  'make soak-start      start the shortened 24 h soak (SOAK_HOURS=... to change) in .local/soak/' \
	  'make soak-stop       stop the soak; its report stays in .local/soak/report.txt'

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

lab-dnsx:
	@scripts/lab/dnsx-run.sh

lab-subfinder:
	@scripts/lab/subfinder-run.sh

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

demo-recovery:
	@set -a; [ -f .local/run-local.env ] && . .local/run-local.env; set +a; \
		uv run --frozen python scripts/demo/demo-recovery.py

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
