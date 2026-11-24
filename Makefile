# AEGIS–Vanguard: dev environment (G0.4a), contract checks (G0.4b) and authorized lab (G0.4c).
#
# `make dev-up` brings up the local stack and applies the contract schema;
# `make lab-up` brings up the authorized DNS lab; `make ci-local` runs exactly what the
# contracts workflow runs on a PR.
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help dev-up dev-down dev-status dev-logs contracts-gate graph-check ci-local \
	lab-up lab-down lab-status lab-check lab-dnsx lab-subfinder

help:
	@printf '%s\n' \
	  'make dev-up          start PostgreSQL 16, Neo4j 5.26, SeaweedFS (S3) and Temporal;' \
	  '                     apply migrations, graph constraints and the raw bucket' \
	  'make dev-down        remove only the aegis-dev compose project (containers + volumes)' \
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
	  'make ci-local        contracts-gate + graph-check'

dev-up:
	@scripts/dev/dev-up.sh

dev-down:
	@scripts/dev/dev-down.sh

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
