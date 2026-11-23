# AEGIS–Vanguard: dev environment (G0.4a) and contract checks (G0.4b).
#
# `make dev-up` brings up the local stack and applies the contract schema;
# `make ci-local` runs exactly what the contracts workflow runs on a PR.
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help dev-up dev-down dev-status dev-logs contracts-gate graph-check ci-local

help:
	@printf '%s\n' \
	  'make dev-up          start PostgreSQL 16, Neo4j 5.26, SeaweedFS (S3) and Temporal;' \
	  '                     apply migrations, graph constraints and the raw bucket' \
	  'make dev-down        remove only the aegis-dev compose project (containers + volumes)' \
	  'make dev-status      health and endpoints of the dev stack (non-zero if not healthy)' \
	  'make dev-logs        follow the dev stack logs' \
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

contracts-gate:
	@scripts/ci/contracts-gate.sh

graph-check:
	@scripts/ci/neo4j-smoke.sh

ci-local: contracts-gate graph-check
