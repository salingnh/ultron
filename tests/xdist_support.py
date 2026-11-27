"""What parallel pytest (pytest-xdist) may not share between its workers.

Everything a test creates is already its own: throwaway databases, containers, networks and
temporary directories carry random or per-process names. Three things on the servers and the host
are not, and are handled here:

* **PostgreSQL cluster roles.** Each test applies the contract chain to its own database, but the
  baseline's `CREATE ROLE IF NOT EXISTS` blocks are cluster-wide and not safe to run concurrently
  on a fresh server. The controller applies the chain once, in a throwaway database, before it
  starts any worker, so every worker finds the roles.
* **Neo4j.** Community Edition has one graph and the M23 tests wipe it. A configured
  `AEGIS_TEST_NEO4J_URI` is one graph, so a parallel run refuses it; each worker that needs a graph
  starts its own container (`tests/graph_support.ensure_test_graph`).
* **Job subnets.** `PodmanRunner` picks a free subnet and then creates the network; two workers can
  pick the same one in between. Each worker allocates from its own slice of the pool.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping

import psycopg

from tests.graph_support import NEO4J_URI_ENV
from tests.pg import DSN_ENV, throwaway_database

WORKER_ENV = "PYTEST_XDIST_WORKER"
#: Test files that `--dist loadgroup` keeps on one worker each. The four sandbox files drive real
#: job containers, and podman slows down under concurrent use: run side by side in two lanes their
#: tests take as long as they do serially, while spread over eight workers they took about three
#: times as long without making the run shorter. The gateway file starts one ~1.3 GB proxy per
#: worker that runs it.
LANES = {
    "test_podman_isolation.py": "sandbox-a",
    "test_l3_job.py": "sandbox-a",
    "test_job_flow.py": "sandbox-b",
    "test_dns_job.py": "sandbox-b",
    "test_llm_gateway_rotation.py": "llm-gateway",
}
#: The default `PodmanRunner.network_pool`, cut into one slice per worker.
JOB_NETWORK_POOL = "10.97.0.0/16"
SLICE_PREFIX = 20
MAX_WORKERS = 2 ** (SLICE_PREFIX - 16)


def worker_network_pool(env: Mapping[str, str] | None = None) -> str:
    """The job subnet pool of this process: the whole pool serially, one slice per xdist worker."""
    worker = (os.environ if env is None else env).get(WORKER_ENV, "")
    if not worker:
        return JOB_NETWORK_POOL
    index = int(worker.removeprefix("gw"))
    slices = list(ipaddress.ip_network(JOB_NETWORK_POOL).subnets(new_prefix=SLICE_PREFIX))
    return str(slices[index])


def prepare_parallel_run(workers: int, env: Mapping[str, str] | None = None) -> None:
    """Run by the xdist controller before the workers exist; raises when they cannot be isolated."""
    source = os.environ if env is None else env
    if workers > MAX_WORKERS:
        raise ValueError(f"at most {MAX_WORKERS} pytest workers: each needs its own job subnets")
    if source.get(NEO4J_URI_ENV, "").strip():
        raise ValueError(
            f"{NEO4J_URI_ENV} is one graph and the tests wipe it: unset it for a parallel run "
            "(each worker then starts its own Neo4j), or run without -n"
        )
    if source.get(DSN_ENV):
        create_cluster_roles()


def create_cluster_roles() -> None:
    from aegis.migrations import apply_contract_migrations

    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        apply_contract_migrations(connection)
