"""The isolation rules of a parallel (pytest-xdist) run: `tests/xdist_support.py`."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from tests import xdist_support
from tests.graph_support import NEO4J_URI_ENV


def test_a_serial_run_uses_the_whole_job_pool() -> None:
    assert xdist_support.worker_network_pool({}) == "10.97.0.0/16"


def test_every_worker_gets_job_subnets_no_other_worker_can_pick() -> None:
    pools = [
        ipaddress.IPv4Network(
            xdist_support.worker_network_pool({xdist_support.WORKER_ENV: f"gw{index}"})
        )
        for index in range(xdist_support.MAX_WORKERS)
    ]
    assert all(pool.subnet_of(ipaddress.IPv4Network("10.97.0.0/16")) for pool in pools)
    assert not any(a.overlaps(b) for i, a in enumerate(pools) for b in pools[i + 1 :])


def test_every_lane_names_an_existing_test_file() -> None:
    # A renamed file would silently leave its lane and run beside the other sandbox tests.
    missing = [name for name in xdist_support.LANES if not (Path(__file__).parent / name).is_file()]
    assert missing == []


def test_a_parallel_run_refuses_one_shared_graph() -> None:
    with pytest.raises(ValueError, match=NEO4J_URI_ENV):
        xdist_support.prepare_parallel_run(2, {NEO4J_URI_ENV: "bolt://127.0.0.1:7687"})


def test_a_parallel_run_refuses_more_workers_than_subnet_slices() -> None:
    with pytest.raises(ValueError, match="at most"):
        xdist_support.prepare_parallel_run(xdist_support.MAX_WORKERS + 1, {})
