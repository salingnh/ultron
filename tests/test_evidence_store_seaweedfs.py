"""Evidence upload against the real object store (SeaweedFS, the dev/lab S3).

The store class is exercised against a stand-in S3 in `test_evidence_store.py`; this test proves the
same `put`/`verify` against the product's S3 server, started as a throwaway container owned by this
test (removed in `finally`). It runs only where Podman is available, like the sandbox suite.
"""

from __future__ import annotations

import http.client
import json
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from aegis.contracts_gen.common.ids_v2_schema import Classification
from aegis.m28_evidence.store import S3Config, S3EvidenceClient, S3EvidenceStore

from . import m06_support

pytestmark = [pytest.mark.podman]
if not m06_support.podman_available():
    pytestmark.append(pytest.mark.skip(reason="rootless podman is not installed on this host"))

BUCKET = "aegis-evidence-test"


def _http_status(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=2.0) as response:
            return response.status, response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, http.client.HTTPException, OSError):
        return 0, b""


def _seaweedfs_ready(ports: dict[str, str]) -> tuple[bool, str]:
    s3_status, _ = _http_status(f"http://127.0.0.1:{ports['8333/tcp']}/readyz")
    if s3_status != 200:
        return False, f"s3 /readyz returned {s3_status}"
    filer_status, _ = _http_status(f"http://127.0.0.1:{ports['8888/tcp']}/healthz")
    if filer_status != 200:
        return False, f"filer /healthz returned {filer_status}"
    vol_status, _ = _http_status(f"http://127.0.0.1:{ports['9340/tcp']}/healthz")
    if vol_status != 200:
        return False, f"volume /healthz returned {vol_status}"
    master_status, _ = _http_status(f"http://127.0.0.1:{ports['9333/tcp']}/cluster/healthz")
    if master_status != 200:
        return False, f"master /cluster/healthz returned {master_status}"
    cluster_code, cluster_body = _http_status(
        f"http://127.0.0.1:{ports['9333/tcp']}/cluster/status"
    )
    if cluster_code != 200:
        return False, f"master /cluster/status returned {cluster_code}"
    try:
        cluster: dict[str, Any] = json.loads(cluster_body)
    except ValueError:
        return False, f"invalid /cluster/status json: {cluster_body[:200]!r}"
    if not cluster.get("IsLeader"):
        return False, f"master has no leader yet: {cluster}"
    dir_code, dir_body = _http_status(f"http://127.0.0.1:{ports['9333/tcp']}/dir/status")
    if dir_code != 200:
        return False, f"master /dir/status returned {dir_code}"
    try:
        topology: dict[str, Any] = json.loads(dir_body).get("Topology") or {}
    except ValueError:
        return False, f"invalid /dir/status json: {dir_body[:200]!r}"
    datanodes = [
        node
        for dc in topology.get("DataCenters") or ()
        for rack in dc.get("Racks") or ()
        for node in rack.get("DataNodes") or ()
    ]
    if not datanodes or int(topology.get("Free") or 0) < 1:
        return False, f"volume server has no registered free capacity: {topology}"
    vol_info_code, vol_info_body = _http_status(f"http://127.0.0.1:{ports['9340/tcp']}/status")
    if vol_info_code != 200:
        return False, f"volume /status returned {vol_info_code}"
    try:
        disks: list[dict[str, Any]] = json.loads(vol_info_body).get("DiskStatuses") or []
    except ValueError:
        return False, f"invalid volume /status json: {vol_info_body[:200]!r}"
    if not disks or int(disks[0].get("free") or 0) <= 0:
        return False, f"volume server reports zero free bytes: {disks}"
    return True, "ready"


@pytest.fixture(scope="module")
def seaweedfs() -> Iterator[str]:
    m06_support.require_podman()
    name = f"aegis-g13a-s3-{uuid.uuid4().hex[:6]}"
    try:
        m06_support.podman(
            "run",
            "--detach",
            "--rm",
            "--name",
            name,
            "--label",
            "aegis.test=g13a",
            "--tmpfs",
            "/data:rw,size=128m,mode=1777",
            "--publish",
            "127.0.0.1::8333",
            "--publish",
            "127.0.0.1::8888",
            "--publish",
            "127.0.0.1::9333",
            "--publish",
            "127.0.0.1::9340",
            m06_support.SEAWEEDFS,
            "mini",
            "-dir=/data",
            "-master.volumeSizeLimitMB=16",
            "-master.telemetry=false",
        )
        deadline = time.monotonic() + 60
        ports: dict[str, str] = {}
        last_reason = "ports not published"
        container_ports = ("8333/tcp", "8888/tcp", "9333/tcp", "9340/tcp")
        while time.monotonic() < deadline:
            resolved: dict[str, str] = {}
            for container_port in container_ports:
                published = m06_support.podman(
                    "port", name, container_port, check=False
                ).stdout.strip()
                if not published:
                    break
                resolved[container_port] = published.rsplit(":", 1)[-1]
            if len(resolved) == len(container_ports):
                ready, last_reason = _seaweedfs_ready(resolved)
                if ready:
                    ports = resolved
                    break
            time.sleep(0.25)
        if not ports:
            logs = m06_support.podman("logs", name, check=False).stdout[-2000:]
            raise AssertionError(f"SeaweedFS never became ready ({last_reason}):\n{logs}")
        endpoint = f"http://127.0.0.1:{ports['8333/tcp']}"
        created = subprocess.run(
            [
                "curl",
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-X",
                "PUT",
                f"{endpoint}/{BUCKET}",
            ],
            capture_output=True,
            text=True,
        )
        assert created.stdout.strip() in {"200", "409"}, created.stdout
        yield endpoint
    finally:
        m06_support.remove_container(name)


def test_put_and_verify_round_trip_on_the_real_store(seaweedfs: str, tmp_path: Path) -> None:
    store = S3EvidenceStore(S3EvidenceClient(S3Config(endpoint=seaweedfs, bucket=BUCKET)))
    campaign = "01934f6a-0000-7000-8000-000000000001"
    job = "01934f6a-0000-7000-8000-00000000d001"
    output = tmp_path / "result.jsonl"
    output.write_text(json.dumps({"host": "a.internal.example"}) + "\n", encoding="utf-8")

    stored = store.put(campaign, job, output, "application/x-ndjson", Classification.INTERNAL)
    assert stored.uri == f"s3://evidence/{campaign}/{job}/{stored.sha256}"
    assert store.verify(stored.evidence_id) is True

    # Overwrite the object with different bytes: verify must report the mismatch, not pass.
    key = f"{campaign}/{job}/{stored.sha256}"
    store.client.put(key, b"tampered", content_type="text/plain")
    assert store.verify(stored.evidence_id) is False
