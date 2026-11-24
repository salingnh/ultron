"""Evidence upload against the real object store (SeaweedFS, the dev/lab S3).

The store class is exercised against a stand-in S3 in `test_evidence_store.py`; this test proves the
same `put`/`verify` against the product's S3 server, started as a throwaway container owned by this
test (removed in `finally`). It runs only where Podman is available, like the sandbox suite.
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from aegis.contracts_gen.common.ids_v2_schema import Classification
from aegis.m28_evidence.store import S3Config, S3EvidenceClient, S3EvidenceStore

from . import m06_support

pytestmark = [pytest.mark.podman]
if not m06_support.podman_available():
    pytestmark.append(pytest.mark.skip(reason="rootless podman is not installed on this host"))

BUCKET = "aegis-evidence-test"


@pytest.fixture(scope="module")
def seaweedfs() -> Iterator[str]:
    m06_support.require_podman()
    name = f"aegis-g13a-s3-{uuid.uuid4().hex[:6]}"
    m06_support.podman(
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        "aegis.test=g13a",
        "--publish",
        "127.0.0.1::8333",
        m06_support.SEAWEEDFS,
        "mini",
        "-dir=/data",
    )
    try:
        deadline = time.monotonic() + 60
        port = ""
        while time.monotonic() < deadline:
            published = m06_support.podman("port", name, "8333/tcp", check=False).stdout.strip()
            if published:
                port = published.rsplit(":", 1)[-1]
                probe = subprocess.run(
                    ["curl", "-fsS", "-o", "/dev/null", f"http://127.0.0.1:{port}/"],
                    capture_output=True,
                    text=True,
                )
                if probe.returncode == 0:
                    break
            time.sleep(0.5)
        assert port, "SeaweedFS never published its S3 port"
        endpoint = f"http://127.0.0.1:{port}"
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
        m06_support.podman("rm", "-f", name, check=False)


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
