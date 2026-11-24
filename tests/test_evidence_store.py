"""M28 evidence store: content-addressed `put`, read-back `verify`, SigV4 signing.

The S3 endpoint is a thread in this process, so the test asserts the actual HTTP the store sends
(path-style key, content type, signature) and that `verify` re-reads the object. The expected
signature is a known-answer vector produced by botocore 1.42.24 for the exact same request
(`S3SigV4Auth`, `us-east-1`, date shown in the test), so the signer is checked against a second
implementation rather than against itself.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aegis.contracts_gen.common.ids_v2_schema import Classification
from aegis.m28_evidence.store import (
    S3Config,
    S3EvidenceClient,
    S3EvidenceStore,
    sign_v4,
)

CAMPAIGN = "01934f6a-0000-7000-8000-000000000001"
JOB = "01934f6a-0000-7000-8000-00000000d001"


@dataclass
class FakeS3:
    objects: dict[str, bytes] = field(default_factory=dict)
    requests: list[dict[str, Any]] = field(default_factory=list)
    bucket: str = "aegis"
    _server: ThreadingHTTPServer | None = None

    def start(self) -> FakeS3:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_PUT(self) -> None:  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                fake.requests.append(
                    {"method": "PUT", "path": self.path, "headers": dict(self.headers.items())}
                )
                if not self.path.startswith(f"/{fake.bucket}/"):
                    self.send_error(404)
                    return
                fake.objects[self.path] = body
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                fake.requests.append({"method": "GET", "path": self.path, "headers": {}})
                body = fake.objects.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_HEAD(self) -> None:  # noqa: N802 - http.server API
                fake.requests.append({"method": "HEAD", "path": self.path, "headers": {}})
                body = fake.objects.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    @property
    def endpoint(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address[:2]
        return f"http://{str(host)}:{int(port)}"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


@pytest.fixture()
def fake_s3() -> Any:
    server = FakeS3().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture()
def store(fake_s3: FakeS3) -> S3EvidenceStore:
    config = S3Config(endpoint=fake_s3.endpoint, bucket=fake_s3.bucket)
    return S3EvidenceStore(S3EvidenceClient(config))


def _output(tmp_path: Path, name: str = "result.jsonl", content: bytes = b'{"host":"a"}\n') -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def test_put_is_content_addressed_and_idempotent(
    store: S3EvidenceStore, fake_s3: FakeS3, tmp_path: Path
) -> None:
    path = _output(tmp_path)
    first = store.put(CAMPAIGN, JOB, path, "application/x-ndjson", Classification.INTERNAL)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    # The object *key* is content addressed; the object *id* is scoped to its campaign and job, so
    # two jobs with identical bytes are two objects (see the regression test below).
    assert first.sha256 == sha
    assert first.evidence_id != sha
    assert first.uri == f"s3://evidence/{CAMPAIGN}/{JOB}/{sha}"
    assert first.classification == Classification.INTERNAL
    assert f"/aegis/{CAMPAIGN}/{JOB}/{sha}" in fake_s3.objects

    second = store.put(CAMPAIGN, JOB, path, "application/x-ndjson", Classification.INTERNAL)
    assert second == first
    assert [request["method"] for request in fake_s3.requests].count("PUT") == 1


def test_two_jobs_with_identical_bytes_are_two_objects(
    store: S3EvidenceStore, fake_s3: FakeS3, tmp_path: Path
) -> None:
    """Regression (G1.5c): keying the store by SHA-256 alone made the second job claim the first
    job's object - no upload, no `evidence` row for the second job, and M27 quarantined every
    observation it referenced (G3 `evidence_reference_not_stored`)."""
    content = b'{"host":"www.lab.aegis.test"}\n'
    first = store.put(
        CAMPAIGN, JOB, _output(tmp_path, content=content), "text/plain", Classification.PUBLIC
    )
    second = store.put(
        CAMPAIGN,
        "01a20c00-0000-7000-8000-000000000002",
        _output(tmp_path, content=content),
        "text/plain",
        Classification.PUBLIC,
    )
    assert first.sha256 == second.sha256
    assert first.evidence_id != second.evidence_id
    assert first.uri != second.uri
    assert store.verify(first.evidence_id) is True
    assert store.verify(second.evidence_id) is True
    assert [request["method"] for request in fake_s3.requests].count("PUT") == 2


def test_put_sends_the_media_type(store: S3EvidenceStore, fake_s3: FakeS3, tmp_path: Path) -> None:
    store.put(CAMPAIGN, JOB, _output(tmp_path), "application/x-ndjson", Classification.INTERNAL)
    put_request = next(request for request in fake_s3.requests if request["method"] == "PUT")
    headers = {name.lower(): value for name, value in put_request["headers"].items()}
    assert headers["content-type"] == "application/x-ndjson"


def test_verify_reads_the_object_back(
    store: S3EvidenceStore, fake_s3: FakeS3, tmp_path: Path
) -> None:
    stored = store.put(CAMPAIGN, JOB, _output(tmp_path), "text/plain", Classification.PUBLIC)
    assert store.verify(stored.evidence_id) is True
    assert [request["method"] for request in fake_s3.requests] == ["PUT", "HEAD", "GET"]


def test_verify_detects_tampered_bytes(
    store: S3EvidenceStore, fake_s3: FakeS3, tmp_path: Path
) -> None:
    stored = store.put(CAMPAIGN, JOB, _output(tmp_path), "text/plain", Classification.PUBLIC)
    key = f"/aegis/{CAMPAIGN}/{JOB}/{stored.sha256}"
    fake_s3.objects[key] = b"tampered"
    assert store.verify(stored.evidence_id) is False


def test_verify_of_a_gone_object_is_false(
    store: S3EvidenceStore, fake_s3: FakeS3, tmp_path: Path
) -> None:
    stored = store.put(CAMPAIGN, JOB, _output(tmp_path), "text/plain", Classification.PUBLIC)
    fake_s3.objects.clear()
    assert store.verify(stored.evidence_id) is False


def test_verify_of_an_unknown_id_is_false(store: S3EvidenceStore) -> None:
    assert store.verify("0" * 64) is False


def test_adopt_lets_a_reloaded_row_be_verified(
    store: S3EvidenceStore, fake_s3: FakeS3, tmp_path: Path
) -> None:
    path = _output(tmp_path)
    stored = store.put(CAMPAIGN, JOB, path, "text/plain", Classification.PUBLIC)
    reloaded = S3EvidenceStore(
        S3EvidenceClient(S3Config(endpoint=fake_s3.endpoint, bucket="aegis"))
    )
    assert reloaded.verify(stored.evidence_id) is False
    reloaded.adopt(stored)
    assert reloaded.verify(stored.evidence_id) is True


def test_read_api_methods_are_not_implemented_in_g1(store: S3EvidenceStore) -> None:
    with pytest.raises(NotImplementedError):
        store.signed_url("0" * 64)
    with pytest.raises(NotImplementedError):
        store.excerpt("0" * 64, 0, 16)


def test_uri_matches_the_envelope_evidence_pattern(
    store: S3EvidenceStore, fake_s3: FakeS3, tmp_path: Path
) -> None:
    import re

    stored = store.put(CAMPAIGN, JOB, _output(tmp_path), "text/plain", Classification.PUBLIC)
    assert re.fullmatch(r"s3://evidence/[0-9a-f-]{36}/[0-9a-f-]{36}/[0-9a-f]{64}", stored.uri)


def test_signed_request_carries_a_sigv4_authorization(fake_s3: FakeS3, tmp_path: Path) -> None:
    config = S3Config(
        endpoint=fake_s3.endpoint, bucket="aegis", access_key="AKIDEXAMPLE", secret_key="SECRET"
    )
    store = S3EvidenceStore(S3EvidenceClient(config))
    stored = store.put(CAMPAIGN, JOB, _output(tmp_path), "text/plain", Classification.PUBLIC)
    put_request = next(request for request in fake_s3.requests if request["method"] == "PUT")
    headers = {name.lower(): value for name, value in put_request["headers"].items()}
    authorization = headers["authorization"]
    assert authorization.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    assert "SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date" in (
        authorization
    )
    assert store.verify(stored.evidence_id) is True


def test_sigv4_known_answer_vector() -> None:
    # Known-answer vector generated with botocore 1.42.24 (`S3SigV4Auth`, region us-east-1) for
    # this exact request; the signature below is botocore's output, not this module's.
    config = S3Config(
        endpoint="http://127.0.0.1:18333",
        bucket="aegis",
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="SECRET",
    )
    key = f"aegis/{CAMPAIGN}/{JOB}/" + "a" * 64
    payload = b'{"a":1}'
    headers = sign_v4(
        config,
        "PUT",
        f"/{key}",
        payload=payload,
        headers={
            "content-type": "application/json",
            "content-length": str(len(payload)),
        },
        amz_date="20261124T012640Z",
        host="127.0.0.1:18333",
    )
    assert headers["authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261124/us-east-1/s3/aws4_request, "
        "SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date, "
        "Signature=54dff9329f205058b0638a5085306dab01175523986cb191ac97bec3f8e4545d"
    )
    assert headers["x-amz-content-sha256"] == hashlib.sha256(payload).hexdigest()


def test_config_from_env_requires_endpoint_and_bucket() -> None:
    with pytest.raises(ValueError):
        S3Config.from_env({})
    config = S3Config.from_env(
        {"AEGIS_S3_ENDPOINT": "http://127.0.0.1:18333", "AEGIS_S3_BUCKET": "aegis"}
    )
    assert config.region == "us-east-1"
    assert config.access_key is None
    assert json.dumps({"bucket": config.bucket})
