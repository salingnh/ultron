"""M28 evidence store on S3 (SeaweedFS in the dev stack): `put` and `verify` for G1.

The contract (interfaces/README.md §4, §3) fixes the object key: raw output of a job is stored at
`s3://evidence/{campaign_id}/{job_id}/{sha256}`, content addressed, so `put` is idempotent by
SHA-256 and a retry cannot create a second object. The container never reaches this store: the
collector uploads from the control network after the job ended.

G1 needs `put` and `verify` only. `signed_url` and `excerpt` belong to the read API (G1.5a) and
raise `NotImplementedError` instead of returning a wrong answer.

`verify()` answers for the objects this store recorded (its own `put`, or `adopt()` of a row read
from the database): the port signature carries no campaign/job, and the key needs them. A verify of
an unknown id is `False`, not an exception, so a missing object is reported, not masked.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from aegis.common.ports import EvidenceObject, EvidenceStore, Excerpt

EVIDENCE_URI_PREFIX = "s3://evidence"
DEFAULT_REGION = "us-east-1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class S3Config:
    """Where the evidence bucket lives; credentials are optional (dev/lab SeaweedFS is open)."""

    endpoint: str
    bucket: str
    region: str = DEFAULT_REGION
    access_key: str | None = None
    secret_key: str | None = None
    timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> S3Config:
        source = os.environ if env is None else env
        endpoint = source.get("AEGIS_S3_ENDPOINT", "")
        bucket = source.get("AEGIS_S3_BUCKET", "")
        if not endpoint or not bucket:
            raise ValueError(
                "AEGIS_S3_ENDPOINT and AEGIS_S3_BUCKET must be set for the evidence store"
            )
        return cls(
            endpoint=endpoint,
            bucket=bucket,
            region=source.get("AEGIS_S3_REGION", DEFAULT_REGION),
            access_key=source.get("AEGIS_S3_ACCESS_KEY") or None,
            secret_key=source.get("AEGIS_S3_SECRET_KEY") or None,
        )


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def sign_v4(
    config: S3Config,
    method: str,
    path: str,
    *,
    payload: bytes,
    headers: Mapping[str, str],
    amz_date: str,
    host: str,
    query: str = "",
) -> dict[str, str]:
    """SigV4 headers of one request (AWS S3, path-style, `x-amz-content-sha256` signed)."""
    if not config.access_key or not config.secret_key:
        raise ValueError("SigV4 needs both an access key and a secret key")
    date_stamp = amz_date[:8]
    payload_hash = hashlib.sha256(payload).hexdigest()
    signed = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
        **{name.lower(): value for name, value in headers.items()},
    }
    canonical_headers = "".join(
        f"{name}:{' '.join(signed[name].split())}\n" for name in sorted(signed)
    )
    signed_headers = ";".join(sorted(signed))
    canonical_request = "\n".join(
        [method, path, query, canonical_headers, signed_headers, payload_hash]
    )
    scope = f"{date_stamp}/{config.region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    key = _hmac(f"AWS4{config.secret_key}".encode(), date_stamp)
    key = _hmac(key, config.region)
    key = _hmac(key, "s3")
    key = _hmac(key, "aws4_request")
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        **signed,
        "authorization": (
            f"AWS4-HMAC-SHA256 Credential={config.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }


@dataclass
class S3EvidenceClient:
    """Minimal path-style S3 client: PUT/GET/HEAD of one object, optional SigV4."""

    config: S3Config

    def put(self, key: str, data: bytes, *, content_type: str) -> None:
        headers = {"content-type": content_type, "content-length": str(len(data))}
        response = self._request("PUT", key, data=data, headers=headers)
        if response.status not in (200, 201, 204):
            raise EvidenceStoreError(
                "S3_PUT_FAILED", f"HTTP {response.status}: {response.body[:500]!r}"
            )

    def get(self, key: str) -> bytes:
        response = self._request("GET", key)
        if response.status != 200:
            raise EvidenceStoreError(
                "S3_GET_FAILED", f"HTTP {response.status}: {response.body[:500]!r}"
            )
        return response.body

    def head(self, key: str) -> int | None:
        """Object size, or None when the object is absent."""
        response = self._request("HEAD", key)
        if response.status == 404:
            return None
        if response.status != 200:
            raise EvidenceStoreError("S3_HEAD_FAILED", f"HTTP {response.status}")
        size = response.headers.get("content-length")
        return int(size) if size is not None else 0

    def _request(
        self,
        method: str,
        key: str,
        *,
        data: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> _Response:
        parts = urlsplit(self.config.endpoint)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise EvidenceStoreError("S3_CONFIG_INVALID", f"bad endpoint {self.config.endpoint!r}")
        path = f"/{self.config.bucket}/{key.lstrip('/')}"
        send_headers = dict(headers or {})
        host = parts.hostname if parts.port is None else f"{parts.hostname}:{parts.port}"
        if self.config.access_key and self.config.secret_key:
            amz_date = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            signed = sign_v4(
                self.config,
                method,
                path,
                payload=data,
                headers=send_headers,
                amz_date=amz_date,
                host=host,
            )
            send_headers = {**send_headers, **{name: value for name, value in signed.items()}}
            send_headers["Authorization"] = send_headers.pop("authorization")
            send_headers.pop("host", None)
        connection = (
            http.client.HTTPSConnection(host, timeout=self.config.timeout_seconds)
            if parts.scheme == "https"
            else http.client.HTTPConnection(host, timeout=self.config.timeout_seconds)
        )
        try:
            connection.request(method, path, body=data if data else None, headers=send_headers)
            response = connection.getresponse()
            body = response.read()
            return _Response(response.status, dict(response.getheaders()), body)
        finally:
            connection.close()


@dataclass(frozen=True)
class _Response:
    status: int
    headers: dict[str, str]
    body: bytes


class EvidenceStoreError(RuntimeError):
    """The evidence store could not store or read an object; carries a stable code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass
class S3EvidenceStore(EvidenceStore):
    """`EvidenceStore` port over S3; `put` is idempotent by SHA-256 of the file content."""

    client: S3EvidenceClient
    _objects: dict[str, EvidenceObject] = field(default_factory=dict, init=False)
    _verified: dict[str, bool] = field(default_factory=dict, init=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> S3EvidenceStore:
        return cls(S3EvidenceClient(S3Config.from_env(env)))

    def put(
        self,
        campaign_id: str,
        job_id: str,
        path: Path,
        media_type: str,
        classification: object,
    ) -> EvidenceObject:
        content = path.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        existing = self._objects.get(sha256)
        if existing is not None:
            return existing
        key = self.key(campaign_id, job_id, sha256)
        try:
            self.client.put(key, content, content_type=media_type)
        except EvidenceStoreError as error:
            raise EvidenceStoreError(
                "EVIDENCE_INCOMPLETE",
                f"upload of {path.name} ({sha256}) failed: {error}",
            ) from error
        evidence = EvidenceObject(
            evidence_id=sha256,
            campaign_id=campaign_id,
            job_id=job_id,
            sha256=sha256,
            uri=f"{EVIDENCE_URI_PREFIX}/{campaign_id}/{job_id}/{sha256}",
            media_type=media_type,
            classification=classification,  # type: ignore[arg-type]
        )
        self._objects[sha256] = evidence
        return evidence

    def adopt(self, evidence: EvidenceObject) -> None:
        """Register an evidence row read from the database so `verify()` can check it again."""
        self._objects[evidence.sha256] = evidence

    def verify(self, evidence_id: str) -> bool:
        """Read the object back and compare its SHA-256 with the id (content addressed)."""
        evidence = self._objects.get(evidence_id)
        if evidence is None:
            return False
        key = self.key(evidence.campaign_id, evidence.job_id, evidence.sha256)
        try:
            size = self.client.head(key)
            if size is None:
                self._verified[evidence_id] = False
                return False
            content = self.client.get(key)
        except EvidenceStoreError:
            self._verified[evidence_id] = False
            return False
        matched = hashlib.sha256(content).hexdigest() == evidence.sha256
        self._verified[evidence_id] = matched
        return matched

    def signed_url(self, evidence_id: str, ttl_seconds: int = 300) -> str:
        raise NotImplementedError(
            "G1 stores and verifies evidence only; presigned URLs belong to the read API (G1.5a)"
        )

    def excerpt(self, evidence_id: str, offset: int, max_bytes: int) -> Excerpt:
        raise NotImplementedError(
            "G1 stores and verifies evidence only; excerpts belong to the read API (G1.5a)"
        )

    @staticmethod
    def key(campaign_id: str, job_id: str, sha256: str) -> str:
        """The contract object key under the bucket (`s3://evidence/{campaign}/{job}/{sha256}`)."""
        return f"{campaign_id}/{job_id}/{sha256}"


__all__ = [
    "EVIDENCE_URI_PREFIX",
    "EvidenceStoreError",
    "S3Config",
    "S3EvidenceClient",
    "S3EvidenceStore",
    "sign_v4",
]
