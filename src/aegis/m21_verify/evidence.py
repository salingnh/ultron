"""Reading the stored result document of a verification job (M21's only IO besides the database).

Evidence bytes live in the deployment's object store (`s3://evidence/<campaign>/<job>/<sha256>`),
uploaded by M06 from the container's output directory and verified there. M21 reads the object
back, checks that its sha256 is the one the `evidence` row promises, and only then parses it - a
swapped object is a loud failure, never a different decision.

The provider decides how its output becomes the contract document:

* `nuclei-verify` writes Nuclei JSONL; `adapters/m21/nuclei_verify/parser.py:result_document`
  converts it (the same function the adapter parser uses);
* `config-verify` (slice S4) writes the document itself as `result.json`.

The reader is injectable so tests (and the demo) can run without an object store; production reads
`AEGIS_S3_ENDPOINT`/`AEGIS_S3_BUCKET` like every other evidence consumer.
"""

from __future__ import annotations

import hashlib
import importlib
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from aegis.m21_verify.result import ResultDocument, ResultError, validate_result

__all__ = [
    "DOCUMENT_READERS",
    "EvidenceReader",
    "EvidenceRow",
    "MemoryEvidenceReader",
    "S3EvidenceReader",
    "document_for",
    "pick_evidence",
    "read_document",
]

#: provider -> (module, function, media type of the file that holds the result). The function has
#: the adapter-parser signature `(content: bytes, task: Mapping) -> dict` and returns the contract
#: document; M21 validates it either way.
DOCUMENT_READERS: dict[str, tuple[str, str, str]] = {
    "nuclei-verify": (
        "adapters.m21.nuclei_verify.parser",
        "result_document",
        "application/x-ndjson",
    ),
}

MEDIA_TYPES = {provider: media for provider, (_, _, media) in DOCUMENT_READERS.items()}


class EvidenceError(RuntimeError):
    """The result document cannot be read (missing object, hash mismatch, unknown provider)."""


class EvidenceReader(Protocol):
    """Read one stored evidence object by its URI, verifying the content hash."""

    def read(self, uri: str, sha256: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class EvidenceRow:
    """The columns of `aegis.evidence` M21 needs."""

    evidence_id: str
    uri: str
    sha256: str
    media_type: str
    size_bytes: int


class S3EvidenceReader:
    """The production reader: the same SeaweedFS bucket M06 uploaded to."""

    def __init__(self, client: Any) -> None:
        self._client = client

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> S3EvidenceReader:
        from aegis.m28_evidence.store import S3Config, S3EvidenceClient

        return cls(S3EvidenceClient(S3Config.from_env(env)))

    def read(self, uri: str, sha256: str) -> bytes:
        prefix = "s3://evidence/"
        if not uri.startswith(prefix):
            raise EvidenceError(f"evidence URI {uri!r} is not an s3://evidence object")
        key = uri[len(prefix) :]
        try:
            content: bytes = self._client.get(key)
        except Exception as error:  # noqa: BLE001 - any store failure is one loud error here
            raise EvidenceError(f"cannot read {uri}: {error}") from error
        actual = hashlib.sha256(content).hexdigest()
        if actual != sha256:
            raise EvidenceError(f"{uri} has sha256 {actual}, the evidence row says {sha256}")
        return content


class MemoryEvidenceReader:
    """A reader over bytes already in memory (tests, the demo, a replay of recorded captures)."""

    def __init__(self, objects: Mapping[str, bytes]) -> None:
        self._objects = dict(objects)

    def read(self, uri: str, sha256: str) -> bytes:
        try:
            content = self._objects[uri]
        except KeyError as error:
            raise EvidenceError(f"no in-memory evidence object {uri!r}") from error
        actual = hashlib.sha256(content).hexdigest()
        if actual != sha256:
            raise EvidenceError(f"{uri} has sha256 {actual}, the evidence row says {sha256}")
        return content


def document_for(provider: str, content: bytes, task: Mapping[str, Any]) -> ResultDocument:
    """Turn the evidence bytes of `provider` into a validated result document."""
    entry = DOCUMENT_READERS.get(provider)
    if entry is None:
        raise EvidenceError(f"provider {provider!r} has no result document reader")
    module_name, function_name, _ = entry
    module = importlib.import_module(module_name)
    function: Callable[[bytes, Mapping[str, Any]], Any] = getattr(module, function_name)
    try:
        document = function(content, task)
    except ValueError as error:
        raise EvidenceError(f"{provider}: {error}") from error
    try:
        return validate_result(document)
    except ResultError as error:
        raise EvidenceError(f"{provider}: {error}") from error


def pick_evidence(rows: Sequence[EvidenceRow], provider: str) -> EvidenceRow:
    """The one evidence object that holds the run's result document."""
    media = MEDIA_TYPES.get(provider)
    if media is None:
        raise EvidenceError(f"provider {provider!r} has no known result media type")
    matching = [row for row in rows if row.media_type == media]
    if not matching:
        raise EvidenceError(f"job evidence has no {media} file; the result document is missing")
    if len(matching) > 1:
        raise EvidenceError(
            f"job evidence has {len(matching)} {media} files; the result document is ambiguous"
        )
    return matching[0]


def read_document(
    reader: EvidenceReader,
    evidence: EvidenceRow,
    *,
    provider: str,
    task: Mapping[str, Any],
) -> ResultDocument:
    """Read the stored object and build the document (hash checked before parsing)."""
    content = reader.read(evidence.uri, evidence.sha256)
    return document_for(provider, content, task)


def evidence_from_row(row: Mapping[str, Any]) -> EvidenceRow:
    return EvidenceRow(
        evidence_id=str(row["evidence_id"]),
        uri=str(row["storage_uri"]),
        sha256=str(row["sha256"]),
        media_type=str(row["media_type"]),
        size_bytes=int(row["size_bytes"]),
    )


def reader_from_env(env: Mapping[str, str] | None = None) -> EvidenceReader:
    """The deployment's reader; an explicit in-memory map is for tests only."""
    del env
    if not os.environ.get("AEGIS_S3_ENDPOINT"):
        raise EvidenceError(
            "the verification decision needs the evidence store (AEGIS_S3_ENDPOINT, "
            "AEGIS_S3_BUCKET)"
        )
    return S3EvidenceReader.from_env()
