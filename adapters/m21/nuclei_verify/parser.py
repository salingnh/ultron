"""Nuclei JSONL -> `verification-result.v2`, from the exact bytes the pinned template sent.

Nuclei writes one JSON object per (target, path) its always-match template answered, including the
request and response bytes. That file is the evidence; this function is the **one** conversion into
the contract document: M21 imports it when it decides (`aegis.m21_verify.documents`), and the
adapter parser reuses it, so the document M21 reads is built by the same reviewed code that the
conformance suite exercises.

What it takes from the signed task (all server-side, never from the caller):

* `input.targets` - the positive target, a `service:<ip>:<port>/tcp` canonical key;
* `input.controls` - `{role, target}` for the patched twin and the benign endpoint;
* `input.benign_path` - which request of a target is the benign control (the template sends both
  paths to every target, so both are recorded and only one is the control);
* `input.check_pack_sha256`, `input.request_cap` - what the run was pinned to; the document repeats
  them, and M21 compares both with the registry and the signed run.

The benign role shares the positive's address: the control is a path that cannot hold the canary,
not a third host (the reviewed registry says `requests.cap = 2 paths x 2 addresses`). It is emitted
as its own role with only that request, so the oracle can compare it like any other control.

A row whose host is not one of the run's addresses, or two rows for the same (address, path),
raises `ResultBuildError`: a swapped or corrupt output file is a loud failure, never a shorter
result document. An empty file is not an error: it is a run where nothing answered, which M21
decides as INCONCLUSIVE.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ["ResultBuildError", "path_of", "result_document"]

_REQUEST_LINE = re.compile(r"^[A-Z]+ (\S+) HTTP/\d\.\d$")
_STATUS_LINE = re.compile(r"^HTTP/\d\.\d (\d{3})\b")
_CANARY = re.compile(r"AEGIS-CANARY-[0-9a-f]{32}")
_KEY = re.compile(r"^service:(?P<address>.+):(?P<port>\d+)/tcp$")


class ResultBuildError(ValueError):
    """The tool output cannot be turned into the contract's result document."""


def _canonical_key(value: Any, where: str) -> tuple[str, int]:
    if not isinstance(value, str):
        raise ResultBuildError(f"{where} must be a canonical service key")
    match = _KEY.match(value)
    if match is None:
        raise ResultBuildError(f"{where} is not a service:<ip>:<port>/tcp key: {value!r}")
    return match.group("address").strip("[]"), int(match.group("port"))


def _split_response(response: str) -> tuple[int, str]:
    head, _, body = response.partition("\r\n\r\n")
    first = head.split("\r\n", 1)[0]
    match = _STATUS_LINE.match(first)
    if match is None:
        raise ResultBuildError(f"the response line is not HTTP: {first[:80]!r}")
    return int(match.group(1)), body


def path_of(row: Mapping[str, Any]) -> str:
    """The request path exactly as sent (the request line), never a normalised URL.

    `matched-at` is what Nuclei matched, and the catch-all lab server showed it can be shortened;
    the request line is the bytes the template produced, which is what the review pinned.
    """
    request = row.get("request")
    if not isinstance(request, str):
        raise ResultBuildError("a result row has no request bytes")
    first = request.split("\r\n", 1)[0]
    match = _REQUEST_LINE.match(first)
    if match is None:
        raise ResultBuildError(f"the request line is malformed: {first[:80]!r}")
    return match.group(1)


def _rows(content: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ResultBuildError(f"the tool output is not UTF-8: {error}") from error
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ResultBuildError(f"line {number} is not JSON: {error}") from error
        if not isinstance(row, dict):
            raise ResultBuildError(f"line {number} is not an object")
        rows.append(row)
    return rows


def _request_results(
    rows: Sequence[Mapping[str, Any]], address: str, port: int, *, only: str | None = None
) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if str(row.get("host")) != address or int(row.get("port", 0)) != port:
            continue
        path = path_of(row)
        if only is not None and path != only:
            continue
        if path in seen:
            raise ResultBuildError(f"{address}:{port} answered {path} more than once")
        seen.add(path)
        status, body = _split_response(str(row.get("response", "")))
        requests.append(
            {
                "path": path,
                "status": status,
                "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "tokens": [
                    str(token)
                    for token in row.get("extracted-results") or []
                    if isinstance(token, str) and _CANARY.fullmatch(token)
                ],
            }
        )
    return requests


def _target(
    role: str, address: str, port: int, rows: Sequence[Mapping[str, Any]], only: str | None = None
) -> dict[str, Any]:
    requests = _request_results(rows, address, port, only=only)
    return {
        "role": role,
        "address": address,
        "port": port,
        "answered": any(item.get("status") is not None for item in requests),
        "requests": requests,
    }


def result_document(content: bytes, task: Mapping[str, Any]) -> dict[str, Any]:
    """Build the document from the collected JSONL and the signed task (no IO, no clock)."""
    input_block = task.get("input")
    if not isinstance(input_block, Mapping):
        raise ResultBuildError("the task has no input block")
    targets = input_block.get("targets")
    if not isinstance(targets, list) or len(targets) != 1:
        raise ResultBuildError("a verification task names exactly one positive target")
    controls = input_block.get("controls") or []
    if not isinstance(controls, list):
        raise ResultBuildError("the task's controls must be a list")
    benign_path = input_block.get("benign_path")
    if not isinstance(benign_path, str) or not benign_path.startswith("/"):
        raise ResultBuildError("the task must name the benign control's path")

    rows = _rows(content)
    positive_address, positive_port = _canonical_key(targets[0], "input.targets[0]")
    roles: dict[str, tuple[str, int]] = {"positive": (positive_address, positive_port)}
    for control in controls:
        if not isinstance(control, Mapping):
            raise ResultBuildError("a control entry is not an object")
        role = str(control.get("role"))
        if role not in ("patched_twin", "benign"):
            raise ResultBuildError(f"unknown control role {role!r}")
        roles[role] = _canonical_key(control.get("target"), f"input.controls[{role}]")
    if "patched_twin" not in roles:
        raise ResultBuildError("a lab verification run needs the patched twin")
    # The benign role is a path on the positive host unless the task names its own endpoint.
    roles.setdefault("benign", roles["positive"])

    addresses = {address for address, _ in roles.values()}
    for row in rows:
        if str(row.get("host")) not in addresses:
            raise ResultBuildError(
                f"a result row names {row.get('host')}, which is not part of the run"
            )

    document: dict[str, Any] = {
        "schema_version": "2.0",
        "check_id": str(input_block.get("check_id")),
        "check_pack_sha256": str(input_block.get("check_pack_sha256")),
        "tool": {
            "name": "nuclei",
            "version": str(task.get("provider_version")),
            "image_digest": str(task.get("image_digest")),
        },
        "targets": [
            _target("positive", *roles["positive"], rows),
            _target("patched_twin", *roles["patched_twin"], rows),
            # The benign control is a path on the positive host (or its own endpoint): one request.
            _target("benign", *roles["benign"], rows, only=benign_path),
        ],
        "errors": [],
    }
    # The benign entry repeats one request of the positive target; the run counts unique requests.
    unique = {
        (target["address"], target["port"], request["path"])
        for target in document["targets"]
        for request in target["requests"]
    }
    document["requests_sent"] = len(unique)
    document["request_cap"] = int(input_block.get("request_cap", 0))
    return document
