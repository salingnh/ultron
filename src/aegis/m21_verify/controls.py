"""The lab control map M21 holds server-side: canary hashes, paths and the twin/benign endpoints.

The canary content never enters a request, a template or a job input. The deployment creates the
canary file, mounts it read-only into the lab targets of a check, and records **its sha256** here;
the provider extracts candidate tokens from the responses and M21 compares their hashes with this
file. A server that echoes a canary-shaped value of its own cannot pass: its hash is not this one.

Shape (`deploy/lab/verify-controls.json`, deployment data, not a contract):

    {
      "canary": {"content_sha256": "<64 hex>", "name_sha256": "<64 hex>"},
      "checks": {
        "cve-2021-41773-traversal": {
          "canaryPath": "/static/.%2e/.%2e/srv/canary/canary.txt",
          "benignPath": "/static/.%2e/.%2e/srv/canary/absent.txt",
          "targets": {
            "patched_twin": {"address": "10.114.60.32", "port": 80},
            "benign": {"address": "10.114.60.31", "port": 80}
          }
        }
      }
    }

`benign` is the *endpoint* the benign role runs against. For the httpd traversal check it is the
same address as the positive (the benign control is a path that cannot hold the canary), which is
why the role map is by name and not by address. The file is read once per process and validated
strictly: an address must be an IP literal (a name would add a resolution step M21 cannot check),
and every L1 check in the contract registry must have an entry, or the deployment cannot decide it.

The lab pairing test (`tests/test_verification_pack.py`) keeps this file and the reviewed Nuclei
template in step: the template's two paths must be `canaryPath` and `benignPath`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from aegis.common.repo import repository_root
from aegis.common.verification import load_checks

__all__ = [
    "CONTROLS_ENV",
    "CheckControls",
    "ControlMap",
    "ControlMapError",
    "Endpoint",
    "canary_hashes",
    "controls_for",
    "load_controls",
]

CONTROLS_ENV = "AEGIS_VERIFY_CONTROLS"
DEFAULT_CONTROLS = Path("deploy/lab/verify-controls.json")


class ControlMapError(ValueError):
    """The deployment control map is missing or does not have the reviewed shape."""


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One lab endpoint: a literal address and a port, never a name."""

    address: str
    port: int


@dataclass(frozen=True, slots=True)
class CheckControls:
    """What one check's lab run needs from the deployment, besides the finding's own asset."""

    check_id: str
    canary_path: str | None
    benign_path: str | None
    patched_twin: Endpoint | None
    benign: Endpoint | None


@dataclass(frozen=True, slots=True)
class ControlMap:
    """The canary identity and every check the deployment can decide."""

    canary_sha256: str | None
    canary_name_sha256: str | None
    checks: Mapping[str, CheckControls]


def canary_hashes(content: bytes, name: str | None = None) -> tuple[str, str | None]:
    """The hashes M21 compares: the canary content, and its file name for a listing check."""
    content_sha = hashlib.sha256(content).hexdigest()
    name_sha = None if name is None else hashlib.sha256(name.encode("utf-8")).hexdigest()
    return content_sha, name_sha


def _sha256(value: Any, where: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ControlMapError(f"{where} must be 64 lowercase hex characters")
    return value


def _path(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 2000:
        raise ControlMapError(f"{where} must be an absolute request path")
    return value


def _endpoint(value: Any, where: str) -> Endpoint:
    if not isinstance(value, Mapping):
        raise ControlMapError(f"{where} must be an object with address and port")
    address = value.get("address")
    if not isinstance(address, str):
        raise ControlMapError(f"{where}.address must be a string")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as error:
        raise ControlMapError(f"{where}.address {address!r} is not an IP literal") from error
    port = value.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ControlMapError(f"{where}.port must be an integer in 1..65535")
    return Endpoint(address=str(parsed), port=port)


def _check(check_id: str, raw: Any, where: str) -> CheckControls:
    if not isinstance(raw, Mapping):
        raise ControlMapError(f"{where} must be an object")
    targets = raw.get("targets")
    if targets is None:
        targets = {}
    if not isinstance(targets, Mapping):
        raise ControlMapError(f"{where}.targets must be an object")
    twin = targets.get("patched_twin")
    benign = targets.get("benign")
    canary_path = raw.get("canaryPath")
    benign_path = raw.get("benignPath")
    return CheckControls(
        check_id=check_id,
        canary_path=None if canary_path is None else _path(canary_path, f"{where}.canaryPath"),
        benign_path=None if benign_path is None else _path(benign_path, f"{where}.benignPath"),
        patched_twin=None if twin is None else _endpoint(twin, f"{where}.targets.patched_twin"),
        benign=None if benign is None else _endpoint(benign, f"{where}.targets.benign"),
    )


def _load(path: Path) -> ControlMap:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ControlMapError(
            f"{path}: cannot read the verification control map: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise ControlMapError(f"{path}: not JSON: {error}") from error
    if not isinstance(document, Mapping):
        raise ControlMapError(f"{path}: the control map must be an object")
    canary = document.get("canary") or {}
    if not isinstance(canary, Mapping):
        raise ControlMapError(f"{path}: canary must be an object")
    content_sha = canary.get("content_sha256")
    name_sha = canary.get("name_sha256")
    raw_checks = document.get("checks") or {}
    if not isinstance(raw_checks, Mapping):
        raise ControlMapError(f"{path}: checks must be an object")
    checks = {
        str(check_id): _check(str(check_id), raw, f"{path}: checks[{check_id}]")
        for check_id, raw in raw_checks.items()
    }
    # An L1 check without its controls would run with no negative control; the review that added
    # the check must add its lab pairing too.
    for check in load_checks().lab_only():
        entry = checks.get(check.check_id)
        if entry is None:
            raise ControlMapError(
                f"{path}: lab check {check.check_id} has no entry; its lab run needs a canary, a "
                "benign path and a patched twin"
            )
        if entry.canary_path is None or entry.benign_path is None:
            raise ControlMapError(f"{path}: {check.check_id} needs canaryPath and benignPath")
        if entry.patched_twin is None or entry.benign is None:
            raise ControlMapError(f"{path}: {check.check_id} needs both control endpoints")
    return ControlMap(
        canary_sha256=None
        if content_sha is None
        else _sha256(content_sha, f"{path}: canary.content_sha256"),
        canary_name_sha256=None
        if name_sha is None
        else _sha256(name_sha, f"{path}: canary.name_sha256"),
        checks=checks,
    )


def load_controls(path: str | Path | None = None) -> ControlMap:
    """Read and validate the deployment control map; the path comes from the environment."""
    if path is not None:
        return _load(Path(path))
    configured = os.environ.get(CONTROLS_ENV)
    resolved = Path(configured) if configured else repository_root() / DEFAULT_CONTROLS
    return _load(resolved)


def controls_for(mapping: ControlMap, check_id: str) -> CheckControls | None:
    """The controls of one check, or None when the deployment has none (internet E1 runs)."""
    return mapping.checks.get(check_id)


def _cache_key(path: Path | None) -> str:
    return "<default>" if path is None else str(path.resolve())


@cache
def _cached(key: str) -> ControlMap:
    if key == "<default>":
        return load_controls()
    return load_controls(key)


def cached_controls(path: str | Path | None = None) -> ControlMap:
    """`load_controls`, once per path per process (the file is deployment data, not per run)."""
    return _cached(_cache_key(None if path is None else Path(path)))
