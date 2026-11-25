"""Shared support for the M06/M28 tests (G1.3a): contract fixtures, probe image, fake ingestion.

Nothing here talks to the dev stack: the probe image is built locally from a digest-pinned base,
and the ingestion endpoint is a thread in this process. The isolation tests use real Podman.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import yaml

from aegis.common.repo import repository_root
from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.m05_registry.signing import KeyRing
from aegis.m06_runner.values import text

REPO_ROOT = repository_root()
CONTAINER_DIR = REPO_ROOT / "tests" / "container"
FIXTURES = REPO_ROOT / "contracts" / "fixtures" / "valid"

#: Digest-pinned test bases (the same pins the G0.2 spike recorded).
ALPINE = (
    "docker.io/library/alpine@sha256:"
    "d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
)
PYTHON_312 = (
    "docker.io/library/python@sha256:"
    "c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89"
)
SEAWEEDFS = (
    "docker.io/chrislusf/seaweedfs@sha256:"
    "7ca46aeae2f223b37e5d91593c17ab37738eec6df6ab69b48a0487f7643342b9"
)
# The tag is per test process: several workers build this image on one host, and a shared tag let a
# concurrent suite's build (another worktree, older sources) become the image a broker container
# ran - a real failure on 2026-11-25 (a stale netpolicy in the broker). The image id is what the
# tests use; the tag only exists to name the build.
PROBE_IMAGE = f"localhost/aegis-probe:{os.getpid()}"

PODMAN = shutil.which("podman") or "podman"


def podman_available() -> bool:
    return shutil.which("podman") is not None


def podman(*args: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PODMAN, *args], capture_output=True, text=True, check=check, timeout=timeout
    )


def require_podman() -> None:
    if not podman_available():
        raise RuntimeError("rootless podman is required by this test suite")


def build_probe_image() -> str:
    """Build the probe image once and return its image id (`sha256:...`, a valid ImageDigest)."""
    built = podman(
        "build",
        "--quiet",
        "--file",
        str(CONTAINER_DIR / "Containerfile"),
        "--tag",
        PROBE_IMAGE,
        str(REPO_ROOT),
        check=False,
    )
    if built.returncode != 0:
        raise RuntimeError(f"probe image build failed: {built.stderr[-3000:]}")
    inspected = podman("image", "inspect", "--format", "{{.Id}}", PROBE_IMAGE)
    image_id = inspected.stdout.strip()
    return image_id if image_id.startswith("sha256:") else f"sha256:{image_id}"


def image_present(image: str) -> bool:
    return podman("image", "exists", image, check=False).returncode == 0


# --- contract fixtures ----------------------------------------------------------------------


#: The published development signing key (OI-7); tests sign the tasks M06 must verify.
DEV_RING = KeyRing.dev()


def sign_task(
    payload: dict[str, Any], *, key_ring: KeyRing = DEV_RING
) -> tuple[ApprovedTask, dict[str, Any]]:
    """Sign a task dict the way M05 does and return `(DTO, exact signed document)`."""
    body = {
        key: value for key, value in payload.items() if key not in {"signature", "signature_key_id"}
    }
    signature, key_id = key_ring.sign(body)
    document = {**body, "signature": signature, "signature_key_id": key_id}
    task = ApprovedTask.model_validate(document)
    _BODIES[str(text(task.task_id))] = document
    return task, document


_BODIES: dict[str, dict[str, Any]] = {}


def body_of(task: ApprovedTask) -> dict[str, Any]:
    """The exact document that was signed for `task` (what M06 verifies)."""
    document = _BODIES.get(str(text(task.task_id)))
    if document is None:
        raise KeyError(f"no signed body recorded for task {text(task.task_id)}")
    return dict(document)


def _fixture(name: str) -> dict[str, Any]:
    path = FIXTURES / name
    text = path.read_text(encoding="utf-8")
    loaded = yaml.safe_load(text) if path.suffix in {".yaml", ".yml"} else json.loads(text)
    return cast(dict[str, Any], loaded)


def approved_task(**overrides: Any) -> ApprovedTask:
    """`approved-task.subfinder.json` with input/pin overrides, signed with the development key."""
    payload = _fixture("approved-task.subfinder.json")
    payload.update(
        {
            "input": {
                "targets": ["internal.example"],
                "concurrency": 2,
                "rate_limit": 1,
            }
        }
    )
    for key, value in overrides.items():
        payload[key] = value
    task, _document = sign_task(payload)
    return task


def manifest(name: str = "manifest.subfinder.yaml") -> tuple[ProviderManifest, bytes]:
    path = FIXTURES / name
    raw = path.read_bytes()
    return ProviderManifest.model_validate(yaml.safe_load(raw)), raw


def target_bound_manifest() -> tuple[ProviderManifest, bytes]:
    return manifest("manifest.naabu.yaml")


def task_for_manifest(
    manifest_value: ProviderManifest, manifest_bytes: bytes, **overrides: Any
) -> ApprovedTask:
    """An approved task pinned to `manifest_value` (task must match the manifest identity)."""
    import hashlib

    payload = _fixture("approved-task.subfinder.json")
    payload.update(
        {
            "capability": text(manifest_value.spec.capability),
            "provider": str(manifest_value.metadata.name),
            "provider_version": str(manifest_value.spec.providerVersion),
            "adapter_version": text(manifest_value.metadata.version),
            "image_digest": text(manifest_value.spec.runtime.imageDigest),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        }
    )
    for key, value in overrides.items():
        payload[key] = value
    task, _document = sign_task(payload)
    return task


def probe_manifest(
    image_digest: str,
    *,
    egress: bool = False,
    timeout_seconds: int | None = None,
    args_template: list[str] | None = None,
    egress_sources: list[dict[str, Any]] | None = None,
    target_bound: bool = False,
) -> tuple[ProviderManifest, bytes]:
    """A manifest whose tool is the probe image; parser/args are test-only overrides.

    `target_bound` gives it the port-scan shape (Naabu's): `targetBinding: required`,
    `targetPorts: from_input` and a manifest port cap, so an internet job reaches exactly the
    addresses the campaign signed.
    """
    payload = _fixture("manifest.subfinder.yaml")
    payload["metadata"]["name"] = "aegis-probe"
    payload["spec"]["capability"] = "dns.enumerate_subdomains"
    payload["spec"]["providerVersion"] = "v0.0.1-test"
    payload["spec"]["runtime"]["imageDigest"] = image_digest
    payload["spec"]["runtime"]["argsTemplate"] = args_template or [
        "python3",
        "-m",
        "aegis_probe.tool",
        "--lines",
        "${input.max_results}",
    ]
    payload["spec"]["parser"]["entrypoint"] = "adapters.probe.parser:parse"
    if timeout_seconds is not None:
        payload["spec"]["budget"]["timeoutSeconds"] = timeout_seconds
    if egress_sources is not None:
        payload["spec"]["permissions"]["egressSources"] = egress_sources
    if target_bound:
        payload["spec"]["permissions"].update(
            {
                "egressSources": egress_sources or [],
                "targetBinding": "required",
                "targetPorts": "from_input",
            }
        )
    if not egress:
        # The contract forbids explicit nulls here (additionalProperties false + const rules):
        # omitting the egress fields is how `networkAccess: none` is expressed.
        permissions = payload["spec"]["permissions"]
        permissions["networkAccess"] = "none"
        for key in (
            "egressMode",
            "proxyAware",
            "egressSources",
            "targetBinding",
            "targetPorts",
        ):
            permissions.pop(key, None)
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    value = ProviderManifest.model_validate(payload)
    if not egress:
        # `targetPorts` is a const default in the generated model; the contract forbids it when
        # targetBinding is none, so the model must not carry it into the wire form.
        value.spec.permissions.targetPorts = None  # type: ignore[assignment]
    return value, raw


# --- fake ingestion endpoint ----------------------------------------------------------------


@dataclass
class ReceivedEnvelope:
    headers: dict[str, str]
    body: dict[str, Any]


@dataclass
class FakeIngestion:
    """An in-process `POST /api/v2/ingestion/results`; receipts follow the contract."""

    service_token: str = "test-service-token"
    received: list[ReceivedEnvelope] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None
    _receipts: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address[:2]
        return f"http://{str(host)}:{int(port)}"

    def start(self) -> FakeIngestion:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - http.server API
                if self.path != "/api/v2/ingestion/results":
                    self.send_error(404)
                    return
                if self.headers.get("X-Aegis-Service-Token") != fake.service_token:
                    self.send_error(401)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length))
                fake.received.append(ReceivedEnvelope(dict(self.headers.items()), body))
                receipt = fake._receipt(body)
                payload = json.dumps(receipt).encode()
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def _receipt(self, body: dict[str, Any]) -> dict[str, Any]:
        key = str(body["dedup_key"])
        existing = self._receipts.get(key)
        if existing is not None:
            return {**existing, "duplicate": True}
        receipt = {
            "event_id": body["event_id"],
            "dedup_key": key,
            "accepted": True,
            "duplicate": False,
            "revision": 1,
            "quarantined": [],
            "payload_hash": "0" * 64,
            "hash_version": "aegis-c14n/1",
            "decided_at": "2026-11-24T00:00:00Z",
        }
        self._receipts[key] = receipt
        return receipt


def remove_tree(path: Path) -> None:
    """Remove a job-tree even when the sandbox user (subuid 65534) created sub-directories.

    Its files are readable by the runner but a directory it created is not writable by it, so a
    plain `rmtree` leaves entries behind; `podman unshare` maps that uid back to the root of the
    user namespace and can delete them.
    """
    if not path.exists():
        return
    podman("unshare", "rm", "-rf", str(path), check=False)
    shutil.rmtree(path, ignore_errors=True)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def container_ip(name: str, network: str) -> str:
    data = json.loads(podman("inspect", name).stdout)[0]
    return str(data["NetworkSettings"]["Networks"][network]["IPAddress"])


def wait_for_logs(name: str, marker: str = "READY", timeout: float = 30.0) -> None:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = podman("logs", name, check=False)
        if marker in (logs.stdout or "") + (logs.stderr or ""):
            return
        time.sleep(0.2)
    raise RuntimeError(
        f"{name} never printed {marker}: {podman('logs', name, check=False).stderr[-800:]}"
    )


def create_network(name: str, *, internal: bool, label: str = "aegis.test=g13a") -> str:
    args = ["network", "create", "--label", label]
    if internal:
        args += ["--internal", "--disable-dns"]
    podman(*args, name)
    return name


def remove_network(name: str) -> None:
    podman("network", "rm", "-f", name, check=False)


def run_detached(
    name: str,
    image: str,
    args: list[str],
    *,
    networks: list[str],
    label: str = "aegis.test=g13a",
    user: str = "65534:65534",
) -> str:
    argv = ["run", "--detach", "--name", name, "--label", label, "--user", user]
    for network in networks:
        argv += ["--network", network]
    argv += [image, *args]
    podman(*argv)
    return name


def host_lan_ip() -> str:
    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) > 3:
            return parts[3].split("/")[0]
    return "192.0.2.1"


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
