"""Rootless Podman runner used by the G0.2 spike.

It only builds and drives commands; the contract-facing behaviour (ContainerSpec
fields, status values, output_dir, remove-without-deleting-output) mirrors
contracts/interfaces/README.md §2 so the spike can be lifted into G1.3a.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

PODMAN = shutil.which("podman") or "podman"
RUNNING_STATES = {"running", "paused", "created", "stopped"}


def podman(*args: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PODMAN, *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
    )


@dataclass(frozen=True)
class ContainerSpec:
    """Contract fields plus the spike-only knobs, in contract order."""

    job_id: str
    image_digest: str  # image reference pinned by digest (or tag for spike pulls)
    args: list[str]
    cpu: float
    memory_mb: int
    timeout_seconds: int
    max_output_bytes: int
    network: str  # "exec" | "none"
    raw_socket: bool = False
    read_only_rootfs: bool = True
    user: str = "65534:65534"
    pids_limit: int = 512
    max_output_files: int = 50000
    seccomp_ruleset: str = "default"
    output_dir: Path | None = None
    env: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class RunResult:
    job_id: str
    state: str  # created|running|exited|oom|timeout|missing
    exit_code: int | None
    oom_killed: bool
    timed_out: bool
    duration_seconds: float
    stdout: str
    stderr: str
    output_dir: Path


class JobNetwork:
    """One internal network per job: no uplink, no DNS, fixed broker address."""

    def __init__(self, job_id: str, pool: str = "10.89.0.0/16", prefix: int = 72):
        self.job_id = job_id
        self.name = f"aegis-job-{job_id}"
        self._pool = ipaddress.ip_network(pool)
        self._prefix = prefix
        self.subnet: ipaddress.IPv4Network | None = None
        self.uplink: str | None = None

    def create(self) -> "JobNetwork":
        used = set()
        for line in podman("network", "ls", "--format", "{{.Name}}").stdout.split():
            inspect = podman("network", "inspect", line, check=False)
            if inspect.returncode != 0:
                continue
            for net in json.loads(inspect.stdout):
                for subnet in net.get("subnets") or []:
                    if subnet.get("subnet"):
                        used.add(ipaddress.ip_network(subnet["subnet"]))
        for candidate in self._pool.subnets(new_prefix=self._prefix):
            if not any(candidate.overlaps(u) for u in used):
                self.subnet = candidate
                break
        if self.subnet is None:
            raise RuntimeError("no free subnet for job network")
        podman(
            "network",
            "create",
            "--internal",
            "--disable-dns",
            "--subnet",
            str(self.subnet),
            "--label",
            f"aegis.job_id={self.job_id}",
            self.name,
        )
        return self

    @property
    def gateway(self) -> str:
        assert self.subnet is not None
        return str(self.subnet.network_address + 1)

    def broker_ip(self) -> str:
        assert self.subnet is not None
        return str(self.subnet.network_address + 2)

    def remove(self) -> None:
        podman("network", "rm", "-f", self.name, check=False)


def build_run_argv(
    spec: ContainerSpec,
    *,
    network: str | None,
    dns: str | None = None,
    extra: list[str] | None = None,
) -> list[str]:
    """Build the hardened `podman run` argv for one job container."""
    name = f"aegis-job-{spec.job_id}"
    argv = [
        PODMAN,
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        f"aegis.job_id={spec.job_id}",
    ]
    for key, value in spec.labels.items():
        argv += ["--label", f"{key}={value}"]
    argv += [
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit",
        str(spec.pids_limit),
        "--memory",
        f"{spec.memory_mb}m",
        "--memory-swap",
        f"{spec.memory_mb}m",
        "--cpus",
        str(spec.cpu),
        "--user",
        spec.user,
        "--workdir",
        "/out" if spec.output_dir is not None else "/",
        "--stop-signal",
        "SIGTERM",
        "--stop-timeout",
        "5",
    ]
    if spec.read_only_rootfs:
        argv += ["--read-only", "--tmpfs", "/tmp:rw,size=64m,mode=1777"]
    if spec.raw_socket:
        argv += ["--cap-add=NET_RAW"]
    # Never host network, never the Podman socket, never --privileged.
    argv += ["--network", network or "none"]
    if dns:
        argv += ["--dns", dns]
    for key, value in spec.env.items():
        argv += ["--env", f"{key}={value}"]
    if spec.output_dir is not None:
        argv += ["--mount", f"type=bind,source={spec.output_dir},target=/out"]
    argv += extra or []
    argv += [spec.image_digest, *spec.args]
    return argv


def inspect(container: str) -> dict:
    result = podman("inspect", container, check=False)
    if result.returncode != 0:
        return {}
    data = json.loads(result.stdout)
    return data[0] if data else {}


def run_job(
    spec: ContainerSpec,
    *,
    network: str | None,
    dns: str | None = None,
    extra: list[str] | None = None,
    poll_seconds: float = 0.25,
) -> RunResult:
    """Start the container, enforce wall-clock timeout, then stop and report."""
    if spec.output_dir is not None:
        spec.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            spec.output_dir.chmod(0o777)  # tool runs as 65534 inside
        except PermissionError:
            pass
    started = time.monotonic()
    podman("rm", "-f", f"aegis-job-{spec.job_id}", check=False)
    argv = build_run_argv(spec, network=network, dns=dns, extra=extra)
    run = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if run.returncode != 0:
        raise RuntimeError(f"podman run failed: {run.stderr.strip()}")
    container = run.stdout.strip().splitlines()[-1]
    timed_out = False
    state = inspect(container)
    while True:
        status = (state.get("State") or {}).get("Status", "missing")
        if status not in RUNNING_STATES:
            break
        if time.monotonic() - started > spec.timeout_seconds:
            timed_out = True
            podman("kill", "--signal", "SIGTERM", container, check=False)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                state = inspect(container)
                if (state.get("State") or {}).get("Status") not in RUNNING_STATES:
                    break
                time.sleep(0.2)
            else:
                podman("kill", "--signal", "SIGKILL", container, check=False)
            state = inspect(container)
            break
        time.sleep(poll_seconds)
        state = inspect(container)
    duration = time.monotonic() - started
    state_obj = state.get("State") or {}
    exit_code = state_obj.get("ExitCode")
    oom = bool(state_obj.get("OOMKilled"))
    status = state_obj.get("Status", "missing")
    logs = podman("logs", container, check=False)
    normalised = "missing"
    if status == "exited":
        normalised = "oom" if oom else ("timeout" if timed_out else "exited")
    elif status in RUNNING_STATES:
        normalised = "running"
    podman("rm", "-f", container, check=False)
    return RunResult(
        job_id=spec.job_id,
        state=normalised,
        exit_code=exit_code,
        oom_killed=oom,
        timed_out=timed_out,
        duration_seconds=round(duration, 2),
        stdout=logs.stdout,
        stderr=logs.stderr,
        output_dir=spec.output_dir or Path("/nonexistent"),
    )


@dataclass
class BrokerContainer:
    job_id: str
    image: str
    network: JobNetwork
    uplink: str
    policy_path: Path
    audit_dir: Path
    name: str = ""
    container_id: str = ""

    def start(self) -> "BrokerContainer":
        self.name = f"aegis-broker-{self.job_id}"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            PODMAN,
            "run",
            "--detach",
            "--name",
            self.name,
            "--label",
            f"aegis.job_id={self.job_id}",
            "--label",
            "aegis.role=egress-broker",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "128m",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=16m,mode=1777",
            "--user",
            "65534:65534",
            "--network",
            f"{self.network.name}:ip={self.network.broker_ip()}",
            "--network",
            self.uplink,
            "--mount",
            f"type=bind,src={self.policy_path},dst=/policy.json,ro,Z",
            "--mount",
            f"type=bind,src={self.audit_dir},dst=/audit,rw,Z",
            self.image,
            "python3",
            "-m",
            "aegis_g02.egress_broker",
            "--policy",
            "/policy.json",
            "--audit",
            "/audit/egress.jsonl",
        ]
        run = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if run.returncode != 0:
            raise RuntimeError(f"broker start failed: {run.stderr.strip()}")
        self.container_id = run.stdout.strip().splitlines()[-1]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            logs = podman("logs", self.container_id, check=False).stdout
            if "READY" in logs:
                return self
            time.sleep(0.2)
        raise RuntimeError("broker did not become ready")

    def audit_records(self) -> list[dict]:
        path = self.audit_dir / "egress.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def stop(self) -> None:
        podman("rm", "-f", self.container_id or self.name, check=False)


def new_job_id(prefix: str = "g02") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"
