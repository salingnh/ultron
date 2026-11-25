"""Rootless Podman runner (M06; interfaces/README.md §2, G0.2 proven shape).

One job is one container named after the job id, started with the hardening the contract pins:
`--cap-drop=ALL`, `--security-opt=no-new-privileges`, read-only rootfs, uid/gid 65534, cgroup v2
cpu/memory/pids limits, no host network and no Podman socket. A job that needs egress gets its own
internal network (`--internal --disable-dns`) plus one broker container that is the only peer it
can reach.

`run()` is idempotent by `spec.job_id` (the container name *is* the job id), so a restarted
process never starts a second container for the same job; `reconcile()` adopts the containers of
live jobs and removes the ones whose job is gone. `remove()` never deletes the output directory:
the collector uploads it as evidence first (contract §2).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import random
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.common.ports import ContainerRunner, ContainerSpec, RunHandle, RunState
from aegis.m06_runner import netpolicy
from aegis.m06_runner.profile import DeploymentProfile, JobProfile

PODMAN = os.environ.get("AEGIS_PODMAN") or shutil.which("podman") or "podman"
ROLE_LABEL = "aegis.role"
RUNNER_LABEL = "aegis.runner"
JOB_ROLE = "job"
BROKER_ROLE = "egress-broker"
JOB_ID_LABEL = "aegis.job_id"
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
BROKER_HTTP_PORT = 3128
BROKER_SOCKS_PORT = 1080
RUNNING_STATES = frozenset({"created", "running", "paused"})
EXITED_STATES = frozenset({"exited", "stopped", "dead", "configured"})


class RunnerError(RuntimeError):
    """The sandbox runtime could not do what the contract requires (fail loudly)."""


def _podman(*args: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PODMAN, *args], capture_output=True, text=True, check=check, timeout=timeout
    )


@dataclass(frozen=True)
class WaitResult:
    """How one run ended; `wait()` is the only place that decides timeout/cancel/output cap."""

    state: RunState
    timed_out: bool = False
    cancelled: bool = False
    capped: bool = False


@dataclass(frozen=True)
class ReconcileReport:
    """What `reconcile()` did on the host; every list is a set of job ids or object names."""

    adopted: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    brokers_removed: tuple[str, ...] = ()
    networks_removed: tuple[str, ...] = ()


@dataclass(frozen=True)
class BrokerHandle:
    job_id: str
    container_id: str
    proxy: str


@dataclass
class JobLayout:
    """Per-job directories on the host; everything the job may touch lives here."""

    root: Path

    @property
    def output(self) -> Path:
        return self.root / "out"

    @property
    def input(self) -> Path:
        return self.root / "in"

    @property
    def policy(self) -> Path:
        return self.root / "policy.json"

    @property
    def audit(self) -> Path:
        return self.root / "audit"

    @property
    def run(self) -> Path:
        return self.root / "run.json"

    def create(self) -> JobLayout:
        for directory in (self.output, self.input, self.audit):
            directory.mkdir(parents=True, exist_ok=True)
        # The job runs as uid/gid 65534 (contract), which is not the owner of these host
        # directories. They are private to the job, and the sandbox user must be able to write its
        # output and the broker its audit line, so both are world-writable (SELinux `Z` already
        # relabels them for this container only).
        for writable in (self.output, self.audit):
            writable.chmod(0o777)
        return self


@dataclass
class PodmanRunner(ContainerRunner):
    """Rootless-Podman `ContainerRunner` with per-job networks and the egress broker."""

    base_dir: Path
    broker_image: str | None = None
    uplink_network: str | None = None
    network_pool: str = "10.97.0.0/16"
    network_prefix: int = 24
    poll_seconds: float = 0.2
    #: Deployment network profiles of this runner, keyed by kind (`lab`, `internet`). A profile is
    #: off unless its file is configured, and a job only uses the profile its signed RoE names.
    profiles: Mapping[str, DeploymentProfile] = field(default_factory=dict)
    _subnets: dict[str, str] = field(default_factory=dict, init=False)
    _images: dict[str, str] = field(default_factory=dict, init=False)

    @property
    def lab(self) -> DeploymentProfile | None:
        return self.profiles.get("lab")

    @property
    def internet(self) -> DeploymentProfile | None:
        return self.profiles.get("internet")

    # -- layout -----------------------------------------------------------------------------

    def layout(self, job_id: str) -> JobLayout:
        if not JOB_ID_PATTERN.fullmatch(job_id):
            raise RunnerError(f"job id is not a usable container name: {job_id!r}")
        return JobLayout(self.base_dir / "jobs" / job_id)

    @property
    def owner(self) -> str:
        """Stable id of this runner (its base directory), the scope of `reconcile()`.

        Two runners can share a host - two CI jobs, or a blue/green restart - and only the one that
        owns a container may adopt or remove it. A restarted process reusing the same base directory
        keeps the same owner, so it still reconciles its own jobs.
        """
        digest = hashlib.sha256(str(self.base_dir.resolve()).encode("utf-8")).hexdigest()
        return digest[:12]

    def container_name(self, job_id: str) -> str:
        return f"aegis-job-{job_id}"

    def network_name(self, job_id: str) -> str:
        # Deliberately not `aegis-job-<id>`: a container and a *network* with the same name make
        # `podman inspect <name>` ambiguous (it matches either kind), which once made `run()` adopt
        # its own network instead of starting the container.
        return f"aegis-net-{job_id}"

    def output_dir(self, handle: RunHandle) -> Path:
        return self.layout(handle.job_id).output

    # -- ContainerRunner --------------------------------------------------------------------

    def run(self, spec: ContainerSpec) -> RunHandle:
        layout = self.layout(spec.job_id).create()
        existing = self._container_id(self.container_name(spec.job_id))
        if existing is not None:
            # Idempotent by job id: a restarted runner adopts the container instead of starting a
            # second one (a retry is a new attempt, not a second container for the same job).
            return RunHandle(job_id=spec.job_id, container_id=existing)
        entry = self.profile_entry(spec.network_profile, spec.image_digest)
        network = "none"
        if spec.network_profile == "lab" and spec.network == "exec":
            profile = self.lab
            if entry is None or profile is None:
                # Fail closed: a lab campaign never falls back to the broker/internet network.
                raise RunnerError(
                    f"campaign profile lab, but this runner has no lab profile entry for "
                    f"{spec.image_digest}"
                )
            network = profile.network
        elif spec.network == "exec":
            network = self._ensure_network(spec.job_id)
        if spec.network != "exec":
            # No egress means no network at all; the profile contributes no endpoint data.
            entry = None
        argv = self._run_argv(spec, layout, network, entry=entry)
        try:
            started = _podman(*argv, timeout=120)
        except subprocess.CalledProcessError as failure:
            # A sandbox that cannot start is a job error, never an exception that escapes the
            # runner loop: `JobRunner` records INTERNAL_ERROR and discards what was prepared.
            raise RunnerError(
                f"podman could not start the job: {(failure.stderr or '').strip()[:2000]}"
            ) from failure
        lines = started.stdout.strip().splitlines()
        if not lines:
            raise RunnerError(f"podman run did not report a container id: {started.stderr.strip()}")
        container_id = lines[-1]
        markers: dict[str, object] = {
            "job_id": spec.job_id,
            "network_profile": spec.network_profile,
            "spec": _spec_document(spec),
        }
        if spec.network_profile == "lab" and entry is not None and self.lab is not None:
            markers["lab"] = {"network": self.lab.network, "args": list(entry.args)}
        self._write_markers(spec.job_id, markers)
        return RunHandle(job_id=spec.job_id, container_id=container_id)

    def image_reference(self, image_digest: str) -> str:
        """A runnable Podman reference for a contract `ImageDigest`.

        A manifest pins the **registry** digest of the provider image (`deploy/lab/images.env`,
        OCI *manifest-list* digest), and Podman only accepts that digest next to a repository name
        (`docker.io/projectdiscovery/subfinder@sha256:...`); bare `sha256:...` resolves only for a
        local image id. So: a local image whose repo digest is exactly this digest wins, and
        anything else is passed through unchanged (an image id, which is what the tests' probe
        image is). Nothing is pulled: the pinned digest must already be on the host.
        """
        cached = self._images.get(image_digest)
        if cached is not None:
            return cached
        listed = _podman(
            "images", "--digests", "--format", "{{.Repository}}@{{.Digest}}", check=False
        )
        for line in listed.stdout.splitlines():
            repository, _, digest = line.partition("@")
            if digest == image_digest and repository and "<none>" not in repository:
                reference = f"{repository}@{digest}"
                self._images[image_digest] = reference
                return reference
        self._images[image_digest] = image_digest
        return image_digest

    def profile_entry(self, kind: str, image_digest: str) -> JobProfile | None:
        """The entry of the deployment profile `kind` for a pinned image, or None.

        The kind comes from the campaign's signed `network_profile`; a job never picks a profile
        from the environment, so an internet campaign cannot land on the lab network (or the other
        way round) because of how one runner happens to be configured.
        """
        profile = self.profiles.get(kind)
        return None if profile is None else profile.for_image(image_digest)

    def owned_jobs(self) -> tuple[str, ...]:
        """Job ids of this runner's containers (running, exited or created), sorted."""
        return tuple(sorted({job_id for _name, job_id in self._containers(JOB_ROLE)}))

    def started(self, job_id: str) -> bool:
        """True when this runner has a job directory for the job (it began it at some point).

        A runner that was killed between claiming a job and starting its container leaves a row in
        `RUNNING` and nothing on the host but this directory, so it is the record that makes such a
        job resumable by this runner and by no other.
        """
        try:
            return self.layout(job_id).root.exists()
        except RunnerError:
            return False

    def inspect(self, handle: RunHandle) -> RunState:
        data = self._inspect(self.container_name(handle.job_id))
        if data is None:
            return RunState(status="missing")
        state = data.get("State") or {}
        status = str(state.get("Status", "missing"))
        exit_code = state.get("ExitCode")
        if status in RUNNING_STATES:
            return RunState(status="created" if status == "created" else "running")
        if status not in EXITED_STATES:
            return RunState(status="missing")
        if bool(state.get("OOMKilled")):
            return RunState(status="oom", exit_code=exit_code)
        if self._markers(handle.job_id).get("timed_out"):
            return RunState(status="timeout", exit_code=exit_code)
        return RunState(status="exited", exit_code=exit_code)

    def stop(self, handle: RunHandle, grace_seconds: int = 10, *, force: bool = False) -> None:
        """Stop the container; `force` sends SIGKILL at once (the output cap has nothing to save).

        A tool is PID 1 in its container, and the kernel ignores a signal PID 1 has no handler
        for, so a tool that never installs one keeps running for the whole grace period. The cap
        check therefore kills instead of waiting (waiting would mean more unbounded writing);
        cancel and timeout keep a short grace so a tool that handles SIGTERM can still flush.
        """
        name = self.container_name(handle.job_id)
        if force:
            _podman("kill", "--signal", "SIGKILL", name, check=False)
            return
        stopped = _podman(
            "stop",
            "--time",
            str(max(1, grace_seconds)),
            name,
            check=False,
            timeout=grace_seconds + 30,
        )
        if stopped.returncode != 0:
            _podman("kill", "--signal", "SIGKILL", name, check=False)

    def remove(self, handle: RunHandle) -> None:
        _podman("rm", "-f", self.container_name(handle.job_id), check=False)
        self.stop_broker(handle.job_id)
        self._remove_network(handle.job_id)

    def wait(
        self,
        handle: RunHandle,
        timeout_seconds: int,
        *,
        cancel: Callable[[], bool] | None = None,
        max_output_bytes: int | None = None,
    ) -> WaitResult:
        """Poll until terminal, the wall clock expires, the user cancels or the output cap is hit.

        The cap is a host-protection bound in addition to the container's `RLIMIT_FSIZE` (one file
        cannot exceed it) and the collector's own cap (the job is rejected afterwards): a tool that
        writes many small files is stopped as soon as the directory grows past the manifest's
        `max_output_bytes`, so a runaway scan cannot fill the host disk while it runs.
        """
        started = time.monotonic()
        size_poll = min(self.poll_seconds, 0.05)
        while True:
            state = self.inspect(handle)
            if state.status in {"exited", "oom", "timeout", "missing"}:
                return WaitResult(state=state)
            if cancel is not None and cancel():
                self._write_markers(handle.job_id, {"cancel_requested_at": _now()}, merge=True)
                self.stop(handle, grace_seconds=5)
                return WaitResult(state=self.inspect(handle), cancelled=True)
            # Between two (expensive) state polls, watch the output size closely: the bound is
            # "one size-poll interval of writes" past the cap, not the disk.
            horizon = time.monotonic() + self.poll_seconds
            while time.monotonic() < horizon:
                if max_output_bytes is not None:
                    written = self.output_bytes(handle.job_id, limit=max_output_bytes)
                    if written > max_output_bytes:
                        self._write_markers(
                            handle.job_id,
                            {"output_cap_exceeded": written, "max_output_bytes": max_output_bytes},
                            merge=True,
                        )
                        self.stop(handle, force=True)
                        return WaitResult(state=self.inspect(handle), capped=True)
                time.sleep(size_poll)
            if time.monotonic() - started > timeout_seconds:
                self._write_markers(handle.job_id, {"timed_out": True}, merge=True)
                self.stop(handle, grace_seconds=5)
                return WaitResult(state=self.inspect(handle), timed_out=True)

    def ensure_network(self, job_id: str) -> str:
        """Create the job network if it is missing (idempotent, also used by `prepare`)."""
        return self._ensure_network(job_id)

    def discard(self, job_id: str) -> None:
        """Forget everything a failed preparation created; no container and no output exists."""
        _podman("rm", "-f", self.container_name(job_id), check=False)
        self.stop_broker(job_id)
        self._remove_network(job_id)

    # -- egress broker ----------------------------------------------------------------------

    def start_broker(self, job_id: str, policy: netpolicy.JobEgressPolicy) -> BrokerHandle:
        """Start the one reachable peer of the job network and wait until it listens."""
        if not self.broker_image:
            raise RunnerError(
                "a job with network=exec needs a pinned broker image (PodmanRunner.broker_image)"
            )
        network = self._ensure_network(job_id)
        layout = self.layout(job_id).create()
        policy_path = layout.policy
        policy_path.write_text(
            json.dumps(netpolicy.policy_document(policy), indent=1, sort_keys=True),
            encoding="utf-8",
        )
        layout.audit.chmod(0o777)
        name = self.broker_name(job_id)
        existing = self._container_id(name)
        if existing is not None:
            return BrokerHandle(
                job_id=job_id, container_id=existing, proxy=self.broker_proxy(job_id)
            )
        argv = [
            "run",
            "--detach",
            "--name",
            name,
            "--label",
            f"{JOB_ID_LABEL}={job_id}",
            "--label",
            f"{ROLE_LABEL}={BROKER_ROLE}",
            "--label",
            f"{RUNNER_LABEL}={self.owner}",
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
            f"{network}:ip={self.broker_ip(job_id)}",
        ]
        argv += ["--network", self.uplink_network] if self.uplink_network else []
        argv += [
            "--mount",
            f"type=bind,src={policy_path},dst=/policy.json,ro,Z",
            "--mount",
            f"type=bind,src={layout.audit},dst=/audit,rw,Z",
            self.broker_image,
            "python3",
            "-m",
            "aegis.m06_runner.broker",
            "--policy",
            "/policy.json",
            "--audit",
            "/audit/egress.jsonl",
            # Listen on the job network only: the broker also has a leg on the uplink, and a
            # container on that (shared) network must not be able to use the job's proxy.
            "--bind",
            self.broker_ip(job_id),
        ]
        started = _podman(*argv, timeout=120)
        container_id = started.stdout.strip().splitlines()[-1]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if "READY" in self.logs(RunHandle(job_id=job_id, container_id=container_id)):
                return BrokerHandle(
                    job_id=job_id, container_id=container_id, proxy=self.broker_proxy(job_id)
                )
            if self._container_id(name) is None:
                break
            time.sleep(0.2)
        raise RunnerError(
            f"egress broker for {job_id} did not become ready: {self.broker_logs(job_id)}"
        )

    def stop_broker(self, job_id: str) -> None:
        _podman("rm", "-f", self.broker_name(job_id), check=False)

    def broker_name(self, job_id: str) -> str:
        return f"aegis-broker-{job_id}"

    def broker_proxy(self, job_id: str) -> str:
        return f"http://{self.broker_ip(job_id)}:{BROKER_HTTP_PORT}"

    def broker_socks(self, job_id: str) -> str:
        return f"{self.broker_ip(job_id)}:{BROKER_SOCKS_PORT}"

    def broker_ip(self, job_id: str) -> str:
        subnet = self._subnets.get(job_id) or self._existing_subnet(self.network_name(job_id))
        if subnet is None:
            raise RunnerError(f"job network of {job_id} does not exist on this host")
        return str(ipaddress.ip_network(subnet).network_address + 2)

    def broker_logs(self, job_id: str) -> str:
        return self._logs(self.broker_name(job_id))

    def audit_records(self, job_id: str) -> list[dict[str, object]]:
        path = self.layout(job_id).audit / "egress.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    # -- lifecycle --------------------------------------------------------------------------

    def output_bytes(self, job_id: str, *, limit: int | None = None) -> int:
        """Bytes of regular files under the job output directory, stopping early at `limit`."""
        total = 0
        root = self.layout(job_id).output
        if not root.is_dir():
            return 0
        stack = [root]
        while stack:
            current = stack.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                            continue
                        total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
                    if limit is not None and total > limit:
                        return total
        return total

    def logs(self, handle: RunHandle) -> str:
        return self._logs(handle.container_id or self.container_name(handle.job_id))

    def markers(self, job_id: str) -> dict[str, object]:
        return self._markers(job_id)

    def list_jobs(self) -> tuple[str, ...]:
        """Job ids that still have a container on this host (running or exited)."""
        return tuple(sorted({job_id for _name, job_id in self._containers(JOB_ROLE)}))

    def reconcile(self, live_job_ids: Iterable[str]) -> ReconcileReport:
        """Adopt this runner's live jobs, remove everything of a job that is gone.

        Only objects carrying this runner's owner label are touched, so a second runner process on
        the same host (another CI job, a blue/green restart) never adopts or removes them.
        """
        live = set(live_job_ids)
        adopted: list[str] = []
        removed: list[str] = []
        for name, job_id in self._containers(JOB_ROLE):
            if job_id in live:
                adopted.append(job_id)
                continue
            # The container is removed but its output directory stays: the collector may still
            # upload what the job produced before it died.
            _podman("rm", "-f", name, check=False)
            removed.append(job_id)
            self._remove_network(job_id)
        brokers = [name for name, job_id in self._containers(BROKER_ROLE) if job_id not in live]
        for name in brokers:
            _podman("rm", "-f", name, check=False)
        networks = [name for name, job_id in self._networks() if job_id not in live]
        for name in networks:
            _podman("network", "rm", "-f", name, check=False)
        return ReconcileReport(
            adopted=tuple(sorted(adopted)),
            removed=tuple(sorted(removed)),
            brokers_removed=tuple(sorted(brokers)),
            networks_removed=tuple(sorted(networks)),
        )

    # -- internals --------------------------------------------------------------------------

    def _run_argv(
        self,
        spec: ContainerSpec,
        layout: JobLayout,
        network: str,
        *,
        entry: JobProfile | None = None,
    ) -> list[str]:
        argv = [
            "run",
            "--detach",
            "--name",
            self.container_name(spec.job_id),
            "--label",
            f"{JOB_ID_LABEL}={spec.job_id}",
            "--label",
            f"{ROLE_LABEL}={JOB_ROLE}",
            "--label",
            f"{RUNNER_LABEL}={self.owner}",
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
            "/out",
            "--stop-signal",
            "SIGTERM",
            "--stop-timeout",
            "5",
            # A single output file cannot exceed the manifest's byte cap (RLIMIT_FSIZE, EFBIG),
            # on top of the directory monitor in `wait()` and the collector's own cap.
            "--ulimit",
            f"fsize={spec.max_output_bytes}:{spec.max_output_bytes}",
        ]
        if spec.read_only_rootfs:
            argv += ["--read-only", "--tmpfs", "/tmp:rw,size=64m,mode=1777"]
        if spec.raw_socket:
            argv += ["--cap-add=NET_RAW"]
        # Never host network, never the Podman socket, never --privileged.
        argv += ["--network", network if network != "none" else "none"]
        if entry is not None:
            # The deployment profile of this job (lab endpoint data, or an internet provider
            # config): trusted deploy config, never a job input - see aegis.m06_runner.profile.
            argv += entry.argv()
        for key, value in self._egress_env(spec).items():
            argv += ["--env", f"{key}={value}"]
        argv += ["--mount", f"type=bind,src={layout.output},dst=/out,rw,Z"]
        if any(layout.input.iterdir()):
            argv += ["--mount", f"type=bind,src={layout.input},dst=/in,ro,Z"]
        argv += [
            self.image_reference(spec.image_digest),
            *spec.args,
            *(entry.args if entry is not None else ()),
        ]
        return argv

    @staticmethod
    def _egress_env(spec: ContainerSpec) -> dict[str, str]:
        if not spec.egress_proxy:
            return {}
        proxy = spec.egress_proxy
        env = {
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "ALL_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            "all_proxy": proxy,
        }
        if spec.egress_binding:
            env["AEGIS_EGRESS_BINDING"] = ",".join(spec.egress_binding)
        return env

    def _ensure_network(self, job_id: str) -> str:
        name = self.network_name(job_id)
        inspect = _podman("network", "inspect", name, check=False)
        if inspect.returncode == 0:
            data = json.loads(inspect.stdout)
            subnets = data[0].get("subnets") or []
            if subnets:
                self._subnets[job_id] = str(subnets[0].get("subnet"))
            return name
        subnet = self._free_subnet()
        _podman(
            "network",
            "create",
            "--internal",
            "--disable-dns",
            "--subnet",
            subnet,
            "--label",
            f"{JOB_ID_LABEL}={job_id}",
            "--label",
            f"{ROLE_LABEL}=network",
            "--label",
            f"{RUNNER_LABEL}={self.owner}",
            name,
        )
        self._subnets[job_id] = subnet
        return name

    def _existing_subnet(self, name: str) -> str | None:
        inspect = _podman("network", "inspect", name, check=False)
        if inspect.returncode != 0:
            return None
        subnets = json.loads(inspect.stdout)[0].get("subnets") or []
        if not subnets:
            return None
        subnet = str(subnets[0].get("subnet"))
        self._subnets[name.removeprefix("aegis-net-")] = subnet
        return subnet

    def _free_subnet(self) -> str:
        used: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
            ipaddress.ip_network(subnet) for subnet in self._used_subnets()
        ]
        candidates: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = list(
            ipaddress.ip_network(self.network_pool).subnets(new_prefix=self.network_prefix)
        )
        # Two CI jobs can run on this host at the same time; a shuffled order makes both picking
        # the same free subnet very unlikely, and `podman network create` still refuses a clash.
        random.SystemRandom().shuffle(candidates)
        for candidate in candidates:
            if not any(candidate.overlaps(network) for network in used):
                return str(candidate)
        raise RunnerError(f"no free job subnet left in {self.network_pool}")

    def _used_subnets(self) -> list[str]:
        subnets: list[str] = []
        listed = _podman("network", "ls", "--format", "{{.Name}}", check=False)
        for name in listed.stdout.split():
            inspect = _podman("network", "inspect", name, check=False)
            if inspect.returncode != 0:
                continue
            for network in json.loads(inspect.stdout):
                for subnet in network.get("subnets") or []:
                    if subnet.get("subnet"):
                        subnets.append(str(subnet["subnet"]))
        return subnets

    def _remove_network(self, job_id: str) -> None:
        _podman("network", "rm", "-f", self.network_name(job_id), check=False)
        self._subnets.pop(job_id, None)

    def _networks(self) -> list[tuple[str, str]]:
        listed = _podman("network", "ls", "--format", "{{.Name}}", check=False)
        found: list[tuple[str, str]] = []
        for name in listed.stdout.split():
            if not name.startswith("aegis-net-"):
                continue
            inspect = _podman("network", "inspect", name, check=False)
            if inspect.returncode != 0:
                continue
            labels = json.loads(inspect.stdout)[0].get("labels") or {}
            if labels.get(RUNNER_LABEL) != self.owner:
                continue
            job_id = str(labels.get(JOB_ID_LABEL, name.removeprefix("aegis-net-")))
            found.append((name, job_id))
        return found

    def _containers(self, role: str) -> list[tuple[str, str]]:
        listed = _podman(
            "ps",
            "-a",
            "--filter",
            f"label={ROLE_LABEL}={role}",
            "--filter",
            f"label={RUNNER_LABEL}={self.owner}",
            "--format",
            '{{.Names}}\t{{.Label "aegis.job_id"}}',
            check=False,
        )
        found: list[tuple[str, str]] = []
        for line in listed.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[1]:
                found.append((parts[0], parts[1]))
        return found

    @staticmethod
    def _inspect(name: str) -> dict[str, Any] | None:
        # `podman container inspect` (not plain `inspect`, which also matches networks/images).
        result = _podman("container", "inspect", name, check=False)
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        return data[0] if data else None

    @staticmethod
    def _container_id(name: str) -> str | None:
        data = PodmanRunner._inspect(name)
        return None if data is None else str(data.get("Id", ""))

    @staticmethod
    def _logs(name: str) -> str:
        result = _podman("logs", name, check=False)
        return (result.stdout or "") + (result.stderr or "")

    def _markers(self, job_id: str) -> dict[str, object]:
        path = self.layout(job_id).run
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write_markers(
        self, job_id: str, values: Mapping[str, object], *, merge: bool = False
    ) -> None:
        layout = self.layout(job_id)
        layout.root.mkdir(parents=True, exist_ok=True)
        data = self._markers(job_id) if merge else {}
        data.update(values)
        temporary = layout.run.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
        temporary.replace(layout.run)


def _spec_document(spec: ContainerSpec) -> dict[str, object]:
    """The spec as JSON, for `run.json`: reconcile and tests can see what a job was started with."""
    return {
        "job_id": spec.job_id,
        "image_digest": spec.image_digest,
        "args": list(spec.args),
        "cpu": spec.cpu,
        "memory_mb": spec.memory_mb,
        "timeout_seconds": spec.timeout_seconds,
        "max_output_bytes": spec.max_output_bytes,
        "max_output_files": spec.max_output_files,
        "network": spec.network,
        "egress_mode": spec.egress_mode,
        "egress_binding": list(spec.egress_binding),
        "egress_proxy": spec.egress_proxy,
        "raw_socket": spec.raw_socket,
        "seccomp_ruleset": spec.seccomp_ruleset,
    }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


__all__ = (
    "BROKER_ROLE",
    "BrokerHandle",
    "JOB_ROLE",
    "JobLayout",
    "PodmanRunner",
    "ReconcileReport",
    "RunnerError",
    "WaitResult",
)
