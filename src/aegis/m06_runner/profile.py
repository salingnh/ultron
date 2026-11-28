"""Deployment network profiles of a job: the authorized lab and the internet (G1.6).

A campaign's RoE names the profile its jobs run on (`network_profile`: `lab` | `internet`, signed
into the `ApprovedTask` by M05). The profile is *deployment* configuration and never part of the
task payload: it only says where this deployment attaches the container and which endpoint data
this deployment's tools need. Everything a job may reach is still decided by the signed egress
binding and the platform deny set.

Two profiles exist, and each is a file the deployment owns:

* `lab` ([deploy/lab](../../../deploy/lab)) - an internal network with no gateway (DNS zone and a
  local passive-source stub). A tool there needs a resolver flag, an `/etc/hosts` entry and the
  throwaway lab CA.
* `internet` ([deploy/internet](../../../deploy/internet)) - the job gets its own internal network
  whose only peer is the L7 broker; the broker joins `network` (an uplink with a gateway) and
  enforces the binding per connection. The tool may need nothing at all (Subfinder uses its
  passive sources) or, optionally, a provider-config file whose **path** comes from an environment
  variable of the runner process (`AEGIS_SUBFINDER_PROVIDER_CONFIG`): key values stay in that file,
  are never logged, never serialized into a task and never passed on a command line.

Both files use the same shape (see `deploy/lab/runner-profile.json`)::

    {
      "network": "aegis-lab-lab",          # lab network, or the broker's uplink for internet
      "jobs": [
        {
          "imageDigest": "sha256:...",     # the pinned digest the job already carries
          "args": ["-r", "10.114.53.53"],  # extra argv appended to the manifest's argv
          "env": {"HOME": "/tmp"},         # literal env (never a secret)
          "envFromHost": ["NAME"],         # forward NAME's *value* from the runner's env
          "hosts": {"crt.sh": "10.114.53.80"},
          "connectTimeoutMs": 1000,       # the tool's own connect budget (see below)
          "mounts": [
            {"source": ".run/tls/ca.crt", "target": "/lab-tls/ca.crt"},
            {"sourceEnv": "AEGIS_SUBFINDER_PROVIDER_CONFIG", "target": "/tmp/.config/..."}
          ]
        }
      ]
    }

`mounts[].source` is resolved against the profile file's directory, so a checkout can carry it;
`mounts[].sourceEnv` names a host environment variable holding an absolute path (unset = the mount
is skipped, which is how the provider-config file is optional).

`connectTimeoutMs` is the tool's own connect timeout, declared next to the argv that sets it
(e.g. Naabu's `-timeout 1s`). The broker paces connections for the RoE caps and records how long
each one waited; the runner compares that wait with this budget, so a connection the broker only
admitted after the tool had already given up becomes an `EGRESS_PACED` coverage limitation instead
of a silently missing port (G1.6 Decision A, item 83 trial). Omit it when the tool's timeout is
unknown: a broker refusal after its bounded wait is still reported as incomplete coverage.

The profile is off unless its file is named, so a production runner never joins the lab network by
accident and a lab runner never opens a broker uplink by accident (`tests/test_m06_profiles.py`).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

__all__ = [
    "BROKER_DNS",
    "BROKER_HTTP",
    "BROKER_SOCKS",
    "ENV_INTERNET_PROFILE",
    "ENV_LAB_PROFILE",
    "DeploymentProfile",
    "JobMount",
    "JobProfile",
    "PinnedInput",
    "ProfileError",
    "ProfileKind",
    "verify_pinned_inputs",
]

ENV_LAB_PROFILE = "AEGIS_M06_LAB_PROFILE"
ENV_INTERNET_PROFILE = "AEGIS_M06_INTERNET_PROFILE"
#: The contract's `ImageDigest` (common/ids.v2). A profile entry keyed by anything else would never
#: match a task and would silently leave the deployment without its endpoint data.
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
#: An environment variable name the deployment may forward; a name is not a secret, its value is.
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

#: An argv element the runner replaces with the job's broker endpoint, e.g. `dnsx -r ${broker_dns}`,
#: `subfinder -proxy ${broker_http}`, `naabu -proxy ${broker_socks}`. Deployment data, like the
#: rest of the profile, not a job input. The HTTP value is a URL (`http://ip:3128`); the SOCKS value
#: is a bare authority (`ip:1080`) because Naabu's `-proxy` silently no-ops on a scheme (G0.2).
BROKER_DNS = "${broker_dns}"
BROKER_HTTP = "${broker_http}"
BROKER_SOCKS = "${broker_socks}"

ProfileKind = Literal["lab", "internet"]


class ProfileError(RuntimeError):
    """A deployment profile cannot be read or is not usable (fail before any container exists)."""


@dataclass(frozen=True, slots=True)
class JobMount:
    """One read-only bind mount, from a path in the profile or from a host environment variable."""

    target: str
    source: Path | None = None
    source_env: str | None = None

    def argv(self) -> list[str] | None:
        """The Podman flag, or None when the environment names no file (the mount is optional)."""
        source = self.source
        if source is None:
            assert self.source_env is not None
            value = os.environ.get(self.source_env, "").strip()
            if not value:
                return None
            source = Path(value).expanduser().resolve()
        return ["--mount", f"type=bind,src={source},dst={self.target},ro,z"]


@dataclass(frozen=True, slots=True)
class PinnedInput:
    """A read-only mount whose bytes a deployment pins, and the rule set those bytes define.

    Trivy's vulnerability DB is the first use (G2-D): the deployment downloads it once, records the
    digest of `trivy.db` and the rule-set label (`trivy-db@<UpdatedAt>`), mounts the directory
    read-only and lets M06 verify the file before any container exists. A drift (re-downloaded DB,
    edited file) is `DEPENDENCY_MISSING`, never a scan against bytes nobody pinned; the verified
    label goes into `coverage.rule_set`, so a finding's provenance names the DB the scan used.
    """

    target: str
    file: str
    sha256: str
    rule_set: str | None = None


#: sha256 of a pinned file keyed by its identity on disk, so a runner does not re-hash a 2 GB DB on
#: every job while a changed file (new size or mtime) is always re-read.
_DIGESTS: dict[tuple[str, int, int], str] = {}


def file_digest(path: Path) -> str:
    stat = path.stat()
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    cached = _DIGESTS.get(key)
    if cached is not None:
        return cached
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    value = digest.hexdigest()
    _DIGESTS[key] = value
    return value


def verify_pinned_inputs(entry: JobProfile) -> str | None:
    """Verify every pinned input of a profile entry; return its rule-set label (or None).

    Raises `ProfileError` when a pinned input has no mount, the mount has no fixed source (a
    `sourceEnv` mount is optional by construction and cannot be a pin) or the file is missing or
    has different bytes. The first label wins: one tool, one rule set.
    """
    label: str | None = None
    for pinned in entry.pinned_inputs:
        mount = next((item for item in entry.mounts if item.target == pinned.target), None)
        if mount is None or mount.source is None:
            raise ProfileError(
                f"pinned input {pinned.file!r} of {entry.image_digest} has no fixed-source mount "
                f"at {pinned.target}"
            )
        path = mount.source / pinned.file
        try:
            found = file_digest(path)
        except OSError as error:
            raise ProfileError(
                f"pinned input {path} of {entry.image_digest} is unreadable: {error}"
            ) from error
        if found != pinned.sha256:
            raise ProfileError(
                f"pinned input {path} of {entry.image_digest} has sha256 {found}, the deployment "
                f"pinned {pinned.sha256}"
            )
        if label is None:
            label = pinned.rule_set
    return label


@dataclass(frozen=True, slots=True)
class JobProfile:
    """What one pinned image needs to run on this deployment's network, beyond its manifest."""

    image_digest: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    env_from_host: tuple[str, ...] = ()
    hosts: Mapping[str, str] = field(default_factory=dict)
    #: The tool's own connect timeout, when the deployment knows it (see the module docstring).
    connect_timeout_ms: int | None = None
    mounts: tuple[JobMount, ...] = ()
    #: Mounts whose bytes the deployment pins (G2-D: an offline vulnerability DB).
    pinned_inputs: tuple[PinnedInput, ...] = ()

    def argv(self, *, network: bool = True) -> list[str]:
        """The Podman flags this profile adds (the network is applied by the runner).

        `network=False` is a job the manifest declares without egress (`networkAccess: none`): its
        endpoint data (resolver hosts, extra argv) has no meaning there, but the read-only mounts
        and literal environment of the profile still do (an offline DB, a CA bundle). A job that
        must not reach the network therefore gets exactly the profile's local inputs.
        """
        argv: list[str] = []
        if network:
            for host, address in self.hosts.items():
                argv += ["--add-host", f"{host}:{address}"]
        for key, value in self.env.items():
            argv += ["--env", f"{key}={value}"]
        for name in self.env_from_host:
            # `--env NAME` (no value) copies the runner process's value: a secret travels through
            # the environment of the two processes, never through argv, the task or a log line.
            argv += ["--env", name]
        for mount in self.mounts:
            flags = mount.argv()
            if flags is not None:
                argv += flags
        return argv


@dataclass(frozen=True, slots=True)
class DeploymentProfile:
    """One deployment network profile: its kind, its network and one entry per pinned image."""

    kind: ProfileKind
    network: str
    jobs: Mapping[str, JobProfile]

    @classmethod
    def from_document(
        cls,
        document: Mapping[str, Any],
        *,
        kind: ProfileKind,
        base_dir: Path | None = None,
        origin: str | None = None,
    ) -> DeploymentProfile:
        where = origin or f"the {kind} profile"
        network = document.get("network")
        if not isinstance(network, str) or not network:
            raise ProfileError(f"{where} must name the network it joins")
        entries = document.get("jobs")
        if not isinstance(entries, list) or not entries:
            raise ProfileError(f"{where} must list at least one job entry")
        jobs: dict[str, JobProfile] = {}
        for entry in entries:
            job = _job_from_entry(entry, base_dir=base_dir, where=where)
            if job.image_digest in jobs:
                raise ProfileError(f"image {job.image_digest} is listed twice in {where}")
            jobs[job.image_digest] = job
        return cls(kind=kind, network=network, jobs=jobs)

    @classmethod
    def from_file(cls, path: str | Path, *, kind: ProfileKind) -> DeploymentProfile:
        profile_path = Path(path)
        try:
            document = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ProfileError(f"cannot read the {kind} profile {profile_path}: {error}") from error
        if not isinstance(document, dict):
            raise ProfileError(f"the {kind} profile {profile_path} is not a JSON object")
        return cls.from_document(
            document, kind=kind, base_dir=profile_path.parent, origin=str(profile_path)
        )

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, *, kind: ProfileKind = "lab"
    ) -> DeploymentProfile | None:
        """The configured profile of this kind, or None when the deployment does not run it."""
        source = os.environ if env is None else env
        variable = ENV_LAB_PROFILE if kind == "lab" else ENV_INTERNET_PROFILE
        configured = source.get(variable, "").strip()
        return cls.from_file(configured, kind=kind) if configured else None

    def for_image(self, image_digest: str) -> JobProfile | None:
        return self.jobs.get(image_digest)


def _job_from_entry(entry: Any, *, base_dir: Path | None, where: str) -> JobProfile:
    if not isinstance(entry, dict):
        raise ProfileError(f"every job entry of {where} must be an object")
    digest = entry.get("imageDigest")
    if not isinstance(digest, str) or not IMAGE_DIGEST.fullmatch(digest):
        raise ProfileError(
            f"job entry {entry!r} of {where} has no valid imageDigest (sha256:<64 hex>)"
        )
    args = entry.get("args") or []
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise ProfileError(f"args of {digest} must be a list of strings")
    env = entry.get("env") or {}
    if not isinstance(env, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in env.items()
    ):
        raise ProfileError(f"env of {digest} must map strings to strings")
    names = entry.get("envFromHost") or []
    if not isinstance(names, list) or not all(
        isinstance(name, str) and ENV_NAME.fullmatch(name) for name in names
    ):
        raise ProfileError(f"envFromHost of {digest} must be a list of environment variable names")
    hosts = entry.get("hosts") or {}
    if not isinstance(hosts, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in hosts.items()
    ):
        raise ProfileError(f"hosts of {digest} must map names to addresses")
    mounts: list[JobMount] = []
    for item in entry.get("mounts") or []:
        if not isinstance(item, dict):
            raise ProfileError(f"a mount of {digest} must be an object")
        target = item.get("target")
        if not isinstance(target, str) or not target.startswith("/"):
            raise ProfileError(f"a mount of {digest} needs an absolute target")
        source = item.get("source")
        source_env = item.get("sourceEnv")
        if (source is None) == (source_env is None):
            raise ProfileError(
                f"a mount of {digest} needs exactly one of source (path) or sourceEnv (name)"
            )
        if source is not None:
            if not isinstance(source, str):
                raise ProfileError(f"the source of a mount of {digest} must be a path")
            resolved = Path(os.path.expanduser(source))
            if not resolved.is_absolute() and base_dir is not None:
                resolved = (base_dir / resolved).resolve()
            mounts.append(JobMount(target=target, source=resolved))
            continue
        if not isinstance(source_env, str) or not ENV_NAME.fullmatch(source_env):
            raise ProfileError(f"sourceEnv of a mount of {digest} must be a variable name")
        mounts.append(JobMount(target=target, source_env=source_env))
    timeout = entry.get("connectTimeoutMs")
    if timeout is not None and (
        not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0
    ):
        raise ProfileError(
            f"connectTimeoutMs of {digest} must be a positive integer (milliseconds), "
            f"got {timeout!r}"
        )
    pinned: list[PinnedInput] = []
    for item in entry.get("pinnedInputs") or []:
        if not isinstance(item, dict):
            raise ProfileError(f"a pinnedInput of {digest} must be an object")
        target = item.get("target")
        name = item.get("file")
        checksum = item.get("sha256")
        label = item.get("ruleSet")
        if not isinstance(target, str) or not target.startswith("/"):
            raise ProfileError(f"a pinnedInput of {digest} needs an absolute mount target")
        if not isinstance(name, str) or not name or name.startswith("/") or ".." in name:
            raise ProfileError(f"a pinnedInput of {digest} needs a relative file name")
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ProfileError(f"a pinnedInput of {digest} needs a lowercase sha256")
        if label is not None and (not isinstance(label, str) or not label):
            raise ProfileError(f"the ruleSet of a pinnedInput of {digest} must be a string")
        pinned.append(PinnedInput(target=target, file=name, sha256=checksum, rule_set=label))
    return JobProfile(
        image_digest=digest,
        args=tuple(args),
        env=dict(env),
        env_from_host=tuple(names),
        hosts=dict(hosts),
        connect_timeout_ms=timeout,
        mounts=tuple(mounts),
        pinned_inputs=tuple(pinned),
    )
