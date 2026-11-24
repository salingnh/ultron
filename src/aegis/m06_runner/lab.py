"""The deployment profile that points a job's container at the authorized lab (G1.5c).

The lab ([deploy/lab](../../../deploy/lab)) is a DNS zone and a local passive-source stub on an
internal network with no route off this host. A tool that runs there needs three things no
provider manifest can express, because they belong to the deployment and not to the tool:

* the **network** it joins (`aegis-lab-lab`): the lab has no published port and no gateway, so a
  container on it can reach the lab and nothing else - that is the isolation evidence, not a hole;
* per-tool **runtime flags and files**: DNSx's resolver (`-r 10.114.53.53`) and Subfinder's
  `/etc/hosts` entry for the lab `crt.sh` stub plus the throwaway lab CA (`SSL_CERT_FILE`).

Everything here is *deployment* configuration, keyed by the **pinned image digest** a job already
carries (`scan_job.image_digest` -> `ApprovedTask.image_digest`), so it can never widen what a job
runs: the manifest still fixes the image, the argv template and the budget, and this profile only
adds the lab's own endpoint data on top. It is off unless `AEGIS_M06_LAB_PROFILE` names a file, so a
production runner never joins the lab network by accident (see `tests/test_m06_lab_profile.py`).

The file format (see `deploy/lab/runner-profile.json`)::

    {
      "network": "aegis-lab-lab",
      "jobs": [
        {
          "imageDigest": "sha256:...",
          "args": ["-r", "10.114.53.53"],
          "env": {"HOME": "/tmp"},
          "hosts": {"crt.sh": "10.114.53.80"},
          "mounts": [{"source": ".run/tls/ca.crt", "target": "/lab-tls/ca.crt"}]
        }
      ]
    }

`mounts[].source` is resolved against the profile file's directory, so a checkout can carry it.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["ENV_PROFILE", "LabJob", "LabMount", "LabProfile", "LabProfileError"]

ENV_PROFILE = "AEGIS_M06_LAB_PROFILE"
#: The contract's `ImageDigest` (common/ids.v2). A profile entry keyed by anything else would never
#: match a task and would silently leave the lab deployment without its endpoint data.
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class LabProfileError(RuntimeError):
    """The lab profile cannot be read or is not usable (fail before any container exists)."""


@dataclass(frozen=True, slots=True)
class LabMount:
    """One read-only bind mount the lab endpoint data needs (the lab CA)."""

    source: Path
    target: str

    def argv(self) -> list[str]:
        return ["--mount", f"type=bind,src={self.source},dst={self.target},ro,z"]


@dataclass(frozen=True, slots=True)
class LabJob:
    """What one pinned image needs to run against the lab, beyond its manifest."""

    image_digest: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    hosts: Mapping[str, str] = field(default_factory=dict)
    mounts: tuple[LabMount, ...] = ()

    def argv(self) -> list[str]:
        """The Podman flags this profile adds (network is applied by the runner)."""
        argv: list[str] = []
        for host, address in self.hosts.items():
            argv += ["--add-host", f"{host}:{address}"]
        for key, value in self.env.items():
            argv += ["--env", f"{key}={value}"]
        for mount in self.mounts:
            argv += mount.argv()
        return argv


@dataclass(frozen=True, slots=True)
class LabProfile:
    """The lab deployment profile: its network plus one entry per pinned image."""

    network: str
    jobs: Mapping[str, LabJob]

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any], *, base_dir: Path | None = None
    ) -> LabProfile:
        network = document.get("network")
        if not isinstance(network, str) or not network:
            raise LabProfileError("the lab profile must name the network it joins")
        entries = document.get("jobs")
        if not isinstance(entries, list) or not entries:
            raise LabProfileError("the lab profile must list at least one job entry")
        jobs: dict[str, LabJob] = {}
        for entry in entries:
            job = _job_from_entry(entry, base_dir=base_dir)
            if job.image_digest in jobs:
                raise LabProfileError(
                    f"image {job.image_digest} is listed twice in the lab profile"
                )
            jobs[job.image_digest] = job
        return cls(network=network, jobs=jobs)

    @classmethod
    def from_file(cls, path: str | Path) -> LabProfile:
        profile_path = Path(path)
        try:
            document = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise LabProfileError(f"cannot read the lab profile {profile_path}: {error}") from error
        if not isinstance(document, dict):
            raise LabProfileError(f"the lab profile {profile_path} is not a JSON object")
        return cls.from_document(document, base_dir=profile_path.parent)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LabProfile | None:
        """The configured profile, or None when the deployment does not run jobs on the lab."""
        source = os.environ if env is None else env
        configured = source.get(ENV_PROFILE, "").strip()
        return cls.from_file(configured) if configured else None

    def for_image(self, image_digest: str) -> LabJob | None:
        return self.jobs.get(image_digest)


def _job_from_entry(entry: Any, *, base_dir: Path | None) -> LabJob:
    if not isinstance(entry, dict):
        raise LabProfileError("every lab profile job entry must be an object")
    digest = entry.get("imageDigest")
    if not isinstance(digest, str) or not IMAGE_DIGEST.fullmatch(digest):
        raise LabProfileError(
            f"lab profile entry {entry!r} has no valid imageDigest (sha256:<64 hex>)"
        )
    args = entry.get("args") or []
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise LabProfileError(f"args of {digest} must be a list of strings")
    env = entry.get("env") or {}
    if not isinstance(env, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in env.items()
    ):
        raise LabProfileError(f"env of {digest} must map strings to strings")
    hosts = entry.get("hosts") or {}
    if not isinstance(hosts, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in hosts.items()
    ):
        raise LabProfileError(f"hosts of {digest} must map names to addresses")
    mounts: list[LabMount] = []
    for item in entry.get("mounts") or []:
        if not isinstance(item, dict):
            raise LabProfileError(f"a mount of {digest} must be an object")
        source = item.get("source")
        target = item.get("target")
        if not isinstance(source, str) or not isinstance(target, str) or not target.startswith("/"):
            raise LabProfileError(f"a mount of {digest} needs source and absolute target")
        resolved = Path(os.path.expanduser(source))
        if not resolved.is_absolute() and base_dir is not None:
            resolved = (base_dir / resolved).resolve()
        mounts.append(LabMount(source=resolved, target=target))
    return LabJob(
        image_digest=digest,
        args=tuple(args),
        env=dict(env),
        hosts=dict(hosts),
        mounts=tuple(mounts),
    )
