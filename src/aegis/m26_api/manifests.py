"""Where the adapter manifests live, and how the service finds them at start-up.

`contracts/interfaces/README.md` §1 and `contracts/fixtures/index.yaml` put a provider manifest in
its adapter package (`adapters/<module>/<tool>/manifest.yaml`). M05 registers those bytes at
start-up; `AEGIS_ADAPTER_MANIFESTS` overrides the directory for a deployment that mounts a package
somewhere else. A manifest that cannot be admitted stops start-up (see `build_job_service`) instead
of turning every job of that capability into "unknown provider".
"""

from __future__ import annotations

import os
from pathlib import Path

from aegis.common.repo import repository_root

__all__ = ["ADAPTER_MANIFESTS_ENV", "DEFAULT_MANIFESTS_DIR", "adapter_manifests"]

ADAPTER_MANIFESTS_ENV = "AEGIS_ADAPTER_MANIFESTS"
DEFAULT_MANIFESTS_DIR = "adapters"


def manifests_dir() -> Path:
    """The directory scanned for `**/manifest.yaml` (repo-relative by default)."""
    configured = os.environ.get(ADAPTER_MANIFESTS_ENV)
    if configured:
        return Path(configured)
    return repository_root() / DEFAULT_MANIFESTS_DIR


def adapter_manifests() -> list[bytes]:
    """Every `manifest.yaml` under the adapter tree, sorted, as the exact bytes to pin."""
    directory = manifests_dir()
    if not directory.is_dir():
        return []
    return [path.read_bytes() for path in sorted(directory.glob("**/manifest.yaml"))]
