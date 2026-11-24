"""Locate the repository that carries contracts/ (the source of truth for every schema)."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT_ENV = "AEGIS_REPO_ROOT"


class RepositoryNotFound(RuntimeError):
    """The checkout that owns contracts/ could not be found; the message says how to fix it."""


def repository_root() -> Path:
    """Return the checkout root, the directory that contains contracts/.

    Resolution order: ``AEGIS_REPO_ROOT`` when set, then the nearest parent of this module that
    holds ``contracts/validation.py``. An installed (non-editable) package has no such parent, so
    the caller must set ``AEGIS_REPO_ROOT`` instead of the code guessing.

    The repository is not packaged with the wheel on purpose: contracts/ has one copy, and every
    consumer reads that copy rather than a vendored second one.
    """
    override = os.environ.get(REPO_ROOT_ENV)
    if override:
        root = Path(override).expanduser().resolve()
        if not (root / "contracts/validation.py").is_file():
            raise RepositoryNotFound(
                f"{REPO_ROOT_ENV}={override} does not contain contracts/validation.py"
            )
        return root
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "contracts/validation.py").is_file():
            return candidate
    raise RepositoryNotFound(
        "cannot find the repository root (a parent holding contracts/validation.py); "
        f"set {REPO_ROOT_ENV} to the checkout root"
    )


def contract_path(*parts: str) -> Path:
    """Absolute path of a file or directory inside the contract bundle."""
    path = repository_root().joinpath("contracts", *parts)
    if not path.exists():
        raise RepositoryNotFound(f"contract path does not exist: {path}")
    return path
