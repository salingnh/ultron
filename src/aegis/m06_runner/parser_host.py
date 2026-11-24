"""Run an adapter parser in a contained child process (M06; interfaces/README.md §2).

The adapter `parse()` function sees hostile scanner output, so it runs in a child that is as
close to "no network, no credentials, no inherited environment" as a rootless host can get:

* a fresh user + network + pid namespace (`unshare --user --map-root-user --net --pid --fork
  --kill-child --mount-proc`), so the child has only a down loopback and cannot open an outbound
  socket - enforced by the kernel, not by convention (G0.2 proof);
* an environment rebuilt from an allowlist: no `AWS_*`, no proxy, no token of the parent;
* rlimits for address space, CPU, file size, open files and processes, plus a wall-clock timeout
  with SIGKILL, and the result in a file: a parser crash cannot take the runner down;
* the manifest entrypoint must match `adapters.<module>.<tool>:<func>` - never an arbitrary import.

`--kill-child` is not cosmetic: without it a killed `unshare` parent leaves the grandchild holding
the stdout pipe and `communicate()` never returns (G0.2 root cause finding 3).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.common.repo import repository_root

ENV_ALLOWLIST = ("PATH", "PYTHONPATH", "PYTHONHASHSEED", "LC_ALL", "HOME", "TMPDIR")
ENTRYPOINT_PREFIX = "adapters."
MAX_ERROR_CHARS = 4000


@dataclass(frozen=True)
class ParserLimits:
    timeout_seconds: int = 60
    memory_mb: int = 512
    cpu_seconds: int = 60
    max_output_bytes: int = 64 * 1024 * 1024
    max_open_files: int = 256


@dataclass
class ParserRun:
    """Outcome of one parser invocation; `sandbox` records what isolation actually ran."""

    ok: bool
    result: dict[str, Any] | None
    error: str | None
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    sandbox: dict[str, Any]


def is_allowed_entrypoint(entrypoint: str, *, extra_prefixes: Sequence[str] = ()) -> bool:
    """`adapters.<module>.<tool>:<func>` (plus explicitly allowed test modules)."""
    module, _, function = entrypoint.partition(":")
    if not function or not function.isidentifier():
        return False
    parts = module.split(".")
    if not all(part.isidentifier() for part in parts):
        return False
    prefixes = (ENTRYPOINT_PREFIX, *extra_prefixes)
    return any(module.startswith(prefix) for prefix in prefixes)


def child_python_path(extra: Sequence[str] = ()) -> str:
    """Explicit paths first (tests shadow `adapters`), then the repo root and `src`.

    The repo root owns the product `adapters` package; a test that needs a contract-valid
    `adapters.*` entrypoint puts its own `adapters` package first, and only in this child.
    """
    root = repository_root()
    return os.pathsep.join([*extra, str(root), str(root / "src")])


def _child_env(workdir: Path, extra_python_path: Sequence[str]) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONPATH": child_python_path(extra_python_path),
        "PYTHONHASHSEED": "0",
        "LC_ALL": "C.UTF-8",
        "HOME": str(workdir),
        "TMPDIR": str(workdir),
    }


def _unshare_argv() -> list[str]:
    return [
        "unshare",
        "--user",
        "--map-root-user",
        "--net",
        "--pid",
        "--fork",
        "--kill-child",
        "--mount-proc",
    ]


def run_parser(
    entrypoint: str,
    output_dir: Path,
    task: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]] = (),
    *,
    limits: ParserLimits | None = None,
    python: str | None = None,
    use_netns: bool = True,
    extra_prefixes: Sequence[str] = (),
    extra_python_path: Sequence[str] = (),
) -> ParserRun:
    """Run `entrypoint(output_dir, task, evidence)` in the isolated child."""
    if not is_allowed_entrypoint(entrypoint, extra_prefixes=extra_prefixes):
        raise ValueError(
            f"parser entrypoint must match adapters.<module>.<tool>:<func>, got {entrypoint!r}"
        )
    active = limits or ParserLimits()
    with tempfile.TemporaryDirectory(prefix="aegis-parser-") as raw_workdir:
        workdir = Path(raw_workdir)
        task_path = workdir / "task.json"
        evidence_path = workdir / "evidence.json"
        result_path = workdir / "result.json"
        task_path.write_text(json.dumps(task), encoding="utf-8")
        evidence_path.write_text(json.dumps(list(evidence)), encoding="utf-8")
        child = [
            python or sys.executable,
            "-m",
            "aegis.m06_runner.parser_child",
            entrypoint,
            str(output_dir),
            str(task_path),
            str(evidence_path),
            str(result_path),
            str(active.memory_mb),
            str(active.cpu_seconds),
            str(active.max_output_bytes),
            str(active.max_open_files),
        ]
        argv = (_unshare_argv() if use_netns else []) + child
        started = time.monotonic()
        timed_out = False
        process = subprocess.Popen(
            argv,
            env=_child_env(workdir, extra_python_path),
            cwd=str(workdir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _, stderr = process.communicate(timeout=active.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            _, stderr = process.communicate()
        duration = time.monotonic() - started
        result: dict[str, Any] | None = None
        error: str | None = None
        parser_error: object = None
        if result_path.exists():
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                error = f"RESULT_UNREADABLE: {exc}"
            else:
                if not isinstance(payload, dict):
                    error = "RESULT_NOT_AN_OBJECT"
                else:
                    parser_error = payload.get("error")
                    candidate = payload.get("result")
                    if isinstance(candidate, dict):
                        result = candidate
                    elif candidate is not None:
                        error = "RESULT_NOT_AN_OBJECT"
        if timed_out:
            error = "PARSER_TIMEOUT"
        elif parser_error:
            # The parser's own traceback is data (hostile input), not a runner crash: keep it
            # verbatim for the job error and the quarantine reason.
            error = str(parser_error)[:MAX_ERROR_CHARS]
        elif process.returncode not in (0, None):
            error = f"PARSER_FAILED({process.returncode}): {stderr.strip()[:2000]}"
        elif result is None and error is None:
            error = "PARSER_NO_RESULT"
        sandbox = {
            "netns": use_netns,
            "unshare": bool(use_netns),
            "argv0": Path(argv[0]).name,
            "duration_seconds": round(duration, 3),
        }
        return ParserRun(
            ok=error is None,
            result=result,
            error=error,
            exit_code=process.returncode,
            timed_out=timed_out,
            duration_seconds=round(duration, 3),
            sandbox=sandbox,
        )
