"""Parser isolation (spike G0.2).

The adapter ``parse()`` function runs in a child process that is as close to
"no network, no credentials, no inherited environment" as a rootless host can
get:

* a fresh user+network namespace (``unshare --user --map-root-user --net``),
  so the child has only a down loopback and cannot open an outbound socket —
  enforced by the kernel, not by convention;
* an environment rebuilt from an allowlist (no ``AWS_*``, no proxy, no tokens);
  the entrypoint module is passed by path, never through the environment;
* rlimits for address space, CPU, file size, open files and processes;
* a wall-clock timeout with SIGKILL, and a JSON result file so a parser crash
  cannot take down the runner.

The real M06 implementation must add the ``adapters.*`` entrypoint allowlist
(contracts/interfaces/README.md §2) and run under the supervisor's own uid;
the spike keeps the same shape and proves the isolation with probe parsers.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

SPIKE_ROOT = Path(__file__).resolve().parent.parent

# Only these variables exist in the parser process. PATH is needed to start
# python; PYTHONPATH points at the adapter package root.
ENV_ALLOWLIST = ("PATH", "PYTHONPATH", "PYTHONHASHSEED", "LC_ALL", "HOME", "TMPDIR")


@dataclass(frozen=True)
class ParserLimits:
    timeout_seconds: int = 60
    memory_mb: int = 512
    cpu_seconds: int = 60
    max_output_bytes: int = 64 * 1024 * 1024
    max_open_files: int = 256


@dataclass
class ParserRun:
    ok: bool
    result: dict | None
    error: str | None
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    sandbox: dict


def run_parser(
    entrypoint: str,
    output_dir: Path,
    task: dict,
    *,
    limits: ParserLimits | None = None,
    python: str | None = None,
    use_netns: bool = True,
) -> ParserRun:
    limits = limits or ParserLimits()
    workdir = Path(tempfile.mkdtemp(prefix="aegis-parser-"))
    task_path = workdir / "task.json"
    result_path = workdir / "result.json"
    task_path.write_text(json.dumps(task), encoding="utf-8")
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(SPIKE_ROOT),
        "PYTHONHASHSEED": "0",
        "LC_ALL": "C.UTF-8",
        "HOME": str(workdir),
        "TMPDIR": str(workdir),
    }
    child = [
        python or sys.executable,
        "-m",
        "aegis_g02.parser_child",
        entrypoint,
        str(output_dir),
        str(task_path),
        str(result_path),
        str(limits.memory_mb),
        str(limits.cpu_seconds),
        str(limits.max_output_bytes),
        str(limits.max_open_files),
    ]
    unshare = [
        "unshare",
        "--user",
        "--map-root-user",
        "--net",
        "--pid",
        "--fork",
        "--kill-child",
        "--mount-proc",
    ]
    argv = (unshare if use_netns else []) + child
    started = time.monotonic()
    timed_out = False
    proc = subprocess.Popen(
        argv,
        env=env,
        cwd=str(workdir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=limits.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        stdout, stderr = proc.communicate()
    duration = time.monotonic() - started
    result = None
    error = None
    if result_path.exists():
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            error = f"RESULT_UNREADABLE: {exc}"
    parser_error = (result or {}).get("error")
    if timed_out:
        error = "PARSER_TIMEOUT"
    elif parser_error:
        # The parser's own traceback is data (hostile input), not a crash of
        # the runner: keep it verbatim for the job error and quarantine reason.
        error = str(parser_error)[:4000]
    elif proc.returncode != 0:
        error = f"PARSER_FAILED({proc.returncode}): {stderr.strip()[:2000]}"
    elif result is None:
        error = "PARSER_NO_RESULT"
    sandbox = {
        "netns": use_netns,
        "unshare": argv[0] == "unshare",
        "duration_seconds": round(duration, 3),
        "argv0": Path(argv[0]).name,
    }
    return ParserRun(
        ok=error is None,
        result=result,
        error=error,
        exit_code=proc.returncode,
        timed_out=timed_out,
        duration_seconds=round(duration, 3),
        sandbox=sandbox,
    )


def child_environment() -> dict[str, str]:
    """The environment the spike hands to the child (for tests/reports)."""
    return {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(SPIKE_ROOT),
        "PYTHONHASHSEED": "0",
        "LC_ALL": "C.UTF-8",
    }


def allowed_env_keys() -> tuple[str, ...]:
    return ENV_ALLOWLIST


def _is_allowed_entrypoint(entrypoint: str) -> bool:
    """Contract pattern is adapters.<module>.<tool>:<func>; the spike also
    accepts its own probe module so the negative tests can run."""
    module, _, func = entrypoint.partition(":")
    parts = module.split(".")
    if not func or not all(p.isidentifier() for p in parts):
        return False
    return module.startswith("adapters.") or module.startswith("aegis_g02.probes")


__all__ = [
    "ParserLimits",
    "ParserRun",
    "run_parser",
    "allowed_env_keys",
    "child_environment",
    "SPIKE_ROOT",
    "os",
]
