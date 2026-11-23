"""Parser child process (spike G0.2).

Started by :mod:`aegis_g02.parser_host` inside a fresh user+network namespace.
It applies its own rlimits, imports exactly one entrypoint, calls it and writes
a single JSON document. It never reads inherited configuration: everything it
needs arrives on argv.
"""

from __future__ import annotations

import importlib
import json
import os
import resource
import sys
import traceback
from pathlib import Path


def _apply_limits(memory_mb: int, cpu_seconds: int, max_output_bytes: int, max_open_files: int) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024, memory_mb * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_output_bytes, max_output_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    except (ValueError, OSError):
        pass  # rootless RLIMIT_NPROC is advisory


def _interfaces() -> list[str]:
    names: list[str] = []
    with open("/proc/net/dev", encoding="utf-8") as fh:
        for line in fh.readlines()[2:]:
            name = line.split(":", 1)[0].strip()
            if name:
                names.append(name)
    return names


def main(argv: list[str]) -> int:
    (
        entrypoint,
        output_dir,
        task_path,
        result_path,
        memory_mb,
        cpu_seconds,
        max_output_bytes,
        max_open_files,
    ) = argv
    _apply_limits(int(memory_mb), int(cpu_seconds), int(max_output_bytes), int(max_open_files))
    module_name, _, func_name = entrypoint.partition(":")
    payload: dict = {
        "entrypoint": entrypoint,
        "pid": os.getpid(),
        "net_interfaces": _interfaces(),
        "env_keys": sorted(os.environ),
    }
    try:
        module = importlib.import_module(module_name)
        func = getattr(module, func_name)
        task = json.loads(Path(task_path).read_text(encoding="utf-8"))
        parsed = func(Path(output_dir), task, task.get("_evidence", []))
        payload["ok"] = True
        payload["parsed"] = parsed
    except BaseException:  # a parser crash must be data, not a dead runner
        payload["ok"] = False
        payload["error"] = traceback.format_exc(limit=8)
    Path(result_path).write_text(json.dumps(payload), encoding="utf-8")
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
