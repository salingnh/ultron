"""Child side of the contained parser (M06): `python -m aegis.m06_runner.parser_child ...`.

Started only by `parser_host.run_parser`, after `unshare` created the user/network/pid namespace.
This module sets its own rlimits, imports the adapter parser named on the command line (already
checked against `adapters.<module>.<tool>:<func>` by the parent), calls it, and writes the result
as JSON. Everything the parser raises is turned into `{"error": ...}` in that file: a contained
failure, never a crash of the runner.
"""

from __future__ import annotations

import importlib
import json
import resource
import sys
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast


def _set_limits(memory_mb: int, cpu_seconds: int, max_file_bytes: int, max_open_files: int) -> None:
    address_space = memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_bytes, max_file_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _load(entrypoint: str) -> Callable[..., Any]:
    module_name, _, function_name = entrypoint.partition(":")
    module = importlib.import_module(module_name)
    function = getattr(module, function_name, None)
    if not callable(function):
        raise AttributeError(f"{entrypoint} is not callable")
    return cast(Callable[..., Any], function)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 9:
        print(
            "usage: parser_child ENTRYPOINT OUTPUT_DIR TASK_JSON EVIDENCE_JSON RESULT_JSON "
            "MEMORY_MB CPU_SECONDS MAX_FILE_BYTES MAX_OPEN_FILES",
            file=sys.stderr,
        )
        return 2
    entrypoint, output_dir, task_path, evidence_path, result_path = args[:5]
    memory_mb, cpu_seconds, max_file_bytes, max_open_files = (int(value) for value in args[5:])
    _set_limits(memory_mb, cpu_seconds, max_file_bytes, max_open_files)
    payload: dict[str, Any]
    try:
        parse = _load(entrypoint)
        task = json.loads(Path(task_path).read_text(encoding="utf-8"))
        evidence = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
        parsed = parse(Path(output_dir), task, evidence)
        if not isinstance(parsed, dict):
            raise TypeError(f"{entrypoint} must return a dict, got {type(parsed).__name__}")
        payload = {"result": parsed, "error": None}
    except BaseException as error:  # noqa: BLE001 - contained and reported, never re-raised
        payload = {
            "result": None,
            "error": "".join(traceback.format_exception_only(type(error), error)).strip(),
        }
    # json.dumps is deliberately strict: a parser returning a non-JSON value is a bug we surface
    # in the parent (`RESULT_UNREADABLE`) instead of coercing silently.
    Path(result_path).write_text(json.dumps(payload), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
