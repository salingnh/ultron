"""Probe parsers used by the G0.2 negative tests.

They stand in for an adapter parser so the isolation properties (no network, no
inherited environment, rlimits, crash containment, determinism) are observable
without shipping a real scanner.
"""

from __future__ import annotations

import hashlib
import os
import socket
import time
from pathlib import Path


def net_probe(output_dir: Path, task: dict, evidence: list) -> dict:
    """Try to reach the network; under the sandbox every attempt must fail."""
    results: dict[str, object] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect(("1.1.1.1", 53))
        results["tcp_connect"] = "CONNECTED"
    except OSError as exc:
        results["tcp_connect"] = f"{exc.__class__.__name__}:{exc.errno}:{exc.strerror}"
    finally:
        sock.close()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.connect(("8.8.8.8", 53))
        udp.send(b"\x00")
        results["udp_send"] = "SENT"
    except OSError as exc:
        results["udp_send"] = f"{exc.__class__.__name__}:{exc.errno}:{exc.strerror}"
    finally:
        udp.close()
    try:
        results["dns"] = socket.gethostbyname("example.com")
    except OSError as exc:
        results["dns"] = f"{exc.__class__.__name__}:{exc.strerror}"
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("0.0.0.0", 0))
        listener.close()
        results["bind"] = "OK"
    except OSError as exc:
        results["bind"] = f"{exc.__class__.__name__}:{exc.errno}"
    return results


def env_probe(output_dir: Path, task: dict, evidence: list) -> dict:
    """Report exactly what the child can read from its environment."""
    return {
        "env": dict(os.environ),
        "cwd": os.getcwd(),
        "files": sorted(p.name for p in Path(output_dir).iterdir()),
    }


def sleep_probe(output_dir: Path, task: dict, evidence: list) -> dict:
    time.sleep(3600)
    return {"slept": True}


def oom_probe(output_dir: Path, task: dict, evidence: list) -> dict:
    blocks = []
    while True:
        blocks.append(b"x" * (8 * 1024 * 1024))
    return {"blocks": len(blocks)}


def crash_probe(output_dir: Path, task: dict, evidence: list) -> dict:
    raise ValueError("parser exploded on hostile input")


def deterministic_probe(output_dir: Path, task: dict, evidence: list) -> dict:
    digest = hashlib.sha256()
    names = []
    for path in sorted(Path(output_dir).rglob("*")):
        if path.is_file() and not path.is_symlink():
            names.append(path.name)
            digest.update(path.read_bytes())
    return {"files": names, "sha256": digest.hexdigest(), "task_input": task.get("input")}
