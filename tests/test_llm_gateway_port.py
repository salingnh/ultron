"""The gateway's own stack settings come from the checkout's `.env` (item 62, live-run defect 2).

The live failure: `AEGIS_LLM_GATEWAY_PORT` was only honoured from the shell environment, so
`make llm-gateway-up` published on 4000 while `.env` (and ultron) aimed at another port - and when
that port was taken, the only symptom was a container that published nothing.

`scripts/llm-gateway/lib.sh` reads the project name, the port and the base URL from `.env` like
every other setting, derives the port from `AEGIS_MODEL_BASE_URL` when it is not named (one source
of truth), refuses a port another process already listens on (naming it and the two lines to fix),
and refuses a base URL that does not point at the gateway it is about to start.

These tests drive the shell functions in a copied, throwaway checkout with a stub `podman`, so no
container, port or `.env` of the real checkout is touched.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: Everything a sourced `lib.sh` reads (no execution: the functions are called by name).
COPIED = (
    "scripts/lib/stack.sh",
    "scripts/llm-gateway/lib.sh",
    "scripts/llm-gateway/render.py",
    "scripts/llm-gateway/validate.py",
    "deploy/llm-gateway/compose.yaml",
    "deploy/llm-gateway/images.env",
    "deploy/llm-gateway/base.yaml",
)

#: A `podman` that claims nothing exists and publishes no port: the checks run for real, containers
#: do not.
PODMAN_STUB = """#!/usr/bin/env bash
exit 1
"""


def checkout(tmp_path: Path, env_lines: list[str]) -> Path:
    root = tmp_path / "checkout"
    for relative in COPIED:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / relative, target)
    (root / ".env").write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    (root / ".env").chmod(0o600)
    return root


def run(
    root: Path, script: str, *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    binary = root / "bin"
    binary.mkdir(exist_ok=True)
    stub = binary / "podman"
    stub.write_text(PODMAN_STUB, encoding="utf-8")
    stub.chmod(0o755)
    # A clean environment: no gateway setting may leak in from the shell that runs the tests.
    environment = {
        "PATH": f"{binary}:/usr/bin:/bin",
        "HOME": str(root),
        **(env or {}),
    }
    return subprocess.run(
        ["bash", "-c", script],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def identity(root: Path, *, env: dict[str, str] | None = None) -> tuple[str, str, str, str]:
    result = run(
        root,
        ". scripts/llm-gateway/lib.sh; "
        'printf "%s|%s|%s|%s\\n" "$PROJECT" "$PORT" "$BASE_URL" "$CONTAINER"',
        env=env,
    )
    assert result.returncode == 0, result.stderr
    project, port, base_url, container = result.stdout.strip().split("|")
    return project, port, base_url, container


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_the_port_comes_from_dot_env(tmp_path: Path) -> None:
    root = checkout(
        tmp_path,
        [
            "AEGIS_MODEL_API_KEY=sk-test-not-real",
            "AEGIS_LLM_GATEWAY_PORT=14123",
            "AEGIS_MODEL_BASE_URL=http://127.0.0.1:14123/v1",
        ],
    )
    _, port, base_url, _ = identity(root)
    assert port == "14123"
    assert base_url == "http://127.0.0.1:14123"


def test_the_port_follows_the_base_url_when_it_is_not_named(tmp_path: Path) -> None:
    root = checkout(
        tmp_path,
        ["AEGIS_MODEL_API_KEY=sk-test-not-real", "AEGIS_MODEL_BASE_URL=http://127.0.0.1:14000/v1"],
    )
    _, port, base_url, _ = identity(root)
    assert port == "14000", "the port ultron already calls is the port to publish"
    assert base_url.endswith(":14000")


def test_the_default_port_is_4000(tmp_path: Path) -> None:
    root = checkout(tmp_path, ["AEGIS_MODEL_API_KEY=sk-test-not-real"])
    _, port, base_url, _ = identity(root)
    assert (port, base_url) == ("4000", "http://127.0.0.1:4000")


def test_the_shell_environment_still_wins(tmp_path: Path) -> None:
    root = checkout(
        tmp_path,
        ["AEGIS_LLM_GATEWAY_PORT=14123", "AEGIS_MODEL_BASE_URL=http://127.0.0.1:14123/v1"],
    )
    _, port, _, _ = identity(root, env={"AEGIS_LLM_GATEWAY_PORT": "19999"})
    assert port == "19999", "a deliberate one-off run may override .env, and says so in the report"


def test_the_project_name_comes_from_dot_env(tmp_path: Path) -> None:
    root = checkout(
        tmp_path,
        [
            "AEGIS_LLM_GATEWAY_PROJECT=aegis-llm-gateway-b",
            "AEGIS_LLM_GATEWAY_PORT=14124",
        ],
    )
    project, _, _, container = identity(root)
    assert (project, container) == ("aegis-llm-gateway-b", "aegis-llm-gateway-b-gateway")


def test_a_busy_port_is_refused_with_its_name_and_the_fix(tmp_path: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = int(busy.getsockname()[1])
        root = checkout(tmp_path, [f"AEGIS_LLM_GATEWAY_PORT={port}"])
        result = run(root, ". scripts/llm-gateway/lib.sh; require_port_free")
    assert result.returncode != 0
    assert f"port {port} on 127.0.0.1 is already in use" in result.stderr, result.stderr
    assert "AEGIS_LLM_GATEWAY_PORT=<free port>" in result.stderr, (
        "the refusal must say which .env line to change"
    )
    assert "AEGIS_MODEL_BASE_URL=http://127.0.0.1:<free port>/v1" in result.stderr


def test_a_free_port_passes(tmp_path: Path) -> None:
    root = checkout(tmp_path, [f"AEGIS_LLM_GATEWAY_PORT={free_port()}"])
    result = run(root, ". scripts/llm-gateway/lib.sh; require_port_free")
    assert result.returncode == 0, result.stderr


def test_a_base_url_on_another_port_is_refused(tmp_path: Path) -> None:
    root = checkout(
        tmp_path,
        [
            "AEGIS_LLM_GATEWAY_PORT=14123",
            "AEGIS_MODEL_BASE_URL=http://127.0.0.1:4000/v1",
        ],
    )
    result = run(root, ". scripts/llm-gateway/lib.sh; require_model_base_url")
    assert result.returncode != 0
    assert "http://127.0.0.1:14123/v1" in result.stderr, result.stderr
    assert "http://127.0.0.1:4000/v1" in result.stderr, "the refusal names what is configured"
    assert "AEGIS_MODEL_BASE_URL=http://127.0.0.1:14123/v1" in result.stderr, (
        "and the exact line that fixes it"
    )


def test_a_matching_or_absent_base_url_passes(tmp_path: Path) -> None:
    matching = checkout(
        tmp_path / "matching",
        [
            "AEGIS_LLM_GATEWAY_PORT=14123",
            "AEGIS_MODEL_BASE_URL=http://localhost:14123/v1/",
        ],
    )
    assert run(matching, ". scripts/llm-gateway/lib.sh; require_model_base_url").returncode == 0
    absent = checkout(tmp_path / "absent", ["AEGIS_LLM_GATEWAY_PORT=14123"])
    assert run(absent, ". scripts/llm-gateway/lib.sh; require_model_base_url").returncode == 0
