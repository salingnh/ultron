"""The tunnel token is deployment state: a 0600 file outside the checkout (G1.6 slice E, follow-up).

These tests run the real resolver from `scripts/vulnlab/lib.sh` in a subshell, with a throwaway
default path so the machine's own token file can never influence them. The token value is never
printed by the resolver, so the assertions compare its sha256 and check that the sentinel string
never appears in stdout/stderr - the same property the operator relies on when the scripts fail.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "scripts" / "vulnlab" / "lib.sh"
SENTINEL = "cf-tunnel-sentinel-0123456789abcdef"
RESOLVE = """
set -euo pipefail
. "{lib}"
resolve_tunnel_token
printf 'SOURCE=%s\\n' "$TUNNEL_TOKEN_SOURCE"
if tunnel_enabled; then printf 'ENABLED=yes\\n'; else printf 'ENABLED=no\\n'; fi
printf 'HASH=%s\\n' "$(printf %s "${{AEGIS_VULNLAB_TUNNEL_TOKEN:-}}" | sha256sum | cut -d' ' -f1)"
"""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _resolve(**overrides: str) -> subprocess.CompletedProcess[str]:
    """Run the bash resolver with a clean token environment and a non-existent default path."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "AEGIS_VULNLAB_TUNNEL_TOKEN",
            "AEGIS_VULNLAB_TUNNEL_TOKEN_FILE",
            "AEGIS_VULNLAB_TUNNEL_TOKEN_FILE_DEFAULT",
        }
    }
    env["AEGIS_VULNLAB_TUNNEL_TOKEN_FILE_DEFAULT"] = str(
        Path(overrides.pop("default_file", "/nonexistent/ultron/default-token"))
    )
    env.update(overrides)
    return subprocess.run(  # noqa: S603 - a fixed command this repository owns
        ["bash", "-c", RESOLVE.format(lib=LIB)],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        check=False,
    )


def _write(path: Path, value: str, mode: int) -> str:
    path.write_text(value, encoding="utf-8")
    os.chmod(path, mode)
    return str(path)


def test_a_0600_file_is_the_token_source(tmp_path: Path) -> None:
    token_file = _write(tmp_path / "tunnel.token", SENTINEL + "\n", 0o600)
    completed = _resolve(AEGIS_VULNLAB_TUNNEL_TOKEN_FILE=token_file)
    assert completed.returncode == 0, completed.stderr
    assert f"SOURCE=file {token_file}" in completed.stdout
    assert "ENABLED=yes" in completed.stdout
    assert f"HASH={_digest(SENTINEL)}" in completed.stdout
    assert SENTINEL not in completed.stdout
    assert SENTINEL not in completed.stderr


def test_a_group_or_world_readable_file_is_refused(tmp_path: Path) -> None:
    for mode in (0o644, 0o640, 0o604):
        token_file = _write(tmp_path / f"tunnel-{mode:o}.token", SENTINEL, mode)
        completed = _resolve(AEGIS_VULNLAB_TUNNEL_TOKEN_FILE=token_file)
        assert completed.returncode != 0, f"mode {mode:o} was accepted"
        assert "refusing tunnel token file" in completed.stderr
        assert "chmod 600" in completed.stderr
        assert SENTINEL not in completed.stdout + completed.stderr


def test_a_missing_explicit_file_is_an_error_not_a_fallback(tmp_path: Path) -> None:
    completed = _resolve(
        AEGIS_VULNLAB_TUNNEL_TOKEN_FILE=str(tmp_path / "absent.token"),
        AEGIS_VULNLAB_TUNNEL_TOKEN=SENTINEL,
    )
    assert completed.returncode != 0
    assert "does not exist" in completed.stderr
    assert SENTINEL not in completed.stderr


def test_an_empty_file_is_refused(tmp_path: Path) -> None:
    token_file = _write(tmp_path / "empty.token", "\n", 0o600)
    completed = _resolve(AEGIS_VULNLAB_TUNNEL_TOKEN_FILE=token_file)
    assert completed.returncode != 0
    assert "is empty" in completed.stderr


def test_a_multi_line_token_is_refused(tmp_path: Path) -> None:
    token_file = _write(tmp_path / "multiline.token", SENTINEL[:10] + " " + SENTINEL[10:], 0o600)
    completed = _resolve(AEGIS_VULNLAB_TUNNEL_TOKEN_FILE=token_file)
    assert completed.returncode != 0
    assert "whitespace" in completed.stderr


def test_the_default_path_is_used_only_when_it_exists(tmp_path: Path) -> None:
    token_file = tmp_path / "default.token"
    token_file.write_text(SENTINEL, encoding="utf-8")
    os.chmod(token_file, 0o600)
    completed = _resolve(AEGIS_VULNLAB_TUNNEL_TOKEN_FILE_DEFAULT=str(token_file))
    assert completed.returncode == 0, completed.stderr
    assert f"SOURCE=file {token_file}" in completed.stdout
    assert "ENABLED=yes" in completed.stdout
    assert SENTINEL not in completed.stdout


def test_a_missing_default_keeps_the_lab_lab_only() -> None:
    completed = _resolve()
    assert completed.returncode == 0, completed.stderr
    assert "SOURCE=none" in completed.stdout
    assert "ENABLED=no" in completed.stdout


def test_the_environment_variable_is_a_documented_fallback() -> None:
    completed = _resolve(AEGIS_VULNLAB_TUNNEL_TOKEN=SENTINEL)
    assert completed.returncode == 0, completed.stderr
    assert "SOURCE=environment" in completed.stdout
    assert f"HASH={_digest(SENTINEL)}" in completed.stdout
    assert SENTINEL not in completed.stdout
