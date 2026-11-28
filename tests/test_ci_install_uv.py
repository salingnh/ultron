"""`scripts/ci/install-uv.sh` installs only the uv release `scripts/ci/uv.env` pins.

The download is faked with a `curl` stub, so these tests need no network: they hold the checksum
and version checks, which are what keep the Python gate from running another tool than the pinned
one.
"""

import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

CI_DIR = Path(__file__).resolve().parents[1] / "scripts" / "ci"
MEMBER = "uv-x86_64-unknown-linux-gnu/uv"


def release_archive(reported_version: str) -> bytes:
    script = f"#!/bin/sh\necho 'uv {reported_version} (x86_64-unknown-linux-gnu)'\n".encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        member = tarfile.TarInfo(MEMBER)
        member.size = len(script)
        member.mode = 0o755
        archive.addfile(member, io.BytesIO(script))
    return buffer.getvalue()


def install(
    tmp_path: Path, served: bytes, pinned_sha256: str
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run a copy of the installer against its own pin file, with `curl` serving `served`."""
    scripts = tmp_path / "ci"
    scripts.mkdir()
    shutil.copy2(CI_DIR / "install-uv.sh", scripts / "install-uv.sh")
    (scripts / "uv.env").write_text(
        f"AEGIS_UV_VERSION=9.9.9\nAEGIS_UV_SHA256={pinned_sha256}\n", encoding="utf-8"
    )
    release = tmp_path / "release.tar.gz"
    release.write_bytes(served)
    stubs = tmp_path / "bin"
    stubs.mkdir()
    curl = stubs / "curl"
    curl.write_text(
        '#!/bin/sh\nwhile [ "$1" != "-o" ]; do shift; done\n'
        f'cp "{release}" "$2"\necho "$3" > "{tmp_path}/url"\n',
        encoding="utf-8",
    )
    curl.chmod(0o755)
    destination = tmp_path / "dest"
    destination.mkdir()
    result = subprocess.run(
        [str(scripts / "install-uv.sh"), str(destination)],
        env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
    )
    return result, destination


def test_the_pin_names_one_release_and_its_sha256() -> None:
    pin = (CI_DIR / "uv.env").read_text(encoding="utf-8")

    assert re.search(r"^AEGIS_UV_VERSION=\d+\.\d+\.\d+$", pin, re.MULTILINE)
    assert re.search(r"^AEGIS_UV_SHA256=[0-9a-f]{64}$", pin, re.MULTILINE)


def test_the_pinned_release_is_installed(tmp_path: Path) -> None:
    served = release_archive("9.9.9")

    result, destination = install(tmp_path, served, hashlib.sha256(served).hexdigest())

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(destination / "uv")
    assert (tmp_path / "url").read_text(encoding="utf-8").strip() == (
        "https://github.com/astral-sh/uv/releases/download/9.9.9/uv-x86_64-unknown-linux-gnu.tar.gz"
    )


def test_a_download_with_another_checksum_is_never_unpacked(tmp_path: Path) -> None:
    result, destination = install(tmp_path, release_archive("9.9.9"), "0" * 64)

    assert result.returncode != 0
    assert "checksum" in result.stderr
    assert not (destination / "uv").exists()


def test_a_binary_that_is_not_the_pinned_version_is_refused(tmp_path: Path) -> None:
    served = release_archive("9.9.8")

    result, _ = install(tmp_path, served, hashlib.sha256(served).hexdigest())

    assert result.returncode != 0
    assert "9.9.9" in result.stderr
    assert result.stdout == ""
