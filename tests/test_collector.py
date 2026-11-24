"""The collector treats scanner output as hostile data (G0.2 suite, ported to M06).

No Podman here: the output directory is a temp dir built by the test, which is exactly the state
the collector sees after a container stops.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import zipfile
from pathlib import Path

import pytest

from aegis.m06_runner import collector
from aegis.m06_runner.collector import CollectionError


def _write(path: Path, size: int = 16) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


def test_collects_regular_files_with_hash_and_local_ref(tmp_path: Path) -> None:
    _write(tmp_path / "result.jsonl", 10)
    _write(tmp_path / "nested" / "http.json", 5)
    result = collector.collect(tmp_path, max_bytes=1024, max_files=10)
    assert [item.relative_path for item in result.files] == ["nested/http.json", "result.jsonl"]
    assert result.total_bytes == 15
    for item in result.files:
        assert (
            hashlib.sha256((tmp_path / item.relative_path).read_bytes()).hexdigest() == item.sha256
        )
        assert item.local_ref == collector.relpath_slug(item.relative_path)
    assert result.by_local_ref()["result-jsonl"].relative_path == "result.jsonl"


def test_symlinked_file_is_skipped_never_followed(tmp_path: Path) -> None:
    _write(tmp_path / "real.txt", 4)
    (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    (tmp_path / "outside.txt").symlink_to("/etc/passwd")
    result = collector.collect(tmp_path, max_bytes=1024, max_files=10)
    assert [item.relative_path for item in result.files] == ["real.txt"]
    assert {entry["reason"] for entry in result.skipped} == {"SYMLINK"}
    assert len(result.skipped) == 2


def test_symlinked_directory_is_skipped(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"outside-{os.getpid()}"
    _write(outside / "secret.txt", 8)
    root = tmp_path / "out"
    root.mkdir()
    (root / "dir-link").symlink_to(outside)
    result = collector.collect(root, max_bytes=1024, max_files=10)
    assert result.files == []
    assert result.skipped[0]["reason"] == "SYMLINK"


def test_fifo_is_skipped_without_opening_it(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    result = collector.collect(tmp_path, max_bytes=1024, max_files=10)
    assert result.files == []
    assert result.skipped[0]["reason"] == "NOT_REGULAR_FILE"


def test_byte_cap_rejects_the_job(tmp_path: Path) -> None:
    _write(tmp_path / "big.bin", 100)
    with pytest.raises(CollectionError) as caught:
        collector.collect(tmp_path, max_bytes=10, max_files=10)
    assert caught.value.code == "OUTPUT_BYTES_EXCEEDED"


def test_file_count_cap_rejects_the_job(tmp_path: Path) -> None:
    for index in range(3):
        _write(tmp_path / f"f{index}.txt", 1)
    with pytest.raises(CollectionError) as caught:
        collector.collect(tmp_path, max_bytes=1024, max_files=2)
    assert caught.value.code == "OUTPUT_FILE_COUNT_EXCEEDED"


def test_zip_bomb_is_refused_from_the_declared_size(tmp_path: Path) -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb.txt", b"\0" * (8 * 1024 * 1024))
    (tmp_path / "bomb.zip").write_bytes(payload.getvalue())
    with pytest.raises(CollectionError) as caught:
        collector.collect(
            tmp_path, max_bytes=1024 * 1024, max_files=10, max_uncompressed_bytes=1024
        )
    assert caught.value.code == "OUTPUT_ARCHIVE_EXPANSION_EXCEEDED"


def test_gzip_declared_size_is_checked_too(tmp_path: Path) -> None:
    (tmp_path / "big.gz").write_bytes(gzip.compress(b"\0" * (4 * 1024 * 1024)))
    with pytest.raises(CollectionError) as caught:
        collector.collect(
            tmp_path, max_bytes=1024 * 1024, max_files=10, max_uncompressed_bytes=1024
        )
    assert caught.value.code == "OUTPUT_ARCHIVE_EXPANSION_EXCEEDED"


def test_missing_output_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(CollectionError) as caught:
        collector.collect(tmp_path / "absent", max_bytes=1, max_files=1)
    assert caught.value.code == "OUTPUT_DIR_MISSING"


def test_two_paths_with_the_same_local_ref_are_refused(tmp_path: Path) -> None:
    _write(tmp_path / "a.b", 1)
    _write(tmp_path / "a-b", 1)
    with pytest.raises(CollectionError) as caught:
        collector.collect(tmp_path, max_bytes=1024, max_files=10)
    assert caught.value.code == "OUTPUT_LOCAL_REF_COLLISION"


def test_local_ref_matches_the_contract_pattern(tmp_path: Path) -> None:
    _write(tmp_path / "Result File.JSONL", 3)
    result = collector.collect(tmp_path, max_bytes=1024, max_files=10)
    assert result.files[0].local_ref == "result-file-jsonl"
    assert result.files[0].media_type == "application/x-ndjson"
