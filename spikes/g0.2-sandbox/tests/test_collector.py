"""Collector tests: hostile output must be skipped or rejected, never followed."""

from __future__ import annotations

import gzip
import io
import os
import zipfile
from pathlib import Path

import pytest

from aegis_g02.collector import CollectionError, collect


def test_regular_files_are_hashed_and_capped(tmp_path: Path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.jsonl").write_text('{"a":1}\n')
    (tmp_path / "sub" / "b.txt").write_text("hello")
    result = collect(tmp_path, max_bytes=1024, max_files=10)
    assert [f.relative_path for f in result.files] == ["a.jsonl", "sub/b.txt"]
    assert all(len(f.sha256) == 64 for f in result.files)
    assert result.files[0].media_type == "application/x-ndjson"


def test_symlink_is_not_followed(tmp_path: Path):
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("SECRET")
    (tmp_path / "link.txt").symlink_to(outside)
    (tmp_path / "real.txt").write_text("ok")
    result = collect(tmp_path, max_bytes=1024, max_files=10)
    assert [f.relative_path for f in result.files] == ["real.txt"]
    assert any(s["reason"] == "SYMLINK" for s in result.skipped)


def test_symlinked_directory_is_not_traversed(tmp_path: Path):
    target = tmp_path.parent / "outside-dir"
    target.mkdir(exist_ok=True)
    (target / "loot.txt").write_text("SECRET")
    (tmp_path / "dirlink").symlink_to(target, target_is_directory=True)
    (tmp_path / "file.txt").write_text("ok")
    result = collect(tmp_path, max_bytes=1024, max_files=10)
    assert [f.relative_path for f in result.files] == ["file.txt"]
    assert any(s["reason"] == "SYMLINK" for s in result.skipped)


def test_fifo_and_socket_are_skipped(tmp_path: Path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    result = collect(tmp_path, max_bytes=1024, max_files=10)
    assert result.files == []
    assert any(s["reason"] == "NOT_REGULAR_FILE" for s in result.skipped)
    assert not any(f.relative_path == "pipe" for f in result.files)


def test_byte_cap_rejects_the_job(tmp_path: Path):
    (tmp_path / "big.bin").write_bytes(b"x" * 2048)
    with pytest.raises(CollectionError) as exc:
        collect(tmp_path, max_bytes=1024, max_files=10)
    assert exc.value.code == "OUTPUT_BYTES_EXCEEDED"


def test_file_count_cap_rejects_the_job(tmp_path: Path):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("x")
    with pytest.raises(CollectionError) as exc:
        collect(tmp_path, max_bytes=1024 * 1024, max_files=4)
    assert exc.value.code == "OUTPUT_FILE_COUNT_EXCEEDED"


def test_zip_bomb_declared_size_rejected_before_extraction(tmp_path: Path):
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros.bin", b"\0" * (64 * 1024 * 1024))
    assert bomb.stat().st_size < 200_000  # compressed small, expands to 64 MiB
    with pytest.raises(CollectionError) as exc:
        collect(
            tmp_path,
            max_bytes=1024 * 1024,
            max_files=10,
            max_uncompressed_bytes=8 * 1024 * 1024,
        )
    assert exc.value.code == "OUTPUT_ARCHIVE_EXPANSION_EXCEEDED"


def test_gzip_declared_size_rejected(tmp_path: Path):
    gz = tmp_path / "big.gz"
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as fh:
        fh.write(b"\0" * (16 * 1024 * 1024))
    gz.write_bytes(buf.getvalue())
    with pytest.raises(CollectionError) as exc:
        collect(
            tmp_path,
            max_bytes=1024 * 1024,
            max_files=10,
            max_uncompressed_bytes=1024 * 1024,
        )
    assert exc.value.code == "OUTPUT_ARCHIVE_EXPANSION_EXCEEDED"


def test_missing_output_dir_is_rejected(tmp_path: Path):
    with pytest.raises(CollectionError) as exc:
        collect(tmp_path / "nope", max_bytes=1024, max_files=10)
    assert exc.value.code == "OUTPUT_DIR_MISSING"
