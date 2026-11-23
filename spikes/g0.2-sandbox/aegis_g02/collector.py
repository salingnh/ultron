"""Output collector for one sandbox job (spike G0.2).

Scanner output is hostile data. The collector:
  * walks the output directory itself (no shelling out, no following symlinks),
  * only accepts regular files; FIFO/socket/device/symlink entries are skipped
    and reported, never opened,
  * enforces a byte cap and a file-count cap while walking (fail fast, before
    reading anything into memory),
  * rejects compressed files whose *declared* uncompressed size exceeds the
    configured cap (zip bomb) before anything would decompress them,
  * hashes every accepted file with SHA-256 for the evidence store.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

MEDIA_TYPES = {
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".ndjson": "application/x-ndjson",
    ".txt": "text/plain",
    ".xml": "application/xml",
    ".csv": "text/csv",
    ".log": "text/plain",
    ".zip": "application/zip",
    ".gz": "application/gzip",
    ".sarif": "application/sarif+json",
}
READ_CHUNK = 1 << 20


class CollectionError(RuntimeError):
    """Hard failure: the job output must be rejected, not silently trimmed."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CollectedFile:
    relative_path: str
    size_bytes: int
    sha256: str
    media_type: str


@dataclass
class CollectionResult:
    files: list[CollectedFile] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def local_refs(self) -> list[str]:
        return [f.relpath_slug(f.relative_path) for f in self.files]


def relpath_slug(path: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in path).strip("-").lower()
    return (slug or "file")[:64]


def _media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    return MEDIA_TYPES.get(suffix, "application/octet-stream")


def declared_uncompressed_bytes(path: Path) -> int | None:
    """Uncompressed size a zip/gzip claims without extracting anything."""
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                return sum(info.file_size for info in archive.infolist())
    except (OSError, zipfile.BadZipFile):
        return None
    if path.suffix.lower() == ".gz":
        try:
            with path.open("rb") as fh:
                fh.seek(-4, os.SEEK_END)
                (isize,) = struct.unpack("<I", fh.read(4))
            return int(isize)
        except (OSError, struct.error):
            return None
    return None


def collect(
    output_dir: Path,
    *,
    max_bytes: int,
    max_files: int,
    max_uncompressed_bytes: int | None = None,
) -> CollectionResult:
    """Collect regular files under ``output_dir`` within the hard caps."""
    if not output_dir.is_dir():
        raise CollectionError("OUTPUT_DIR_MISSING", str(output_dir))
    result = CollectionResult()
    seen_files = 0
    stack: list[Path] = [output_dir]
    while stack:
        current = stack.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                path = Path(entry.path)
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    result.skipped.append({"path": str(path), "reason": "SYMLINK"})
                    continue
                if stat.S_ISDIR(mode):
                    stack.append(path)
                    continue
                if not stat.S_ISREG(mode):
                    result.skipped.append(
                        {"path": str(path), "reason": "NOT_REGULAR_FILE"}
                    )
                    continue
                seen_files += 1
                if seen_files > max_files:
                    raise CollectionError(
                        "OUTPUT_FILE_COUNT_EXCEEDED", f"> {max_files} files"
                    )
                size = entry.stat(follow_symlinks=False).st_size
                result.total_bytes += size
                if result.total_bytes > max_bytes:
                    raise CollectionError(
                        "OUTPUT_BYTES_EXCEEDED", f"> {max_bytes} bytes"
                    )
                if max_uncompressed_bytes is not None:
                    declared = declared_uncompressed_bytes(path)
                    if declared is not None and declared > max_uncompressed_bytes:
                        raise CollectionError(
                            "OUTPUT_ARCHIVE_EXPANSION_EXCEEDED",
                            f"{path.name} declares {declared} bytes",
                        )
                digest = hashlib.sha256()
                with path.open("rb") as fh:
                    while True:
                        chunk = fh.read(READ_CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk)
                result.files.append(
                    CollectedFile(
                        relative_path=str(path.relative_to(output_dir)),
                        size_bytes=size,
                        sha256=digest.hexdigest(),
                        media_type=_media_type(path),
                    )
                )
    result.files.sort(key=lambda f: f.relative_path)
    return result
