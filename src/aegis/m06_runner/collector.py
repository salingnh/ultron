"""Output collector of one sandbox job (M06; interfaces/README.md §2, G0.2 proven shape).

Scanner output is hostile data. The collector

* walks the output directory itself (no shelling out) and never follows a symlink,
* accepts only regular files; FIFO/socket/device/symlink entries are skipped and reported,
* enforces the byte and file-count caps while walking, before reading anything into memory,
* refuses an archive whose *declared* uncompressed size exceeds the cap (zip bomb) without
  decompressing it,
* hashes every accepted file with SHA-256 and names it with a `local_ref` the parser can use.

A cap violation is `CollectionError`: the job is rejected instead of silently trimmed.
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
MAX_LOCAL_REF = 64


class CollectionError(RuntimeError):
    """Hard failure: the job output must be rejected, not silently trimmed."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CollectedFile:
    """One accepted output file; `local_ref` is what parser results and envelopes reference."""

    relative_path: str
    local_ref: str
    size_bytes: int
    sha256: str
    media_type: str


@dataclass
class CollectionResult:
    files: list[CollectedFile] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def local_refs(self) -> list[str]:
        return [item.local_ref for item in self.files]

    def by_local_ref(self) -> dict[str, CollectedFile]:
        return {item.local_ref: item for item in self.files}


def relpath_slug(path: str) -> str:
    """Contract `local_ref` form: `^[a-z0-9_-]{1,64}$`."""
    slug = "".join(char if char.isalnum() else "-" for char in path).strip("-").lower()
    return (slug or "file")[:MAX_LOCAL_REF]


def _media_type(path: Path) -> str:
    return MEDIA_TYPES.get(path.suffix.lower(), "application/octet-stream")


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
            with path.open("rb") as handle:
                handle.seek(-4, os.SEEK_END)
                (isize,) = struct.unpack("<I", handle.read(4))
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
    """Collect regular files under `output_dir` within the hard caps."""
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
                    result.skipped.append({"path": str(path), "reason": "NOT_REGULAR_FILE"})
                    continue
                seen_files += 1
                if seen_files > max_files:
                    raise CollectionError("OUTPUT_FILE_COUNT_EXCEEDED", f"> {max_files} files")
                size = entry.stat(follow_symlinks=False).st_size
                result.total_bytes += size
                if result.total_bytes > max_bytes:
                    raise CollectionError("OUTPUT_BYTES_EXCEEDED", f"> {max_bytes} bytes")
                if max_uncompressed_bytes is not None:
                    declared = declared_uncompressed_bytes(path)
                    if declared is not None and declared > max_uncompressed_bytes:
                        raise CollectionError(
                            "OUTPUT_ARCHIVE_EXPANSION_EXCEEDED",
                            f"{path.name} declares {declared} bytes",
                        )
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    while True:
                        chunk = handle.read(READ_CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk)
                relative = str(path.relative_to(output_dir))
                result.files.append(
                    CollectedFile(
                        relative_path=relative,
                        local_ref=relpath_slug(relative),
                        size_bytes=size,
                        sha256=digest.hexdigest(),
                        media_type=_media_type(path),
                    )
                )
    result.files.sort(key=lambda item: item.relative_path)
    if len({item.local_ref for item in result.files}) != len(result.files):
        raise CollectionError(
            "OUTPUT_LOCAL_REF_COLLISION",
            "two output files map to the same local_ref after slugging",
        )
    return result
