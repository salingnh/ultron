#!/usr/bin/env bash
# Compute the content-hashed tag for the internet-profile egress broker image and build it if absent.
#
# Usage:
#   scripts/dev/broker-image.sh --tag-only   # print localhost/aegis-broker:g16-<hash12>
#   scripts/dev/broker-image.sh              # build if missing and print the tag
#
# The hash covers the exact inputs copied/used by deploy/broker/Containerfile:
#   - deploy/broker/Containerfile
#   - src/aegis/__init__.py
#   - src/aegis/m06_runner/** (excluding __pycache__ and *.pyc)
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)

compute_hash() {
  python3 - "$REPO_ROOT" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
inputs: list[Path] = [
    root / "deploy" / "broker" / "Containerfile",
    root / "src" / "aegis" / "__init__.py",
]
runner_dir = root / "src" / "aegis" / "m06_runner"
for path in sorted(runner_dir.rglob("*")):
    if not path.is_file():
        continue
    if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
        continue
    inputs.append(path)

digest = hashlib.sha256()
for path in sorted(set(inputs), key=lambda p: p.relative_to(root).as_posix()):
    rel = path.relative_to(root).as_posix().encode("utf-8")
    digest.update(rel + b"\0")
    digest.update(path.read_bytes())
    digest.update(b"\0")

print(digest.hexdigest()[:12])
PY
}

HASH=$(compute_hash)
TAG="localhost/aegis-broker:g16-$HASH"

if [ "${1:-}" = "--tag-only" ]; then
  printf '%s\n' "$TAG"
  exit 0
fi

if ! podman image exists "$TAG" >/dev/null 2>&1; then
  echo "[dev] broker: building $TAG (deploy/broker/Containerfile)" >&2
  podman build --quiet --file "$REPO_ROOT/deploy/broker/Containerfile" --tag "$TAG" "$REPO_ROOT" >/dev/null
fi
printf '%s\n' "$TAG"
