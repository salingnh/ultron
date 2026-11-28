#!/usr/bin/env bash
# Provision the offline vulnerability database of Grype (G2-D) and pin it.
#
# Network happens HERE, once, on the deployment host. A scan job runs with `networkAccess: none`
# and mounts this directory read-only at `/db`; M06 refuses a Grype job whose pinned file digest no
# longer matches, and the tool names the DB build it used (`grype-db@<built>`) in its own report,
# so a re-downloaded database cannot silently change a finding.
#
#   scripts/artifact/grype-db.sh                            # download/update if missing, then pin
#   AEGIS_GRYPE_DB_REFRESH=1 scripts/artifact/grype-db.sh   # force a re-download
#
# Output: deploy/lab/.run/artifact/grype-db/{6/vulnerability.db,...} (git-ignored) and the
# `pinnedInputs` of the Grype job entry in deploy/lab/runner-profile.json.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

IMAGES_ENV="deploy/lab/images.env"
PROFILE="deploy/lab/runner-profile.json"
STORE="$ROOT/deploy/lab/.run/artifact/grype-db"

# shellcheck disable=SC1090
source "$IMAGES_ENV"
if [[ -z "${AEGIS_LAB_GRYPE_IMAGE:-}" ]]; then
    echo "error: $IMAGES_ENV sets no AEGIS_LAB_GRYPE_IMAGE" >&2
    exit 1
fi
IMAGE="$AEGIS_LAB_GRYPE_IMAGE"
DIGEST="${IMAGE##*@}"
if ! podman image exists "$IMAGE"; then
    echo "error: $IMAGE is not in the local image store; pull that exact digest first" >&2
    exit 1
fi

mkdir -p "$STORE"
chmod 0777 "$STORE"

if [[ "${AEGIS_GRYPE_DB_REFRESH:-0}" == "1" || ! -f "$STORE/6/vulnerability.db" ]]; then
    echo "downloading the Grype vulnerability DB (network, once)..."
    podman run --rm -q -e GRYPE_DB_CACHE_DIR=/db -v "$STORE:/db:z" "$IMAGE" db update
fi
chmod -R a+rX "$STORE"

BUILT=$(podman run --rm -q -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_DB_AUTO_UPDATE=false \
    -v "$STORE:/db:z" "$IMAGE" db status | sed -n 's/^Built:[[:space:]]*//p' | head -1)
if [[ -z "$BUILT" ]]; then
    echo "error: grype db status printed no build time; refusing to pin an unknown DB" >&2
    exit 1
fi

python3 - "$STORE" "$PROFILE" "$DIGEST" "$BUILT" <<'PY'
import json
import sys
from hashlib import sha256
from pathlib import Path

store = Path(sys.argv[1])
profile_path = Path(sys.argv[2])
image_digest = sys.argv[3]
built = sys.argv[4]


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


database = store / "6" / "vulnerability.db"
if not database.is_file():
    raise SystemExit(f"missing {database}")

pins = [
    {
        "target": "/db",
        "file": "6/vulnerability.db",
        "sha256": file_sha256(database),
        "ruleSet": "grype-db@" + built,
    }
]
profile = json.loads(profile_path.read_text(encoding="utf-8"))
updated = 0
for entry in profile.get("jobs") or []:
    if entry.get("imageDigest") == image_digest:
        entry["pinnedInputs"] = pins
        updated += 1
if updated != 1:
    raise SystemExit(f"{profile_path}: expected one job entry for {image_digest}, found {updated}")
profile_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
print("pinned", pins[0]["ruleSet"], "->", profile_path)
PY

ls -lh "$STORE/6/vulnerability.db"
echo "done: the scan mounts this read-only; it never downloads and never runs the target image."
