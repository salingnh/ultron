#!/usr/bin/env bash
# Provision the offline vulnerability databases of the artifact scanner (G2-D) and pin them.
#
# Network happens HERE, once, on the deployment host. A scan job runs with `networkAccess: none`
# and mounts these directories read-only; M06 refuses an artifact job whose pinned file digests no
# longer match, so a re-downloaded or edited database can never change a finding silently.
#
#   scripts/artifact/trivy-db.sh            # download/update if missing, then pin
#   AEGIS_TRIVY_DB_REFRESH=1 scripts/artifact/trivy-db.sh   # force a re-download
#
# Outputs (all git-ignored):
#   deploy/lab/.run/artifact/trivy-db/db/{trivy.db,metadata.json}
#   deploy/lab/.run/artifact/trivy-db/java-db/{trivy-java.db,metadata.json}
# and rewrites the `pinnedInputs` of the Trivy job entry in deploy/lab/runner-profile.json with the
# sha256 of each database file and the `UpdatedAt` of its metadata (the rule set label).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

IMAGES_ENV="deploy/lab/images.env"
PROFILE="deploy/lab/runner-profile.json"
STORE="deploy/lab/.run/artifact/trivy-db"

# shellcheck disable=SC1090
source "$IMAGES_ENV"
if [[ -z "${AEGIS_LAB_TRIVY_IMAGE:-}" ]]; then
    echo "error: $IMAGES_ENV sets no AEGIS_LAB_TRIVY_IMAGE" >&2
    exit 1
fi
# images.env carries the full reference (`repo:tag@sha256:...`); the digest is the authority here.
IMAGE="$AEGIS_LAB_TRIVY_IMAGE"
DIGEST="${IMAGE##*@}"
if ! podman image exists "$IMAGE"; then
    echo "error: $IMAGE is not in the local image store; pull that exact digest first" >&2
    exit 1
fi

mkdir -p "$STORE/db" "$STORE/java-db"
chmod 0755 "$STORE" "$STORE/db" "$STORE/java-db"

if [[ "${AEGIS_TRIVY_DB_REFRESH:-0}" == "1" || ! -f "$STORE/db/trivy.db" ]]; then
    echo "downloading the vulnerability DB (network, once)..."
    podman run --rm -q -v "$STORE:/db:z" "$IMAGE" image --download-db-only --cache-dir /db
fi
if [[ "${AEGIS_TRIVY_DB_REFRESH:-0}" == "1" || ! -f "$STORE/java-db/trivy-java.db" ]]; then
    echo "downloading the Java DB (network, once)..."
    podman run --rm -q -v "$STORE:/db:z" "$IMAGE" image --download-java-db-only --cache-dir /db
fi
chmod -R a+rX "$STORE"

python3 - "$STORE" "$PROFILE" "$DIGEST" <<'PY'
import json
import sys
from datetime import datetime
from hashlib import sha256
from pathlib import Path

store = Path(sys.argv[1])
profile_path = Path(sys.argv[2])
image_digest = sys.argv[3]


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def updated_at(path: Path) -> str:
    document = json.loads(path.read_text(encoding="utf-8"))
    value = str(document.get("UpdatedAt") or "")
    if not value:
        raise SystemExit(f"{path} has no UpdatedAt")
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


vuln_db = store / "db" / "trivy.db"
java_db = store / "java-db" / "trivy-java.db"
for path in (vuln_db, java_db):
    if not path.is_file():
        raise SystemExit(f"missing {path}")

pins = [
    {
        "target": "/cache/db",
        "file": "trivy.db",
        "sha256": file_sha256(vuln_db),
        "ruleSet": "trivy-db@" + updated_at(store / "db" / "metadata.json"),
    },
    {
        "target": "/cache/java-db",
        "file": "trivy-java.db",
        "sha256": file_sha256(java_db),
    },
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

ls -lh "$STORE/db/trivy.db" "$STORE/java-db/trivy-java.db"
echo "done: the scan mounts these read-only; it never downloads and never runs the target image."
