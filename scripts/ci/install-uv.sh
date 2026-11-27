#!/usr/bin/env bash
# Install the uv release pinned in uv.env into an existing directory and print the binary's path.
#
#   scripts/ci/install-uv.sh <directory>
#
# The archive is unpacked only after its SHA-256 equals the committed one. Linux x86_64 only, the
# platform of the self-hosted runner.
set -euo pipefail

die() {
  printf '[ci] error: %s\n' "$*" >&2
  exit 1
}

[[ $# == 1 && -d $1 ]] || die "usage: install-uv.sh <existing directory>"
DEST=$1
# shellcheck source=scripts/ci/uv.env
. "$(dirname "${BASH_SOURCE[0]}")/uv.env"

[[ $(uname -s)-$(uname -m) == Linux-x86_64 ]] ||
  die "uv.env pins the Linux x86_64 release, this host is $(uname -s)-$(uname -m)"

TARGET=uv-x86_64-unknown-linux-gnu
ARCHIVE="$DEST/$TARGET.tar.gz"
URL="https://github.com/astral-sh/uv/releases/download/$AEGIS_UV_VERSION/$TARGET.tar.gz"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$ARCHIVE" "$URL" ||
  die "cannot download $URL"
printf '%s  %s\n' "$AEGIS_UV_SHA256" "$ARCHIVE" | sha256sum --check --status ||
  die "checksum mismatch for $URL (expected sha256 $AEGIS_UV_SHA256)"
tar -xzf "$ARCHIVE" -C "$DEST" --strip-components=1 "$TARGET/uv"
rm -f "$ARCHIVE"

reported=$("$DEST/uv" --version)
[[ $reported == "uv $AEGIS_UV_VERSION "* || $reported == "uv $AEGIS_UV_VERSION" ]] ||
  die "uv.env pins $AEGIS_UV_VERSION but the release binary reports: $reported"
printf '%s\n' "$DEST/uv"
