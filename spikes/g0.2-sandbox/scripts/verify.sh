#!/usr/bin/env bash
# G0.2 verify script: unit tests, then Podman isolation tests, then host facts.
set -euo pipefail
cd "$(dirname "$0")/.."

VENV=${VENV:-.venv}
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r requirements.txt
fi

export G02_REPO_ROOT=${G02_REPO_ROOT:-$(cd ../.. && pwd)}
echo "== repo root: $G02_REPO_ROOT"

echo "== unit tests"
"$VENV/bin/python" -m pytest tests -q -m "not integration"

echo "== podman integration tests"
podman info --format '{{.Host.CgroupVersion}} {{.Host.CgroupManager}}'
G02_PODMAN=1 "$VENV/bin/python" -m pytest tests -q -m integration

echo "== host facts"
echo "kernel:      $(uname -r)"
echo "os:          $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "podman:      $(podman --version)"
echo "net backend: $(podman info --format '{{.Host.NetworkBackend}}')"
echo "controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"
echo "delegated:   $(cat "/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers" 2>/dev/null || echo 'n/a')"
echo "selinux:     $(getenforce 2>/dev/null || echo 'n/a')"
