#!/usr/bin/env bash
# Does this change affect the `python` or the `ui` workflow? Writes run=true|false to
# $GITHUB_OUTPUT; the workflow keeps its job (so its check always reports) and skips the steps.
#
#   scripts/ci/job-scope.sh python|ui
#
# Only a pull request is ever skipped: push and workflow_dispatch run everything. The checkout of a
# pull request is its merge commit, so HEAD^1..HEAD is the whole pull request against its base
# (needs `fetch-depth: 2`). A path no rule names affects both jobs; any error fails the step.
set -euo pipefail

job=${1:-}
[[ $job == python || $job == ui ]] || {
  echo "usage: job-scope.sh python|ui" >&2
  exit 2
}

# Prints the jobs a path affects. The first matching rule wins.
affected_jobs() {
  local path=$1
  case $path in
  # Shared inputs. Every file under contracts/ counts: the contract gate plan, the graph model
  # and the schemas are read by the gates, Markdown included.
  contracts/* | ui/src/api/schema.ts | src/aegis/contracts_gen/* | scripts/* | .github/* | Makefile)
    echo "python ui"
    ;;
  # Read by Python tests whatever the file type (tests/test_python_pin.py scans deploy/).
  src/* | tests/* | deploy/*) echo "python" ;;
  # Documentation no gate reads.
  README.md | */README.md | docs/*.md) ;;
  ui/*) echo "ui" ;;
  adapters/* | pyproject.toml | uv.lock | .python-version) echo "python" ;;
  *)
    # Top-level Markdown is documentation too.
    if [[ $path != */* && $path == *.md ]]; then return; fi
    echo "python ui"
    ;;
  esac
}

run=true
if [[ ${GITHUB_EVENT_NAME:?} == pull_request ]]; then
  git rev-parse --verify --quiet 'HEAD^2' >/dev/null || {
    echo "job-scope: HEAD is not a pull request merge commit with its parents (fetch-depth: 2)" >&2
    exit 1
  }
  changed=$(mktemp)
  trap 'rm -f "$changed"' EXIT
  # Without rename detection a moved file counts at both its old and its new path.
  git diff --name-only --no-renames -z 'HEAD^1' HEAD >"$changed"
  run=false
  while IFS= read -r -d '' path; do
    if [[ " $(affected_jobs "$path") " == *" $job "* ]]; then
      echo "job-scope: $path affects $job"
      run=true
    fi
  done <"$changed"
fi

echo "job-scope: $job run=$run"
echo "run=$run" >>"${GITHUB_OUTPUT:?}"
