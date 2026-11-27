"""Path-based job skipping of the `python` and `ui` workflows (`scripts/ci/job-scope.sh`)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/ci/job-scope.sh"
BOTH = {"python", "ui"}
NEITHER: set[str] = set()


def git(repo: Path, *args: str) -> None:
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", *identity, *args], cwd=repo, check=True, capture_output=True)


def write(repo: Path, path: str, text: str) -> None:
    (repo / path).parent.mkdir(parents=True, exist_ok=True)
    (repo / path).write_text(text, encoding="utf-8")


def pull_request_checkout(
    tmp_path: Path, changed: list[str], *, renamed: tuple[str, str] | None = None
) -> Path:
    """The merge commit GitHub checks out for a pull request: HEAD^1 is the base branch."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "base")
    write(repo, "seed", "seed\n")
    if renamed is not None:
        write(repo, renamed[0], "moved\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    git(repo, "checkout", "-qb", "topic")
    for path in changed:
        write(repo, path, "changed\n")
    if renamed is not None:
        (repo / renamed[1]).parent.mkdir(parents=True, exist_ok=True)
        git(repo, "mv", renamed[0], renamed[1])
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "topic")
    git(repo, "checkout", "-q", "base")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "topic")
    return repo


def scope(repo: Path, job: str, event: str = "pull_request") -> subprocess.CompletedProcess[str]:
    output = repo.parent / f"output-{job}"
    output.write_text("", encoding="utf-8")
    environment = {**os.environ, "GITHUB_EVENT_NAME": event, "GITHUB_OUTPUT": str(output)}
    completed = subprocess.run(
        ["bash", str(SCRIPT), job], cwd=repo, capture_output=True, text=True, env=environment
    )
    completed.stdout = output.read_text(encoding="utf-8")
    return completed


def jobs_that_run(repo: Path, event: str = "pull_request") -> set[str]:
    running = set()
    for job in sorted(BOTH):
        completed = scope(repo, job, event)
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout in {"run=true\n", "run=false\n"}
        if completed.stdout == "run=true\n":
            running.add(job)
    return running


@pytest.mark.parametrize(
    ("changed", "expected"),
    [
        # documentation no job reads
        (["README.md", "PROGRESS.md", "docs/s1/00-a.md", "docs/a/b/c.md"], NEITHER),
        (["ui/README.md", "adapters/m08/dnsx/README.md"], NEITHER),
        # Markdown a gate does read is not documentation
        (["contracts/README.md"], BOTH),
        (["contracts/graph/model.md"], BOTH),
        (["deploy/lab/README.md"], {"python"}),
        # one side only
        (["ui/src/App.tsx", "ui/package-lock.json"], {"ui"}),
        (["ui/e2e/screens.spec.ts", "docs/x.md"], {"ui"}),
        (["src/aegis/m05_registry/service.py"], {"python"}),
        (["tests/test_ids.py", "adapters/m08/dnsx/manifest.yaml"], {"python"}),
        (["pyproject.toml", "uv.lock", ".python-version"], {"python"}),
        (["deploy/dev/images.env"], {"python"}),
        (["ui/src/App.tsx", "src/aegis/common/ports.py"], BOTH),
        # shared inputs: contracts, codegen, the generated API schema, scripts, CI itself
        (["contracts/api/openapi.v2.yaml"], BOTH),
        (["ui/src/api/schema.ts"], BOTH),
        (["scripts/codegen.py"], BOTH),
        (["src/aegis/contracts_gen/api/a_v2_schema.py"], BOTH),
        (["scripts/ci/lib.sh"], BOTH),
        ([".github/workflows/ui.yml"], BOTH),
        (["Makefile"], BOTH),
        # a path nobody classified runs everything; so does a non-Markdown file under docs/
        (["new-top-level/file"], BOTH),
        (["docs/diagram.py"], BOTH),
        (["docs/name with space.md", "ui/a b.ts"], {"ui"}),
    ],
)
def test_a_pull_request_runs_the_jobs_its_paths_affect(
    tmp_path: Path, changed: list[str], expected: set[str]
) -> None:
    assert jobs_that_run(pull_request_checkout(tmp_path, changed)) == expected


def test_a_file_moved_out_of_a_tested_tree_still_runs_its_job(tmp_path: Path) -> None:
    repo = pull_request_checkout(tmp_path, [], renamed=("src/aegis/x.md", "docs/x.md"))
    assert jobs_that_run(repo) == {"python"}


@pytest.mark.parametrize("event", ["push", "workflow_dispatch"])
def test_only_pull_requests_are_ever_skipped(tmp_path: Path, event: str) -> None:
    assert jobs_that_run(pull_request_checkout(tmp_path, ["README.md"]), event) == BOTH


def test_a_checkout_that_is_not_the_merge_commit_fails_loudly(tmp_path: Path) -> None:
    repo = pull_request_checkout(tmp_path, ["src/a.py"])
    git(repo, "checkout", "-q", "topic")
    completed = scope(repo, "python")
    assert completed.returncode != 0
    assert completed.stdout == ""


def test_an_unknown_job_is_refused(tmp_path: Path) -> None:
    completed = scope(pull_request_checkout(tmp_path, ["README.md"]), "contracts")
    assert completed.returncode != 0
    assert completed.stdout == ""


@pytest.mark.parametrize("job", sorted(BOTH))
def test_the_workflow_keeps_its_job_and_gates_every_heavy_step(job: str) -> None:
    """The job itself always runs, so its check always reports; only its steps are skipped."""
    name = "ci.yml" if job == "python" else "ui.yml"
    text = (REPO / ".github/workflows" / name).read_text(encoding="utf-8")
    header, _, steps = text.partition("    steps:\n")
    assert "paths:" not in text and "paths-ignore:" not in text
    assert "steps.scope" not in header
    assert "fetch-depth: 2" in steps
    blocks = steps.split("      - name: ")[1:]
    assert f"run: scripts/ci/job-scope.sh {job}\n" in blocks[1]
    for block in blocks[2:]:
        assert "steps.scope.outputs.run == 'true'" in block, block.splitlines()[0]
