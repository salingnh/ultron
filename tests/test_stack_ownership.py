"""A stack on a shared host belongs to the checkout that created it (scripts/lib/stack.sh).

The incident: two workers on one machine, each with a worktree of this repository. One ran
`make run-local`; `dev-up` found the project `aegis-dev` and recreated its containers from *its own*
compose file (different bind-mount paths), taking the other worker's walkthrough stack down. Nothing
checked who owned the project.

`scripts/lib/stack.sh` answers that with the labels podman-compose puts on every container
(`io.podman.compose.project.working_dir`, `...config_files`) plus the configuration fingerprint a
checkout records when it starts its stack, and `dev-up` / `dev-down` / `lab-up` / `lab-down` refuse
to touch a project another checkout owns or a configuration that changed. These tests drive the
shell functions with a stub `podman`, so no container is created or examined:

* another checkout's project is refused, with its path in the message (and the way out: a project
  name of your own);
* this checkout's own project is accepted, also when a configuration change is applied on purpose
  (`AEGIS_STACK_RECREATE=1`);
* a container whose owner cannot be proven is refused;
* a checkout can run its own isolated stack: `AEGIS_DEV_PROJECT` / `AEGIS_LAB_PROJECT` rename the
  project, its containers and the lab network, and the compose files template those names.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DEV_LIB = REPO / "scripts/dev/lib.sh"
LAB_LIB = REPO / "scripts/lab/lib.sh"

#: A `podman` that only answers what stack.sh asks: the project's containers and two labels.
PODMAN_STUB = """#!/usr/bin/env bash
case "$1" in
  ps) echo "${STUB_CONTAINER:-}" ;;
  inspect)
    case "$3" in
      *working_dir*) echo "${STUB_WORKING_DIR:-}" ;;
      *config_files*) echo "${STUB_CONFIG_FILES:-}" ;;
    esac
    ;;
esac
"""


def _run(
    tmp_path: Path, script: str, *, env: dict[str, str] | None = None, lib: Path = DEV_LIB
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "podman"
    stub.write_text(PODMAN_STUB, encoding="utf-8")
    stub.chmod(0o755)
    (tmp_path / "state").mkdir(exist_ok=True)
    environment = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "AEGIS_STATE_DIR": str(tmp_path / "state"),
        # The stubs decide what exists; no real stack setting may leak in from the shell.
        "AEGIS_DEV_PROJECT": "",
        "AEGIS_LAB_PROJECT": "",
        "AEGIS_STACK_RECREATE": "",
        "AEGIS_STACK_FORCE": "",
        "STUB_CONTAINER": "",
        "STUB_WORKING_DIR": "",
        "STUB_CONFIG_FILES": "",
    }
    environment.update(env or {})
    return subprocess.run(  # noqa: S603 - this repository's own shell functions under a stub
        ["bash", "-c", f'. "{lib}"; set +e\n{script}'],
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
        check=False,
    )


def _other_checkout(tmp_path: Path) -> dict[str, str]:
    other = tmp_path / "another-worktree"
    return {
        "STUB_CONTAINER": "aegis-dev-pg",
        "STUB_WORKING_DIR": str(other / "deploy/dev"),
        "STUB_CONFIG_FILES": str(other / "deploy/dev/compose.yaml"),
    }


def _this_checkout() -> dict[str, str]:
    return {
        "STUB_CONTAINER": "aegis-dev-pg",
        "STUB_WORKING_DIR": str(REPO / "deploy/dev"),
        "STUB_CONFIG_FILES": str(REPO / "deploy/dev/compose.yaml"),
    }


def test_another_checkouts_project_is_refused_with_its_path(tmp_path: Path) -> None:
    other = tmp_path / "another-worktree" / "deploy/dev"
    result = _run(tmp_path, "require_dev_stack_ownership", env=_other_checkout(tmp_path))
    assert result.returncode == 1, result.stderr
    assert "belongs to another checkout" in result.stderr
    assert str(other) in result.stderr
    assert "AEGIS_DEV_PROJECT" in result.stderr, "the message must say how to get your own stack"


def test_this_checkouts_project_is_accepted(tmp_path: Path) -> None:
    result = _run(tmp_path, "require_dev_stack_ownership", env=_this_checkout())
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


def test_no_project_at_all_is_accepted(tmp_path: Path) -> None:
    result = _run(tmp_path, 'require_dev_stack_ownership; echo "searched=$STUB_CONTAINER"')
    assert result.returncode == 0, result.stderr


def test_a_changed_configuration_is_refused_until_it_is_recreated_on_purpose(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    # This checkout's own stack, started with a different configuration than the files have now.
    (state / "stack.identity").write_text(
        "project=aegis-dev\nworking_dir=x\nfingerprint=deadbeef\n", encoding="utf-8"
    )
    refused = _run(tmp_path, "require_dev_stack_ownership", env=_this_checkout())
    assert refused.returncode == 1, refused.stderr
    assert "different configuration" in refused.stderr
    assert "AEGIS_STACK_RECREATE=1" in refused.stderr

    allowed = _run(
        tmp_path,
        "require_dev_stack_ownership",
        env={**_this_checkout(), "AEGIS_STACK_RECREATE": "1"},
    )
    assert allowed.returncode == 0, allowed.stderr
    assert "recreating its containers" in allowed.stderr


def test_an_unprovable_owner_is_refused(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        "require_dev_stack_ownership",
        env={"STUB_CONTAINER": "aegis-dev-pg"},  # a container without compose labels
    )
    assert result.returncode == 1, result.stderr
    assert "owner cannot be proven" in result.stderr


def test_the_force_escape_hatch_is_explicit_and_loud(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        "require_dev_stack_ownership",
        env={**_other_checkout(tmp_path), "AEGIS_STACK_FORCE": "1"},
    )
    assert result.returncode == 0, result.stderr
    assert "AEGIS_STACK_FORCE=1" in result.stderr


def test_a_checkout_can_name_its_own_dev_stack(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        'echo "project=$DEV_PROJECT pg=$PG_CONTAINER neo4j=$NEO4J_CONTAINER"',
        env={"AEGIS_DEV_PROJECT": "aegis-dev-worker-b"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "project=aegis-dev-worker-b pg=aegis-dev-worker-b-pg neo4j=aegis-dev-worker-b-neo4j"
    )
    compose = (REPO / "deploy/dev/compose.yaml").read_text(encoding="utf-8")
    assert "container_name: ${AEGIS_DEV_PROJECT:-aegis-dev}-pg" in compose
    assert "name: ${AEGIS_DEV_PROJECT:-aegis-dev}" in compose


def test_a_checkout_can_name_its_own_lab_and_gets_its_own_network(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        'echo "project=$LAB_PROJECT network=$LAB_NETWORK dns=$DNS_CONTAINER '
        'services=${SERVICE_CONTAINERS[*]}"',
        env={"AEGIS_LAB_PROJECT": "aegis-lab-worker-b"},
        lib=LAB_LIB,
    )
    assert result.returncode == 0, result.stderr
    fields = result.stdout.strip()
    assert "project=aegis-lab-worker-b" in fields
    assert "network=aegis-lab-worker-b-lab" in fields
    assert "dns=aegis-lab-worker-b-dns" in fields
    assert "aegis-lab-worker-b-app" in fields
    compose = (REPO / "deploy/lab/compose.yaml").read_text(encoding="utf-8")
    assert "container_name: ${AEGIS_LAB_PROJECT:-aegis-lab}-dns" in compose
    assert "name: ${AEGIS_LAB_PROJECT:-aegis-lab}-lab" in compose


def test_defaults_keep_the_documented_names(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        'echo "$DEV_PROJECT/$PG_CONTAINER"; '
        f'. "{LAB_LIB}"; echo "$LAB_PROJECT/$LAB_NETWORK/$DNS_CONTAINER"',
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [
        "aegis-dev/aegis-dev-pg",
        "aegis-lab/aegis-lab-lab/aegis-lab-dns",
    ]


@pytest.mark.parametrize("script", ["dev-up.sh", "dev-down.sh"])
def test_the_dev_scripts_call_the_ownership_guard(script: str) -> None:
    body = (REPO / "scripts/dev" / script).read_text(encoding="utf-8")
    assert "require_dev_stack_ownership" in body


@pytest.mark.parametrize(
    ("script", "guard"),
    [
        # lab-down removes a lab, so it needs the refusal; lab-up may *use* another checkout's
        # running lab (one lab serves the host) and therefore reads the verdict instead.
        ("lab-down.sh", "require_lab_stack_ownership"),
        ("lab-up.sh", "lab_stack_verdict"),
    ],
)
def test_the_lab_scripts_apply_the_ownership_rule(script: str, guard: str) -> None:
    body = (REPO / "scripts/lab" / script).read_text(encoding="utf-8")
    assert guard in body
