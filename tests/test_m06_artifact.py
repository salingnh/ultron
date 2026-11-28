"""G2-D: the artifact job's sandbox - no network, the signed image staged as a file, a pinned DB.

The claims this suite has to make are the ones the gate asks for: the image is analysed **without
running it**, the job has no egress, and the scanner's rule set is a deployment dependency whose
bytes are verified before a container exists. Everything here runs without Podman: the spec, the
profile and the staging seam are pure functions; the one real scan is the demo/lab fixture.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from aegis.common.ports import ContainerSpec
from aegis.m06_runner import podman as podman_module
from aegis.m06_runner import profile as profiles
from aegis.m06_runner import spec as specs
from aegis.m06_runner.job import JobPlan, JobRunner
from aegis.m06_runner.podman import ImageUnavailable, PodmanRunner
from tests import m06_support

IMAGE = "sha256:" + "a6" * 32
SCANNER = "sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
DB_BYTES = b"trivy-db fixture bytes\n"


def _task() -> tuple[object, dict[str, object]]:
    payload = json.loads(
        (m06_support.FIXTURES / "approved-task.trivy.json").read_text(encoding="utf-8")
    )
    payload["image_digest"] = SCANNER
    payload["input"] = {"targets": [IMAGE]}
    payload.pop("signature", None)
    payload.pop("signature_key_id", None)
    task, document = m06_support.sign_task(payload)
    return task, document


def _manifest() -> tuple[object, bytes]:
    return m06_support.manifest("manifest.trivy.yaml")


def _spec() -> ContainerSpec:
    task, document = _task()
    manifest, raw = _manifest()
    return specs.build_spec(
        task,  # type: ignore[arg-type]
        manifest,  # type: ignore[arg-type]
        dict(task.input),  # type: ignore[attr-defined]
        job_id="01934f6a-0000-7000-8000-00000000a001",
        task_body=document,
        key_ring=m06_support.DEV_RING,
        manifest_bytes=raw,
    )


def test_an_artifact_job_has_no_network_and_stages_the_signed_image() -> None:
    spec = _spec()
    assert spec.network == "none"
    assert spec.egress_mode is None
    assert spec.egress_binding == ()
    assert spec.artifact_digest == IMAGE
    assert spec.scratch_mb == 512
    assert "/in/image.tar" in spec.args
    assert "--skip-db-update" in spec.args
    # No argument asks the scanner to run, pull or open a socket: the image is one local file.
    assert not any(item.startswith(("docker://", "podman://", "registry")) for item in spec.args)
    task, document = _task()
    manifest, _ = _manifest()
    policy = specs.build_policy(
        task,  # type: ignore[arg-type]
        manifest,  # type: ignore[arg-type]
        dict(task.input),  # type: ignore[attr-defined]
        job_id="01934f6a-0000-7000-8000-00000000a001",
        task_body=document,
        key_ring=m06_support.DEV_RING,
    )
    assert policy.mode == "none"


def test_the_artifact_target_is_the_single_signed_digest() -> None:
    manifest, _ = _manifest()
    assert specs.artifact_target(manifest, {"targets": [IMAGE]}) == IMAGE  # type: ignore[arg-type]
    with pytest.raises(specs.SpecError):
        specs.artifact_target(manifest, {"targets": [IMAGE, IMAGE]})  # type: ignore[arg-type]
    with pytest.raises(specs.SpecError):
        specs.artifact_target(manifest, {"targets": ["dns:example.test"]})  # type: ignore[arg-type]


def _document(
    tmp_path: Path, *, sha256: str, rule_set: str | None = "trivy-db@2026-11-28T00:00:00Z"
) -> dict[str, Any]:
    database = tmp_path / "db"
    database.mkdir(parents=True, exist_ok=True)
    (database / "trivy.db").write_bytes(DB_BYTES)
    pinned: list[dict[str, object]] = [
        {"target": "/cache/db", "file": "trivy.db", "sha256": sha256}
    ]
    if rule_set is not None:
        pinned[0]["ruleSet"] = rule_set
    entry: dict[str, object] = {
        "imageDigest": SCANNER,
        "env": {"HOME": "/tmp"},
        "hosts": {"crt.sh": "10.114.53.80"},
        "mounts": [{"source": "db", "target": "/cache/db"}],
        "pinnedInputs": pinned,
    }
    return {"network": "aegis-lab-lab", "jobs": [entry]}


def test_a_no_network_job_gets_the_profile_mounts_but_no_endpoint_data(tmp_path: Path) -> None:
    document = _document(tmp_path, sha256=hashlib.sha256(DB_BYTES).hexdigest())
    entry = profiles.DeploymentProfile.from_document(
        document, kind="lab", base_dir=tmp_path
    ).for_image(SCANNER)
    assert entry is not None
    assert entry is not None
    local = entry.argv(network=False)
    assert "--add-host" not in local
    assert "HOME=/tmp" in local
    assert any(value.endswith(",ro,z") and "/cache/db" in value for value in local)
    # A job that does reach the network keeps the endpoint data as before.
    assert entry.argv(network=True)[:2] == ["--add-host", "crt.sh:10.114.53.80"]


def test_pinned_inputs_are_verified_before_a_job(tmp_path: Path) -> None:
    digest = hashlib.sha256(DB_BYTES).hexdigest()
    document = _document(tmp_path, sha256=digest)
    entry = profiles.DeploymentProfile.from_document(
        document, kind="lab", base_dir=tmp_path
    ).for_image(SCANNER)
    assert entry is not None
    assert profiles.verify_pinned_inputs(entry) == "trivy-db@2026-11-28T00:00:00Z"

    drifted = tmp_path / "drifted"
    entry = profiles.DeploymentProfile.from_document(
        _document(drifted, sha256=digest), kind="lab", base_dir=drifted
    ).for_image(SCANNER)
    assert entry is not None
    (drifted / "db" / "trivy.db").write_bytes(b"another database\n")
    with pytest.raises(profiles.ProfileError):
        profiles.verify_pinned_inputs(entry)

    missing = tmp_path / "missing"
    entry = profiles.DeploymentProfile.from_document(
        _document(missing, sha256=digest), kind="lab", base_dir=missing
    ).for_image(SCANNER)
    assert entry is not None
    (missing / "db" / "trivy.db").unlink()
    with pytest.raises(profiles.ProfileError):
        profiles.verify_pinned_inputs(entry)


def test_an_artifact_job_without_a_pinned_rule_set_is_refused(tmp_path: Path) -> None:
    # The image the job would scan is known, but nobody pinned which advisories the verdict uses:
    # refuse before a container exists instead of scanning with whatever is on disk.
    document = _document(tmp_path, sha256=hashlib.sha256(DB_BYTES).hexdigest(), rule_set=None)
    profile = profiles.DeploymentProfile.from_document(document, kind="lab", base_dir=tmp_path)
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": profile})
    task, _document_body = _task()
    manifest, raw = _manifest()
    plan = JobPlan(
        job_id="01934f6a-0000-7000-8000-00000000a002",
        task=task,  # type: ignore[arg-type]
        manifest=manifest,  # type: ignore[arg-type]
        input=dict(task.input),  # type: ignore[attr-defined]
        manifest_bytes=raw,
        task_body=_document_body,
    )
    with pytest.raises(specs.SpecError) as refused:
        JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(plan)  # type: ignore[arg-type]
    assert refused.value.code == "DEPENDENCY_MISSING"

    # With the rule set pinned the same job plans, and the DB bytes are verified on the way.
    (tmp_path / "db" / "trivy.db").write_bytes(DB_BYTES)
    document["jobs"][0]["pinnedInputs"][0]["ruleSet"] = "trivy-db@2026-11-28T00:00:00Z"
    profile = profiles.DeploymentProfile.from_document(document, kind="lab", base_dir=tmp_path)
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": profile})
    spec, policy = JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(plan)  # type: ignore[arg-type]
    assert policy.mode == "none"
    assert spec.artifact_digest == IMAGE

    (tmp_path / "db" / "trivy.db").write_bytes(b"edited after pinning\n")
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": profile})
    with pytest.raises(specs.SpecError) as drifted:
        JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(plan)  # type: ignore[arg-type]
    assert drifted.value.code == "DEPENDENCY_MISSING"


def test_the_image_is_copied_from_local_storage_by_digest(tmp_path: Path) -> None:
    runner = PodmanRunner(base_dir=tmp_path / "run")
    calls: list[tuple[str, ...]] = []

    def fake_podman(
        *args: str, check: bool = True, timeout: int = 600
    ) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ("images", "--format"):
            return subprocess.CompletedProcess(
                args,
                0,
                json.dumps(
                    [
                        {
                            "RepoDigests": [
                                "docker.io/library/python@sha256:" + "a6" * 32,
                                "docker.io/library/python@sha256:" + "b7" * 32,
                            ]
                        }
                    ]
                ),
                "",
            )
        if args[:2] == ("save", "--format"):
            Path(args[args.index("-o") + 1]).write_bytes(b"docker-archive")
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(args)

    original = podman_module._podman  # noqa: SLF001 - the seam under test
    podman_module._podman = fake_podman  # noqa: SLF001
    try:
        target = tmp_path / "image.tar"
        runner._stage_image("sha256:" + "a6" * 32, target)  # noqa: SLF001
        assert target.read_bytes() == b"docker-archive"
        assert target.stat().st_mode & 0o777 == 0o644
        assert calls[0][:2] == ("images", "--format")
        assert calls[1][:3] == ("save", "--format", "docker-archive")
        assert "docker.io/library/python@sha256:" + "a6" * 32 in calls[1]

        # A second call reuses the staged file (a resumed job does not re-copy an image).
        before = len(calls)
        runner._stage_image("sha256:" + "a6" * 32, target)  # noqa: SLF001
        assert len(calls) == before

        with pytest.raises(ImageUnavailable) as missing:
            runner._stage_image("sha256:" + "c8" * 32, tmp_path / "absent.tar")  # noqa: SLF001
        assert missing.value.code == "DEPENDENCY_MISSING"
    finally:
        podman_module._podman = original  # noqa: SLF001


def test_an_sbom_job_has_no_rule_set_requirement(tmp_path: Path) -> None:
    """Syft produces an SBOM and uses no database, so its job needs no pinned rule set.

    `runtime.ruleSet: pinned` is the manifest's declaration that a verified deployment rule set is
    required (Trivy, Grype); the SBOM provider does not declare it, and the same no-network profile
    entry is enough to plan it.
    """
    syft_scanner = "sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060"
    profile = profiles.DeploymentProfile.from_document(
        {
            "network": "aegis-lab-lab",
            "jobs": [{"imageDigest": syft_scanner, "env": {"HOME": "/tmp"}}],
        },
        kind="lab",
        base_dir=tmp_path,
    )
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": profile})
    payload = json.loads(
        (m06_support.FIXTURES / "approved-task.syft.json").read_text(encoding="utf-8")
    )
    payload.pop("signature", None)
    payload.pop("signature_key_id", None)
    task, document = m06_support.sign_task(payload)
    manifest, raw = m06_support.manifest("manifest.syft.yaml")
    plan = JobPlan(
        job_id="01934f6a-0000-7000-8000-00000000a003",
        task=task,
        manifest=manifest,
        input=dict(task.input),
        manifest_bytes=raw,
        task_body=document,
    )
    spec, policy = JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(plan)  # type: ignore[arg-type]
    assert policy.mode == "none"
    assert (
        spec.artifact_digest
        == "sha256:a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20"
    )
    assert spec.scratch_mb == 1024
    assert "docker-archive:/in/image.tar" in spec.args
