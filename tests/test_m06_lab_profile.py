"""The lab deployment profile of the M06 runner (G1.5c).

The profile is what lets a pinned tool run against the authorized lab: the lab network, the
resolver flag, the `crt.sh` entry and the throwaway CA. It is deploy config keyed by image digest,
so these tests check the two properties that matter: it is off unless a file is configured, and it
can only add endpoint data to a job whose pinned image it names - never to another image.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.m06_runner.lab import LabProfile, LabProfileError
from aegis.m06_runner.podman import PodmanRunner

SUBFINDER = "sha256:" + "2f" * 32
DNSX = "sha256:" + "8f" * 32


def _document(tmp_path: Path) -> dict[str, object]:
    ca = tmp_path / "ca.crt"
    ca.write_text("not a real certificate\n", encoding="utf-8")
    return {
        "network": "aegis-lab-lab",
        "jobs": [
            {
                "imageDigest": SUBFINDER,
                "args": ["-sources", "crtsh"],
                "env": {"SSL_CERT_FILE": "/lab-tls/ca.crt"},
                "hosts": {"crt.sh": "10.114.53.80"},
                "mounts": [{"source": "ca.crt", "target": "/lab-tls/ca.crt"}],
            },
            {"imageDigest": DNSX, "args": ["-r", "10.114.53.53"]},
        ],
    }


def test_a_profile_is_off_unless_a_file_is_configured() -> None:
    assert LabProfile.from_env({}) is None
    assert LabProfile.from_env({"AEGIS_M06_LAB_PROFILE": ""}) is None


def test_the_profile_is_keyed_by_the_pinned_image_digest(tmp_path: Path) -> None:
    profile = LabProfile.from_document(_document(tmp_path), base_dir=tmp_path)
    assert profile.network == "aegis-lab-lab"
    subfinder = profile.for_image(SUBFINDER)
    assert subfinder is not None
    assert subfinder.args == ("-sources", "crtsh")
    assert subfinder.hosts == {"crt.sh": "10.114.53.80"}
    assert subfinder.mounts[0].source == (tmp_path / "ca.crt").resolve()
    assert subfinder.mounts[0].target == "/lab-tls/ca.crt"
    assert profile.for_image("sha256:" + "00" * 32) is None


def test_a_relative_mount_is_resolved_against_the_profile_file(tmp_path: Path) -> None:
    (tmp_path / ".run").mkdir()
    (tmp_path / ".run" / "ca.crt").write_text("x", encoding="utf-8")
    document = _document(tmp_path)
    document["jobs"] = [
        {"imageDigest": SUBFINDER, "mounts": [{"source": ".run/ca.crt", "target": "/ca.crt"}]}
    ]
    profile = LabProfile.from_file(_write(tmp_path, document))
    job = profile.for_image(SUBFINDER)
    assert job is not None
    assert job.mounts[0].source == (tmp_path / ".run" / "ca.crt").resolve()


def test_the_profile_argv_carries_hosts_env_and_mounts(tmp_path: Path) -> None:
    profile = LabProfile.from_document(_document(tmp_path), base_dir=tmp_path)
    job = profile.for_image(SUBFINDER)
    assert job is not None
    argv = job.argv()
    assert argv[:2] == ["--add-host", "crt.sh:10.114.53.80"]
    assert "--env" in argv and "SSL_CERT_FILE=/lab-tls/ca.crt" in argv
    assert any(value.startswith("type=bind,src=") and value.endswith(",ro,z") for value in argv)


@pytest.mark.parametrize(
    "document",
    [
        {"jobs": [{"imageDigest": SUBFINDER}]},
        {"network": "", "jobs": [{"imageDigest": SUBFINDER}]},
        {"network": "aegis-lab-lab", "jobs": []},
        {"network": "aegis-lab-lab", "jobs": [{}]},
        {"network": "aegis-lab-lab", "jobs": [{"imageDigest": "sha256:00"}]},
        {
            "network": "aegis-lab-lab",
            "jobs": [{"imageDigest": SUBFINDER, "args": [1]}],
        },
        {
            "network": "aegis-lab-lab",
            "jobs": [
                {"imageDigest": SUBFINDER},
                {"imageDigest": SUBFINDER},
            ],
        },
    ],
)
def test_a_broken_profile_fails_before_any_container(tmp_path: Path, document: object) -> None:
    with pytest.raises(LabProfileError):
        LabProfile.from_document(document, base_dir=tmp_path)  # type: ignore[arg-type]


def test_a_missing_file_says_which_one(tmp_path: Path) -> None:
    with pytest.raises(LabProfileError, match="cannot read the lab profile"):
        LabProfile.from_file(tmp_path / "missing.json")


def test_the_runner_without_a_profile_starts_no_lab_flags(tmp_path: Path) -> None:
    runner = PodmanRunner(base_dir=tmp_path)
    assert runner.lab is None
    assert runner.lab_for(SUBFINDER) is None


def test_the_runner_with_a_profile_only_profiles_the_named_images(tmp_path: Path) -> None:
    profile = LabProfile.from_document(_document(tmp_path), base_dir=tmp_path)
    runner = PodmanRunner(base_dir=tmp_path, lab=profile)
    assert runner.lab_for(SUBFINDER) is not None
    assert runner.lab_for("sha256:" + "11" * 32) is None


def _write(tmp_path: Path, document: dict[str, object]) -> Path:
    path = tmp_path / "runner-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path
