"""Deployment network profiles of the M06 runner: the lab (G1.5c) and the internet (G1.6).

A profile is what lets a pinned tool run on the deployment's network: the lab network with its
resolver entry and CA, or the internet profile's provider-config file and uplink. It is deploy
config keyed by image digest, so these tests check the properties that matter: it is off unless a
file is configured, it can only add endpoint data to a job whose pinned image it names, and the
profile a job uses is the one the campaign signed - never one the environment happens to have.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.m06_runner.podman import PodmanRunner
from aegis.m06_runner.profile import DeploymentProfile, ProfileError

SUBFINDER = "sha256:" + "2f" * 32
DNSX = "sha256:" + "8f" * 32
DSN = "postgresql://aegis@127.0.0.1/aegis"


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


def _internet_document() -> dict[str, object]:
    return {
        "network": "podman",
        "jobs": [
            {
                "imageDigest": SUBFINDER,
                "env": {"HOME": "/tmp"},
                "envFromHost": ["SUBFINDER_PROVIDER_TOKEN"],
                "mounts": [
                    {
                        "sourceEnv": "AEGIS_SUBFINDER_PROVIDER_CONFIG",
                        "target": "/tmp/.config/subfinder/provider-config.yaml",
                    }
                ],
            }
        ],
    }


def test_a_profile_is_off_unless_a_file_is_configured() -> None:
    assert DeploymentProfile.from_env({}, kind="lab") is None
    assert DeploymentProfile.from_env({"AEGIS_M06_LAB_PROFILE": ""}, kind="lab") is None
    assert DeploymentProfile.from_env({}, kind="internet") is None
    assert DeploymentProfile.from_env({"AEGIS_M06_INTERNET_PROFILE": " "}, kind="internet") is None


def test_each_profile_reads_its_own_variable(tmp_path: Path) -> None:
    lab = _write(tmp_path, _document(tmp_path))
    internet = _write(tmp_path, _internet_document(), name="internet.json")
    source = {"AEGIS_M06_LAB_PROFILE": str(lab), "AEGIS_M06_INTERNET_PROFILE": str(internet)}
    assert DeploymentProfile.from_env(source, kind="lab") is not None
    assert DeploymentProfile.from_env(source, kind="internet") is not None
    assert DeploymentProfile.from_env({"AEGIS_M06_LAB_PROFILE": str(lab)}, kind="internet") is None


def test_the_profile_is_keyed_by_the_pinned_image_digest(tmp_path: Path) -> None:
    profile = DeploymentProfile.from_document(_document(tmp_path), kind="lab", base_dir=tmp_path)
    assert profile.kind == "lab"
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
    profile = DeploymentProfile.from_file(_write(tmp_path, document), kind="lab")
    job = profile.for_image(SUBFINDER)
    assert job is not None
    assert job.mounts[0].source == (tmp_path / ".run" / "ca.crt").resolve()


def test_the_profile_argv_carries_hosts_env_and_mounts(tmp_path: Path) -> None:
    profile = DeploymentProfile.from_document(_document(tmp_path), kind="lab", base_dir=tmp_path)
    job = profile.for_image(SUBFINDER)
    assert job is not None
    argv = job.argv()
    assert argv[:2] == ["--add-host", "crt.sh:10.114.53.80"]
    assert "--env" in argv and "SSL_CERT_FILE=/lab-tls/ca.crt" in argv
    assert any(value.startswith("type=bind,src=") and value.endswith(",ro,z") for value in argv)


def test_the_internet_profile_forwards_names_and_an_optional_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = DeploymentProfile.from_document(_internet_document(), kind="internet")
    job = profile.for_image(SUBFINDER)
    assert job is not None
    # An unset variable means no mount and no env value: the provider config file is optional.
    monkeypatch.delenv("AEGIS_SUBFINDER_PROVIDER_CONFIG", raising=False)
    argv = job.argv()
    assert "--env" in argv and "HOME=/tmp" in argv
    assert "SUBFINDER_PROVIDER_TOKEN" in argv  # name only: Podman copies the runner's value
    assert not any(value.startswith("type=bind,src=") for value in argv)
    # Set: the path (never the file content) becomes a read-only mount.
    config = tmp_path / "provider-config.yaml"
    config.write_text("crtsh: []\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_SUBFINDER_PROVIDER_CONFIG", str(config))
    argv = job.argv()
    assert any(
        value
        == f"type=bind,src={config.resolve()},dst=/tmp/.config/subfinder/provider-config.yaml,ro,z"
        for value in argv
    )


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
        # A mount must carry exactly one source: a path (deploy file) or a variable name.
        {
            "network": "aegis-lab-lab",
            "jobs": [{"imageDigest": SUBFINDER, "mounts": [{"target": "/x"}]}],
        },
        {
            "network": "aegis-lab-lab",
            "jobs": [
                {
                    "imageDigest": SUBFINDER,
                    "mounts": [{"source": "/x", "sourceEnv": "Y", "target": "/x"}],
                }
            ],
        },
        {
            "network": "aegis-lab-lab",
            "jobs": [
                {"imageDigest": SUBFINDER, "mounts": [{"sourceEnv": "not a name", "target": "/x"}]}
            ],
        },
        {
            "network": "aegis-lab-lab",
            "jobs": [{"imageDigest": SUBFINDER, "mounts": [{"source": "/x", "target": "rel"}]}],
        },
        {
            "network": "aegis-lab-lab",
            "jobs": [{"imageDigest": SUBFINDER, "envFromHost": ["lower-case"]}],
        },
    ],
)
def test_a_broken_profile_fails_before_any_container(
    tmp_path: Path, document: dict[str, object]
) -> None:
    with pytest.raises(ProfileError):
        DeploymentProfile.from_document(document, kind="lab", base_dir=tmp_path)


def test_a_missing_file_says_which_one_and_which_profile(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="cannot read the internet profile"):
        DeploymentProfile.from_file(tmp_path / "missing.json", kind="internet")


def test_the_runner_without_a_profile_starts_no_endpoint_data(tmp_path: Path) -> None:
    runner = PodmanRunner(base_dir=tmp_path)
    assert runner.lab is None
    assert runner.internet is None
    assert runner.profile_entry("lab", SUBFINDER) is None
    assert runner.profile_entry("internet", SUBFINDER) is None


def test_the_runner_only_profiles_the_named_images_and_kind(tmp_path: Path) -> None:
    lab = DeploymentProfile.from_document(_document(tmp_path), kind="lab", base_dir=tmp_path)
    internet = DeploymentProfile.from_document(_internet_document(), kind="internet")
    runner = PodmanRunner(
        base_dir=tmp_path, profiles={"lab": lab, "internet": internet}, uplink_network="podman"
    )
    assert runner.profile_entry("lab", SUBFINDER) is not None
    assert runner.profile_entry("lab", "sha256:" + "11" * 32) is None
    # The same image has an internet entry; the kind decides which one a job gets.
    assert runner.profile_entry("internet", SUBFINDER) is not None
    assert runner.profile_entry("internet", DNSX) is None


def _write(
    tmp_path: Path, document: dict[str, object], *, name: str = "runner-profile.json"
) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("path", "kind", "network"),
    [
        ("deploy/lab/runner-profile.json", "lab", "aegis-lab-lab"),
        ("deploy/internet/runner-profile.json", "internet", "podman"),
    ],
)
def test_the_shipped_deploy_profiles_stay_loadable(path: str, kind: str, network: str) -> None:
    """The deployment files are config the runner relies on; a broken one fails at start-up."""
    from aegis.common.repo import repository_root

    profile = DeploymentProfile.from_file(repository_root() / path, kind=kind)  # type: ignore[arg-type]
    assert profile.kind == kind
    assert profile.network == network
    assert profile.jobs, "a shipped profile must list at least one pinned image"


def test_the_uplink_is_the_profile_then_the_deployment_override(tmp_path: Path) -> None:
    """The broker's outbound leg: the profile names a default, the deployment may own one."""
    from aegis.m06_runner.loop import LoopConfig

    profile = DeploymentProfile.from_document(_internet_document(), kind="internet")
    assert LoopConfig(dsn=DSN, base_dir=tmp_path, internet=profile).uplink == "podman"
    overridden = LoopConfig(
        dsn=DSN,
        base_dir=tmp_path,
        internet=profile,
        uplink_network="aegis-uplink",
    )
    assert overridden.uplink == "aegis-uplink"
    assert LoopConfig(dsn=DSN, base_dir=tmp_path).uplink is None

    configured = _write(tmp_path, _internet_document(), name="internet.json")
    base = {"AEGIS_PG_DSN": DSN}
    assert (
        LoopConfig.from_env({**base, "AEGIS_M06_INTERNET_PROFILE": str(configured)}).uplink
        == "podman"
    )
    from_env = LoopConfig.from_env(
        {
            **base,
            "AEGIS_M06_INTERNET_PROFILE": str(configured),
            "AEGIS_UPLINK_NETWORK": "aegis-uplink",
        }
    )
    assert from_env.uplink == "aegis-uplink"
