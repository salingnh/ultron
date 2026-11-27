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

from aegis.common.ports import ContainerSpec
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


def test_the_broker_placeholders_are_resolved_from_the_job(tmp_path: Path) -> None:
    """`${broker_dns|http|socks}` are deployment argv, resolved per job, never a literal token."""
    from aegis.m06_runner.podman import RunnerError
    from aegis.m06_runner.profile import BROKER_DNS, BROKER_HTTP, BROKER_SOCKS, JobProfile

    runner = PodmanRunner(base_dir=tmp_path)
    job = JobProfile(image_digest=SUBFINDER, args=("-r", BROKER_DNS, "-proxy", BROKER_HTTP))
    resolved = runner._profile_args(
        job,
        broker_dns="10.97.0.2:53",
        broker_http="http://10.97.0.2:3128",
        broker_socks=None,
    )
    assert resolved == ["-r", "10.97.0.2:53", "-proxy", "http://10.97.0.2:3128"]
    naabu = JobProfile(image_digest=SUBFINDER, args=("-proxy", BROKER_SOCKS))
    assert runner._profile_args(
        naabu, broker_dns=None, broker_http=None, broker_socks="10.97.0.2:1080"
    ) == ["-proxy", "10.97.0.2:1080"]
    # A job without that broker endpoint cannot run a profile that needs it.
    with pytest.raises(RunnerError, match="no such broker endpoint"):
        runner._profile_args(job, broker_dns=None, broker_http=None, broker_socks=None)
    assert runner._profile_args(None, broker_dns=None, broker_http=None, broker_socks=None) == []


def _run_spec(job_id: str, *, profile: str, egress: str | None) -> ContainerSpec:
    return ContainerSpec(
        job_id=job_id,
        image_digest=SUBFINDER,
        args=["-d", "lab.aegis.test"],
        cpu=0.5,
        memory_mb=128,
        timeout_seconds=60,
        max_output_bytes=1024 * 1024,
        network="exec",
        network_profile=profile,  # type: ignore[arg-type]
        egress_mode=egress,  # type: ignore[arg-type]
    )


def test_a_lab_profile_job_never_asks_for_a_job_network_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lab-profile job joins the lab network: it has no per-job network to name.

    Regression (integration branch, 2026-11-25): `_run_argv` resolved the broker endpoints of every
    job, so a lab-profile job called `broker_ip` for a network that `run()` never creates and every
    subfinder/dnsx/naabu job failed before a container started with "job network ... does not exist
    on this host". A manifest's `egressMode: broker` does not mean a lab job has a broker: its
    endpoint data is the deployment profile's own argv.
    """
    lab = DeploymentProfile.from_document(_document(tmp_path), kind="lab", base_dir=tmp_path)
    runner = PodmanRunner(base_dir=tmp_path, profiles={"lab": lab})
    # The argv is what this test is about: no podman call to map a digest to a local reference.
    monkeypatch.setattr(runner, "image_reference", lambda digest: digest)
    spec = _run_spec("01a21340-0000-7000-8000-000000000001", profile="lab", egress="broker")
    layout = runner.layout(spec.job_id).create()
    entry = runner.profile_entry("lab", spec.image_digest)
    assert entry is not None

    argv = runner._run_argv(spec, layout, lab.network, entry=entry)

    assert argv[argv.index("--network") + 1] == "aegis-lab-lab"
    assert "--dns" not in argv
    assert runner.network_name(spec.job_id) not in argv
    # The profile's own argv is still there (the crtsh source, the stub's host, the CA env).
    assert "-sources" in argv and "crtsh" in argv
    assert "crt.sh:10.114.53.80" in argv
    assert "SSL_CERT_FILE=/lab-tls/ca.crt" in argv
    # No placeholder survives as a literal token.
    assert not any("${broker_" in value for value in argv)


def test_an_internet_profile_job_keeps_its_broker_endpoints(tmp_path: Path) -> None:
    """The guard is the job network, not the profile: an internet job still resolves `${broker_*}`.

    Its `run()` creates the per-job network before the argv is built, so the profile's placeholders
    are what G1.6's proxy wiring relies on.
    """
    from aegis.m06_runner.profile import BROKER_DNS, JobProfile

    runner = PodmanRunner(base_dir=tmp_path)
    runner._images[SUBFINDER] = SUBFINDER  # no podman call; only the argv matters here
    spec = _run_spec("01a21340-0000-7000-8000-000000000002", profile="internet", egress="broker")
    runner._subnets[spec.job_id] = "10.97.0.0/24"
    layout = runner.layout(spec.job_id).create()
    entry = JobProfile(image_digest=spec.image_digest, args=("-r", BROKER_DNS))

    argv = runner._run_argv(spec, layout, runner.network_name(spec.job_id), entry=entry)

    assert argv[argv.index("-r") + 1] == "10.97.0.2:53"
    assert not any("${broker_" in value for value in argv)
