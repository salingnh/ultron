"""G2-B layer 1 and 2: the request M05 signs, and the refusal M06 makes before a container.

Layer 1 (`aegis.m05_registry.verification`) derives the whole verification input from data the
server holds - the finding, the reviewed check registry, the deployment control map and the signed
profile's pack - and refuses a submission that differs in any field. The tests below use the real
`PostgresJobService` so a refusal is a recorded `policy_decision` (no task signed) and an accepted
request is a signed `verify.check` job whose input is exactly the derived one.

Layer 2 (`aegis.m06_runner.verification`) re-checks the signed task against the deployment profile
before `prepare` builds anything: no profile entry, no `verify` pack, a pack whose bytes moved, a
check missing from the mounted pack, a lab-only check on the internet - each is a `SpecError`
raised before a container or network exists. The last test pins "zero containers" by making the
podman seam explode if it is touched at all.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from aegis.common import verification_controls as control_map
from aegis.common.repo import repository_root
from aegis.common.verification import load_checks, pack_sha256, template_sha256
from aegis.m05_registry.caps import CampaignPolicy
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import PostgresJobService
from aegis.m05_registry.signing import KeyRing
from aegis.m05_registry.verification import Approvals, check_request
from aegis.m06_runner import profile as profiles
from aegis.m06_runner import verification as m06_verification
from aegis.m06_runner.job import JobPlan, JobRunner
from aegis.m06_runner.podman import PodmanRunner
from aegis.m06_runner.spec import SpecError
from aegis.m26_api.manifests import adapter_manifests
from tests import db_support, m06_support

pytestmark = db_support.requires_postgres

REPO = repository_root()
LAB = REPO / "deploy/lab/verify"
APPROVED = "cve-2021-41773-traversal"
POSITIVE = "service:10.114.60.31:80/tcp"
TWIN = "service:10.114.60.32:80/tcp"
BENIGN = "/static/.%2e/.%2e/srv/canary/absent.txt"
NUCLEI = "sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"


# --- deployment data ---------------------------------------------------------------------------


def test_the_lab_profile_pins_the_pack_it_mounts() -> None:
    document = json.loads((REPO / "deploy/lab/runner-profile.json").read_text(encoding="utf-8"))
    entry = next(item for item in document["jobs"] if item["imageDigest"] == NUCLEI)
    assert entry["verify"]["sha256"] == pack_sha256(LAB)
    assert entry["verify"]["target"] == "/opt/verify"
    mount = next(item for item in entry["mounts"] if item["target"] == "/opt/verify")
    assert (REPO / "deploy/lab" / mount["source"]).resolve() == LAB.resolve()


def test_the_internet_profile_has_no_verification_provider() -> None:
    document = json.loads(
        (REPO / "deploy/internet/runner-profile.json").read_text(encoding="utf-8")
    )
    assert not [item for item in document["jobs"] if item["imageDigest"] == NUCLEI]
    assert not [item for item in document["jobs"] if "verify" in item]


def test_only_the_approved_lab_check_is_approved() -> None:
    document = json.loads((REPO / "deploy/lab/verify-approvals.json").read_text())
    assert document == {"lab": [APPROVED], "internet": []}
    assert APPROVED in {check.check_id for check in load_checks(LAB / "templates").lab_only()}


def test_the_control_map_pairs_the_reviewed_template_and_canary() -> None:
    mapping = control_map.load_controls(REPO / "deploy/lab/verify-controls.json")
    entry = control_map.controls_for(mapping, APPROVED)
    assert entry is not None and entry.canary_path and entry.benign_path
    assert entry.patched_twin is not None and entry.benign is not None
    template = LAB / "templates" / f"{APPROVED}.yaml"
    body = template.read_text(encoding="utf-8")
    assert entry.canary_path in body and entry.benign_path in body
    canary = (REPO / "deploy/lab/verify-canary.txt").read_text()
    assert hashlib.sha256(canary.encode()).hexdigest() == mapping.canary_sha256
    assert content_sha_of(canary) == mapping.canary_sha256


def content_sha_of(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_the_pack_review_hashes_the_template_the_registry_pins() -> None:
    check = load_checks(LAB / "templates").by_id(APPROVED)
    assert check is not None and check.template and check.template_sha256
    assert template_sha256(LAB / "templates" / check.template) == check.template_sha256


# --- layer 1: M05 ------------------------------------------------------------------------------


def _campaign(dsn: str) -> tuple[db_support.SeededCampaign, dict[str, str]]:
    seeded = db_support.seed_campaign(dsn, status="RUNNING")
    ids = {}
    with psycopg.connect(dsn) as conn, conn.transaction():
        for name, key in (("positive", POSITIVE), ("twin", TWIN)):
            asset_id = str(_uuid7())
            ids[name] = asset_id
            conn.execute(
                "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
                " normalization_version) VALUES (%s, %s, 'service', now(), now(), 'aegis-norm/1')",
                (asset_id, key),
            )
            conn.execute(
                "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen)"
                " VALUES (%s, %s, now())",
                (asset_id, seeded.campaign_id),
            )
        ids["finding"] = str(_uuid7())
        job = _seed_job(conn, seeded, ids["positive"])
        conn.execute(
            "INSERT INTO finding (finding_id, fingerprint, asset_id, rule_id, category, title,"
            " vulnerability_ids, status, first_seen, last_seen, first_job_id, first_campaign_id)"
            " VALUES (%s, %s, %s, 'cve:CVE-2021-41773', 'vulnerability', 'httpd traversal',"
            " '{CVE-2021-41773}', 'CANDIDATE', now(), now(), %s, %s)",
            (ids["finding"], "e" * 64, ids["positive"], job, seeded.campaign_id),
        )
    return seeded, ids


def _seed_job(conn: Any, seeded: db_support.SeededCampaign, asset: str) -> str:
    """The job a finding points at (the DB requires a real first_job_id)."""
    item_id = str(_uuid7())
    conn.execute(
        "INSERT INTO policy_decision (decision_id, campaign_id, capability, provider, targets,"
        " input, decision, rationale, requested_by, target_refs, policy_version, scope_id,"
        " idempotency_key, trace_id)"
        " VALUES (%s, %s, 'service.fingerprint', 'fingerprintx', %s, '{}',"
        " 'approved', 'seed', %s, %s, %s, %s, %s, %s)",
        (
            item_id,
            seeded.campaign_id,
            [POSITIVE],
            Jsonb(db_support.OPERATOR),
            Jsonb([{"canonical_key": POSITIVE}]),
            seeded.policy_version,
            seeded.scope_id,
            f"seed-{item_id}",
            "f" * 32,
        ),
    )
    job = str(_uuid7())
    conn.execute(
        "INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider,"
        " provider_version, adapter_version, image_digest, manifest_sha256, scan_cycle,"
        " job_fingerprint, policy_version, scope_id, input, targets, target_refs, requested_by,"
        " rationale, trace_id, status, started_at, finished_at)"
        " VALUES (%s, %s, %s, 'service.fingerprint', 'fingerprintx', 'v1.1.19', '1.1.1', %s, %s,"
        " %s, %s, %s, %s, '{}', %s, %s, %s, 'seed', %s, 'SUCCEEDED', now(), now())",
        (
            job,
            seeded.campaign_id,
            item_id,
            "sha256:" + "5" * 64,
            "6" * 64,
            str(_uuid7()),
            hashlib.sha256(job.encode()).hexdigest(),
            seeded.policy_version,
            seeded.scope_id,
            [POSITIVE],
            Jsonb([{"canonical_key": POSITIVE}]),
            Jsonb(db_support.OPERATOR),
            "e" * 32,
        ),
    )
    return job


def _finding_job(dsn: str, campaign_id: str) -> str:
    with psycopg.connect(dsn) as conn:
        row = conn.execute(
            "SELECT first_job_id FROM finding WHERE first_campaign_id = %s LIMIT 1",
            (campaign_id,),
        ).fetchone()
    assert row is not None
    return str(row[0])


def _uuid7() -> str:
    from aegis.m05_registry.ids import uuid7

    return str(uuid7())


def _policy(seeded: db_support.SeededCampaign) -> CampaignPolicy:
    return CampaignPolicy(
        campaign_id=seeded.campaign_id,
        policy_version=seeded.policy_version,
        scope_id=seeded.scope_id,
        policy=seeded.policy,
    )


def _derived(dsn: str, seeded: db_support.SeededCampaign) -> dict[str, Any]:
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as conn:
        from aegis.m05_registry.verification import build_request_input

        check = load_checks().by_id(APPROVED)
        assert check is not None
        return build_request_input(
            conn,
            campaign=_policy(seeded),
            check=check,
            finding_id=_finding_id(dsn, seeded),
        )


def _finding_id(dsn: str, seeded: db_support.SeededCampaign) -> str:
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as conn:
        row = conn.execute(
            "SELECT finding_id FROM finding WHERE first_campaign_id = %s",
            (seeded.campaign_id,),
        ).fetchone()
    assert row is not None
    return str(row["finding_id"])


def _check(
    dsn: str, seeded: db_support.SeededCampaign, submitted: dict[str, Any]
) -> dict[str, Any]:
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as conn:
        return check_request(
            conn,
            campaign=_policy(seeded),
            submitted=submitted,
            approvals=Approvals(lab=frozenset({APPROVED}), internet=frozenset({APPROVED})),
        )


@pytest.fixture()
def lab_campaign() -> Iterator[dict[str, Any]]:
    with db_support.migrated_database() as dsn:
        seeded, ids = _campaign(dsn)
        derived = _derived(dsn, seeded)
        yield {"dsn": dsn, "campaign": seeded, "ids": ids, "input": derived}


def test_the_derived_input_is_the_signed_one(lab_campaign: dict[str, Any]) -> None:
    values = _check(lab_campaign["dsn"], lab_campaign["campaign"], lab_campaign["input"])
    assert values == lab_campaign["input"]
    assert values["targets"] == [POSITIVE, TWIN]
    assert values["ports"] == [80]
    assert values["controls"] == [{"role": "patched_twin", "target": TWIN}]
    assert values["benign_path"] == BENIGN
    assert values["request_cap"] == 4
    assert values["check_pack_sha256"] == pack_sha256(LAB)


def test_an_unapproved_check_is_refused(lab_campaign: dict[str, Any]) -> None:
    with psycopg.connect(lab_campaign["dsn"], row_factory=psycopg.rows.dict_row) as conn:
        with pytest.raises(M05Error) as refused:
            check_request(
                conn,
                campaign=_policy(lab_campaign["campaign"]),
                submitted=lab_campaign["input"],
                approvals=Approvals(lab=frozenset(), internet=frozenset()),
            )
    assert refused.value.refusal.code == "POLICY_DENIED"
    assert refused.value.refusal.rule == "verification_check_not_approved"


def test_a_lab_only_check_on_the_internet_is_refused(lab_campaign: dict[str, Any]) -> None:
    campaign = _policy(lab_campaign["campaign"])
    internet = CampaignPolicy(
        campaign_id=campaign.campaign_id,
        policy_version=campaign.policy_version,
        scope_id=campaign.scope_id,
        policy={**campaign.policy, "network_profile": "internet"},
    )
    with psycopg.connect(lab_campaign["dsn"], row_factory=psycopg.rows.dict_row) as conn:
        with pytest.raises(M05Error) as refused:
            check_request(
                conn,
                campaign=internet,
                submitted=lab_campaign["input"],
                approvals=Approvals(lab=frozenset({APPROVED}), internet=frozenset({APPROVED})),
            )
    assert refused.value.refusal.rule == "verification_check_profile_mismatch"


def test_an_operator_edited_input_is_refused(lab_campaign: dict[str, Any]) -> None:
    submitted = {**lab_campaign["input"], "benign_path": "/index.html"}
    with psycopg.connect(lab_campaign["dsn"], row_factory=psycopg.rows.dict_row) as conn:
        with pytest.raises(M05Error) as refused:
            check_request(
                conn,
                campaign=_policy(lab_campaign["campaign"]),
                submitted=submitted,
                approvals=Approvals(lab=frozenset({APPROVED}), internet=frozenset()),
            )
    assert refused.value.refusal.rule == "verification_input_not_server_built"


def test_a_stale_expected_seq_is_refused(lab_campaign: dict[str, Any]) -> None:
    submitted = {**lab_campaign["input"], "expected_seq": 9}
    with psycopg.connect(lab_campaign["dsn"], row_factory=psycopg.rows.dict_row) as conn:
        with pytest.raises(M05Error) as refused:
            check_request(
                conn,
                campaign=_policy(lab_campaign["campaign"]),
                submitted=submitted,
                approvals=Approvals(lab=frozenset({APPROVED}), internet=frozenset()),
            )
    assert refused.value.refusal.field == "/input/expected_seq"


def test_a_finding_whose_asset_the_campaign_does_not_hold_is_refused(
    lab_campaign: dict[str, Any],
) -> None:
    dsn = lab_campaign["dsn"]
    other_asset = _uuid7()
    other_finding = _uuid7()
    with psycopg.connect(dsn) as conn, conn.transaction():
        conn.execute(
            "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
            " normalization_version) VALUES (%s, 'service:10.114.59.77:80/tcp', 'service', now(),"
            " now(), 'aegis-norm/1')",
            (other_asset,),
        )
        conn.execute(
            "INSERT INTO finding (finding_id, fingerprint, asset_id, rule_id, category, title,"
            " vulnerability_ids, status, first_seen, last_seen, first_job_id, first_campaign_id)"
            " VALUES (%s, %s, %s, 'cve:CVE-2021-41773', 'vulnerability', 'elsewhere',"
            " '{CVE-2021-41773}', 'CANDIDATE', now(), now(), %s, %s)",
            (
                other_finding,
                "f" * 64,
                other_asset,
                _finding_job(dsn, lab_campaign["campaign"].campaign_id),
                lab_campaign["campaign"].campaign_id,
            ),
        )
    submitted = {**lab_campaign["input"], "finding_id": other_finding}
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as rows:
        with pytest.raises(M05Error) as refused:
            check_request(
                rows,
                campaign=_policy(lab_campaign["campaign"]),
                submitted=submitted,
                approvals=Approvals(lab=frozenset({APPROVED}), internet=frozenset()),
            )
    assert refused.value.refusal.rule == "verification_target_not_in_scope"


def test_the_service_refusal_records_a_decision_and_signs_no_task(
    lab_campaign: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dsn = lab_campaign["dsn"]
    approvals = tmp_path / "approvals.json"
    approvals.write_text(json.dumps({"lab": [], "internet": []}))
    monkeypatch.setenv("AEGIS_VERIFY_APPROVALS", str(approvals))
    registry = PostgresManifestRegistry(lambda: psycopg.connect(dsn))
    for raw in adapter_manifests():
        registry.register(raw, registered_by={"kind": "module", "id": "M05"})
    service = PostgresJobService(
        lambda: psycopg.connect(dsn), registry=registry, key_ring=KeyRing.dev()
    )
    from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit

    with pytest.raises(M05Error) as refused:
        service.submit(
            JobSubmit.model_validate(
                {
                    "campaign_id": lab_campaign["campaign"].campaign_id,
                    "capability": "verify.check",
                    "provider": "nuclei-verify",
                    "input": lab_campaign["input"],
                    "rationale": "layer-1 refusal test",
                    "priority": 60,
                }
            ),
            requested_by={"kind": "operator", "id": "op-g2b"},
            idempotency_key="test-verification-refusal",
        )
    assert refused.value.refusal.code == "POLICY_DENIED"
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as conn:
        decision = conn.execute(
            "SELECT * FROM policy_decision WHERE decision = 'denied'"
        ).fetchone()
        jobs = conn.execute(
            "SELECT count(*) AS n FROM scan_job WHERE capability = 'verify.check'"
        ).fetchone()
    assert decision is not None and decision["decision"] == "denied"
    assert jobs is not None and int(jobs["n"]) == 0


# --- layer 2: M06 ------------------------------------------------------------------------------


def _signed_task(**overrides: Any) -> tuple[Any, dict[str, Any]]:
    payload = json.loads(
        (REPO / "contracts/fixtures/valid/approved-task.nuclei-verify.json").read_text()
    )
    payload["input"] = {**payload["input"], **overrides.pop("input", {})}
    payload.update(overrides)
    payload.pop("signature", None)
    payload.pop("signature_key_id", None)
    task, document = m06_support.sign_task(payload)
    return task, document


def _manifest() -> tuple[Any, bytes]:
    return m06_support.manifest("manifest.nuclei-verify.yaml")


def _copy_pack(tmp_path: Path) -> Path:
    target = tmp_path / "verify"
    target.mkdir()
    for path in LAB.rglob("*"):
        if path.is_file():
            relative = path.relative_to(LAB)
            (target / relative).parent.mkdir(parents=True, exist_ok=True)
            (target / relative).write_bytes(path.read_bytes())
    return target


def _profile(
    pack: Path, sha: str | None = None, *, kind: str = "lab"
) -> profiles.DeploymentProfile:
    document = {
        "network": "aegis-lab-lab" if kind == "lab" else "aegis-uplink",
        "jobs": [
            {
                "imageDigest": NUCLEI,
                "args": [],
                "mounts": [{"source": str(pack), "target": "/opt/verify"}],
                "verify": {
                    "pack": str(pack),
                    "target": "/opt/verify",
                    "sha256": pack_sha256(pack) if sha is None else sha,
                },
            }
        ],
    }
    return profiles.DeploymentProfile.from_document(document, kind=kind)  # type: ignore[arg-type]


def _plan(task: Any, document: dict[str, Any], manifest: Any, raw: bytes) -> JobPlan:
    return JobPlan(
        job_id="01934f6a-0000-7000-8000-00000000b001",
        task=task,
        manifest=manifest,
        input=dict(task.input),
        manifest_bytes=raw,
        task_body=document,
    )


def test_the_pack_gate_passes_with_the_real_deployment_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = _copy_pack(tmp_path)
    task, document = _signed_task(input={"check_pack_sha256": pack_sha256(pack)})
    manifest, raw = _manifest()
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": _profile(pack)})
    # No podman call may happen while preparing a lab verification job.
    monkeypatch.setattr(
        "aegis.m06_runner.podman._podman",
        lambda *args, **kwargs: pytest.fail(f"podman {args} was called before the container"),
    )
    spec, policy = JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(  # type: ignore[arg-type]
        _plan(task, document, manifest, raw)
    )
    assert spec.image_digest == NUCLEI
    assert policy.mode == "egress"
    assert spec.args[spec.args.index("-id") + 1] == APPROVED


def test_a_profile_without_the_pack_is_refused(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    task, document = _signed_task(input={"check_pack_sha256": pack_sha256(pack)})
    manifest, raw = _manifest()
    without = profiles.DeploymentProfile.from_document(
        {"network": "aegis-lab-lab", "jobs": [{"imageDigest": NUCLEI, "args": []}]},
        kind="lab",
    )
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": without})
    with pytest.raises(SpecError) as refused:
        JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(  # type: ignore[arg-type]
            _plan(task, document, manifest, raw)
        )
    assert refused.value.code == "POLICY_DENIED"


def test_the_internet_profile_refuses_a_signed_lab_check(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    task, document = _signed_task(
        network_profile="internet", input={"check_pack_sha256": pack_sha256(pack)}
    )
    manifest, raw = _manifest()
    # A hand-built internet profile that does carry the pack: the check's class still refuses it.
    internet = _profile(pack, kind="internet")
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"internet": internet})
    with pytest.raises(SpecError) as refused:
        JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(  # type: ignore[arg-type]
            _plan(task, document, manifest, raw)
        )
    assert refused.value.code == "POLICY_DENIED"


def test_a_pack_that_moved_after_signing_is_refused(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    signed = pack_sha256(pack)
    task, document = _signed_task(input={"check_pack_sha256": signed})
    manifest, raw = _manifest()
    (pack / "checks.v2.yaml").write_text("apiVersion: aegis.io/v2\n", encoding="utf-8")
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": _profile(pack, signed)})
    with pytest.raises(SpecError) as refused:
        JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(  # type: ignore[arg-type]
            _plan(task, document, manifest, raw)
        )
    assert refused.value.code == "DEPENDENCY_MISSING"


def test_a_pack_mounted_from_somewhere_else_is_refused(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    task, document = _signed_task(input={"check_pack_sha256": pack_sha256(pack)})
    manifest, raw = _manifest()
    document_profile = {
        "network": "aegis-lab-lab",
        "jobs": [
            {
                "imageDigest": NUCLEI,
                "args": [],
                "mounts": [{"source": str(other), "target": "/opt/verify"}],
                "verify": {
                    "pack": str(pack),
                    "target": "/opt/verify",
                    "sha256": pack_sha256(pack),
                },
            }
        ],
    }
    profile = profiles.DeploymentProfile.from_document(document_profile, kind="lab")
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": profile})
    with pytest.raises(SpecError) as refused:
        JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(  # type: ignore[arg-type]
            _plan(task, document, manifest, raw)
        )
    assert refused.value.code == "DEPENDENCY_MISSING"


def test_an_unknown_check_id_is_refused(tmp_path: Path) -> None:
    pack = _copy_pack(tmp_path)
    task, document = _signed_task(
        input={"check_pack_sha256": pack_sha256(pack), "check_id": "config.tls.certificate"}
    )
    manifest, raw = _manifest()
    # An E1 check is not in the lab pack's provider (config-verify), and M06 refuses it for the
    # nuclei image before any container.
    runner = PodmanRunner(base_dir=tmp_path / "run", profiles={"lab": _profile(pack)})
    with pytest.raises(SpecError) as refused:
        JobRunner(runner, store=None, key_ring=m06_support.DEV_RING).prepare(  # type: ignore[arg-type]
            _plan(task, document, manifest, raw)
        )
    assert refused.value.code == "POLICY_DENIED"
    assert m06_verification.CAPABILITY == "verify.check"
