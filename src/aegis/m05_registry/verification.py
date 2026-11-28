"""M05 layer of the verification gate (G2-B, D29): only the server's own input is ever signed.

The operator chooses one thing: a `check_id` from the reviewed registry, plus the finding and
sequence they saw. Everything the job runs with is derived here, from data M05 already holds - the
finding's asset and rule, the check registry, the deployment's control map and the profile's pack:

* the check id must be approved **for the campaign's signed network profile** (deployment policy:
  `AEGIS_VERIFY_APPROVALS` names a JSON document `{"lab": [...], "internet": [...]}`; unset means
  nothing is approved, and the internet list is empty by owner decision);
* an `L1`/`C1` check is refused on any profile but `lab`;
* the target must be the finding's own asset, and every control endpoint a campaign target (the
  normal `resolve_targets`/`check_campaign_caps` path then applies to them too);
* `check_pack_sha256` must be the deployment pack of the signed profile, `request_cap` the
  registry's, `benign_path` the control map's, and `expected_seq` the finding's current sequence.

The submitted input must equal the derived one exactly. That is what makes "no free-form template,
URL or payload" true at the signing boundary and not only in the UI: a hand-built submission that
differs in any field is `POLICY_DENIED verification_input_not_server_built`, and nothing is signed.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg

from aegis.common.repo import repository_root
from aegis.common.targets import TargetError, address_port
from aegis.common.verification import VerificationCheck, load_checks, pack_sha256
from aegis.common.verification_controls import ControlMap, cached_controls, controls_for
from aegis.m05_registry.caps import CampaignPolicy, network_profile
from aegis.m05_registry.errors import M05Error

__all__ = [
    "APPROVALS_ENV",
    "CAPABILITY",
    "approved_checks",
    "build_request_input",
    "check_request",
    "service_key",
]

APPROVALS_ENV = "AEGIS_VERIFY_APPROVALS"
CAPABILITY = "verify.check"


@dataclass(frozen=True, slots=True)
class Approvals:
    """The checks a deployment approves per network profile (empty when unnamed)."""

    lab: frozenset[str]
    internet: frozenset[str]

    def allowed(self, profile: str) -> frozenset[str]:
        return self.internet if profile == "internet" else self.lab


def _read_approvals(path: Path) -> Approvals:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise M05Error.dependency_missing(
            f"the verification approval file {path} cannot be read: {error}"
        ) from error
    if not isinstance(document, Mapping):
        raise M05Error.dependency_missing(f"{path}: the approvals must be an object")
    lists: dict[str, frozenset[str]] = {}
    for profile in ("lab", "internet"):
        values = document.get(profile) or []
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise M05Error.dependency_missing(f"{path}: {profile} must be a list of check ids")
        lists[profile] = frozenset(values)
    return Approvals(lab=lists["lab"], internet=lists["internet"])


def approved_checks(path: str | Path | None = None) -> Approvals:
    """The deployment's approved checks; an unnamed file approves nothing (fail closed)."""
    configured = Path(path) if path is not None else Path(os.environ.get(APPROVALS_ENV, ""))
    if not str(configured) or str(configured) == ".":
        return Approvals(lab=frozenset(), internet=frozenset())
    return _read_approvals(configured)


def approved_for(profile: str, path: str | Path | None = None) -> frozenset[str]:
    return approved_checks(path).allowed(profile)


def service_key(address: str, port: int) -> str:
    return f"service:{address}:{port}/tcp"


def _finding(connection: psycopg.Connection[Any], finding_id: str) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM finding WHERE finding_id = %s", (finding_id,)
    ).fetchone()
    if row is None:
        raise M05Error.input_invalid(
            f"finding {finding_id} does not exist", field="/input/finding_id"
        )
    return dict(row)


def build_request_input(
    connection: psycopg.Connection[Any],
    *,
    campaign: CampaignPolicy,
    check: VerificationCheck,
    finding_id: str,
    mapping: ControlMap | None = None,
) -> dict[str, Any]:
    """The one input a verification job may have, derived server-side from the finding."""
    return _derived(
        connection,
        campaign=campaign,
        profile=network_profile(campaign.policy),
        check=check,
        mapping=mapping if mapping is not None else cached_controls(),
        finding_id=finding_id,
    )


def _derived(
    connection: psycopg.Connection[Any],
    *,
    campaign: CampaignPolicy,
    profile: str,
    check: VerificationCheck,
    mapping: ControlMap,
    finding_id: str,
) -> dict[str, Any]:
    finding = _finding(connection, finding_id)
    # A finding belongs to every campaign that holds its asset; the request's campaign must hold
    # it too, or the run would scan a surface this campaign never authorized.
    held = connection.execute(
        "SELECT 1 FROM asset_campaign WHERE asset_id = %s AND campaign_id = %s",
        (finding["asset_id"], campaign.campaign_id),
    ).fetchone()
    if held is None:
        raise M05Error.policy_denied(
            "verification_target_not_in_scope",
            "the finding's asset is not held by this campaign",
            field="/input/finding_id",
        )
    if check.finding_rule != str(finding["rule_id"]):
        raise M05Error.policy_denied(
            "verification_check_not_applicable",
            f"check {check.check_id!r} verifies {check.finding_rule}, the finding is "
            f"{finding['rule_id']}",
            field="/input/check_id",
        )
    asset = connection.execute(
        "SELECT canonical_key FROM asset WHERE asset_id = %s", (finding["asset_id"],)
    ).fetchone()
    if asset is None:  # pragma: no cover - a finding always names an asset
        raise M05Error.dependency_missing(f"finding {finding_id} has no asset row")
    canonical = str(asset["canonical_key"])
    try:
        address, port = address_port(canonical)
    except TargetError as error:
        raise M05Error.policy_denied(
            "verification_target_not_in_scope", str(error), field="/input/targets"
        ) from error
    controls = controls_for(mapping, check.check_id)
    if controls is None or controls.patched_twin is None or controls.benign_path is None:
        raise M05Error.dependency_missing(
            f"the deployment has no control map for check {check.check_id!r}"
        )
    twin_key = service_key(controls.patched_twin.address, controls.patched_twin.port)
    targets = [canonical, twin_key] if twin_key != canonical else [canonical]
    try:
        pack = pack_sha256(repository_root() / "deploy" / profile / "verify")
    except ValueError as error:
        raise M05Error.dependency_missing(
            f"the {profile} verification pack is unusable: {error}"
        ) from error
    return {
        "check_id": check.check_id,
        "check_pack_sha256": pack,
        "expected_seq": int(finding["transition_seq"]),
        "request_cap": check.request_cap,
        "finding_id": finding_id,
        "targets": targets,
        "ports": sorted({port, controls.patched_twin.port}),
        "controls": [{"role": "patched_twin", "target": twin_key}],
        "benign_path": controls.benign_path,
    }


def check_request(
    connection: psycopg.Connection[Any],
    *,
    campaign: CampaignPolicy,
    submitted: Mapping[str, Any],
    approvals: Approvals | None = None,
    control_map: ControlMap | None = None,
) -> dict[str, Any]:
    """Validate (and return) the server-derived verification input; refuse on any difference."""
    profile = network_profile(campaign.policy)
    check_id = submitted.get("check_id")
    check = load_checks().by_id(str(check_id)) if isinstance(check_id, str) else None
    if check is None:
        raise M05Error.policy_denied(
            "verification_check_unknown",
            f"check {check_id!r} is not in the reviewed registry",
            field="/input/check_id",
        )
    allowed = (approvals or approved_checks()).allowed(profile)
    if check.check_id not in allowed:
        raise M05Error.policy_denied(
            "verification_check_not_approved",
            f"check {check.check_id!r} is not approved for the {profile} profile of this "
            "deployment",
            field="/input/check_id",
        )
    if check.lab_only and profile != "lab":
        raise M05Error.policy_denied(
            "verification_check_profile_mismatch",
            f"check {check.check_id!r} is lab-only; the campaign's signed profile is {profile}",
            field="/input/check_id",
        )
    mapping = control_map if control_map is not None else cached_controls()
    finding_id = submitted.get("finding_id")
    if not isinstance(finding_id, str):
        raise M05Error.input_invalid("finding_id is required", field="/input/finding_id")
    current = connection.execute(
        "SELECT transition_seq FROM finding WHERE finding_id = %s", (finding_id,)
    ).fetchone()
    if current is not None and submitted.get("expected_seq") != int(current["transition_seq"]):
        raise M05Error.input_invalid(
            f"expected_seq {submitted.get('expected_seq')!r} is not the finding's transition_seq "
            f"{current['transition_seq']}",
            field="/input/expected_seq",
        )
    derived = _derived(
        connection,
        campaign=campaign,
        profile=profile,
        check=check,
        mapping=mapping,
        finding_id=finding_id,
    )
    if dict(submitted) != derived:
        raise M05Error.policy_denied(
            "verification_input_not_server_built",
            "the verification input is derived from the finding, the check registry and the "
            "deployment's control map; the submitted input differs",
            field="/input",
        )
    return derived
