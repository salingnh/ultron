"""M06's layer of the verification gate: re-check the signed run before any container exists.

Dynamic verification is refused three times, fail closed (owner decision D29, design §7): M05 at
signing, the deployment profile (only the lab carries an L1 template or a Nuclei entry) and M06
here. M06 trusts nothing it is handed:

1. the deployment profile of the job's image must carry a `verify` block; a profile without one
   (the internet profile, by design) can never run a verification, so a hand-built task signed with
   the development key is refused before anything is created;
2. the pack directory is hashed now, and its hash must equal the profile pin **and** the
   `check_pack_sha256` of the signed task - a swapped template or a stale pack is
   `DEPENDENCY_MISSING`, never a scan against bytes nobody pinned;
3. the pack must be the source of the mount at the profile's target: the container reads exactly
   the bytes that were hashed;
4. the check id must be in that mounted pack, the check's provider must be the task's provider, and
   a lab-only (`L1`/`C1`) check may only run on the `lab` profile.

The gate runs first in `JobRunner.prepare`, before the egress policy, the network and the container,
so a refused verification sends zero packets and creates zero containers. The result document's
decision is M21's; this module only refuses runs there is no honest way to execute.
"""

from __future__ import annotations

from typing import Any

from aegis.common.verification import load_checks, pack_sha256
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.m06_runner.profile import DeploymentProfile, JobProfile
from aegis.m06_runner.spec import SpecError
from aegis.m06_runner.values import text

__all__ = ["check_verification"]

CAPABILITY = "verify.check"


def _refuse(code: str, detail: str) -> SpecError:
    return SpecError(code, detail)


def check_verification(
    *,
    capability: str,
    network_profile: str,
    image_digest: str,
    provider: str,
    input_values: Any,
    manifest: ProviderManifest,
    profile: DeploymentProfile,
    entry: JobProfile | None,
) -> None:
    """Refuse a `verify.check` job the deployment cannot honestly run; return None otherwise."""
    if capability != CAPABILITY:
        return
    if text(manifest.spec.capability) != CAPABILITY:  # pragma: no cover - M05 pins the manifest
        raise _refuse("POLICY_DENIED", "the pinned manifest is not a verification provider")
    if entry is None:
        raise _refuse(
            "POLICY_DENIED",
            f"the {network_profile} deployment has no profile entry for {image_digest}; a "
            "verification provider only runs where the deployment mounts a reviewed check pack",
        )
    pack = entry.verify
    if pack is None:
        raise _refuse(
            "POLICY_DENIED",
            f"the {network_profile} profile entry for {image_digest} has no `verify` pack; a "
            "verification run needs the reviewed pack of its deployment",
        )
    if not isinstance(input_values, dict):
        raise _refuse("POLICY_DENIED", "the signed verification input is not an object")
    check_id = input_values.get("check_id")
    signed_pack = input_values.get("check_pack_sha256")
    if not isinstance(check_id, str) or not isinstance(signed_pack, str):
        raise _refuse("POLICY_DENIED", "the signed verification input has no check id or pack")
    if signed_pack != pack.sha256:
        raise _refuse(
            "POLICY_DENIED",
            "the signed task's check_pack_sha256 is not the pack this deployment pins",
        )
    mount = next(
        (item for item in entry.mounts if item.target == pack.target and item.source is not None),
        None,
    )
    if mount is None or mount.source is None or mount.source.resolve() != pack.pack.resolve():
        raise _refuse(
            "DEPENDENCY_MISSING",
            f"the verification pack {pack.pack} is not mounted at {pack.target}; the container "
            "would read bytes nobody hashed",
        )
    try:
        actual = pack_sha256(pack.pack)
        checks = load_checks(pack.pack / "templates")
    except (OSError, ValueError) as error:
        raise _refuse(
            "DEPENDENCY_MISSING", f"the verification pack is unusable: {error}"
        ) from error
    if actual != pack.sha256:
        raise _refuse(
            "DEPENDENCY_MISSING",
            f"the verification pack at {pack.pack} has sha256 {actual}, the profile pins "
            f"{pack.sha256}",
        )
    check = checks.by_id(check_id)
    if check is None:
        raise _refuse(
            "POLICY_DENIED",
            f"check {check_id!r} is not in the pack mounted for this profile",
        )
    if check.provider != provider:
        raise _refuse(
            "POLICY_DENIED",
            f"check {check_id!r} runs on provider {check.provider!r}, the task names {provider!r}",
        )
    if check.lab_only and network_profile != "lab":
        raise _refuse(
            "POLICY_DENIED",
            f"check {check_id!r} is lab-only; a {network_profile} job cannot run it",
        )
    if input_values.get("request_cap") != check.request_cap:
        raise _refuse(
            "POLICY_DENIED",
            f"the signed request cap {input_values.get('request_cap')!r} is not the registry's "
            f"{check.request_cap}",
        )
    benign_path = input_values.get("benign_path")
    if not isinstance(benign_path, str) or not benign_path.startswith("/"):
        raise _refuse("POLICY_DENIED", "the signed benign control path is not an absolute path")
