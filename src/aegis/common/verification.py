"""The verification check pack (`contracts/verification/checks.v2.yaml`) as one reviewed registry.

Dynamic verification runs only checks declared here. A check id is a contract enum, not an
operator input: M05 signs it, M06 mounts only the pack of the signed profile, and M21 decides with
the oracle named here. Adding a check is a reviewed contract change (this file, the id enum of
`verification-request.v2`, and the L1/C1 template), never a free-form template, URL or payload.

The registry has two jobs:

* structure: every entry declares a class (E1 config | L1 behaviour | C1 credential), whether it is
  lab-only, its provider, the finding rule it verifies, the negative controls a lab run needs and a
  hard request cap;
* pin: an L1/C1 entry names the template file and the sha256 of its exact bytes. The template lives
  in the deployment pack (`deploy/lab/verify/templates`), so `load_checks(template_root=...)` reads
  the reviewed bytes and refuses a swap; M06 does the same before a container exists.

`pack_sha256(directory)` hashes a pack directory (the generated registry copy plus its templates)
as `sha256` over the sorted `<relative path>\\0<file sha256>\\n` records. The deployment profile
holds that value (S3) and M06 compares it with the mounted pack and the signed task.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, NoReturn

import yaml

from aegis.common.repo import contract_path

__all__ = [
    "CheckPack",
    "VerificationCheck",
    "load_checks",
    "pack_sha256",
]

CHECKS = ("verification", "checks.v2.yaml")
CHECK_CLASSES = ("E1", "L1", "C1")
#: Oracle -> the only class allowed to use it. A new oracle is a code change reviewed with the pack.
ORACLE_CLASSES = {
    "canary-extract": "L1",
    "certificate-property": "E1",
    "tls-version-list": "E1",
    "product-version": "E1",
    "listing-name": "E1",
}
#: Provider -> the class it executes. C1 has no provider until V7 reuses credentials.
PROVIDER_CLASSES = {"nuclei-verify": "L1", "config-verify": "E1"}
#: `expected.kind` while the only expectation with two properties is the certificate check.
EXPECTED_KINDS = ("certificate",)
ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
TEMPLATE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]*\.yaml$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Targets:
    """The roles one lab run must supply (positive, patched twin, benign control)."""

    positive: int
    control_patched_twin: int
    control_benign: int


@dataclass(frozen=True)
class VerificationCheck:
    """One reviewed check; `per_target`/`request_cap` bound the whole run, all addresses."""

    check_id: str
    title: str
    check_class: str
    lab_only: bool
    provider: str
    finding_rule: str
    oracle: str
    per_target: int
    request_cap: int
    targets: Targets
    template: str | None = None
    template_sha256: str | None = None
    expected_kind: str | None = None


@dataclass(frozen=True)
class CheckPack:
    checks: tuple[VerificationCheck, ...]

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(check.check_id for check in self.checks)

    def by_id(self, check_id: str) -> VerificationCheck | None:
        return next((check for check in self.checks if check.check_id == check_id), None)

    def lab_only(self) -> tuple[VerificationCheck, ...]:
        return tuple(check for check in self.checks if check.lab_only)

    def e1(self) -> tuple[VerificationCheck, ...]:
        return tuple(check for check in self.checks if check.check_class == "E1")


def _fail(path: Path, index: int | None, message: str) -> NoReturn:
    where = f"checks[{index}]" if index is not None else "checks"
    raise ValueError(f"{path}: {where}: {message}")


def _mapping(path: Path, index: int | None, value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, index, f"{what} must be a mapping")
    return value


def _string(path: Path, index: int | None, value: Any, what: str, *, max_length: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        _fail(path, index, f"{what} must be a non-empty string of at most {max_length} characters")
    return value


def _integer(path: Path, index: int | None, value: Any, what: str, *, minimum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        _fail(path, index, f"{what} must be an integer >= {minimum}")
    return value


def _known_keys(path: Path, index: int | None, value: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        _fail(path, index, f"unknown fields {unknown}")


def template_sha256(path: Path) -> str:
    """sha256 of a template's exact bytes (the file hash a check pins)."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_template(
    path: Path, index: int, check: dict[str, Any], template_root: Path | None
) -> tuple[str, str]:
    name = _string(path, index, check.get("template"), "template", max_length=128)
    if not TEMPLATE_PATTERN.match(name):
        _fail(path, index, f"template {name!r} must be a plain *.yaml file name")
    digest = _string(path, index, check.get("templateSha256"), "templateSha256", max_length=64)
    if not SHA256_PATTERN.match(digest):
        _fail(path, index, "templateSha256 must be 64 lowercase hex characters")
    if template_root is not None:
        file = template_root / name
        if file.is_symlink() or not file.is_file():
            _fail(
                path,
                index,
                f"template {name!r} is missing or not a regular file in {template_root}",
            )
        actual = template_sha256(file)
        if actual != digest:
            _fail(path, index, f"template {name!r} has sha256 {actual}, the registry pins {digest}")
    return name, digest


def _parse_check(path: Path, index: int, raw: Any, template_root: Path | None) -> VerificationCheck:
    entry = _mapping(path, index, raw, "check")
    _known_keys(
        path,
        index,
        entry,
        {
            "id",
            "title",
            "class",
            "labOnly",
            "provider",
            "appliesTo",
            "template",
            "templateSha256",
            "targets",
            "requests",
            "oracle",
            "expected",
        },
    )
    check_id = _string(path, index, entry.get("id"), "id", max_length=64)
    if not ID_PATTERN.match(check_id):
        _fail(path, index, f"id {check_id!r} is not a contract check id")
    title = _string(path, index, entry.get("title"), "title", max_length=200)
    check_class = _string(path, index, entry.get("class"), "class", max_length=2)
    if check_class not in CHECK_CLASSES:
        _fail(path, index, f"class {check_class!r} is not one of {CHECK_CLASSES}")
    lab_only = entry.get("labOnly")
    if not isinstance(lab_only, bool):
        _fail(path, index, "labOnly must be a boolean")
    if lab_only != (check_class != "E1"):
        _fail(path, index, "labOnly must be true exactly for L1/C1 and false for E1")
    provider = _string(path, index, entry.get("provider"), "provider", max_length=64)
    provider_class = PROVIDER_CLASSES.get(provider)
    if provider_class is None:
        _fail(path, index, f"provider {provider!r} is not one of {sorted(PROVIDER_CLASSES)}")
    if provider_class != check_class:
        _fail(path, index, f"provider {provider!r} runs {provider_class}, not {check_class}")

    applies = _mapping(path, index, entry.get("appliesTo"), "appliesTo")
    _known_keys(path, index, applies, {"findingRule"})
    finding_rule = _string(
        path, index, applies.get("findingRule"), "appliesTo.findingRule", max_length=200
    )
    prefix = "cve:" if check_class == "L1" else "config:"
    if not finding_rule.startswith(prefix):
        _fail(
            path, index, f"appliesTo.findingRule must start with {prefix!r} for class {check_class}"
        )

    targets_raw = _mapping(path, index, entry.get("targets"), "targets")
    _known_keys(path, index, targets_raw, {"positive", "controlPatchedTwin", "controlBenign"})
    targets = Targets(
        positive=_integer(path, index, targets_raw.get("positive"), "targets.positive", minimum=1),
        control_patched_twin=_integer(
            path,
            index,
            targets_raw.get("controlPatchedTwin"),
            "targets.controlPatchedTwin",
            minimum=0,
        ),
        control_benign=_integer(
            path, index, targets_raw.get("controlBenign"), "targets.controlBenign", minimum=0
        ),
    )
    # A lab-only check without both negative controls cannot decide anything (D29/OD-B).
    if lab_only and (targets.control_patched_twin != 1 or targets.control_benign != 1):
        _fail(path, index, "lab-only checks need exactly one patched twin and one benign control")

    requests_raw = _mapping(path, index, entry.get("requests"), "requests")
    _known_keys(path, index, requests_raw, {"perTarget", "cap"})
    per_target = _integer(
        path, index, requests_raw.get("perTarget"), "requests.perTarget", minimum=1
    )
    request_cap = _integer(path, index, requests_raw.get("cap"), "requests.cap", minimum=1)
    if request_cap < per_target:
        _fail(path, index, "requests.cap must be at least requests.perTarget")

    oracle = _string(path, index, entry.get("oracle"), "oracle", max_length=64)
    oracle_class = ORACLE_CLASSES.get(oracle)
    if oracle_class is None:
        _fail(path, index, f"oracle {oracle!r} is not one of {sorted(ORACLE_CLASSES)}")
    if oracle_class != check_class:
        _fail(path, index, f"oracle {oracle!r} belongs to {oracle_class}, not {check_class}")

    expected_kind: str | None = None
    if "expected" in entry:
        expected = _mapping(path, index, entry["expected"], "expected")
        _known_keys(path, index, expected, {"kind"})
        expected_kind = _string(path, index, expected.get("kind"), "expected.kind", max_length=32)
        if expected_kind not in EXPECTED_KINDS:
            _fail(path, index, f"expected.kind {expected_kind!r} is not one of {EXPECTED_KINDS}")
        if check_id != "config.tls.certificate":
            _fail(path, index, "expected is only meaningful for config.tls.certificate")

    template: str | None = None
    digest: str | None = None
    if lab_only:
        if "template" not in entry or "templateSha256" not in entry:
            _fail(path, index, "lab-only checks must pin template and templateSha256")
        template, digest = _verify_template(path, index, entry, template_root)
    elif "template" in entry or "templateSha256" in entry:
        _fail(path, index, "E1 checks run reviewed code, not a template")

    return VerificationCheck(
        check_id=check_id,
        title=title,
        check_class=check_class,
        lab_only=lab_only,
        provider=provider,
        finding_rule=finding_rule,
        oracle=oracle,
        per_target=per_target,
        request_cap=request_cap,
        targets=targets,
        template=template,
        template_sha256=digest,
        expected_kind=expected_kind,
    )


@cache
def _load(path: Path, template_root: Path | None) -> CheckPack:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path}: the check pack must be a mapping")
    if document.get("apiVersion") != "aegis.io/v2":
        raise ValueError(f"{path}: apiVersion must be 'aegis.io/v2'")
    if document.get("kind") != "VerificationCheckPack":
        raise ValueError(f"{path}: kind must be 'VerificationCheckPack'")
    raw_checks = document.get("checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        raise ValueError(f"{path}: `checks` must be a non-empty list")
    checks = tuple(
        _parse_check(path, index, raw, template_root) for index, raw in enumerate(raw_checks)
    )
    ids = [check.check_id for check in checks]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate check id in {ids}")
    return CheckPack(checks)


def load_checks(template_root: Path | None = None) -> CheckPack:
    """Parse and validate the published registry.

    `template_root` is the deployment pack's `templates/` directory. When given (M06, the pack
    generator and its tests), every declared template must exist with exactly the pinned bytes; a
    missing or swapped template refuses the whole pack. Callers that only list checks (M05/M26) may
    pass None, but they never execute a template.
    """
    return _load(contract_path(*CHECKS), None if template_root is None else Path(template_root))


def pack_sha256(directory: Path) -> str:
    """The content hash of a pack directory: sorted `<relative path>\\0<file sha256>\\n` records.

    Every regular file under `directory` is part of the pack (the registry copy and its templates),
    sorted by its POSIX relative path, so the value depends only on the file set and their bytes.
    A symlink is refused: a pack is read from one mounted tree, never followed out of it.
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise ValueError(f"{directory}: not a pack directory")
    files = [path for path in directory.rglob("*") if path.is_file() or path.is_symlink()]
    files.sort(key=lambda path: path.relative_to(directory).as_posix())
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise ValueError(f"{directory}: pack file {relative} is a symlink")
        if not path.is_file():
            raise ValueError(f"{directory}: pack entry {relative} is not a regular file")
        record = f"{relative}\x00{template_sha256(path)}\n"
        digest.update(record.encode("utf-8"))
    return digest.hexdigest()
