"""Vulnlab testcase catalog: the loader, its static rules and the detection assertions (G1.6).

The catalog (`cases.yaml`, next to this file) is the acceptance spec for the discovery chain on a
known-vulnerable lab: per service the open port, the product/version/CPE a fingerprint should read,
and the CVE ids the candidate matcher (slice C) must return - plus the ids it must *not* return,
because a version-range matcher that ignores its range is a silent false-positive factory.

Two halves, both importable without a stack:

* `load_catalog()` reads and validates the YAML. Everything static is checked here, so a broken
  pin, a duplicated hostname or a KEV id outside `mustInclude` fails in CI (see
  `tests/test_vulnlab_catalog.py`) instead of halfway through a live run.
* `compare()` turns a `CampaignSnapshot` (what the campaign actually recorded) into a per-case
  verdict (`pass` / `fail` / `blocked`). It is pure: the runner in `scripts/vulnlab/test_cases.py`
  only reads PostgreSQL/Neo4j and builds the snapshot, and the unit tests feed the same function
  synthetic snapshots.

`blocked` is deliberately different from `fail`: a campaign that ran only DNS capabilities cannot
assert anything about ports, products or CVEs, and saying so is not the same as a detector that ran
and found the wrong thing.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

__all__ = [
    "CATALOG_PATH",
    "CASE_PROFILES",
    "Catalog",
    "CatalogError",
    "CampaignSnapshot",
    "Case",
    "CaseVerdict",
    "Check",
    "Cpe",
    "CveExpectation",
    "CveFinding",
    "Expectation",
    "ProductExpectation",
    "ServiceFinding",
    "WebFinding",
    "campaign_target",
    "compare",
    "load_catalog",
]

CATALOG_PATH = Path(__file__).with_name("cases.yaml")
CASE_PROFILES = ("lab", "internet")

FEED_KEYS = ("nvd", "kev")
#: Fields every profile expectation must carry. `product`/`cves` are optional on purpose: an
#: origin that publishes no product marker (no Server header, no title, no X- header) has nothing
#: the chain could identity, and `product: null` together with an empty `cves` is the honest
#: expectation - the evidence (the probe transcript) belongs in a comment next to it.
PROFILE_REQUIRED = ("ports",)
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
IMAGE_REF = re.compile(
    r"^(?P<repo>[a-z0-9][a-z0-9._/-]*):(?P<tag>[A-Za-z0-9._-]+)@sha256:(?P<digest>[0-9a-f]{64})$"
)
HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{1,63}$")
#: Compose service key; the container is `<project>-<service>` (see compose.yaml).
SERVICE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
#: CPE 2.3 formatted string: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:...
CPE_PREFIX = "cpe:2.3:"


class CatalogError(ValueError):
    """The catalog is not usable; the message names the entry and the field."""


# --- static model ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Cpe:
    """The CPE 2.3 triple the candidate matcher keys on (vendor, product, version)."""

    part: str
    vendor: str
    product: str
    version: str
    text: str

    @classmethod
    def parse(cls, raw: str) -> Cpe:
        text = raw.strip()
        if not text.startswith(CPE_PREFIX):
            raise CatalogError(f"CPE must be a cpe:2.3 formatted string, got {raw!r}")
        fields = text.split(":")
        # `cpe:2.3:a:vendor:product:version` is accepted as shorthand and expanded to the full
        # 13-field form; anything longer must already be complete.
        if len(fields) == 6:
            fields += ["*"] * 7
        if len(fields) != 13:
            raise CatalogError(f"CPE must have 13 fields (or the 6-field shorthand), got {raw!r}")
        if fields[1] != "2.3" or fields[2] not in {"a", "o", "h"}:
            raise CatalogError(f"CPE part/version is not 2.3:{raw!r}")
        vendor, product, version = fields[3], fields[4], fields[5]
        for name, value in (("vendor", vendor), ("product", product), ("version", version)):
            if not value or value == "*":
                raise CatalogError(f"CPE {name} must be concrete in the catalog: {raw!r}")
        return cls(
            part=fields[2], vendor=vendor, product=product, version=version, text=":".join(fields)
        )


@dataclass(frozen=True, slots=True)
class ProductExpectation:
    """What a fingerprint should say about the service, and the CPE it should map to."""

    names: tuple[str, ...]
    version_prefix: str
    cpe: Cpe


@dataclass(frozen=True, slots=True)
class CveExpectation:
    must_include: tuple[str, ...] = ()
    kev: tuple[str, ...] = ()
    must_not_include: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Expectation:
    """One profile's assertions for a case (`lab` or `internet`)."""

    ports: tuple[int, ...]
    product: ProductExpectation | None
    cves: CveExpectation | None
    http_status: int | None = None
    http_title_contains: str | None = None
    ip: str | None = None
    note: str | None = None


@dataclass(frozen=True, slots=True)
class Case:
    id: str
    title: str
    image_env: str
    image_version: str
    version: str
    license: str
    service: str
    image_port: int
    request_path: str
    disclose_server: str | None
    disclose_body: tuple[str, ...]
    lab_address: str
    host_env: str | None
    expectations: Mapping[str, Expectation]
    disclose_status: int | None = None
    read_only_rootfs: bool = True
    read_only_reason: str | None = None

    def expectation(self, profile: str) -> Expectation:
        try:
            return self.expectations[profile]
        except KeyError as error:  # pragma: no cover - load_catalog validates both profiles
            raise CatalogError(f"case {self.id} has no {profile} expectations") from error


@dataclass(frozen=True, slots=True)
class Catalog:
    api_version: str
    version: int
    feed: Mapping[str, Mapping[str, str]]
    networks: Mapping[str, str]
    policy: Mapping[str, Any]
    timeout_seconds: int
    cases: tuple[Case, ...]

    def case(self, case_id: str) -> Case:
        for item in self.cases:
            if item.id == case_id:
                return item
        raise CatalogError(f"unknown case id {case_id!r}")

    def host_envs(self) -> dict[str, str]:
        """`{case_id: host env var}` for the cases that have a public hostname."""
        return {case.id: case.host_env for case in self.cases if case.host_env}


# --- loader ----------------------------------------------------------------------------------


def load_catalog(path: str | Path = CATALOG_PATH) -> Catalog:
    """Read and validate the catalog; a `CatalogError` names the entry and the field."""
    catalog_path = Path(path)
    try:
        document = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise CatalogError(f"cannot read {catalog_path}: {error}") from error
    except yaml.YAMLError as error:
        raise CatalogError(f"{catalog_path} is not valid YAML: {error}") from error
    if not isinstance(document, Mapping):
        raise CatalogError(f"{catalog_path} must be a mapping")

    api_version = _text(document, "apiVersion")
    if api_version != "aegis.io/v2":
        raise CatalogError(f"apiVersion must be aegis.io/v2, got {api_version!r}")
    version = document.get("version")
    if not isinstance(version, int) or version < 1:
        raise CatalogError("version must be a positive integer")

    feed = _feed(document.get("feed"))
    networks = _networks(document.get("network"))
    policy, timeout_seconds = _campaign(document.get("campaign"))

    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise CatalogError("cases must be a non-empty list")
    cases = tuple(_case(entry, index) for index, entry in enumerate(raw_cases))
    _unique(cases)
    return Catalog(
        api_version=api_version,
        version=version,
        feed=feed,
        networks=networks,
        policy=policy,
        timeout_seconds=timeout_seconds,
        cases=cases,
    )


def _text(mapping: Mapping[str, Any], key: str, where: str = "catalog") -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{where}: {key} must be a non-empty string")
    return value.strip()


def _feed(raw: Any) -> dict[str, Mapping[str, str]]:
    if not isinstance(raw, Mapping):
        raise CatalogError("feed must be a mapping with nvd and kev")
    feed: dict[str, Mapping[str, str]] = {}
    for name in FEED_KEYS:
        entry = raw.get(name)
        if not isinstance(entry, Mapping):
            raise CatalogError(f"feed.{name} must be a mapping")
        fields: dict[str, str] = {}
        for key, value in entry.items():
            if not isinstance(key, str) or not isinstance(value, str) or not value.strip():
                raise CatalogError(f"feed.{name}.{key} must be a non-empty string")
            fields[key] = value.strip()
        feed[name] = fields
    for required in ("retrievedAt", "source"):
        if required not in feed["nvd"]:
            raise CatalogError(
                f"feed.nvd.{required} is required (which CVE data the ids came from)"
            )
    for required in ("catalogVersion", "releasedAt"):
        if required not in feed["kev"]:
            raise CatalogError(
                f"feed.kev.{required} is required (which KEV snapshot kev flags mean)"
            )
    return feed


def _networks(raw: Any) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise CatalogError("network must be a mapping")
    names: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str) or not value.strip():
            raise CatalogError(f"network.{key} must be a non-empty string")
        names[key] = value.strip()
    for required in ("lab", "internal", "subnet", "labSubnet", "egress"):
        if required not in names:
            raise CatalogError(f"network.{required} is required")
    for key in ("subnet", "labSubnet"):
        try:
            ipaddress.ip_network(names[key], strict=True)
        except ValueError as error:
            raise CatalogError(f"network.{key} is not a network: {names[key]!r}") from error
    for key in ("lab", "internal", "egress"):
        if not names[key].startswith("aegis-"):
            raise CatalogError(f"network.{key} must name an aegis-* network, got {names[key]!r}")
    return names


def _campaign(raw: Any) -> tuple[Mapping[str, Any], int]:
    if not isinstance(raw, Mapping):
        raise CatalogError("campaign must be a mapping")
    policy = raw.get("policy")
    if not isinstance(policy, Mapping):
        raise CatalogError("campaign.policy must be a mapping (the RoE policy body)")
    timeout = raw.get("timeoutSeconds")
    if not isinstance(timeout, int) or not 30 <= timeout <= 3600:
        raise CatalogError("campaign.timeoutSeconds must be an integer in [30, 3600]")
    return policy, timeout


def _case(raw: Any, index: int) -> Case:
    where = f"cases[{index}]"
    if not isinstance(raw, Mapping):
        raise CatalogError(f"{where} must be a mapping")
    case_id = _text(raw, "id", where)
    if not CASE_ID.match(case_id):
        raise CatalogError(f"{where}.id must match {CASE_ID.pattern}, got {case_id!r}")
    where = f"case {case_id}"
    image_env = _text(raw, "imageEnv", where)
    if not ENV_NAME.match(image_env):
        raise CatalogError(f"{where}: imageEnv must be an env var name, got {image_env!r}")
    service = _text(raw, "service", where)
    if not SERVICE.match(service):
        raise CatalogError(
            f"{where}: service must be a compose service name ({SERVICE.pattern}), got {service!r}"
        )
    image_version = _text(raw, "imageVersion", where)
    version = _text(raw, "version", where)
    license_name = _text(raw, "license", where)
    image_port = raw.get("imagePort")
    if not isinstance(image_port, int) or not 1 <= image_port <= 65535:
        raise CatalogError(f"{where}: imagePort must be a port number")
    request_path = raw.get("request")
    if not isinstance(request_path, Mapping):
        raise CatalogError(f"{where}: request must be a mapping with path")
    path = _text(request_path, "path", f"{where}.request")

    disclose = raw.get("disclose")
    if not isinstance(disclose, Mapping):
        raise CatalogError(f"{where}: disclose must be a mapping (what the raw service reveals)")
    server = disclose.get("server")
    if server is not None and not isinstance(server, str):
        raise CatalogError(f"{where}.disclose.server must be a string")
    body = disclose.get("bodyContains", [])
    if not isinstance(body, list) or not all(isinstance(item, str) and item for item in body):
        raise CatalogError(f"{where}.disclose.bodyContains must be a list of strings")
    disclose_status = disclose.get("status")
    if disclose_status is not None and (
        not isinstance(disclose_status, int) or not 100 <= disclose_status <= 599
    ):
        raise CatalogError(f"{where}.disclose.status must be an HTTP status")

    lab = raw.get("lab")
    if not isinstance(lab, Mapping):
        raise CatalogError(f"{where}.lab must be a mapping with address and port")
    address = _text(lab, "address", f"{where}.lab")
    try:
        ipaddress.ip_address(address)
    except ValueError as error:
        raise CatalogError(f"{where}.lab.address is not an IP: {address!r}") from error
    lab_port = lab.get("port")
    if lab_port != image_port:
        raise CatalogError(
            f"{where}.lab.port must equal imagePort {image_port}: the origin listens on one port"
        )

    internet = raw.get("internet")
    if not isinstance(internet, Mapping):
        raise CatalogError(f"{where}.internet must be a mapping with hostEnv")
    host_env = internet.get("hostEnv")
    if host_env is not None and (not isinstance(host_env, str) or not ENV_NAME.match(host_env)):
        raise CatalogError(f"{where}.internet.hostEnv must be an env var name")

    raw_expect = raw.get("expect")
    if not isinstance(raw_expect, Mapping):
        raise CatalogError(f"{where}.expect must be a mapping with lab and internet")
    for profile in CASE_PROFILES:
        if profile not in raw_expect:
            raise CatalogError(f"{where}.expect.{profile} is required")
    expectations = {
        profile: _expectation(raw_expect[profile], f"{where}.expect.{profile}", profile)
        for profile in CASE_PROFILES
    }
    read_only = raw.get("readOnlyRootfs", True)
    if not isinstance(read_only, bool):
        raise CatalogError(f"{where}: readOnlyRootfs must be a boolean")
    read_only_reason = raw.get("readOnlyReason")
    if read_only is False and (
        not isinstance(read_only_reason, str) or not read_only_reason.strip()
    ):
        raise CatalogError(f"{where}: a writable rootfs needs readOnlyReason")
    return Case(
        id=case_id,
        title=_text(raw, "title", where),
        image_env=image_env,
        image_version=image_version,
        version=version,
        license=license_name,
        service=service,
        image_port=image_port,
        request_path=path if path.startswith("/") else "/" + path,
        disclose_server=server,
        disclose_body=tuple(body),
        disclose_status=disclose_status,
        lab_address=address,
        host_env=host_env,
        expectations=expectations,
        read_only_rootfs=read_only,
        read_only_reason=read_only_reason.strip() if isinstance(read_only_reason, str) else None,
    )


def _expectation(raw: Any, where: str, profile: str) -> Expectation:
    if not isinstance(raw, Mapping):
        raise CatalogError(f"{where} must be a mapping")
    for required in PROFILE_REQUIRED:
        if required not in raw:
            raise CatalogError(f"{where}.{required} is required")
    ports = raw.get("ports")
    if not isinstance(ports, list) or not ports:
        raise CatalogError(f"{where}.ports must be a non-empty list")
    for port in ports:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise CatalogError(f"{where}.ports contains a non-port {port!r}")
    if len(set(ports)) != len(ports):
        raise CatalogError(f"{where}.ports contains duplicates")

    product_raw = raw.get("product")
    product: ProductExpectation | None = None
    if product_raw is not None:
        if not isinstance(product_raw, Mapping):
            raise CatalogError(f"{where}.product must be a mapping or null")
        names = product_raw.get("names")
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(item, str) and item.strip() for item in names)
        ):
            raise CatalogError(f"{where}.product.names must be a non-empty list of strings")
        version_prefix = _text(product_raw, "versionPrefix", f"{where}.product")
        product = ProductExpectation(
            names=tuple(item.strip() for item in names),
            version_prefix=version_prefix,
            cpe=Cpe.parse(_text(product_raw, "cpe", f"{where}.product")),
        )

    cves_raw = raw.get("cves")
    cves: CveExpectation | None = None
    if cves_raw is not None:
        if not isinstance(cves_raw, Mapping):
            raise CatalogError(f"{where}.cves must be a mapping or null")
        cves = CveExpectation(
            must_include=_cve_list(cves_raw, "mustInclude", where),
            kev=_cve_list(cves_raw, "kev", where),
            must_not_include=_cve_list(cves_raw, "mustNotInclude", where),
        )
    if cves is not None:
        overlap = set(cves.must_include) & set(cves.must_not_include)
        if overlap:
            raise CatalogError(f"{where}.cves: ids both expected and forbidden: {sorted(overlap)}")
        outside = set(cves.kev) - set(cves.must_include)
        if outside:
            raise CatalogError(
                f"{where}.cves.kev must be a subset of mustInclude: {sorted(outside)}"
            )

    status = raw.get("httpStatus")
    if status is not None and (not isinstance(status, int) or not 100 <= status <= 599):
        raise CatalogError(f"{where}.httpStatus must be an HTTP status")
    title = raw.get("httpTitleContains")
    if title is not None and (not isinstance(title, str) or not title):
        raise CatalogError(f"{where}.httpTitleContains must be a non-empty string")
    ip = raw.get("ip")
    if ip is not None:
        try:
            ipaddress.ip_address(ip)
        except ValueError as error:
            raise CatalogError(f"{where}.ip is not an IP: {ip!r}") from error
    note = raw.get("note")
    if note is not None and (not isinstance(note, str) or not note.strip()):
        raise CatalogError(f"{where}.note must be a non-empty string")
    if profile == "lab" and ip is None:
        raise CatalogError(f"{where}.ip is required on the lab profile (the origin's own address)")
    return Expectation(
        ports=tuple(ports),
        product=product,
        cves=cves,
        http_status=status,
        http_title_contains=title,
        ip=ip,
        note=note,
    )


def _cve_list(raw: Mapping[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CatalogError(f"{where}.cves.{key} must be a list of CVE ids")
    for item in value:
        if not CVE_ID.match(item):
            raise CatalogError(f"{where}.cves.{key} has a malformed CVE id {item!r}")
    if len(set(value)) != len(value):
        raise CatalogError(f"{where}.cves.{key} contains duplicates")
    return tuple(value)


def _unique(cases: Sequence[Case]) -> None:
    for label, values in (
        ("id", [case.id for case in cases]),
        ("service", [case.service for case in cases]),
        ("imageEnv", [case.image_env for case in cases]),
        ("lab.address", [case.lab_address for case in cases]),
        ("internet.hostEnv", [case.host_env for case in cases if case.host_env]),
    ):
        duplicates = sorted({value for value in values if values.count(value) > 1})
        if duplicates:
            raise CatalogError(f"cases share a {label}: {duplicates}")


def assert_image_pins(catalog: Catalog, images: Mapping[str, str]) -> None:
    """Every case's image pin exists and carries the version the catalog records.

    `images` is the parsed `deploy/vulnlab/images.env` (env var -> digest-pinned reference). The
    static test calls this, so a pinned image and the catalog cannot drift apart silently.
    """
    for case in catalog.cases:
        reference = images.get(case.image_env)
        if reference is None:
            raise CatalogError(f"images.env has no {case.image_env} (case {case.id})")
        match = IMAGE_REF.match(reference.strip())
        if match is None:
            raise CatalogError(
                f"images.env {case.image_env} must be <repo>:<tag>@sha256:<64 hex>, "
                f"got {reference!r}"
            )
        if case.image_version not in match.group("tag"):
            raise CatalogError(
                f"images.env {case.image_env} tag {match.group('tag')!r} does not carry "
                f"imageVersion {case.image_version!r} (case {case.id})"
            )


# --- campaign target -------------------------------------------------------------------------


def campaign_target(case: Case, profile: str, hostnames: Mapping[str, str]) -> Mapping[str, Any]:
    """The `targets` body of `POST /campaigns` for one case and profile.

    `lab` targets the origin's own address on the lab network; `internet` targets the public
    hostname (the tunnel origin port is not visible from outside, so the campaign must target the
    name, not the origin address). A missing hostname is an error, never a silent fallback.
    """
    if profile == "lab":
        return {"ips": [case.lab_address]}
    if profile != "internet":
        raise CatalogError(f"unknown profile {profile!r}")
    env = case.host_env
    if env is None:
        raise CatalogError(f"case {case.id} has no internet hostname")
    hostname = (hostnames.get(env) or "").strip().lower()
    if not hostname:
        raise CatalogError(f"{env} is empty: set the public hostname in deploy/vulnlab/.env")
    if not HOSTNAME.match(hostname):
        raise CatalogError(f"{env} is not a lowercase FQDN: {hostname!r}")
    return {"domains": [hostname]}


# --- what a campaign recorded ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ServiceFinding:
    ip: str
    port: int
    transport: str = "tcp"
    product: str | None = None
    version: str | None = None
    cpe: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WebFinding:
    url: str
    status: int | None = None
    title: str | None = None
    technology: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CveFinding:
    asset: str
    cve_id: str
    kev: bool | None = None


@dataclass(frozen=True, slots=True)
class CampaignSnapshot:
    """Everything one campaign recorded for one case, already scoped to the campaign."""

    campaign_id: str
    status: str
    jobs: tuple[str, ...] = ()
    services: tuple[ServiceFinding, ...] = ()
    web: tuple[WebFinding, ...] = ()
    cves: tuple[CveFinding, ...] = ()
    #: Vulnerability ids the loaded intel snapshot knows (empty = no filtering, for unit fixtures).
    known_vulnerabilities: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted({job for job in self.jobs if job}))

    @property
    def non_dns_capabilities(self) -> tuple[str, ...]:
        return tuple(
            capability for capability in self.capabilities if not capability.startswith("dns.")
        )

    def cve_ids(self) -> tuple[str, ...]:
        return tuple(sorted({cve.cve_id for cve in self.cves}))


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class CaseVerdict:
    case_id: str
    profile: str
    status: Literal["pass", "fail", "blocked"]
    checks: tuple[Check, ...] = ()
    reason: str = ""

    def summary(self) -> str:
        passed = sum(1 for check in self.checks if check.ok)
        return f"{self.status.upper()} {passed}/{len(self.checks)} {self.case_id} [{self.profile}]"


# --- comparison ------------------------------------------------------------------------------


def compare(case: Case, profile: str, snapshot: CampaignSnapshot) -> CaseVerdict:
    """The case's verdict: `blocked` when the chain never left DNS, else pass/fail per assertion."""
    expectation = case.expectation(profile)
    if snapshot.errors:
        return CaseVerdict(
            case_id=case.id,
            profile=profile,
            status="fail",
            reason="; ".join(snapshot.errors),
        )
    if not snapshot.capabilities:
        return CaseVerdict(
            case_id=case.id,
            profile=profile,
            status="blocked",
            reason=(
                f"campaign {snapshot.campaign_id} ended {snapshot.status} without running a job: "
                "the scripted policy proposed none for this target type (port/fingerprint "
                "providers are slices A/B)"
            ),
        )
    if not snapshot.non_dns_capabilities:
        return CaseVerdict(
            case_id=case.id,
            profile=profile,
            status="blocked",
            reason=(
                "only DNS capabilities ran ("
                + ", ".join(snapshot.capabilities)
                + "): port/fingerprint/CVE providers are not on this branch (slices A/B/C)"
            ),
        )

    checks: list[Check] = []
    services = snapshot.services
    for port in expectation.ports:
        matches = [
            service
            for service in services
            if service.port == port and (expectation.ip is None or service.ip == expectation.ip)
        ]
        detail = f"port {port}" + (f" on {expectation.ip}" if expectation.ip else "")
        if matches:
            details = ", ".join(_describe_service(service) for service in matches)
            checks.append(Check(f"port {port}", True, details))
        else:
            checks.append(
                Check(
                    f"port {port}",
                    False,
                    f"{detail}: no open service asset"
                    + (f" (saw {_seen_ports(services)})" if services else " (no service assets)"),
                )
            )

    if expectation.product is not None:
        checks.append(_product_check(expectation, services, snapshot.web))

    if expectation.http_status is not None or expectation.http_title_contains is not None:
        checks.append(_http_check(expectation, snapshot.web))

    if expectation.cves is not None:
        checks.extend(_cve_checks(expectation.cves, snapshot.cves, snapshot.known_vulnerabilities))

    ok = all(check.ok for check in checks)
    return CaseVerdict(
        case_id=case.id,
        profile=profile,
        status="pass" if ok else "fail",
        checks=tuple(checks),
        reason="" if ok else "; ".join(check.detail for check in checks if not check.ok),
    )


def _describe_service(service: ServiceFinding) -> str:
    label = f"{service.ip}:{service.port}/{service.transport}"
    if service.product:
        label += f" {service.product} {service.version or ''}".rstrip()
    return label


def _seen_ports(services: Sequence[ServiceFinding]) -> str:
    if not services:
        return "none"
    return ", ".join(
        sorted({f"{service.ip}:{service.port}/{service.transport}" for service in services})
    )


@dataclass(frozen=True, slots=True)
class _ProductCandidate:
    """One observed product, from `service.product` or from `http.technology`."""

    source: str
    product: str
    version: str
    cpe: tuple[str, ...] = ()


def _technology_parts(raw: str) -> tuple[str, str]:
    """`http.technology` is a string list; accept `name:version` and `name version`."""
    text = raw.strip()
    for separator in (":", " "):
        head, found, tail = text.partition(separator)
        if found and head.strip():
            return head.strip(), tail.strip()
    return text, ""


def _product_candidates(
    expectation: Expectation, services: Sequence[ServiceFinding], web: Sequence[WebFinding]
) -> list[_ProductCandidate]:
    wanted_ports = set(expectation.ports)
    candidates = [
        _ProductCandidate(
            source="service.product",
            product=service.product or "",
            version=service.version or "",
            cpe=service.cpe,
        )
        for service in services
        if service.port in wanted_ports and (service.product or service.version or service.cpe)
    ]
    for finding in web:
        for raw in finding.technology:
            name, version = _technology_parts(raw)
            if name:
                candidates.append(
                    _ProductCandidate(
                        source=f"http.technology ({finding.url})",
                        product=name,
                        version=version,
                    )
                )
    return candidates


def _product_check(
    expectation: Expectation, services: Sequence[ServiceFinding], web: Sequence[WebFinding]
) -> Check:
    product = expectation.product
    assert product is not None  # guarded by the caller
    candidates = _product_candidates(expectation, services, web)
    if not candidates:
        return Check(
            "product",
            False,
            f"no service.product observation or http.technology entry ({_seen_ports(services)})",
        )

    matched = next(
        (
            candidate
            for candidate in candidates
            if candidate.product and _name_matches(candidate.product, product.names)
        ),
        None,
    )
    if matched is None:
        return Check(
            "product",
            False,
            f"product name not one of {list(product.names)}: "
            f"saw {sorted({candidate.product or '(no name)' for candidate in candidates})}",
        )

    checks: list[Check] = [
        Check("product", True, f"{matched.product} {matched.version or '-'} via {matched.source}")
    ]
    version = matched.version.strip()
    if not version.startswith(product.version_prefix):
        checks.append(
            Check(
                "version",
                False,
                f"version {version!r} does not start with {product.version_prefix!r}",
            )
        )
    else:
        checks.append(Check("version", True, version))

    cpe = _cpe_match(product.cpe, candidates)
    if cpe is None:
        seen = sorted({value for candidate in candidates for value in candidate.cpe}) or ["(none)"]
        checks.append(
            Check(
                "cpe",
                False,
                f"no CPE maps to {product.cpe.vendor}:{product.cpe.product}:"
                f"{product.cpe.version}: saw {seen}",
            )
        )
    else:
        checks.append(Check("cpe", True, cpe))
    return _join(checks)


def _join(checks: Sequence[Check]) -> Check:
    """Collapse the product/version/cpe checks into one line so a verdict stays readable."""
    failed = [check for check in checks if not check.ok]
    if failed:
        return Check(
            "product",
            False,
            "; ".join(check.detail for check in failed),
        )
    return Check(
        "product", True, "; ".join(check.detail for check in checks if check.name != "product")
    )


def _name_matches(actual: str, names: Iterable[str]) -> bool:
    normalized = actual.strip().casefold()
    return any(normalized == name.strip().casefold() for name in names)


def _cpe_match(wanted: Cpe, candidates: Sequence[_ProductCandidate]) -> str | None:
    for service in candidates:
        for raw in service.cpe:
            try:
                found = Cpe.parse(raw)
            except CatalogError:
                continue
            if (
                found.part == wanted.part
                and found.vendor.casefold() == wanted.vendor.casefold()
                and found.product.casefold() == wanted.product.casefold()
                and found.version.startswith(wanted.version)
            ):
                return found.text
    return None


def _http_check(expectation: Expectation, web: Sequence[WebFinding]) -> Check:
    if not web:
        return Check("http", False, "no application/URL asset with an HTTP observation")
    failures: list[str] = []
    for finding in web:
        if expectation.http_status is not None and finding.status != expectation.http_status:
            failures.append(f"{finding.url} status {finding.status} != {expectation.http_status}")
            continue
        if (
            expectation.http_title_contains is not None
            and expectation.http_title_contains.casefold() not in (finding.title or "").casefold()
        ):
            failures.append(
                f"{finding.url} title {finding.title!r} does not contain "
                f"{expectation.http_title_contains!r}"
            )
            continue
        return Check("http", True, f"{finding.url} status {finding.status} title {finding.title!r}")
    return Check("http", False, "; ".join(failures))


def _cve_checks(
    expectation: CveExpectation,
    cves: Sequence[CveFinding],
    known: Sequence[str] = (),
) -> list[Check]:
    """Candidates the catalog expects *and the pinned intel snapshot can produce*.

    The catalog lists the public CVE set of a version; the intel store the demo loads is the
    committed slice (`tests/fixtures/intel`), which covers a subset. Asserting a CVE the snapshot
    never loaded would fail on missing data rather than on the chain, so the expectation is
    intersected with the snapshot's vulnerability ids; ids outside it are reported as one
    informational check instead of pretending they passed.
    """
    seen = {cve.cve_id for cve in cves}
    known_set = set(known)
    required = [cve for cve in expectation.must_include if not known_set or cve in known_set]
    uncovered = [cve for cve in expectation.must_include if known_set and cve not in known_set]
    checks: list[Check] = []
    missing = [cve for cve in required if cve not in seen]
    if expectation.must_include:
        checks.append(
            Check(
                "cves",
                not missing,
                f"missing candidates {missing} (saw {sorted(seen)})"
                if missing
                else f"{len(required)} expected candidate(s) present"
                + (f" ({len(uncovered)} not in the intel slice: {uncovered})" if uncovered else ""),
            )
        )
    for cve in expectation.kev:
        if known_set and cve not in known_set:
            continue
        flagged = [item for item in cves if item.cve_id == cve and item.kev is True]
        checks.append(
            Check(
                f"kev {cve}",
                bool(flagged),
                "KEV flag present" if flagged else f"{cve} missing or not flagged kev=true",
            )
        )
    forbidden = sorted(seen & set(expectation.must_not_include))
    if expectation.must_not_include:
        checks.append(
            Check(
                "no-false-cves",
                not forbidden,
                f"matcher attributed {forbidden} although the version is not affected"
                if forbidden
                else f"forbidden {list(expectation.must_not_include)} absent",
            )
        )
    return checks
