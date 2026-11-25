"""Static rules of the vulnlab catalog and the detection-verdict rules (G1.6 slice E).

The stack itself is exercised live (`make vulnlab-check`, `make vulnlab-test`); what runs in CI is
everything that can be decided without a container: the catalog is coherent, its image pins match
`deploy/vulnlab/images.env`, `deploy/vulnlab/compose.yaml` keeps the isolation it promises, the
public hostnames are declared as names only, and `catalog.compare` turns a recorded campaign into
the same verdict the runner prints.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.vulnlab.catalog import (
    CampaignSnapshot,
    Case,
    Catalog,
    CatalogError,
    Cpe,
    CveFinding,
    ServiceFinding,
    WebFinding,
    assert_image_pins,
    campaign_target,
    compare,
    load_catalog,
)

REPO = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO / "tests" / "vulnlab" / "cases.yaml"
IMAGES_ENV = REPO / "deploy" / "vulnlab" / "images.env"
ENV_EXAMPLE = REPO / "deploy" / "vulnlab" / ".env.example"
COMPOSE_FILE = REPO / "deploy" / "vulnlab" / "compose.yaml"
TOKEN_PLACEHOLDER = re.compile(r"^[A-Za-z0-9+/_=-]{20,}$")


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    document = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _images() -> dict[str, str]:
    images: dict[str, str] = {}
    for raw in IMAGES_ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        images[name.strip()] = value.strip()
    return images


def _env_example() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip()
    return values


def _service_for(catalog: Catalog, compose: dict[str, Any], case: Case) -> dict[str, Any]:
    services: dict[str, dict[str, Any]] = compose["services"]
    service = services.get(case.service)
    if service is None:
        raise AssertionError(f"compose has no service {case.service!r} (case {case.id})")
    expected = f"{{AEGIS_VULNLAB_PROJECT:-aegis-vulnlab}}-{case.service}"
    assert service.get("container_name") == "$" + expected, (
        f"{case.service}: container_name must derive from AEGIS_VULNLAB_PROJECT"
    )
    return service


def _origin_services(catalog: Catalog, compose: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {case.service: _service_for(catalog, compose, case) for case in catalog.cases}


# --- catalog ----------------------------------------------------------------------------------


def test_catalog_is_coherent(catalog: Catalog) -> None:
    assert catalog.api_version == "aegis.io/v2"
    assert 5 <= len(catalog.cases) <= 8, "the lab must stay small: 5-8 services"
    assert catalog.networks["lab"] == "aegis-lab-lab"
    assert catalog.networks["internal"] == "aegis-vulnlab-net"
    assert catalog.networks["egress"] == "aegis-vulnlab-egress"
    assert catalog.feed["nvd"]["retrievedAt"] == "2026-11-25"
    assert catalog.feed["kev"]["catalogVersion"] == "2026.11.24"
    lab_net = ipaddress.ip_network(catalog.networks["labSubnet"])
    internal_net = ipaddress.ip_network(catalog.networks["subnet"])
    assert not lab_net.overlaps(internal_net)
    for case in catalog.cases:
        assert ipaddress.ip_address(case.lab_address) in lab_net
        # `version` is the product version a fingerprint should read; it is the image's own version
        # unless the image ships a different one (the Spring demo ships Tomcat 8.5.77).
        assert (
            case.version == case.image_version
            or case.version.startswith(case.image_version)
            or case.id.startswith("spring")
        )


def test_every_case_expects_a_port_and_kev_flags_are_subset(catalog: Catalog) -> None:
    for case in catalog.cases:
        for profile in ("lab", "internet"):
            expectation = case.expectation(profile)
            assert expectation.ports, f"{case.id}/{profile} expects no port"
            assert set(expectation.cves.kev) <= set(expectation.cves.must_include)
            if profile == "internet":
                assert 443 in expectation.ports, f"{case.id} must be reachable over TLS on 443"
            else:
                assert case.image_port in expectation.ports


def test_lab_addresses_are_inside_the_lab_subnet_and_unique(catalog: Catalog) -> None:
    subnet = ipaddress.ip_network(catalog.networks["labSubnet"])
    addresses = [ipaddress.ip_address(case.lab_address) for case in catalog.cases]
    assert len(set(addresses)) == len(addresses)
    reserved = {ipaddress.ip_address("10.114.53.53"), ipaddress.ip_address("10.114.53.80")}
    for address in addresses:
        assert address in subnet
        # .53 is the lab resolver, .80 the passive stub; nothing else in the lab uses the range.
        assert address not in reserved


def test_unknown_and_malformed_catalog_entries_are_rejected(tmp_path: Path) -> None:
    broken = CATALOG_PATH.read_text(encoding="utf-8").replace(
        "cpe:2.3:a:apache:http_server:2.4.49", "not-a-cpe"
    )
    path = tmp_path / "cases.yaml"
    path.write_text(broken, encoding="utf-8")
    with pytest.raises(CatalogError, match="CPE"):
        load_catalog(path)


# --- image pins -------------------------------------------------------------------------------


def test_images_env_pins_every_case_image(catalog: Catalog) -> None:
    # The loader-side rule the runner will use too: every case's pin exists, is digest-pinned and
    # carries the version the catalog records.
    assert_image_pins(catalog, _images())


def test_images_env_pins_the_tunnel_and_probe(catalog: Catalog) -> None:
    images = _images()
    for name in ("AEGIS_VULNLAB_CLOUDFLARED_IMAGE", "AEGIS_VULNLAB_PROBE_IMAGE"):
        assert re.match(
            r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$", images.get(name, "")
        ), name


# --- compose isolation ------------------------------------------------------------------------


def test_compose_has_only_the_catalog_services_and_the_tunnel(
    catalog: Catalog, compose: dict[str, Any]
) -> None:
    expected_services = {case.service for case in catalog.cases} | {"cloudflared"}
    assert set(compose["services"]) == expected_services
    assert compose.get("name") == "${AEGIS_VULNLAB_PROJECT:-aegis-vulnlab}", (
        "the compose project name must derive from AEGIS_VULNLAB_PROJECT"
    )
    wanted = {case.image_env for case in catalog.cases}
    seen = {
        str(service.get("image", "")).split(":", 1)[0].strip("${")
        for service in compose["services"].values()
    }
    assert wanted <= seen, f"compose does not use these image env vars: {sorted(wanted - seen)}"


def test_origins_publish_nothing_and_mount_nothing(
    catalog: Catalog, compose: dict[str, Any]
) -> None:
    for service_name, service in _origin_services(catalog, compose).items():
        container = service_name
        assert "ports" not in service, f"{container} publishes a host port"
        for volume in service.get("volumes") or []:
            assert isinstance(volume, dict) and volume.get("type") == "tmpfs", (
                f"{container} mounts something other than tmpfs: {volume}"
            )
            assert "source" not in volume, f"{container} mounts the host: {volume}"
        assert service.get("restart") == "no", f"{container} would outlive the TTL restart policy"
        case = next(item for item in catalog.cases if item.service == container)
        assert service.get("read_only", False) is case.read_only_rootfs, (
            f"{container}: compose and catalog disagree about the rootfs"
        )
        assert "ALL" in service.get("cap_drop", []), f"{container} keeps capabilities"
        assert "no-new-privileges:true" in service.get("security_opt", []), container
        assert service.get("mem_limit") and service.get("cpus") and service.get("pids_limit"), (
            f"{container} has no resource caps"
        )


def test_origins_sit_on_the_internal_network_and_on_the_lab(
    catalog: Catalog, compose: dict[str, Any]
) -> None:
    internal = ipaddress.ip_network(catalog.networks["subnet"])
    lab = ipaddress.ip_network(catalog.networks["labSubnet"])
    for case in catalog.cases:
        networks = _service_for(catalog, compose, case)["networks"]
        assert set(networks) == {"vulnlab", "lab"}, case.service
        assert ipaddress.ip_address(networks["vulnlab"]["ipv4_address"]) in internal
        assert networks["lab"]["ipv4_address"] == case.lab_address
        assert ipaddress.ip_address(networks["lab"]["ipv4_address"]) in lab


def test_tunnel_is_opt_in_and_cannot_expose_an_origin_directly(
    catalog: Catalog, compose: dict[str, Any]
) -> None:
    tunnel = compose["services"]["cloudflared"]
    assert tunnel.get("profiles") == ["tunnel"], "the tunnel must not start without a token"
    assert "ports" not in tunnel
    assert set(tunnel["networks"]) == {"vulnlab", "egress"}
    assert "ipv4_address" not in (tunnel["networks"]["egress"] or {})
    # A remotely managed tunnel takes its ingress from Cloudflare: no local file is mounted, and
    # `--config` would make cloudflared read a file the dashboard does not use.
    assert "volumes" not in tunnel, "a remote-managed tunnel must not mount an ingress file"
    assert tunnel.get("command") == ["tunnel", "run"], tunnel.get("command")
    assert "--config" not in " ".join(tunnel.get("command") or [])


def test_networks_are_declared_internal_or_external_as_promised(
    catalog: Catalog, compose: dict[str, Any]
) -> None:
    networks = compose["networks"]
    assert networks["vulnlab"]["name"] == "${AEGIS_VULNLAB_PROJECT:-aegis-vulnlab}-net"
    assert networks["vulnlab"]["internal"] is True
    assert networks["vulnlab"]["ipam"]["config"][0]["subnet"] == catalog.networks["subnet"]
    assert networks["lab"]["name"] == catalog.networks["lab"]
    assert networks["lab"]["external"] is True
    assert networks["egress"]["name"] == "${AEGIS_VULNLAB_PROJECT:-aegis-vulnlab}-egress"
    assert networks["egress"].get("internal") is not True, "the tunnel needs a route to Cloudflare"


def test_no_service_publishes_a_port_anywhere(compose: dict[str, Any]) -> None:
    for name, service in compose["services"].items():
        assert "ports" not in service, f"{name} publishes a port"
        assert "network_mode" not in service, f"{name} overrides the network"


# --- the public side is names only -----------------------------------------------------------


def test_env_example_declares_names_not_secrets(catalog: Catalog) -> None:
    values = _env_example()
    assert values.get("AEGIS_VULNLAB_TUNNEL_TOKEN") in {None, ""}, (
        "the example must not carry a token; keep it in a 0600 file"
    )
    assert values.get("AEGIS_VULNLAB_TUNNEL_TOKEN_FILE") == "", (
        "the example must name the token-file variable with no path baked in"
    )
    assert values.get("AEGIS_VULNLAB_PROJECT") == "", (
        "the example must default to the default project, not bake a checkout name"
    )
    assert values.get("VULNLAB_TUNNEL") == "0", "publishing must be off by default"
    assert values.get("VULNLAB_TTL_MINUTES", "").isdigit()
    for case in catalog.cases:
        assert case.host_env, f"{case.id} has no public hostname variable"
        hostname = values.get(case.host_env, "")
        assert hostname, f".env.example has no {case.host_env}"
        assert re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", hostname), hostname
        assert "example" in hostname or hostname.count(".") >= 2, (
            f"{case.host_env} must be an obvious placeholder until the owner picks the subdomain"
        )
    for name, value in values.items():
        if name == "AEGIS_VULNLAB_TUNNEL_TOKEN":
            continue
        assert not TOKEN_PLACEHOLDER.match(value), f"{name} looks like a credential value"


def test_env_example_hostnames_are_unique(catalog: Catalog) -> None:
    values = _env_example()
    hostnames = [values[case.host_env] for case in catalog.cases if case.host_env]
    assert len(hostnames) == len(set(hostnames))


def test_ingress_template_is_the_documented_mirror(catalog: Catalog) -> None:
    # The dashboard owns the live ingress; the template is the mirror a reviewer compares it with.
    template = (REPO / "deploy" / "vulnlab" / "cloudflared" / "config.yml.template").read_text(
        encoding="utf-8"
    )
    for case in catalog.cases:
        assert case.host_env is not None
        assert f"@{case.host_env}@" in template, f"template has no placeholder for {case.id}"
        assert "http://" in template
    assert "http_status:404" in template, "the mirror must close everything else"
    assert "salingnh.com" not in template, "owner-specific hostnames must not be committed"


# --- campaign target -------------------------------------------------------------------------


def _lab_case(catalog: Catalog) -> Case:
    return catalog.case("httpd-2.4.49")


def test_campaign_target_lab_uses_the_origin_address(catalog: Catalog) -> None:
    case = _lab_case(catalog)
    assert campaign_target(case, "lab", {}) == {"ips": [case.lab_address]}


def test_campaign_target_internet_uses_the_public_hostname(catalog: Catalog) -> None:
    case = _lab_case(catalog)
    assert case.host_env is not None
    target = campaign_target(case, "internet", {case.host_env: "Httpd.Vulnlab.Example.com"})
    assert target == {"domains": ["httpd.vulnlab.example.com"]}


def test_campaign_target_internet_refuses_a_missing_or_bad_hostname(catalog: Catalog) -> None:
    case = _lab_case(catalog)
    assert case.host_env is not None
    with pytest.raises(CatalogError, match=case.host_env):
        campaign_target(case, "internet", {case.host_env: ""})
    with pytest.raises(CatalogError, match="FQDN"):
        campaign_target(case, "internet", {case.host_env: "not a hostname"})


# --- verdicts --------------------------------------------------------------------------------


def _httpd_snapshot(**overrides: Any) -> CampaignSnapshot:
    defaults: dict[str, Any] = {
        "campaign_id": "c1",
        "status": "COMPLETED",
        "jobs": ("network.discover_services", "web.fingerprint", "cti.match_candidates"),
        "services": (
            ServiceFinding(
                ip="10.114.53.61",
                port=80,
                product="Apache HTTP Server",
                version="2.4.49",
                cpe=("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",),
            ),
        ),
        "web": (WebFinding(url="app:http://10.114.53.61:80", status=404, title="404 Not Found"),),
        "cves": (
            CveFinding("service:10.114.53.61:80/tcp", "CVE-2021-41773", kev=True),
            CveFinding("service:10.114.53.61:80/tcp", "CVE-2021-42013", kev=True),
            CveFinding("service:10.114.53.61:80/tcp", "CVE-2021-44790", kev=False),
            CveFinding("service:10.114.53.61:80/tcp", "CVE-2022-22720", kev=False),
            CveFinding("service:10.114.53.61:80/tcp", "CVE-2024-38475", kev=True),
        ),
    }
    defaults.update(overrides)
    return CampaignSnapshot(**defaults)


def test_compare_passes_when_every_expectation_holds(catalog: Catalog) -> None:
    verdict = compare(_lab_case(catalog), "lab", _httpd_snapshot())
    assert verdict.status == "pass", verdict.reason
    assert all(check.ok for check in verdict.checks)


def test_compare_fails_on_a_missing_port(catalog: Catalog) -> None:
    snapshot = _httpd_snapshot(services=(), web=())
    verdict = compare(_lab_case(catalog), "lab", snapshot)
    assert verdict.status == "fail"
    assert "port 80" in verdict.reason


def test_compare_fails_on_a_wrong_product_version(catalog: Catalog) -> None:
    snapshot = _httpd_snapshot(
        services=(ServiceFinding(ip="10.114.53.61", port=80, product="nginx", version="1.16.0"),)
    )
    verdict = compare(_lab_case(catalog), "lab", snapshot)
    assert verdict.status == "fail"
    assert "product name" in verdict.reason


def test_compare_accepts_the_product_from_http_technology(catalog: Catalog) -> None:
    snapshot = _httpd_snapshot(
        services=(ServiceFinding(ip="10.114.53.61", port=80),),
        web=(
            WebFinding(
                url="app:http://10.114.53.61:80",
                status=404,
                title="404 Not Found",
                technology=("Apache HTTP Server:2.4.49",),
            ),
        ),
    )
    verdict = compare(_lab_case(catalog), "lab", snapshot)
    # The name/version come from http.technology, but the contract's CPE field is still missing.
    assert verdict.status == "fail"
    assert "CPE" in verdict.reason


def test_compare_fails_on_a_missing_candidate_and_kev_flag(catalog: Catalog) -> None:
    case = _lab_case(catalog)
    snapshot = _httpd_snapshot(
        cves=(
            CveFinding("service:10.114.53.61:80/tcp", "CVE-2021-41773", kev=False),
            CveFinding("service:10.114.53.61:80/tcp", "CVE-2021-42013", kev=True),
            CveFinding("service:10.114.53.61:80/tcp", "CVE-2024-38475", kev=True),
        )
    )
    verdict = compare(case, "lab", snapshot)
    assert verdict.status == "fail"
    assert "missing candidates" in verdict.reason
    assert "CVE-2021-41773" in verdict.reason


def test_compare_fails_a_forbidden_cve(catalog: Catalog) -> None:
    case = catalog.case("tomcat-8.5.19")
    snapshot = CampaignSnapshot(
        campaign_id="c2",
        status="COMPLETED",
        jobs=("network.discover_services", "web.fingerprint"),
        services=(
            ServiceFinding(
                ip="10.114.53.63",
                port=8080,
                product="Apache Tomcat",
                version="8.5.19",
                cpe=("cpe:2.3:a:apache:tomcat:8.5.19",),
            ),
        ),
        web=(WebFinding("app:http://10.114.53.63:8080", 200, "Apache Tomcat/8.5.19"),),
        cves=(
            CveFinding("service:10.114.53.63:8080/tcp", "CVE-2017-12615", kev=False),
            CveFinding("service:10.114.53.63:8080/tcp", "CVE-2017-12617", kev=True),
        ),
    )
    verdict = compare(case, "lab", snapshot)
    assert verdict.status == "fail"
    assert "CVE-2017-12615" in verdict.reason


def test_compare_blocks_when_only_dns_capabilities_ran(catalog: Catalog) -> None:
    case = _lab_case(catalog)
    verdict = compare(
        case,
        "lab",
        CampaignSnapshot(
            campaign_id="c3",
            status="COMPLETED",
            jobs=("dns.enumerate_subdomains", "dns.resolve"),
        ),
    )
    assert verdict.status == "blocked"
    assert "slices A/B/C" in verdict.reason


def test_compare_blocks_when_the_campaign_proposed_no_job(catalog: Catalog) -> None:
    verdict = compare(
        _lab_case(catalog), "lab", CampaignSnapshot(campaign_id="c4", status="COMPLETED")
    )
    assert verdict.status == "blocked"
    assert "without running a job" in verdict.reason


def test_compare_does_not_assert_a_null_product_or_empty_cve_list(catalog: Catalog) -> None:
    case = _lab_case(catalog)
    verdict = compare(
        case,
        "internet",
        CampaignSnapshot(
            campaign_id="c5",
            status="COMPLETED",
            jobs=("network.discover_services", "web.fingerprint"),
            services=(ServiceFinding(ip="203.0.113.9", port=443),),
            web=(WebFinding("app:https://httpd.vulnlab.example.com:443", 404, "404 Not Found"),),
        ),
    )
    assert verdict.status == "pass", verdict.reason


def test_cpe_parser_rejects_a_shorthand_without_product(tmp_path: Path) -> None:
    with pytest.raises(CatalogError):
        Cpe.parse("cpe:2.3:a:apache:*:2.4.49")


def test_check_live_loads_hostnames_from_the_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`make vulnlab-check PROFILE=internet` must work standalone: the names are deployment state.

    Regression guard for the first live run: the check was executed from the Makefile without
    `vulnlab-up`'s exported environment and every public host looked empty.
    """
    spec = importlib.util.spec_from_file_location(
        "vulnlab_check_live", REPO / "scripts" / "vulnlab" / "check_live.py"
    )
    assert spec is not None and spec.loader is not None
    module: Any = importlib.util.module_from_spec(spec)
    # dataclasses resolves postponed annotations through sys.modules[cls.__module__].
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    env_file = tmp_path / ".env"
    env_file.write_text(
        "AEGIS_VULNLAB_HOST_HTTPD=vl-httpd.example.test\n"
        "AEGIS_VULNLAB_HOST_NGINX=from-file.example.test\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "ENV_FILE", env_file)
    monkeypatch.delenv("AEGIS_VULNLAB_HOST_HTTPD", raising=False)
    monkeypatch.setenv("AEGIS_VULNLAB_HOST_NGINX", "from-environment.example.test")

    module.load_vulnlab_env()

    assert os.environ["AEGIS_VULNLAB_HOST_HTTPD"] == "vl-httpd.example.test"
    assert os.environ["AEGIS_VULNLAB_HOST_NGINX"] == "from-environment.example.test"


def test_every_service_carries_the_project_and_role_labels(
    catalog: Catalog, compose: dict[str, Any]
) -> None:
    # The host-wide checks find a vulnlab stack and its tunnel by these labels; legacy stacks are
    # caught by their container names.
    for name, service in compose["services"].items():
        labels = service.get("labels") or {}
        assert labels.get("aegis.vulnlab.project") == ("${AEGIS_VULNLAB_PROJECT:-aegis-vulnlab}"), (
            name
        )
        assert labels.get("aegis.vulnlab.role") in {"origin", "cloudflared"}, name
    assert compose["services"]["cloudflared"]["labels"]["aegis.vulnlab.role"] == "cloudflared"


def test_no_container_or_network_name_is_hardcoded(compose: dict[str, Any]) -> None:
    for name, service in compose["services"].items():
        container = str(service.get("container_name", ""))
        assert container.startswith("${AEGIS_VULNLAB_PROJECT"), f"{name}: {container}"
    for network, description in compose["networks"].items():
        if network == "lab":
            assert description["name"] == "aegis-lab-lab"  # shared, not ours
            continue
        assert description["name"].startswith("${AEGIS_VULNLAB_PROJECT"), network
