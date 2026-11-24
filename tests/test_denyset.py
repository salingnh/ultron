"""The platform deny set and literal normalization (R-5 acceptance).

`normalize_host` must see IPv4 literals the way `inet_aton(3)` (and therefore `getaddrinfo`) sees
them: `127.1`, `2130706433`, `0x7f000001` and `017700000001` are the loopback address, not DNS
names. The runtime deny set must cover the contract constant in `contracts/validation.py`; a drift
between the two is a test failure, not a runtime surprise.
"""

from __future__ import annotations

import importlib.util
import ipaddress
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from aegis.common.repo import repository_root
from aegis.m06_runner.denyset import (
    DENY_HOSTS,
    DENY_NETWORKS,
    METADATA_NETWORKS,
    DenyReason,
    denied_host,
    deny_reason,
    host_key,
    normalize_host,
)


def _contract_validation() -> ModuleType:
    path = repository_root() / "contracts" / "validation.py"
    spec = importlib.util.spec_from_file_location("contract_validation_for_denyset_tests", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        ("127.1", "127.0.0.1"),
        ("127.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("017700000001", "127.0.0.1"),
        ("169.254.169.254", "169.254.169.254"),
        ("[::1]", "::1"),
        ("::ffff:127.0.0.1", "::ffff:127.0.0.1"),
        ("fe80::1%eth0", "fe80::1"),
    ],
)
def test_inet_aton_literals_are_addresses(literal: str, expected: str) -> None:
    address = normalize_host(literal)
    assert address is not None
    assert str(address) == expected


@pytest.mark.parametrize("name", ["example.com", "dead.beef", "crt.sh", "127.0.0.1.", ""])
def test_names_are_not_literals(name: str) -> None:
    assert normalize_host(name) is None


@pytest.mark.parametrize(
    ("literal", "reason"),
    [
        ("127.1", DenyReason.LOOPBACK),
        ("2130706433", DenyReason.LOOPBACK),
        ("0x7f000001", DenyReason.LOOPBACK),
        ("::1", DenyReason.LOOPBACK),
        ("::ffff:127.0.0.1", DenyReason.LOOPBACK),
        ("169.254.169.254", DenyReason.METADATA),
        ("100.100.100.200", DenyReason.METADATA),
        ("fd00:ec2::254", DenyReason.METADATA),
        ("fe80::1", DenyReason.LINK_LOCAL),
        ("fec0::1", DenyReason.RESERVED),
        ("::7f00:1", DenyReason.RESERVED),
        ("::127.0.0.1", DenyReason.RESERVED),
        ("::", DenyReason.UNSPECIFIED),
        ("0.0.0.0", DenyReason.UNSPECIFIED),
        ("224.0.0.1", DenyReason.MULTICAST),
        ("ff02::1", DenyReason.MULTICAST),
        ("64:ff9b::7f00:1", DenyReason.EMBEDDED_V4),
        ("2002:7f00:1::1", DenyReason.EMBEDDED_V4),
        ("2001:0:7f00:1::1", DenyReason.EMBEDDED_V4),
    ],
)
def test_deny_reasons(literal: str, reason: DenyReason) -> None:
    address = normalize_host(literal)
    assert address is not None
    assert deny_reason(address) is reason


@pytest.mark.parametrize(
    "literal", ["10.0.0.5", "192.168.1.10", "93.184.216.34", "2606:2800:220:1::1"]
)
def test_ordinary_addresses_are_not_denied(literal: str) -> None:
    address = ipaddress.ip_address(literal)
    assert deny_reason(address) is None


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("localhost", DenyReason.RESERVED),
        ("metadata.google.internal", DenyReason.RESERVED),
        ("anything.localhost", DenyReason.RESERVED),
        ("127.1", DenyReason.LOOPBACK),
        ("0x7f000001", DenyReason.LOOPBACK),
        ("[::1]", DenyReason.LOOPBACK),
        ("crt.sh", None),
        ("10.0.0.5", None),
    ],
)
def test_declared_hosts_are_refused_like_the_registry(host: str, reason: DenyReason | None) -> None:
    assert denied_host(host) is reason


def test_host_key_canonicalizes_literals_and_names() -> None:
    assert host_key("127.1") == "127.0.0.1"
    assert host_key("CRT.sh.") == "crt.sh"
    assert host_key("0x7f000001") == "127.0.0.1"


def test_runtime_deny_set_covers_the_contract_constant() -> None:
    contract = cast(Any, _contract_validation())
    runtime = {str(net) for net, _ in DENY_NETWORKS} | {str(net) for net in METADATA_NETWORKS}
    missing = {str(net) for net in contract.EGRESS_DENY_NETWORKS} - runtime
    assert not missing, f"contract deny networks missing from the runtime set: {sorted(missing)}"
    assert set(contract.EGRESS_DENY_HOSTS) <= set(DENY_HOSTS)


def test_every_deny_network_contains_a_refused_address() -> None:
    # The network address of a range may be denied for a more specific reason (::/96 starts at
    # the unspecified address), so assert a refused address inside each range, not the exact code.
    for net, reason in DENY_NETWORKS:
        first = net.network_address
        address = ipaddress.ip_address(int(first) + 1) if net.num_addresses > 1 else first
        assert deny_reason(address) is not None, f"{net} is not refused"
        if reason is DenyReason.EMBEDDED_V4:
            assert deny_reason(address) is DenyReason.EMBEDDED_V4
    for net in METADATA_NETWORKS:
        assert deny_reason(net.network_address) is DenyReason.METADATA


def test_the_contract_file_is_the_one_in_the_checkout() -> None:
    path = repository_root() / "contracts" / "validation.py"
    assert Path(path).is_file()
    assert "EGRESS_DENY_NETWORKS" in path.read_text(encoding="utf-8")
