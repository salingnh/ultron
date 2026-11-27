"""The wildcard probe fails closed (item #61 follow-up, same class as R5).

F3 guardrail 4 refuses active signing of a zone that answers a random label. The probe used to
treat *any* binder error as "no wildcard", so a resolver that could not be asked skipped the
guardrail and the target was signed. Only a **missing** probe name (NXDOMAIN) is evidence of no
wildcard now; every other failure refuses with `target_wildcard_unknown` — a resolver outage
blocking active signing is the intended safe outcome.

The probes are the reviewer's `inproc2.py` F3 case with a failing resolver; no DNS leaves the host
(the conftest guard fails a test that asks the system resolver).
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from aegis.common import dns_cname
from aegis.m05_registry import egress
from aegis.m05_registry.errors import M05Error

from . import m06_support


@pytest.fixture(autouse=True)
def _stub_cname_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    # The fixture names are not real DNS, and the conftest guard refuses a system-resolver lookup:
    # the chain is stubbed as "no CNAME" so these tests reach the wildcard probe.
    monkeypatch.setattr(dns_cname, "cname_chain", lambda host: ())


def _record() -> Any:
    return m06_support.record("manifest.naabu.yaml")


class FailingProbe(m06_support.StaticBinder):
    """Answers the target name but cannot answer the random wildcard label."""

    def __init__(self, table: dict[str, list[str]], error: BaseException) -> None:
        super().__init__(table)
        self.error = error

    def addresses(self, value: str) -> tuple[str, ...]:
        if value.startswith("aegis-wildcard-"):
            raise self.error
        return super().addresses(value)


def _policy_refusal(binder: egress.TargetBinder) -> M05Error:
    with pytest.raises(M05Error) as caught:
        egress.build_egress_binding(
            _record(),
            merged_input={"ports": [443]},
            targets=m06_support.resolved_targets(_record(), ["dns:www.icomm.vn"]),
            binder=binder,
            authorized_suffixes=("icomm.vn",),
        )
    return caught.value


def test_a_resolver_failure_on_the_wildcard_probe_refuses() -> None:
    binder = FailingProbe(
        {"www.icomm.vn": ["93.184.216.34"]},
        M05Error.policy_denied("target_lookup_failed", "resolver unreachable"),
    )
    refusal = _policy_refusal(binder)
    assert refusal.refusal.rule == "target_wildcard_unknown"
    assert "stays refused" in refusal.refusal.message


def test_a_raw_resolver_error_on_the_wildcard_probe_refuses() -> None:
    # A binder that surfaces the transport error instead of an M05Error must not be read as clean.
    binder = FailingProbe(
        {"www.icomm.vn": ["93.184.216.34"]}, OSError("Temporary failure in name resolution")
    )
    assert _policy_refusal(binder).refusal.rule == "target_wildcard_unknown"


def test_an_ip_target_whose_provenance_probe_fails_refuses() -> None:
    # The second caller of the probe: ip/service targets get their wildcard check through their DB
    # provenance, so a failing probe there must refuse the target too.
    provenance = egress.ActiveProvenance(
        by_address={"203.0.113.10": (egress.DomainProvenance(name="api.icomm.vn"),)}
    )
    binder = FailingProbe(
        {}, M05Error.policy_denied("target_lookup_failed", "resolver unreachable")
    )
    with pytest.raises(M05Error) as caught:
        egress.build_egress_binding(
            _record(),
            merged_input={"ports": [443]},
            targets=m06_support.resolved_targets(_record(), ["ip:203.0.113.10"]),
            binder=binder,
            network_profile="internet",
            authorized_suffixes=("icomm.vn",),
            provenance=provenance,
        )
    assert caught.value.refusal.rule == "target_wildcard_unknown"


def test_a_missing_probe_name_is_still_no_wildcard() -> None:
    # NXDOMAIN is the normal answer for a random label: the guardrail must not refuse every zone.
    binder = m06_support.StaticBinder({"www.icomm.vn": ["93.184.216.34"]})
    binding = egress.build_egress_binding(
        _record(),
        merged_input={"ports": [443]},
        targets=m06_support.resolved_targets(_record(), ["dns:www.icomm.vn"]),
        binder=binder,
        authorized_suffixes=("icomm.vn",),
    )
    assert binding.target_addresses == ("93.184.216.34",)


def test_the_system_binder_tells_a_missing_name_from_a_resolver_outage() -> None:
    missing = egress.SystemTargetBinder(
        resolver=lambda *_args: (_ for _ in ()).throw(
            socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        )
    )
    with pytest.raises(M05Error) as caught:
        missing.addresses("probe.icomm.vn")
    assert caught.value.refusal.rule == "target_unresolvable"

    for error in (
        socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution"),
        TimeoutError("resolver did not answer"),
    ):
        outage = egress.SystemTargetBinder(
            resolver=lambda *_args, error=error: (_ for _ in ()).throw(error)
        )
        with pytest.raises(M05Error) as caught:
            outage.addresses("probe.icomm.vn")
        assert caught.value.refusal.rule == "target_lookup_failed"
