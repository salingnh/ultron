"""Shared pytest configuration for the G1 skeleton tests.

`AEGIS_NO_SKIPS=1` (set by scripts/ci/python-gate.sh) turns every skip into a failure: a check the
CI job did not actually run is not evidence, the same rule the contract gate applies to
contracts/tests/*.py.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

import pytest

_LOCAL_JOB_ID: str | None = None
_LOCAL_VOLUME_LOG: Path | None = None
if not os.environ.get("AEGIS_CI_JOB"):
    _LOCAL_JOB_ID = f"local-pytest-{os.getpid()}"
    os.environ["AEGIS_CI_JOB"] = _LOCAL_JOB_ID
    if not os.environ.get("AEGIS_CI_VOLUME_LOG"):
        _LOCAL_VOLUME_LOG = Path(tempfile.gettempdir()) / f"aegis-ci-volumes-{_LOCAL_JOB_ID}.txt"
        _LOCAL_VOLUME_LOG.write_text("", encoding="utf-8")
        os.environ["AEGIS_CI_VOLUME_LOG"] = str(_LOCAL_VOLUME_LOG)

#: `tests/live` needs a Temporal server; the CI `python` job has none, and a skipped check is not
#: evidence (AEGIS_NO_SKIPS). It is collected only when a target is configured, and the live runner
#: sets that variable. The committed replay fixture is what the default gate replays instead.
#:
#: The gateway rotation test runs the digest-pinned LiteLLM image (a ~1.3 GB pull on a cold runner)
#: against two fake upstreams; `scripts/ci/python-gate.sh` sets AEGIS_TEST_LLM_GATEWAY=1 and pulls
#: the image first, and `make llm-gateway-test` is the same test for one checkout. Anywhere else it
#: is not collected at all, so a plain `make test` never pulls an image on someone's laptop.
collect_ignore: list[str] = []
if not os.environ.get("AEGIS_TEMPORAL_TARGET"):
    collect_ignore.append("live")
if os.environ.get("AEGIS_TEST_LLM_GATEWAY") != "1":
    collect_ignore.append("test_llm_gateway_rotation.py")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[object]) -> Any:
    report: Any = cast(Any, (yield))
    if (
        os.environ.get("AEGIS_NO_SKIPS") == "1"
        and getattr(report, "skipped", False)
        and report.when in {"setup", "call"}
    ):
        report.outcome = "failed"
        report.longrepr = (
            f"{report.nodeid}: skipped, but AEGIS_NO_SKIPS=1 requires every check to run"
        )
    return report


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Ensure any throwaway Neo4j container started during this pytest session is removed."""
    del exitstatus
    module = sys.modules.get("tests.graph_support")
    if module is not None:
        module.stop_test_graph()
    if _LOCAL_JOB_ID is None:
        return
    try:
        if shutil.which("podman") is not None:
            script = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "check-volume-leak.sh"
            if script.is_file():
                checked = subprocess.run(
                    ["bash", str(script)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                )
                if checked.returncode != 0:
                    session.exitstatus = pytest.ExitCode.TESTS_FAILED
                    sys.stderr.write(checked.stderr)
    finally:
        if _LOCAL_VOLUME_LOG is not None:
            _LOCAL_VOLUME_LOG.unlink(missing_ok=True)


# --- no test may reach the system resolver (item #61, requirement 7) ---------------------------


class SystemResolverReached(BaseException):
    """A test asked the host's resolver a question; the answer cannot be part of the evidence.

    The independent review leaked about ten real A/AAAA/CNAME queries for `.test` names through
    systemd-resolved while probing M05/M06, because the name paths fall back to the system resolver
    when a test does not stub them. A test that reaches the system resolver is not isolated (its
    result depends on the host's DNS) and sends packets to a third party, so it fails here instead.
    A test that truly needs the host resolver marks itself `@pytest.mark.system_resolver`.

    It derives from `BaseException`, not `Exception`: the name paths catch `Exception` around a
    lookup (`decide` turns a resolver failure into RESOLVE_FAILED, for one), which would hide the
    guard and let the query through.
    """


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "system_resolver: the test may query the host's resolver (isolation exception, review it)",
    )


_LOCAL_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})


def _is_literal_or_local(host: str) -> bool:
    value = host.strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if value in _LOCAL_NAMES:
        return True
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _refuse_name(host: object) -> None:
    if not isinstance(host, str) or not host:
        return  # a bind (None / "" / numeric) is not a lookup
    if not _is_literal_or_local(host):
        raise SystemResolverReached(
            f"test asked the system resolver for {host!r}; stub the resolver (or mark the test "
            "system_resolver if a real host lookup is the subject)"
        )


@pytest.fixture(autouse=True)
def _no_system_resolver(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("system_resolver") is not None:
        return
    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname = socket.gethostbyname
    real_gethostbyname_ex = socket.gethostbyname_ex
    real_connect = socket.socket.connect
    raw_sendto = cast(Any, socket.socket.sendto)

    def getaddrinfo(host: object, *args: object, **kwargs: object) -> Any:
        _refuse_name(host)
        return real_getaddrinfo(host, *args, **kwargs)  # type: ignore[arg-type]

    def gethostbyname(host: str) -> str:
        _refuse_name(host)
        return real_gethostbyname(host)

    def gethostbyname_ex(host: str) -> Any:
        _refuse_name(host)
        return real_gethostbyname_ex(host)

    def gethostbyaddr(host: str) -> Any:
        # A loopback literal is answered locally (and `socketserver` asks for it when it binds a
        # test server); anything else is a PTR query to the host's resolver.
        try:
            parsed = ipaddress.ip_address(str(host))
        except ValueError:
            parsed = None
        if parsed is None or not (parsed.is_loopback or parsed.is_unspecified):
            raise SystemResolverReached(f"test asked for a reverse lookup of {host!r}")
        return (str(host), [], [str(host)])

    def _guard_port(address: object) -> None:
        if isinstance(address, tuple) and len(address) >= 2 and address[1] == 53:
            raise SystemResolverReached(
                f"test sent a DNS query to {address[0]!r}:53; a fake resolver must use an "
                "ephemeral port (or the test marks itself system_resolver)"
            )

    def connect(self: socket.socket, address: object) -> object:
        _guard_port(address)
        return real_connect(self, address)  # type: ignore[arg-type]

    def sendto(self: socket.socket, data: bytes, address: object, *args: object) -> int:
        _guard_port(address)
        return int(raw_sendto(self, data, address, *args))

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", gethostbyname_ex)
    monkeypatch.setattr(socket, "gethostbyaddr", gethostbyaddr)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    monkeypatch.setattr(
        "aegis.common.dns_cname.resolver_address",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            SystemResolverReached("test read the host resolver configuration (/etc/resolv.conf)")
        ),
    )
