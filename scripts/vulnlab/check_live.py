#!/usr/bin/env python3
"""Check that every vulnlab origin serves the page the catalog documents (G1.6 slice E).

Two profiles:

* `lab` (the default) runs one probe container per origin on the authorized lab network, as the
  current uid:gid with all capabilities dropped, a read-only rootfs and its own TTL: the same path a
  scanner takes, not a `curl` from the host (the origins publish no host port).
* `internet` requests each public hostname from **this machine** over HTTPS, through the Cloudflare
  Tunnel and its Access policy. Cloudflare terminates TLS and normalizes `Server`, so only the
  status, title and body markers of the catalog's `internet` block are asserted.

Used by `make vulnlab-up` (readiness, `--wait`; plus tunnel readiness when a token is configured)
and `make vulnlab-check`. The check is deliberately about what the *service* reveals; whether a
detector parses it into product/version/CPE is `make vulnlab-test` (campaign level).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.vulnlab.catalog import CATALOG_PATH, HOSTNAME, Case, load_catalog  # noqa: E402

IMAGES_FILE = REPO / "deploy" / "vulnlab" / "images.env"
ENV_FILE = REPO / "deploy" / "vulnlab" / ".env"
LAB_NETWORK = "aegis-lab-lab"
RUN_LABEL = "aegis.vulnlab=aegis-vulnlab-run"
PROBE_TIMEOUT_SECONDS = 20
TUNNEL_TIMEOUT_SECONDS = 20
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

PROBE_SCRIPT = r"""
import json
import re
import sys
import urllib.error
import urllib.request

url = sys.argv[1]
request = urllib.request.Request(url, headers={"User-Agent": "aegis-vulnlab-probe/1"})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with opener.open(request, timeout=15) as response:
        status = response.status
        headers = {key.lower(): value for key, value in response.headers.items()}
        body = response.read(131072).decode("utf-8", "replace")
    error = None
except urllib.error.HTTPError as failure:
    status = failure.code
    headers = {key.lower(): value for key, value in failure.headers.items()}
    body = failure.read(131072).decode("utf-8", "replace")
    error = None
except Exception as failure:  # noqa: BLE001 - a probe failure is data, not a crash
    status, headers, body, error = None, {}, "", f"{type(failure).__name__}: {failure}"
title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
print(json.dumps({
    "status": status,
    "server": headers.get("server"),
    "title": title.group(1).strip() if title else None,
    "body": body,
    "error": error,
}))
"""


class ProbeError(RuntimeError):
    """The probe could not run; the message says why."""


@dataclass(frozen=True, slots=True)
class Probe:
    status: int | None
    server: str | None
    title: str | None
    body: str
    error: str | None


@dataclass(frozen=True, slots=True)
class LiveResult:
    case_id: str
    ok: bool
    detail: str
    probe: Probe | None


def load_vulnlab_env() -> None:
    """Export deploy/vulnlab/.env (hostnames); an explicit environment value wins.

    `make vulnlab-up` already exports it, but the check must also work when run on its own
    (`make vulnlab-check PROFILE=internet`) - the names are deployment state, not arguments.
    """
    if not ENV_FILE.is_file():
        return
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if separator:
            os.environ.setdefault(name.strip(), value.strip())


def probe_image() -> str:
    reference = os.environ.get("AEGIS_VULNLAB_PROBE_IMAGE", "").strip()
    if reference:
        return reference
    for raw in IMAGES_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("AEGIS_VULNLAB_PROBE_IMAGE="):
            return line.split("=", 1)[1].strip()
    raise ProbeError(f"{IMAGES_FILE} has no AEGIS_VULNLAB_PROBE_IMAGE")


def _decode(status: int | None, server: str | None, body: str, error: str | None) -> Probe:
    title = TITLE.search(body)
    return Probe(
        status=status,
        server=server,
        title=title.group(1).strip() if title else None,
        body=body,
        error=error,
    )


def probe(url: str) -> Probe:
    """One-shot probe container on the lab network (no host port is ever published)."""
    command = [
        "podman",
        "run",
        "--rm",
        "--name",
        f"aegis-vulnlab-probe-{os.getpid()}",
        "--label",
        RUN_LABEL,
        "--network",
        LAB_NETWORK,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp:size=8m",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--cpus",
        "0.25",
        "--timeout",
        str(PROBE_TIMEOUT_SECONDS + 20),
        "--userns",
        "keep-id",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-i",
        probe_image(),
        "python3",
        "-",
        url,
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - a fixed command this repository owns
            command,
            input=PROBE_SCRIPT,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS + 30,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ProbeError(f"probe of {url} did not finish: {error}") from error
    if completed.returncode != 0:
        raise ProbeError(
            f"probe of {url} failed: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    try:
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as error:
        raise ProbeError(f"probe of {url} printed no JSON: {completed.stdout[:200]!r}") from error
    return _decode(
        payload.get("status"),
        payload.get("server"),
        str(payload.get("body") or ""),
        payload.get("error"),
    )


def host_probe(url: str) -> Probe:
    """One HTTPS request from this machine (through Cloudflare and its Access policy)."""
    request = urllib.request.Request(url, headers={"User-Agent": "aegis-vulnlab-tunnel-check/1"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=TUNNEL_TIMEOUT_SECONDS) as response:
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(131072).decode("utf-8", "replace")
        error = None
    except urllib.error.HTTPError as failure:
        status = failure.code
        headers = {key.lower(): value for key, value in failure.headers.items()}
        body = failure.read(131072).decode("utf-8", "replace")
        error = None
    except Exception as failure:  # noqa: BLE001 - a tunnel failure is data, not a crash
        status, headers, body, error = None, {}, "", f"{type(failure).__name__}: {failure}"
    return _decode(status, headers.get("server"), body, error)


def lab_url(case: Case) -> str:
    return f"http://{case.lab_address}:{case.image_port}{case.request_path}"


def internet_url(case: Case) -> str:
    if case.host_env is None:
        raise ProbeError(f"case {case.id} has no public hostname")
    hostname = (os.environ.get(case.host_env) or "").strip().lower()
    if not hostname:
        raise ProbeError(f"{case.host_env} is empty: set the public hostname in deploy/vulnlab/.env")
    if not HOSTNAME.match(hostname):
        raise ProbeError(f"{case.host_env} is not a lowercase FQDN: {hostname!r}")
    return f"https://{hostname}{case.request_path}"


def check(case: Case, profile: str, observed: Probe) -> LiveResult:
    """Compare one observation with the case's expectations for that profile."""
    expectation = case.expectation(profile)
    url = internet_url(case) if profile == "internet" else lab_url(case)
    if observed.error:
        return LiveResult(case.id, False, f"{url}: {observed.error}", observed)
    problems: list[str] = []
    if expectation.http_status is not None and observed.status != expectation.http_status:
        problems.append(f"status {observed.status} != {expectation.http_status}")
    if profile == "lab" and case.disclose_server and case.disclose_server not in (
        observed.server or ""
    ):
        # Cloudflare normalizes Server, so the origin banner is a lab-only assertion.
        problems.append(f"Server {observed.server!r} does not contain {case.disclose_server!r}")
    for marker in case.disclose_body:
        if marker not in observed.body:
            problems.append(f"body does not contain {marker!r}")
    if (
        expectation.http_title_contains is not None
        and expectation.http_title_contains.casefold() not in (observed.title or "").casefold()
    ):
        problems.append(
            f"title {observed.title!r} does not contain {expectation.http_title_contains!r}"
        )
    if problems:
        return LiveResult(case.id, False, f"{url}: " + "; ".join(problems), observed)
    detail = (
        f"{url} status {observed.status}"
        + (f" Server {observed.server!r}" if observed.server else "")
        + (f" title {observed.title!r}" if observed.title else "")
    )
    return LiveResult(case.id, True, detail, observed)


def run_once(case: Case, profile: str) -> LiveResult:
    try:
        observed = probe(lab_url(case)) if profile == "lab" else host_probe(internet_url(case))
        return check(case, profile, observed)
    except ProbeError as error:
        return LiveResult(case.id, False, str(error), None)


def wait_ready(
    cases: list[Case], profile: str, timeout_seconds: int, tick_seconds: float = 3.0
) -> list[LiveResult]:
    """Poll until every origin (or public hostname) serves its documented page, or the deadline."""
    deadline = time.monotonic() + timeout_seconds
    results: dict[str, LiveResult] = {}
    pending = {case.id: case for case in cases}
    while pending and time.monotonic() < deadline:
        for case_id in list(pending):
            result = run_once(pending[case_id], profile)
            results[case_id] = result
            if result.ok:
                pending.pop(case_id)
        if pending:
            time.sleep(tick_seconds)
    for case_id, case in pending.items():
        results[case_id] = run_once(case, profile)
    return [results[case.id] for case in cases]


def print_results(results: list[LiveResult]) -> int:
    failed = 0
    for result in results:
        if result.ok:
            print(f"  PASS  {result.case_id}: {result.detail}")
        else:
            failed += 1
            print(f"  FAIL  {result.case_id}: {result.detail}", file=sys.stderr)
    return failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("lab", "internet"), default="lab")
    parser.add_argument("--wait", type=int, metavar="SECONDS", help="poll until ready or timeout")
    parser.add_argument("--case", action="append", default=[], help="only these case ids")
    parser.add_argument("--json", type=Path, help="write the observations as JSON here")
    parser.add_argument(
        "--allow-placeholder-hostnames",
        action="store_true",
        help="accept the .env.example example.com names (the tunnel run will fail, by design)",
    )
    arguments = parser.parse_args(argv)

    load_vulnlab_env()
    catalog = load_catalog(CATALOG_PATH)
    cases = catalog.cases
    if arguments.case:
        wanted = set(arguments.case)
        unknown = wanted - {case.id for case in cases}
        if unknown:
            print(f"[vulnlab] unknown case(s): {sorted(unknown)}", file=sys.stderr)
            return 2
        cases = tuple(case for case in cases if case.id in wanted)

    if arguments.profile == "internet":
        placeholders = [
            case.id
            for case in cases
            if case.host_env and ".example." in (os.environ.get(case.host_env) or "")
        ]
        if placeholders and not arguments.allow_placeholder_hostnames:
            print(
                f"[vulnlab] placeholder hostnames for {placeholders}: set the real public names "
                "in deploy/vulnlab/.env first",
                file=sys.stderr,
            )
            return 2

    if arguments.wait is not None:
        results = wait_ready(list(cases), arguments.profile, arguments.wait)
    else:
        results = [run_once(case, arguments.profile) for case in cases]

    if arguments.json:
        arguments.json.parent.mkdir(parents=True, exist_ok=True)
        arguments.json.write_text(
            json.dumps(
                [
                    {
                        "case": result.case_id,
                        "profile": arguments.profile,
                        "ok": result.ok,
                        "detail": result.detail,
                        "status": result.probe.status if result.probe else None,
                        "server": result.probe.server if result.probe else None,
                        "title": result.probe.title if result.probe else None,
                    }
                    for result in results
                ],
                indent=1,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    failed = print_results(results)
    if failed:
        print(
            f"[vulnlab] {failed}/{len(results)} {arguments.profile} endpoint(s) did not serve "
            "the documented page"
        )
        return 1
    print(f"[vulnlab] {len(results)}/{len(results)} {arguments.profile} endpoint(s) serve the documented page")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
