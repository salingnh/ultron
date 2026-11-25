#!/usr/bin/env python3
"""Check that every vulnlab origin serves the page the catalog documents (G1.6 slice E).

Each probe is a one-shot container on the authorized lab network, run as the current uid:gid with
all capabilities dropped, a read-only rootfs and its own TTL: the same path a scanner takes, not a
`curl` from the host (the origins publish no host port, so a host curl could not reach them anyway).

Used by `make vulnlab-up` (readiness, `--wait`) and `make vulnlab-check` (the disclosure gate). The
check is deliberately about what the *service* reveals (status, `Server`, title, body markers);
whether a detector parses it into product/version/CPE is `make vulnlab-test` (campaign level).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.vulnlab.catalog import CATALOG_PATH, Case, load_catalog  # noqa: E402

REPO_ROOT = REPO
IMAGES_FILE = REPO / "deploy" / "vulnlab" / "images.env"
LAB_NETWORK = "aegis-lab-lab"
RUN_LABEL = "aegis.vulnlab=aegis-vulnlab-run"
PROBE_TIMEOUT_SECONDS = 20

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
    """The probe container could not run; the message says why."""


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


def probe_image() -> str:
    reference = os.environ.get("AEGIS_VULNLAB_PROBE_IMAGE", "").strip()
    if reference:
        return reference
    for raw in IMAGES_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("AEGIS_VULNLAB_PROBE_IMAGE="):
            return line.split("=", 1)[1].strip()
    raise ProbeError(f"{IMAGES_FILE} has no AEGIS_VULNLAB_PROBE_IMAGE")


def probe(url: str) -> Probe:
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
    return Probe(
        status=payload.get("status"),
        server=payload.get("server"),
        title=payload.get("title"),
        body=str(payload.get("body") or ""),
        error=payload.get("error"),
    )


def lab_url(case: Case) -> str:
    return f"http://{case.lab_address}:{case.image_port}{case.request_path}"


def check(case: Case, observed: Probe) -> LiveResult:
    expectation = case.expectation("lab")
    if observed.error:
        return LiveResult(case.id, False, f"probe error: {observed.error}", observed)
    problems: list[str] = []
    if expectation.http_status is not None and observed.status != expectation.http_status:
        problems.append(f"status {observed.status} != {expectation.http_status}")
    if case.disclose_server and case.disclose_server not in (observed.server or ""):
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
        return LiveResult(case.id, False, "; ".join(problems), observed)
    detail = (
        f"{lab_url(case)} status {observed.status}"
        + (f" Server {observed.server!r}" if observed.server else "")
        + (f" title {observed.title!r}" if observed.title else "")
    )
    return LiveResult(case.id, True, detail, observed)


def run_once(case: Case) -> LiveResult:
    try:
        return check(case, probe(lab_url(case)))
    except ProbeError as error:
        return LiveResult(case.id, False, str(error), None)


def wait_ready(cases: list[Case], timeout_seconds: int, tick_seconds: float = 3.0) -> list[LiveResult]:
    """Poll until every origin serves its documented page, or the deadline passes."""
    deadline = time.monotonic() + timeout_seconds
    results: dict[str, LiveResult] = {}
    pending = {case.id: case for case in cases}
    while pending and time.monotonic() < deadline:
        for case_id in list(pending):
            result = run_once(pending[case_id])
            results[case_id] = result
            if result.ok:
                pending.pop(case_id)
        if pending:
            time.sleep(tick_seconds)
    for case_id, case in pending.items():
        results[case_id] = run_once(case)
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
    parser.add_argument("--wait", type=int, metavar="SECONDS", help="poll until ready or timeout")
    parser.add_argument("--case", action="append", default=[], help="only these case ids")
    parser.add_argument("--json", type=Path, help="write the observations as JSON here")
    arguments = parser.parse_args(argv)

    catalog = load_catalog(CATALOG_PATH)
    cases = catalog.cases
    if arguments.case:
        wanted = set(arguments.case)
        unknown = wanted - {case.id for case in cases}
        if unknown:
            print(f"[vulnlab] unknown case(s): {sorted(unknown)}", file=sys.stderr)
            return 2
        cases = tuple(case for case in cases if case.id in wanted)

    if arguments.wait is not None:
        results = wait_ready(list(cases), arguments.wait)
    else:
        results = [run_once(case) for case in cases]

    if arguments.json:
        arguments.json.parent.mkdir(parents=True, exist_ok=True)
        arguments.json.write_text(
            json.dumps(
                [
                    {
                        "case": result.case_id,
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
        print(f"[vulnlab] {failed}/{len(results)} origin(s) did not serve the documented page")
        return 1
    print(f"[vulnlab] {len(results)}/{len(results)} origin(s) serve the documented page")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
