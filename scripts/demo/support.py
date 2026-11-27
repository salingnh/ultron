"""Shared helpers of the G1.5c demo scripts (`demo-g1`, `demo-recovery`, `soak`).

Everything here is thin on purpose: the demos must show what the running stack does, not a second
implementation of it. Reads go through the API (the operator view) or straight to PostgreSQL /
Neo4j (counts and duplicates the API does not publish), and every query is scoped to the campaign
the demo created.

`load_demo_env()` reads `.local/run-local.env`, the file `make run-local` writes (mode 600): the API
URL, the two dev tokens and the endpoint of each store. A demo started from a clean checkout only
needs `make run-local` first.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
STATE_DIR = REPO / ".local"
RUN_ENV = STATE_DIR / "run-local.env"
RUNNERS = ("api", "mcp", "m02-worker", "m02-dispatcher", "m23", "m06")
LAB_ZONE = "lab.aegis.test"
LAB_NETWORK = "aegis-lab-lab"
ENUMERATE = "dns.enumerate_subdomains"
RESOLVE = "dns.resolve"
DISCOVER = "network.discover_services"
#: Ports the G1.6a discovery demo asks for. The lab services answer on 80/443 (web), 8080/8009
#: (Tomcat), 2222 (sshd) and 6379 (Redis); 22 is in the list as a negative control (nothing listens
#: there, so a run that reports it is not scanning the lab).
SERVICE_PORTS = (22, 80, 443, 2222, 6379, 8009, 8080)
TERMINAL_CAMPAIGN = {"COMPLETED", "FAILED", "CANCELLED"}

#: The campaign the demo creates: the lab zone only, the lab-only policy, a fake model.
DEMO_POLICY: dict[str, Any] = {
    # Demos run on the authorized lab network; an operator campaign defaults to `internet`.
    "network_profile": "lab",
    "max_parallel_jobs": 2,
    "max_duration_hours": 1,
    "rate_limits": {"requests_per_second_per_host": 5},
    "budget": {"max_jobs": 20, "idle_cycles_before_pause": 3},
}


class DemoError(RuntimeError):
    """The demo cannot continue; the message says what is missing and how to fix it."""


def load_demo_env() -> None:
    """Load `.local/run-local.env` into the environment (no shell, `export NAME=value` lines)."""
    if not RUN_ENV.is_file():
        raise DemoError(
            f"{RUN_ENV} is missing: run `make run-local` first (it starts every process and writes "
            "this file)"
        )
    for raw in RUN_ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("export ") or "=" not in line:
            raise DemoError(f"{RUN_ENV}: unsupported line {line!r} (expected `export NAME=value`)")
        name, _, value = line[len("export ") :].partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(name.strip(), value)


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def campaign_body(
    name: str,
    objective: str | None = None,
    *,
    targets: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """A demo campaign: the lab seeds and the lab-only execution settings.

    `objective` is what the session reads (it reaches M03 verbatim in the context bundle), so it is
    how a demo says how far the scripted policy should go: `make demo-g1` stops after the DNS
    chain, `make demo-discovery`/`make demo-g16c` ask for the services on the resolved addresses,
    `make demo-g16b` asks for the services and the product behind them. `targets` overrides the seed
    object (a demo that seeds addresses instead of the zone).
    """
    return {
        "name": name,
        "objective": objective
        or (
            "Enumerate the subdomains of the authorized lab zone, then resolve the names the "
            "enumeration found"
        ),
        "targets": dict(targets) if targets else {"domains": [LAB_ZONE]},
        "policy": dict(DEMO_POLICY),
    }


# --- API -------------------------------------------------------------------------------------


def api(
    method: str,
    path: str,
    *,
    payload: Mapping[str, Any] | None = None,
    token: str | None = None,
    service_token: str | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 60.0,
) -> Any:
    """One API call against the local stack; prints and raises on an error body."""
    base = os.environ.get("AEGIS_API_URL", "http://127.0.0.1:8000").rstrip("/")
    url = f"{base}{path}"
    request_headers = {"Accept": "application/json"}
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if service_token:
        request_headers["X-Aegis-Service-Token"] = service_token
    request_headers.update(dict(headers or {}))
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise DemoError(f"{method} {path}: HTTP {error.code}: {detail[:2000]}") from error
    except urllib.error.URLError as error:
        raise DemoError(f"{method} {path}: cannot reach {base}: {error.reason}") from error
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise DemoError(f"{method} {path}: answer is not JSON: {error}") from error


def operator_token() -> str:
    token = os.environ.get("AEGIS_OPERATOR_TOKEN", "")
    if not token:
        raise DemoError("AEGIS_OPERATOR_TOKEN is not set: run `make run-local` (it writes .local)")
    return token


def create_campaign(name: str, objective: str | None = None) -> str:
    created = api(
        "POST",
        "/api/v2/campaigns",
        payload=campaign_body(name, objective),
        token=operator_token(),
        headers={"Idempotency-Key": f"demo-{uuid.uuid4()}"},
    )
    if not isinstance(created, dict) or "campaign_id" not in created:
        raise DemoError(f"POST /campaigns answered {created!r}")
    return str(created["campaign_id"])


def campaign(campaign_id: str) -> dict[str, Any]:
    body = api("GET", f"/api/v2/campaigns/{campaign_id}", token=operator_token())
    if not isinstance(body, dict):
        raise DemoError(f"GET /campaigns/{campaign_id} answered {body!r}")
    return body


def campaign_events(campaign_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
    body = api(
        "GET",
        f"/api/v2/campaigns/{campaign_id}/events?limit={limit}",
        token=operator_token(),
        headers={"Accept": "application/json"},
    )
    return list((body or {}).get("items") or [])


def campaign_flow(campaign_id: str) -> dict[str, Any]:
    body = api("GET", f"/api/v2/campaigns/{campaign_id}/flow", token=operator_token())
    if not isinstance(body, dict):
        raise DemoError(f"GET /campaigns/{campaign_id}/flow answered {body!r}")
    return body


def wait_campaign(
    campaign_id: str,
    *,
    timeout_seconds: float,
    on_tick: Callable[[dict[str, Any]], None] | None = None,
    tick_seconds: float = 2.0,
) -> dict[str, Any]:
    """Poll the campaign until it is terminal; the demo's only wait."""
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = campaign(campaign_id)
        if on_tick is not None:
            on_tick(last)
        if str(last.get("status")) in TERMINAL_CAMPAIGN:
            return last
        time.sleep(tick_seconds)
    status = last.get("status")
    raise DemoError(
        f"campaign {campaign_id} did not finish within {timeout_seconds:.0f}s (status {status}); "
        "logs: .local/m02-worker.log, .local/m02-dispatcher.log, .local/m06.log, .local/m23.log"
    )


# --- PostgreSQL ------------------------------------------------------------------------------


def pg() -> Any:
    """A dict-row connection pinned to the `aegis` schema (imports psycopg lazily)."""
    import psycopg
    from psycopg.rows import dict_row

    dsn = os.environ.get("AEGIS_PG_DSN")
    if not dsn:
        raise DemoError("AEGIS_PG_DSN is not set: run `make run-local` first")
    connection = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
    connection.execute("SET search_path = aegis, public")
    return connection


def rows(connection: Any, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
    return list(connection.execute(sql, list(params)).fetchall())


def one(connection: Any, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
    found = rows(connection, sql, params)
    return found[0] if found else None


def count(connection: Any, sql: str, params: Sequence[Any] = ()) -> int:
    found = one(connection, sql, params)
    return int(next(iter(found.values()))) if found else 0


# --- Neo4j -----------------------------------------------------------------------------------


def neo4j_query(cypher: str, **parameters: Any) -> list[dict[str, Any]]:
    """Run one Cypher statement through the dev Neo4j container (no driver dependency)."""
    uri = os.environ.get("AEGIS_NEO4J_URI", "")
    password = os.environ.get("AEGIS_NEO4J_PASSWORD", "")
    user = os.environ.get("AEGIS_NEO4J_USER", "neo4j")
    if not uri or not password:
        raise DemoError("AEGIS_NEO4J_URI/AEGIS_NEO4J_PASSWORD are not set: run `make run-local`")
    container = _neo4j_container()
    command = [
        "podman",
        "exec",
        container,
        "/var/lib/neo4j/bin/cypher-shell",
        "--format",
        "plain",
        "-u",
        user,
        "-p",
        password,
        _inline(cypher, parameters),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    if completed.returncode != 0:
        raise DemoError(f"cypher failed: {completed.stderr.strip()[:2000]}")
    return _parse_plain(completed.stdout)


def _inline(cypher: str, parameters: Mapping[str, Any]) -> str:
    """Inline the few string/int parameters the demos pass (cypher-shell has no --param here)."""
    rendered = cypher
    for name, value in parameters.items():
        literal = "'" + str(value).replace("'", "") + "'" if isinstance(value, str) else str(value)
        rendered = rendered.replace(f"${name}", literal)
    return rendered


def _parse_plain(output: str) -> list[dict[str, Any]]:
    """Rows of `cypher-shell --format plain`; a quoted cell is a string, as cypher prints it."""
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        return []
    header = [cell.strip() for cell in lines[0].split("|")]
    return [
        dict(zip(header, (_cell(cell) for cell in line.split("|")), strict=False))
        for line in lines[1:]
    ]


def _cell(raw: str) -> Any:
    """One plain-format cell: JSON-unquote strings, keep numbers and booleans as written."""
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            return json.loads(value)
        except json.JSONDecodeError:  # pragma: no cover - cypher always emits valid JSON strings
            return value[1:-1]
    return value


def _dotenv_value(name: str) -> str:
    """Read one unquoted `KEY=VALUE` from `.env` if present (never mutates `os.environ`)."""
    env_file = REPO / ".env"
    if not env_file.is_file():
        return ""
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        entry = raw.strip()
        if not entry or entry.startswith("#") or "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        if key.strip() != name:
            continue
        cleaned = value.strip()
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in "\"'":
            cleaned = cleaned[1:-1]
        return cleaned
    return ""


def _neo4j_container() -> str:
    """The Neo4j container of the dev compose project (names live in scripts/dev/lib.sh).

    `AEGIS_NEO4J_CONTAINER` names it explicitly; otherwise the compose project comes from
    `AEGIS_DEV_PROJECT` (environment or `.env`), defaulting to `aegis-dev`.
    """
    override = os.environ.get("AEGIS_NEO4J_CONTAINER", "").strip()
    if override:
        return override
    project = os.environ.get("AEGIS_DEV_PROJECT", "").strip() or _dotenv_value("AEGIS_DEV_PROJECT")
    project = project or "aegis-dev"
    completed = subprocess.run(
        [
            "podman",
            "ps",
            "--filter",
            f"label=io.podman.compose.project={project}",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    for name in completed.stdout.split():
        if name.endswith("-neo4j"):
            return name
    raise DemoError(
        f"the dev Neo4j container for compose project {project!r} is not running: "
        "run `make dev-up` (or `make run-local`)"
    )


# --- evidence helpers ------------------------------------------------------------------------


def duplicate_groups(connection: Any, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
    """Groups a `GROUP BY ... HAVING count(*) > 1` query returns; empty means no duplicates."""
    return rows(connection, sql, params)


def evidence_dir() -> Path:
    directory = STATE_DIR / "demo"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_artifact(name: str, document: Mapping[str, Any]) -> Path:
    path = evidence_dir() / name
    path.write_text(json.dumps(document, indent=1, sort_keys=True, default=str) + "\n", "utf-8")
    return path


def section(title: str) -> None:
    print(f"\n== {title} " + "=" * max(0, 74 - len(title)))


def line(*parts: Any) -> None:
    print(" ", *parts)


def fail(message: str) -> None:
    print(f"\nFAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: object, message: str) -> None:
    if not condition:
        fail(message)


def campaign_ids_env() -> list[str]:
    """Campaign ids an operator passed through the environment, if any."""
    raw = os.environ.get("AEGIS_DEMO_CAMPAIGNS", "")
    return [value for _name, value in urllib.parse.parse_qsl(raw) if value] if raw else []


@dataclass(frozen=True, slots=True)
class ProcessState:
    name: str
    pid: int
    command: str

    @property
    def alive(self) -> bool:
        try:
            os.kill(self.pid, 0)
        except OSError:
            return False
        return True


def processes() -> list[ProcessState]:
    """The stack processes `make run-local` started, as far as their pid files are still valid."""
    found: list[ProcessState] = []
    for name in RUNNERS:
        pid_file = STATE_DIR / f"{name}.pid"
        if not pid_file.is_file():
            continue
        raw = pid_file.read_text(encoding="utf-8").strip()
        if not raw.isdigit():
            continue
        command = ""
        try:
            command = (
                Path(f"/proc/{raw}/cmdline")
                .read_bytes()
                .replace(b"\0", b" ")
                .decode("utf-8", "replace")
            )
        except OSError:
            command = "(exited)"
        found.append(ProcessState(name=name, pid=int(raw), command=command))
    return found


def rss_kb(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def start_runner() -> int:
    """Start the M06 runner exactly as `make run-local` does, detached, and record its pid.

    The recovery demo restarts the service after SIGKILL; the pid file is the one `make stop-local`
    reads, so the demo leaves the stack in the state run-local expects.
    """
    log = STATE_DIR / "m06.log"
    with log.open("ab") as handle:
        process = subprocess.Popen(  # noqa: S603 - a fixed command this repository owns
            [str(REPO / ".venv/bin/python"), "-u", "-m", "aegis.m06_runner"],
            cwd=str(REPO),
            stdout=handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=os.environ.copy(),
        )
    (STATE_DIR / "m06.pid").write_text(f"{process.pid}\n", encoding="utf-8")
    return process.pid


def container_name(job_id: str) -> str:
    """The container name of one job (`PodmanRunner.container_name`: the job id is the name)."""
    return f"aegis-job-{job_id}"


def container_id(job_id: str) -> str:
    """The container id of a job's container, or "" when no container exists."""
    completed = subprocess.run(  # noqa: S603 - fixed podman query
        [
            "podman",
            "ps",
            "-a",
            "--filter",
            f"label=aegis.job_id={job_id}",
            "--filter",
            "label=aegis.role=job",
            "--format",
            "{{.ID}}",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    found = [item for item in completed.stdout.split() if item.strip()]
    return found[0] if found else ""
