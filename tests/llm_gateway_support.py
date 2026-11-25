"""Fake LLM upstreams and a pinned-gateway runner for the G1.6 rotation tests.

No test in this module opens a socket to a model provider. Two fake upstreams answer in-process on
loopback, and the pinned LiteLLM image is started with `--network=host` so it reaches them at
127.0.0.1: the same image, the same config shape and the same request path a live gateway uses,
without a key or a cent.

Every fake answers all three shapes a gateway may call:
  * POST /v1/chat/completions - OpenAI Chat Completions (the OpenAI standard, and what the gateway
    uses to reach an OpenAI-compatible endpoint from a chat-completions client),
  * POST /v1/responses        - OpenAI Responses (what this LiteLLM version uses when an
    Anthropic-standard call is translated onto an OpenAI-compatible endpoint),
  * POST /v1/messages         - Anthropic Messages (an Anthropic upstream, either standard).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[1]
GATEWAY_DIR = REPO / "deploy" / "llm-gateway"
EXAMPLE_CONFIG = GATEWAY_DIR / "config.example.yaml"
IMAGES_FILE = GATEWAY_DIR / "images.env"
STATUS_SCRIPT = REPO / "scripts" / "llm-gateway" / "status.py"
VALIDATE_SCRIPT = REPO / "scripts" / "llm-gateway" / "validate.py"

MASTER_KEY = "sk-llm-gateway-test-master-key-not-a-real-secret"
UPSTREAM_KEYS = {
    "UPSTREAM_A_API_KEY": "sk-test-upstream-a",
    "UPSTREAM_B_API_KEY": "sk-test-upstream-b",
}
QUOTA_MESSAGE = "insufficient_quota: you exceeded your current quota"


def pinned_image() -> str:
    """The image the repository pins, digest included (the line `make llm-gateway-up` loads)."""
    text = IMAGES_FILE.read_text(encoding="utf-8")
    match = re.search(r"^AEGIS_LLM_GATEWAY_IMAGE=(.+)$", text, re.MULTILINE)
    assert match is not None, "deploy/llm-gateway/images.env must pin AEGIS_LLM_GATEWAY_IMAGE"
    image = match.group(1).strip()
    assert "@sha256:" in image, f"the gateway image must be digest-pinned: {image}"
    return image


def free_port() -> int:
    """A loopback port nothing is listening on (closed again before the caller binds it)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _chat(text: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "fake-model",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
    }


def _responses(text: str) -> dict[str, Any]:
    return {
        "id": "resp_fake",
        "object": "response",
        "created_at": 1700000000,
        "status": "completed",
        "model": "fake-model",
        "parallel_tool_calls": False,
        "tool_choice": "auto",
        "tools": [],
        "output": [
            {
                "type": "message",
                "id": "msg_fake",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text, "annotations": []}],
            }
        ],
        "usage": {
            "input_tokens": 11,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 3,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 14,
        },
    }


def _messages(text: str) -> dict[str, Any]:
    return {
        "id": "msg_fake",
        "type": "message",
        "role": "assistant",
        "model": "fake-model",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 11, "output_tokens": 3},
    }


@dataclass
class FakeUpstream:
    """One fake upstream on `127.0.0.1:<port>`; `mode` decides what the next request answers."""

    mode: str = "ok"  # ok | rate (429 quota) | server (500)
    hits: list[dict[str, Any]] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    @property
    def port(self) -> int:
        assert self._server is not None, "start() the upstream first"
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def paths(self) -> list[str]:
        return [str(hit["path"]) for hit in self.hits]

    def start(self) -> FakeUpstream:
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: object) -> None:
                pass  # the test's own assertions are the evidence, not a request log

            def _send(self, status: int, payload: Mapping[str, Any]) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                upstream.hits.append({"path": self.path, "body": body})
                if upstream.mode == "rate":
                    if self.path.startswith("/v1/messages"):
                        self._send(
                            429,
                            {
                                "type": "error",
                                "error": {"type": "rate_limit_error", "message": QUOTA_MESSAGE},
                            },
                        )
                    else:
                        self._send(
                            429,
                            {
                                "error": {
                                    "message": QUOTA_MESSAGE,
                                    "type": "insufficient_quota",
                                    "code": "insufficient_quota",
                                }
                            },
                        )
                    return
                if upstream.mode == "server":
                    self._send(
                        500, {"error": {"message": "upstream exploded", "type": "server_error"}}
                    )
                    return
                if self.path.startswith("/v1/responses"):
                    self._send(200, _responses("pong"))
                elif self.path.startswith("/v1/messages"):
                    self._send(200, _messages("pong"))
                else:
                    self._send(200, _chat("pong"))

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def gateway_config(
    upstreams: Sequence[FakeUpstream], *, cooldown_time: int = 300
) -> dict[str, Any]:
    """The shipped example config, with its endpoint slots pointed at the fake upstreams.

    The routing settings, privacy settings and master-key rule are the ones the repository ships;
    only `api_base`, `model`, the ids and the group membership are replaced, so a test passing here
    means the example the owner copies is the one that rotates.
    """
    document = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    templates = document["model_list"][: len(upstreams)]
    model_list: list[dict[str, Any]] = []
    for index, (template, upstream) in enumerate(zip(templates, upstreams, strict=True)):
        letter = chr(ord("a") + index)
        endpoint = f"fake-endpoint-{letter}"
        params = dict(template["litellm_params"])
        params.update(
            model="openai/fake-model",
            api_base=upstream.base_url,
            api_key=f"os.environ/UPSTREAM_{letter.upper()}_API_KEY",
            timeout=10,
            max_retries=0,
        )
        model_list.append(
            {
                "model_name": endpoint,
                "litellm_params": params,
                "model_info": {
                    "id": endpoint,
                    # 11 input + 3 output tokens at these prices is $0.000017: a number no price
                    # in gateway_env() produces, so "the gateway reported it" is provable.
                    "input_cost_per_token": 0.000001,
                    "output_cost_per_token": 0.000002,
                },
            }
        )
    document["model_list"] = model_list
    group = document["router_settings"]["routing_groups"][0]
    group["models"] = [entry["model_name"] for entry in model_list]
    group["model_priorities"] = {
        entry["model_name"]: index for index, entry in enumerate(model_list, start=1)
    }
    document["router_settings"]["cooldown_time"] = cooldown_time
    return document


def gateway_env(base_url: str, model: str, *, provider: str = "openai") -> dict[str, str]:
    """The environment M04 reads to call the gateway (what .env holds in production)."""
    return {
        "AEGIS_SESSION_LIVE_MODEL": "1",
        "AEGIS_MODEL_GATEWAY": "1",
        "AEGIS_MODEL_PROVIDER": provider,
        "AEGIS_MODEL_NAME": model,
        "AEGIS_MODEL_BASE_URL": base_url,
        "AEGIS_MODEL_API_KEY": MASTER_KEY,
        # M04's own price: deliberately different from the gateway's, so a recorded cost proves
        # which of the two won.
        "AEGIS_MODEL_PRICE_INPUT_PER_MTOK": "9.0",
        "AEGIS_MODEL_PRICE_OUTPUT_PER_MTOK": "9.0",
        "AEGIS_MODEL_TIMEOUT_SECONDS": "60",
    }


@dataclass
class GatewayProcess:
    """The pinned image running the owner's config shape on loopback, for one test module."""

    config: Mapping[str, Any]
    name: str = "llm-gateway"
    config_dir: Path = field(default_factory=Path)
    port: int = 0
    container: str = ""
    labels: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.port = free_port()
        suite = os.environ.get("AEGIS_CI_SUITE") or os.environ.get("GITHUB_JOB") or "local"
        run = os.environ.get("GITHUB_RUN_ID") or f"local-{os.getpid()}"
        # Named and labelled like every other CI container, so scripts/ci/cleanup.sh removes this
        # one too when a gate is killed before its own trap runs.
        self.container = f"aegis-ci-{run}-{self.name}"
        self.labels = {"aegis.ci.suite": suite, "aegis.ci.run": run}

    @classmethod
    def spawn(cls, config: Mapping[str, Any], *, name: str = "llm-gateway") -> GatewayProcess:
        process = cls(config=config, name=name)
        process.config_dir = Path(tempfile.mkdtemp(prefix="aegis-llm-gateway-test-"))
        return process

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _write_owner_files(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        (self.config_dir / "config.yaml").write_text(
            yaml.safe_dump(dict(self.config), sort_keys=False), encoding="utf-8"
        )
        secrets = [f"LITELLM_MASTER_KEY={MASTER_KEY}"]
        secrets += [f"{name}={value}" for name, value in UPSTREAM_KEYS.items()]
        path = self.config_dir / "secrets.env"
        path.write_text("\n".join(secrets) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def start(self, *, timeout: float = 180) -> GatewayProcess:
        assert shutil.which("podman"), "podman is required (the CI python gate provides it)"
        self._write_owner_files()
        subprocess.run(["podman", "rm", "-f", self.container], check=False, capture_output=True)
        args = [
            "podman",
            "run",
            "-d",
            "--name",
            self.container,
            *[f"--label={key}={value}" for key, value in self.labels.items()],
            # Host networking is what makes 127.0.0.1 mean the same thing inside and outside the
            # container: the fake upstreams stay loopback-only, exactly like a production host.
            "--network=host",
            "--read-only",
            "--tmpfs=/tmp:rw,size=64m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "-v",
            f"{self.config_dir}:/app/config:ro,z",
            "--env-file",
            str(self.config_dir / "secrets.env"),
            pinned_image(),
            "--config",
            "/app/config/config.yaml",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
        ]
        result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=120)
        assert result.returncode == 0, f"cannot start the gateway: {result.stderr}"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                ready = urllib.request.urlopen(f"{self.base_url}/health/readiness", timeout=2)
                with ready as answer:
                    if answer.status == 200:
                        return self
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(1)
        logs = self.logs()
        self.stop()
        raise AssertionError(f"the gateway did not become ready within {timeout}s:\n{logs}")

    def stop(self) -> None:
        if self.container:
            subprocess.run(["podman", "rm", "-f", self.container], check=False, capture_output=True)

    def logs(self, tail: int = 60) -> str:
        result = subprocess.run(
            ["podman", "logs", "--tail", str(tail), self.container],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout + result.stderr

    def _get(self, path: str) -> str:
        request = urllib.request.Request(
            f"{self.base_url}{path}", headers={"authorization": f"Bearer {MASTER_KEY}"}
        )
        with urllib.request.urlopen(request, timeout=15) as answer:
            return str(answer.read().decode())

    def model_info(self) -> dict[str, Any]:
        payload: dict[str, Any] = json.loads(self._get("/model/info"))
        return payload

    def metrics(self) -> str:
        return self._get("/metrics/")

    def status_table(self) -> str:
        """Run `make llm-gateway-status`'s reader against this gateway's live payloads."""
        info = self.config_dir / "model-info.json"
        metrics = self.config_dir / "metrics.txt"
        info.write_text(json.dumps(self.model_info()), encoding="utf-8")
        metrics.write_text(self.metrics(), encoding="utf-8")
        result = subprocess.run(
            [
                "python3",
                str(STATUS_SCRIPT),
                str(self.config_dir / "config.yaml"),
                str(info),
                str(metrics),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout
